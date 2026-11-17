"""Engagements: one fully isolated database per client engagement.

Layout:
    data/registry.db                       what engagements exist (names, scope, status)
    data/engagements/<id>/analyzer.db      that engagement's items, findings and model queue

Separate files (not a client column in a shared table) mean one client's traffic and findings
can never leak into another's through a bug or a missed filter, and deleting an engagement is
removing a directory. Ids are random, so client names never appear in URLs, paths or logs.
"""

from __future__ import annotations

import json
import re
import shutil
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from services.store import Store

ID_RE = re.compile(r"^e[0-9a-f]{8}$")
SCOPE_RE = re.compile(r"^[a-z0-9*._:\-\[\]]+$")
STATUSES = ("active", "archived")
KINDS = ("pentest", "bounty")

SCHEMA = """
CREATE TABLE IF NOT EXISTS engagements (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    client TEXT NOT NULL DEFAULT '',
    scope TEXT NOT NULL DEFAULT '[]',
    notes TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active',
    kind TEXT NOT NULL DEFAULT 'pentest',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    last_opened TEXT
);
"""


class EngagementError(ValueError):
    """Invalid input (surfaced to the API as a 400)."""


class NotFound(KeyError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def normalize_scope(patterns) -> list[str]:
    """Clean host patterns. Pasted URLs are reduced to host[:port]; a bare wildcard is refused
    because it would make scope meaningless."""
    out: list[str] = []
    for raw in patterns or []:
        p = str(raw).strip().lower()
        if not p:
            continue
        if "://" in p:
            p = urlsplit(p).netloc or p.split("://", 1)[1]
        p = p.split("/")[0].rsplit("@", 1)[-1]
        if not p.strip("*.:"):
            raise EngagementError("Scope can't be a bare wildcard: list the hosts that are in scope "
                                  "(e.g. app.client.com or *.client.com).")
        if not SCOPE_RE.match(p):
            raise EngagementError(f"'{raw}' doesn't look like a host or host:port pattern.")
        if p not in out:
            out.append(p)
    return out


def _clean_name(name: str) -> str:
    name = " ".join(str(name).split())
    if not 1 <= len(name) <= 80:
        raise EngagementError("Name is required (80 characters max).")
    return name


class EngagementManager:
    def __init__(self, data_dir: Path | str):
        self.data_dir = Path(data_dir)
        self.root = self.data_dir / "engagements"
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(self.data_dir / "registry.db", check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.executescript(SCHEMA)
        have = {r["name"] for r in self._db.execute("PRAGMA table_info(engagements)")}
        if "kind" not in have:   # registry created before engagement types existed
            self._db.execute("ALTER TABLE engagements ADD COLUMN kind TEXT NOT NULL DEFAULT 'pentest'")
        self._db.commit()
        self._stores: dict[str, Store] = {}

    def close(self) -> None:
        with self._lock:
            for s in self._stores.values():
                s.close()
            self._stores.clear()
            self._db.close()

    # ---- registry --------------------------------------------------
    @staticmethod
    def _row(r: sqlite3.Row) -> dict:
        d = dict(r)
        d["scope"] = json.loads(d["scope"])
        return d

    def list(self) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM engagements ORDER BY (status='archived'), "
                "COALESCE(last_opened, created_at) DESC").fetchall()
        return [self._row(r) for r in rows]

    def get(self, eid: str) -> dict | None:
        if not ID_RE.match(eid or ""):
            return None
        with self._lock:
            r = self._db.execute("SELECT * FROM engagements WHERE id=?", (eid,)).fetchone()
        return self._row(r) if r else None

    def _require(self, eid: str) -> dict:
        e = self.get(eid)
        if not e:
            raise NotFound(eid)
        return e

    def _name_taken(self, name: str, exclude: str | None = None) -> bool:
        with self._lock:
            r = self._db.execute("SELECT 1 FROM engagements WHERE lower(name)=lower(?) AND id != ?",
                                 (name, exclude or "")).fetchone()
        return r is not None

    def create(self, name: str, client: str = "", scope=(), notes: str = "", kind: str = "pentest") -> dict:
        name = _clean_name(name)
        if kind not in KINDS:
            raise EngagementError(f"type must be one of {KINDS}")
        if self._name_taken(name):
            raise EngagementError(f"An engagement named '{name}' already exists.")
        scope = normalize_scope(scope)
        eid = "e" + uuid.uuid4().hex[:8]
        now = _now()
        with self._lock:
            self._db.execute(
                "INSERT INTO engagements (id, name, client, scope, notes, kind, created_at, updated_at)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (eid, name, " ".join(client.split())[:80], json.dumps(scope), notes[:4000], kind, now, now))
            self._db.commit()
        self.store(eid)  # create the database now so the schema exists
        return self._require(eid)

    def update(self, eid: str, **fields) -> dict:
        cur = self._require(eid)
        sets: dict = {}
        if fields.get("name") is not None:
            name = _clean_name(fields["name"])
            if self._name_taken(name, exclude=eid):
                raise EngagementError(f"An engagement named '{name}' already exists.")
            sets["name"] = name
        if fields.get("client") is not None:
            sets["client"] = " ".join(fields["client"].split())[:80]
        if fields.get("scope") is not None:
            sets["scope"] = json.dumps(normalize_scope(fields["scope"]))
        if fields.get("notes") is not None:
            sets["notes"] = fields["notes"][:4000]
        if fields.get("kind") is not None:
            if fields["kind"] not in KINDS:
                raise EngagementError(f"type must be one of {KINDS}")
            sets["kind"] = fields["kind"]
        if fields.get("status") is not None:
            if fields["status"] not in STATUSES:
                raise EngagementError(f"status must be one of {STATUSES}")
            sets["status"] = fields["status"]
        if sets:
            cols = ", ".join(f"{k}=?" for k in sets)
            with self._lock:
                self._db.execute(f"UPDATE engagements SET {cols}, updated_at=? WHERE id=?",
                                 (*sets.values(), _now(), eid))
                self._db.commit()
        return self._require(eid) if sets else cur

    def touch(self, eid: str) -> dict:
        self._require(eid)
        with self._lock:
            self._db.execute("UPDATE engagements SET last_opened=? WHERE id=?", (_now(), eid))
            self._db.commit()
        return self._require(eid)

    def delete(self, eid: str) -> None:
        """Permanently remove the engagement and every file it owns."""
        self._require(eid)
        with self._lock:
            store = self._stores.pop(eid, None)
            if store:
                store.close()
            self._db.execute("DELETE FROM engagements WHERE id=?", (eid,))
            self._db.commit()
        path = (self.root / eid).resolve()
        if path.parent == self.root.resolve() and ID_RE.match(path.name):  # never delete outside root
            shutil.rmtree(path, ignore_errors=True)

    # ---- per-engagement data ---------------------------------------
    def db_path(self, eid: str) -> Path:
        return self.root / eid / "analyzer.db"

    def store(self, eid: str) -> Store:
        self._require(eid)
        with self._lock:
            if eid not in self._stores:
                self._stores[eid] = Store(self.db_path(eid))
            return self._stores[eid]

    def summary(self, eid: str) -> dict:
        """Counts for the picker, read without opening a full Store."""
        out = {"items": 0, "findings": 0, "by_status": {}, "queue": 0}
        path = self.db_path(eid)
        if not path.exists():
            return out
        try:
            db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
            try:
                out["items"] = db.execute("SELECT COUNT(*) FROM items").fetchone()[0]
                out["by_status"] = dict(db.execute("SELECT status, COUNT(*) FROM findings GROUP BY status").fetchall())
                out["findings"] = sum(out["by_status"].values())
                out["queue"] = db.execute(
                    "SELECT COUNT(*) FROM items WHERE llm_queued=1 AND llm_done=0").fetchone()[0]
            finally:
                db.close()
        except sqlite3.Error:
            pass
        return out

    # ---- one-time import of pre-engagement data --------------------
    def import_legacy(self, legacy_db: Path, scope=()) -> dict | None:
        """If a pre-engagements database holds data, adopt it as an engagement.

        The original file is kept (renamed) rather than deleted.
        """
        legacy_db = Path(legacy_db)
        if self.list() or not legacy_db.exists():
            return None
        try:
            src = sqlite3.connect(legacy_db)
            try:
                n = src.execute("SELECT COUNT(*) FROM items").fetchone()[0] + \
                    src.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            finally:
                src.close()
        except sqlite3.Error:
            return None
        if not n:
            return None
        eng = self.create("Imported (earlier data)", scope=scope,
                          notes="Created automatically from data saved before engagements existed.")
        self.store(eng["id"]).close()
        self._stores.pop(eng["id"], None)
        src = sqlite3.connect(legacy_db)
        dst = sqlite3.connect(self.db_path(eng["id"]))
        try:
            src.backup(dst)
        finally:
            src.close()
            dst.close()
        legacy_db.rename(legacy_db.with_suffix(".db.pre-engagements"))
        return self._require(eng["id"])
