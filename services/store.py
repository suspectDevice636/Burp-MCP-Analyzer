"""SQLite persistence for exchanges and findings.

The database lives on local disk (SQLite over SMB is unsafe). Use backup()
to copy it to the NAS.
"""

from __future__ import annotations

import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from services import wstg

STATUSES = ("candidate", "confirmed", "dismissed", "reported")
SEVERITIES = ("info", "low", "medium", "high", "critical")

SCHEMA = """
CREATE TABLE IF NOT EXISTS items (
    id TEXT PRIMARY KEY,
    method TEXT, url TEXT, host TEXT, status INTEGER,
    raw_request TEXT, raw_response TEXT,
    llm_done INTEGER NOT NULL DEFAULT 0,
    llm_queued INTEGER NOT NULL DEFAULT 0,
    llm_attempts INTEGER NOT NULL DEFAULT 0,
    endpoint TEXT,
    first_seen TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    item_id TEXT,
    dedupe_key TEXT NOT NULL UNIQUE,
    source TEXT NOT NULL,
    type TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL DEFAULT 'medium',
    method TEXT, url TEXT,
    evidence TEXT NOT NULL DEFAULT '',
    evidence_quality TEXT NOT NULL DEFAULT '',
    wstg TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    recommendation TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'candidate',
    notes TEXT NOT NULL DEFAULT '',
    report_text TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE TABLE IF NOT EXISTS coverage (wstg_id TEXT PRIMARY KEY, requests INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS wstg_notes (
    wstg_id TEXT PRIMARY KEY, status TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Store:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(self.path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.executescript(SCHEMA)
        self._migrate()
        self._db.commit()

    def _migrate(self) -> None:
        """Add columns introduced after a database was first created."""
        have = {r["name"] for r in self._db.execute("PRAGMA table_info(items)")}
        for col, ddl in (("llm_queued", "INTEGER NOT NULL DEFAULT 0"),
                         ("llm_attempts", "INTEGER NOT NULL DEFAULT 0"),
                         ("endpoint", "TEXT")):
            if col not in have:
                self._db.execute(f"ALTER TABLE items ADD COLUMN {col} {ddl}")
        have_f = {r["name"] for r in self._db.execute("PRAGMA table_info(findings)")}
        if "evidence_quality" not in have_f:
            self._db.execute("ALTER TABLE findings ADD COLUMN evidence_quality TEXT NOT NULL DEFAULT ''")
        if "wstg" not in have_f:
            self._db.execute("ALTER TABLE findings ADD COLUMN wstg TEXT NOT NULL DEFAULT ''")
            for r in self._db.execute("SELECT id, type, title FROM findings").fetchall():   # tag existing findings
                self._db.execute("UPDATE findings SET wstg=? WHERE id=?",
                                 (",".join(wstg.tags_for(r["type"], r["title"])), r["id"]))
        self._db.execute("CREATE INDEX IF NOT EXISTS idx_items_endpoint ON items(endpoint)")
        self._db.execute("CREATE INDEX IF NOT EXISTS idx_items_queue ON items(llm_queued, llm_done)")

    def close(self) -> None:
        self._db.close()

    # ---- items -----------------------------------------------------
    def upsert_item(self, ex) -> bool:
        """Insert an exchange. Returns True if it was new."""
        with self._lock:
            cur = self._db.execute(
                "INSERT OR IGNORE INTO items (id, method, url, host, status, raw_request,"
                " raw_response, endpoint, first_seen) VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    ex.id, ex.method, ex.url, ex.host,
                    ex.response.status if ex.response else None,
                    ex.raw_request, ex.raw_response, ex.endpoint, _now(),
                ),
            )
            # backfill rows saved before the endpoint column existed
            self._db.execute("UPDATE items SET endpoint=? WHERE id=? AND endpoint IS NULL", (ex.endpoint, ex.id))
            self._db.commit()
            return cur.rowcount > 0

    def item_llm_done(self, item_id: str) -> bool:
        with self._lock:
            row = self._db.execute("SELECT llm_done FROM items WHERE id=?", (item_id,)).fetchone()
        return bool(row and row["llm_done"])

    def mark_llm_done(self, item_id: str) -> None:
        with self._lock:
            self._db.execute("UPDATE items SET llm_done=1, llm_queued=0 WHERE id=?", (item_id,))
            self._db.commit()

    # ---- model queue (persistent: survives restarts, pause and cancel) --------
    def enqueue_llm(self, item_id: str) -> None:
        with self._lock:
            self._db.execute("UPDATE items SET llm_queued=1 WHERE id=? AND llm_done=0", (item_id,))
            self._db.commit()

    def llm_slots_used(self, endpoint: str) -> int:
        """Items of this endpoint already reviewed or waiting for review."""
        with self._lock:
            return self._db.execute(
                "SELECT COUNT(*) FROM items WHERE endpoint=? AND (llm_done=1 OR llm_queued=1)",
                (endpoint,)).fetchone()[0]

    def next_queued(self) -> dict[str, Any] | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM items WHERE llm_queued=1 AND llm_done=0 ORDER BY rowid LIMIT 1").fetchone()
        return dict(row) if row else None

    def queue_depth(self) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM items WHERE llm_queued=1 AND llm_done=0").fetchone()[0]

    def bump_attempts(self, item_id: str) -> int:
        with self._lock:
            self._db.execute("UPDATE items SET llm_attempts=llm_attempts+1 WHERE id=?", (item_id,))
            self._db.commit()
            return self._db.execute("SELECT llm_attempts FROM items WHERE id=?", (item_id,)).fetchone()[0]

    def clear_queue(self) -> int:
        """Drop the backlog (items stay stored and deterministic findings are kept)."""
        with self._lock:
            n = self._db.execute("UPDATE items SET llm_queued=0 WHERE llm_queued=1 AND llm_done=0").rowcount
            self._db.commit()
        return n

    def get_item(self, item_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._db.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        return dict(row) if row else None

    # ---- findings --------------------------------------------------
    def add_finding(self, f: dict[str, Any]) -> str | None:
        """Insert a finding. Returns its id, or None if a duplicate (same dedupe_key)."""
        fid = uuid.uuid4().hex[:12]
        now = _now()
        with self._lock:
            cur = self._db.execute(
                "INSERT OR IGNORE INTO findings (id, item_id, dedupe_key, source, type, title,"
                " severity, confidence, method, url, evidence, description, recommendation,"
                " evidence_quality, wstg, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    fid, f.get("item_id"), f["dedupe_key"], f["source"], f["type"], f["title"],
                    f["severity"], f.get("confidence", "medium"), f.get("method"), f.get("url"),
                    f.get("evidence", ""), f.get("description", ""), f.get("recommendation", ""),
                    f.get("evidence_quality", ""),
                    f["wstg"] if "wstg" in f else ",".join(wstg.tags_for(f["type"], f["title"])), now, now,
                ),
            )
            self._db.commit()
            return fid if cur.rowcount > 0 else None

    def get_finding(self, fid: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._db.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
        return dict(row) if row else None

    def list_findings(
        self,
        status: str | None = None,
        severity: str | None = None,
        source: str | None = None,
        url_contains: str | None = None,
        wstg_id: str | None = None,
    ) -> list[dict[str, Any]]:
        q, args = "SELECT * FROM findings WHERE 1=1", []
        for col, val in (("status", status), ("severity", severity), ("source", source)):
            if val:
                q += f" AND {col}=?"
                args.append(val)
        if url_contains:
            q += " AND url LIKE ?"
            args.append(f"%{url_contains}%")
        if wstg_id:
            q += " AND (',' || wstg || ',') LIKE ?"
            args.append(f"%,{wstg_id},%")
        q += (
            " ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1"
            " WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, created_at DESC"
        )
        with self._lock:
            rows = self._db.execute(q, args).fetchall()
        return [dict(r) for r in rows]

    def findings_for_url(self, url: str, source: str | None = None) -> list[dict[str, Any]]:
        q, args = "SELECT * FROM findings WHERE url=?", [url]
        if source:
            q += " AND source=?"
            args.append(source)
        with self._lock:
            rows = self._db.execute(q, args).fetchall()
        return [dict(r) for r in rows]

    def update_finding(self, fid: str, **fields: Any) -> dict[str, Any] | None:
        allowed = {"status", "severity", "notes", "title", "description", "recommendation", "report_text", "wstg"}
        sets = {k: v for k, v in fields.items() if k in allowed and v is not None}
        if "wstg" in sets:
            sets["wstg"] = ",".join(wstg.parse_tags(sets["wstg"]))
        if "status" in sets and sets["status"] not in STATUSES:
            raise ValueError(f"status must be one of {STATUSES}")
        if "severity" in sets and sets["severity"] not in SEVERITIES:
            raise ValueError(f"severity must be one of {SEVERITIES}")
        if sets:
            cols = ", ".join(f"{k}=?" for k in sets)
            with self._lock:
                self._db.execute(
                    f"UPDATE findings SET {cols}, updated_at=? WHERE id=?",
                    (*sets.values(), _now(), fid),
                )
                self._db.commit()
        return self.get_finding(fid)

    def stats(self) -> dict[str, Any]:
        with self._lock:
            by = lambda col: {  # noqa: E731
                r[0]: r[1]
                for r in self._db.execute(f"SELECT {col}, COUNT(*) FROM findings GROUP BY {col}")
            }
            total = self._db.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            items = self._db.execute("SELECT COUNT(*) FROM items").fetchone()[0]
        return {
            "total_findings": total,
            "items_seen": items,
            "model_queue": self.queue_depth(),
            "by_status": by("status"),
            "by_severity": by("severity"),
            "by_source": by("source"),
        }

    # ---- WSTG coverage ---------------------------------------------
    def add_coverage(self, tests) -> None:
        """Count one more request that gave these WSTG tests something to examine."""
        tests = list(tests)
        if not tests:
            return
        with self._lock:
            self._db.executemany(
                "INSERT INTO coverage (wstg_id, requests) VALUES (?,1)"
                " ON CONFLICT(wstg_id) DO UPDATE SET requests = requests + 1", [(t,) for t in tests])
            self._db.commit()

    def coverage(self) -> dict[str, int]:
        with self._lock:
            return {r[0]: r[1] for r in self._db.execute("SELECT wstg_id, requests FROM coverage")}

    def meta_get(self, key: str) -> str | None:
        with self._lock:
            r = self._db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return r[0] if r else None

    def meta_set(self, key: str, value: str) -> None:
        with self._lock:
            self._db.execute("INSERT INTO meta (key, value) VALUES (?,?)"
                             " ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))
            self._db.commit()

    def reset_coverage(self, rows: dict[str, int]) -> None:
        with self._lock:
            self._db.execute("DELETE FROM coverage")
            self._db.executemany("INSERT INTO coverage (wstg_id, requests) VALUES (?,?)", list(rows.items()))
            self._db.commit()

    def iter_items(self, batch: int = 500):
        """Yield stored items in batches (raw request/response included)."""
        last = ""
        while True:
            with self._lock:
                rows = self._db.execute(
                    "SELECT id, raw_request, raw_response FROM items WHERE id > ? ORDER BY id LIMIT ?",
                    (last, batch)).fetchall()
            if not rows:
                return
            last = rows[-1]["id"]
            yield from rows

    def wstg_notes(self) -> dict[str, dict]:
        with self._lock:
            return {r["wstg_id"]: {"status": r["status"], "note": r["note"]}
                    for r in self._db.execute("SELECT wstg_id, status, note FROM wstg_notes")}

    def set_wstg_note(self, tid: str, status: str, note: str) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO wstg_notes (wstg_id, status, note, updated_at) VALUES (?,?,?,?)"
                " ON CONFLICT(wstg_id) DO UPDATE SET status=excluded.status, note=excluded.note,"
                " updated_at=excluded.updated_at", (tid, status, note, _now()))
            self._db.commit()

    # ---- backup ----------------------------------------------------
    def backup(self, dest_dir: str | Path) -> Path:
        dest_dir = Path(dest_dir)
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / f"analyzer-{datetime.now().strftime('%Y%m%d-%H%M%S')}.db"
        with self._lock:
            target = sqlite3.connect(dest)
            try:
                self._db.backup(target)
            finally:
                target.close()
        return dest
