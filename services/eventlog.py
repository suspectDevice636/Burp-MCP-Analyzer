"""In-memory event log (shown in the review page) plus an optional rotating log file.

Only this service's own events are kept (model errors, pauses, Burp failures, job start/finish),
not the per-request access chatter. Messages carry method and path only (no query string, no
bodies) and engagement ids rather than client names, so the log is safe to read and to share.
"""

from __future__ import annotations

import collections
import itertools
import logging
import os
import threading
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

OURS = ("services", "routes", "analyzer", "deps", "security", "main", "__main__")
LEVELS = {"INFO": logging.INFO, "WARNING": logging.WARNING, "ERROR": logging.ERROR}
MAX_ENTRIES = 1000


class _OurEvents(logging.Filter):
    def filter(self, rec: logging.LogRecord) -> bool:
        if rec.name.startswith(OURS):
            return True
        return rec.levelno >= logging.WARNING and not rec.name.startswith("uvicorn.access")


class Ring(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.INFO)
        self.buf: collections.deque[dict] = collections.deque(maxlen=MAX_ENTRIES)
        self._ids = itertools.count(1)
        self._lock2 = threading.Lock()
        self.addFilter(_OurEvents())

    def emit(self, rec: logging.LogRecord) -> None:
        try:
            msg = rec.getMessage()
            if rec.exc_info:
                msg += "\n" + logging.Formatter().formatException(rec.exc_info)[-1500:]
            entry = {"t": datetime.fromtimestamp(rec.created, timezone.utc).isoformat(timespec="seconds"),
                     "level": rec.levelname, "source": rec.name, "message": msg}
            with self._lock2:
                entry["id"] = next(self._ids)
                self.buf.append(entry)
        except Exception:  # noqa: BLE001 - logging must never break the service
            self.handleError(rec)


RING = Ring()
_state: dict = {"installed": False, "file": None}


def install(log_file: str | Path | None) -> str | None:
    """Attach the ring (and file) handlers to the root logger once. Returns the log file path."""
    if _state["installed"]:
        return _state["file"]
    root = logging.getLogger()
    root.addHandler(RING)
    path = None
    if log_file:
        try:
            p = Path(log_file)
            p.parent.mkdir(parents=True, exist_ok=True)
            fh = RotatingFileHandler(p, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
            fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
            fh.addFilter(_OurEvents())
            root.addHandler(fh)
            try:
                os.chmod(p, 0o600)
            except OSError:
                pass
            path = str(p)
        except OSError as e:   # unwritable location: keep running with the in-memory log only
            logging.getLogger("analyzer").warning("Could not open log file %s: %s", log_file, e)
    _state.update(installed=True, file=path)
    return path


def entries(limit: int = 200, level: str = "INFO", after: int = 0) -> list[dict]:
    floor = LEVELS.get(level, logging.INFO)
    with RING._lock2:
        rows = [e for e in RING.buf if e["id"] > after and LEVELS.get(e["level"], logging.INFO) >= floor
                or e["id"] > after and e["level"] == "CRITICAL"]
    return rows[-limit:]


def log_file() -> str | None:
    return _state["file"]
