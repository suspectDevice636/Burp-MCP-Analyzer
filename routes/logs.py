from typing import Literal

from fastapi import APIRouter, Query

from services import eventlog

router = APIRouter()


@router.get("/logs")
async def get_logs(limit: int = Query(200, ge=1, le=1000),
                   level: Literal["INFO", "WARNING", "ERROR"] = "INFO", after: int = Query(0, ge=0)):
    """Recent service events (model errors, pauses, Burp failures, job start/finish), newest last.

    Messages hold method and path only (no query strings or bodies) and engagement ids, not names.
    """
    return {"file": eventlog.log_file(), "entries": eventlog.entries(limit, level, after)}
