"""OWASP WSTG v4.2 coverage for the selected engagement."""

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from deps import Ctx, current, writable
from services import wstg

router = APIRouter()


class TestNote(BaseModel):
    status: Literal["", "tested", "na"] = ""
    note: str = Field("", max_length=4000)


def _ensure_built(ctx: Ctx) -> None:
    if ctx.store.meta_get("coverage_built") is None:
        wstg.rebuild(ctx.store)


@router.get("/wstg")
async def coverage(ctx: Ctx = Depends(current)):
    """Every WSTG v4.2 test with its status: findings, checked automatically with nothing found,
    tested manually, not applicable, or untested."""
    _ensure_built(ctx)
    return wstg.build_view(ctx.store.list_findings(), ctx.store.coverage(), ctx.store.wstg_notes())


@router.put("/wstg/{test_id}")
async def set_note(test_id: str, body: TestNote, ctx: Ctx = Depends(writable)):
    tid = wstg.normalize_id(test_id)
    if not tid:
        raise HTTPException(404, f"Unknown WSTG v{wstg.VERSION} test '{test_id}'")
    ctx.store.set_wstg_note(tid, body.status, body.note)
    return {"id": tid, **body.model_dump()}


@router.post("/wstg/rebuild")
async def rebuild(ctx: Ctx = Depends(writable)):
    """Recount automated coverage from every stored request (after upgrading, or if numbers look stale)."""
    return {"requests_examined": wstg.rebuild(ctx.store)}
