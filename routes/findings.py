import re
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from pathlib import Path

from config.config import settings
from deps import Ctx, current, writable
from services import ollama_client
from services import wstg as wstg_mod
from services.report import build_report

router = APIRouter()


class FindingUpdate(BaseModel):
    status: Literal["candidate", "confirmed", "dismissed", "reported"] | None = None
    severity: Literal["info", "low", "medium", "high", "critical"] | None = None
    notes: str | None = None
    title: str | None = None
    description: str | None = None
    recommendation: str | None = None
    report_text: str | None = None
    wstg: list[str] | None = None   # WSTG v4.2 test IDs, e.g. ["ATHZ-04"]


def _get(ctx: Ctx, fid: str) -> dict:
    f = ctx.store.get_finding(fid)
    if not f:
        raise HTTPException(404, "Finding not found")
    return f


@router.get("/findings")
async def list_findings(status: str | None = None, severity: str | None = None,
                        source: str | None = None, url: str | None = None,
                        wstg: str | None = None, ctx: Ctx = Depends(current)):
    tid = None
    if wstg:
        tid = wstg_mod.normalize_id(wstg)
        if not tid:
            raise HTTPException(400, f"'{wstg}' is not a WSTG v{wstg_mod.VERSION} test ID")
    rows = ctx.store.list_findings(status, severity, source, url, wstg_id=tid)
    return {"total": len(rows), "findings": rows}


@router.get("/findings/stats")
async def stats(ctx: Ctx = Depends(current)):
    return ctx.store.stats()


@router.get("/findings/{fid}")
async def get_finding(fid: str, ctx: Ctx = Depends(current)):
    f = _get(ctx, fid)
    f["item"] = ctx.store.get_item(f["item_id"]) if f.get("item_id") else None
    f["wstg_labels"] = [{"id": t, "name": wstg_mod.TESTS[t]} for t in (f.get("wstg") or "").split(",")
                        if t in wstg_mod.TESTS]
    return f


@router.patch("/findings/{fid}")
async def update_finding(fid: str, body: FindingUpdate, ctx: Ctx = Depends(writable)):
    _get(ctx, fid)
    try:
        return ctx.store.update_finding(fid, **body.model_dump(exclude_none=True))
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/findings/{fid}/draft")
async def draft(fid: str, format: Literal["pentest", "bounty"] | None = None, ctx: Ctx = Depends(writable)):
    """Have the local LLM draft report prose for a finding (saved as report_text; edit via PATCH).

    The layout follows the engagement type (override with `format`).
    """
    f = _get(ctx, fid)
    try:
        text = await ollama_client.draft_report_text(f, format or ctx.meta.get("kind", "pentest"))
    except Exception as e:
        raise HTTPException(502, f"Ollama error: {type(e).__name__}: {e}"[:300])
    return ctx.store.update_finding(fid, report_text=text)


@router.get("/report", response_class=PlainTextResponse)
async def report(status: str = "confirmed", title: str | None = None,
                 format: Literal["pentest", "bounty"] | None = None, coverage: bool = False,
                 ctx: Ctx = Depends(current)):
    """Markdown report for this engagement (confirmed findings by default).

    `format` defaults to the engagement's type (web app pentest or bug bounty) and can be
    overridden per request.
    """
    kind = format or ctx.meta.get("kind", "pentest")
    rows = ctx.store.list_findings(status=status)
    name = ctx.meta["client"] or ctx.meta["name"]
    heading = title or (f"{name}: Bug Bounty Submission Drafts" if kind == "bounty"
                        else f"{name}: Penetration Test Findings")
    view = None
    if coverage and kind == "pentest":   # WSTG appendix (pentest layout only)
        if ctx.store.meta_get("coverage_built") is None:
            wstg_mod.rebuild(ctx.store)
        view = wstg_mod.build_view(ctx.store.list_findings(), ctx.store.coverage(), ctx.store.wstg_notes())
    return build_report(rows, heading, kind=kind, scope=ctx.meta["scope"], coverage=view)


@router.post("/backup")
async def backup(ctx: Ctx = Depends(current)):
    if not settings.backup_dir:
        raise HTTPException(400, "BACKUP_DIR is not configured")
    slug = re.sub(r"[^a-z0-9]+", "-", ctx.meta["name"].lower()).strip("-")[:40] or "engagement"
    path = ctx.store.backup(Path(settings.backup_dir) / f"{slug}-{ctx.id}")
    return {"backup": str(path)}
