import asyncio

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from config.config import settings
from deps import Ctx, current, writable
from services.httpmsg import build_exchange
from services.pipeline import Job

router = APIRouter()


class ScanRequest(BaseModel):
    count: int = Field(200, ge=1, le=5000, description="Max history items to pull (once mode)")
    offset: int = Field(0, ge=0, description="History position to start from")
    use_llm: bool | None = Field(None, description="Defaults to LLM_ENABLED")
    regex: str | None = Field(None, description="Only history items matching this regex")
    live: bool = Field(False, description="Keep watching Burp for new traffic until stopped")
    interval_seconds: float = Field(15, ge=2, le=3600, description="Live mode: seconds between polls")
    min_batch: int = Field(1, ge=1, le=1000,
                           description="Live mode: wait for this many new requests before analyzing "
                                       "(a smaller batch is flushed once traffic goes quiet)")


class PasteRequest(BaseModel):
    request: str
    response: str = ""
    use_llm: bool = False


def _job(request: Request, job_id: str) -> Job:
    job = request.app.state.jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Unknown job")
    return job


def _active(job: Job) -> Job:
    if not job.active:
        raise HTTPException(409, f"Job is already {job.status}")
    return job


@router.post("/scan")
async def start_scan(body: ScanRequest, request: Request, ctx: Ctx = Depends(writable)):
    """Start a one-off scan, or (live=true) a monitor that keeps watching Burp.

    Either way: deterministic checks run immediately, model review is queued and drained in
    the background. Only one job runs at a time (there is one model).
    """
    scope = ctx.meta["scope"]
    if not scope:
        raise HTTPException(400, "This engagement has no scope. Edit it and list the hosts that are in scope.")
    app = request.app
    running = next((j for j in app.state.jobs.values() if j.active), None)
    if running:
        raise HTTPException(409, f"A scan is already running for '{running.engagement_name}'. "
                                 "Pause, resume or stop it first.")
    use_llm = settings.llm_enabled if body.use_llm is None else body.use_llm
    job = Job(engagement_id=ctx.id, engagement_name=ctx.meta["name"], mode="live" if body.live else "once",
              interval_seconds=body.interval_seconds if body.live else 0.0,
              min_batch=body.min_batch if body.live else 1)
    app.state.jobs[job.id] = job
    job._task = asyncio.create_task(
        ctx.pipeline.scan_burp(job, body.count, body.offset, scope, use_llm, body.regex))
    app.state.tasks.add(job._task)
    job._task.add_done_callback(app.state.tasks.discard)
    return job.public()


@router.get("/scan")
async def list_scans(request: Request, ctx: Ctx = Depends(current)):
    """This engagement's jobs (job control endpoints below work by id, across engagements)."""
    return [j.public() for j in request.app.state.jobs.values() if j.engagement_id == ctx.id]


@router.get("/scan/{job_id}")
async def get_scan(job_id: str, request: Request):
    return _job(request, job_id).public()


@router.post("/scan/{job_id}/pause")
async def pause_scan(job_id: str, request: Request):
    """Hold after the current model item finishes (a few seconds). Resume continues where it left off."""
    job = _active(_job(request, job_id))
    job.paused = True
    return job.public()


@router.post("/scan/{job_id}/resume")
async def resume_scan(job_id: str, request: Request):
    job = _active(_job(request, job_id))
    job.paused = False
    return job.public()


@router.post("/scan/{job_id}/cancel")
async def cancel_scan(job_id: str, request: Request):
    """Stop now (also ends a live monitor). Findings are kept; unfinished model work stays queued."""
    job = _active(_job(request, job_id))
    if job._task and not job._task.done():
        job._task.cancel()
        await asyncio.wait({job._task}, timeout=3)
    return job.public()


@router.delete("/queue")
async def clear_queue(ctx: Ctx = Depends(writable)):
    """Discard this engagement's waiting model work (items and deterministic findings are kept)."""
    return {"cleared": ctx.store.clear_queue()}


@router.post("/analyze")
async def analyze_pasted(body: PasteRequest, ctx: Ctx = Depends(writable)):
    """Analyze one pasted raw request/response (no Burp needed). Synchronous."""
    ex = build_exchange(body.request, body.response)
    if ex is None:
        raise HTTPException(400, "Could not parse request (needs a request line and Host header)")
    pipe = ctx.pipeline
    job = Job()
    new = pipe.analyze_deterministic(ex)
    if body.use_llm:
        new += await pipe.analyze_llm(ex, job)
    return {"new_findings": new, "llm_warnings": job.warnings,
            "findings": ctx.store.list_findings(url_contains=ex.path_only)}
