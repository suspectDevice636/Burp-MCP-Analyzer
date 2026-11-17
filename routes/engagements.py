from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from services.engagements import EngagementError, NotFound

router = APIRouter()


class EngagementCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    client: str = Field("", max_length=80)
    scope: list[str] = Field(default_factory=list, description="Hosts in scope, e.g. app.client.com or *.client.com")
    notes: str = Field("", max_length=4000)
    kind: Literal["pentest", "bounty"] = Field("pentest", description="Decides the report format")


class EngagementUpdate(BaseModel):
    name: str | None = Field(None, max_length=80)
    client: str | None = Field(None, max_length=80)
    scope: list[str] | None = None
    notes: str | None = Field(None, max_length=4000)
    status: Literal["active", "archived"] | None = None
    kind: Literal["pentest", "bounty"] | None = None


class DeleteRequest(BaseModel):
    confirm: str = Field(description="The engagement's exact name, as a guard against accidental deletion")


def _active_job(request: Request):
    return next((j for j in request.app.state.jobs.values() if j.active), None)


def _view(request: Request, e: dict, with_summary: bool = True) -> dict:
    mgr = request.app.state.engagements
    job = _active_job(request)
    out = {**e, "running": bool(job and job.engagement_id == e["id"])}
    if with_summary:
        out["summary"] = mgr.summary(e["id"])
    return out


def _call(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except EngagementError as e:
        raise HTTPException(400, str(e))
    except NotFound:
        raise HTTPException(404, "Unknown engagement")


@router.get("/status")
async def status(request: Request):
    """Cheap, global: is a scan running anywhere, and for which engagement?"""
    job = _active_job(request)
    return {"active_job": job.public() if job else None}


@router.get("/engagements")
async def list_engagements(request: Request):
    mgr = request.app.state.engagements
    job = _active_job(request)
    return {
        "engagements": [_view(request, e) for e in mgr.list()],
        "active_job": job.public() if job else None,
    }


@router.post("/engagements", status_code=201)
async def create_engagement(body: EngagementCreate, request: Request):
    e = _call(request.app.state.engagements.create, body.name, body.client, body.scope, body.notes, body.kind)
    return _view(request, e)


@router.get("/engagements/{eid}")
async def get_engagement(eid: str, request: Request):
    e = request.app.state.engagements.get(eid)
    if not e:
        raise HTTPException(404, "Unknown engagement")
    return _view(request, e)


@router.post("/engagements/{eid}/open")
async def open_engagement(eid: str, request: Request):
    """Record that the engagement was opened (orders the picker, 'last used')."""
    return _view(request, _call(request.app.state.engagements.touch, eid))


@router.patch("/engagements/{eid}")
async def update_engagement(eid: str, body: EngagementUpdate, request: Request):
    job = _active_job(request)
    if job and job.engagement_id == eid and body.status == "archived":
        raise HTTPException(409, "A scan is running for this engagement. Stop it before archiving.")
    e = _call(request.app.state.engagements.update, eid, **body.model_dump(exclude_none=True))
    return _view(request, e)


@router.delete("/engagements/{eid}")
async def delete_engagement(eid: str, body: DeleteRequest, request: Request):
    """Permanently delete the engagement and ALL its findings and captured traffic."""
    mgr = request.app.state.engagements
    e = mgr.get(eid)
    if not e:
        raise HTTPException(404, "Unknown engagement")
    job = _active_job(request)
    if job and job.engagement_id == eid:
        raise HTTPException(409, "A scan is running for this engagement. Stop it before deleting.")
    if body.confirm != e["name"]:
        raise HTTPException(400, "Confirmation doesn't match the engagement name.")
    mgr.delete(eid)
    return {"deleted": eid}
