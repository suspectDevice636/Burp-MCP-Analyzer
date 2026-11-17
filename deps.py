"""Per-request engagement context.

Every data route needs an explicit engagement (X-Engagement header, or ?engagement=). There is
deliberately no default: with several clients, "whichever was last" is how data lands in the
wrong place.
"""

from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request

from services.pipeline import Pipeline
from services.store import Store


@dataclass
class Ctx:
    id: str
    meta: dict
    store: Store
    pipeline: Pipeline

    @property
    def writable(self) -> bool:
        return self.meta["status"] == "active"


async def current(request: Request) -> Ctx:
    eid = request.headers.get("x-engagement") or request.query_params.get("engagement") or ""
    if not eid:
        raise HTTPException(400, "No engagement selected. Send an X-Engagement header "
                                 "(ids are listed by GET /api/engagements).")
    mgr = request.app.state.engagements
    meta = mgr.get(eid)
    if not meta:
        raise HTTPException(404, "Unknown engagement")
    store = mgr.store(eid)
    pipeline = Pipeline(store, request.app.state.burp, llm=request.app.state.llm)
    return Ctx(id=eid, meta=meta, store=store, pipeline=pipeline)


async def writable(ctx: Ctx = Depends(current)) -> Ctx:
    if not ctx.writable:
        raise HTTPException(409, "This engagement is archived (read-only). Restore it to make changes.")
    return ctx
