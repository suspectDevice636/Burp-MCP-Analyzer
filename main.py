#!/usr/bin/env python3
"""Burp MCP Analyzer - FastAPI service.

Pulls traffic from Burp Suite's MCP extension, runs deterministic checks and
local-LLM triage, and tracks findings through to a report. Fully local.
"""

import logging
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import Depends, FastAPI, Request
from fastapi.staticfiles import StaticFiles

from config.config import APP_DESCRIPTION, APP_NAME, APP_VERSION, settings
from routes import engagements, findings, health, scan
from routes import logs as logs_routes
from routes import wstg as wstg_routes
from security import require_token
from services import eventlog, ollama_client
from services.burp_mcp import BurpMCP
from services.engagements import EngagementManager

logging.basicConfig(
    level=settings.log_level,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("analyzer")
eventlog.install(settings.log_file_path)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings.validate()
    mgr = EngagementManager(settings.data_dir)
    imported = mgr.import_legacy(settings.legacy_db_path, settings.scope_hosts)
    if imported:
        logger.info("Imported earlier data as engagement '%s' (original kept as *.pre-engagements)",
                    imported["name"])
    app.state.engagements = mgr
    app.state.burp = BurpMCP()
    app.state.llm = ollama_client
    app.state.jobs = {}
    app.state.tasks = set()
    logger.info("%s v%s ready (%d engagements in %s, burp=%s, ollama=%s/%s)", APP_NAME, APP_VERSION,
                len(mgr.list()), settings.data_dir, settings.burp_mcp_url,
                settings.ollama_host, settings.ollama_model)
    yield
    for t in list(app.state.tasks):
        t.cancel()
    mgr.close()


app = FastAPI(title=APP_NAME, description=APP_DESCRIPTION, version=APP_VERSION, lifespan=lifespan)

# No CORS middleware on purpose: this API is for scripts/curl, never for browsers.
auth = [Depends(require_token)]
app.include_router(health.router, prefix="/api", tags=["Health"], dependencies=auth)
app.include_router(engagements.router, prefix="/api", tags=["Engagements"], dependencies=auth)
app.include_router(scan.router, prefix="/api", tags=["Scan"], dependencies=auth)
app.include_router(findings.router, prefix="/api", tags=["Findings"], dependencies=auth)
app.include_router(logs_routes.router, prefix="/api", tags=["Logs"], dependencies=auth)
app.include_router(wstg_routes.router, prefix="/api", tags=["WSTG"], dependencies=auth)


UI_DIR = Path(__file__).parent / "ui"
UI_CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
          "img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


@app.middleware("http")
async def ui_security_headers(request: Request, call_next):
    """Strict CSP for the review page: it renders attacker-controlled traffic."""
    response = await call_next(request)
    if request.url.path.startswith("/ui"):
        response.headers["Content-Security-Policy"] = UI_CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
    return response


# The page holds no data; it calls the (token-protected) API from the browser.
app.mount("/ui", StaticFiles(directory=UI_DIR, html=True), name="ui")


@app.get("/")
async def root():
    return {"name": APP_NAME, "version": APP_VERSION, "docs": "/docs", "review_ui": "/ui/"}


def main():
    settings.validate()
    uvicorn.run("main:app", host=settings.server_host, port=settings.server_port,
                reload=settings.debug, log_level=settings.log_level.lower())


if __name__ == "__main__":
    main()
