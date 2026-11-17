"""Bearer-token auth for the API."""

import secrets

from fastapi import HTTPException, Request

from config.config import settings


async def require_token(request: Request) -> None:
    """If API_TOKEN is configured, every request must carry it."""
    if not settings.api_token:
        return  # only permitted on loopback (see Settings.validate)
    header = request.headers.get("authorization", "")
    supplied = header[7:] if header.lower().startswith("bearer ") else ""
    if not secrets.compare_digest(supplied.encode(), settings.api_token.encode()):
        raise HTTPException(status_code=401, detail="Invalid or missing token")
