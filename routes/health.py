from fastapi import APIRouter, Request

from config.config import settings
from services import ollama_client

router = APIRouter()


@router.get("/health")
async def health(request: Request):
    """Reports each dependency separately; always 200 so you can see which one is down."""
    burp = await request.app.state.burp.health()
    llm = await ollama_client.check_health()
    return {
        "status": "healthy" if burp["ok"] and llm["ok"] else "degraded",
        "burp": burp,
        "ollama": llm,
        "engagements": len(request.app.state.engagements.list()),
        "data_dir": str(settings.data_dir),
    }
