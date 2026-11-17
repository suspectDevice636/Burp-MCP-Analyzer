import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402

from config.config import settings  # noqa: E402


@pytest.fixture(autouse=True)
def _isolated_settings(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "data_dir", tmp_path / "data")
    monkeypatch.setattr(settings, "scope_hosts", ["localhost:3000"])
    monkeypatch.setattr(settings, "api_token", "")
    monkeypatch.setattr(settings, "server_host", "127.0.0.1")


def raw(method="GET", path="/", host="localhost:3000", headers=None, body=""):
    h = {"Host": host, **(headers or {})}
    lines = [f"{method} {path} HTTP/1.1"] + [f"{k}: {v}" for k, v in h.items()]
    return "\r\n".join(lines) + "\r\n\r\n" + body


def resp(status=200, headers=None, body="", ctype="application/json"):
    h = {"Content-Type": ctype, **(headers or {})}
    lines = [f"HTTP/1.1 {status} OK"] + [f"{k}: {v}" for k, v in h.items()]
    return "\r\n".join(lines) + "\r\n\r\n" + body


def item(req, res, notes=""):
    return json.dumps({"request": req, "response": res, "notes": notes})


@pytest.fixture
def api(monkeypatch):
    """TestClient with one engagement ('Acme', scope localhost:3000) already selected."""
    from fastapi.testclient import TestClient

    import main
    from services import ollama_client

    async def ok():
        return {"ok": True}
    monkeypatch.setattr(ollama_client, "check_health", ok)
    with TestClient(main.app) as c:
        e = c.post("/api/engagements", json={"name": "Acme", "client": "Acme Corp",
                                             "scope": ["localhost:3000"]}).json()
        c.eid = e["id"]
        c.headers["X-Engagement"] = e["id"]
        yield c
