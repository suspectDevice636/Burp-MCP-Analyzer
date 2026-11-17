import pytest
from fastapi.testclient import TestClient

from config.config import settings
from services import ollama_client
from tests.conftest import item, raw, resp


class FakeBurp:
    async def history(self, count, offset=0, regex=None):
        return [item(raw(path="/api/Users"), resp(
            body='{"data":[' + ",".join(f'{{"email":"u{i}@x.io","password":"{"a" * 32}"}}' for i in range(6)) + "]}"))] if offset == 0 else []

    async def health(self):
        return {"ok": True, "tools": 3}


@pytest.fixture
def client(api):
    api.app.state.burp = FakeBurp()
    return api


def test_full_flow(client):
    r = client.post("/api/scan", json={"use_llm": False})
    assert r.status_code == 200
    jid = r.json()["id"]
    import time
    for _ in range(50):
        j = client.get(f"/api/scan/{jid}").json()
        if j["status"] != "running":
            break
        time.sleep(0.05)
    assert j["status"] == "done" and j["new_findings"] >= 2

    rows = client.get("/api/findings", params={"severity": "high"}).json()["findings"]
    assert rows and rows[0]["status"] == "candidate"
    fid = rows[0]["id"]

    assert "No findings" in client.get("/api/report").text           # nothing confirmed yet
    client.patch(f"/api/findings/{fid}", json={"status": "confirmed", "notes": "Reproduced in Repeater"})
    rep = client.get("/api/report").text
    assert "Reproduced in Repeater" in rep and "Password hashes" in rep
    assert client.patch(f"/api/findings/{fid}", json={"status": "nope"}).status_code == 422
    assert client.get("/api/findings/stats").json()["by_status"]["confirmed"] == 1


def test_scan_requires_scope(client):
    empty = client.post("/api/engagements", json={"name": "No scope yet"}).json()
    r = client.post("/api/scan", json={}, headers={"X-Engagement": empty["id"]})
    assert r.status_code == 400 and "no scope" in r.json()["detail"].lower()


def test_paste_analyze(client):
    r = client.post("/api/analyze", json={"request": raw(path="/ftp"),
                                          "response": resp(ctype="text/html", body="listing directory /ftp")})
    assert r.status_code == 200 and r.json()["new_findings"] >= 1
    assert client.post("/api/analyze", json={"request": "junk"}).status_code == 400


def test_token_auth(client, monkeypatch):
    monkeypatch.setattr(settings, "api_token", "s3cret")
    assert client.get("/api/findings").status_code == 401
    assert client.get("/api/findings", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get("/api/findings", headers={"Authorization": "Bearer s3cret"}).status_code == 200


def test_non_loopback_requires_token(monkeypatch):
    monkeypatch.setattr(settings, "server_host", "0.0.0.0")
    monkeypatch.setattr(settings, "api_token", "")
    with pytest.raises(RuntimeError):
        settings.validate()
