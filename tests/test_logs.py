"""Service log: model error messages, the event ring, the file, the API, and the pause reason."""
import logging

import httpx
import pytest

from config.config import settings
from services import eventlog, ollama_client
from services.httpmsg import build_exchange
from services.pipeline import Job, Pipeline
from services.store import Store
from tests.conftest import raw, resp


@pytest.fixture(autouse=True)
def fresh_ring():
    eventlog.RING.buf.clear()
    logging.getLogger().setLevel(logging.INFO)
    yield


# ------------------------------------------------------- error messages
@pytest.mark.parametrize("exc,expect", [
    (httpx.ReadTimeout(""), "timed out after"),
    (httpx.ConnectError("All connection attempts failed"), "cannot connect to Ollama"),
    (httpx.ReadError(""), "dropped mid-request"),
    (ollama_client.OllamaError("Ollama returned HTTP 500: model requires more system memory"), "more system memory"),
    (RuntimeError(), "RuntimeError"),
])
def test_describe_error_is_never_empty(exc, expect):
    msg = ollama_client.describe_error(exc)
    assert expect in msg and msg.strip()


async def test_http_error_body_is_surfaced(monkeypatch):
    class R:
        status_code, reason_phrase, text = 404, "Not Found", ""
        def json(self): return {"error": "model 'mistral' not found, try pulling it first"}
    class C:
        async def post(self, *a, **k): return R()
        async def aclose(self): pass
    with pytest.raises(ollama_client.OllamaError, match="not found, try pulling"):
        await ollama_client._chat([{"role": "user", "content": "x"}], client=C())


async def test_triage_returns_readable_error(monkeypatch):
    async def boom(*a, **k): raise httpx.ReadTimeout("")
    monkeypatch.setattr(ollama_client, "_chat", boom)
    res = await ollama_client.triage(build_exchange(raw(path="/a"), resp(body="{}")))
    assert "timed out after" in res.error


# ------------------------------------------------------- ring + api
def test_ring_keeps_our_events_not_access_noise():
    logging.getLogger("services.pipeline").warning("model error [engagement e1] GET /a: boom")
    logging.getLogger("uvicorn.access").info("127.0.0.1 GET /api/status")
    logging.getLogger("httpx").info("HTTP Request: POST http://x/api/chat")
    msgs = [e["message"] for e in eventlog.entries()]
    assert msgs == ["model error [engagement e1] GET /a: boom"]
    assert eventlog.entries(level="ERROR") == []


def test_logs_api_filters_by_level(api):
    eventlog.RING.buf.clear()      # drop the service's own startup line
    logging.getLogger("services.pipeline").info("job x started")
    logging.getLogger("services.pipeline").warning("model error: nope")
    allv = api.get("/api/logs?level=INFO").json()
    assert [e["level"] for e in allv["entries"]] == ["INFO", "WARNING"]
    warn = api.get("/api/logs?level=WARNING").json()
    assert [e["message"] for e in warn["entries"]] == ["model error: nope"]
    after = api.get(f"/api/logs?after={allv['entries'][0]['id']}").json()
    assert len(after["entries"]) == 1


def test_log_file_is_written(tmp_path):
    saved = dict(eventlog._state)
    root = logging.getLogger()
    before = list(root.handlers)
    eventlog._state.update(installed=False, file=None)
    try:
        path = eventlog.install(tmp_path / "logs" / "analyzer.log")
        logging.getLogger("services.pipeline").warning("model error: file check")
        for h in root.handlers:
            h.flush()
        assert "model error: file check" in (tmp_path / "logs" / "analyzer.log").read_text()
        assert path.endswith("analyzer.log")
    finally:
        for h in list(root.handlers):
            if h not in before:
                root.removeHandler(h)
                h.close()
        eventlog._state.update(saved)


def test_log_file_setting():
    assert settings.log_file_path is None or settings.log_file_path.endswith("analyzer.log")


# ------------------------------------------- pipeline: error + pause reason
class DownLLM:
    async def triage(self, ex):
        return ollama_client.TriageResult(error="cannot connect to Ollama at http://x:11434 (refused)")


async def test_model_errors_are_logged_without_query_strings_and_pause_with_reason(tmp_path):
    st = Store(tmp_path / "a.db")
    p = Pipeline(st, burp=None, llm=DownLLM())
    job = Job(engagement_id="e12345678")
    for i in range(3):
        ex = build_exchange(raw(path=f"/api/item{i}?token=SECRETVALUE99"), resp(body='{"a":1}'))
        st.upsert_item(ex)
        st.enqueue_llm(ex.id)
    import asyncio
    task = asyncio.create_task(p._drain(job, forever=False))
    for _ in range(100):                 # it pauses itself after 3 errors, then waits for Resume
        if job.paused:
            break
        await asyncio.sleep(0.02)
    task.cancel()
    text = "\n".join(e["message"] for e in eventlog.entries())
    assert "model error [engagement e12345678] GET /api/item0" in text
    assert "SECRETVALUE99" not in text                 # no query strings in the log
    assert "paused after 3 model errors" in text
    assert job.paused and "cannot connect to Ollama" in job.llm_last_error
    assert any("Last error: cannot connect" in w for w in job.warnings)
    assert job.public()["llm_last_error_at"]
