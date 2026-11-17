"""Keeping scripts and runaway replies away from the model, and not pausing a job over one slow item."""
import asyncio

import httpx
import pytest

from config.config import settings
from services import ollama_client
from services.httpmsg import build_exchange
from services.pipeline import Job, Pipeline, llm_eligible, looks_like_js
from services.store import Store
from tests.conftest import raw, resp

MINIFIED = '!function(e){var t={};function n(r){if(t[r])return t[r].exports}n.m=e}([function(){}]);' * 40


# --------------------------------------------------- scripts stay out
@pytest.mark.parametrize("path,ctype,body,eligible", [
    ("/main.js", "text/plain", MINIFIED, False),                       # extension wins over a wrong type
    ("/static/bundle", "text/html", MINIFIED, False),                  # sniffed as code
    ("/static/bundle", "application/javascript", MINIFIED, False),
    ("/api/Users", "application/json", '{"a":1}', True),
    ("/index", "text/html", "<html><script>var a = 1;</script></html>", True),   # HTML is reviewed
    ("/notes", "text/plain", "meeting notes: ship it", True),
])
def test_script_detection(path, ctype, body, eligible):
    ex = build_exchange(raw(path=path), resp(ctype=ctype, body=body))
    assert llm_eligible(ex) is eligible


def test_js_reviewed_when_skip_disabled(monkeypatch):
    monkeypatch.setattr(settings, "llm_skip_js", False)
    ex = build_exchange(raw(path="/a"), resp(ctype="application/javascript", body=MINIFIED))
    assert llm_eligible(ex)


def test_looks_like_js_ignores_json_and_html():
    assert looks_like_js(MINIFIED)
    assert not looks_like_js('{"fn":"function(x)"}')
    assert not looks_like_js("<script>function(){}</script>")


# ------------------------------------------------- output is bounded
async def test_triage_requests_cap_output_but_drafts_are_uncapped(monkeypatch):
    seen = []

    class R:
        status_code = 200
        def json(self): return {"message": {"content": '{"findings":[]}'}}

    class C:
        async def post(self, url, json): seen.append(json); return R()
        async def aclose(self): pass

    monkeypatch.setattr(settings, "ollama_num_predict", 321)
    await ollama_client._chat([{"role": "user", "content": "x"}], fmt={"type": "object"}, client=C())
    await ollama_client._chat([{"role": "user", "content": "x"}], client=C())
    assert seen[0]["options"]["num_predict"] == 321
    assert "num_predict" not in seen[1]["options"]


async def test_cut_off_reply_is_discarded_not_an_error(monkeypatch):
    async def cut(*a, **k): return {"message": {"content": '{"findings":[{"ty'}, "done_reason": "length"}
    monkeypatch.setattr(ollama_client, "_chat", cut)
    res = await ollama_client.triage(build_exchange(raw(path="/a"), resp(body="{}")))
    assert res.truncated and res.error is None and res.findings == []


# ------------------------------------- a slow item must not pause the job
class SlowLLM:
    def __init__(self, healthy): self.healthy, self.calls = healthy, 0
    async def triage(self, ex):
        self.calls += 1
        return ollama_client.TriageResult(error="timed out after 180s waiting for Ollama", error_kind="timeout")
    async def check_health(self): return {"ok": self.healthy}


def seeded(tmp_path, n=4):
    st = Store(tmp_path / "a.db")
    for i in range(n):
        ex = build_exchange(raw(path=f"/api/thing{i}"), resp(body='{"a":1}'))
        st.upsert_item(ex); st.enqueue_llm(ex.id)
    return st


async def test_timeouts_with_healthy_ollama_skip_items_and_do_not_pause(tmp_path):
    st = seeded(tmp_path)
    llm = SlowLLM(healthy=True)
    job = Job()
    await Pipeline(st, burp=None, llm=llm)._drain(job, forever=False)
    assert llm.calls == 4                       # each tried once, none retried
    assert not job.paused and job.llm_errors == 0
    assert job.llm_discard_reasons == {"timed_out_skipped": 4}
    assert st.queue_depth() == 0


async def test_timeouts_with_dead_ollama_still_pause(tmp_path):
    st = seeded(tmp_path)
    job = Job()
    task = asyncio.create_task(Pipeline(st, burp=None, llm=SlowLLM(healthy=False))._drain(job, forever=False))
    for _ in range(100):
        if job.paused:
            break
        await asyncio.sleep(0.02)
    task.cancel()
    assert job.paused and "timed out" in job.llm_last_error
