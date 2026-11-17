import json

import pytest

from config.config import settings
from services import ollama_client
from services.burp_mcp import parse_history_item
from services.httpmsg import build_exchange
from services.pipeline import Job, Pipeline, in_scope, llm_eligible
from services.store import Store
from tests.conftest import item, raw, resp


def test_build_exchange_params_and_url():
    ex = build_exchange(raw(method="POST", path="/rest/user/login?a=1", headers={"Content-Type": "application/json"},
                            body='{"email":"a@b.c","nested":{"pw":"x"}}'), resp(body="{}"))
    assert ex.url == "http://localhost:3000/rest/user/login?a=1"
    assert ex.params["a"] == ["1"] and ex.params["email"] == ["a@b.c"] and ex.params["nested.pw"] == ["x"]
    assert ex.hostname == "localhost"


def test_unparseable_request():
    assert build_exchange("garbage", "") is None
    assert build_exchange("GET / HTTP/1.1\r\n\r\n", "") is None  # no host


def test_parse_history_item_variants():
    r, s = raw(), resp(body="hi")
    assert parse_history_item(item(r, s)).response == s
    assert parse_history_item(json.dumps({"request": {"raw": r}, "response": {"raw": s}})).request == r
    assert parse_history_item("Proxy history access denied") is None
    assert parse_history_item(r).request == r.strip()


def test_scope_matching():
    ex = build_exchange(raw(host="localhost:3000"), resp())
    assert in_scope(ex, ["localhost:3000"]) and in_scope(ex, ["localhost"]) and in_scope(ex, ["*host"])
    assert not in_scope(ex, ["example.com"]) and not in_scope(ex, [])


def test_llm_eligibility():
    assert llm_eligible(build_exchange(raw(), resp(body='{"a":1}')))
    assert not llm_eligible(build_exchange(raw(path="/a.png"), resp(body="x", ctype="image/png")))
    assert not llm_eligible(build_exchange(raw(path="/m.js"), resp(body="x", ctype="application/javascript")))
    assert not llm_eligible(build_exchange(raw(), resp(body="")))


def test_store_dedupe_and_update(tmp_path):
    s = Store(tmp_path / "t.db")
    f = {"dedupe_key": "k", "source": "check", "type": "t", "title": "T", "severity": "low"}
    fid = s.add_finding(f)
    assert fid and s.add_finding(f) is None
    out = s.update_finding(fid, status="confirmed", notes="verified")
    assert out["status"] == "confirmed" and out["notes"] == "verified"
    with pytest.raises(ValueError):
        s.update_finding(fid, status="bogus")
    assert s.stats()["by_status"] == {"confirmed": 1}
    assert s.backup(tmp_path / "bk").exists()


# ---- LLM evidence validation ------------------------------------------------
async def test_triage_discards_unquoted_evidence(monkeypatch):
    ex = build_exchange(raw(path="/api/Users/7"), resp(body='{"id":7,"email":"jim@juice-sh.op"}'))
    answer = {"findings": [
        {"type": "idor_candidate", "title": "Sequential user id", "severity": "medium", "confidence": "medium",
         "evidence_quote": '"id":7,"email":"jim@juice-sh.op"', "explanation": "e", "recommendation": "r"},
        {"type": "injection_candidate", "title": "Hallucinated SQLi", "severity": "high", "confidence": "high",
         "evidence_quote": "SELECT * FROM users WHERE", "explanation": "e", "recommendation": "r"},
    ]}

    async def fake_chat(messages, fmt=None, client=None):
        assert fmt is not None and messages[0]["role"] == "system"
        return {"message": {"content": json.dumps(answer)}, "eval_count": 10, "total_duration": 2_000_000_000}

    monkeypatch.setattr(ollama_client, "_chat", fake_chat)
    res = await ollama_client.triage(ex)
    assert [f.title for f in res.findings] == ["Sequential user id"]
    assert res.discarded == 1 and res.timings.total_s == 2.0


async def test_triage_bad_json(monkeypatch):
    async def fake_chat(messages, fmt=None, client=None):
        return {"message": {"content": "not json"}}
    monkeypatch.setattr(ollama_client, "_chat", fake_chat)
    res = await ollama_client.triage(build_exchange(raw(), resp(body="{}")))
    assert res.error and not res.findings


def test_prompt_marks_traffic_untrusted_and_truncates(monkeypatch):
    monkeypatch.setattr(settings, "max_body_chars", 50)
    ex = build_exchange(raw(), resp(body="A" * 500))
    p = ollama_client.build_user_prompt(ex)
    assert "<traffic>" in p and "[truncated]" in p and "A" * 51 not in p
    assert "UNTRUSTED" in ollama_client.SYSTEM_PROMPT


# ---- pipeline ---------------------------------------------------------------
class FakeBurp:
    def __init__(self, items):
        self.items = items

    async def history(self, count, offset=0, regex=None):
        return self.items[offset: offset + count]


class FakeLLM:
    calls = 0

    async def triage(self, ex):
        FakeLLM.calls += 1
        f = ollama_client.LLMFinding(type="idor_candidate", title="IDOR?", severity="medium",
                                     confidence="low", evidence_quote="user id 7", explanation="e")
        return ollama_client.TriageResult(findings=[f])


async def test_pipeline_scope_dedupe_incremental_llm(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "history_page_size", 2)
    html = resp(ctype="text/html", body="<html>hi</html>")
    items = [
        item(raw(path="/a"), html), item(raw(path="/a"), html),              # duplicate
        item(raw(path="/b", host="other.example"), html),                    # out of scope
        item(raw(path="/api/x"), resp(body='{"k":1}')),
        "Proxy history access denied",                                       # unparseable
    ]
    store = Store(tmp_path / "p.db")
    pipe = Pipeline(store, FakeBurp(items), llm=FakeLLM())
    job = Job()
    await pipe.scan_burp(job, 50, 0, ["localhost:3000"], use_llm=True)
    assert job.status == "done", job.error
    assert (job.fetched, job.in_scope, job.out_of_scope, job.unparsed) == (5, 2, 1, 1)
    assert not any("other.example" in (f["url"] or "") for f in store.list_findings())
    assert job.llm_done == 2 and FakeLLM.calls == 2

    # re-scan: nothing new, LLM not re-run
    job2 = Job()
    await pipe.scan_burp(job2, 50, 0, ["localhost:3000"], use_llm=True)
    assert job2.new_findings == 0 and FakeLLM.calls == 2


async def test_pipeline_reports_approval_hint(tmp_path):
    pipe = Pipeline(Store(tmp_path / "p.db"), FakeBurp(["Proxy history access denied"]), llm=FakeLLM())
    job = Job()
    await pipe.scan_burp(job, 10, 0, ["localhost:3000"], use_llm=False)
    assert job.unparsed == 1 and any("approve" in w for w in job.warnings)


# ---- Burp may return many items inside ONE text block --------------------------
def test_split_history_texts_variants():
    from services.burp_mcp import split_history_texts
    a, b = item(raw(path="/a"), resp(body="1")), item(raw(path="/b"), resp(body="2"))
    assert split_history_texts(a) == [a]
    assert split_history_texts(a + "\n\n" + b) == [a, b]            # blank-line separated
    assert split_history_texts(a + b) == [a, b]                      # directly concatenated
    assert split_history_texts("[" + a + "," + b + "]") == [a, b]    # JSON array
    assert split_history_texts("Proxy history access denied") == ["Proxy history access denied"]
    assert split_history_texts("   ") == []


def test_parse_tolerates_raw_control_chars():
    bad = '{"request": "GET / HTTP/1.1\r\nHost: localhost:3000\r\n\r\n", "response": "HTTP/1.1 200 OK\r\n\r\nx"}'
    assert parse_history_item(bad) is not None  # literal CR/LF inside strings (invalid strict JSON)


async def test_pipeline_expands_joined_block(tmp_path):
    html = resp(ctype="text/html", body="<html>hi</html>")
    block = "\n\n".join(item(raw(path=f"/p{i}"), html) for i in range(4))
    pipe = Pipeline(Store(tmp_path / "j.db"), FakeBurp([block]), llm=FakeLLM())
    job = Job()
    await pipe.scan_burp(job, 50, 0, ["localhost:3000"], use_llm=False)
    assert (job.fetched, job.in_scope, job.unparsed) == (4, 4, 0)
