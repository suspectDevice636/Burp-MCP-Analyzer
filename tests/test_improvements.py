import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from config.config import settings
from services import checks, ollama_client
from services.httpmsg import build_exchange
from services.pipeline import Job, Pipeline, llm_eligible
from services.store import Store
from tests.conftest import item, raw, resp


# ============================================================ 1. LLM noise
def F(**kw):
    base = dict(type="info_disclosure", title="Admin config returned without auth", severity="medium",
                confidence="high", evidence_quote="placeholder quote", explanation="e", recommendation="r")
    base.update(kw)
    return ollama_client.LLMFinding(**base)


def make_ex(path="/api/x", body='{"email":"jim@juice-sh.op","token":"abc123abc123"}'):
    return build_exchange(raw(path=path), resp(body=body))


@pytest.mark.parametrize("finding,reason", [
    (F(evidence_quote="short"), "evidence_too_short"),
    (F(evidence_quote="this text is not in the traffic at all"), "evidence_not_in_traffic"),
    (F(evidence_quote="GET /api/x"), "evidence_is_request_line"),
    (F(type="idor_candidate", evidence_quote="Host: localhost:3000"), "idor_evidence_not_in_response"),
    (F(title="Potential Information Disclosure", evidence_quote='"email":"jim@juice-sh.op"'), "generic_title"),
    (F(title="Possible IDOR (Insecure Direct Object Reference)", evidence_quote='"email":"jim@juice-sh.op"'), "generic_title"),
    (F(severity="info", evidence_quote='"email":"jim@juice-sh.op"'), "info_only"),
])
def test_gate_reasons(finding, reason):
    assert ollama_client.gate(finding, make_ex()) == reason


def test_gate_accepts_specific_supported_finding():
    f = F(evidence_quote='"email":"jim@juice-sh.op"')
    assert ollama_client.gate(f, make_ex()) is None


def test_severity_cap(monkeypatch):
    monkeypatch.setattr(settings, "llm_severity_cap", "medium")
    a = F(severity="critical", confidence="high"); ollama_client.cap_severity(a)
    b = F(severity="high", confidence="medium"); ollama_client.cap_severity(b)
    c = F(severity="low", confidence="high"); ollama_client.cap_severity(c)
    assert (a.severity, b.severity, c.severity) == ("medium", "low", "low")
    monkeypatch.setattr(settings, "llm_severity_cap", "low")
    d = F(severity="critical", confidence="high"); ollama_client.cap_severity(d)
    assert d.severity == "low"


def test_skip_paths_not_sent_to_model():
    assert not llm_eligible(build_exchange(raw(path="/socket.io/?EIO=4"), resp(body='0{"sid":"x"}')))
    assert llm_eligible(build_exchange(raw(path="/api/Users"), resp(body='{"a":1}')))


class FakeLLM:
    def __init__(self, findings):
        self.findings = findings

    async def triage(self, ex):
        return ollama_client.TriageResult(findings=self.findings, discard_reasons={"generic_title": 2})


async def test_pipeline_drops_duplicates_of_checks_and_reports_reasons(tmp_path):
    ex = build_exchange(raw(path="/ftp"), resp(ctype="text/html", body="<title>listing directory /ftp</title>"))
    store = Store(tmp_path / "d.db")
    llm = FakeLLM([
        F(type="info_disclosure", title="Directory contents exposed at /ftp", severity="low",
          evidence_quote="<title>listing directory /ftp</title>"),
        F(type="other", title="Something genuinely new here", severity="low",
          evidence_quote="a different quote entirely"),
    ])
    pipe = Pipeline(store, burp=None, llm=llm)
    pipe.analyze_deterministic(ex)                      # directory_listing check stores evidence
    job = Job()
    await pipe.analyze_llm(ex, job)
    titles = [f["title"] for f in store.list_findings(source="llm")]
    assert titles == ["Something genuinely new here"]   # duplicate of the check was dropped
    assert job.llm_discard_reasons == {"generic_title": 2, "duplicate_of_check": 1}
    assert job.llm_discarded == 3


# ======================================================== 2. smarter checks
def run(req, res):
    return {c.type: c for c in checks.run_checks(build_exchange(req, res))}


def test_unauthenticated_admin_endpoint_flagged():
    body = json.dumps({"config": {"server": {"port": 3000}, "googleOauth": {"clientId": "abc"}}})
    found = run(raw(path="/rest/admin/application-configuration"), resp(body=body))
    assert found["unauthenticated_access"].severity == "medium"


def test_unauthenticated_admin_with_secretish_keys_is_high():
    found = run(raw(path="/admin/config"), resp(body='{"database":{"password":"hunter2hunter2"}}'))
    assert found["unauthenticated_access"].severity == "high"


def test_admin_endpoint_not_flagged_when_credentials_sent_or_html_shell():
    body = '{"config": {"server": {"port": 3000}}, "more": "data here"}'
    assert "unauthenticated_access" not in run(raw(path="/rest/admin/x", headers={"Authorization": "Bearer t"}), resp(body=body))
    assert "unauthenticated_access" not in run(raw(path="/rest/admin/x", headers={"Cookie": "a=b"}), resp(body=body))
    assert "unauthenticated_access" not in run(raw(path="/admin"), resp(ctype="text/html", body="<app-root>" + "x" * 50))
    assert "unauthenticated_access" not in run(raw(path="/api/products"), resp(body=body))  # not an admin path


def test_account_enumeration_message_and_lookup():
    found = run(raw(method="POST", path="/rest/user/login"), resp(401, body='{"error":"User does not exist"}'))
    assert found["account_enumeration"].confidence == "medium"
    found = run(raw(path="/rest/user/security-question?email=admin@juice-sh.op"),
                resp(body='{"question":{"id":2,"question":"Mother\'s maiden name?"}}'))
    assert found["account_enumeration"].confidence == "low"
    # plain wrong-password wording is not enumeration
    found = run(raw(method="POST", path="/rest/user/login"), resp(401, body="Invalid email or password."))
    assert "account_enumeration" not in found


def test_path_template():
    assert checks.path_template("/rest/basket/6/items/2") == ("/rest/basket/{id}/items/{id}", ["6", "2"])
    assert checks.path_template("/api/Users/abc")[1] == []


def ex_auth(path, token, body='{"id":1}', method="GET"):
    return build_exchange(raw(method=method, path=path, headers={"Authorization": f"Bearer {token}"}), resp(body=body))


def test_idor_lead_groups_by_template_and_counts_credentials():
    exs = [
        ex_auth("/rest/basket/1", "userA", '{"data":{"UserId":1,"id":1}}'),
        ex_auth("/rest/basket/2", "userB", '{"data":{"UserId":2,"id":2}}'),
        ex_auth("/rest/basket/3", "userA"),
        build_exchange(raw(path="/rest/basket/9"), resp(body='{"id":9}')),     # no credentials: ignored
        ex_auth("/rest/products/search", "userA"),                              # no id: ignored
    ]
    leads = checks.cross_request_checks(exs)
    assert len(leads) == 1
    c = leads[0][1]
    assert c.type == "idor_lead" and c.severity == "info" and "{id}" in c.title
    assert "Distinct credentials in capture: 2" in c.evidence and "1, 2, 3" in c.evidence
    assert c.confidence == "medium"   # response has ownership fields (UserId)


def test_idor_lead_query_param_and_pipeline_stores_once(tmp_path):
    ex = build_exchange(raw(path="/api/orders?userId=7", headers={"Cookie": "s=1"}), resp(body='{"email":"a@b.co"}'))
    store = Store(tmp_path / "x.db")
    pipe = Pipeline(store, burp=None)
    assert pipe.analyze_cross_request([ex]) == 1
    assert pipe.analyze_cross_request([ex]) == 0     # de-duplicated
    assert store.list_findings(source="check")[0]["type"] == "idor_lead"


# ============================================================== 3. review UI
@pytest.fixture
def client(api):
    return api


def test_ui_served_with_strict_csp(client):
    r = client.get("/ui/")
    assert r.status_code == 200 and "<title>Burp MCP Analyzer" in r.text
    csp = r.headers["content-security-policy"]
    assert "default-src 'none'" in csp and "script-src 'self'" in csp and "'unsafe-inline'" not in csp
    assert r.headers["x-content-type-options"] == "nosniff"
    assert client.get("/ui/app.js").status_code == 200 and client.get("/ui/style.css").status_code == 200
    assert "content-security-policy" not in client.get("/api/findings").headers  # API untouched


def test_ui_page_needs_no_inline_code_or_external_resources():
    html = Path("ui/index.html").read_text()
    assert not re.search(r"<script(?![^>]*\bsrc=)", html)          # no inline scripts
    assert not re.search(r"\son\w+\s*=", html)                      # no inline handlers
    assert not re.search(r"""(src|href)\s*=\s*["']https?://""", html)  # nothing loaded from the internet


def test_ui_js_never_renders_untrusted_data_as_html():
    js = "\n".join(l for l in Path("ui/app.js").read_text().splitlines() if not l.strip().startswith("//"))
    for banned in (r"\.innerHTML", r"\.outerHTML", r"insertAdjacentHTML", r"document\.write", r"\beval\(", r"new Function"):
        assert not re.search(banned, js), banned


def test_ui_data_comes_only_through_token_protected_api(client, monkeypatch):
    monkeypatch.setattr(settings, "api_token", "s3cret")
    assert client.get("/ui/").status_code == 200                    # page itself holds no data
    assert client.get("/api/findings").status_code == 401
