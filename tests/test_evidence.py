"""Evidence quality: bare-header quotes, upload claims, the weak-evidence flag, and old-DB migration."""
import sqlite3

import pytest

from services import ollama_client
from services.httpmsg import build_exchange
from services.pipeline import Pipeline
from services.store import Store
from tests.conftest import raw, resp


def F(**kw):
    base = dict(type="other", title="File upload accepts any image type", severity="medium",
                confidence="high", evidence_quote="Content-Type: image/jpeg",
                explanation="Server returns an image content type", recommendation="r")
    base.update(kw)
    return ollama_client.LLMFinding(**base)


def photo_ex(request_ctype="application/json"):
    return build_exchange(raw(method="POST", path="/profile/image", headers={"Content-Type": request_ctype},
                              body="x=1"), resp(ctype="image/jpeg", body="JFIF-binary"))


def test_bare_header_evidence_rejected_for_behavior_claims():
    f = F(title="Image served without validation", explanation="served an image")
    assert ollama_client.gate(f, photo_ex()) == "evidence_is_bare_header"


def test_upload_claim_needs_an_upload_request():
    f = F(type="auth_issue", evidence_quote="JFIF-binary", title="Unrestricted file upload")
    assert ollama_client.gate(f, photo_ex()) == "upload_claim_without_upload_request"


def test_upload_claim_with_multipart_request_is_kept():
    f = F(type="auth_issue", evidence_quote="JFIF-binary", title="Unrestricted file upload")
    ex = photo_ex("multipart/form-data; boundary=xyz")
    assert ollama_client.gate(f, ex) is None


@pytest.mark.parametrize("quote,weak", [
    ("Content-Type: image/jpeg", True),            # bare header
    ("short quote", True),                         # under 20 chars
    ('{"role":"admin","email":"a@b.co"}', False),  # real data from the response
])
def test_weak_evidence_flag(quote, weak):
    ex = build_exchange(raw(path="/api/me"), resp(body='{"role":"admin","email":"a@b.co"}',
                                                  headers={"X-Note": "short quote here"}))
    assert ollama_client.weak_evidence(F(type="auth_issue", evidence_quote=quote), ex) is weak


def test_request_only_quote_is_weak():
    ex = build_exchange(raw(method="POST", path="/api/x", body='{"name":"payload-in-request-only"}'),
                        resp(body="{}"))
    assert ollama_client.weak_evidence(F(type="auth_issue", evidence_quote='{"name":"payload-in-request-only"}'), ex)


async def test_pipeline_stores_weak_flag(tmp_path):
    ex = build_exchange(raw(path="/api/me"), resp(body='{"a":1}', headers={"X-Debug": "on-in-production"}))
    st = Store(tmp_path / "a.db")
    st.upsert_item(ex)
    f = F(type="auth_issue", title="Debug header exposed in production", evidence_quote="X-Debug: on-in-production")
    # header evidence on an auth_issue passes the gate but is flagged weak

    class Fake:
        async def triage(self, e):
            ok = ollama_client.gate(f, e)
            assert ok is None
            return ollama_client.TriageResult(findings=[f])

    class Burp: ...
    p = Pipeline(st, Burp(), llm=Fake())
    await p.analyze_llm(ex)
    row = st.list_findings()[0]
    assert row["evidence_quality"] == "weak"


def test_old_database_gets_evidence_quality_column(tmp_path):
    path = tmp_path / "old.db"
    db = sqlite3.connect(path)
    db.executescript("""CREATE TABLE findings (id TEXT PRIMARY KEY, item_id TEXT, dedupe_key TEXT NOT NULL UNIQUE,
        source TEXT NOT NULL, type TEXT NOT NULL, title TEXT NOT NULL, severity TEXT NOT NULL,
        confidence TEXT NOT NULL DEFAULT 'medium', method TEXT, url TEXT, evidence TEXT NOT NULL DEFAULT '',
        description TEXT NOT NULL DEFAULT '', recommendation TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'candidate', notes TEXT NOT NULL DEFAULT '',
        report_text TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
        INSERT INTO findings (id, dedupe_key, source, type, title, severity, created_at, updated_at)
        VALUES ('f1','k','check','t','Old finding','low','now','now');""")
    db.commit(); db.close()
    st = Store(path)
    assert st.get_finding("f1")["evidence_quality"] == ""


def test_detail_endpoint_returns_item_and_quality(api):
    from tests.conftest import item
    ex = photo_ex()
    # seed through the engagement's store
    import main
    eid = api.headers["X-Engagement"]
    store = main.app.state.engagements.store(eid)
    store.upsert_item(ex)
    fid = store.add_finding({"item_id": ex.id, "dedupe_key": "d1", "source": "llm", "type": "other",
                             "title": "Thin one", "severity": "low", "url": ex.url, "method": "POST",
                             "evidence": "Content-Type: image/jpeg", "evidence_quality": "weak"})
    d = api.get(f"/api/findings/{fid}").json()
    assert d["evidence_quality"] == "weak"
    assert "Content-Type: image/jpeg" in d["item"]["raw_response"]
