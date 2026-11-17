import sqlite3
from pathlib import Path

import pytest

from services import ollama_client
from services.engagements import EngagementError, EngagementManager
from services.report import build_report, cwe_for
from tests.conftest import raw, resp


def F(**kw):
    base = dict(id="f1", type="open_redirect", title="Redirect to attacker-supplied URL via 'to'", severity="medium",
                confidence="medium", method="GET", url="http://app.test/redirect?to=https://evil.example",
                evidence="Request param to=https://evil.example; Location: https://evil.example",
                description="The application redirects to a URL taken from user input.",
                recommendation="Only redirect to an allow-list of destinations.", notes="", report_text="")
    base.update(kw)
    return base


# ============================================================ engagement type
def test_kind_defaults_validates_and_can_change(tmp_path):
    m = EngagementManager(tmp_path)
    assert m.create("A")["kind"] == "pentest"
    b = m.create("B", kind="bounty")
    assert b["kind"] == "bounty"
    with pytest.raises(EngagementError):
        m.create("C", kind="redteam")
    assert m.update(b["id"], kind="pentest")["kind"] == "pentest"
    with pytest.raises(EngagementError):
        m.update(b["id"], kind="nope")
    m.close()


def test_registry_created_before_types_existed_is_migrated(tmp_path):
    db = sqlite3.connect(tmp_path / "registry.db")
    db.executescript("""
        CREATE TABLE engagements (id TEXT PRIMARY KEY, name TEXT NOT NULL, client TEXT NOT NULL DEFAULT '',
            scope TEXT NOT NULL DEFAULT '[]', notes TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'active',
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL, last_opened TEXT);
        INSERT INTO engagements (id, name, created_at, updated_at) VALUES ('e0000000a','Old one','2026-01-01','2026-01-01');
    """)
    db.commit(); db.close()
    m = EngagementManager(tmp_path)
    assert m.get("e0000000a")["kind"] == "pentest"          # existing engagements keep the pentest layout
    EngagementManager(tmp_path).close()                      # reopening is idempotent
    m.close()


def test_api_type_roundtrip_and_validation(api):
    r = api.post("/api/engagements", json={"name": "Program X", "scope": ["x.test"], "kind": "bounty"}, headers={})
    assert r.status_code == 201 and r.json()["kind"] == "bounty"
    assert api.post("/api/engagements", json={"name": "Plain"}, headers={}).json()["kind"] == "pentest"
    assert api.post("/api/engagements", json={"name": "Bad", "kind": "redteam"}, headers={}).status_code == 422
    eid = r.json()["id"]
    assert {e["kind"] for e in api.get("/api/engagements", headers={}).json()["engagements"]} == {"pentest", "bounty"}
    assert api.patch(f"/api/engagements/{eid}", json={"kind": "pentest"}, headers={}).json()["kind"] == "pentest"
    assert api.patch(f"/api/engagements/{eid}", json={"kind": "x"}, headers={}).status_code == 422


# ============================================================== report layouts
def test_pentest_layout_has_scope_summary_and_reference():
    out = build_report([F(severity="high"), F(id="f2", type="directory_listing", title="Directory listing enabled")],
                       "Acme: Penetration Test Findings", kind="pentest", scope=["app.test", "*.test"])
    assert out.startswith("# Acme: Penetration Test Findings")
    assert "## Scope" in out and "- `app.test`" in out and "| High | 1 |" in out
    assert "**Reference:** CWE-601" in out and "**Reference:** CWE-548" in out
    assert out.index("1. Redirect") < out.index("2. Directory")            # severity order


def test_bounty_layout_is_one_self_contained_draft_per_finding():
    out = build_report([F(), F(id="f2", type="directory_listing", title="Directory listing enabled", severity="low")],
                       "Prog: Bug Bounty Submission Drafts", kind="bounty", scope=["app.test"])
    assert "separate submission draft" in out and "In-scope hosts for this program: `app.test`" in out
    assert out.count("\n---\n") == 2 and "## [1] Redirect" in out and "## [2] Directory" in out
    for heading in ("### Summary", "### Steps to reproduce", "### Impact", "### Suggested fix", "### Evidence"):
        assert out.count(heading) == 2, heading
    assert "**Weakness:** CWE-601: URL Redirection to Untrusted Site" in out
    assert "**Suggested severity:** Medium" in out and "`GET http://app.test/redirect" in out


def test_bounty_never_invents_steps_or_impact():
    out = build_report([F()], "t", kind="bounty")
    assert out.count("_TODO:") == 2                                          # steps and impact left for the tester
    steps = out.split("### Steps to reproduce")[1].split("### Impact")[0]
    assert "TODO" in steps and not any(ch.isdigit() for ch in steps.replace("1.", ""))  # no fabricated numbered steps


def test_bounty_uses_the_testers_notes_as_the_steps():
    out = build_report([F(notes="1. Log in as user A\n2. Open /redirect?to=https://evil.example")], "t", kind="bounty")
    steps = out.split("### Steps to reproduce")[1].split("### Impact")[0]
    assert "Log in as user A" in steps and "TODO" not in steps


def test_bounty_warns_only_for_classes_programs_often_reject():
    low = build_report([F(type="missing_header", title="Missing Content-Security-Policy header", severity="low")], "t", kind="bounty")
    real = build_report([F()], "t", kind="bounty")
    assert "Low-impact class" in low and "Low-impact class" not in real
    assert "Low-impact" not in build_report([F(type="missing_header")], "t", kind="pentest")   # bounty-only advice


def test_a_drafted_report_text_replaces_the_template_but_keeps_evidence():
    out = build_report([F(report_text="### Summary\nDrafted.\n### Steps to Reproduce\n1. real steps")], "t", kind="bounty")
    assert "Drafted." in out and "_TODO:" not in out and "### Evidence" in out and out.count("### Summary") == 1


def test_empty_and_invalid():
    assert "No findings match" in build_report([], "t", kind="bounty")
    assert "No findings match" in build_report([], "t", kind="pentest")
    with pytest.raises(ValueError):
        build_report([], "t", kind="other")


@pytest.mark.parametrize("ftype,title,expected", [
    ("missing_header", "Missing Content-Security-Policy header", "CWE-693"),
    ("missing_header", "No clickjacking protection (X-Frame-Options / frame-ancestors)", "CWE-1021"),
    ("missing_header", "Missing Strict-Transport-Security header", "CWE-319"),
    ("cookie_flags", "Cookie 'sid' missing HttpOnly flag", "CWE-1004"),
    ("cookie_flags", "Cookie 'sid' missing Secure flag", "CWE-614"),
    ("cookie_flags", "Cookie 'sid' missing SameSite flag", "CWE-1275"),
    ("reflected_input", "x", "CWE-79"), ("unauthenticated_access", "x", "CWE-306"),
    ("jwt_alg_none", "x", "CWE-347"), ("cors_misconfiguration", "x", "CWE-942"),
])
def test_cwe_mapping(ftype, title, expected):
    assert cwe_for({"type": ftype, "title": title}).startswith(expected)
    assert cwe_for({"type": "something_new", "title": "x"}) is None


# =================================================================== the routes
def _confirmed(api, headers):
    api.post("/api/analyze", json={"request": raw(path="/redirect?to=https://evil.example"),
                                   "response": resp(302, headers={"Location": "https://evil.example"}, ctype="text/html")}, headers=headers)
    f = next(x for x in api.get("/api/findings", headers=headers).json()["findings"] if x["type"] == "open_redirect")
    api.patch(f"/api/findings/{f['id']}", json={"status": "confirmed"}, headers=headers)
    return f["id"]


def test_report_format_follows_the_engagement_type_and_can_be_overridden(api):
    bounty = api.post("/api/engagements", json={"name": "Prog", "client": "ProgCo", "scope": ["localhost:3000"],
                                                "kind": "bounty"}, headers={}).json()
    bh = {"X-Engagement": bounty["id"]}
    _confirmed(api, {}), _confirmed(api, bh)

    pent = api.get("/api/report").text                         # 'Acme' is a pentest
    assert pent.startswith("# Acme Corp: Penetration Test Findings") and "## Scope" in pent

    bnt = api.get("/api/report", headers=bh).text
    assert bnt.startswith("# ProgCo: Bug Bounty Submission Drafts") and "## [1]" in bnt and "TODO" in bnt

    assert "## [1]" in api.get("/api/report", params={"format": "bounty"}).text           # override per request
    assert "## Scope" in api.get("/api/report", params={"format": "pentest"}, headers=bh).text
    assert api.get("/api/report", params={"format": "xml"}).status_code == 422


def test_drafting_prompt_matches_the_engagement_type(api, monkeypatch):
    seen = []

    async def fake_chat(messages, fmt=None, client=None):
        seen.append(messages[0]["content"])
        return {"message": {"content": "drafted"}}
    monkeypatch.setattr(ollama_client, "_chat", fake_chat)

    bounty = api.post("/api/engagements", json={"name": "Prog", "scope": ["localhost:3000"], "kind": "bounty"}, headers={}).json()
    bh = {"X-Engagement": bounty["id"]}
    pid, bid = _confirmed(api, {}), _confirmed(api, bh)
    api.post(f"/api/findings/{pid}/draft")
    api.post(f"/api/findings/{bid}/draft", headers=bh)
    assert "**Remediation**" in seen[0] and "Steps to Reproduce" not in seen[0]
    assert "Steps to Reproduce" in seen[1] and "never invent" in seen[1] and "TODO" in seen[1]
    assert api.get(f"/api/findings/{bid}", headers=bh).json()["report_text"] == "drafted"


# ======================================================================== UI
def test_ui_asks_for_the_type_and_offers_a_report_format():
    html = Path("ui/index.html").read_text()
    assert html.count('name="eng-kind"') == 2 and 'value="pentest"' in html and 'value="bounty"' in html
    assert 'id="report-format"' in html and 'id="kind-badge"' in html
    js = Path("ui/app.js").read_text()
    assert "Choose the type of work" in js                       # no silent default when creating
    assert '"/report?format="' in js.replace("'", '"')
    assert "checked = !!e && r.value === e.kind" in js           # new engagement: nothing preselected
