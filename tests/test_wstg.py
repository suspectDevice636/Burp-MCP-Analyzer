"""WSTG v4.2: catalog, tagging, coverage, new passive checks, API and report."""
import sqlite3

import pytest

from services import checks, wstg
from services.httpmsg import build_exchange
from services.report import build_report
from services.store import Store
from tests.conftest import raw, resp


def run(req, res, fn):
    return fn(build_exchange(req, res))


# ------------------------------------------------------------- catalog
def test_catalog_matches_v42():
    assert len(wstg.TESTS) == 97
    assert wstg.TESTS["ATHZ-04"].startswith("Insecure direct object")
    assert wstg.normalize_id("wstg-sess-02") == "SESS-02"
    assert wstg.normalize_id("SESS-99") is None
    assert wstg.parse_tags("ATHZ-04, wstg-sess-02,ATHZ-04") == ["ATHZ-04", "SESS-02"]
    with pytest.raises(ValueError):
        wstg.parse_tags("NOPE-01")


@pytest.mark.parametrize("ftype,title,expected", [
    ("cookie_flags", "Cookie x missing Secure flag", ["SESS-02"]),
    ("missing_header", "No clickjacking protection (X-Frame-Options / frame-ancestors)", ["CLNT-09"]),
    ("missing_header", "Missing Strict-Transport-Security header", ["CONF-07"]),
    ("info_disclosure", "X-Powered-By header discloses technology", ["INFO-08"]),
    ("info_disclosure", "Server header discloses version", ["INFO-02"]),
    ("verbose_error", "Verbose error disclosed: Python stack trace", ["ERRH-02"]),
    ("verbose_error", "Verbose error disclosed: MySQL error message", ["ERRH-01"]),
    ("idor_lead", "x", ["ATHZ-04"]),
    ("injection_candidate", "x", []),          # no honest single match: tag by hand
])
def test_tags_for(ftype, title, expected):
    assert wstg.tags_for(ftype, title) == expected


# ---------------------------------------------------------- new checks
def test_secret_in_url_query():
    c = run(raw(path="/api/export?token=abcdef123456&page=1"), resp(body="{}"), checks.check_secrets_in_url)
    assert [x.type for x in c] == ["url_sensitive_data"] and "abcdef123456" not in c[0].evidence
    assert not run(raw(path="/socket.io/?EIO=4&sid=abcdef123456"), resp(body="0"), checks.check_secrets_in_url)
    assert not run(raw(path="/x?token=abc"), resp(body="{}"), checks.check_secrets_in_url)  # too short to be real


def test_cache_control_only_for_authenticated_personal_data():
    req = raw(path="/api/account", headers={"Cookie": "sid=abc"})
    body = '{"email":"a@b.co"}'
    assert run(req, resp(body=body), checks.check_cache_control)[0].type == "cache_control_missing"
    assert not run(req, resp(body=body, headers={"Cache-Control": "no-store"}), checks.check_cache_control)
    assert not run(raw(path="/api/account"), resp(body=body), checks.check_cache_control)  # anonymous


def test_source_map_and_comments():
    js = resp(ctype="application/javascript", body="var a=1;\n//# sourceMappingURL=app.js.map")
    assert run(raw(path="/app.js"), js, checks.check_source_map)[0].severity == "info"
    smap = resp(body='{"version":3,"mappings":"AAAA"}')
    assert run(raw(path="/app.js.map"), smap, checks.check_source_map)[0].severity == "low"
    html = resp(ctype="text/html", body="<html><!-- TODO remove admin password before launch --></html>")
    assert run(raw(path="/"), html, checks.check_html_comments)[0].type == "html_comment_leak"
    assert not run(raw(path="/"), resp(ctype="text/html", body="<html><!-- nav --></html>"), checks.check_html_comments)


def test_csrf_lead_conditions():
    form = {"Cookie": "sid=abc", "Content-Type": "application/x-www-form-urlencoded"}
    lead = run(raw(method="POST", path="/account/email", headers=form, body="email=x%40y.z"),
               resp(status=200, body="ok"), checks.check_csrf_lead)
    assert lead and lead[0].type == "csrf_lead"
    assert not run(raw(method="POST", path="/account/email", headers=form, body="email=x&csrf_token=1"),
                   resp(body="ok"), checks.check_csrf_lead)
    assert not run(raw(method="POST", path="/login", headers=form, body="u=a"), resp(body="ok"), checks.check_csrf_lead)
    json_req = {"Cookie": "sid=abc", "Content-Type": "application/json"}
    assert not run(raw(method="POST", path="/api/x", headers=json_req, body="{}"), resp(body="ok"), checks.check_csrf_lead)


def test_session_not_rotated_at_login():
    req = raw(method="POST", path="/login", headers={"Cookie": "PHPSESSID=abc123"}, body="u=a&p=b")
    assert run(req, resp(status=302, headers={"Location": "/home"}), checks.check_session_rotation)[0].type == "session_not_rotated"
    rotated = resp(status=302, headers={"Location": "/home", "Set-Cookie": "PHPSESSID=new999; Path=/"})
    assert not run(req, rotated, checks.check_session_rotation)
    assert not run(raw(method="POST", path="/login", body="u=a"), resp(status=302), checks.check_session_rotation)
    assert not run(req, resp(status=401), checks.check_session_rotation)


def test_trace_method():
    c = run(raw(method="OPTIONS", path="/"), resp(headers={"Allow": "GET, HEAD, TRACE"}), checks.check_http_methods)
    assert c[0].type == "http_methods"
    assert not run(raw(method="OPTIONS", path="/"), resp(headers={"Allow": "GET, POST"}), checks.check_http_methods)


# -------------------------------------------------------------- coverage
def test_exercised_only_counts_relevant_traffic():
    plain = build_exchange(raw(path="/api/x"), resp(body='{"a":1}'))
    assert "SESS-02" not in wstg.exercised(plain)
    cookie = build_exchange(raw(path="/"), resp(headers={"Set-Cookie": "sid=1; HttpOnly"}, body="{}"))
    assert "SESS-02" in wstg.exercised(cookie)
    idor = build_exchange(raw(path="/rest/basket/6", headers={"Cookie": "sid=1"}), resp(body='{"id":6}'))
    assert "ATHZ-04" in wstg.exercised(idor)


def test_build_view_statuses():
    findings = [{"wstg": "SESS-02", "status": "candidate"}, {"wstg": "CONF-07", "status": "dismissed"}]
    view = wstg.build_view(findings, {"SESS-02": 3, "CONF-07": 5, "INFO-02": 4},
                           {"ATHN-02": {"status": "tested", "note": "default creds fail"},
                            "CONF-10": {"status": "na", "note": ""}})
    by = {t["id"]: t for c in view["categories"] for t in c["tests"]}
    assert by["SESS-02"]["status"] == "findings" and by["SESS-02"]["open"] == 1
    assert by["CONF-07"]["status"] == "clear"       # only dismissed findings, and traffic was examined
    assert by["INFO-02"]["status"] == "clear"
    assert by["ATHN-02"]["status"] == "tested" and by["CONF-10"]["status"] == "na"
    assert by["INPV-05"]["status"] == "untested"
    assert by["INFO-01"]["status"] == "untested" and not by["INFO-01"]["automated"]
    assert sum(view["summary"].values()) == 97


def test_clear_requires_traffic_for_automated_tests():
    view = wstg.build_view([], {}, {})
    by = {t["id"]: t for c in view["categories"] for t in c["tests"]}
    assert by["SESS-02"]["status"] == "untested"     # nothing examined, so never "clear"


# ----------------------------------------------------- store + migration
def test_findings_are_tagged_and_filterable(tmp_path):
    st = Store(tmp_path / "a.db")
    base = dict(source="check", severity="low", url="u", method="GET")
    st.add_finding(dict(base, dedupe_key="1", type="cookie_flags", title="Cookie x missing Secure flag"))
    st.add_finding(dict(base, dedupe_key="2", type="injection_candidate", title="Odd"))
    assert [f["type"] for f in st.list_findings(wstg_id="SESS-02")] == ["cookie_flags"]
    odd = [f for f in st.list_findings() if f["type"] == "injection_candidate"][0]
    assert odd["wstg"] == ""
    assert st.update_finding(odd["id"], wstg=["INPV-05"])["wstg"] == "INPV-05"
    with pytest.raises(ValueError):
        st.update_finding(odd["id"], wstg=["BOGUS-1"])


def test_old_database_is_tagged_on_upgrade(tmp_path):
    path = tmp_path / "old.db"
    db = sqlite3.connect(path)
    db.executescript("""CREATE TABLE findings (id TEXT PRIMARY KEY, item_id TEXT, dedupe_key TEXT NOT NULL UNIQUE,
        source TEXT NOT NULL, type TEXT NOT NULL, title TEXT NOT NULL, severity TEXT NOT NULL,
        confidence TEXT NOT NULL DEFAULT 'medium', method TEXT, url TEXT, evidence TEXT NOT NULL DEFAULT '',
        description TEXT NOT NULL DEFAULT '', recommendation TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'candidate', notes TEXT NOT NULL DEFAULT '',
        report_text TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
        INSERT INTO findings (id, dedupe_key, source, type, title, severity, created_at, updated_at)
        VALUES ('f1','k','check','idor_lead','Lead','info','now','now');""")
    db.commit(); db.close()
    assert Store(path).get_finding("f1")["wstg"] == "ATHZ-04"


# --------------------------------------------------------------- API
def seed(api):
    import main
    store = main.app.state.engagements.store(api.headers["X-Engagement"])
    ex = build_exchange(raw(path="/"), resp(headers={"Set-Cookie": "sid=abcdef; Path=/"}, body="{}"))
    return store, ex


def test_coverage_api_builds_from_existing_items_and_takes_notes(api):
    store, ex = seed(api)
    store.upsert_item(ex)                      # stored before any coverage was counted
    data = api.get("/api/wstg").json()
    by = {t["id"]: t for c in data["categories"] for t in c["tests"]}
    assert by["SESS-02"]["requests"] == 1 and by["SESS-02"]["status"] == "clear"
    r = api.put("/api/wstg/ATHN-02", json={"status": "tested", "note": "default creds rejected"})
    assert r.status_code == 200
    by = {t["id"]: t for c in api.get("/api/wstg").json()["categories"] for t in c["tests"]}
    assert by["ATHN-02"]["status"] == "tested" and by["ATHN-02"]["manual"]["note"] == "default creds rejected"
    assert api.put("/api/wstg/NOPE-01", json={"status": "na"}).status_code == 404
    assert api.put("/api/wstg/ATHN-02", json={"status": "bogus"}).status_code == 422


def test_scan_counts_coverage_once_per_distinct_request(api):
    from services.pipeline import Pipeline
    store, ex = seed(api)
    p = Pipeline(store, burp=None)
    p.analyze_deterministic(ex)
    p.analyze_deterministic(ex)                # re-ingesting the same request must not double count
    assert store.coverage().get("SESS-02") == 1


def test_finding_patch_validates_wstg_and_filter(api):
    store, ex = seed(api)
    from services.pipeline import Pipeline
    Pipeline(store, burp=None).analyze_deterministic(ex)
    fid = api.get("/api/findings?wstg=SESS-02").json()["findings"][0]["id"]
    assert api.patch(f"/api/findings/{fid}", json={"wstg": ["BOGUS-1"]}).status_code == 400
    assert api.patch(f"/api/findings/{fid}", json={"wstg": ["SESS-02", "SESS-03"]}).json()["wstg"] == "SESS-02,SESS-03"
    assert api.get("/api/findings?wstg=nope").status_code == 400


def test_pentest_report_has_wstg_refs_and_optional_appendix(api):
    store, ex = seed(api)
    from services.pipeline import Pipeline
    Pipeline(store, burp=None).analyze_deterministic(ex)
    for f in store.list_findings():
        store.update_finding(f["id"], status="confirmed")
    plain = api.get("/api/report?format=pentest").text
    assert "**WSTG:** WSTG-SESS-02: Cookies attributes" in plain and "Appendix" not in plain
    full = api.get("/api/report?format=pentest&coverage=true").text
    assert "Appendix: OWASP WSTG v4.2 coverage" in full and "| WSTG-INFO-01 |" in full
    assert "Not tested" in full
    bounty = api.get("/api/report?format=bounty&coverage=true").text
    assert "WSTG" not in bounty
