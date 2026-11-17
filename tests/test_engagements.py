import re
import sqlite3
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from config.config import settings
from services.engagements import EngagementError, EngagementManager, NotFound, normalize_scope
from services.store import Store
from tests.conftest import item, raw, resp


# ============================================================ the manager
def test_scope_normalization():
    assert normalize_scope(["https://App.Acme.com/login?x=1", "*.acme.com", "app.acme.com", " 10.0.0.5:8443 ", ""]) == [
        "app.acme.com", "*.acme.com", "10.0.0.5:8443"]
    assert normalize_scope(["user:pw@host.example/path"]) == ["host.example"]
    for bad in (["*"], ["*."], ["has space"], ["bad;chars"]):
        with pytest.raises(EngagementError):
            normalize_scope(bad)


def test_lifecycle_and_unique_names(tmp_path):
    m = EngagementManager(tmp_path)
    a = m.create("Acme Corp", "Acme", ["acme.com"], "notes")
    assert re.fullmatch(r"e[0-9a-f]{8}", a["id"]) and a["status"] == "active" and a["scope"] == ["acme.com"]
    with pytest.raises(EngagementError):
        m.create("  acme   CORP ")                         # same name, ignoring case/whitespace
    b = m.create("Globex")
    with pytest.raises(EngagementError):
        m.update(b["id"], name="acme corp")
    assert m.update(b["id"], scope=["globex.io"], status="archived")["status"] == "archived"
    assert [e["name"] for e in m.list()] == ["Acme Corp", "Globex"]   # archived sorts last
    assert m.touch(a["id"])["last_opened"]
    m.delete(a["id"])
    assert m.get(a["id"]) is None and not (tmp_path / "engagements" / a["id"]).exists()
    with pytest.raises(NotFound):
        m.delete(a["id"])
    m.close()


def test_ids_are_validated_never_used_as_paths(tmp_path):
    m = EngagementManager(tmp_path)
    for evil in ("../../etc", "e00000000/../x", "", "E12345678", "e1234567"):
        assert m.get(evil) is None
    m.close()


def test_each_engagement_has_its_own_database_file(tmp_path):
    m = EngagementManager(tmp_path)
    a, b = m.create("A"), m.create("B")
    assert m.db_path(a["id"]) != m.db_path(b["id"]) and m.db_path(a["id"]).exists()
    m.store(a["id"]).add_finding({"dedupe_key": "k", "source": "check", "type": "t", "title": "T", "severity": "low"})
    assert m.summary(a["id"])["findings"] == 1 and m.summary(b["id"])["findings"] == 0
    assert m.store(b["id"]).list_findings() == []
    m.close()


def test_legacy_import(tmp_path):
    legacy = tmp_path / "analyzer.db"
    s = Store(legacy)
    s.add_finding({"dedupe_key": "k", "source": "check", "type": "t", "title": "Old finding", "severity": "high"})
    s.close()
    m = EngagementManager(tmp_path)
    e = m.import_legacy(legacy, ["localhost:3000"])
    assert e and e["name"].startswith("Imported") and e["scope"] == ["localhost:3000"]
    assert [f["title"] for f in m.store(e["id"]).list_findings()] == ["Old finding"]
    assert not legacy.exists() and (tmp_path / "analyzer.db.pre-engagements").exists()   # original kept
    assert m.import_legacy(legacy) is None                                               # only once
    m.close()


def test_empty_legacy_database_is_not_imported(tmp_path):
    Store(tmp_path / "analyzer.db").close()
    m = EngagementManager(tmp_path)
    assert m.import_legacy(tmp_path / "analyzer.db") is None and m.list() == []
    m.close()


def test_legacy_import_happens_at_startup():
    import main
    Store(settings.data_dir / "analyzer.db").add_finding(
        {"dedupe_key": "k", "source": "check", "type": "t", "title": "Carried over", "severity": "low"})
    with TestClient(main.app) as c:
        engs = c.get("/api/engagements").json()["engagements"]
        assert len(engs) == 1
        r = c.get("/api/findings", headers={"X-Engagement": engs[0]["id"]}).json()
        assert [f["title"] for f in r["findings"]] == ["Carried over"]


# ================================================================== the API
def new(api, name, scope=("localhost:3000",), **kw):
    r = api.post("/api/engagements", json={"name": name, "scope": list(scope), **kw}, headers={})
    assert r.status_code == 201, r.text
    return r.json()


def hdr(e):
    return {"X-Engagement": e["id"]}


def test_every_data_route_requires_an_explicit_engagement(api):
    anon = {"X-Engagement": ""}
    for method, path in (("get", "/api/findings"), ("get", "/api/findings/stats"), ("get", "/api/report"),
                         ("get", "/api/scan"), ("post", "/api/scan"), ("delete", "/api/queue"),
                         ("post", "/api/analyze"), ("post", "/api/backup")):
        r = getattr(api, method)(path, headers=anon)
        assert r.status_code == 400 and "No engagement selected" in r.json()["detail"], path
    assert api.get("/api/findings", headers={"X-Engagement": "e00000000"}).status_code == 404
    assert api.get("/api/findings", headers={"X-Engagement": "../../x"}).status_code == 404
    assert api.get("/api/findings", params={"engagement": api.eid}, headers=anon).status_code == 200


def test_findings_never_cross_between_clients(api):
    other = new(api, "Globex")
    r = api.post("/api/analyze", json={"request": raw(path="/ftp"),
                                       "response": resp(ctype="text/html", body="<title>listing directory /ftp</title>")})
    assert r.json()["new_findings"] >= 1
    mine = api.get("/api/findings").json()["findings"]
    theirs = api.get("/api/findings", headers=hdr(other)).json()["findings"]
    assert mine and theirs == []
    assert api.get(f"/api/findings/{mine[0]['id']}", headers=hdr(other)).status_code == 404   # not even by id
    assert api.patch(f"/api/findings/{mine[0]['id']}", json={"status": "confirmed"}, headers=hdr(other)).status_code == 404
    assert api.get("/api/report", headers=hdr(other)).text.count("listing") == 0
    assert api.get("/api/findings/stats", headers=hdr(other)).json()["items_seen"] == 0


def test_picker_summaries_and_open(api):
    api.post("/api/analyze", json={"request": raw(path="/ftp"),
                                   "response": resp(ctype="text/html", body="<title>listing directory /ftp</title>")})
    engs = api.get("/api/engagements", headers={}).json()["engagements"]
    me = next(e for e in engs if e["id"] == api.eid)
    assert me["summary"]["items"] == 1 and me["summary"]["by_status"].get("candidate", 0) >= 1 and me["running"] is False
    assert me["last_opened"] is None
    assert api.post(f"/api/engagements/{api.eid}/open", headers={}).json()["last_opened"]


def test_edit_scope_changes_what_scans_use_and_validates(api):
    e = new(api, "Initech", scope=())
    assert api.post("/api/scan", json={}, headers=hdr(e)).status_code == 400          # no scope yet
    assert api.patch(f"/api/engagements/{e['id']}", json={"scope": ["*"]}, headers={}).status_code == 400
    ok = api.patch(f"/api/engagements/{e['id']}", json={"scope": ["https://initech.test/x"]}, headers={})
    assert ok.status_code == 200 and ok.json()["scope"] == ["initech.test"]
    assert api.patch(f"/api/engagements/{e['id']}", json={"name": "Acme"}, headers={}).status_code == 400   # name taken


def test_archive_makes_it_read_only_but_viewable_and_restorable(api):
    api.post("/api/analyze", json={"request": raw(path="/ftp"),
                                   "response": resp(ctype="text/html", body="<title>listing directory /ftp</title>")})
    fid = api.get("/api/findings").json()["findings"][0]["id"]
    assert api.patch(f"/api/engagements/{api.eid}", json={"status": "archived"}, headers={}).json()["status"] == "archived"
    # reading and reporting still work
    assert api.get("/api/findings").status_code == 200 and api.get("/api/report").status_code == 200
    assert api.get(f"/api/findings/{fid}").status_code == 200
    # every write is refused
    for r in (api.patch(f"/api/findings/{fid}", json={"status": "confirmed"}),
              api.post(f"/api/findings/{fid}/draft"),
              api.post("/api/scan", json={}),
              api.delete("/api/queue"),
              api.post("/api/analyze", json={"request": raw(), "response": ""})):
        assert r.status_code == 409 and "archived" in r.json()["detail"]
    api.patch(f"/api/engagements/{api.eid}", json={"status": "active"}, headers={})
    assert api.patch(f"/api/findings/{fid}", json={"status": "confirmed"}).status_code == 200


def test_delete_needs_exact_name_and_removes_everything(api):
    e = new(api, "Delete Me")
    api.post("/api/analyze", json={"request": raw(path="/ftp"),
                                   "response": resp(ctype="text/html", body="<title>listing directory /ftp</title>")}, headers=hdr(e))
    db_dir = settings.data_dir / "engagements" / e["id"]
    assert db_dir.exists()
    assert api.request("DELETE", f"/api/engagements/{e['id']}", json={"confirm": "delete me"}, headers={}).status_code == 400
    assert api.request("DELETE", f"/api/engagements/{e['id']}", json={}, headers={}).status_code == 422
    assert db_dir.exists()                                                   # a wrong guess deleted nothing
    assert api.request("DELETE", f"/api/engagements/{e['id']}", json={"confirm": "Delete Me"}, headers={}).status_code == 200
    assert not db_dir.exists()
    assert api.get("/api/findings", headers=hdr(e)).status_code == 404
    assert api.get(f"/api/engagements/{e['id']}", headers={}).status_code == 404
    assert api.get("/api/findings").status_code == 200                       # the other client is untouched


def test_client_name_is_the_report_heading_and_never_in_urls(api):
    assert api.get("/api/report").text.startswith("# Acme Corp: Penetration Test Findings")
    assert "Acme" not in api.get("/api/findings").request.url.path and re.fullmatch(r"e[0-9a-f]{8}", api.eid)


# --------------------------------------------- one job at a time, all clients
class TinyBurp:
    async def history(self, count, offset=0, regex=None):
        return []


def wait_status(api, jid, want, timeout=5):
    end = time.time() + timeout
    while time.time() < end:
        s = api.get(f"/api/scan/{jid}", headers={}).json()["status"]
        if s == want:
            return
        time.sleep(0.05)
    raise AssertionError(f"job never became {want}")


def test_only_one_scan_runs_across_engagements(api):
    api.app.state.burp = TinyBurp()
    other = new(api, "Globex")
    a = api.post("/api/scan", json={"live": True, "interval_seconds": 2, "use_llm": False}).json()
    assert a["engagement_id"] == api.eid and a["engagement_name"] == "Acme"

    blocked = api.post("/api/scan", json={"use_llm": False}, headers=hdr(other))
    assert blocked.status_code == 409 and "'Acme'" in blocked.json()["detail"]          # names who is running

    st = api.get("/api/status", headers={}).json()["active_job"]
    assert st["id"] == a["id"]
    engs = {e["name"]: e for e in api.get("/api/engagements", headers={}).json()["engagements"]}
    assert engs["Acme"]["running"] and not engs["Globex"]["running"]
    # each engagement lists only its own jobs, but the job can be controlled from anywhere by id
    assert len(api.get("/api/scan").json()) == 1 and api.get("/api/scan", headers=hdr(other)).json() == []
    assert api.post(f"/api/scan/{a['id']}/pause", headers=hdr(other)).json()["paused"] is True
    assert api.post(f"/api/scan/{a['id']}/cancel", headers={}).json()["status"] == "canceled"
    assert api.post("/api/scan", json={"use_llm": False}, headers=hdr(other)).status_code == 200   # now free


def test_cannot_archive_or_delete_an_engagement_while_its_scan_runs(api):
    api.app.state.burp = TinyBurp()
    j = api.post("/api/scan", json={"live": True, "interval_seconds": 2, "use_llm": False}).json()
    assert api.patch(f"/api/engagements/{api.eid}", json={"status": "archived"}, headers={}).status_code == 409
    assert api.request("DELETE", f"/api/engagements/{api.eid}", json={"confirm": "Acme"}, headers={}).status_code == 409
    api.post(f"/api/scan/{j['id']}/cancel", headers={})
    assert api.request("DELETE", f"/api/engagements/{api.eid}", json={"confirm": "Acme"}, headers={}).status_code == 200


def test_scan_uses_the_engagements_scope_not_a_global_one(api):
    class Burp:
        async def history(self, count, offset=0, regex=None):
            return [item(raw(path="/a", host="localhost:3000"), resp(ctype="text/html", body="<title>listing directory /a</title>")),
                    item(raw(path="/b", host="other.client.test"), resp(ctype="text/html", body="<title>listing directory /b</title>"))] if offset == 0 else []
    api.app.state.burp = Burp()
    other = new(api, "Other client", scope=["other.client.test"])
    for e, host in ((None, "localhost:3000"), (other, "other.client.test")):
        h = hdr(e) if e else {}
        jid = api.post("/api/scan", json={"use_llm": False}, headers=h).json()["id"]
        wait_status(api, jid, "done")
        urls = [f["url"] for f in api.get("/api/findings", headers=h).json()["findings"]]
        assert urls and all(host in u for u in urls), (host, urls)


# ======================================================================== UI
def test_ui_has_the_engagement_flow_elements():
    html = Path("ui/index.html").read_text()
    for needed in ("view-engagements", "eng-list", "btn-new-eng", "dlg-eng", "dlg-delete", "del-input",
                   "btn-switch", "eng-archived", "eng-f-scope", "ro-badge"):
        assert f'id="{needed}"' in html, needed


def test_ui_never_sets_inline_styles_which_the_csp_blocks():
    js = "\n".join(l for l in Path("ui/app.js").read_text().splitlines() if not l.strip().startswith("//"))
    assert not re.search(r'\bstyle\s*:|setAttribute\(\s*["\']style', js)
    assert "style.setProperty" in js           # colors go through the CSSOM instead


def test_ui_does_not_prefill_scope_from_another_client():
    js = Path("ui/app.js").read_text()
    assert re.search(r'\$\("eng-f-scope"\)\.value = e \? e\.scope\.join\("\\n"\) : ""', js)


def test_ui_detail_pane_drops_null_children():
    # replaceChildren(null) renders the literal text "null"; read-only mode returns nulls for hidden buttons
    assert "detail(f).filter(Boolean)" in Path("ui/app.js").read_text()
