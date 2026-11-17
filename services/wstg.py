"""OWASP Web Security Testing Guide v4.2: the test catalog, finding tags and passive coverage.

IDs below were checked against the published v4.2 contents (wstg.owasp.org/v4.2). Test names are
shortened a little for the UI. Tagging is a best-effort mapping to the closest test: it is editable
per finding, so treat it as a starting point rather than a verdict.
"""

from __future__ import annotations

import re
from typing import Iterable

from services import checks
from services.httpmsg import Exchange, path_template

VERSION = "4.2"

CATEGORIES: dict[str, tuple[str, list[tuple[str, str]]]] = {
    "INFO": ("Information Gathering", [
        ("01", "Search engine discovery and reconnaissance for information leakage"),
        ("02", "Fingerprint web server"),
        ("03", "Review webserver metafiles for information leakage"),
        ("04", "Enumerate applications on webserver"),
        ("05", "Review webpage content for information leakage"),
        ("06", "Identify application entry points"),
        ("07", "Map execution paths through application"),
        ("08", "Fingerprint web application framework"),
        ("09", "Fingerprint web application"),
        ("10", "Map application architecture")]),
    "CONF": ("Configuration and Deployment Management", [
        ("01", "Network infrastructure configuration"),
        ("02", "Application platform configuration"),
        ("03", "File extensions handling for sensitive information"),
        ("04", "Old, backup and unreferenced files"),
        ("05", "Infrastructure and application admin interfaces"),
        ("06", "HTTP methods"),
        ("07", "HTTP Strict Transport Security"),
        ("08", "RIA cross domain policy"),
        ("09", "File permission"),
        ("10", "Subdomain takeover"),
        ("11", "Cloud storage")]),
    "IDNT": ("Identity Management", [
        ("01", "Role definitions"),
        ("02", "User registration process"),
        ("03", "Account provisioning process"),
        ("04", "Account enumeration and guessable user accounts"),
        ("05", "Weak or unenforced username policy")]),
    "ATHN": ("Authentication", [
        ("01", "Credentials transported over an encrypted channel"),
        ("02", "Default credentials"),
        ("03", "Weak lock out mechanism"),
        ("04", "Bypassing authentication schema"),
        ("05", "Vulnerable remember password"),
        ("06", "Browser cache weaknesses"),
        ("07", "Weak password policy"),
        ("08", "Weak security question answer"),
        ("09", "Weak password change or reset functionalities"),
        ("10", "Weaker authentication in alternative channel")]),
    "ATHZ": ("Authorization", [
        ("01", "Directory traversal / file include"),
        ("02", "Bypassing authorization schema"),
        ("03", "Privilege escalation"),
        ("04", "Insecure direct object references")]),
    "SESS": ("Session Management", [
        ("01", "Session management schema"),
        ("02", "Cookies attributes"),
        ("03", "Session fixation"),
        ("04", "Exposed session variables"),
        ("05", "Cross site request forgery"),
        ("06", "Logout functionality"),
        ("07", "Session timeout"),
        ("08", "Session puzzling"),
        ("09", "Session hijacking")]),
    "INPV": ("Input Validation", [
        ("01", "Reflected cross site scripting"),
        ("02", "Stored cross site scripting"),
        ("03", "HTTP verb tampering"),
        ("04", "HTTP parameter pollution"),
        ("05", "SQL injection"),
        ("06", "LDAP injection"),
        ("07", "XML injection"),
        ("08", "SSI injection"),
        ("09", "XPath injection"),
        ("10", "IMAP / SMTP injection"),
        ("11", "Code injection"),
        ("12", "Command injection"),
        ("13", "Format string injection"),
        ("14", "Incubated vulnerability"),
        ("15", "HTTP splitting / smuggling"),
        ("16", "HTTP incoming requests"),
        ("17", "Host header injection"),
        ("18", "Server-side template injection"),
        ("19", "Server-side request forgery")]),
    "ERRH": ("Error Handling", [
        ("01", "Improper error handling"),
        ("02", "Stack traces")]),
    "CRYP": ("Cryptography", [
        ("01", "Weak transport layer security"),
        ("02", "Padding oracle"),
        ("03", "Sensitive information sent via unencrypted channels"),
        ("04", "Weak encryption")]),
    "BUSL": ("Business Logic", [
        ("01", "Business logic data validation"),
        ("02", "Ability to forge requests"),
        ("03", "Integrity checks"),
        ("04", "Process timing"),
        ("05", "Number of times a function can be used limits"),
        ("06", "Circumvention of work flows"),
        ("07", "Defenses against application misuse"),
        ("08", "Upload of unexpected file types"),
        ("09", "Upload of malicious files")]),
    "CLNT": ("Client-side Testing", [
        ("01", "DOM-based cross site scripting"),
        ("02", "JavaScript execution"),
        ("03", "HTML injection"),
        ("04", "Client-side URL redirect"),
        ("05", "CSS injection"),
        ("06", "Client-side resource manipulation"),
        ("07", "Cross origin resource sharing"),
        ("08", "Cross site flashing"),
        ("09", "Clickjacking"),
        ("10", "WebSockets"),
        ("11", "Web messaging"),
        ("12", "Browser storage"),
        ("13", "Cross site script inclusion")]),
    "APIT": ("API Testing", [("01", "GraphQL")]),
}

TESTS: dict[str, str] = {f"{code}-{n}": name for code, (_, tests) in CATEGORIES.items() for n, name in tests}
ID_RE = re.compile(r"^(?:WSTG-)?([A-Z]{4}-\d{2})$", re.I)


def normalize_id(raw: str) -> str | None:
    """'wstg-athz-04' / 'ATHZ-04' -> 'ATHZ-04'; None if it is not a v4.2 test."""
    m = ID_RE.match((raw or "").strip())
    tid = m.group(1).upper() if m else None
    return tid if tid in TESTS else None


def parse_tags(raw: str | Iterable[str]) -> list[str]:
    """Clean a comma-separated string (or list) of test IDs. Raises ValueError on an unknown one."""
    items = re.split(r"[,\s]+", raw) if isinstance(raw, str) else list(raw)
    out: list[str] = []
    for it in items:
        if not str(it).strip():
            continue
        tid = normalize_id(str(it))
        if not tid:
            raise ValueError(f"'{it}' is not a WSTG v{VERSION} test ID (for example ATHZ-04).")
        if tid not in out:
            out.append(tid)
    return out


def label(tid: str) -> str:
    return f"WSTG-{tid}: {TESTS[tid]}"


# ------------------------------------------------------------------ tagging
def tags_for(ftype: str, title: str = "") -> list[str]:
    """Closest WSTG test(s) for a finding. Empty when there is no honest match (tag it by hand)."""
    t, ttl = ftype, (title or "").lower()
    if t == "missing_header":
        if "clickjack" in ttl or "x-frame" in ttl:
            return ["CLNT-09"]
        if "strict-transport" in ttl:
            return ["CONF-07"]
        return ["CONF-02"]
    if t == "info_disclosure":
        if "x-powered-by" in ttl:
            return ["INFO-08"]
        if "server header" in ttl:
            return ["INFO-02"]
        return ["INFO-05"]
    if t == "verbose_error":
        return ["ERRH-02"] if "stack trace" in ttl else ["ERRH-01"]
    return list(TAGS.get(t, []))


TAGS: dict[str, list[str]] = {
    "cookie_flags": ["SESS-02"],
    "cors_misconfiguration": ["CLNT-07"],
    "secret_exposure": ["INFO-05"],
    "jwt_alg_none": ["SESS-01"],
    "sensitive_data_exposure": ["INFO-05"],
    "directory_listing": ["CONF-04"],
    "reflected_input": ["INPV-01"],
    "open_redirect": ["CLNT-04"],
    "unauthenticated_access": ["ATHZ-02"],
    "account_enumeration": ["IDNT-04"],
    "idor_lead": ["ATHZ-04"],
    "idor_candidate": ["ATHZ-04"],
    "url_sensitive_data": ["SESS-04"],
    "cache_control_missing": ["ATHN-06"],
    "source_map_exposed": ["INFO-05"],
    "html_comment_leak": ["INFO-05"],
    "csrf_lead": ["SESS-05"],
    "session_not_rotated": ["SESS-03"],
    "http_methods": ["CONF-06"],
}


# ----------------------------------------------------------------- coverage
def _real_html(ex: Exchange) -> bool:
    r = ex.response
    return bool(r and r.content_type == "text/html" and 200 <= (r.status or 0) < 300
                and re.search(r"<(!doctype|html)", r.body[:2000], re.I))


def exercised(ex: Exchange) -> set[str]:
    """WSTG tests whose automated checks had something to look at in this exchange.

    This is what makes "checked, nothing found" honest: a test only counts as checked when
    relevant traffic existed (a Set-Cookie to inspect, an HTML page to frame-test, ...).
    """
    r = ex.response
    if r is None:
        return set()
    hit: set[str] = set()
    body = bool(r.body.strip())
    static = checks.is_static(ex)
    authed = bool(ex.request.header("authorization") or ex.request.header("cookie"))
    if r.header("server"):
        hit.add("INFO-02")
    if r.header("x-powered-by"):
        hit.add("INFO-08")
    if body and not static:
        hit |= {"INFO-05", "ERRH-02"}
    if (r.status or 0) >= 400 and body:
        hit.add("ERRH-01")
    if ex.method in ("OPTIONS", "TRACE") or r.header("allow"):
        hit.add("CONF-06")
    if ex.scheme == "https":
        hit.add("CONF-07")
    if _real_html(ex):
        hit |= {"CONF-02", "CLNT-09"}
        if ex.params:
            hit.add("INPV-01")
    if r.headers_all("set-cookie"):
        hit.add("SESS-02")
    if checks.JWT_RE.search(r.body + " " + (ex.request.header("authorization") or "")):
        hit.add("SESS-01")
    if "?" in ex.path:
        hit.add("SESS-04")
    if authed and 200 <= (r.status or 0) < 300 and not static and body and any(
            t in r.content_type for t in ("html", "json")):
        hit.add("ATHN-06")
    if checks.AUTH_PATH.search(ex.path_only) and body:
        hit.add("IDNT-04")
    if checks.SENSITIVE_PATH.search(ex.path_only):
        hit.add("ATHZ-02")
    template, ids = path_template(ex.path_only)
    id_params = [k for k, vs in ex.params.items() if checks.ID_PARAM.search(k) and any(v.isdigit() for v in vs)]
    if authed and (ids or id_params) and 200 <= (r.status or 0) < 300 and not static:
        hit.add("ATHZ-04")
    if ex.method in checks.STATE_METHODS and ex.request.header("cookie") and not ex.request.header("authorization") \
            and ex.request.content_type in checks.FORM_TYPES:
        hit.add("SESS-05")
    if ex.method == "POST" and checks.LOGIN_PATH.search(ex.path_only) and any(
            checks.SESSION_COOKIE.search(n) for n in checks._cookie_names(ex.request.header("cookie") or "")):
        hit.add("SESS-03")
    if r.header("access-control-allow-origin") or ex.request.header("origin"):
        hit.add("CLNT-07")
    if 300 <= (r.status or 0) < 400 and ex.params:
        hit.add("CLNT-04")
    return hit


AUTOMATED = frozenset({
    "INFO-02", "INFO-05", "INFO-08", "CONF-02", "CONF-04", "CONF-06", "CONF-07", "IDNT-04", "ATHN-06",
    "ATHZ-02", "ATHZ-04", "SESS-01", "SESS-02", "SESS-03", "SESS-04", "SESS-05", "INPV-01", "ERRH-01",
    "ERRH-02", "CLNT-04", "CLNT-07", "CLNT-09",
})
MANUAL_STATUSES = ("", "tested", "na")
OPEN_STATUSES = ("candidate", "confirmed", "reported")


def build_view(findings: list[dict], coverage: dict[str, int], notes: dict[str, dict]) -> dict:
    """Per-test status for one engagement.

    findings: rows with 'wstg' and 'status'; coverage: test -> requests exercised;
    notes: test -> {'status', 'note'} set by the tester.
    """
    by_test: dict[str, dict[str, int]] = {}
    for f in findings:
        for tid in filter(None, (f.get("wstg") or "").split(",")):
            d = by_test.setdefault(tid, {})
            d[f["status"]] = d.get(f["status"], 0) + 1
    summary = {"findings": 0, "clear": 0, "tested": 0, "na": 0, "untested": 0}
    cats = []
    for code, (cname, tests) in CATEGORIES.items():
        rows = []
        for n, name in tests:
            tid = f"{code}-{n}"
            counts = by_test.get(tid, {})
            open_n = sum(counts.get(s, 0) for s in OPEN_STATUSES)
            manual = notes.get(tid, {"status": "", "note": ""})
            reqs = coverage.get(tid, 0)
            if open_n:
                status = "findings"
            elif manual["status"] == "tested":
                status = "tested"
            elif manual["status"] == "na":
                status = "na"
            elif tid in AUTOMATED and reqs:
                status = "clear"
            else:
                status = "untested"
            summary[status] += 1
            rows.append({"id": tid, "name": name, "automated": tid in AUTOMATED, "requests": reqs,
                         "findings": counts, "open": open_n, "manual": manual, "status": status})
        cats.append({"code": code, "name": cname, "tests": rows})
    return {"version": VERSION, "summary": summary, "categories": cats}


def rebuild(store) -> int:
    """Recompute automated coverage from every stored request. Returns how many were examined."""
    from services.httpmsg import build_exchange

    counts: dict[str, int] = {}
    n = 0
    for row in store.iter_items():
        ex = build_exchange(row["raw_request"] or "", row["raw_response"] or "")
        if ex is None:
            continue
        n += 1
        for t in exercised(ex):
            counts[t] = counts.get(t, 0) + 1
    store.reset_coverage(counts)
    store.meta_set("coverage_built", "1")
    return n
