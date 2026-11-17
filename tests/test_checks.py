import json

from services import checks
from services.httpmsg import build_exchange
from tests.conftest import raw, resp


def run(req, res):
    ex = build_exchange(req, res)
    assert ex is not None
    return {c.type: c for c in checks.run_checks(ex)}


def test_password_hash_and_bulk_emails():
    users = [{"id": i, "email": f"user{i}@juice-sh.op", "password": "0192023a7bbd73250516f069df18b500"} for i in range(6)]
    found = run(raw(path="/api/Users"), resp(body=json.dumps({"data": users})))
    assert "sensitive_data_exposure" in found
    all_ = checks.run_checks(build_exchange(raw(path="/api/Users"), resp(body=json.dumps({"data": users}))))
    titles = [c.title for c in all_]
    assert any("Password hashes" in t for t in titles)
    assert any("email addresses" in t for t in titles)
    hash_c = next(c for c in all_ if "Password hashes" in c.title)
    assert "0192023a7bbd73250516f069df18b500" not in hash_c.evidence  # redacted


def test_stack_trace():
    body = "<pre>Error: boom\n    at Object.next (/juice-shop/node_modules/express/lib/router/index.js:280:10)</pre>"
    found = run(raw(path="/rest/x"), resp(500, body=body, ctype="text/html"))
    assert "verbose_error" in found


def test_directory_listing():
    found = run(raw(path="/ftp"), resp(body="<title>listing directory /ftp</title>", ctype="text/html"))
    assert "directory_listing" in found


def test_open_redirect():
    found = run(raw(path="/redirect?to=https://evil.example/x"),
                resp(302, headers={"Location": "https://evil.example/x"}, ctype="text/html"))
    assert "open_redirect" in found


def test_not_redirect_when_location_differs():
    found = run(raw(path="/redirect?to=https://evil.example/x"),
                resp(302, headers={"Location": "/home"}, ctype="text/html"))
    assert "open_redirect" not in found


def test_reflection():
    found = run(raw(path='/search?q=%3Cscript%3Ex%3C/script%3E'),
                resp(body="<p>You searched <script>x</script></p>", ctype="text/html"))
    assert "reflected_input" in found


def test_no_reflection_when_encoded():
    found = run(raw(path='/search?q=%3Cscript%3Ex%3C/script%3E'),
                resp(body="<p>You searched &lt;script&gt;x&lt;/script&gt;</p>", ctype="text/html"))
    assert "reflected_input" not in found


def test_cookie_flags_redact_value():
    ex = build_exchange(raw(), resp(headers={"Set-Cookie": "sessionid=abcdef1234567890; Path=/"}, ctype="text/html"))
    cs = [c for c in checks.run_checks(ex) if c.type == "cookie_flags"]
    assert {c.title.split()[-2] for c in cs} >= {"HttpOnly", "SameSite"}
    assert all("abcdef1234567890" not in c.evidence for c in cs)
    assert any(c.severity == "medium" for c in cs)  # session-ish name


def test_cors_reflected_with_credentials():
    found = run(raw(headers={"Origin": "https://evil.example"}),
                resp(headers={"Access-Control-Allow-Origin": "https://evil.example",
                              "Access-Control-Allow-Credentials": "true"}))
    assert "cors_misconfiguration" in found


def test_jwt_alg_none():
    import base64
    h = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
    p = base64.urlsafe_b64encode(b'{"sub":"admin"}').decode().rstrip("=")
    found = run(raw(), resp(body=json.dumps({"token": f"{h}.{p}."})))
    assert "jwt_alg_none" in found


def test_signed_jwt_not_flagged():
    import base64
    h = base64.urlsafe_b64encode(b'{"alg":"HS256"}').decode().rstrip("=")
    p = base64.urlsafe_b64encode(b'{"sub":"admin"}').decode().rstrip("=")
    found = run(raw(), resp(body=json.dumps({"token": f"{h}.{p}.sig123"})))
    assert "jwt_alg_none" not in found


def test_missing_headers_html_only_and_deduped_key():
    ex = build_exchange(raw(), resp(ctype="text/html", body="<html></html>"))
    keys = {c.dedupe_key for c in checks.run_checks(ex) if c.type == "missing_header"}
    assert "hdr:content-security-policy:localhost:3000" in keys
    ex_json = build_exchange(raw(), resp(body="{}"))
    assert not [c for c in checks.run_checks(ex_json) if c.type == "missing_header"]


def test_header_check_ignores_non_page_html_content_type():
    # e.g. socket.io polling answers with text/html but is not a page
    ex = build_exchange(raw(path="/socket.io/?EIO=4"), resp(ctype="text/html", body="0{\"sid\":\"abc\"}"))
    assert not [c for c in checks.run_checks(ex) if c.type == "missing_header"]
