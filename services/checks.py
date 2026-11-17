"""Deterministic checks. No LLM involved: cheap, repeatable, explainable.

Every check returns Candidate objects carrying the exact evidence they matched.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit

from services.httpmsg import ID_SEG, Exchange, path_template  # noqa: F401


@dataclass
class Candidate:
    type: str
    title: str
    severity: str
    confidence: str
    evidence: str
    description: str
    recommendation: str
    dedupe_key: str
    source: str = "check"


STATIC_TYPES = ("image/", "font/", "audio/", "video/")
STATIC_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".css", ".map", ".mp4")


def is_static(ex: Exchange) -> bool:
    if ex.path_only.lower().endswith(STATIC_EXT):
        return True
    ct = ex.response.content_type if ex.response else ""
    return ct.startswith(STATIC_TYPES) or ct == "text/css"


def _snip(text: str, start: int, end: int, pad: int = 80) -> str:
    s = text[max(0, start - pad): end + pad]
    return re.sub(r"\s+", " ", s).strip()


def _redact(value: str, keep: int = 6) -> str:
    return value[:keep] + "…[redacted]" if len(value) > keep else value


# ---------------------------------------------------------------- headers
def check_security_headers(ex: Exchange) -> list[Candidate]:
    r = ex.response
    if not r or r.content_type != "text/html" or not (200 <= (r.status or 0) < 300):
        return []
    # Only judge real pages: socket.io/polling and API endpoints may reuse text/html
    if not re.search(r"<(!doctype|html)", r.body[:2000], re.I):
        return []
    out: list[Candidate] = []
    csp =r.header("content-security-policy") or ""
    hdrs = r.header_block()

    def add(name: str, title: str, desc: str, rec: str, sev: str = "low") -> None:
        out.append(Candidate(
            type="missing_header", title=title, severity=sev, confidence="high",
            evidence=f"{name} header absent. Response headers: {hdrs[:400]}",
            description=desc, recommendation=rec, dedupe_key=f"hdr:{name}:{ex.host}",
        ))

    if not csp:
        add("content-security-policy", "Missing Content-Security-Policy header",
            "HTML responses carry no CSP, removing a defense-in-depth layer against XSS.",
            "Define a restrictive Content-Security-Policy.")
    if (r.header("x-content-type-options") or "").lower() != "nosniff":
        add("x-content-type-options", "Missing X-Content-Type-Options: nosniff",
            "Browsers may MIME-sniff responses, enabling some content-type confusion attacks.",
            "Send X-Content-Type-Options: nosniff.")
    if not r.header("x-frame-options") and "frame-ancestors" not in csp.lower():
        add("x-frame-options", "No clickjacking protection (X-Frame-Options / frame-ancestors)",
            "The page can be framed by any origin.",
            "Send X-Frame-Options: DENY or a CSP frame-ancestors directive.")
    if ex.scheme == "https" and not r.header("strict-transport-security"):
        add("strict-transport-security", "Missing Strict-Transport-Security header",
            "HTTPS responses do not instruct browsers to enforce HTTPS.",
            "Send Strict-Transport-Security with a long max-age.")
    return out


SESSIONISH = re.compile(r"sess|token|auth|jwt|sid|login", re.I)


def check_cookies(ex: Exchange) -> list[Candidate]:
    if not ex.response:
        return []
    out: list[Candidate] = []
    for sc in ex.response.headers_all("set-cookie"):
        parts = [p.strip() for p in sc.split(";")]
        name, _, value = parts[0].partition("=")
        flags = {p.split("=")[0].lower() for p in parts[1:]}
        shown = f"{name}={_redact(value)}; " + "; ".join(parts[1:])
        sensitive = bool(SESSIONISH.search(name))
        missing = []
        if "httponly" not in flags:
            missing.append(("HttpOnly", "medium" if sensitive else "low",
                            "Script running in the page can read this cookie, making XSS more damaging."))
        if "secure" not in flags and ex.scheme == "https":
            missing.append(("Secure", "medium" if sensitive else "low",
                            "The cookie may be sent over plain HTTP."))
        if "samesite" not in flags:
            missing.append(("SameSite", "low", "No SameSite attribute; relies on browser defaults for CSRF protection."))
        for flag, sev, desc in missing:
            out.append(Candidate(
                type="cookie_flags", title=f"Cookie '{name}' missing {flag} flag",
                severity=sev, confidence="high", evidence=f"Set-Cookie: {shown}",
                description=desc, recommendation=f"Set the {flag} attribute on the cookie.",
                dedupe_key=f"cookie:{flag}:{name}:{ex.host}",
            ))
    return out


def check_info_headers(ex: Exchange) -> list[Candidate]:
    r = ex.response
    if not r:
        return []
    out: list[Candidate] = []
    server = r.header("server") or ""
    powered = r.header("x-powered-by") or ""
    if re.search(r"\d+\.\d+", server):
        out.append(Candidate(
            "info_disclosure", "Server header discloses version", "info", "high",
            f"Server: {server}", "The Server header reveals software and version.",
            "Remove or genericize version details.", f"srv:{ex.host}"))
    if powered:
        out.append(Candidate(
            "info_disclosure", "X-Powered-By header discloses technology", "info", "high",
            f"X-Powered-By: {powered}", "The response reveals the underlying framework.",
            "Remove the X-Powered-By header.", f"xpb:{ex.host}"))
    return out


def check_cors(ex: Exchange) -> list[Candidate]:
    r = ex.response
    if not r:
        return []
    acao = r.header("access-control-allow-origin")
    acac = (r.header("access-control-allow-credentials") or "").lower() == "true"
    origin = ex.request.header("origin")
    if not acao or not acac:
        return []
    reflected = origin and acao == origin and urlsplit(origin).netloc != ex.host
    if reflected or acao == "null":
        return [Candidate(
            "cors_misconfiguration", "CORS allows credentialed requests from an untrusted origin",
            "medium", "medium",
            f"Request Origin: {origin}; Access-Control-Allow-Origin: {acao}; Access-Control-Allow-Credentials: true",
            "The server reflects arbitrary origins (or 'null') with credentials allowed, so another site may read authenticated responses.",
            "Validate Origin against an allow-list; never reflect it with credentials.",
            f"cors:{ex.method}:{ex.host}{ex.path_only}")]
    return []


# ------------------------------------------------------------------ bodies
ERROR_PATTERNS = [
    (r"Traceback \(most recent call last\)", "Python stack trace"),
    (r"\bat [\w$.<>]+\([\w$.\-]+\.(?:java|js|ts|kt|cs):\d+(?::\d+)?\)", "Stack trace with source locations"),
    (r"\bat [\w$.<>]+ \((?:/|[A-Za-z]:\\)[^)\n]+:\d+:\d+\)", "Node.js stack trace with file paths"),
    (r"You have an error in your SQL syntax", "MySQL error message"),
    (r"SQLITE_ERROR|SQLITE_CONSTRAINT", "SQLite error message"),
    (r"SequelizeDatabaseError|SequelizeUniqueConstraintError", "Sequelize database error"),
    (r"ORA-\d{5}", "Oracle error message"),
    (r"PG::\w+Error|org\.postgresql\.util\.PSQLException", "PostgreSQL error message"),
    (r"System\.(?:\w+\.)*\w+Exception", ".NET exception"),
    (r"<b>(?:Warning|Fatal error)</b>:.+ on line <b>\d+</b>", "PHP error message"),
]


def check_verbose_errors(ex: Exchange) -> list[Candidate]:
    r = ex.response
    if not r or not r.body:
        return []
    for pat, label in ERROR_PATTERNS:
        m = re.search(pat, r.body)
        if m:
            return [Candidate(
                "verbose_error", f"Verbose error disclosed: {label}", "low", "high",
                _snip(r.body, m.start(), m.end(), 160),
                "The response exposes internal error details useful for mapping the application.",
                "Return generic error pages and log details server-side.",
                f"err:{label}:{ex.method}:{ex.host}{ex.path_only}")]
    return []


SECRET_PATTERNS = [
    ("AWS access key", r"\bAKIA[0-9A-Z]{16}\b", "high"),
    ("Google API key", r"\bAIza[0-9A-Za-z_\-]{35}\b", "medium"),
    ("Private key block", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", "critical"),
    ("Slack token", r"\bxox[abprs]-[0-9A-Za-z\-]{10,}\b", "high"),
    ("GitHub token", r"\bgh[pousr]_[0-9A-Za-z]{36,}\b", "high"),
    ("Hard-coded credential", r"""(?i)["']?(?:api[_-]?key|secret|client_secret|access_token)["']?\s*[:=]\s*["'][A-Za-z0-9_\-./+]{16,}["']""", "medium"),
]


def check_secrets(ex: Exchange) -> list[Candidate]:
    r = ex.response
    if not r or not r.body:
        return []
    out = []
    for label, pat, sev in SECRET_PATTERNS:
        m = re.search(pat, r.body)
        if m:
            ev = _snip(r.body, m.start(), m.end(), 40).replace(m.group(0), _redact(m.group(0), 8))
            out.append(Candidate(
                "secret_exposure", f"{label} in response", sev, "medium", ev,
                f"A value resembling a {label.lower()} appears in the response body.",
                "Remove secrets from client-visible responses and rotate any exposed value.",
                f"secret:{label}:{ex.host}{ex.path_only}"))
    return out


JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]{6,}\.eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]*")


def _jwt_header(token: str) -> dict:
    seg = token.split(".")[0]
    try:
        return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
    except Exception:
        return {}


def check_jwt(ex: Exchange) -> list[Candidate]:
    hay = (ex.response.body if ex.response else "") + "\n" + "\n".join(
        v for k, v in ex.request.headers if k.lower() in ("authorization", "cookie"))
    for m in JWT_RE.finditer(hay):
        alg = str(_jwt_header(m.group(0)).get("alg", "")).lower()
        if alg == "none":
            return [Candidate(
                "jwt_alg_none", "JWT uses alg=none", "high", "high",
                f"JWT header decodes to alg={alg!r}: {_redact(m.group(0), 20)}",
                "An unsigned JWT is issued or accepted, allowing token forgery.",
                "Reject unsigned tokens and pin the expected algorithm.",
                f"jwtnone:{ex.host}")]
    return []


PW_HASH = re.compile(r'''(?i)"(?:password|passwd|pwd|pass_hash|hash)"\s*:\s*"([0-9a-f]{32,128}|\$2[aby]\$\d\d\$[./A-Za-z0-9]{50,})"''')
EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")


def check_data_exposure(ex: Exchange) -> list[Candidate]:
    r = ex.response
    if not r or not r.body:
        return []
    out = []
    m = PW_HASH.search(r.body)
    if m:
        out.append(Candidate(
            "sensitive_data_exposure", "Password hashes returned in API response", "high", "high",
            _snip(r.body, m.start(), m.end(), 60).replace(m.group(1), _redact(m.group(1), 8)),
            "The response includes stored password hashes, which enables offline cracking.",
            "Never serialize credential fields; use explicit response DTOs.",
            f"pwhash:{ex.method}:{ex.host}{ex.path_only}"))
    if "json" in r.content_type:
        emails = set(EMAIL.findall(r.body))
        if len(emails) >= 5:
            sample = ", ".join(sorted(emails)[:3])
            out.append(Candidate(
                "sensitive_data_exposure", f"Response exposes {len(emails)} user email addresses",
                "medium", "medium", f"Distinct emails in one response: {len(emails)} (e.g. {sample})",
                "A single response discloses many users' personal data; check whether authorization is enforced.",
                "Restrict the endpoint to authorized callers and return only necessary fields.",
                f"bulkpii:{ex.method}:{ex.host}{ex.path_only}"))
    return out


LISTING = re.compile(r"<title>Index of /|Directory listing for|listing directory /", re.I)


def check_directory_listing(ex: Exchange) -> list[Candidate]:
    r = ex.response
    if r and r.body:
        m = LISTING.search(r.body)
        if m:
            return [Candidate(
                "directory_listing", "Directory listing enabled", "medium", "high",
                _snip(r.body, m.start(), m.end(), 100),
                "The server lists directory contents, potentially exposing sensitive files.",
                "Disable directory indexing and remove sensitive files from the web root.",
                f"dirlist:{ex.host}{ex.path_only}")]
    return []


# --------------------------------------------------------------- reflections
def check_reflection(ex: Exchange) -> list[Candidate]:
    r = ex.response
    if not r or "html" not in r.content_type or not r.body:
        return []
    for name, values in ex.params.items():
        for v in values:
            if len(v) >= 3 and any(c in v for c in "<>\"'") and v in r.body:
                idx = r.body.index(v)
                return [Candidate(
                    "reflected_input", f"Parameter '{name}' reflected without encoding (possible XSS)",
                    "medium", "medium", _snip(r.body, idx, idx + len(v), 80),
                    "Input containing HTML metacharacters appears verbatim in an HTML response.",
                    "Context-aware output encoding; add a CSP.",
                    f"reflect:{ex.method}:{ex.host}{ex.path_only}:{name}")]
    return []


def check_open_redirect(ex: Exchange) -> list[Candidate]:
    r = ex.response
    if not r or not (300 <= (r.status or 0) < 400):
        return []
    loc = r.header("location") or ""
    for name, values in ex.params.items():
        for v in values:
            if v.lower().startswith(("http://", "https://", "//")) and loc.startswith(v):
                return [Candidate(
                    "open_redirect", f"Redirect to attacker-supplied URL via '{name}'", "medium", "medium",
                    f"Request param {name}={v}; Location: {loc}",
                    "The application redirects to a URL taken from user input.",
                    "Only redirect to an allow-list of destinations.",
                    f"redir:{ex.host}{ex.path_only}:{name}")]
    return []


# ---------------------------------------------------------- access control
SENSITIVE_PATH = re.compile(
    r"/(administrator|admin|actuator|management|debug|internal|config|configuration|metrics|console)(?:[/\-_.?]|$)", re.I)
SENSITIVE_KEYS = re.compile(r'(?i)"[^"]*(secret|password|passwd|api[_-]?key|token|private|credential)[^"]*"\s*:')
DATA_TYPES = ("json", "xml", "yaml", "text/plain")


def check_unauthenticated_sensitive(ex: Exchange) -> list[Candidate]:
    """Admin/config-style endpoint that returned data to a request with no credentials."""
    r = ex.response
    if not r or r.status != 200 or len(r.body.strip()) < 20:
        return []
    if ex.request.header("authorization") or ex.request.header("cookie"):
        return []
    if not SENSITIVE_PATH.search(ex.path_only) or not any(t in r.content_type for t in DATA_TYPES):
        return []
    has_keys = bool(SENSITIVE_KEYS.search(r.body))
    return [Candidate(
        "unauthenticated_access",
        f"Administrative/config endpoint answers without credentials: {ex.path_only}",
        "high" if has_keys else "medium", "medium" if has_keys else "low",
        f"{ex.method} {ex.path} sent with no Authorization or Cookie header; "
        f"response 200 {r.content_type}: {_snip(r.body, 0, 0, 140)}",
        "An admin- or config-style path returned data to a request carrying no credentials. "
        "Confirm in Repeater that it is genuinely unauthenticated and what it exposes.",
        "Require authentication and authorization on administrative and configuration endpoints.",
        f"unauth:{ex.method}:{ex.host}{ex.path_only}")]


AUTH_PATH = re.compile(r"login|signin|sign-in|forgot|reset|recover|security-question|register|signup|password", re.I)
ENUM_MSG = re.compile(
    r"(user|account|email)[^\"'\n]{0,30}(does not|doesn't|not)\s+(exist|found|registered)"
    r"|no (such )?(user|account)|unknown (user|email|account)|not registered", re.I)
LOOKUP_PATH = re.compile(r"security-question|forgot|reset|recover|exists|check", re.I)
ACCOUNT_PARAMS = {"email", "username", "user", "login", "account"}


def check_account_enumeration(ex: Exchange) -> list[Candidate]:
    r = ex.response
    if not r or not r.body or not AUTH_PATH.search(ex.path_only):
        return []
    m = ENUM_MSG.search(r.body)
    if m:
        return [Candidate(
            "account_enumeration", "Authentication endpoint reveals whether an account exists",
            "low", "medium", _snip(r.body, m.start(), m.end(), 80),
            "The response wording distinguishes unknown accounts from known ones, letting an attacker enumerate valid users.",
            "Return the same response and timing for known and unknown accounts.",
            f"enum:{ex.method}:{ex.host}{ex.path_only}")]
    names = {k.lower() for k in ex.params}
    if (names & ACCOUNT_PARAMS and LOOKUP_PATH.search(ex.path_only) and r.status == 200
            and "json" in r.content_type and len(r.body.strip()) > 20):
        return [Candidate(
            "account_enumeration", "Lookup endpoint returns account-specific data for a supplied identifier",
            "low", "low",
            f"{ex.method} {ex.path} -> 200 {_snip(r.body, 0, 0, 120)}",
            "An unauthenticated-looking lookup returns data keyed on an email/username. Compare the response for a "
            "known and an unknown account in Repeater; if they differ, accounts can be enumerated.",
            "Return identical responses for existing and non-existing accounts.",
            f"enum:{ex.method}:{ex.host}{ex.path_only}")]
    return []


# ------------------------------------------- session, caching, client-side leakage
URL_SECRET_PARAM = re.compile(r"(?i)^(?:.*[_-])?(pass(?:word|wd)?|pwd|token|session(?:_?id)?|sid|jwt|api[_-]?key|apikey|secret|auth(?:orization)?)$")


def check_secrets_in_url(ex: Exchange) -> list[Candidate]:
    """Credentials or session identifiers carried in the query string (logged, cached, leaked via Referer)."""
    if "socket.io" in ex.path_only:   # the transport session id there is plumbing
        return []
    out = []
    for name, value in parse_qsl(urlsplit(ex.path).query, keep_blank_values=True):
        if URL_SECRET_PARAM.match(name) and len(value) >= 6:
            out.append(Candidate(
                "url_sensitive_data", f"Sensitive value '{name}' sent in the URL query string",
                "medium", "medium", f"{ex.method} {ex.path_only}?{name}={_redact(value)}",
                "Credentials, tokens or session identifiers in a URL end up in server and proxy logs, browser "
                "history and Referer headers.",
                "Send secrets in the request body or an Authorization header, never in the URL.",
                f"urlsecret:{ex.host}{ex.path_only}:{name.lower()}"))
    return out


SENSITIVE_RESPONSE_PATH = re.compile(
    r"/(account|profile|me|user|users|order|orders|basket|cart|payment|payments|wallet|settings|invoice|address)(?:[/\-_.?]|$)", re.I)


def check_cache_control(ex: Exchange) -> list[Candidate]:
    """Authenticated responses with personal data that browsers and proxies may cache."""
    r = ex.response
    if not r or not (200 <= (r.status or 0) < 300) or is_static(ex) or not r.body.strip():
        return []
    if not (ex.request.header("authorization") or ex.request.header("cookie")):
        return []
    if not any(t in r.content_type for t in ("html", "json")):
        return []
    cc = (r.header("cache-control") or "").lower()
    if "no-store" in cc:
        return []
    sensitive = bool(SENSITIVE_KEYS.search(r.body) or EMAIL.search(r.body)
                     or SENSITIVE_RESPONSE_PATH.search(ex.path_only))
    if not sensitive:
        return []
    return [Candidate(
        "cache_control_missing", "Authenticated response with personal data is cacheable",
        "low", "low", f"{ex.method} {ex.path_only} -> {r.status}; Cache-Control: {cc or '(absent)'}",
        "The response carries account data for a logged-in user but does not send Cache-Control: no-store, "
        "so shared proxies or the browser (back button, shared computers) may keep a copy.",
        "Send Cache-Control: no-store on authenticated responses that contain personal data.",
        f"cache:{ex.host}{path_template(ex.path_only)[0]}")]


def check_source_map(ex: Exchange) -> list[Candidate]:
    r = ex.response
    if not r or r.status != 200 or not r.body:
        return []
    m = re.search(r"sourceMappingURL=([^\s*]+\.map)", r.body[-2000:])
    is_map = ex.path_only.endswith(".map") and '"mappings"' in r.body[:200000]
    if is_map:
        return [Candidate(
            "source_map_exposed", "JavaScript source map is publicly served", "low", "high",
            f"{ex.method} {ex.path_only} -> 200 (source map with mappings)",
            "A source map lets anyone reconstruct the original front-end source, including comments, "
            "internal routes and logic.",
            "Do not deploy source maps to production, or restrict them to authorized users.",
            f"srcmap:{ex.host}{ex.path_only}")]
    if m and "javascript" in r.content_type:
        return [Candidate(
            "source_map_exposed", "JavaScript references a source map", "info", "medium",
            f"//# sourceMappingURL={m.group(1)}",
            "The script points at a source map. If the map file is served, the original source is exposed.",
            "Remove sourceMappingURL and the map files from production builds.",
            f"srcmapref:{ex.host}{ex.path_only}")]
    return []


COMMENT_RE = re.compile(r"<!--(?!\[if)(.{3,400}?)-->", re.S)
COMMENT_WORDS = re.compile(r"(?i)\b(password|passwd|secret|api[_ -]?key|token|credential|todo|fixme|hack|debug|internal|staging|backdoor)\b")


def check_html_comments(ex: Exchange) -> list[Candidate]:
    r = ex.response
    if not r or "html" not in r.content_type or not r.body:
        return []
    for m in COMMENT_RE.finditer(r.body):
        if COMMENT_WORDS.search(m.group(1)):
            return [Candidate(
                "html_comment_leak", "HTML comment contains potentially sensitive developer notes", "info", "low",
                _snip(r.body, m.start(), m.end(), 20),
                "A comment in the page source mentions credentials, internals or unfinished work.",
                "Strip comments from production HTML.",
                f"comment:{ex.host}{ex.path_only}")]
    return []


CSRF_NAME = re.compile(r"(?i)csrf|xsrf|authenticity_token|anti-?forgery|__requestverificationtoken|^_token$|nonce")
FORM_TYPES = ("application/x-www-form-urlencoded", "multipart/form-data")
STATE_METHODS = ("POST", "PUT", "PATCH", "DELETE")


def check_csrf_lead(ex: Exchange) -> list[Candidate]:
    """Cookie-authenticated, form-encoded state change with no anti-CSRF token in sight. A lead only."""
    r = ex.response
    if not r or ex.method not in STATE_METHODS or not (200 <= (r.status or 0) < 400):
        return []
    if not ex.request.header("cookie") or ex.request.header("authorization"):
        return []
    if ex.request.content_type not in FORM_TYPES or AUTH_PATH.search(ex.path_only):
        return []
    if any(CSRF_NAME.search(k) for k in ex.params) or any(CSRF_NAME.search(k) for k, _ in ex.request.headers):
        return []
    if ex.request.header("x-requested-with"):
        return []
    return [Candidate(
        "csrf_lead", f"State-changing form request without an anti-CSRF token: {ex.method} {path_template(ex.path_only)[0]}",
        "low", "low", f"{ex.method} {ex.path_only} (Content-Type {ex.request.content_type}); cookie auth; "
        f"no CSRF token in parameters or headers",
        "A cookie-authenticated request changes state and carries no anti-CSRF token. Lead only: modern "
        "SameSite defaults may block cross-site use. Test it with a forged cross-origin form.",
        "Add anti-CSRF tokens (or require a custom header) and set SameSite on the session cookie.",
        f"csrf:{ex.method}:{ex.host}{path_template(ex.path_only)[0]}")]


LOGIN_PATH = re.compile(r"login|signin|sign-in|authenticate|/session|/auth(?:/|$)", re.I)
SESSION_COOKIE = re.compile(r"(?i)sess|^sid$|^connect\.sid$")


def _cookie_names(header: str) -> list[str]:
    return [p.split("=")[0].strip() for p in header.split(";") if "=" in p]


def check_session_rotation(ex: Exchange) -> list[Candidate]:
    """A session cookie sent into a login that is not replaced by it: possible session fixation."""
    r = ex.response
    if not r or ex.method != "POST" or not LOGIN_PATH.search(ex.path_only):
        return []
    if r.status not in (200, 201, 204, 302, 303):
        return []
    cookie_hdr = ex.request.header("cookie") or ""
    pre = [n for n in _cookie_names(cookie_hdr) if SESSION_COOKIE.search(n)]
    if not pre:
        return []
    set_names = {sc.split("=")[0].strip() for sc in r.headers_all("set-cookie")}
    if any(n in set_names for n in pre):
        return []
    return [Candidate(
        "session_not_rotated", "Session cookie not reissued at login (possible session fixation)",
        "medium", "low", f"POST {ex.path_only} sent cookie '{pre[0]}'; the {r.status} response sets no replacement for it",
        "The login request already carried a session cookie and the response did not issue a new one. If "
        "the pre-login session ID stays valid after authentication, an attacker who plants it can hijack the "
        "session. Lead only: confirm the login actually succeeded and that the old ID now works as the user.",
        "Issue a fresh session identifier on login and invalidate the old one.",
        f"fixation:{ex.host}{ex.path_only}")]


def check_http_methods(ex: Exchange) -> list[Candidate]:
    r = ex.response
    if not r:
        return []
    allow = (r.header("allow") or "").upper()
    if "TRACE" in re.split(r"[,\s]+", allow) or (ex.method == "TRACE" and r.status == 200):
        return [Candidate(
            "http_methods", "HTTP TRACE method enabled", "low", "medium",
            f"{ex.method} {ex.path_only} -> {r.status}; Allow: {allow or '(n/a)'}",
            "TRACE echoes requests back and can aid cross-site tracing attacks that expose headers.",
            "Disable TRACE (and CONNECT) on the web server.",
            f"trace:{ex.host}")]
    return []


CHECKS = [
    check_security_headers, check_cookies, check_info_headers, check_cors,
    check_verbose_errors, check_secrets, check_jwt, check_data_exposure,
    check_directory_listing, check_reflection, check_open_redirect,
    check_unauthenticated_sensitive, check_account_enumeration,
    check_secrets_in_url, check_cache_control, check_source_map, check_html_comments,
    check_csrf_lead, check_session_rotation, check_http_methods,
]


def run_checks(ex: Exchange) -> list[Candidate]:
    if ex.response is None:
        return []
    out: list[Candidate] = []
    for fn in CHECKS:
        out.extend(fn(ex))
    return out


# ------------------------------------------------- cross-request (whole capture)
ID_PARAM = re.compile(r"(^|_|-)id$|[a-z]Id$", re.I)
OWNERISH = re.compile(r'(?i)"(email|user_?id|basket_?id|account_?id|owner|customer_?id|order_?id|address)"')




def cross_request_checks(exchanges: list[Exchange]) -> list[tuple[Exchange, Candidate]]:
    """Object-ID endpoints hit with credentials: leads for broken-access-control testing.

    Purely observational (nothing is sent). One lead per method+template.
    """
    import hashlib

    groups: dict[tuple[str, str, str], dict] = {}
    for ex in exchanges:
        r = ex.response
        if not r or not (200 <= (r.status or 0) < 300) or is_static(ex):
            continue
        cred = ex.request.header("authorization") or ex.request.header("cookie")
        if not cred:
            continue
        template, ids = path_template(ex.path_only)
        id_params = sorted(k for k, vs in ex.params.items() if ID_PARAM.search(k) and any(v.isdigit() for v in vs))
        if not ids and not id_params:
            continue
        key = (ex.method, ex.host, template + (f"?{{{','.join(id_params)}}}" if id_params else ""))
        g = groups.setdefault(key, {"first": ex, "ids": set(), "creds": set(), "owner": False})
        g["ids"].update(ids)
        for k in id_params:
            g["ids"].update(v for v in ex.params[k] if v.isdigit())
        g["creds"].add(hashlib.sha1(cred.encode()).hexdigest()[:8])
        g["owner"] = g["owner"] or bool(OWNERISH.search(r.body))

    out = []
    for (method, host, template), g in groups.items():
        ex = g["first"]
        ids = sorted(g["ids"], key=lambda s: (len(s), s))[:8]
        n = len(g["creds"])
        out.append((ex, Candidate(
            "idor_lead", f"Object-ID endpoint to test for broken access control: {method} {template}",
            "info", "medium" if g["owner"] else "low",
            f"IDs seen: {', '.join(ids)}. Distinct credentials in capture: {n}. "
            f"Response {'contains user/ownership fields' if g['owner'] else 'has no obvious ownership fields'}.",
            "Authenticated requests reference an object ID. This is a lead, not a confirmed issue: replay "
            "it in Repeater with another user's session and with other IDs, and see whether you get data "
            "that isn't yours.",
            "Enforce object-level authorization server-side on every request.",
            f"idlead:{method}:{host}{template}")))
    return out
