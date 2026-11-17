"""Markdown reports from tracked findings, in two layouts:

  pentest  one client document: scope, summary table, then every finding in severity order.
  bounty   one self-contained submission draft per finding, in the shape bounty platforms ask
           for (summary, steps to reproduce, impact, fix). Never invents steps or impact: what
           the tool does not know is left as a clearly marked TODO.
"""

from __future__ import annotations

from datetime import datetime

from services import wstg

SEV_ORDER = ["critical", "high", "medium", "low", "info"]
KINDS = ("pentest", "bounty")

# Suggested weakness classification per finding type (a starting point; check the program's taxonomy).
CWE = {
    "directory_listing": "CWE-548: Exposure of Information Through Directory Listing",
    "verbose_error": "CWE-209: Generation of Error Message Containing Sensitive Information",
    "cors_misconfiguration": "CWE-942: Permissive Cross-domain Policy with Untrusted Domains",
    "secret_exposure": "CWE-798: Use of Hard-coded Credentials",
    "jwt_alg_none": "CWE-347: Improper Verification of Cryptographic Signature",
    "sensitive_data_exposure": "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
    "info_disclosure": "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
    "reflected_input": "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
    "open_redirect": "CWE-601: URL Redirection to Untrusted Site ('Open Redirect')",
    "unauthenticated_access": "CWE-306: Missing Authentication for Critical Function",
    "account_enumeration": "CWE-204: Observable Response Discrepancy",
    "idor_lead": "CWE-639: Authorization Bypass Through User-Controlled Key",
    "idor_candidate": "CWE-639: Authorization Bypass Through User-Controlled Key",
    "injection_candidate": "CWE-74: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')",
    "auth_issue": "CWE-287: Improper Authentication",
}

# Classes many bounty programs exclude or rate very low.
LOW_IMPACT_TYPES = {"missing_header", "cookie_flags", "info_disclosure", "account_enumeration", "verbose_error"}


def cwe_for(f: dict) -> str | None:
    t, title = f.get("type", ""), (f.get("title") or "").lower()
    if t == "missing_header":
        if "clickjack" in title or "x-frame" in title:
            return "CWE-1021: Improper Restriction of Rendered UI Layers or Frames"
        if "strict-transport" in title:
            return "CWE-319: Cleartext Transmission of Sensitive Information"
        return "CWE-693: Protection Mechanism Failure"
    if t == "cookie_flags":
        if "httponly" in title:
            return "CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag"
        if "secure" in title:
            return "CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute"
        if "samesite" in title:
            return "CWE-1275: Sensitive Cookie with Improper SameSite Attribute"
    return CWE.get(t)


def _by_severity(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda f: SEV_ORDER.index(f["severity"]) if f["severity"] in SEV_ORDER else 9)


def _affected(f: dict) -> str:
    return f"{f.get('method') or ''} {f.get('url') or ''}".strip()


def build_report(findings: list[dict], title: str = "Penetration Test Findings",
                 kind: str = "pentest", scope: list[str] | None = None,
                 coverage: dict | None = None) -> str:
    """`coverage` (a wstg.build_view result) adds a WSTG coverage appendix to a pentest report."""
    if kind not in KINDS:
        raise ValueError(f"kind must be one of {KINDS}")
    findings = _by_severity(findings)
    if kind == "bounty":
        return _bounty(findings, title, scope or [])
    text = _pentest(findings, title, scope or [])
    return text + _appendix(coverage) if coverage else text


STATUS_TEXT = {"findings": "Findings reported", "clear": "Automated checks: nothing found",
               "tested": "Tested manually", "na": "Not applicable", "untested": "Not tested"}


def _appendix(view: dict) -> str:
    s = view["summary"]
    lines = ["", "## Appendix: OWASP WSTG v%s coverage" % view["version"], "",
             "Status of each test in the OWASP Web Security Testing Guide. \"Automated checks\" means passive "
             "analysis of captured traffic found nothing; it is not a substitute for manual testing.", "",
             f"Findings: {s['findings']} · automated clear: {s['clear']} · tested manually: {s['tested']} · "
             f"not applicable: {s['na']} · not tested: {s['untested']}", ""]
    for cat in view["categories"]:
        lines += [f"### {cat['code']}: {cat['name']}", "", "| Test | Name | Status | Notes |", "|---|---|---|---|"]
        for t in cat["tests"]:
            note = " ".join((t["manual"]["note"] or "").split()).replace("|", "/")
            status = STATUS_TEXT[t["status"]] + (f" ({t['open']})" if t["open"] else "")
            lines.append(f"| WSTG-{t['id']} | {t['name']} | {status} | {note} |")
        lines.append("")
    return "\n".join(lines)


# ------------------------------------------------------------------ pentest
def _pentest(findings: list[dict], title: str, scope: list[str]) -> str:
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEV_ORDER}
    lines = [f"# {title}", "", f"_Generated {datetime.now().strftime('%Y-%m-%d %H:%M')}_", ""]
    if scope:
        lines += ["## Scope", ""] + [f"- `{h}`" for h in scope] + [""]
    lines += ["## Summary", "", "| Severity | Count |", "|---|---|"]
    lines += [f"| {s.capitalize()} | {n} |" for s, n in counts.items() if n]
    lines.append("")
    for i, f in enumerate(findings, 1):
        cwe = cwe_for(f)
        lines += [f"## {i}. {f['title']}", "",
                  f"- **Severity:** {f['severity'].capitalize()}",
                  f"- **Affected:** `{_affected(f)}`"]
        if cwe:
            lines.append(f"- **Reference:** {cwe}")
        tags = [t for t in (f.get("wstg") or "").split(",") if t in wstg.TESTS]
        if tags:
            lines.append("- **WSTG:** " + "; ".join(wstg.label(t) for t in tags))
        lines.append("")
        if f.get("report_text"):
            lines += [f["report_text"], ""]
        else:
            lines += ["**Description**", "", f.get("description") or "", "",
                      "**Remediation**", "", f.get("recommendation") or "", ""]
        if f.get("evidence"):
            lines += ["**Evidence**", "", "```", f["evidence"][:1500], "```", ""]
        if f.get("notes"):
            lines += ["**Tester notes**", "", f["notes"], ""]
    if not findings:
        lines.append("_No findings match the selected status._")
    return "\n".join(lines)


# ------------------------------------------------------------------- bounty
def _bounty(findings: list[dict], title: str, scope: list[str]) -> str:
    lines = [f"# {title}", "", f"_Generated {datetime.now().strftime('%Y-%m-%d %H:%M')}_", "",
             "> Each section below is a **separate submission draft**. Before sending: reproduce it once "
             "more, fill in every TODO, check the program's policy and scope, and attach your own "
             "request/response from Burp (redact your tokens and any other users' data).", ""]
    if scope:
        lines += ["In-scope hosts for this program: " + ", ".join(f"`{h}`" for h in scope), ""]
    for i, f in enumerate(findings, 1):
        cwe = cwe_for(f)
        lines += ["---", "", f"## [{i}] {f['title']}", "",
                  f"- **Suggested severity:** {f['severity'].capitalize()} "
                  "(adjust to the program's own rating scale)",
                  f"- **Asset / affected URL:** `{_affected(f)}`"]
        if cwe:
            lines.append(f"- **Weakness:** {cwe}")
        lines.append("")
        if f.get("type") in LOW_IMPACT_TYPES:
            lines += ["> ⚠ **Low-impact class.** Many programs exclude this or rate it very low. Check the "
                      "policy and show real impact before submitting.", ""]
        if f.get("report_text"):
            lines += [f["report_text"], ""]
        else:
            lines += ["### Summary", "", f.get("description") or "_TODO: one or two sentences._", "",
                      "### Steps to reproduce", ""]
            lines += [f["notes"], ""] if f.get("notes") else [
                "_TODO: numbered steps another person can follow (account used, request sent, what you "
                "observe). Your notes on the finding are used here when you add them._", ""]
            lines += ["### Impact", "",
                      "_TODO: what an attacker gains in this application, in the program's terms._", ""]
            if f.get("recommendation"):
                lines += ["### Suggested fix", "", f["recommendation"], ""]
        if f.get("evidence"):
            lines += ["### Evidence", "", "```", f["evidence"][:1500], "```", ""]
    if not findings:
        lines.append("_No findings match the selected status._")
    return "\n".join(lines)
