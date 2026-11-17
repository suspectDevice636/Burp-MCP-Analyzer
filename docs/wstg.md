# OWASP WSTG coverage

## Test IDs, tagging and coverage (WSTG v4.2)

Every finding is tagged with the closest WSTG v4.2 test (`WSTG-SESS-02` for cookie attributes,
`WSTG-ATHZ-04` for IDOR leads, and so on). The mapping is a starting point: edit the tags on any finding,
which is how you tag model findings that have no obvious single match. IDs were checked against
wstg.owasp.org/v4.2 (97 tests, INFO to APIT).

The **WSTG coverage** button shows all 97 tests for the engagement:

| Status | Meaning |
|---|---|
| findings | open findings are tagged with this test (click to filter the list) |
| auto-checked | an automated check had matching traffic to examine and found nothing. This is not a pass: it only means passive analysis of what Burp captured was clean |
| tested manually / not applicable | set by you, with a note |
| untested | nothing yet. Tests with no automated checks are always manual |

"Auto-checked" is only claimed when relevant traffic existed (for example a `Set-Cookie` to inspect for
`SESS-02`), so an engagement with no cookies never shows cookie handling as clear. Counts are kept as
requests are ingested; **Recount** rebuilds them from every stored request (it also runs automatically the
first time you open the view on an older engagement). The pentest report adds the WSTG reference to each
finding and can include a coverage appendix (a checkbox in the Report dialog); bug bounty drafts don't, as
platforms use their own taxonomies. API: `GET /api/wstg`, `PUT /api/wstg/{id}`, `POST /api/wstg/rebuild`,
`GET /api/findings?wstg=ATHZ-04`.

Passive checks added with this feature: secrets in the URL query string (SESS-04), cacheable authenticated
responses with personal data (ATHN-06), exposed JS source maps and HTML comments with developer notes
(INFO-05), form-encoded state changes without an anti-CSRF token (SESS-05, a lead), a session cookie not
reissued at login (SESS-03, a lead) and TRACE enabled (CONF-06). Cleartext credentials (ATHN-01) isn't
detected because Burp history usually doesn't say whether a request used HTTP or HTTPS.

[← Back to the README](../README.md)
