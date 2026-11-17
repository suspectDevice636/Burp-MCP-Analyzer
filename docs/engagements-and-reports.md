# Engagements and reports

## Engagements (one workspace per client)
Open the review page and you get, in order: the **API token**, then the **engagement picker**. Each
engagement is a separate client workspace with its **own database file** (findings, captured traffic,
model queue), its **own scope** and its own report. Nothing is shared between them, and no client
name appears in a URL, a file path or a log line (engagements are identified by a random id).

| Action | What it does |
|---|---|
| **New** | Name, client or program (used in the report heading), **type** (web app pentest or bug bounty: you must choose; it decides the report layout), scope (hosts you are authorized to test) and notes. A pasted URL is reduced to its host; a bare `*` is refused. Scope is **not** pre-filled from another client. |
| **Continue** | Opens it and remembers it as "last used". Switch any time from the header (the engagement name, top left). |
| **Edit** | Change name, client, type, scope, notes. |
| **Archive** | Locks it read-only and moves it to an "Archived" list: you can still view findings and produce the report, but not scan, confirm or edit. **Restore** undoes it. |
| **Delete** | Permanently removes every finding and all captured traffic for that engagement. You must type its exact name; the server checks it too. |

Each engagement has a color (swatch, header bar, card edge) so it is hard to confuse which client you
are in. Only one scan runs at a time across all engagements (there is one model): the header shows
which engagement is scanning from anywhere, and starting a scan elsewhere tells you who is running.
Pausing or stopping one client's scan to work on another loses nothing; unfinished model work stays
queued in that client's database and resumes when you scan it again.

Existing data from before engagements is imported once as **"Imported (earlier data)"** with your old
`SCOPE_HOSTS` as its scope; the original file is kept as `data/analyzer.db.pre-engagements`.
`SCOPE_HOSTS` is not used for anything else now: scope belongs to each engagement.

For scripts, every data endpoint needs `X-Engagement: <id>` (ids: `GET /api/engagements`); there is
deliberately no default, so nothing can be written to the wrong client by omission:
```bash
curl -H "Authorization: Bearer $TOKEN" localhost:8765/api/engagements
curl -H "Authorization: Bearer $TOKEN" -H "X-Engagement: e1a2b3c4d" localhost:8765/api/findings
```

## Reports: pentest or bug bounty
The engagement's **type** decides the default report layout, and the Report dialog lets you switch
format on the spot (`GET /api/report?format=pentest|bounty`). Only **confirmed** findings are included.

- **Web app pentest:** one client document: scope, summary table by severity, then every finding in
  severity order with affected URL, a CWE reference, description, evidence, remediation and your notes.
- **Bug bounty:** one **self-contained submission draft per finding**: suggested severity, asset, weakness
  (CWE), summary, steps to reproduce, impact, suggested fix and evidence. It never invents what it
  doesn't know: your notes become the steps, and anything missing is a clearly marked `_TODO:` for you
  to fill in. Finding classes many programs reject or rate very low (missing headers, cookie flags,
  version banners, account enumeration, verbose errors) carry a warning to check the program's policy
  and show real impact first. Attach your own request/response from Burp (redacted) before submitting.

**Draft with model** follows the type too: the bounty prompt writes Summary / Steps to Reproduce /
Impact / Suggested Fix, builds the steps only from the evidence and your notes, and marks anything it
can't support as TODO. CWE and severity are suggestions: use the program's own taxonomy and scale.

[← Back to the README](../README.md)
