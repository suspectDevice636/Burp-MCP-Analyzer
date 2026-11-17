# Burp MCP Analyzer

A local, offline assistant for reviewing Burp Suite traffic. It pulls proxy history from Burp's
MCP extension, runs deterministic checks, asks a local Ollama model to triage what's left, and
tracks each finding from **candidate → confirmed → reported** so only things you've verified reach
the report.

> ## ⚠ Authorized use only
>
> This tool analyzes HTTP traffic captured in Burp Suite. **Use it only on systems and applications you
> own or have explicit, written permission to test**: a signed engagement or rules of engagement for a
> client, or the published scope of a bug bounty or vulnerability disclosure program. Testing anything
> else may be illegal (for example under the US CFAA, the UK Computer Misuse Act or equivalent laws
> elsewhere) regardless of your intent.
>
> - **Stay in scope.** Set each engagement's scope and keep to it, including the program's own rules
>   on rate limits, prohibited techniques, excluded assets and what data you may access or keep. This tool
>   only reads what Burp has captured; it sends nothing to the target. The testing that generates that
>   traffic is yours, and so is the responsibility for it.
> - **Handle client data with care.** Captured traffic can contain credentials, tokens and personal data.
>   It is stored unencrypted in `data/` on the machine running this service and sent only to the Ollama
>   host you configure. Protect that disk and network, set `API_TOKEN`, and delete engagement data when
>   your agreement says to.
> - **AI output is unreliable.** The model and the automated checks produce *leads*, not verdicts. They
>   miss things and can be wrong or invent details. Verify every finding yourself before you report it.
> - **No warranty.** This software is provided "as is", without warranty of any kind, and the authors
>   accept no liability for its use or misuse. Nothing here is legal advice. You are responsible for
>   complying with the law, your contracts and the program rules that apply to you.

```
Burp (VM) ──MCP──▶  this service  ──▶ Ollama (local model)
 proxy history        checks + triage      JSON-schema output, evidence must be quoted
                          │
                          ▼
                   SQLite (local disk)  ──▶ Markdown report
```

**What to expect:** it is a second pair of eyes and a drafting aid, not a scanner replacement. It
will surface things worth a look (exposed data, error leaks, IDOR candidates); you confirm them.
Logic and authorization flaws mostly still need you.

## How a finding is produced
1. **Deterministic checks** (`services/checks.py`): headers, cookies, CORS, stack traces, secrets,
   JWT `alg=none`, password hashes, bulk PII, directory listings, reflected input, open redirects,
   admin/config endpoints answering **without credentials**, and account enumeration. Fast, repeatable,
   no model.
   - **Object-ID leads** look across the whole capture: authenticated requests to endpoints like
     `/rest/basket/{id}` become `idor_lead` findings (info severity): places worth testing for broken
     access control with a second user. They are leads, not confirmed issues. Nothing is sent.
2. **LLM triage** (`services/ollama_client.py`): structured JSON output at low temperature, then a
   quality gate. A suggestion is discarded unless its evidence is quoted verbatim from the traffic,
   is not just the request line, is not a bare category title ("Potential Information Disclosure"),
   is not a bare header line (`Content-Type: image/jpeg`) offered as proof of a behavior claim, is not
   an upload claim without a `multipart/form-data` request, is not for plumbing paths like
   `/socket.io/`, and does not duplicate a deterministic finding. Findings that pass but rest on thin
   evidence (a bare header, a quote under 20 characters, or text found only in the request) are kept
   and tagged **weak evidence** so you check them before relying on them.
   Model severity is capped (see `LLM_SEVERITY_CAP`). `llm_discard_reasons` in the scan status shows
   why suggestions were dropped, which is how you measure a model or prompt change.
3. **You** review candidates (CLI or the review page) and mark them `confirmed` or `dismissed`.
4. **Report** includes confirmed findings only (optionally with LLM-drafted prose you can edit).

## Setup
Needs Python 3.10+ (3.12 recommended).

```bash
uv venv --python 3.12 .venv && uv pip install --python .venv/bin/python -r requirements.txt
cp .env.example .env     # set BURP_MCP_URL, OLLAMA_HOST, OLLAMA_MODEL (scope is set per engagement in the UI)
.venv/bin/python main.py
```

### Burp side
1. Install **MCP Server** from the BApp Store; enable it in Burp's **MCP** tab.
2. Burp asks for approval before handing over proxy history. Approve it, or enable auto-approve for
   history in the MCP tab (the first scan will time out or return nothing otherwise; the scan
   status says so).
3. The extension has **no authentication**. Keep it on loopback and reach it with an SSH tunnel, or,
   if you use a Parallels port forward, restrict the forwarded port to the Mac mini's IP with a
   firewall rule.
4. If you connect through a forward and get 403s, set `BURP_HOST_HEADER=127.0.0.1:9876`.

### Ollama side
```bash
ollama pull mistral        # or a larger model; set OLLAMA_MODEL
```
`OLLAMA_KEEP_ALIVE` keeps the model loaded between requests (cold loads are a big part of "slow").

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

## WSTG coverage (OWASP Web Security Testing Guide v4.2)

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

## Scripts, slow items and runaway replies

- **Scripts never reach the model** (`LLM_SKIP_JS=true`): files are skipped by extension (`.js`, `.mjs`,
  `.map`, ...), by `Content-Type`, and by content, so a bundle served as `text/plain` or `text/html` is
  still recognized. Their *requests* are still covered by the deterministic checks (secrets, source maps).
- **Bounded output** (`OLLAMA_NUM_PREDICT`, default 1024): triage replies are short JSON, so a reply that
  runs past the limit is discarded and logged instead of generating until the timeout.
- **One slow item doesn't stop the scan:** if a request times out but Ollama still answers a health check,
  that item is skipped (counted as `timed_out_skipped` in the scan status, with the path in the log) and
  the scan carries on. The job only auto-pauses when Ollama itself looks down or errors keep coming.
- Request bodies and response bodies are each cut to `MAX_BODY_CHARS` (4000) before being sent, so the
  prompt stays far inside `OLLAMA_NUM_CTX`. A timeout is almost never a context overflow.

## Logs and troubleshooting

The **Logs** button (header, and "View logs" in the scan panel) shows recent service events: model
errors, auto-pauses, Burp connection failures and job start/finish. It follows a running scan and can
filter to warnings and errors. The same events go to `<DATA_DIR>/analyzer.log` (rotating, 1 MB x 3,
owner-only permissions; change with `LOG_FILE`, or `LOG_FILE=off`). `GET /api/logs?level=WARNING` returns
them as JSON. Entries hold the method and path only (no query strings or bodies) and engagement ids,
not client names, so a log is safe to share.

Model errors now say what happened: a timeout names the limit (`OLLAMA_TIMEOUT`), a refused or dropped
connection names the Ollama host and likely cause, and an HTTP error includes Ollama's own message (for
example `model requires more system memory`). The scan panel shows the **last model error** with its
time, and the auto-pause warning (after 3 model errors in a row) includes it.

## Review page
Open `http://localhost:8765/ui/` in a browser. Filter by status, severity or source; similar findings
are grouped (with a one-click "Dismiss all" for noisy groups). Select a finding to see, in order: the model's
reasoning (labeled unverified), the quoted evidence, and a **Show in context** dropdown with the full
request and response, the evidence highlighted (long bodies are windowed around the match, with a
"Show all" button). Then add notes, change severity, draft report prose with the model, and confirm or
dismiss. Keys: `j`/`k` move, `c` confirm, `d` dismiss. It also starts scans and previews the report.
The page holds no data itself; it calls the token-protected API, and if `API_TOKEN` is set it asks for
it (kept for that tab only). Captured traffic is attacker-controlled, so the page renders it as text only
and is served with a strict Content-Security-Policy.

## Scanning: once, or live
Open **Scan Burp…** in the review page (or use `POST /api/scan`).

- **Scan once** pulls `count` items from Burp's Proxy history, then finishes.
- **Live** keeps watching: every `interval_seconds` (default 15) it asks Burp for history added since
  the last poll, so each poll is cheap. `min_batch` (default 1) waits for that many new requests
  before analyzing; a smaller batch is still processed once traffic goes quiet. If you clear Burp's
  history, it notices and starts over from the beginning.

Either way the work is split in two, so a big capture never blocks you:

1. **Instant:** scope filter, deterministic checks and the object-ID leads run as soon as items are
   pulled, so those findings appear within seconds of the traffic.
2. **Background:** model review goes into a queue stored in the database, and a worker drains it one
   item at a time (~7-9 s each on a 7B model). The page shows queue depth, seconds per item and an
   ETA. The queue survives restarts.

**Speed:** the model is the bottleneck, so it is not asked about everything. Near-duplicate endpoints
(same method, host, path template and status, e.g. `/api/products/1`, `/api/products/2`) are reviewed
at most `LLM_MAX_PER_ENDPOINT` times (default 3; `0` = review all). Images, CSS, JS, empty bodies and
`LLM_SKIP_PATHS` are skipped. The deterministic checks always run on every in-scope item. So 1000
requests is typically a few hundred model calls, not 1000.

**Controls** (only one job runs at a time, since there is one model):
- **Pause** holds after the current model item (a few seconds); **Resume** carries on exactly where it was.
- **Stop** cancels immediately (also how you end a live watch). Nothing is lost: findings are kept and
  unfinished model work stays queued for the next run. **Clear model queue** discards that backlog.
- If the model errors 3 times in a row (Ollama down?) the job **pauses itself** with a warning instead
  of burning through the queue; fix it and Resume. A live watch tolerates Burp restarting and gives up
  only after 10 failed polls in a row.

API: `POST /api/scan` (`live`, `interval_seconds`, `min_batch`), `POST /api/scan/{id}/pause|resume|cancel`,
`DELETE /api/queue`. `GET /api/scan/{id}` returns `status` (`running`, `paused`, `done`, `error`,
`canceled`) plus `queue_depth`, `llm_avg_seconds`, `eta_minutes`, `skipped_endpoint_cap` and, in live
mode, `polls`, `last_poll` and `next_offset`.

## Usage
```bash
# health: Burp connection, Ollama + model, scope
curl localhost:8765/api/health

# pull history and analyze (background job); scope comes from the engagement
curl -X POST localhost:8765/api/scan -H "X-Engagement: $ENG" -H 'content-type: application/json' -d '{"count":200}'
curl localhost:8765/api/scan/<job_id>         # progress, counts, LLM time, warnings

# review
curl 'localhost:8765/api/findings?status=candidate&severity=high'
curl localhost:8765/api/findings/<id>         # includes the raw request/response
curl -X PATCH localhost:8765/api/findings/<id> -H 'content-type: application/json' \
     -d '{"status":"confirmed","notes":"Reproduced in Repeater with user B token"}'

# report
curl -X POST localhost:8765/api/findings/<id>/draft   # optional: LLM drafts the prose
curl localhost:8765/api/report > report.md            # confirmed findings only
```
Interactive docs at `/docs`. `POST /api/analyze` analyzes one pasted request/response without Burp.

Re-scanning is incremental: identical exchanges and findings are de-duplicated, and items the LLM
has already reviewed are skipped.

## Safety
- **Scope is mandatory and per engagement.** Only hosts matching that engagement's scope are analyzed;
  out-of-scope items are counted and dropped. Burp's history is shared across clients, so this is what
  keeps one client's traffic out of another's workspace.
- **Clients are isolated.** Separate database per engagement, an explicit engagement on every request,
  and no client names in URLs or paths.
- **Read-only toward Burp.** Only the proxy-history tools are called. The service never sends
  traffic or touches Repeater/Intruder/scanner.
- Binds to `127.0.0.1` by default. Any other bind requires `API_TOKEN` (bearer auth). No CORS.
- Evidence for cookies, hashes and secrets is redacted before storage.
- SQLite lives on local disk (one file per engagement); `POST /api/backup` copies it to `BACKUP_DIR` (e.g. the NAS).

## Tests
```bash
.venv/bin/python -m pytest
```
Includes the Burp client run against a stand-in MCP server over both transports.

## Known limitations
- The exact JSON shape of Burp's history items isn't documented; the parser accepts several
  variants and the scan status reports anything it couldn't parse. Verify on first real run.
- Scheme (http/https) isn't in Burp's serialized items, so HSTS and `Secure`-flag checks only fire
  when the scheme is inferable (absolute URI or `:443`).
- One model, one request at a time. Live-mode object-ID leads are computed per batch of new requests,
  so a lead's "IDs seen" list reflects the batch that first produced it.
- Live mode assumes Burp's history is append-only and indexed oldest-first (`offset` counts from the
  oldest item). Clearing history is detected; other reordering is not.
- One model, one request at a time. A two-tier (small filter + larger triage) setup is a possible
  next step once you've measured real speed and hit-rate on your hardware.
- Old planning docs are kept in `docs_old/`; they describe the previous REST-based design.

## License

MIT, see [LICENSE](LICENSE). The authorized-use notice at the top of this file is a request and a
reminder, not a license condition: you remain responsible for how you use the software.
