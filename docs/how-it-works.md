# How it works

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

[← Back to the README](../README.md)
