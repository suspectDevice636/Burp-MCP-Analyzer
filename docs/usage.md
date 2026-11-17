# Using the review page and the API

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

## API examples
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

[← Back to the README](../README.md)
