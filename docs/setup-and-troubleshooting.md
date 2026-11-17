# Setup details and troubleshooting

## Burp side
1. Install **MCP Server** from the BApp Store; enable it in Burp's **MCP** tab.
2. Burp asks for approval before handing over proxy history. Approve it, or enable auto-approve for
   history in the MCP tab (the first scan will time out or return nothing otherwise; the scan
   status says so).
3. The extension has **no authentication**. Keep it on loopback and reach it with an SSH tunnel, or,
   if you use a Parallels port forward, restrict the forwarded port to the Mac mini's IP with a
   firewall rule.
4. If you connect through a forward and get 403s, set `BURP_HOST_HEADER=127.0.0.1:9876`.

## Ollama side
```bash
ollama pull mistral        # or a larger model; set OLLAMA_MODEL
```
`OLLAMA_KEEP_ALIVE` keeps the model loaded between requests (cold loads are a big part of "slow").

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

## Known limitations
- The exact JSON shape of Burp's history items isn't documented; the parser accepts several
  variants and the scan status reports anything it couldn't parse. Verify on first real run.
- Scheme (http/https) isn't in Burp's serialized items, so HSTS and `Secure`-flag checks only fire
  when the scheme is inferable (absolute URI or `:443`).
- One model, one request at a time. A two-tier setup (a small filter plus a larger triage model) is a
  possible next step once you've measured speed and hit rate on your hardware.
- Live-mode object-ID leads are computed per batch of new requests, so a lead's "IDs seen" list reflects
  the batch that first produced it.
- Live mode assumes Burp's history is append-only and indexed oldest-first (`offset` counts from the
  oldest item). Clearing history is detected; other reordering is not.

[← Back to the README](../README.md)
