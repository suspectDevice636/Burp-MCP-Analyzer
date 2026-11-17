# Scanning

## Once or live
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

[← Back to the README](../README.md)
