"""Orchestration: pull Burp history -> scope -> checks -> model queue -> store.

Two decoupled halves:

  * ingest (fast): pull history, filter to scope, run the deterministic checks and
    add model work to a persistent queue (in SQLite).
  * model worker (slow, ~7-9 s/item): drains that queue one item at a time.

A job runs in one of two modes:
  once  pull `count` items from `offset`, then drain the queue and finish.
  live  keep polling Burp every `interval_seconds`, ingesting only NEW history, while
        the worker drains the queue in the background. Runs until stopped.

Both modes support pause/resume and cancel. Canceling loses nothing: the queue lives
in the database, so unfinished model work simply waits for the next run.
"""

from __future__ import annotations

import asyncio
import fnmatch
import hashlib
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from config.config import settings
from services import checks, ollama_client, wstg
from services.burp_mcp import parse_history_item, split_history_texts
from services.httpmsg import Exchange, build_exchange
from services.store import Store

logger = logging.getLogger(__name__)

LLM_CONTENT_TYPES = ("json", "html", "xml", "text/plain", "x-www-form-urlencoded")
LIVE_POLL_MAX = 1000          # most history items ingested per live poll
MAX_MODEL_ERRORS_IN_ROW = 3   # then the job auto-pauses (Ollama probably down)
MAX_ITEM_ATTEMPTS = 2         # then that one item is given up on
MAX_POLL_FAILURES = 10        # consecutive Burp poll failures before a live job stops


def in_scope(ex: Exchange, patterns: list[str]) -> bool:
    """Match host or host:port against fnmatch patterns. Empty scope matches nothing."""
    host, hostport = ex.hostname.lower(), ex.host.lower()
    return any(
        fnmatch.fnmatch(host, p.lower()) or fnmatch.fnmatch(hostport, p.lower())
        for p in patterns
    )


JS_EXT = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".map")
CODE_HINT = re.compile(r"\bfunction\s*\(|=>|\b(?:var|let|const)\s+[\w$]+\s*=|webpackJsonp|\(function\(|!function\(|[\"']use strict[\"']")


def looks_like_js(body: str) -> bool:
    """Script served with a wrong Content-Type (text/plain, text/html, none)."""
    head = body.lstrip()[:3000]
    if not head or head[0] in "{[<":      # JSON and HTML are reviewed normally
        return False
    return bool(CODE_HINT.search(head))


def llm_eligible(ex: Exchange) -> bool:
    r = ex.response
    if r is None or checks.is_static(ex):
        return False
    path = ex.path_only.lower()
    if any(p in path for p in settings.llm_skip_paths):
        return False
    ct = r.content_type
    if settings.llm_skip_js and (path.endswith(JS_EXT) or "javascript" in ct or looks_like_js(r.body)):
        return False
    if ct and not any(t in ct for t in LLM_CONTENT_TYPES + ("javascript",)):
        return False
    return bool(r.body.strip() or ex.request.body.strip())


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Job:
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:10])
    engagement_id: str = ""
    engagement_name: str = ""
    # running | paused | done | error | canceled
    status: str = "running"
    mode: str = "once"  # once | live
    paused: bool = False  # requested; status flips to "paused" once the current item finishes
    started: str = field(default_factory=_now)
    fetched: int = 0
    in_scope: int = 0
    out_of_scope: int = 0
    unparsed: int = 0
    unparsed_sample: str = ""
    new_findings: int = 0
    llm_total: int = 0           # model work added to the queue (plus any leftovers at start)
    llm_done: int = 0
    llm_errors: int = 0
    llm_discarded: int = 0
    llm_discard_reasons: dict = field(default_factory=dict)
    llm_seconds: float = 0.0
    queue_depth: int = 0
    skipped_endpoint_cap: int = 0  # near-duplicate endpoints not sent to the model
    # live mode
    interval_seconds: float = 0.0
    min_batch: int = 1
    polls: int = 0
    last_poll: str | None = None
    next_offset: int = 0
    buffered: int = 0
    error: str | None = None
    llm_last_error: str = ""
    llm_last_error_at: str | None = None
    warnings: list[str] = field(default_factory=list)
    # internal (never serialized)
    _task: Any = field(default=None, repr=False)
    _first_fp: str | None = field(default=None, repr=False)
    _buffer: list = field(default_factory=list, repr=False)
    _last_buffer_len: int = field(default=0, repr=False)
    _errors_in_row: int = field(default=0, repr=False)

    def warn(self, msg: str) -> None:
        if msg not in self.warnings:
            self.warnings.append(msg)
            del self.warnings[:-20]

    def drop_warnings(self, prefix: str) -> None:
        """Remove warnings about a problem that has since gone away."""
        self.warnings[:] = [w for w in self.warnings if not w.startswith(prefix)]

    @property
    def active(self) -> bool:
        return self.status in ("running", "paused")

    def public(self) -> dict:
        d = {k: (list(v) if isinstance(v, list) else v) for k, v in self.__dict__.items() if not k.startswith("_")}
        avg = self.llm_seconds / self.llm_done if self.llm_done else None
        d["llm_avg_seconds"] = round(avg, 1) if avg else None
        d["eta_minutes"] = round(self.queue_depth * avg / 60, 1) if avg and self.queue_depth else None
        return d


class Pipeline:
    def __init__(self, store: Store, burp, llm=ollama_client):
        self.store, self.burp, self.llm = store, burp, llm

    # ---- single exchange ------------------------------------------
    def analyze_deterministic(self, ex: Exchange) -> int:
        """Run checks, store item and findings. Returns number of NEW findings."""
        if self.store.upsert_item(ex):   # count coverage once per distinct request
            self.store.add_coverage(wstg.exercised(ex))
        return self._store_candidates(ex, checks.run_checks(ex))

    def analyze_cross_request(self, exchanges: list[Exchange]) -> int:
        """Checks that need several exchanges at once (e.g. object-ID endpoints)."""
        n = 0
        for ex, c in checks.cross_request_checks(exchanges):
            n += self._store_candidates(ex, [c])
        return n

    def _store_candidates(self, ex: Exchange, candidates) -> int:
        n = 0
        for c in candidates:
            fid = self.store.add_finding({
                "item_id": ex.id, "dedupe_key": c.dedupe_key, "source": c.source,
                "type": c.type, "title": c.title, "severity": c.severity,
                "confidence": c.confidence, "method": ex.method, "url": ex.url,
                "evidence": c.evidence, "description": c.description,
                "recommendation": c.recommendation,
            })
            n += fid is not None
        return n

    async def _ollama_healthy(self) -> bool:
        probe = getattr(self.llm, "check_health", None)
        if probe is None:
            return False
        try:
            return bool((await probe()).get("ok"))
        except Exception:  # noqa: BLE001
            return False

    @staticmethod
    def _weak(f, ex) -> bool:
        return ollama_client.weak_evidence(f, ex)

    async def analyze_llm(self, ex: Exchange, job: Job | None = None) -> int:
        """Model-review one exchange. Marks it done only on success (errors leave it queued)."""
        res = await self.llm.triage(ex)
        where = f"{ex.method} {ex.path_only}"
        if res.error and res.error_kind == "timeout" and await self._ollama_healthy():
            # One slow item, not a dead model: skip it rather than retry it (it would time out again)
            # and rather than let a few of them pause the whole job.
            logger.warning("model request timed out on %s (Ollama is up): skipped. %s", where, res.error)
            if job:
                job.warn(f"{where}: skipped, the model timed out on it although Ollama is up")
                job.llm_discard_reasons["timed_out_skipped"] = job.llm_discard_reasons.get("timed_out_skipped", 0) + 1
                job.llm_discarded += 1
            self.store.mark_llm_done(ex.id)
            return 0
        if res.truncated:
            logger.warning("model reply to %s hit the %d-token limit (OLLAMA_NUM_PREDICT): no findings kept",
                           where, settings.ollama_num_predict)
            if job:
                job.warn(f"{where}: model reply hit the token limit and was discarded")
        if res.error:
            logger.warning("model error [engagement %s] %s: %s", (job.engagement_id if job else "") or "-", where, res.error)
            if job:
                job.warn(f"{where}: {res.error}")
                job.llm_last_error, job.llm_last_error_at = res.error, _now()
            return 0
        n = 0
        reasons = dict(res.discard_reasons)
        known = self.store.findings_for_url(ex.url, source="check")
        for f in res.findings:
            if _duplicates_check(f.evidence_quote, known):
                reasons["duplicate_of_check"] = reasons.get("duplicate_of_check", 0) + 1
                continue
            key = f"llm:{f.type}:{ex.method}:{ex.host}{ex.path_only}:{f.title.lower()[:60]}"
            fid = self.store.add_finding({
                "item_id": ex.id, "dedupe_key": key, "source": "llm", "type": f.type,
                "title": f.title, "severity": f.severity, "confidence": f.confidence,
                "method": ex.method, "url": ex.url, "evidence": f.evidence_quote,
                "description": f.explanation, "recommendation": f.recommendation,
                "evidence_quality": "weak" if self._weak(f, ex) else "",
            })
            n += fid is not None
        self.store.mark_llm_done(ex.id)
        if job:
            job.llm_discarded += sum(reasons.values())
            for k, v in reasons.items():
                job.llm_discard_reasons[k] = job.llm_discard_reasons.get(k, 0) + v
            job.llm_seconds += res.timings.total_s
        return n

    # ---- jobs ------------------------------------------------------
    async def scan_burp(self, job: Job, count: int, offset: int, scope: list[str],
                        use_llm: bool, regex: str | None = None) -> None:
        """Run a job to completion (once) or until canceled (live). Never raises."""
        logger.info("job %s started (%s, engagement %s)", job.id, job.mode, job.engagement_id or "-")
        try:
            if job.mode == "live":
                await self._live(job, scope, use_llm, regex, offset)
            else:
                await self._once(job, count, offset, scope, use_llm, regex)
                job.status = "done"
        except asyncio.CancelledError:
            job.status = "canceled"
        except BaseException as e:  # noqa: BLE001 - anyio ExceptionGroups
            logger.exception("job %s failed", job.id)
            job.status, job.error = "error", _err(e)
        logger.info("job %s finished: %s (fetched %d, findings %d, model errors %d)",
                    job.id, job.status, job.fetched, job.new_findings, job.llm_errors)

    async def _once(self, job, count, offset, scope, use_llm, regex) -> None:
        texts = await self._pull(count, offset, regex)
        self._ingest(job, self._parse(job, texts, scope), use_llm)
        if use_llm:
            job.llm_total = self.store.queue_depth()  # includes leftovers from a canceled run
            await self._drain(job, forever=False)

    async def _live(self, job, scope, use_llm, regex, offset) -> None:
        job.next_offset = offset
        job.llm_total = self.store.queue_depth() if use_llm else 0
        worker = asyncio.create_task(self._drain(job, forever=True)) if use_llm else None
        failures = 0
        try:
            while True:
                await self._checkpoint(job)
                try:
                    await self._poll(job, scope, use_llm, regex)
                    failures = 0
                    job.drop_warnings("Burp poll failed")
                except Exception as e:  # noqa: BLE001 - Burp restarting etc. must not kill the watch
                    failures += 1
                    logger.warning("job %s: Burp poll failed (%d/%d): %s", job.id, failures, MAX_POLL_FAILURES, _err(e))
                    job.warn(f"Burp poll failed ({failures}/{MAX_POLL_FAILURES}): {_err(e)}")
                    if failures >= MAX_POLL_FAILURES:
                        raise RuntimeError(f"Burp unreachable for {failures} polls in a row: {_err(e)}") from e
                if worker and worker.done():
                    worker.result()  # surface an unexpected worker crash
                    raise RuntimeError("model worker stopped unexpectedly")
                await asyncio.sleep(job.interval_seconds)
        finally:
            if worker:
                worker.cancel()
                await asyncio.gather(worker, return_exceptions=True)

    async def _checkpoint(self, job: Job) -> None:
        """Park here while paused."""
        if job.paused:
            job.status = "paused"
            while job.paused:
                await asyncio.sleep(0.25)
            job.status = "running"

    # ---- ingest ----------------------------------------------------
    async def _pull(self, count: int, offset: int, regex: str | None) -> list[str]:
        """Raw history entries from Burp, in pages."""
        out: list[str] = []
        pos, page = offset, settings.history_page_size
        while len(out) < count:
            take = min(page, count - len(out))
            blocks = await self.burp.history(take, pos, regex)
            texts = [t for b in blocks for t in split_history_texts(b)]
            if not texts:
                break
            out.extend(texts)
            pos += len(texts)
            if len(texts) < take:
                break
        return out

    def _parse(self, job: Job, texts: list[str], scope: list[str]) -> list[Exchange]:
        out: list[Exchange] = []
        seen: set[str] = set()
        bad = oos = 0
        for t in texts:
            job.fetched += 1
            item = parse_history_item(t)
            ex = build_exchange(item.request, item.response, item.notes) if item else None
            if ex is None:
                job.unparsed += 1
                bad += 1
                if not job.unparsed_sample:
                    job.unparsed_sample = f"[len={len(t)}] {t[:600]}"
                continue
            if not in_scope(ex, scope):
                job.out_of_scope += 1
                oos += 1
                continue
            if ex.id in seen:
                continue
            seen.add(ex.id)
            job.in_scope += 1
            out.append(ex)
        if bad and not out and not oos:
            job.warn("No items could be parsed. If Burp is waiting for approval of the "
                     "history request, approve it in Burp's MCP tab (or enable auto-approve).")
        elif out or oos:
            job.drop_warnings("No items could be parsed")   # items are coming through now
        return out

    def _ingest(self, job: Job, exchanges: list[Exchange], use_llm: bool) -> None:
        """Deterministic checks now; model work goes on the persistent queue."""
        for ex in exchanges:
            job.new_findings += self.analyze_deterministic(ex)
        job.new_findings += self.analyze_cross_request(exchanges)
        if use_llm:
            cap = settings.llm_max_per_endpoint
            for ex in exchanges:
                row = self.store.get_item(ex.id) or {}
                if row.get("llm_done") or row.get("llm_queued") or not llm_eligible(ex):
                    continue
                if cap and self.store.llm_slots_used(ex.endpoint) >= cap:
                    job.skipped_endpoint_cap += 1
                    continue
                self.store.enqueue_llm(ex.id)
                if job.mode == "live":
                    job.llm_total += 1
        job.queue_depth = self.store.queue_depth()

    async def _poll(self, job: Job, scope: list[str], use_llm: bool, regex: str | None) -> None:
        """One live-mode poll: ingest only history added since the last one."""
        # Detect a cleared history: the item at position 0 changes.
        probe = [t for b in await self.burp.history(1, 0, regex) for t in split_history_texts(b)]
        fp = hashlib.sha1(probe[0].encode("utf-8", "replace")).hexdigest() if probe else None
        if job._first_fp is not None and fp != job._first_fp:
            job.warn("Burp history changed (cleared?): resynced from the start.")
            job.next_offset = 0
            job._buffer.clear()
            job._last_buffer_len = 0
        job._first_fp = fp

        texts = await self._pull(LIVE_POLL_MAX, job.next_offset, regex)
        job.next_offset += len(texts)
        job._buffer.extend(texts)
        job.polls += 1
        job.last_poll = _now()

        n = len(job._buffer)
        # Process once min_batch have accumulated, or when traffic has gone quiet (no growth).
        if n and (n >= job.min_batch or n == job._last_buffer_len):
            batch, job._buffer = job._buffer, []
            job._last_buffer_len = 0
            self._ingest(job, self._parse(job, batch, scope), use_llm)
        else:
            job._last_buffer_len = n
        job.buffered = len(job._buffer)

    # ---- model worker ---------------------------------------------
    async def _drain(self, job: Job, forever: bool) -> None:
        while True:
            await self._checkpoint(job)
            row = self.store.next_queued()
            job.queue_depth = self.store.queue_depth()
            if row is None:
                if not forever:
                    return
                await asyncio.sleep(0.5)
                continue
            ex = build_exchange(row["raw_request"], row["raw_response"])
            if ex is None:
                self.store.mark_llm_done(row["id"])
                continue
            n = await self.analyze_llm(ex, job)
            if self.store.item_llm_done(ex.id):
                job.llm_done += 1
                job.new_findings += n
                job._errors_in_row = 0
                job.drop_warnings("Paused after")
            else:
                job.llm_errors += 1
                job._errors_in_row += 1
                if self.store.bump_attempts(ex.id) >= MAX_ITEM_ATTEMPTS:
                    self.store.mark_llm_done(ex.id)  # give up on this one item
                if job._errors_in_row >= MAX_MODEL_ERRORS_IN_ROW:
                    job._errors_in_row = 0
                    job.paused = True
                    logger.error("job %s paused after %d model errors in a row; last error: %s",
                                 job.id, MAX_MODEL_ERRORS_IN_ROW, job.llm_last_error)
                    job.warn(f"Paused after {MAX_MODEL_ERRORS_IN_ROW} model errors in a row. Last error: "
                             f"{job.llm_last_error or 'unknown'}. Fix it, then Resume.")
            job.queue_depth = self.store.queue_depth()


def _norm(s: str) -> str:
    return " ".join(s.split()).lower()


def _duplicates_check(quote: str, check_findings: list[dict]) -> bool:
    """True if a deterministic finding on the same URL already covers this evidence."""
    q = _norm(quote)
    for f in check_findings:
        ev = _norm(f.get("evidence") or "")
        if q and ev and (q in ev or ev in q):
            return True
    return False


def _err(e: BaseException) -> str:
    subs = getattr(e, "exceptions", None)
    if subs:
        return "; ".join(_err(x) for x in subs)[:300]
    return f"{type(e).__name__}: {e}"[:300]
