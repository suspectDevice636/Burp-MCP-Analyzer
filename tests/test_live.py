import asyncio
import re
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from config.config import settings
from services import ollama_client, pipeline as pipeline_mod
from services.pipeline import Job, Pipeline
from services.store import Store
from tests.conftest import item, raw, resp

SCOPE = ["localhost:3000"]


def mk(i, path=None):
    return item(raw(path=path or f"/api/thing{i}/x"), resp(body='{"n":%d}' % i))


class GrowingBurp:
    def __init__(self, items=None):
        self.items = list(items or [])
        self.calls = []
        self.fail = 0

    async def history(self, count, offset=0, regex=None):
        self.calls.append((count, offset))
        if self.fail:
            self.fail -= 1
            raise ConnectionError("Burp is down")
        return self.items[offset: offset + count]


class SlowLLM:
    def __init__(self, delay=0.05):
        self.delay, self.calls = delay, []

    async def triage(self, ex):
        self.calls.append(ex.path_only)
        await asyncio.sleep(self.delay)
        return ollama_client.TriageResult(timings=ollama_client.Timings(total_s=0.05))


class ErrLLM:
    async def triage(self, ex):
        return ollama_client.TriageResult(error="boom")


async def wait_for(cond, timeout=5.0):
    end = asyncio.get_event_loop().time() + timeout
    while not cond():
        if asyncio.get_event_loop().time() > end:
            raise AssertionError("condition not met in time")
        await asyncio.sleep(0.02)


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "t.db")


# ------------------------------------------------------------ pause / cancel
async def test_pause_holds_model_work_and_resume_finishes(store):
    pipe = Pipeline(store, GrowingBurp([mk(i) for i in range(6)]), llm=SlowLLM(0.05))
    job = Job()
    task = asyncio.create_task(pipe.scan_burp(job, 50, 0, SCOPE, True))
    await wait_for(lambda: job.llm_done >= 1)
    job.paused = True
    await wait_for(lambda: job.status == "paused")
    done = job.llm_done
    await asyncio.sleep(0.3)
    assert job.llm_done == done                     # nothing happens while paused
    job.paused = False
    await task
    assert job.status == "done" and job.llm_done == 6 and store.queue_depth() == 0


async def test_cancel_keeps_findings_and_leaves_work_queued_for_next_run(store):
    pipe = Pipeline(store, GrowingBurp([mk(i) for i in range(8)]), llm=SlowLLM(0.05))
    job = Job()
    task = asyncio.create_task(pipe.scan_burp(job, 50, 0, SCOPE, True))
    await wait_for(lambda: job.llm_done >= 2)
    task.cancel()
    await task
    assert job.status == "canceled"
    left = store.queue_depth()
    assert 0 < left < 8                              # unfinished work is still queued, not lost
    assert store.stats()["items_seen"] == 8          # everything ingested is kept

    job2 = Job()                                      # a later run drains the leftovers
    await pipe.scan_burp(job2, 50, 0, SCOPE, True)
    assert job2.status == "done" and store.queue_depth() == 0 and job2.llm_total == left


async def test_cancel_while_paused(store):
    pipe = Pipeline(store, GrowingBurp([mk(i) for i in range(4)]), llm=SlowLLM(0.05))
    job = Job()
    job.paused = True
    task = asyncio.create_task(pipe.scan_burp(job, 50, 0, SCOPE, True))
    await wait_for(lambda: job.status == "paused")
    task.cancel()
    await task
    assert job.status == "canceled"


async def test_model_outage_auto_pauses_instead_of_burning_the_queue(store):
    pipe = Pipeline(store, GrowingBurp([mk(i) for i in range(5)]), llm=ErrLLM())
    job = Job()
    task = asyncio.create_task(pipe.scan_burp(job, 50, 0, SCOPE, True))
    await wait_for(lambda: job.status == "paused")
    assert job.llm_errors == 3 and any("Paused after 3 model errors" in w for w in job.warnings)
    # item 1 was retried then given up on; the other four are still queued
    assert store.queue_depth() == 4
    task.cancel()
    await task


# ----------------------------------------------------------------- live mode
async def test_live_ingests_only_new_history_then_stops(store):
    burp = GrowingBurp([mk(i) for i in range(3)])
    pipe = Pipeline(store, burp, llm=SlowLLM(0.01))
    job = Job(mode="live", interval_seconds=0.05)
    task = asyncio.create_task(pipe.scan_burp(job, 0, 0, SCOPE, True))
    await wait_for(lambda: job.in_scope == 3 and job.llm_done == 3)

    burp.items += [mk(i) for i in range(3, 5)]       # traffic arrives while it is watching
    await wait_for(lambda: job.in_scope == 5 and job.llm_done == 5)
    full_pulls_from_zero = [c for c in burp.calls if c == (settings.history_page_size, 0)]
    assert len(full_pulls_from_zero) == 1             # it did not re-read old history
    assert (settings.history_page_size, 3) in burp.calls
    assert job.next_offset == 5 and job.polls >= 3

    task.cancel()
    await task
    assert job.status == "canceled"
    n = len(burp.calls)
    await asyncio.sleep(0.2)
    assert len(burp.calls) == n                        # polling really stopped


async def test_live_min_batch_waits_then_flushes_when_quiet(store):
    burp = GrowingBurp([mk(i) for i in range(3)])
    pipe = Pipeline(store, burp)
    job = Job(mode="live", min_batch=5)
    await pipe._poll(job, SCOPE, False, None)
    assert job.in_scope == 0 and job.buffered == 3     # held back: fewer than 5

    burp.items += [mk(i) for i in range(3, 6)]
    await pipe._poll(job, SCOPE, False, None)
    assert job.in_scope == 6 and job.buffered == 0     # 6 >= 5: processed together

    job2 = Job(mode="live", min_batch=10)
    pipe2 = Pipeline(Store(store.path.parent / "b.db"), GrowingBurp([mk(i) for i in range(3)]))
    await pipe2._poll(job2, SCOPE, False, None)
    assert job2.in_scope == 0
    await pipe2._poll(job2, SCOPE, False, None)        # no growth: traffic went quiet, flush
    assert job2.in_scope == 3


async def test_live_resyncs_when_burp_history_is_cleared(store):
    burp = GrowingBurp([mk(0), mk(1)])
    pipe = Pipeline(store, burp)
    job = Job(mode="live")
    await pipe._poll(job, SCOPE, False, None)
    assert job.in_scope == 2 and job.next_offset == 2
    burp.items = [mk(7)]                               # history cleared, new traffic since
    await pipe._poll(job, SCOPE, False, None)
    assert job.in_scope == 3 and job.next_offset == 1
    assert any("resynced" in w for w in job.warnings)


async def test_live_survives_burp_blips_but_gives_up_eventually(store, monkeypatch):
    burp = GrowingBurp([mk(0)])
    burp.fail = 2
    job = Job(mode="live", interval_seconds=0.02)
    task = asyncio.create_task(Pipeline(store, burp).scan_burp(job, 0, 0, SCOPE, False))
    await wait_for(lambda: job.in_scope == 1)           # recovered after two failed polls
    assert job.status == "running" and len(burp.calls) > 2     # it saw the failures and carried on
    assert not any("poll failed" in w for w in job.warnings)   # and the stale warning healed
    task.cancel()
    await task

    monkeypatch.setattr(pipeline_mod, "MAX_POLL_FAILURES", 3)
    burp2 = GrowingBurp()
    burp2.fail = 10 ** 6
    job2 = Job(mode="live", interval_seconds=0.01)
    await Pipeline(Store(store.path.parent / "c.db"), burp2).scan_burp(job2, 0, 0, SCOPE, False)
    assert job2.status == "error" and "Burp unreachable" in job2.error


# ------------------------------------------------------- endpoint sampling
async def test_near_duplicate_endpoints_capped(store, monkeypatch):
    monkeypatch.setattr(settings, "llm_max_per_endpoint", 2)
    items = [mk(i, path=f"/api/products/{i}") for i in range(1, 7)] + [mk(0, path="/api/other")]
    llm = SlowLLM(0.0)
    job = Job()
    await Pipeline(store, GrowingBurp(items), llm=llm).scan_burp(job, 50, 0, SCOPE, True)
    assert job.skipped_endpoint_cap == 4 and len(llm.calls) == 3   # 2 products + the other endpoint
    assert store.stats()["items_seen"] == 7                         # deterministic checks saw all of them


async def test_cap_zero_reviews_everything(store, monkeypatch):
    monkeypatch.setattr(settings, "llm_max_per_endpoint", 0)
    llm = SlowLLM(0.0)
    await Pipeline(store, GrowingBurp([mk(i, path=f"/api/products/{i}") for i in range(1, 6)]), llm=llm).scan_burp(
        Job(), 50, 0, SCOPE, True)
    assert len(llm.calls) == 5


# --------------------------------------------------------------- the store
def test_store_migrates_an_old_database(tmp_path):
    path = tmp_path / "old.db"
    db = sqlite3.connect(path)
    db.executescript("""
        CREATE TABLE items (id TEXT PRIMARY KEY, method TEXT, url TEXT, host TEXT, status INTEGER,
            raw_request TEXT, raw_response TEXT, llm_done INTEGER NOT NULL DEFAULT 0, first_seen TEXT NOT NULL);
        INSERT INTO items VALUES ('abc','GET','http://x/','x',200,'r','s',1,'2026-01-01');
    """)
    db.commit(); db.close()
    s = Store(path)
    cols = {r["name"] for r in s._db.execute("PRAGMA table_info(items)")}
    assert {"llm_queued", "llm_attempts", "endpoint"} <= cols
    assert s.item_llm_done("abc") and s.queue_depth() == 0     # old data intact
    Store(path)                                                  # reopening is idempotent


def test_store_queue_operations(store):
    from services.httpmsg import build_exchange
    ex = build_exchange(raw(path="/a"), resp(body="{}"))
    store.upsert_item(ex)
    assert store.llm_slots_used(ex.endpoint) == 0
    store.enqueue_llm(ex.id)
    assert store.queue_depth() == 1 and store.llm_slots_used(ex.endpoint) == 1
    assert store.next_queued()["id"] == ex.id
    assert store.clear_queue() == 1 and store.queue_depth() == 0
    store.enqueue_llm(ex.id); store.mark_llm_done(ex.id)
    assert store.queue_depth() == 0 and store.item_llm_done(ex.id)
    store.enqueue_llm(ex.id)                                      # done items are never re-queued
    assert store.queue_depth() == 0


# -------------------------------------------------------------------- the API
@pytest.fixture
def client(api):
    api.app.state.burp = GrowingBurp([mk(i) for i in range(3)])
    return api


def test_api_live_pause_resume_cancel_flow(client):
    r = client.post("/api/scan", json={"live": True, "interval_seconds": 2, "min_batch": 3, "use_llm": False})
    assert r.status_code == 200
    job = r.json()
    assert job["mode"] == "live" and job["interval_seconds"] == 2 and job["min_batch"] == 3
    jid = job["id"]

    assert client.post("/api/scan", json={}).status_code == 409           # one job at a time
    assert client.post(f"/api/scan/{jid}/pause").json()["paused"] is True
    assert client.post(f"/api/scan/{jid}/resume").json()["paused"] is False
    out = client.post(f"/api/scan/{jid}/cancel").json()
    assert out["status"] == "canceled"
    assert client.post(f"/api/scan/{jid}/pause").status_code == 409       # already finished
    assert client.post("/api/scan/nope/pause").status_code == 404
    assert client.post("/api/scan", json={"use_llm": False}).status_code == 200   # a new one may start


def test_api_validation_and_queue_clear(client):
    assert client.post("/api/scan", json={"live": True, "interval_seconds": 0.1}).status_code == 422
    assert client.post("/api/scan", json={"live": True, "min_batch": 0}).status_code == 422
    assert client.delete("/api/queue").json() == {"cleared": 0}
    assert "model_queue" in client.get("/api/findings/stats").json()


# ---------------------------------------------------------------------- the UI
def test_ui_script_only_references_elements_that_exist():
    html = Path("ui/index.html").read_text()
    js = Path("ui/app.js").read_text()
    ids = set(re.findall(r'\$\("([\w-]+)"\)', js)) | set(re.findall(r'getElementById\("([\w-]+)"\)', js))
    missing = [i for i in ids if f'id="{i}"' not in html]
    assert not missing, f"app.js references ids not in index.html: {missing}"


# ------------------------------------- Burp's "Reached end of items" and healing warnings
def test_end_of_history_reply_is_not_an_item():
    from services.burp_mcp import is_end_marker, split_history_texts
    assert is_end_marker("Reached end of items") and is_end_marker("  reached end of items. ")
    assert split_history_texts("Reached end of items") == []
    a = mk(1)
    assert split_history_texts("[" + a + ',"Reached end of items"]') == [a]
    assert split_history_texts("Proxy history access denied") == ["Proxy history access denied"]   # still unparsed


class EndMarkerBurp:
    """Returns real items, then Burp's plain-text end marker once you ask past the end."""
    def __init__(self, items):
        self.items = items

    async def history(self, count, offset=0, regex=None):
        chunk = self.items[offset: offset + count]
        return chunk if chunk else ["Reached end of items"]


async def test_live_polls_past_the_end_do_not_count_as_unparsed_or_warn(store):
    burp = EndMarkerBurp([mk(i) for i in range(3)])
    pipe = Pipeline(store, burp)
    job = Job(mode="live")
    for _ in range(5):                                   # one real poll, then quiet polls at the end
        await pipe._poll(job, SCOPE, False, None)
    assert job.in_scope == 3 and job.unparsed == 0 and job.warnings == []


async def test_stale_warnings_clear_once_the_problem_is_gone(store):
    burp = GrowingBurp(["Proxy history access denied"])  # unreadable: looks like a pending approval
    pipe = Pipeline(store, burp)
    job = Job(mode="live")
    await pipe._poll(job, SCOPE, False, None)
    assert any("No items could be parsed" in w for w in job.warnings)
    burp.items = [mk(0)]                                 # approved: real items now
    await pipe._poll(job, SCOPE, False, None)
    assert not any("No items could be parsed" in w for w in job.warnings)


async def test_poll_failure_warnings_clear_after_recovery(store):
    burp = GrowingBurp([mk(0)])
    burp.fail = 2
    job = Job(mode="live", interval_seconds=0.02)
    task = asyncio.create_task(Pipeline(store, burp).scan_burp(job, 0, 0, SCOPE, False))
    await wait_for(lambda: job.in_scope == 1)
    await wait_for(lambda: not any("poll failed" in w for w in job.warnings))
    task.cancel()
    await task
