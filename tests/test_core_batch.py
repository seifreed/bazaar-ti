"""Tests for the concurrency helpers."""

from __future__ import annotations

import asyncio
import gc
import threading
import time
import warnings
from urllib.parse import parse_qs

from bazaar_ti.core.batch import MAX_CONCURRENCY, gather_async, threaded_map
from bazaar_ti.core.errors import RateLimitError
from bazaar_ti.services.malwarebazaar import MalwareBazaarAsync
from tests.conftest import ReplyApp


def test_threaded_map_nonempty() -> None:
    assert threaded_map(lambda x: x * 2, [1, 2, 3], concurrency=2) == [2, 4, 6]


def test_threaded_map_empty() -> None:
    assert threaded_map(lambda x: x, []) == []


def test_threaded_map_zero_concurrency() -> None:
    assert threaded_map(lambda x: x, [1, 2], concurrency=0) == [1, 2]


async def test_gather_async_zero_concurrency() -> None:
    async def one(value: int) -> int:
        return value

    assert await gather_async([one(1)], concurrency=0) == [1]


async def test_gather_async() -> None:
    async def double(value: int) -> int:
        await asyncio.sleep(0)
        return value * 2

    result = await gather_async([double(1), double(2)], concurrency=2)
    assert result == [2, 4]


async def test_gather_async_raises_but_still_runs_every_item() -> None:
    """A failure must not abandon the items still queued behind the semaphore.

    Letting it propagate straight out of gather left those coroutines unsent
    and warning that they were never awaited.
    """
    started: list[int] = []
    finished: list[int] = []

    async def item(value: int) -> int:
        started.append(value)
        if value == 0:
            raise RateLimitError("rate limited")
        # Suspending here is what separates "was scheduled" from "ran to the
        # end": gather turns every coroutine into a task up front, so they all
        # start either way, but only a gather that collects results lets the
        # ones queued behind the failure resume past this point.
        await asyncio.sleep(0)
        finished.append(value)
        return value

    reported = "no error"
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        try:
            await gather_async([item(i) for i in range(6)], concurrency=1)
        except RateLimitError as exc:
            gc.collect()
            assert not [w for w in caught if "never awaited" in str(w.message)]
            reported = str(exc)
    assert reported == "rate limited"
    assert sorted(started) == [0, 1, 2, 3, 4, 5]
    assert sorted(finished) == [1, 2, 3, 4, 5]


def test_threaded_map_never_exceeds_the_concurrency_ceiling() -> None:
    """One worker is one OS thread, so an unbounded count exhausts the machine."""
    lock = threading.Lock()
    live = 0
    peak = 0

    def work(_: int) -> int:
        nonlocal live, peak
        with lock:
            live += 1
            peak = max(peak, live)
        time.sleep(0.05)
        with lock:
            live -= 1
        return 1

    items = list(range(MAX_CONCURRENCY * 4))
    assert threaded_map(work, items, concurrency=100_000) == [1] * len(items)
    assert peak <= MAX_CONCURRENCY


async def test_gather_async_never_exceeds_the_concurrency_ceiling() -> None:
    live = 0
    peak = 0

    async def one() -> None:
        nonlocal live, peak
        live += 1
        peak = max(peak, live)
        await asyncio.sleep(0.01)
        live -= 1

    await gather_async([one() for _ in range(MAX_CONCURRENCY * 4)], concurrency=100_000)
    assert peak <= MAX_CONCURRENCY


async def test_gather_async_fans_a_bulk_lookup_out_across_the_async_client(
    base_url: str, app: ReplyApp
) -> None:
    """The job this helper exists for, and the one nothing exercised.

    ``threaded_map`` has a caller — the CLI's bulk mode drives it — so it is
    held in place by something that would break. ``gather_async`` is the async
    half and has no caller in the library at all: it is there for consumers of
    the async clients, who cannot use ``threaded_map`` because a thread pool
    blocks the event loop they are already in. Every test above drove it with
    bare coroutines, which is not the same thing as a client call: that opens a
    connection pool, awaits a socket, and is the only shape anyone will
    actually pass it.

    So this is what says the exported helper works on the clients exported
    beside it: every lookup reaches the server exactly once, none stranded
    behind the semaphore, and one answer comes back per input. Ordering is not
    asserted here — the server answers every request identically, so the
    results cannot tell it — and ``test_gather_async`` already holds it.
    """
    hashes = [f"{index:064x}" for index in range(12)]
    async with MalwareBazaarAsync(auth_key="k", base_url=base_url) as mb:
        results = await gather_async([mb.get_info(h) for h in hashes], concurrency=4)
    assert [r["query_status"] for r in results] == ["ok"] * len(hashes)
    sent = [parse_qs(body.decode())["hash"][0] for body in app.bodies]
    assert sorted(sent) == sorted(hashes)
