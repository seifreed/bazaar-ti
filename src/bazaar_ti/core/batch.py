"""Concurrency helpers: async fan-out and threaded map for bulk lookups."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from typing import cast

MAX_CONCURRENCY = 16
"""Ceiling on simultaneous requests, whatever the caller asks for.

Two reasons, and the second now binds first. Workers are one OS thread each, so
an unbounded count turns a large or mistyped value into thousands of threads and
exhausts the machine. And abuse.ch runs a Fair Use Policy: it rate limits
accounts with unusual query volumes for up to 72 hours, and repeated abuse
earns longer restrictions. A ceiling that protects the caller's machine but not
their account is only doing half the job, which is why this came down from 32.
"""

DEFAULT_CONCURRENCY = 4
"""How many lookups a bulk query runs at once when nobody says otherwise.

A default is what most callers will actually send, so it is the number that
decides whether this client is a good citizen of a free service. Four is still
four times faster than serial and is unlikely to be what gets an account
limited; anyone who has cleared a higher rate can pass ``--concurrency``.

The same number as the ``--concurrency`` default, which is the point: it was
written out three times — here, in the other helper below, and in the CLI — so
tuning the library default left the CLI still sending the old one, and the two
would have disagreed about what "no answer given" means. The ceiling beside it
was already read from one place by the CLI's help text; this is the other half.
"""


def _bounded(concurrency: int) -> int:
    return max(1, min(concurrency, MAX_CONCURRENCY))


async def gather_async[R](
    awaitables: Iterable[Awaitable[R]],
    *,
    concurrency: int = DEFAULT_CONCURRENCY,
) -> list[R]:
    """Await many coroutines with a bounded number running at once.

    Every awaitable is awaited even if one fails, then the first failure is
    raised. Letting the failure propagate straight out of ``gather`` would
    abandon the coroutines still queued behind the semaphore: they would never
    be sent, and each would warn that it was never awaited.
    """
    semaphore = asyncio.Semaphore(_bounded(concurrency))

    async def _run(item: Awaitable[R]) -> R:
        async with semaphore:
            return await item

    settled = await asyncio.gather(*(_run(item) for item in awaitables), return_exceptions=True)
    for outcome in settled:
        if isinstance(outcome, BaseException):
            raise outcome
    return cast("list[R]", settled)


def threaded_map[T, R](
    func: Callable[[T], R],
    items: Sequence[T],
    *,
    concurrency: int = DEFAULT_CONCURRENCY,
) -> list[R]:
    """Apply a blocking function across items using a thread pool, preserving order.

    Never runs more than :data:`MAX_CONCURRENCY` workers, so a large
    ``concurrency`` cannot spawn a thread per item and take the machine down.
    """
    if not items:
        return []
    # No min() against len(items): ThreadPoolExecutor starts a thread only when
    # it has work to hand it, so a short list never opens more than it needs.
    workers = _bounded(concurrency)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(func, items))
