"""abuse.ch datalake bulk batch downloads.

These are public ZIP archives (password ``infected``) published per hour and per
day; they need no Auth-Key. Example name: ``2026-07-24.zip`` (daily) — see the
directory listings under https://datalake.abuse.ch/.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .core.config import DATALAKE_URL, DEFAULT_RETRIES, DEFAULT_TIMEOUT
from .core.errors import BazaarTIError
from .core.transport import RequestSpec, Transport, path_segment

MALWAREBAZAAR = "malware-bazaar"
URLHAUS = "urlhaus"
DATASETS = (MALWAREBAZAAR, URLHAUS)

DAILY = "daily"
HOURLY = "hourly"
PERIODS = (DAILY, HOURLY)


@dataclass(frozen=True, slots=True)
class BatchOptions:
    """Transport settings for a datalake download."""

    timeout: float = DEFAULT_TIMEOUT
    retries: int = DEFAULT_RETRIES
    base_url: str = DATALAKE_URL


def _spec(dataset: str, period: str, name: str) -> RequestSpec:
    """Build the archive path, refusing segments that address a directory.

    An empty segment collapses the path onto its parent, which answers 200
    with an HTML directory listing — half a megabyte of markup that would be
    saved as the archive and reported as a successful download.
    """
    segments = {"dataset": dataset, "period": period, "name": name}
    for label, value in segments.items():
        if not value.strip():
            raise BazaarTIError(f"Datalake {label} is required (got {value!r}).")
    for label, value, allowed in (("dataset", dataset, DATASETS), ("period", period, PERIODS)):
        if value not in allowed:
            # These two name directories, so a wrong one is a 404 that reads
            # like the archive is missing rather than like a mistyped dataset.
            raise BazaarTIError(
                f"Unknown datalake {label} {value!r}; expected one of {', '.join(allowed)}."
            )
    parts = "/".join(path_segment(value) for value in segments.values())
    return RequestSpec(method="GET", path=parts)


def _transport(options: BatchOptions | None) -> Transport:
    opts = options or BatchOptions()
    return Transport(opts.base_url, "", timeout=opts.timeout, retries=opts.retries)


def download_batch(
    dataset: str,
    period: str,
    name: str,
    options: BatchOptions | None = None,
) -> bytes:
    """Download a datalake batch archive synchronously."""
    transport = _transport(options)
    try:
        return transport.request_download_sync(_spec(dataset, period, name))
    finally:
        transport.close()


def download_batch_to_file(
    dataset: str,
    period: str,
    name: str,
    dest: Path,
    options: BatchOptions | None = None,
) -> int:
    """Stream a datalake batch archive straight to ``dest``, returning bytes written.

    The daily archives run past a gigabyte, so :func:`download_batch` holding the
    whole body in memory to hand it back as ``bytes`` is the wrong shape for
    them. This spools the response to disk a chunk at a time instead, so peak
    memory does not grow with the archive.
    """
    transport = _transport(options)
    try:
        return transport.stream_download_sync(_spec(dataset, period, name), dest)
    finally:
        transport.close()


async def download_batch_async(
    dataset: str,
    period: str,
    name: str,
    options: BatchOptions | None = None,
) -> bytes:
    """Download a datalake batch archive asynchronously."""
    transport = _transport(options)
    try:
        return await transport.request_download(_spec(dataset, period, name))
    finally:
        await transport.aclose()


async def download_batch_to_file_async(
    dataset: str,
    period: str,
    name: str,
    dest: Path,
    options: BatchOptions | None = None,
) -> int:
    """Async twin of :func:`download_batch_to_file`, returning bytes written."""
    transport = _transport(options)
    try:
        return await transport.stream_download(_spec(dataset, period, name), dest)
    finally:
        await transport.aclose()
