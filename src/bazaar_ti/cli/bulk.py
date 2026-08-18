"""Bulk CLI input and dispatch."""

from __future__ import annotations

import codecs
import threading
from pathlib import Path
from typing import Any

from ..core.batch import threaded_map
from ..core.errors import BazaarTIError, RateLimitError
from ..formats import render_batch
from ..services.base import SyncService
from ._common import Command, _call, _values
from .output import emit

NOT_ATTEMPTED = "not attempted: the batch stopped after the server rate-limited it"
"""What a bulk result says for a value the batch never got to.

Written into the output rather than left out of it, so the record of the run
names every input: a value that is simply absent reads like one that was
looked up and found nothing.
"""


def run_bulk(client: SyncService, command: Command, args: Any, key: str) -> None:
    """Query values from an input file, preserving partial results on failure."""
    fixed = _values(command, args)
    fixed.pop(key, None)
    lines = _read_values(Path(args.input_file))
    typed = getattr(args, key, None)
    values = list(dict.fromkeys(([typed] if typed is not None else []) + lines))
    if not values:
        raise BazaarTIError(f"No values to query: {args.input_file} holds none.")

    errors: dict[str, str] = {}
    limited = threading.Event()

    def query(value: str) -> Any:
        if limited.is_set():
            return {"error": NOT_ATTEMPTED}
        try:
            return _call(client, command, {key: value, **fixed})
        except RateLimitError as exc:
            # No entry in ``errors``: a rate-limited batch raises below on
            # ``limited`` alone, before anything reads that dict, so recording
            # it here was a line nothing could ever look at. The value still
            # carries its reason in the results, which is what gets written out.
            limited.set()
            return {"error": str(exc)}
        except BazaarTIError as exc:
            errors[value] = str(exc)
            return {"error": str(exc)}

    results = threaded_map(query, values, concurrency=args.concurrency)
    emit(render_batch(dict(zip(values, results, strict=True)), args.format), args)
    if limited.is_set():
        skipped = sum(result.get("error") == NOT_ATTEMPTED for result in results)
        raise BazaarTIError(
            f"Stopped: the server rate-limited this batch. {skipped} of "
            f"{len(values)} values were not queried — wait for the limit to "
            "lift, then re-run with just those."
        )
    if errors:
        raise BazaarTIError(f"{len(errors)} of {len(values)} lookups failed.")


def _read_values(path: Path) -> list[str]:
    """Read one value per line from UTF-8 or BOM-marked UTF-16 input."""
    raw = path.read_bytes()
    encoding = (
        "utf-16" if raw.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)) else "utf-8-sig"
    )
    try:
        text = raw.decode(encoding)
    except UnicodeDecodeError as exc:
        raise BazaarTIError(f"{path} is not valid {encoding} text: {exc}") from exc
    values = [line.strip() for line in text.splitlines() if line.strip()]
    if any("\x00" in value for value in values):
        raise BazaarTIError(
            f"{path} read as {encoding} gave values containing NUL bytes; it is "
            "probably UTF-16 or UTF-32 without a byte-order mark. Re-save it as UTF-8."
        )
    return values
