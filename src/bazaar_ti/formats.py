"""Public output-format facade for JSON, SARIF, and TOON."""

from __future__ import annotations

import json
from typing import Any

from .formats_sarif import SARIF_SCHEMA, to_sarif
from .formats_toon import to_toon

FORMATS = ("json", "sarif", "toon")


def render(data: Any, fmt: str) -> str:
    """Serialize data in one of :data:`FORMATS`."""
    if fmt == "sarif":
        return to_sarif(data)
    if fmt == "toon":
        return to_toon(data)
    if fmt != "json":
        raise ValueError(f"Unknown output format {fmt!r}; expected one of {', '.join(FORMATS)}.")
    return to_json(data)


def render_batch(results: dict[str, Any], fmt: str) -> str:
    """Serialize a bulk lookup, flattening it for SARIF consumers."""
    if fmt == "sarif":
        return to_sarif(list(results.values()))
    return render(results, fmt)


def to_json(data: Any) -> str:
    return json.dumps(data, indent=2, sort_keys=True, allow_nan=False)


__all__ = [
    "FORMATS",
    "SARIF_SCHEMA",
    "render",
    "render_batch",
    "to_json",
    "to_sarif",
    "to_toon",
]
