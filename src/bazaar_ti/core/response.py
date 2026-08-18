"""Validate and decode responses returned by abuse.ch endpoints."""

from __future__ import annotations

import json
import math
from typing import Any

from .errors import AuthError, TransportError

MAX_JSON_DEPTH = 100
"""Deepest response accepted by the clients."""

_AUTH_FAILURES = frozenset({"invalid_auth_key", "unknown_auth_key"})


def _detail(payload: dict[str, Any]) -> str:
    for field in ("data", "message", "error"):
        value = payload.get(field)
        if isinstance(value, str) and value:
            return f" ({value})"
    return ""


def _reject_auth_failure(payload: dict[str, Any]) -> None:
    status = payload.get("query_status")
    if status in _AUTH_FAILURES:
        raise AuthError(f"Server rejected the Auth-Key: {status}{_detail(payload)}")


def ensure_download(data: bytes) -> bytes:
    """Return sample bytes, or raise if the server sent a JSON error instead."""
    if not data:
        raise TransportError("Download was empty; the server sent no content.")
    candidate = data.lstrip()
    if candidate[:1] == b"{":
        try:
            payload = json.loads(candidate)
        except ValueError:
            return data
        status = payload.get("query_status")
        if isinstance(status, str) and status != "ok":
            raise TransportError(f"Download failed: {status}{_detail(payload)}")
    return data


def ensure_not_an_error(text: str) -> str:
    """Return a body that is not JSON, or raise the error it turned out to be.

    Hunting's false-positive list is the one endpoint served in a format the
    JSON decoder never sees, so it is the one whose errors nothing read. Asked
    for CSV with a key the server rejects, it answers HTTP 200 with the same
    ``{"query_status": "unknown_auth_key"}`` body the JSON format raises on —
    and the CSV path handed it back as the list. Redirected to a file, that is
    an auth error saved as ``fplist.csv``, reported as a success.

    A real list opens with ``#`` comment lines, so a body that parses as a JSON
    object is never the one that was asked for.
    """
    candidate = text.lstrip()
    if candidate[:1] != "{":
        return text
    try:
        payload = json.loads(candidate)
    except ValueError:
        return text
    _reject_auth_failure(payload)
    status = payload.get("query_status")
    if isinstance(status, str) and status != "ok":
        raise TransportError(f"Request failed: {status}{_detail(payload)}")
    return text


def _too_deep(data: Any) -> bool:
    """Check nesting iteratively, without recursing through untrusted data."""
    level: list[Any] = [data] if isinstance(data, (dict, list)) else []
    for _ in range(MAX_JSON_DEPTH):
        if not level:
            return False
        below: list[Any] = []
        for node in level:
            values = node.values() if isinstance(node, dict) else node
            below.extend(value for value in values if isinstance(value, (dict, list)))
        level = below
    return bool(level)


class _NonFiniteNumberError(ValueError):
    """Raised by the decoder when a body carries NaN or Infinity."""


def _reject_non_finite(token: str) -> float:
    raise _NonFiniteNumberError(token)


def _finite_float(token: str) -> float:
    """Reject a numeric literal that overflows the float range to ±inf.

    ``parse_constant`` fires only for the bare ``NaN``/``Infinity`` tokens, so
    an out-of-range literal such as ``1e400`` would otherwise decode to ``inf``
    through the default ``float`` and slip past the guard, then render back as
    the invalid JSON token ``Infinity`` — the exact value :func:`_reject_non_finite`
    exists to keep out.
    """
    value = float(token)
    if not math.isfinite(value):
        raise _NonFiniteNumberError(token)
    return value


def parse_json(response: Any) -> dict[str, Any]:
    """Decode one response object and reject values downstream cannot render."""
    try:
        data = response.json(parse_constant=_reject_non_finite, parse_float=_finite_float)
    except _NonFiniteNumberError as exc:
        raise TransportError(
            f"Response contained {exc}, which is not a JSON number and cannot "
            "be rendered as JSON, SARIF, or TOON."
        ) from exc
    except ValueError as exc:
        raise TransportError("Response body was not valid JSON.") from exc
    except RecursionError as exc:
        raise TransportError("Response body was nested too deeply to parse.") from exc
    if not isinstance(data, dict):
        raise TransportError(f"Expected a JSON object, got {type(data).__name__}.")
    if _too_deep(data):
        raise TransportError(f"Response nested deeper than {MAX_JSON_DEPTH} levels.")
    _reject_auth_failure(data)
    return data
