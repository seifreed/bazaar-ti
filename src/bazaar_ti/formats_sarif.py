"""SARIF 2.1.0 serialization for abuse.ch records."""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import quote

from ._version import PROJECT_URL, __version__

SARIF_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
)
SARIF_VERSION = "2.1.0"
TOOL_NAME = "bazaar-ti"
TOOL_URI = PROJECT_URL

_RULE_FIELDS = ("signature", "malware_printable", "malware", "threat_type", "threat")
_ID_FIELDS = ("sha256_hash", "url", "host", "ioc", "md5_hash", "entry_value", "rule_name")
_LOCATION_FIELDS = ("url", "host")
_COLLECTION_FIELDS = ("data", "urls", "payloads")
_URI_SAFE = ":/?#@!$&'()*+,;=~-._%"
_PERCENT_ESCAPE = re.compile(r"%[0-9A-Fa-f]{2}\Z")


def _first_str(record: dict[str, Any], candidates: tuple[str, ...]) -> str | None:
    for field in candidates:
        value = record.get(field)
        if isinstance(value, str) and value:
            return value
    return None


def _identifies_a_record(envelope: dict[str, Any]) -> bool:
    return _first_str(envelope, _ID_FIELDS) is not None


def _records(data: Any) -> list[Any]:
    if isinstance(data, list):
        return [record for item in data for record in _records(item)]
    if not isinstance(data, dict) or _identifies_a_record(data):
        return [data]
    for field in _COLLECTION_FIELDS:
        inner = data.get(field)
        if isinstance(inner, list) and inner:
            # Record dicts pass through untouched; a stray non-dict element is
            # unwrapped the way the top-level list branch does, rather than
            # reaching _result and rendering as its Python repr.
            return [
                record
                for item in inner
                for record in ([item] if isinstance(item, dict) else _records(item))
            ]
    if data and all(isinstance(value, dict) for value in data.values()):
        return list(data.values())
    return [data]


def _rule_id(record: Any) -> str:
    if not isinstance(record, dict):
        return "ioc"
    return _first_str(record, _RULE_FIELDS) or "ioc"


def _message(record: Any) -> str:
    if not isinstance(record, dict):
        return str(record)
    parts: list[str] = []
    identity = _first_str(record, _ID_FIELDS)
    if identity is not None:
        parts.append(identity)
    for field in ("file_name", "signature"):
        value = record.get(field)
        if isinstance(value, str) and value:
            parts.append(value)
    return " — ".join(parts) if parts else "abuse.ch record"


def _uri_reference(value: str) -> str:
    """Percent-encode a URL for the location field, leaving existing escapes alone.

    ``errors`` matters because this is the one place the document is built from
    text rather than handed to ``json.dumps``, which escapes what it cannot
    encode. A URL in a malware feed is written by whoever ran the campaign, and
    a body carrying an unpaired surrogate as a ``"\\udXXX"`` escape reached
    ``quote`` as a character UTF-8 cannot represent: rendering a record raised
    UnicodeEncodeError, which neither the CLI nor the library catches. Written
    out as its escape instead, the reader still sees what the field held.
    """
    safe = _URI_SAFE.replace("%", "")
    return "".join(
        (
            part
            if _PERCENT_ESCAPE.fullmatch(part)
            else quote(part, safe=safe, errors="backslashreplace")
        )
        for part in re.split(r"(%[0-9A-Fa-f]{2})", value)
    )


def _locations(record: Any) -> list[dict[str, Any]]:
    if not isinstance(record, dict):
        return []
    value = _first_str(record, _LOCATION_FIELDS)
    if value is None:
        return []
    return [{"physicalLocation": {"artifactLocation": {"uri": _uri_reference(value)}}}]


def _sarif_tags(value: Any) -> list[str] | None:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return None
    unique = list(dict.fromkeys(tag for tag in value if isinstance(tag, str)))
    return unique or None


def _properties(record: Any) -> dict[str, Any]:
    if not isinstance(record, dict):
        return {"value": record}
    if "tags" not in record:
        return record
    bag = dict(record)
    tags = _sarif_tags(bag.pop("tags"))
    if tags is not None:
        bag["tags"] = tags
    return bag


def _result(record: Any) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": _rule_id(record),
        "level": "warning",
        "message": {"text": _message(record)},
        "properties": _properties(record),
    }
    locations = _locations(record)
    if locations:
        result["locations"] = locations
    return result


def to_sarif(data: Any) -> str:
    log = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": __version__,
                        "informationUri": TOOL_URI,
                    }
                },
                "results": [_result(record) for record in _records(data)],
            }
        ],
    }
    return json.dumps(log, indent=2, allow_nan=False)
