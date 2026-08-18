"""TOON serialization implemented with the standard library."""

from __future__ import annotations

import math
import re
from typing import Any

_BARE_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*\Z")
_NUMERIC_LIKE = re.compile(r"^[+-]?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\Z")
_RESERVED = frozenset({"true", "false", "null"})
_INDENT = "  "

# Every character a bare value must be quoted for: TOON's structural punctuation
# plus the characters that break the line-oriented layout or read back wrong —
# the Unicode Cc controls (C0 0x00-0x1F, DEL 0x7F, C1 0x80-0x9F), the line and
# paragraph separators (Zl U+2028, Zp U+2029), and the surrogates (Cs
# U+D800-U+DFFF). Left raw, U+0085/U+2028/U+2029 split a value across a physical
# line and the decoder rejects the whole document, and an unpaired surrogate
# cannot be encoded as UTF-8 at all: printing the document or writing it to a
# file raised UnicodeEncodeError, which nothing catches. A response can carry one
# as a "\udXXX" escape — a sample's file name is written by whoever built the
# sample — and JSON and SARIF survive it only because json.dumps escapes it
# straight back. One compiled scan replaces a per-character Python loop; the
# controls and separators take the "\uXXXX" escape in _quote, and the surrogates
# take the one beside it, for the reason given there.
_MUST_QUOTE = re.compile(r"[,:\"\\\\\[\]{}\x00-\x1f\x7f-\x9f\u2028\u2029\ud800-\udfff]")


def _is_surrogate(ch: str) -> bool:
    """A code point with no encoding of its own; see :func:`_quote`."""
    return "\ud800" <= ch <= "\udfff"


def _must_escape(ch: str) -> bool:
    """The subset of :data:`_MUST_QUOTE` that _quote escapes rather than emits."""
    return ch < "\x20" or "\x7f" <= ch <= "\x9f" or ch in "\u2028\u2029"


def _encode_number(value: int | float) -> str:
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("TOON cannot encode a non-finite number")
    return repr(value)


def _needs_quote(text: str) -> bool:
    if text == "" or text[0].isspace() or text[-1].isspace():
        return True
    if text in _RESERVED or _NUMERIC_LIKE.match(text) is not None:
        return True
    if text[0] in "-#":
        return True
    return _MUST_QUOTE.search(text) is not None


def _quote(text: str) -> str:
    out = ['"']
    for ch in text:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif _is_surrogate(ch):
            # An unpaired surrogate has no encoding: raw it is not UTF-8, and
            # the reference decoder refuses a "\uXXXX" escape of one outright
            # ("supplementary code points MUST appear as literal UTF-8"). So
            # the escape is written as text, with its backslash escaped — the
            # reader sees which code point the field held, and the document
            # stays one the decoder accepts. SARIF does the same for a URL,
            # where the sequence survives as "%5Cud800".
            out.append(f"\\\\u{ord(ch):04x}")
        elif _must_escape(ch):
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _encode_primitive(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return _encode_number(value)
    text = str(value)
    return _quote(text) if _needs_quote(text) else text


def _encode_key(key: str) -> str:
    return key if _BARE_KEY.match(key) is not None else _quote(key)


def _is_primitive(value: Any) -> bool:
    return value is None or isinstance(value, (bool, int, float, str))


def _is_tabular(array: list[Any]) -> bool:
    if not array or not all(isinstance(item, dict) and item for item in array):
        return False
    keyset = set(array[0].keys())
    return all(
        set(item.keys()) == keyset and all(_is_primitive(v) for v in item.values())
        for item in array
    )


def _encode_object(obj: dict[str, Any], depth: int) -> list[str]:
    lines: list[str] = []
    pad = _INDENT * depth
    for key, value in obj.items():
        ek = _encode_key(key)
        if isinstance(value, dict):
            lines.append(f"{pad}{ek}:")
            if value:
                lines.extend(_encode_object(value, depth + 1))
        elif isinstance(value, list):
            lines.extend(_encode_array(ek, value, depth))
        else:
            lines.append(f"{pad}{ek}: {_encode_primitive(value)}")
    return lines


def _encode_array(key: str, array: list[Any], depth: int, *, at_root: bool = False) -> list[str]:
    pad = _INDENT * depth
    if not array:
        if key:
            return [f"{pad}{key}: []"]
        return [f"{pad}[]"] if at_root else [f"{pad}[0]:"]
    if all(_is_primitive(item) for item in array):
        row = ",".join(_encode_primitive(item) for item in array)
        return [f"{pad}{key}[{len(array)}]: {row}"]
    if _is_tabular(array) and (key or at_root):
        fields = list(array[0].keys())
        names = ",".join(_encode_key(field) for field in fields)
        header = f"{pad}{key}[{len(array)}]{{{names}}}:"
        rows = [
            f"{_INDENT * (depth + 1)}{','.join(_encode_primitive(item[field]) for field in fields)}"
            for item in array
        ]
        return [header, *rows]
    return [f"{pad}{key}[{len(array)}]:", *_encode_list_items(array, depth + 1)]


def _encode_list_items(array: list[Any], depth: int) -> list[str]:
    lines: list[str] = []
    pad = _INDENT * depth
    for item in array:
        if isinstance(item, dict):
            if item:
                lines.extend(_dash(_encode_object(item, depth + 1), pad))
            else:
                lines.append(f"{pad}-")
        elif isinstance(item, list):
            lines.extend(_dash(_encode_array("", item, depth), pad))
        else:
            lines.append(f"{pad}- {_encode_primitive(item)}")
    return lines


def _dash(block: list[str], pad: str) -> list[str]:
    return [f"{pad}- {block[0].lstrip()}", *block[1:]]


def to_toon(data: Any) -> str:
    if isinstance(data, dict):
        return "\n".join(_encode_object(data, 0))
    if isinstance(data, list):
        return "\n".join(_encode_array("", data, 0, at_root=True))
    return _encode_primitive(data)
