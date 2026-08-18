"""Render and write CLI results."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from ..core.errors import BazaarTIError
from ..formats import render


def emit(result: Any, args: Any) -> None:
    """Render a result to stdout, or to ``--output`` when given."""
    if isinstance(result, bytes):
        _emit_bytes(result, args)
    else:
        _emit_text(result if isinstance(result, str) else render(result, args.format), args)


def _emit_bytes(data: bytes, args: Any) -> None:
    output = getattr(args, "output", None)
    if output is None:
        stream = getattr(sys.stdout, "buffer", None)
        if stream is None:
            raise BazaarTIError("This output is binary; write it to a file with --output.")
        stream.write(data)
        return
    _write(data, output)


def _emit_text(text: str, args: Any) -> None:
    output = getattr(args, "output", None)
    if output is None:
        print(text)
        return
    _write((text + "\n").encode("utf-8"), output)


def _write(data: bytes, output: str) -> None:
    Path(output).write_bytes(data)
    print(f"Wrote {len(data)} bytes to {output}")
