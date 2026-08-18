"""Root CLI entry point for bazaar-ti."""

from __future__ import annotations

import argparse
import io
import math
import os
import sys
from collections.abc import Callable
from pathlib import Path

from .._version import __version__
from ..core.config import DEFAULT_RETRIES, DEFAULT_TIMEOUT, MAX_RETRIES
from ..core.errors import BazaarTIError
from ..formats import FORMATS
from ..services.base import SyncService
from . import datalake, hunting, malwarebazaar, threatfox, urlhaus, yaraify
from ._common import Command, _call, _values, bulk_key_of
from .bulk import run_bulk
from .output import emit

SIGINT_EXIT = 130
"""Exit status a shell reports for a command stopped with Ctrl-C (128 + 2)."""

SIGPIPE_EXIT = 141
"""Exit status a shell reports for a command whose reader closed (128 + 13)."""

SERVICES = (malwarebazaar, urlhaus, threatfox, yaraify, hunting, datalake)
"""Every service the root parser registers, in the order ``--help`` lists them.

Named rather than written inline because the tests were each keeping their own
copy of it — one to count the subcommands the README claims, one to walk the
command tables, one to check every service documents its subcommands. A service
added here and missed there is one nothing tests, and the copies gave no sign.
"""


def _in_range[T](
    convert: Callable[[str], T], value: str, accepts: Callable[[T], bool], must: str
) -> T:
    """Parse one numeric flag, failing as a usage error rather than a traceback.

    Both flags below reach code that raises something ``main`` does not catch
    when the value is out of range, so argparse has to be the one to refuse it:
    an ``ArgumentTypeError`` here is the usage message and exit status 2 that a
    mistyped argument should produce.
    """
    try:
        parsed = convert(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid {convert.__name__} value: {value!r}") from None
    if not accepts(parsed):
        raise argparse.ArgumentTypeError(f"must be {must}: {value!r}")
    return parsed


def _timeout(value: str) -> float:
    """Parse ``--timeout`` as a positive, finite number of seconds.

    httpx rejects a negative timeout with ValueError, and an infinite one
    overflows the platform timer with OverflowError. Neither is BazaarTIError
    nor OSError, so both escaped as a traceback instead of a usage error.
    """
    return _in_range(
        float,
        value,
        lambda seconds: math.isfinite(seconds) and seconds > 0,
        "a positive number of seconds",
    )


def _retries(value: str) -> int:
    """Parse ``--retries`` as a count within the range the transport can serve.

    A negative one silently meant "do not retry at all", and a large one is an
    apparent hang: every attempt sleeps, so the backoff ceiling alone leaves
    ``--retries 100000`` waiting for weeks before it reports anything.
    """
    return _in_range(
        int, value, lambda count: 0 <= count <= MAX_RETRIES, f"between 0 and {MAX_RETRIES}"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bazaar-ti",
        description="Command-line client for the abuse.ch APIs.",
    )
    # Every SARIF document already carries this under tool.driver.version, so
    # a finding could name the build that produced it while the tool itself
    # could not be asked.
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--auth-key", default=None, help="Auth-Key (else $BAZAAR_TI_AUTH_KEY).")
    parser.add_argument("--config", type=Path, default=None, help="Path to a config.toml file.")
    parser.add_argument(
        "--timeout", type=_timeout, default=DEFAULT_TIMEOUT, help="Request timeout in seconds."
    )
    parser.add_argument(
        "--retries",
        type=_retries,
        default=DEFAULT_RETRIES,
        help=f"Retry attempts (0-{MAX_RETRIES}).",
    )
    parser.add_argument(
        "--base-url", default=None, help="Override the API base URL (mirrors/testing)."
    )
    parser.add_argument(
        "--format",
        choices=FORMATS,
        default=FORMATS[0],
        help=f"Output format for structured responses (default: {FORMATS[0]}).",
    )
    sub = parser.add_subparsers(dest="service", required=True)
    for module in SERVICES:
        module.register(sub)
    return parser


def _use_utf8_output() -> None:
    """Print UTF-8 whatever the console's default encoding is.

    abuse.ch records carry non-ASCII in signatures, file names and tags. On
    Windows stdout defaults to the ANSI code page, which raises
    UnicodeEncodeError — not caught below — as soon as output is redirected.

    stderr needs it just as much: every message below goes there, and they
    quote text this side does not choose — a config path under a non-ASCII
    user name, the server's own explanation of a failed download, an argparse
    complaint about a mistyped value. Left alone, reporting the error crashed
    harder than the error being reported.
    """
    for stream in (sys.stdout, sys.stderr):
        if isinstance(stream, io.TextIOWrapper):
            stream.reconfigure(encoding="utf-8")


def _discard_stdout() -> None:
    """Send anything still queued for stdout to the null device.

    Both halves can be absent: a caller that replaced ``sys.stdout`` with an
    in-memory stream has no file descriptor to redirect, and then there is no
    pipe left to break either.
    """
    try:
        target = sys.stdout.fileno()
    except AttributeError, OSError, ValueError:
        return
    null = os.open(os.devnull, os.O_WRONLY)
    try:
        os.dup2(null, target)
    finally:
        os.close(null)


def run(args: argparse.Namespace) -> None:
    """Dispatch a parsed command: build the client, call it, render output."""
    plain_handler = getattr(args, "_plain_handler", None)
    if plain_handler is not None:
        plain_handler(args)
        return
    command: Command = args._command
    factory: Callable[[argparse.Namespace], SyncService] = args._factory
    client = factory(args)
    bulk_key = bulk_key_of(command)
    try:
        if command.handler is not None:
            command.handler(client, args)
        elif bulk_key is not None and getattr(args, "input_file", None) is not None:
            run_bulk(client, command, args, bulk_key)
        else:
            if bulk_key is not None and getattr(args, bulk_key) is None:
                # Only optional because --input-file is the other way to supply it.
                raise BazaarTIError(f"Provide a {bulk_key} value or --input-file.")
            emit(_call(client, command, _values(command, args)), args)
    finally:
        client.close()


def main(argv: list[str] | None = None) -> int:
    _use_utf8_output()
    args = build_parser().parse_args(argv)
    try:
        run(args)
    except BrokenPipeError:
        # `bazaar-ti threatfox malware_list | head` closes the pipe as soon as
        # head has its lines, and the write that lands after that reported
        # "error: [Errno 32] Broken pipe" and exit 1 — this program failing at
        # the most ordinary thing a reader can do. Caught before the OSError
        # arm below, which is where it used to end up. stdout is pointed at the
        # null device first: the interpreter flushes it on the way out, and
        # that flush would raise the same error again with nothing left to
        # catch it, printing "Exception ignored" after main had handled it.
        _discard_stdout()
        return SIGPIPE_EXIT
    except (BazaarTIError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        # A call can sit in a timeout and up to MAX_RETRIES backoffs, so Ctrl-C
        # is the ordinary way to stop one. Unhandled it printed forty lines of
        # httpx and httpcore frames, which reads as a crash rather than as the
        # user's own decision. 128 + SIGINT is the status a shell expects.
        print("interrupted", file=sys.stderr)
        return SIGINT_EXIT
    return 0
