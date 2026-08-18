"""CLI tests: real argument parsing and dispatch against the local server."""

from __future__ import annotations

import _thread
import argparse
import codecs
import contextlib
import importlib
import io
import json
import os
import runpy
import signal
import sys
import tracemalloc
from pathlib import Path

import pytest

from bazaar_ti._version import __version__
from bazaar_ti.cli._common import Command, Factory, Param, register_service
from bazaar_ti.cli.bulk import NOT_ATTEMPTED
from bazaar_ti.cli.main import (
    SERVICES,
    SIGINT_EXIT,
    SIGPIPE_EXIT,
    _discard_stdout,
    build_parser,
    main,
    run,
)
from bazaar_ti.core.errors import BazaarTIError
from bazaar_ti.services.base import SyncService
from bazaar_ti.services.threatfox import ThreatFox
from tests.conftest import ReplyApp, json_data_part


def _args(base_url: str, *rest: str) -> list[str]:
    return ["--auth-key", "k", "--base-url", base_url, *rest]


def _bulk(base_url: str, tmp_path: Path, values: bytes, *extra: str, fmt: str = "") -> int:
    """Write a value list and run the bulk lookup every bulk test below shares.

    Bytes rather than text because several of these are about the encodings a
    list arrives in, and the rest are the same either way. ``fmt`` goes before
    the service name, where a global flag belongs; anything in ``extra`` is an
    argument of the subcommand.
    """
    listing = tmp_path / "hashes.txt"
    listing.write_bytes(values)
    prefix = ("--format", fmt) if fmt else ()
    argv = (*prefix, "malwarebazaar", "get_info", *extra, "--input-file", str(listing))
    return main(_args(base_url, *argv))


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        pytest.param(("threatfox", "types"), "query_status", id="a JSON response"),
        pytest.param(
            ("hunting", "get_fplist", "--fmt", "csv"), "query_status", id="text passed through"
        ),
        pytest.param(("hunting", "get_fplist"), "query_status", id="an omitted optional"),
        # TOON spells it "key: value", so this also proves --format reached the
        # renderer rather than falling back to JSON.
        pytest.param(
            ("--format", "toon", "threatfox", "types"), "query_status: ok", id="--format toon"
        ),
    ],
)
def test_a_command_renders_to_stdout(
    base_url: str, capsys: pytest.CaptureFixture[str], argv: tuple[str, ...], expected: str
) -> None:
    assert main(_args(base_url, *argv)) == 0
    assert expected in capsys.readouterr().out


_TABLE_DRIVEN = [
    module.__name__.rsplit(".", 1)[-1] for module in SERVICES if hasattr(module, "COMMANDS")
]


@pytest.mark.parametrize("service", _TABLE_DRIVEN)
def test_every_subcommand_is_described_in_help(
    capsys: pytest.CaptureFixture[str], service: str
) -> None:
    """--help is the only documentation these subcommands have.

    Each is registered with ``command.help or command.name``, so the fallback
    is what most of them show. Turning that into ``and`` empties the column for
    every command that set no help and swaps in the method name for the few
    that did, and the suite noticed neither.
    """
    with pytest.raises(SystemExit):
        main([service, "--help"])
    out = capsys.readouterr().out
    body = out.split("{", 1)[1] if "{" in out else out
    described = [
        line.split()[0]
        for line in body.splitlines()
        if line.startswith("    ") and len(line.split()) > 1 and not line.startswith("     ")
    ]
    assert described, f"{service} --help listed no described subcommands"


def test_format_sarif(base_url: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(_args(base_url, "--format", "sarif", "threatfox", "types")) == 0
    out = capsys.readouterr().out
    assert '"version": "2.1.0"' in out and '"$schema"' in out


def test_format_bulk_toon(
    base_url: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _bulk(base_url, tmp_path, b"aaa\nbbb\n", fmt="toon") == 0
    assert "aaa:" in capsys.readouterr().out


def test_bytes_to_file(base_url: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "sample.zip"
    assert main(_args(base_url, "malwarebazaar", "download", "0" * 64, "-o", str(out))) == 0
    assert out.read_bytes()
    assert "Wrote" in capsys.readouterr().out


def test_structured_output_to_file(
    base_url: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # The README's Quick Start and Code Scanning workflow both do this; -o used
    # to be registered only for binary downloads, so it failed to parse.
    out = tmp_path / "iocs.sarif"
    code = main(_args(base_url, "--format", "sarif", "threatfox", "get_iocs", "-o", str(out)))
    assert code == 0
    assert "Wrote" in capsys.readouterr().out
    written = out.read_text(encoding="utf-8")
    assert json.loads(written)["version"] == "2.1.0"
    # A rendered document is a text file, so it ends in a newline: without one
    # the next line a shell appends runs into the closing brace, and `cat` of
    # several exports runs them together.
    assert written.endswith("\n")


def test_text_output_to_file_is_utf8(base_url: str, app: ReplyApp, tmp_path: Path) -> None:
    # Explicit UTF-8, not the platform encoding a shell redirect would use.
    app.reply = (200, "café,ünïcøde\n".encode())
    out = tmp_path / "fp.csv"
    assert main(_args(base_url, "hunting", "get_fplist", "--fmt", "csv", "-o", str(out))) == 0
    assert out.read_bytes().decode("utf-8").startswith("café,ünïcøde")


def test_bulk_output_to_file(base_url: str, tmp_path: Path) -> None:
    out = tmp_path / "bulk.json"
    assert _bulk(base_url, tmp_path, b"aaa\nbbb\n", "-o", str(out)) == 0
    assert sorted(json.loads(out.read_text(encoding="utf-8"))) == ["aaa", "bbb"]


def test_bytes_to_stdout(base_url: str, capsysbinary: pytest.CaptureFixture[bytes]) -> None:
    assert main(_args(base_url, "malwarebazaar", "download", "0" * 64)) == 0
    assert b"query_status" in capsysbinary.readouterr().out


def test_binary_output_to_a_text_only_stdout(
    base_url: str, capsys: pytest.CaptureFixture[str]
) -> None:
    # redirect_stdout installs a stream with no .buffer, which main() hits when
    # it is driven from Python; writing binary there raised AttributeError.
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = main(_args(base_url, "malwarebazaar", "download", "0" * 64))
    assert code == 1
    assert "binary" in capsys.readouterr().err


def test_bulk(base_url: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert _bulk(base_url, tmp_path, b"aaa\n\nbbb\n") == 0
    out = capsys.readouterr().out
    assert "aaa" in out and "bbb" in out


def test_bulk_queries_each_line_when_a_value_is_typed_too(
    base_url: str, app: ReplyApp, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A typed value joins the list; it does not replace what the file holds.

    The typed one arrives as a fixed argument as well, and a fixed argument
    wins when the call is assembled — so left in place it would be sent for
    every line, and each lookup would ask about the same value under a
    different key. Only the file-only form was covered, where there is no
    typed value to override anything.
    """
    assert _bulk(base_url, tmp_path, b"bbb\nccc\n", "aaa") == 0
    assert sorted(json.loads(capsys.readouterr().out)) == ["aaa", "bbb", "ccc"]
    asked = sorted(body.split(b"hash=")[1] for body in app.bodies)
    assert asked == [b"aaa", b"bbb", b"ccc"]


def test_bulk_deduplicates_repeated_values(
    base_url: str, app: ReplyApp, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Counting the requests is the only way to see this: the results are keyed
    # by input value, so a list queried twice collapses to the same two keys
    # whether or not anything deduplicated it. Asserting the output alone let
    # the whole dedup be deleted with the test still passing.
    distinct = ["aaa", "bbb"]
    assert _bulk(base_url, tmp_path, b"aaa\nbbb\naaa\n") == 0
    assert sorted(json.loads(capsys.readouterr().out)) == distinct
    assert len(app.bodies) == len(distinct)


@pytest.mark.parametrize(
    "encoded",
    [
        "aaa\r\nbbb\r\n".encode("utf-16"),  # Notepad's "Unicode" option
        b"\xfe\xff" + "aaa\nbbb\n".encode("utf-16-be"),
        # A Windows-authored list must not carry its BOM into the first lookup.
        "aaa\r\nbbb\r\n".encode("utf-8-sig"),
        b"aaa\nbbb\n",
    ],
)
def test_bulk_input_file_encodings(
    base_url: str, tmp_path: Path, capsys: pytest.CaptureFixture[str], encoded: bytes
) -> None:
    assert _bulk(base_url, tmp_path, encoded) == 0
    assert sorted(json.loads(capsys.readouterr().out)) == ["aaa", "bbb"]


@pytest.mark.parametrize(
    "encoded",
    [
        "aaa\nbbb\n".encode("utf-16-le"),  # UTF-16 with the BOM stripped
        "aaa\nbbb\n".encode("utf-16-be"),
        codecs.BOM_UTF32_LE + "aaa\nbbb\n".encode("utf-32-le"),  # starts with the UTF-16 BOM
    ],
)
def test_bulk_input_file_with_a_misdetected_encoding_is_refused(
    base_url: str, app: ReplyApp, tmp_path: Path, capsys: pytest.CaptureFixture[str], encoded: bytes
) -> None:
    # None of these raise UnicodeDecodeError: ASCII interleaved with NUL is
    # valid UTF-8, and a UTF-32 file opens with the UTF-16 BOM. Each one used to
    # decode "successfully" into values padded with NUL bytes, so the batch
    # queried nonsense and reported it as a clean run that simply found nothing.
    assert _bulk(base_url, tmp_path, encoded) == 1
    assert "NUL bytes" in capsys.readouterr().err
    assert app.bodies == []


def test_bulk_input_file_that_is_not_text(
    base_url: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # UnicodeDecodeError is a ValueError, which the CLI does not catch, so an
    # undecodable list used to escape as a traceback.
    assert _bulk(base_url, tmp_path, "caf\xe9\nbbb\n".encode("latin-1")) == 1
    assert "is not valid utf-8-sig text" in capsys.readouterr().err


def test_bulk_keeps_results_when_one_lookup_fails(
    base_url: str, app: ReplyApp, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # A single failed lookup must not discard the whole batch, but it must
    # still be visible in the output and in the exit status. The failure is a
    # body the client cannot parse rather than a 429: a rate limit is about the
    # account and not this value, so it now stops the batch instead, which is
    # the test below.
    app.fail_on = b"bbb"
    app.fail_reply = (200, b"not json")
    assert _bulk(base_url, tmp_path, b"aaa\nbbb\nccc\n") == 1
    results = json.loads(capsys.readouterr().out)
    assert results["aaa"] == {"query_status": "ok"}
    assert results["ccc"] == {"query_status": "ok"}
    assert "not valid JSON" in results["bbb"]["error"]


def test_bulk_stops_sending_once_the_server_rate_limits(
    base_url: str, app: ReplyApp, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """abuse.ch limits the account, so carrying on is what makes it worse.

    Their Fair Use notice puts a limit at up to 72 hours, and longer for
    repeated abuse. Every other failure here is about one value and the batch
    is right to continue; a 429 is the service saying stop, and the batch used
    to answer by sending the other 499 — each one another 429 against the same
    account.

    Concurrency of 1 makes the count exact: the first lookup trips the limit
    and nothing after it is sent. In flight requests still land at a higher
    concurrency, so the guarantee is that dispatch stops, not that it stops
    within one request.
    """
    total = 40
    app.fail_on = b""  # matches every body, so every lookup is rate-limited
    values = b"\n".join(f"{index:064x}".encode() for index in range(total)) + b"\n"
    assert _bulk(base_url, tmp_path, values, "--concurrency", "1") == 1
    captured = capsys.readouterr()
    results = json.loads(captured.out)
    assert len(app.bodies) == 1, f"kept querying after a 429: {len(app.bodies)} requests"
    # The ones it never got to are named in the output rather than missing from
    # it, so the run still says what needs looking up.
    assert len(results) == total
    assert sum(r.get("error") == NOT_ATTEMPTED for r in results.values()) == total - 1
    # And the count is stated back: it tells the caller how much of the list is
    # still to do, and it was reached by counting the same marker the results
    # carry, which nothing here had compared against.
    assert f"{total - 1} of {total} values were not queried" in captured.err


def test_bulk_also_queries_a_value_given_on_the_command_line(
    base_url: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # The typed value used to be required and then silently discarded.
    assert _bulk(base_url, tmp_path, b"aaa\nbbb\n", "ccc") == 0
    assert sorted(json.loads(capsys.readouterr().out)) == ["aaa", "bbb", "ccc"]


def test_bulk_command_without_a_value_or_input_file(
    base_url: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(_args(base_url, "malwarebazaar", "get_info")) == 1
    assert "Provide a file_hash value or --input-file" in capsys.readouterr().err


def test_format_bulk_sarif_is_one_result_per_record(
    base_url: str, app: ReplyApp, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # The batch is keyed by input value, which SARIF has nowhere to put, so the
    # whole thing used to render as a single opaque finding — the records that
    # Code Scanning reads invisible inside its properties bag.
    envelope = {"query_status": "ok", "data": [{"signature": "Qakbot"}]}
    app.reply = (200, json.dumps(envelope).encode())
    assert _bulk(base_url, tmp_path, b"aaa\nbbb\n", fmt="sarif") == 0
    results = json.loads(capsys.readouterr().out)["runs"][0]["results"]
    assert [r["ruleId"] for r in results] == ["Qakbot", "Qakbot"]


def test_bulk_with_an_input_file_holding_no_values(
    base_url: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # An empty or mistyped list used to query nothing, print "{}" and exit 0,
    # which reads exactly like a batch that ran and matched nothing.
    assert _bulk(base_url, tmp_path, b"\n   \n\n") == 1
    assert "holds none" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("flag", "value"),
    [("--retries", v) for v in ("-1", "11", "1000000", "abc")]
    + [("--timeout", v) for v in ("-1", "0", "1e400", "inf", "nan", "abc")],
)
def test_rejects_an_unusable_transport_setting(
    base_url: str, capsys: pytest.CaptureFixture[str], flag: str, value: str
) -> None:
    """Both flags have to fail as usage errors rather than as tracebacks.

    A negative --retries silently meant "no retries", and a large one sleeps
    between every attempt, so the backoff ceiling still leaves it running for
    weeks. httpx raises ValueError on a negative --timeout and the platform
    timer raises OverflowError on an infinite one; neither is BazaarTIError nor
    OSError, so both escaped the CLI's handler entirely.
    """
    argparse_usage_error = 2
    with pytest.raises(SystemExit) as caught:
        main(_args(base_url, flag, value, "threatfox", "types"))
    assert caught.value.code == argparse_usage_error
    assert flag in capsys.readouterr().err


@pytest.mark.parametrize(
    ("flag", "value"),
    [("--retries", "0"), ("--retries", "2"), ("--retries", "10")]
    + [("--timeout", "0.5"), ("--timeout", "30")],
)
def test_accepts_a_usable_transport_setting(base_url: str, flag: str, value: str) -> None:
    assert main(_args(base_url, flag, value, "threatfox", "types")) == 0


def test_submit_ioc_without_any_ioc_is_refused(
    base_url: str, app: ReplyApp, capsys: pytest.CaptureFixture[str]
) -> None:
    # Submissions are not retryable, so an empty list spends the single
    # attempt there is on a write the endpoint cannot honour.
    code = main(_args(base_url, "threatfox", "submit_ioc", "botnet_cc", "ip:port", "qakbot", " ,"))
    assert code == 1
    assert "at least one IOC" in capsys.readouterr().err
    assert app.bodies == []


def test_non_utf8_stdout_does_not_crash(
    base_url: str, app: ReplyApp, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # TOON and passthrough text carry raw non-ASCII; on Windows the console
    # encoding would raise UnicodeEncodeError straight out of print().
    app.reply = (200, json.dumps({"signature": "Тест"}).encode())
    assert main(_args(base_url, "--format", "toon", "threatfox", "types")) == 0
    assert "Тест" in capsys.readouterr().out


def test_non_utf8_stderr_does_not_crash() -> None:
    # Every error message goes to stderr, and they quote text this side does
    # not choose: a config path under a non-ASCII user name, the server's own
    # explanation, a mistyped URL. On a Windows console that is the ANSI code
    # page, so printing one raised UnicodeEncodeError straight out of main() —
    # the report crashing harder than the failure it was reporting.
    captured = io.BytesIO()
    original = sys.stderr
    sys.stderr = io.TextIOWrapper(captured, encoding="cp1252", errors="strict")
    try:
        code = main(_args("::日本語::", "threatfox", "types"))
        sys.stderr.flush()
        # Read it before the wrapper is dropped: collecting it closes the
        # BytesIO underneath and the bytes go with it.
        written = captured.getvalue()
    finally:
        sys.stderr = original
    assert code == 1
    assert "日本語" in written.decode("utf-8")


def test_stdout_without_reconfigure_is_left_alone(
    base_url: str, capsys: pytest.CaptureFixture[str]
) -> None:
    # A redirected stdout is not a TextIOWrapper and has no encoding to set.
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = main(_args(base_url, "threatfox", "types"))
    assert code == 0
    assert "query_status" in buffer.getvalue()
    capsys.readouterr()


@pytest.mark.parametrize(("flag", "sent"), [("1", True), ("0", False)])
def test_bool_param_is_sent_as_a_json_boolean(
    base_url: str, app: ReplyApp, flag: str, sent: bool
) -> None:
    # exact_match is documented as a boolean and typed bool on the client, but
    # the CLI used to put the raw integer on the wire.
    assert main(_args(base_url, "threatfox", "search_ioc", "1.2.3.4", "--exact-match", flag)) == 0
    assert json.loads(app.bodies[-1])["exact_match"] is sent


def test_bool_param_rejects_values_other_than_zero_or_one() -> None:
    argparse_usage_error = 2
    with pytest.raises(SystemExit) as caught:
        build_parser().parse_args(["threatfox", "search_ioc", "1.2.3.4", "--exact-match", "2"])
    assert caught.value.code == argparse_usage_error


def test_upload_handler(base_url: str, tmp_path: Path) -> None:
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"data")
    assert main(_args(base_url, "malwarebazaar", "upload", str(sample), "--anonymous", "1")) == 0


def test_upload_handler_parses_tags_and_json_objects(
    base_url: str, app: ReplyApp, tmp_path: Path
) -> None:
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"data")
    code = main(
        _args(
            base_url,
            "malwarebazaar",
            "upload",
            str(sample),
            "--tags",
            "exe, test ,",
            "--references",
            '{"twitter": ["https://twitter.com/x/status/1"]}',
            "--context",
            '{"comment": "nasty"}',
        )
    )
    assert code == 0
    payload = json_data_part(app.bodies[-1])
    assert payload["tags"] == ["exe", "test"]
    assert payload["references"] == {"twitter": ["https://twitter.com/x/status/1"]}
    assert payload["context"] == {"comment": "nasty"}


@pytest.mark.parametrize("bad", ["not json", "[1, 2]", '"a string"'])
def test_upload_handler_rejects_a_non_object(
    base_url: str, tmp_path: Path, capsys: pytest.CaptureFixture[str], bad: str
) -> None:
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"data")
    code = main(_args(base_url, "malwarebazaar", "upload", str(sample), "--context", bad))
    assert code == 1
    assert "--context must be a JSON object" in capsys.readouterr().err


def test_submit_ioc_handler_sends_what_was_typed(base_url: str, app: ReplyApp) -> None:
    """The exit status says the command ran, not what it filed.

    These handlers turn flags into a submission, and every one of those turns
    — the comma-split, the 0/1 read as a real boolean, an omitted flag left
    out rather than sent as a default — was invisible to a test that only
    asked whether the command returned 0.
    """
    argv = [
        "threatfox",
        "submit_ioc",
        "botnet_cc",
        "ip:port",
        "Cobalt Strike",
        "1.2.3.4:80,5.6.7.8:90",
        "--tags",
        "a,b",
        "--is-compromised",
        "1",
    ]
    assert main(_args(base_url, *argv)) == 0
    body = json.loads(app.bodies[-1])
    assert body == {
        "query": "submit_ioc",
        "threat_type": "botnet_cc",
        "ioc_type": "ip:port",
        "malware": "Cobalt Strike",
        "iocs": ["1.2.3.4:80", "5.6.7.8:90"],
        "is_compromised": True,
        "tags": ["a", "b"],
    }
    assert (
        main(_args(base_url, "threatfox", "submit_ioc", "botnet_cc", "ip:port", "x", "1.2.3.4:80"))
        == 0
    )
    # An omitted flag is omitted: sending is_compromised=false would claim the
    # host was attacker-owned on the submitter's behalf.
    assert json.loads(app.bodies[-1]).keys() == {
        "query",
        "threat_type",
        "ioc_type",
        "malware",
        "iocs",
    }


def test_urlhaus_submit_handler_sends_what_was_typed(base_url: str, app: ReplyApp) -> None:
    argv = ["urlhaus", "submit", "http://x", "--tags", "a,b", "--anonymous", "1"]
    assert main(_args(base_url, *argv)) == 0
    assert json.loads(app.bodies[-1]) == {
        "anonymous": 1,
        "submission": [{"url": "http://x", "threat": "malware_download", "tags": ["a", "b"]}],
    }
    assert main(_args(base_url, "urlhaus", "submit", "http://x")) == 0
    # --anonymous decides whether the submitter's handle is published, so the
    # default it falls back to is a decision and not an accident.
    assert json.loads(app.bodies[-1]) == {
        "anonymous": 0,
        "submission": [{"url": "http://x", "threat": "malware_download"}],
    }


def test_yaraify_scan_and_deploy(base_url: str, app: ReplyApp, tmp_path: Path) -> None:
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"data")
    assert main(_args(base_url, "yaraify", "scan_file", str(sample), "--unpack", "1")) == 0
    # The scan options ride as one json_data document, and the flags nobody
    # gave stay out of it — share_file in particular, whose absence is what
    # keeps a submitted sample from being shared.
    assert json_data_part(app.bodies[-1]) == {"unpack": 1}
    assert b'name="file"; filename="s.bin"' in app.bodies[-1]
    rule = tmp_path / "r.yar"
    rule.write_text("rule t {condition: true}", encoding="utf-8")
    assert main(_args(base_url, "yaraify", "deploy_yara_rule", str(rule))) == 0


def test_datalake_command(
    base_url: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "batch.zip"
    code = main(_args(base_url, "datalake", "malware-bazaar", "daily", "x.zip", "-o", str(out)))
    assert code == 0
    assert out.read_bytes()
    assert "Wrote" in capsys.readouterr().out


def test_datalake_command_with_an_output_file_does_not_hold_the_archive(
    base_url: str, app: ReplyApp, tmp_path: Path
) -> None:
    """--output streams; it is the only reason download_batch_to_file exists.

    Both paths write the same bytes and print the same line, so swapping the
    streaming call for the buffered one changes nothing a test could read —
    except the memory, which is the whole point: the daily archives run past a
    gigabyte. tracemalloc sees the Python allocations either path makes, and
    the buffered one has to hold the body whole.

    The bar is the archive's own size rather than something tighter, because
    the local server shares this process: measured over an 8 MiB archive, the
    streaming path peaks around 6.5 MB and the buffered one around 18.5 MB, so
    the size sits between them with room on both sides.
    """
    body = b"PK\x03\x04" + bytes(8 * (1 << 20))
    app.reply = (200, body)
    out = tmp_path / "day.zip"
    tracemalloc.start()
    try:
        code = main(_args(base_url, "datalake", "malware-bazaar", "daily", "x.zip", "-o", str(out)))
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert code == 0
    assert out.read_bytes() == body
    assert peak < len(body), f"held {peak} bytes of a {len(body)}-byte archive"


def test_datalake_command_without_output_buffers_to_stdout(
    base_url: str, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
    # No --output, so the archive goes to stdout on the buffered path rather
    # than the streaming-to-file one.
    code = main(_args(base_url, "datalake", "malware-bazaar", "daily", "x.zip"))
    assert code == 0
    assert b"query_status" in capsysbinary.readouterr().out


def test_ctrl_c_reports_an_interrupt_not_a_crash(
    base_url: str, app: ReplyApp, capsys: pytest.CaptureFixture[str]
) -> None:
    """A call can sit in a timeout and several backoffs, so Ctrl-C is routine.

    ``interrupt_main`` raises the same KeyboardInterrupt the console does, in
    the main thread, without depending on signal delivery. Unhandled, it
    printed forty lines of httpx and httpcore frames.
    """
    app.on_request = _thread.interrupt_main
    # Spelled out rather than compared against the constant: 128 + the signal
    # number is what a shell reports and what a calling script tests for, so
    # the value is a contract with the outside rather than an internal choice.
    # Asserting main() == SIGINT_EXIT alone holds either to whatever it is set
    # to, and passes just as well if someone makes it 131.
    assert SIGINT_EXIT == 128 + signal.SIGINT
    assert main(_args(base_url, "threatfox", "types")) == SIGINT_EXIT
    assert capsys.readouterr().err.strip() == "interrupted"


def test_a_reader_that_closed_the_pipe_is_not_reported_as_a_failure(
    base_url: str, app: ReplyApp, capsys: pytest.CaptureFixture[str]
) -> None:
    """``bazaar-ti threatfox malware_list | head`` is not this program failing.

    head closes the pipe as soon as it has its lines, and the write landing
    after that reached the OSError arm: "error: [Errno 32] Broken pipe" and
    exit 1 for the most ordinary thing a reader can do. A real pipe with its
    read end closed is the same condition, without a shell.

    The body has to outrun stdout's buffer, or nothing is written until the
    stream is closed and the break lands after main has already returned —
    which is the small-output case that was quiet all along.
    """
    app.reply = (200, json.dumps({"data": ["x" * 64] * 2000}).encode())
    read_fd, write_fd = os.pipe()
    os.close(read_fd)
    with open(write_fd, "w", encoding="utf-8") as broken, contextlib.redirect_stdout(broken):
        code = main(_args(base_url, "threatfox", "types"))
    assert SIGPIPE_EXIT == 128 + signal.SIGPIPE
    assert code == SIGPIPE_EXIT
    assert capsys.readouterr().err == ""


def test_discarding_stdout_leaves_a_stream_with_no_descriptor_alone() -> None:
    # A caller that replaced sys.stdout with an in-memory stream has no file
    # descriptor to redirect — and no pipe that could have broken either.
    with contextlib.redirect_stdout(io.StringIO()):
        _discard_stdout()


def test_error_returns_1(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(
        [
            "--auth-key",
            "k",
            "--base-url",
            "http://127.0.0.1:1/",
            "--retries",
            "0",
            "threatfox",
            "types",
        ]
    )
    assert code == 1
    assert "error:" in capsys.readouterr().err


def test_missing_file_returns_1(base_url: str, capsys: pytest.CaptureFixture[str]) -> None:
    code = main(_args(base_url, "malwarebazaar", "upload", "/nonexistent/nope.bin"))
    assert code == 1
    assert "error:" in capsys.readouterr().err


def test_dunder_main_module() -> None:
    saved = sys.argv
    sys.argv = ["bazaar-ti", "--help"]
    try:
        with pytest.raises(SystemExit):
            runpy.run_module("bazaar_ti.__main__", run_name="__main__")
    finally:
        sys.argv = saved


def test_dunder_main_import() -> None:
    module = importlib.import_module("bazaar_ti.__main__")
    assert module is not None


# --------------------------------------------------------------------------- #
# Argument errors must stay usage errors. Each case below is one argparse
# setting away from reaching run() with no command attached, which surfaces as
# an AttributeError traceback rather than a message telling you what to type.
# --------------------------------------------------------------------------- #

ARGPARSE_USAGE_ERROR = 2


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        ([], "arguments are required: service"),
        (["malwarebazaar"], "arguments are required: command"),
        (["malwarebazaar", "nope"], "invalid choice: 'nope'"),
        # A command that is not bulkable has no --input-file to supply its
        # value, so the value itself stays required.
        (["malwarebazaar", "get_taginfo"], "arguments are required: tag"),
        # types takes no value at all, so a list has nothing to substitute into
        # and the flag must not be registered. The other half of that pairing —
        # that a bulkable command does accept it — is what every _bulk() call
        # below runs, so it needs no test of its own.
        (["threatfox", "types", "--input-file", "x"], "unrecognized arguments: --input-file"),
    ],
)
def test_argument_errors_are_usage_errors(
    capsys: pytest.CaptureFixture[str], argv: list[str], expected: str
) -> None:
    with pytest.raises(SystemExit) as caught:
        main(argv)
    assert caught.value.code == ARGPARSE_USAGE_ERROR
    assert expected in capsys.readouterr().err


def test_version_flag_reports_the_package_version(capsys: pytest.CaptureFixture[str]) -> None:
    # Every SARIF document names the version that produced it, so the tool has
    # to be able to say the same thing when someone asks which build they run.
    with pytest.raises(SystemExit) as caught:
        main(["--version"])
    assert caught.value.code == 0
    assert capsys.readouterr().out.strip() == f"bazaar-ti {__version__}"


def test_the_client_is_closed_when_the_command_finishes(base_url: str) -> None:
    """A command that returns leaves no open connection pool behind.

    ``run`` builds the client from the factory argparse attached and closes it
    in a finally. Nothing watched the closing: the suite passes either way,
    because a leaked pool only shows up as sockets held by a long-lived
    process. The factory is wrapped here to keep hold of the real client — no
    stand-in, the same object the command ran on — so the state can be read
    afterwards.
    """
    parser = build_parser()
    args = parser.parse_args(_args(base_url, "threatfox", "types"))
    built: list[SyncService] = []
    factory: Factory = args._factory

    def remember(namespace: argparse.Namespace) -> SyncService:
        client = factory(namespace)
        built.append(client)
        return client

    args._factory = remember
    run(args)
    assert len(built) == 1
    assert built[0]._t._sync_client is None, "the command left its connection pool open"


def test_command_table_drift_fails_during_parser_registration() -> None:
    root = argparse.ArgumentParser().add_subparsers(dest="service")
    with pytest.raises(BazaarTIError, match="is not on ThreatFox"):
        register_service(root, "threatfox", ThreatFox, (Command("renamed_method"),))
    with pytest.raises(BazaarTIError, match="does not match"):
        register_service(root, "threatfox-drift", ThreatFox, (Command("types", (Param("old"),)),))
    # The other half of the same guard: a table that forgot a parameter the
    # method requires. Registration used to be checked for parameters the
    # client does not have and not for the ones it insists on, so a command
    # short of a required argument registered cleanly and failed as a
    # TypeError when someone ran it.
    with pytest.raises(BazaarTIError, match="missing=\\['tag'\\]"):
        register_service(root, "threatfox-short", ThreatFox, (Command("taginfo"),))
