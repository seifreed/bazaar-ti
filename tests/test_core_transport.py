"""Tests for the HTTP transport, using a real local server and real sockets."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import cast

import httpx
import pytest

from bazaar_ti._version import PROJECT_URL, __version__
from bazaar_ti.core.batch import threaded_map
from bazaar_ti.core.errors import AuthError, RateLimitError, TransportError
from bazaar_ti.core.response import ensure_not_an_error
from bazaar_ti.core.transport import (
    MAX_BACKOFF,
    MAX_JSON_DEPTH,
    RequestSpec,
    Transport,
    _backoff,
    _is_loopback,
    _request_kwargs,
    _spool_to_file,
    ensure_download,
    file_part,
    json_part,
)
from tests.conftest import ReplyApp

_UNROUTABLE = "http://127.0.0.1:1/"


def test_request_kwargs_variants() -> None:
    assert _request_kwargs(RequestSpec(encoding="json", data={"a": 1})) == {"json": {"a": 1}}
    assert _request_kwargs(RequestSpec(encoding="json", data=None)) == {}
    assert _request_kwargs(RequestSpec(encoding="form", data={"a": "b"})) == {"data": {"a": "b"}}
    assert _request_kwargs(RequestSpec(encoding="form", data=None)) == {}
    part = file_part("n", b"x")
    multipart = _request_kwargs(
        RequestSpec(encoding="multipart", data={"a": "b"}, files={"f": part})
    )
    assert multipart == {"data": {"a": "b"}, "files": {"f": part}}
    assert _request_kwargs(RequestSpec(encoding="multipart")) == {"data": {}, "files": {}}
    assert _request_kwargs(RequestSpec(method="GET", params={"x": "y"})) == {"params": {"x": "y"}}


def test_multipart_part_helpers() -> None:
    # json_data travels as a named part with no filename, so servers read it as
    # a JSON document rather than an uploaded file.
    assert json_part({"a": 1}) == (None, b'{"a": 1}', "application/json")
    assert file_part("s.exe", b"MZ") == ("s.exe", b"MZ", "application/octet-stream")


def test_backoff_grows() -> None:
    assert _backoff(2) > _backoff(1) > _backoff(0)


def test_backoff_is_capped() -> None:
    """Uncapped doubling made a raised --retries look like a hang.

    At 15 retries it slept over four hours in total, and the exponent
    overflowed a float long before that.
    """
    retries = 20
    assert all(_backoff(attempt) <= MAX_BACKOFF for attempt in range(200))
    assert _backoff(10_000) == MAX_BACKOFF
    assert sum(_backoff(attempt) for attempt in range(retries)) <= retries * MAX_BACKOFF


@pytest.mark.parametrize("retries", [-1, 11, 1.5, True])
def test_transport_rejects_an_invalid_retry_budget(retries: object) -> None:
    with pytest.raises(ValueError, match="retries must be between 0 and 10"):
        Transport(_UNROUTABLE, "k", retries=cast(int, retries))


@pytest.mark.parametrize(
    "timeout",
    [-1, 0, float("nan"), float("inf"), "abc", None, True],
)
def test_transport_rejects_an_unusable_timeout(timeout: object) -> None:
    """The CLI refused these; a caller holding the library got them anyway.

    Kept until the first request, each came back from inside httpx or CPython
    as something no caller of this library would think to catch — ValueError
    for a negative one, OverflowError for an infinite one, TypeError for a
    string — and none of them named the argument that was wrong. ``None`` is
    refused with them because httpx reads it as "wait forever", which is the
    one outcome a timeout is there to prevent.
    """
    with pytest.raises(ValueError, match="timeout must be a positive number of seconds"):
        Transport(_UNROUTABLE, "k", timeout=cast(float, timeout))


async def test_the_timeout_reaches_the_client_that_does_the_waiting() -> None:
    """Both clients are built lazily, and the timeout is the reason to build them.

    Left off, httpx applies its own five seconds: a caller asking for sixty
    gets five, and every test still passes because none of them waits long
    enough to tell. Both halves keep their own client, so both are checked.
    """
    transport = Transport(_UNROUTABLE, "k", timeout=7.5)
    try:
        assert transport._sclient().timeout == httpx.Timeout(7.5)
        assert transport._aclient().timeout == httpx.Timeout(7.5)
    finally:
        transport.close()
        await transport.aclose()


def test_empty_download_is_an_error() -> None:
    # Passing it through wrote a 0-byte "sample" and reported success.
    with pytest.raises(TransportError, match="Download was empty"):
        ensure_download(b"")


@pytest.mark.parametrize(
    ("chunks", "label"),
    [([], "no chunk at all"), ([b""], "a chunk carrying no bytes"), ([b"", b""], "two of them")],
)
def test_a_stream_that_carries_no_bytes_is_an_error(
    tmp_path: Path, chunks: list[bytes], label: str
) -> None:
    """A download that produced nothing is refused, and leaves nothing behind.

    Whether a chunk was offered is not the question — the byte count is. Asked
    only whether a chunk arrived, an empty one opened the file and reported
    success: a 0-byte archive under the name the caller asked for, which is
    exactly what the buffered guard refuses.
    """
    dest = tmp_path / f"{label.replace(' ', '-')}.zip"
    with pytest.raises(TransportError, match="was empty"):
        _spool_to_file(iter(chunks), dest)
    assert not dest.exists()


def test_ensure_download() -> None:
    assert ensure_download(b"PK\x03\x04binary") == b"PK\x03\x04binary"
    assert ensure_download(b"{not valid json") == b"{not valid json"
    assert ensure_download(b'{"query_status": "ok"}') == b'{"query_status": "ok"}'
    assert ensure_download(b'{"data": 1}') == b'{"data": 1}'
    # The rejecting side is the table below, which asserts the message too.


@pytest.mark.parametrize(
    "body",
    [
        "#################\nsha256,reason\n",
        "{not valid json",
        # JSON, but not an object: only an object can carry query_status, and
        # handing one of these to the auth check instead raises AttributeError
        # on a body the server is perfectly entitled to send.
        "[1, 2, 3]",
        "42",
        '"a string"',
        '{"query_status": "ok"}',
        '{"data": 1}',
    ],
)
def test_a_body_that_is_not_a_json_error_is_returned_unchanged(body: str) -> None:
    assert ensure_not_an_error(body) == body


@pytest.mark.parametrize(
    ("body", "error", "expected"),
    [
        ('{"query_status":"unknown_auth_key"}', AuthError, "Server rejected the Auth-Key"),
        (
            '\n  {"query_status":"no_results","data":"nothing here"}',
            TransportError,
            "Request failed: no_results \\(nothing here\\)",
        ),
    ],
)
def test_a_json_error_where_text_was_expected_is_refused(
    body: str, error: type[Exception], expected: str
) -> None:
    # Hunting serves its false-positive list as CSV, which never reaches the
    # JSON decoder — so this body was handed back as the list and written out
    # under whatever name the caller redirected it to.
    with pytest.raises(error, match=expected):
        ensure_not_an_error(body)


def test_ensure_download_detects_whitespace_before_a_json_error() -> None:
    body = b'\n  {"query_status": "not_found"}'
    with pytest.raises(TransportError, match="Download failed: not_found"):
        ensure_download(body)


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        # YARAify answers a missing sample with the reason in "data".
        (
            b'{"query_status":"not_found","data":"Unknown file or file not shareable"}',
            "Download failed: not_found (Unknown file or file not shareable)",
        ),
        (b'{"query_status":"error","message":"nope"}', "Download failed: error (nope)"),
        (b'{"query_status":"error","error":"nope"}', "Download failed: error (nope)"),
        (b'{"query_status":"file_not_found"}', "Download failed: file_not_found"),
        (b'{"query_status":"error","data":123}', "Download failed: error"),
    ],
)
def test_download_failure_keeps_the_server_explanation(body: bytes, expected: str) -> None:
    with pytest.raises(TransportError, match=re.escape(expected)):
        ensure_download(body)


def test_every_request_names_the_client_and_its_version(base_url: str, app: ReplyApp) -> None:
    """abuse.ch rate limits by account, so its operators must see what we are.

    Unset, httpx sends its own default and every user of this package arrives
    as anonymous ``python-httpx`` traffic — indistinguishable from a script
    someone wrote in an afternoon, and throttling is then the only lever the
    service has. The version is in there because a bug worth blocking is
    usually a bug in one release.
    """
    t = Transport(base_url, "k")
    t.request_json_sync(RequestSpec())
    t.close()
    agent = app.headers[-1]["user-agent"]
    assert agent.startswith("bazaar-ti/")
    assert __version__ in agent
    assert PROJECT_URL in agent


def test_sync_json_and_text(base_url: str) -> None:
    t = Transport(base_url, "k")
    assert t.request_json_sync(RequestSpec()) == {"query_status": "ok"}
    assert "query_status" in t.request_text_sync(RequestSpec())
    t.close()
    t.close()  # idempotent: covers the "no client" branch


async def test_async_json_and_text(base_url: str) -> None:
    t = Transport(base_url, "k")
    assert await t.request_json(RequestSpec()) == {"query_status": "ok"}
    assert "query_status" in await t.request_text(RequestSpec())
    await t.aclose()
    await t.aclose()


def _nested(depth: int) -> bytes:
    """A JSON object nested ``depth`` levels, for the two rows that need one."""
    return b'{"a":' * depth + b"1" + b"}" * depth


# Each row: the status and body the server sends, and the exception and message
# the clients must turn them into. Grouped into one tuple per case because the
# columns are one description, and because six separate parameters is more than
# a test signature should carry.
_UNUSABLE_RESPONSES = [
    # Which exception a status maps to is part of the contract: a caller
    # retries a rate limit and re-reads its config for an Auth-Key, so these
    # cannot all arrive as the same generic transport failure.
    pytest.param((401, b"{}", AuthError, "rejected the Auth-Key"), id="a rejected Auth-Key"),
    pytest.param((403, b"{}", AuthError, "rejected the Auth-Key"), id="an Auth-Key without access"),
    pytest.param(
        (
            200,
            b'{"query_status":"unknown_auth_key","data":"expired"}',
            AuthError,
            "rejected the Auth-Key",
        ),
        id="an Auth-Key rejected in a JSON body",
    ),
    pytest.param((429, b"{}", RateLimitError, "Rate limit exceeded"), id="a rate limit"),
    pytest.param(
        (200, b"not json", TransportError, "not valid JSON"), id="a body that is not JSON"
    ),
    # The clients are typed to return a JSON object; an array or scalar body
    # must fail here rather than surface as an AttributeError in caller code.
    pytest.param(
        (200, b'["not", "an", "object"]', TransportError, "Expected a JSON object, got list"),
        id="JSON that is not an object",
    ),
    # Redirects are not followed, so the Auth-Key never reaches another host.
    # The empty body used to surface as "not valid JSON", which hides the real
    # cause — typically an http:// base URL that the server bounces to https.
    pytest.param(
        (301, b"", TransportError, r"Unexpected redirect \(HTTP 301\)"), id="moved permanently"
    ),
    pytest.param((302, b"", TransportError, r"Unexpected redirect \(HTTP 302\)"), id="found"),
    pytest.param(
        (307, b"", TransportError, r"Unexpected redirect \(HTTP 307\)"), id="temporary redirect"
    ),
    # 300 is the first redirect status, so it is the one the check can miss.
    pytest.param(
        (300, b"", TransportError, r"Unexpected redirect \(HTTP 300\)"),
        id="the first redirect status",
    ),
    # 4xx is checked before the redirect branch it would otherwise fall into,
    # which would report a 404 as "Unexpected redirect (HTTP 404)".
    pytest.param(
        (404, b"{}", TransportError, "Unexpected HTTP status 404"),
        id="a client error, not a redirect",
    ),
    # 400 is the boundary the check is written against, and the only status
    # where being one off matters: >= 401, or > 400, sends a Bad Request down
    # the redirect branch below it and reports it as "Unexpected redirect
    # (HTTP 400)". 404 passes either way and cannot show it.
    pytest.param(
        (400, b"{}", TransportError, "Unexpected HTTP status 400"),
        id="the first client-error status",
    ),
    # Python's decoder accepts these three; nothing downstream can emit them.
    # Accepted, they reach the renderers, and to_json/to_sarif write the same
    # tokens straight back out — a file that no longer parses as JSON for the
    # consumer it was written for. TOON is worse: a bare "nan" decodes as the
    # string "nan", so the type changes without anything failing.
    pytest.param((200, b'{"score": NaN}', TransportError, "Response contained NaN"), id="NaN"),
    pytest.param(
        (200, b'{"score": Infinity}', TransportError, "Response contained Infinity"),
        id="Infinity",
    ),
    pytest.param(
        (200, b'{"score": -Infinity}', TransportError, "Response contained -Infinity"),
        id="-Infinity",
    ),
    # An out-of-range numeric literal is decoded by parse_float, not the
    # parse_constant hook that catches the bare Infinity token, so it used to
    # slip through to inf and render back as the invalid JSON token "Infinity".
    pytest.param(
        (200, b'{"score": 1e400}', TransportError, "Response contained 1e400"),
        id="a positive overflow literal",
    ),
    pytest.param(
        (200, b'{"score": -1e400}', TransportError, "Response contained -1e400"),
        id="a negative overflow literal",
    ),
    pytest.param(
        (200, b'{"a": {"b": [1, NaN]}}', TransportError, "Response contained NaN"),
        id="a non-finite number buried in the body",
    ),
    # The TOON encoder recurses, so a deep response overflowed the stack.
    # Responses come off the network, and --base-url points anywhere, so the
    # depth is checked here rather than left to whichever renderer runs.
    pytest.param(
        (200, _nested(MAX_JSON_DEPTH + 50), TransportError, f"nested deeper than {MAX_JSON_DEPTH}"),
        id="nested past the cap",
    ),
    # Past a few hundred thousand levels json.loads itself raises RecursionError,
    # which is neither BazaarTIError nor OSError and so would escape the CLI as a
    # traceback before the depth guard ever runs.
    pytest.param(
        (200, _nested(200_000), TransportError, "nested too deeply to parse"),
        id="nested past the decoder's own limit",
    ),
]


@pytest.mark.parametrize("case", _UNUSABLE_RESPONSES)
def test_a_response_the_clients_cannot_use_is_refused_clearly(
    base_url: str, app: ReplyApp, case: tuple[int, bytes, type[Exception], str]
) -> None:
    """Each of these must name what went wrong, not fail somewhere further on.

    One table rather than four. Every refusal above reaches the caller through
    the same two methods — ``_check`` reads the status, ``_json`` reads the body
    — so a test per family was one harness written out four times, differing
    only in which column it filled in. Split that way the 400 boundary was
    already written twice, once asserting the exception type and once the
    message, and the weaker copy could never fail on its own.
    """
    status, body, error, message = case
    app.reply = (status, body)
    t = Transport(base_url, "k")
    with pytest.raises(error, match=message):
        t.request_json_sync(RequestSpec())
    t.close()


_USABLE_RESPONSES = [
    # The guards above are all one comparison away from refusing a real record,
    # and each needs the same harness to say so, so they share this one too.
    pytest.param(
        (b'{"a": 1, "b": -2.5, "c": 1e300}', {"a": 1, "b": -2.5, "c": 1e300}),
        id="finite numbers, including one at the top of the float range",
    ),
    pytest.param(
        (
            b'{"query_status":"ok","data":[{"vendor_intel":{"a":{"b":[1,2]}}}]}',
            {"query_status": "ok", "data": [{"vendor_intel": {"a": {"b": [1, 2]}}}]},
        ),
        id="the handful of levels a real record nests",
    ),
]


@pytest.mark.parametrize("case", _USABLE_RESPONSES)
def test_a_response_the_clients_can_use_is_returned_intact(
    base_url: str, app: ReplyApp, case: tuple[bytes, dict[str, object]]
) -> None:
    body, expected = case
    app.reply = (200, body)
    t = Transport(base_url, "k")
    assert t.request_json_sync(RequestSpec()) == expected
    t.close()


def test_base_url_without_a_trailing_slash(base_url: str, app: ReplyApp) -> None:
    """A mirror URL naming a directory used to swallow it into the first path.

    ``https://mirror/api`` + ``v1/url/`` concatenated to ``/apiv1/url/``: a
    valid URL that nothing rejects, requesting something the caller never
    asked for and handing it the Auth-Key.
    """
    t = Transport(base_url.rstrip("/") + "/api", "k")
    t.request_json_sync(RequestSpec(method="GET", path="v1/url/"))
    t.close()
    assert app.paths == ["/api/v1/url/"]


def test_base_url_with_a_trailing_slash_is_unchanged(base_url: str, app: ReplyApp) -> None:
    t = Transport(base_url, "k")
    t.request_json_sync(RequestSpec(method="GET", path="v1/url/"))
    t.close()
    assert app.paths == ["/v1/url/"]


def test_invalid_base_url_is_a_transport_error() -> None:
    t = Transport("::not a url::", "k")
    with pytest.raises(TransportError, match="Invalid URL"):
        t.request_json_sync(RequestSpec(method="GET"))
    t.close()


def test_remote_http_base_url_is_rejected_before_sending_the_auth_key() -> None:
    t = Transport("http://example.com/", "secret")
    with pytest.raises(TransportError, match="plain HTTP"):
        t.request_json_sync(RequestSpec(method="GET"))
    t.close()


def test_localhost_is_treated_as_loopback() -> None:
    assert _is_loopback("localhost")


def test_non_http_base_url_is_rejected() -> None:
    t = Transport("ftp://example.com/", "secret")
    with pytest.raises(TransportError, match=r"Invalid HTTP\(S\) URL"):
        t.request_json_sync(RequestSpec(method="GET"))
    t.close()


async def test_invalid_base_url_is_a_transport_error_async() -> None:
    t = Transport("::not a url::", "k")
    with pytest.raises(TransportError, match="Invalid URL"):
        await t.request_json(RequestSpec(method="GET"))
    await t.aclose()


def test_sync_client_is_threadsafe(base_url: str) -> None:
    transport = Transport(base_url, "k")
    count = 24
    try:
        results = threaded_map(
            lambda _: transport.request_json_sync(RequestSpec()),
            list(range(count)),
            concurrency=8,
        )
        assert len(results) == count
        assert all(r == {"query_status": "ok"} for r in results)
    finally:
        transport.close()


def test_sync_connection_error() -> None:
    t = Transport(_UNROUTABLE, "k", retries=1)
    with pytest.raises(TransportError):
        t.request_json_sync(RequestSpec(method="GET"))
    t.close()


async def test_async_connection_error() -> None:
    t = Transport(_UNROUTABLE, "k", retries=1)
    with pytest.raises(TransportError):
        await t.request_json(RequestSpec(method="GET"))
    await t.aclose()


async def test_aclose_closes_the_underlying_async_client(base_url: str) -> None:
    """A closed transport must leave no open connection pool behind.

    The sync side is covered by every service test; the async one had nothing
    asserting that aclose reached the client it opened.
    """
    t = Transport(base_url, "k")
    await t.request_json(RequestSpec())
    client = t._async_client
    assert client is not None and not client.is_closed
    await t.aclose()
    assert client.is_closed
    assert t._async_client is None
    await t.aclose()  # closing twice is a no-op, not an error


def test_close_closes_the_underlying_sync_client(base_url: str) -> None:
    t = Transport(base_url, "k")
    t.request_json_sync(RequestSpec())
    client = t._sync_client
    assert client is not None and not client.is_closed
    t.close()
    assert client.is_closed
    assert t._sync_client is None
    t.close()


@pytest.mark.parametrize("payload", [{"data": ["a", "b"]}, {"message": {"x": 1}}, {"error": 5}])
def test_download_detail_ignores_a_non_string_explanation(payload: dict[str, object]) -> None:
    # The explanation is pasted into the error message, so anything that is not
    # text has to be passed over rather than rendered as a Python repr.
    body = json.dumps({"query_status": "not_found", **payload}).encode()
    with pytest.raises(TransportError) as caught:
        ensure_download(body)
    assert str(caught.value) == "Download failed: not_found"


def test_status_500_is_retried_but_499_is_not(base_url: str, app: ReplyApp) -> None:
    # 500 is the first status worth another attempt; 499 is a client error the
    # server will answer the same way however many times it is asked.
    #
    # This also stands in for the plain "a 500 ends as a TransportError" test
    # that used to sit above: exhausting the budget is how that path is reached,
    # and counting the attempts says which of the two branches got there.
    retries = 2
    for status, expected in ((500, retries + 1), (499, 1)):
        app.reply = (status, b"{}")
        app.bodies.clear()
        t = Transport(base_url, "k", retries=retries)
        with pytest.raises(TransportError):
            t.request_json_sync(RequestSpec())
        t.close()
        assert len(app.bodies) == expected


async def test_async_retries_reads_and_never_retries_a_write(base_url: str, app: ReplyApp) -> None:
    """The async transport keeps its own copy of the retry loop.

    Every retry test until now drove the sync client, leaving the async
    boundary — and the guarantee that a submission is sent once — unheld. It is
    also the whole async side of the loop: a bare "a 500 raises" twin sat beside
    this one and could not fail without this one failing first.
    """
    retries = 3
    app.reply = (500, b"boom")

    async def attempts(spec: RequestSpec) -> int:
        app.bodies.clear()
        t = Transport(base_url, "k", retries=retries)
        with pytest.raises(TransportError):
            await t.request_json(spec)
        await t.aclose()
        return len(app.bodies)

    reads = await attempts(RequestSpec())
    writes = await attempts(RequestSpec(retryable=False))
    assert reads == retries + 1
    assert writes == 1


def test_redaction_leaves_a_message_alone_when_there_is_no_key() -> None:
    """The datalake needs no Auth-Key, so its transport carries an empty one.

    Replacing the empty string is a match at every position, which would turn
    the whole message into "***I***n***v***a***l***i***d***" and lose it.
    """
    t = Transport("::bad url::", "")
    with pytest.raises(TransportError) as caught:
        t.request_download_sync(RequestSpec(method="GET", path="urlhaus/daily/x.zip"))
    t.close()
    message = str(caught.value)
    assert message.startswith("Invalid URL")
    assert "***" not in message
