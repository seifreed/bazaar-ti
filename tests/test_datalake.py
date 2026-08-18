"""Tests for datalake batch downloads against the local server."""

from __future__ import annotations

from pathlib import Path

import pytest

from bazaar_ti.core.errors import BazaarTIError, TransportError
from bazaar_ti.datalake import (
    DAILY,
    DATASETS,
    MALWAREBAZAAR,
    PERIODS,
    BatchOptions,
    download_batch,
    download_batch_async,
    download_batch_to_file,
    download_batch_to_file_async,
)
from tests.conftest import ReplyApp


def test_download_batch_sync(base_url: str) -> None:
    data = download_batch(MALWAREBAZAAR, "daily", "x.zip", BatchOptions(base_url=base_url))
    assert isinstance(data, bytes)


async def test_download_batch_async(base_url: str) -> None:
    data = await download_batch_async(
        MALWAREBAZAAR, "daily", "x.zip", BatchOptions(base_url=base_url)
    )
    assert isinstance(data, bytes)


@pytest.mark.parametrize(
    ("body", "expected"),
    [(b"", "was empty"), (b'{"query_status":"not_found"}', "not_found")],
)
def test_a_batch_that_is_not_an_archive_is_refused(
    base_url: str, app: ReplyApp, body: bytes, expected: str
) -> None:
    # Both answer HTTP 200, so without this the body was written out as the
    # archive and the download reported as a success: a zero-byte "batch", or
    # a JSON error saved under a .zip name and only noticed when unzipped.
    app.reply = (200, body)
    with pytest.raises(TransportError, match=expected):
        download_batch(MALWAREBAZAAR, DAILY, "x.zip", BatchOptions(base_url=base_url))


async def test_an_async_batch_that_is_not_an_archive_is_refused(
    base_url: str, app: ReplyApp
) -> None:
    app.reply = (200, b"")
    with pytest.raises(TransportError, match="was empty"):
        await download_batch_async(MALWAREBAZAAR, DAILY, "x.zip", BatchOptions(base_url=base_url))


def test_download_batch_to_file_streams_a_multi_chunk_body(
    base_url: str, app: ReplyApp, tmp_path: Path
) -> None:
    # Larger than one read chunk, so the streaming loop runs more than once, and
    # not JSON, so it takes the spool-to-disk path rather than the guard.
    body = b"PK\x03\x04" + bytes(3 * (1 << 20))
    app.reply = (200, body)
    dest = tmp_path / "batch.zip"
    written = download_batch_to_file(
        MALWAREBAZAAR, DAILY, "x.zip", dest, BatchOptions(base_url=base_url)
    )
    assert written == len(body)
    assert dest.read_bytes() == body


def test_download_batch_to_file_writes_a_leading_brace_that_is_not_an_error(
    base_url: str, app: ReplyApp, tmp_path: Path
) -> None:
    # A body that opens with "{" is inspected by the guard; a non-error JSON is
    # written through rather than raised on.
    body = b'{"query_status":"ok"}'
    app.reply = (200, body)
    dest = tmp_path / "batch.json"
    written = download_batch_to_file(
        MALWAREBAZAAR, DAILY, "x.zip", dest, BatchOptions(base_url=base_url)
    )
    assert written == len(body)
    assert dest.read_bytes() == body


@pytest.mark.parametrize(
    ("body", "expected"),
    [(b"", "was empty"), (b'{"query_status":"not_found"}', "not_found")],
)
def test_a_streamed_batch_that_is_not_an_archive_is_refused_and_leaves_no_file(
    base_url: str, app: ReplyApp, tmp_path: Path, body: bytes, expected: str
) -> None:
    app.reply = (200, body)
    dest = tmp_path / "batch.zip"
    with pytest.raises(TransportError, match=expected):
        download_batch_to_file(MALWAREBAZAAR, DAILY, "x.zip", dest, BatchOptions(base_url=base_url))
    assert not dest.exists()


def test_a_streamed_batch_removes_the_partial_file_when_the_write_fails(
    base_url: str, app: ReplyApp, tmp_path: Path
) -> None:
    # The destination's parent does not exist, so opening it for writing fails
    # after the body has started; the guard must not leave a stray file behind.
    app.reply = (200, b"PK\x03\x04data")
    dest = tmp_path / "missing" / "batch.zip"
    with pytest.raises(OSError):
        download_batch_to_file(MALWAREBAZAAR, DAILY, "x.zip", dest, BatchOptions(base_url=base_url))
    assert not dest.exists()


def test_a_streamed_json_error_larger_than_one_chunk_is_still_refused(
    base_url: str, app: ReplyApp, tmp_path: Path
) -> None:
    # The guard reads a leading-brace body out whole before judging it, so an
    # error big enough to arrive in several chunks must be reassembled rather
    # than judged on the first one.
    padding = "a" * (2 * (1 << 20))
    app.reply = (200, f'{{"query_status":"not_found","note":"{padding}"}}'.encode())
    dest = tmp_path / "batch.zip"
    with pytest.raises(TransportError, match="not_found"):
        download_batch_to_file(MALWAREBAZAAR, DAILY, "x.zip", dest, BatchOptions(base_url=base_url))
    assert not dest.exists()


def test_a_streamed_batch_cut_off_mid_body_leaves_no_partial_file(
    base_url: str, app: ReplyApp, tmp_path: Path
) -> None:
    # The server promises more than it sends, so the connection dies after the
    # first chunk is already on disk — the case the whole download failed at,
    # rather than the open failing before it. What must not survive is a
    # truncated archive under the name the caller asked for.
    app.reply = (200, b"PK\x03\x04" + bytes(2 * (1 << 20)))
    app.declared_length = 4 * (1 << 20)
    dest = tmp_path / "batch.zip"
    with pytest.raises(TransportError):
        download_batch_to_file(MALWAREBAZAAR, DAILY, "x.zip", dest, BatchOptions(base_url=base_url))
    assert not dest.exists()


def test_a_streamed_batch_retries_a_server_error_and_leaves_no_file(
    base_url: str, app: ReplyApp, tmp_path: Path
) -> None:
    app.reply = (500, b"boom")
    dest = tmp_path / "batch.zip"
    retries = 3
    with pytest.raises(TransportError):
        download_batch_to_file(
            MALWAREBAZAAR, DAILY, "x.zip", dest, BatchOptions(base_url=base_url, retries=retries)
        )
    assert len(app.bodies) == retries + 1
    assert not dest.exists()


def test_a_streamed_batch_reports_a_client_error(
    base_url: str, app: ReplyApp, tmp_path: Path
) -> None:
    app.reply = (404, b"nope")
    dest = tmp_path / "batch.zip"
    with pytest.raises(TransportError, match="404"):
        download_batch_to_file(MALWAREBAZAAR, DAILY, "x.zip", dest, BatchOptions(base_url=base_url))
    assert not dest.exists()


def test_a_streamed_batch_retries_then_reports_a_connection_failure(tmp_path: Path) -> None:
    # retries=1 so the first connect error falls through to a retry before the
    # second, final one is raised — exercising both sides of the open loop.
    dest = tmp_path / "batch.zip"
    with pytest.raises(TransportError, match="Request failed"):
        download_batch_to_file(
            MALWAREBAZAAR,
            DAILY,
            "x.zip",
            dest,
            BatchOptions(base_url="http://127.0.0.1:1/", retries=1),
        )
    assert not dest.exists()


async def test_async_download_batch_to_file_streams_a_multi_chunk_body(
    base_url: str, app: ReplyApp, tmp_path: Path
) -> None:
    body = b"PK\x03\x04" + bytes(3 * (1 << 20))
    app.reply = (200, body)
    dest = tmp_path / "batch.zip"
    written = await download_batch_to_file_async(
        MALWAREBAZAAR, DAILY, "x.zip", dest, BatchOptions(base_url=base_url)
    )
    assert written == len(body)
    assert dest.read_bytes() == body


async def test_async_download_batch_to_file_writes_a_leading_brace_that_is_not_an_error(
    base_url: str, app: ReplyApp, tmp_path: Path
) -> None:
    body = b'{"query_status":"ok"}'
    app.reply = (200, body)
    dest = tmp_path / "batch.json"
    written = await download_batch_to_file_async(
        MALWAREBAZAAR, DAILY, "x.zip", dest, BatchOptions(base_url=base_url)
    )
    assert written == len(body)
    assert dest.read_bytes() == body


@pytest.mark.parametrize(
    ("body", "expected"),
    [(b"", "was empty"), (b'{"query_status":"not_found"}', "not_found")],
)
async def test_an_async_streamed_batch_that_is_not_an_archive_is_refused_and_leaves_no_file(
    base_url: str, app: ReplyApp, tmp_path: Path, body: bytes, expected: str
) -> None:
    app.reply = (200, body)
    dest = tmp_path / "batch.zip"
    with pytest.raises(TransportError, match=expected):
        await download_batch_to_file_async(
            MALWAREBAZAAR, DAILY, "x.zip", dest, BatchOptions(base_url=base_url)
        )
    assert not dest.exists()


async def test_an_async_streamed_batch_removes_the_partial_file_when_the_write_fails(
    base_url: str, app: ReplyApp, tmp_path: Path
) -> None:
    app.reply = (200, b"PK\x03\x04data")
    dest = tmp_path / "missing" / "batch.zip"
    with pytest.raises(OSError):
        await download_batch_to_file_async(
            MALWAREBAZAAR, DAILY, "x.zip", dest, BatchOptions(base_url=base_url)
        )
    assert not dest.exists()


async def test_an_async_streamed_batch_cut_off_mid_body_leaves_no_partial_file(
    base_url: str, app: ReplyApp, tmp_path: Path
) -> None:
    app.reply = (200, b"PK\x03\x04" + bytes(2 * (1 << 20)))
    app.declared_length = 4 * (1 << 20)
    dest = tmp_path / "batch.zip"
    with pytest.raises(TransportError):
        await download_batch_to_file_async(
            MALWAREBAZAAR, DAILY, "x.zip", dest, BatchOptions(base_url=base_url)
        )
    assert not dest.exists()


async def test_an_async_streamed_batch_retries_a_server_error_and_leaves_no_file(
    base_url: str, app: ReplyApp, tmp_path: Path
) -> None:
    app.reply = (500, b"boom")
    dest = tmp_path / "batch.zip"
    retries = 3
    with pytest.raises(TransportError):
        await download_batch_to_file_async(
            MALWAREBAZAAR, DAILY, "x.zip", dest, BatchOptions(base_url=base_url, retries=retries)
        )
    assert len(app.bodies) == retries + 1
    assert not dest.exists()


async def test_an_async_streamed_batch_reports_a_client_error(
    base_url: str, app: ReplyApp, tmp_path: Path
) -> None:
    app.reply = (404, b"nope")
    dest = tmp_path / "batch.zip"
    with pytest.raises(TransportError, match="404"):
        await download_batch_to_file_async(
            MALWAREBAZAAR, DAILY, "x.zip", dest, BatchOptions(base_url=base_url)
        )
    assert not dest.exists()


async def test_an_async_streamed_batch_retries_then_reports_a_connection_failure(
    tmp_path: Path,
) -> None:
    dest = tmp_path / "batch.zip"
    with pytest.raises(TransportError, match="Request failed"):
        await download_batch_to_file_async(
            MALWAREBAZAAR,
            DAILY,
            "x.zip",
            dest,
            BatchOptions(base_url="http://127.0.0.1:1/", retries=1),
        )
    assert not dest.exists()


@pytest.mark.parametrize(
    ("dataset", "period", "name"),
    [
        (MALWAREBAZAAR, "daily", ""),
        (MALWAREBAZAAR, "daily", "   "),
        (MALWAREBAZAAR, "", "x.zip"),
        ("", "daily", "x.zip"),
    ],
)
def test_empty_path_segment_is_refused(base_url: str, dataset: str, period: str, name: str) -> None:
    # An empty segment addresses the parent directory, which answers 200 with
    # an HTML listing that would be saved as the archive and called a success.
    with pytest.raises(BazaarTIError, match="is required"):
        download_batch(dataset, period, name, BatchOptions(base_url=base_url))


@pytest.mark.parametrize(
    "name",
    ["2026-07-24.zip", "a#b.zip", "a?b.zip", "my file.zip", "ünï.zip"],
)
def test_archive_name_reaches_the_server_intact(base_url: str, app: ReplyApp, name: str) -> None:
    # Unencoded, "#" ended the path and "?" started a query string, so the
    # request quietly asked for a different archive than the caller named.
    download_batch(MALWAREBAZAAR, "daily", name, BatchOptions(base_url=base_url))
    assert app.paths[-1] == f"/{MALWAREBAZAAR}/daily/{name}"


def test_a_batch_is_fetched_with_get(base_url: str, app: ReplyApp, tmp_path: Path) -> None:
    # RequestSpec defaults to POST, which the datalake is not: these are static
    # archives on a file host, and the local server answers either verb, so
    # nothing here noticed the difference.
    download_batch(MALWAREBAZAAR, DAILY, "x.zip", BatchOptions(base_url=base_url))
    download_batch_to_file(
        MALWAREBAZAAR, DAILY, "x.zip", tmp_path / "batch.zip", BatchOptions(base_url=base_url)
    )
    assert app.methods == ["GET", "GET"]


def test_archive_name_cannot_escape_the_dataset_prefix(base_url: str, app: ReplyApp) -> None:
    download_batch(MALWAREBAZAAR, "daily", "../../etc/passwd", BatchOptions(base_url=base_url))
    assert app.paths[-1].startswith(f"/{MALWAREBAZAAR}/daily/")


@pytest.mark.parametrize(
    ("dataset", "period"),
    [
        ("malwarebazaar", DAILY),  # the real name is hyphenated
        ("Malware-Bazaar", DAILY),
        (MALWAREBAZAAR, "Daily"),
        (MALWAREBAZAAR, "weekly"),
    ],
)
def test_unknown_dataset_or_period_is_named(
    base_url: str, app: ReplyApp, dataset: str, period: str
) -> None:
    # Both segments name a directory on the server, so a wrong one came back as
    # a 404 that reads like the archive is missing rather than like a typo.
    with pytest.raises(BazaarTIError, match="expected one of"):
        download_batch(dataset, period, "x.zip", BatchOptions(base_url=base_url))
    assert app.paths == []


def test_every_documented_dataset_and_period_is_accepted(base_url: str, app: ReplyApp) -> None:
    for dataset in DATASETS:
        for period in PERIODS:
            download_batch(dataset, period, "x.zip", BatchOptions(base_url=base_url))
    assert app.paths == [f"/{dataset}/{period}/x.zip" for dataset in DATASETS for period in PERIODS]
