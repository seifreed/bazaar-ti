"""HTTP transport shared by every service client (async and sync)."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import math
import threading
import time
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Literal
from urllib.parse import quote

import httpx

from .config import DEFAULT_RETRIES, DEFAULT_TIMEOUT, MAX_RETRIES, USER_AGENT
from .errors import AuthError, RateLimitError, TransportError
from .response import MAX_JSON_DEPTH, ensure_download, parse_json

__all__ = [
    "Encoding",
    "UploadFile",
    "RequestSpec",
    "Transport",
    "ensure_download",
    "file_part",
    "json_part",
    "path_segment",
    "MAX_JSON_DEPTH",
]

Encoding = Literal["json", "form", "multipart"]

UploadFile = tuple[str | None, bytes, str]
"""One multipart part: ``(filename or None, content, content type)``."""

JSON_CONTENT_TYPE = "application/json"
BINARY_CONTENT_TYPE = "application/octet-stream"


def json_part(data: dict[str, Any]) -> UploadFile:
    """Build a named multipart part carrying a JSON document, with no filename."""
    return (None, json.dumps(data).encode(), JSON_CONTENT_TYPE)


def file_part(filename: str, content: bytes) -> UploadFile:
    """Build a multipart part carrying an uploaded file."""
    return (filename, content, BINARY_CONTENT_TYPE)


def path_segment(value: str) -> str:
    """Percent-encode one URL path segment.

    Left raw, a value containing ``#`` or ``?`` ends the path early and quietly
    requests something other than what the caller asked for.
    """
    return quote(value, safe="")


_REDIRECT = 300
_BAD_REQUEST = 400
_RATE_LIMIT = 429
_SERVER_ERROR = 500
_AUTH_REJECTED = (401, 403)


@dataclass(frozen=True, slots=True)
class RequestSpec:
    """A single, transport-agnostic description of an API call."""

    method: Literal["GET", "POST"] = "POST"
    path: str = ""
    encoding: Encoding = "json"
    data: dict[str, Any] | None = None
    params: dict[str, str] | None = None
    files: dict[str, UploadFile] | None = None
    retryable: bool = True
    """False for calls that create something.

    A timeout can arrive after the server already committed the request, so
    retrying a submission or upload would file it more than once.
    """


def _request_kwargs(spec: RequestSpec) -> dict[str, Any]:
    kwargs: dict[str, Any] = {}
    if spec.params is not None:
        kwargs["params"] = spec.params
    if spec.encoding == "json" and spec.data is not None:
        kwargs["json"] = spec.data
    elif spec.encoding == "form" and spec.data is not None:
        kwargs["data"] = spec.data
    elif spec.encoding == "multipart":
        kwargs["data"] = spec.data or {}
        kwargs["files"] = spec.files or {}
    return kwargs


MAX_BACKOFF = 30.0
"""Longest a single retry will wait.

Uncapped doubling turns a raised --retries into an apparent hang: at 15 it
sleeps for over four hours in total, and at 20 for nearly a week.
"""


def _backoff(attempt: int) -> float:
    # The inner cap keeps the exponent from overflowing a float on a large
    # --retries; anything past a handful of attempts is pinned to the ceiling.
    return min(MAX_BACKOFF, 0.5 * (2.0 ** min(attempt, 16)))


def _joinable(base_url: str) -> str:
    """End the base URL with the separator the paths are appended after.

    Paths are relative, so a ``--base-url`` of ``https://mirror/api`` used to
    concatenate into ``https://mirror/apiv1/url/``: a URL that is valid, that
    nothing rejects, and that sends the Auth-Key somewhere the caller never
    asked for. Only the last segment is ambiguous, so adding the slash is the
    reading the caller meant rather than a guess.

    ``httpx.Client(base_url=...)`` normalizes and merges identically — checked
    across every base URL and path this project issues, and they agree on all
    of them. Handing the join to httpx anyway would cost more than it saves:
    ``_url`` is the one place both the async and the sync send path validate
    through, and httpx raises ``InvalidURL`` from the client constructor, which
    each of the two client factories would then have to catch, wrap as
    :class:`TransportError` and redact separately. Removing this would put that
    back twice.
    """
    return base_url if base_url.endswith("/") else base_url + "/"


def _is_loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


_STREAM_CHUNK = 1 << 20
"""How much of a streamed download is held in memory at once (1 MiB).

Spooling to disk a chunk at a time keeps peak memory near this, whatever the
archive's size; the datalake's daily archives run past a gigabyte, so buffering
the whole body the way the plain download does would hold all of it at once.
"""


class _Spool:
    """Writes streamed chunks to ``dest``, whatever pulls them off the wire.

    An abuse.ch error is a small JSON body and never a real archive, so a
    response that opens with ``{`` is held in memory and handed to the buffered
    guard, which raises on an error; anything else goes straight to disk. A
    download that fails part way removes the partial file rather than leaving a
    truncated archive that looks complete.

    The sync and async streaming paths differ only in how they await the next
    chunk, so both feed this rather than each restating the two rules above.
    """

    def __init__(self, dest: Path) -> None:
        self._dest = dest
        self._handle: BinaryIO | None = None
        self._error: list[bytes] | None = None
        self._written = 0

    def add(self, chunk: bytes) -> None:
        if self._error is not None:
            self._error.append(chunk)
            return
        if self._handle is None:
            if chunk.lstrip()[:1] == b"{":
                self._error = [chunk]
                return
            self._handle = self._dest.open("wb")
        self._handle.write(chunk)
        self._written += len(chunk)

    def finish(self) -> int:
        if self._error is not None:
            body = ensure_download(b"".join(self._error))
            self._dest.write_bytes(body)
            return len(body)
        if self._handle is None or not self._written:
            # The byte count is the question that matters: it only grows on a
            # write, so it answers both "no chunk came" and "the chunks that
            # came carried no bytes", and the second used to open the file,
            # write nothing and report success — the 0-byte "sample" the
            # buffered guard refuses. abort() removes the file if one was
            # opened. The handle half is not a second rule; it is what tells
            # the type checker that the close below has something to close.
            raise TransportError("Download was empty; the server sent no content.")
        self._handle.close()
        return self._written

    def abort(self) -> None:
        """Drop a partial file, leaving an untouched ``dest`` alone."""
        if self._handle is None:
            return
        self._handle.close()
        self._dest.unlink(missing_ok=True)


def _spool_to_file(chunks: Iterator[bytes], dest: Path) -> int:
    """Write streamed chunks to ``dest``, returning the byte count."""
    spool = _Spool(dest)
    try:
        for chunk in chunks:
            spool.add(chunk)
        return spool.finish()
    except BaseException:
        spool.abort()
        raise


async def _spool_to_file_async(chunks: AsyncIterator[bytes], dest: Path) -> int:
    """Async twin of :func:`_spool_to_file`.

    The writes themselves stay blocking: a chunk is a megabyte to a local file,
    which costs far less than the network wait it sits between, and a thread per
    write would be the expensive half.
    """
    spool = _Spool(dest)
    try:
        async for chunk in chunks:
            spool.add(chunk)
        return spool.finish()
    except BaseException:
        spool.abort()
        raise


class Transport:
    """Issues requests for one service base URL, with retries and error mapping.

    A single instance exposes both async and sync entry points; each lazily
    opens its own ``httpx`` client.
    """

    def __init__(
        self,
        base_url: str,
        auth_key: str,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
    ) -> None:
        if (
            isinstance(retries, bool)
            or not isinstance(retries, int)
            or not 0 <= retries <= MAX_RETRIES
        ):
            raise ValueError(f"retries must be between 0 and {MAX_RETRIES}")
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            # Checked here rather than only in the CLI, which is the other
            # caller. Held until the first request, each bad value came back
            # as something from inside httpx or CPython that no caller of this
            # library would think to catch — ValueError for a negative one,
            # OverflowError for an infinite one, TypeError for a string — and
            # none of them mentioned the argument that was wrong. ``None`` is
            # rejected with them: httpx reads it as "wait forever", which is
            # the one outcome a timeout exists to prevent.
            raise ValueError("timeout must be a positive number of seconds")
        self._base_url = _joinable(base_url)
        self._auth_key = auth_key
        self._headers = {"Auth-Key": auth_key, "User-Agent": USER_AGENT}
        self._timeout = timeout
        self._retries = retries
        self._async_client: httpx.AsyncClient | None = None
        self._sync_client: httpx.Client | None = None
        self._sync_lock = threading.Lock()

    def _aclient(self) -> httpx.AsyncClient:
        if self._async_client is None:
            self._async_client = httpx.AsyncClient(timeout=self._timeout)
        return self._async_client

    def _sclient(self) -> httpx.Client:
        with self._sync_lock:
            if self._sync_client is None:
                self._sync_client = httpx.Client(timeout=self._timeout)
            return self._sync_client

    def _check(self, response: httpx.Response) -> httpx.Response:
        status = response.status_code
        if status in _AUTH_REJECTED:
            raise AuthError(f"Server rejected the Auth-Key (HTTP {status}).")
        if status == _RATE_LIMIT:
            raise RateLimitError("Rate limit exceeded (HTTP 429).")
        if status >= _BAD_REQUEST:
            raise TransportError(f"Unexpected HTTP status {status}.")
        if status >= _REDIRECT:
            # Redirects are deliberately not followed, so the Auth-Key header
            # is never handed to another host. Say so, rather than letting the
            # empty body surface as "not valid JSON".
            location = response.headers.get("location", "")
            raise TransportError(
                self._redact(
                    f"Unexpected redirect (HTTP {status}) to {location!r}; "
                    "redirects are not followed."
                )
            )
        return response

    def _redact(self, text: str) -> str:
        """Keep the Auth-Key out of messages headed for terminals and logs.

        Some endpoints carry the key in the URL path, so any message quoting a
        URL would otherwise disclose the caller's credential. It has to be
        matched percent-encoded as well: a key holding any character that
        ``path_segment`` escapes reaches the message in that form, and
        matching only the raw text would walk straight past it.
        """
        if not self._auth_key:
            return text
        for form in (self._auth_key, path_segment(self._auth_key)):
            text = text.replace(form, "***")
        return text

    def _url(self, path: str) -> str:
        """Join and validate the request URL, so a bad base URL is a clean error."""
        url = self._base_url + path
        try:
            parsed = httpx.URL(url)
        except httpx.InvalidURL as exc:
            raise TransportError(self._redact(f"Invalid URL {url!r}: {exc}")) from exc
        if parsed.scheme not in {"http", "https"} or parsed.host is None:
            raise TransportError(self._redact(f"Invalid HTTP(S) URL {url!r}."))
        if parsed.scheme == "http" and not _is_loopback(parsed.host):
            raise TransportError(
                "Refusing to send the Auth-Key over plain HTTP to a non-loopback host."
            )
        return url

    def _last_attempt(self, spec: RequestSpec) -> int:
        """Number of the attempt after which a send gives up.

        A retryable spec gets ``retries`` further tries after the first. One
        that is not retryable gets only the first, since a timeout can land
        after the server already committed and a second send would file the
        submission twice.
        """
        return self._retries if spec.retryable else 0

    async def _send(self, spec: RequestSpec) -> httpx.Response:
        client = self._aclient()
        url = self._url(spec.path)
        kwargs = _request_kwargs(spec)
        last = self._last_attempt(spec)
        attempt = 0
        while True:
            try:
                response = await client.request(spec.method, url, headers=self._headers, **kwargs)
            except httpx.RequestError as exc:
                if attempt == last:
                    raise TransportError(self._redact(f"Request failed: {exc}")) from exc
            else:
                # A server error on the last attempt goes to _check, which
                # reports the status rather than retrying past the budget.
                if response.status_code < _SERVER_ERROR or attempt == last:
                    return self._check(response)
            await asyncio.sleep(_backoff(attempt))
            attempt += 1

    def _send_sync(self, spec: RequestSpec) -> httpx.Response:
        client = self._sclient()
        url = self._url(spec.path)
        kwargs = _request_kwargs(spec)
        last = self._last_attempt(spec)
        attempt = 0
        while True:
            try:
                response = client.request(spec.method, url, headers=self._headers, **kwargs)
            except httpx.RequestError as exc:
                if attempt == last:
                    raise TransportError(self._redact(f"Request failed: {exc}")) from exc
            else:
                if response.status_code < _SERVER_ERROR or attempt == last:
                    return self._check(response)
            time.sleep(_backoff(attempt))
            attempt += 1

    @staticmethod
    def _json(response: httpx.Response) -> dict[str, Any]:
        return parse_json(response)

    async def request_json(self, spec: RequestSpec) -> dict[str, Any]:
        return self._json(await self._send(spec))

    def request_json_sync(self, spec: RequestSpec) -> dict[str, Any]:
        return self._json(self._send_sync(spec))

    async def request_download(self, spec: RequestSpec) -> bytes:
        """Fetch bytes that are meant to be a file, refusing an error body.

        Every download in the library paired :func:`ensure_download` with a
        bytes request, and none of the twelve did one without the other — so
        the pairing is the operation, and writing it out per endpoint left the
        guard optional at exactly the call that must not skip it. Skipped, a
        JSON ``{"query_status": "file_not_found"}`` is saved under the sample's
        name and the download reports success.

        The unguarded half used to be reachable on its own, as a
        ``request_bytes`` pair whose only caller was this method. Nothing asked
        for raw bytes — that is the point of the paragraph above — so all it
        offered was the one way to get a download wrong, on a class that
        ``bazaar_ti`` deliberately does not re-export for callers to reach.
        """
        return ensure_download((await self._send(spec)).content)

    def request_download_sync(self, spec: RequestSpec) -> bytes:
        return ensure_download(self._send_sync(spec).content)

    async def _open_stream(self, spec: RequestSpec) -> httpx.Response:
        """Async twin of :meth:`_open_stream_sync`; see it for what is retried."""
        client = self._aclient()
        url = self._url(spec.path)
        kwargs = _request_kwargs(spec)
        last = self._last_attempt(spec)
        attempt = 0
        while True:
            request = client.build_request(spec.method, url, headers=self._headers, **kwargs)
            try:
                response = await client.send(request, stream=True)
            except httpx.RequestError as exc:
                if attempt == last:
                    raise TransportError(self._redact(f"Request failed: {exc}")) from exc
            else:
                if response.status_code < _SERVER_ERROR or attempt == last:
                    try:
                        return self._check(response)
                    except BaseException:
                        await response.aclose()
                        raise
                await response.aclose()
            await asyncio.sleep(_backoff(attempt))
            attempt += 1

    async def stream_download(self, spec: RequestSpec, dest: Path) -> int:
        """Stream a download to ``dest`` instead of buffering it, returning bytes written."""
        response = await self._open_stream(spec)
        try:
            return await _spool_to_file_async(response.aiter_bytes(_STREAM_CHUNK), dest)
        except httpx.RequestError as exc:
            # A body that dies part way cannot be retried without range
            # requests, but it is still this transport's failure to report.
            raise TransportError(self._redact(f"Request failed: {exc}")) from exc
        finally:
            await response.aclose()

    def _open_stream_sync(self, spec: RequestSpec) -> httpx.Response:
        """Open a streamed response, retrying the connection like a buffered send.

        Only the open is retried: once the body is flowing a mid-stream failure
        cannot be resumed without range requests, so it is raised. A transient
        connection error or a server error before the first byte is retried on
        the same budget the buffered path uses.
        """
        client = self._sclient()
        url = self._url(spec.path)
        kwargs = _request_kwargs(spec)
        last = self._last_attempt(spec)
        attempt = 0
        while True:
            request = client.build_request(spec.method, url, headers=self._headers, **kwargs)
            try:
                response = client.send(request, stream=True)
            except httpx.RequestError as exc:
                if attempt == last:
                    raise TransportError(self._redact(f"Request failed: {exc}")) from exc
            else:
                if response.status_code < _SERVER_ERROR or attempt == last:
                    try:
                        return self._check(response)
                    except BaseException:
                        response.close()
                        raise
                response.close()
            time.sleep(_backoff(attempt))
            attempt += 1

    def stream_download_sync(self, spec: RequestSpec, dest: Path) -> int:
        """Stream a download to ``dest`` instead of buffering it, returning bytes written."""
        response = self._open_stream_sync(spec)
        try:
            return _spool_to_file(response.iter_bytes(_STREAM_CHUNK), dest)
        except httpx.RequestError as exc:
            # A body that dies part way cannot be retried without range
            # requests, but it is still this transport's failure to report.
            raise TransportError(self._redact(f"Request failed: {exc}")) from exc
        finally:
            response.close()

    async def request_text(self, spec: RequestSpec) -> str:
        return (await self._send(spec)).text

    def request_text_sync(self, spec: RequestSpec) -> str:
        return self._send_sync(spec).text

    async def aclose(self) -> None:
        if self._async_client is not None:
            await self._async_client.aclose()
            self._async_client = None

    def close(self) -> None:
        if self._sync_client is not None:
            self._sync_client.close()
            self._sync_client = None
