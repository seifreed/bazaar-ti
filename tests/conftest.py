"""Shared fixtures: a real local WSGI server and live-API helpers.

The local server uses real sockets and real HTTP (no ``unittest.mock``), so it
satisfies the project's no-mocks rule while making error paths and write
endpoints deterministic and side-effect free. Tests marked ``live`` talk to the
real abuse.ch API and require ``BAZAAR_TI_AUTH_KEY``.
"""

from __future__ import annotations

import json
import os
import threading
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Any
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

import pytest

# A real, non-malicious sample known to MalwareBazaar/URLhaus/YARAify.
KNOWN_SHA256 = "b1ece5874c05e86f9daaa08096d9acf0f8e07071e2700fcd99fb35d0a4d598c1"

REPO_ROOT = Path(__file__).resolve().parent.parent
"""The checked-out project, from the one file that is placed to know where it is.

Two suites read out of it rather than out of the package: test_packaging checks
the README and pyproject against what the code says, and test_services asks src
which builders refuse a retry. Both had worked it out from their own __file__,
which is the layout of this directory written down twice.
"""

_StartResponse = Callable[[str, list[tuple[str, str]]], object]


def json_data_part(body: bytes) -> Any:
    """Pull the decoded ``json_data`` part out of a captured multipart body.

    MalwareBazaar's upload and YARAify's scan both carry their metadata as one
    JSON document beside the file, so both the service tests and the CLI tests
    need to read it back off the wire. Asserting the marker first turns a body
    that never got the part into a readable failure rather than an IndexError.
    """
    marker = b'name="json_data"'
    assert marker in body, body[:400]
    section = body.split(marker, 1)[1]
    payload = section.split(b"\r\n\r\n", 1)[1].split(b"\r\n--", 1)[0]
    return json.loads(payload)


class ReplyApp:
    """A WSGI app that returns a settable (status, body); the test server.

    Setting ``fail_on`` makes just the requests whose body contains that
    substring answer with ``fail_reply``, so a batch can fail partway through
    the way a real service would. That reply defaults to HTTP 429 because a
    rate limit is the failure the bulk path treats specially — it stops the
    batch — and a test of the ordinary case has to pick something else.
    ``on_request`` runs once the request has been read, which is where a test
    can interrupt the waiting client. ``declared_length`` overstates
    Content-Length, which cuts the body off mid-stream the way a connection
    that drops part way through a download does.
    """

    def __init__(self) -> None:
        self.reply: tuple[int, bytes] = (200, json.dumps({"query_status": "ok"}).encode())
        self.fail_on: bytes | None = None
        self.fail_reply: tuple[int, bytes] = (
            429,
            json.dumps({"query_status": "rate_limited"}).encode(),
        )
        self.on_request: Callable[[], object] | None = None
        self.declared_length: int | None = None
        self.port: int = 0
        self.bodies: list[bytes] = []
        self.paths: list[str] = []
        self.methods: list[str] = []
        self.headers: list[dict[str, str]] = []

    def __call__(self, environ: dict[str, Any], start_response: _StartResponse) -> Iterable[bytes]:
        length = int(str(environ.get("CONTENT_LENGTH") or 0))
        request_body = environ["wsgi.input"].read(length) if length else b""
        self.bodies.append(request_body)
        self.headers.append(
            {
                key[5:].replace("_", "-").lower(): str(value)
                for key, value in environ.items()
                if key.startswith("HTTP_")
            }
        )
        query = environ.get("QUERY_STRING") or ""
        # WSGI hands PATH_INFO over decoded as latin-1 (PEP 3333); recover the
        # text the client actually percent-encoded.
        raw_path = str(environ.get("PATH_INFO", ""))
        path = raw_path.encode("latin-1", "replace").decode("utf-8", "replace")
        self.paths.append(path + (f"?{query}" if query else ""))
        self.methods.append(str(environ.get("REQUEST_METHOD", "")))
        if self.on_request is not None:
            self.on_request()
        if self.fail_on is not None and self.fail_on in request_body:
            status, body = self.fail_reply
        else:
            status, body = self.reply
        declared = self.declared_length if self.declared_length is not None else len(body)
        start_response(
            f"{status} STATUS",
            [("Content-Type", "application/json"), ("Content-Length", str(declared))],
        )
        return [body]


class _QuietHandler(WSGIRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: object) -> None:
        return


class _ThreadingWSGIServer(ThreadingMixIn, WSGIServer):
    daemon_threads = True


@pytest.fixture
def app() -> Iterator[ReplyApp]:
    """Yield a WSGI app whose ``reply`` a test can override, served on a real port."""
    application = ReplyApp()
    httpd: WSGIServer = make_server(
        "127.0.0.1",
        0,
        application,
        server_class=_ThreadingWSGIServer,
        handler_class=_QuietHandler,
    )
    # shutdown() waits for the accept loop to notice, so the poll interval is
    # paid on teardown by every test that uses the server; the 0.5s default
    # dominated the run time.
    thread = threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.01})
    thread.daemon = True
    thread.start()
    application.port = httpd.server_address[1]
    try:
        yield application
    finally:
        httpd.shutdown()
        thread.join()
        httpd.server_close()


@pytest.fixture
def base_url(app: ReplyApp) -> str:
    return f"http://127.0.0.1:{app.port}/"


@pytest.fixture
def live_key() -> str:
    key = os.environ.get("BAZAAR_TI_AUTH_KEY")
    if not key:
        pytest.skip("BAZAAR_TI_AUTH_KEY not set; skipping live test.")
    return key
