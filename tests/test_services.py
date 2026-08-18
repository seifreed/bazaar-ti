"""Exercise every service method (async + sync) against the local server.

The server returns ``{"query_status": "ok"}`` for every request, so these tests
prove the request-building and response-handling code paths without touching the
live platform. Real-API behaviour is checked in ``test_live.py``.
"""

from __future__ import annotations

import ast
import json
from typing import Any
from urllib.parse import quote

import pytest

from bazaar_ti.core.errors import AuthError, BazaarTIError, TransportError
from bazaar_ti.core.transport import RequestSpec
from bazaar_ti.services.base import upload_spec
from bazaar_ti.services.hunting import (
    FPLIST_FORMATS,
    Hunting,
    HuntingAsync,
    _spec_create_collection,
)
from bazaar_ti.services.malwarebazaar import (
    MalwareBazaar,
    MalwareBazaarAsync,
    UploadOptions,
    _spec_add_comment,
    _spec_download,
    _spec_get_certificate,
    _spec_get_info,
    _spec_update,
)
from bazaar_ti.services.threatfox import (
    SubmitIocOptions,
    ThreatFox,
    ThreatFoxAsync,
    _spec_submit_ioc,
)
from bazaar_ti.services.urlhaus import Urlhaus, UrlhausAsync, _spec_submit
from bazaar_ti.services.yaraify import (
    ScanOptions,
    Yaraify,
    YaraifyAsync,
    _spec_deploy,
    _spec_rescan,
)
from tests.conftest import REPO_ROOT, ReplyApp, json_data_part

H = "0" * 64


def test_malwarebazaar_sync(base_url: str) -> None:
    with MalwareBazaar(auth_key="k", base_url=base_url) as mb:
        assert mb.get_info(H)["query_status"] == "ok"
        mb.get_recent()
        mb.recent_detections()
        mb.recent_detections(24)
        mb.get_taginfo("t")
        mb.get_taginfo("t", 10)
        mb.get_siginfo("s")
        mb.get_file_type("exe")
        mb.get_clamavinfo("c")
        mb.get_imphash("i")
        mb.get_tlsh("t")
        mb.get_telfhash("t")
        mb.get_gimphash("g")
        mb.get_dhash_icon("d")
        mb.get_yarainfo("y")
        mb.get_issuerinfo("cn")
        mb.get_subjectinfo("cn")
        mb.get_certificate("1")
        mb.get_cscb()
        mb.update(H, "comment", "hi")
        mb.add_comment(H, "hi")
        assert isinstance(mb.download(H), bytes)
        mb.upload(b"x", "f.bin")
        mb.upload(
            b"x",
            "f.bin",
            UploadOptions(1, ["t"], {"twitter": ["u"]}, {"comment": "c"}, "web_download"),
        )


async def test_malwarebazaar_async(base_url: str) -> None:
    async with MalwareBazaarAsync(auth_key="k", base_url=base_url) as mb:
        await mb.get_info(H)
        await mb.get_recent()
        await mb.recent_detections(24)
        await mb.get_taginfo("t", 10)
        await mb.get_siginfo("s")
        await mb.get_file_type("exe")
        await mb.get_clamavinfo("c")
        await mb.get_imphash("i")
        await mb.get_tlsh("t")
        await mb.get_telfhash("t")
        await mb.get_gimphash("g")
        await mb.get_dhash_icon("d")
        await mb.get_yarainfo("y")
        await mb.get_issuerinfo("cn")
        await mb.get_subjectinfo("cn")
        await mb.get_certificate("1")
        await mb.get_cscb()
        await mb.update(H, "comment", "hi")
        await mb.add_comment(H, "hi")
        assert isinstance(await mb.download(H), bytes)
        await mb.upload(b"x", "f.bin", UploadOptions(anonymous=1))


def test_threatfox_sync(base_url: str) -> None:
    with ThreatFox(auth_key="k", base_url=base_url) as tf:
        tf.get_iocs()
        tf.get_iocs(3)
        tf.ioc(1)
        tf.search_ioc("x")
        tf.search_ioc("x", True)
        tf.search_hash(H)
        tf.taginfo("t")
        tf.taginfo("t", 5)
        tf.malwareinfo("m")
        tf.get_label("m")
        tf.get_label("m", "win")
        tf.malware_list()
        tf.types()
        tf.tag_list()
        tf.submit_ioc("botnet_cc", "ip:port", "Cobalt Strike", ["1.2.3.4:80"])
        tf.submit_ioc(
            "botnet_cc",
            "ip:port",
            "Cobalt Strike",
            ["1.2.3.4:80"],
            SubmitIocOptions(50, True, "https://x", ["t"], "c", 1),
        )


def test_threatfox_submit_ioc_needs_an_ioc(base_url: str, app: ReplyApp) -> None:
    with ThreatFox(auth_key="k", base_url=base_url) as tf, pytest.raises(BazaarTIError):
        tf.submit_ioc("botnet_cc", "ip:port", "Cobalt Strike", [])
    assert app.bodies == []


async def test_threatfox_async(base_url: str) -> None:
    async with ThreatFoxAsync(auth_key="k", base_url=base_url) as tf:
        await tf.get_iocs(3)
        await tf.ioc(1)
        await tf.search_ioc("x", True)
        await tf.search_hash(H)
        await tf.taginfo("t", 5)
        await tf.malwareinfo("m")
        await tf.get_label("m", "win")
        await tf.malware_list()
        await tf.types()
        await tf.tag_list()
        await tf.submit_ioc(
            "botnet_cc", "ip:port", "x", ["1.2.3.4:80"], SubmitIocOptions(anonymous=1)
        )


def test_urlhaus_sync(base_url: str) -> None:
    with Urlhaus(auth_key="k", base_url=base_url) as uh:
        uh.urls_recent()
        uh.urls_recent(5)
        uh.payloads_recent()
        uh.payloads_recent(2)
        uh.url("http://x")
        uh.urlid("1")
        uh.host("h")
        uh.payload(md5_hash="m")
        uh.payload(sha256_hash="s")
        uh.tag("t")
        uh.signature("s")
        assert isinstance(uh.download(H), bytes)
        assert isinstance(uh.export(), bytes)
        assert isinstance(uh.export("recent.json"), bytes)
        uh.submit([{"url": "http://x", "threat": "malware_download"}])
        uh.submit([{"url": "http://x", "threat": "malware_download"}], anonymous=1)


async def test_urlhaus_async(base_url: str) -> None:
    async with UrlhausAsync(auth_key="k", base_url=base_url) as uh:
        await uh.urls_recent(5)
        await uh.payloads_recent()
        await uh.url("http://x")
        await uh.urlid("1")
        await uh.host("h")
        await uh.payload(sha256_hash="s")
        await uh.tag("t")
        await uh.signature("s")
        assert isinstance(await uh.download(H), bytes)
        assert isinstance(await uh.export(), bytes)
        await uh.submit([{"url": "http://x", "threat": "malware_download"}], anonymous=1)


def test_yaraify_sync(base_url: str) -> None:
    with Yaraify(auth_key="k", base_url=base_url) as ya:
        ya.generate_identifier()
        ya.list_tasks("id")
        ya.list_tasks("id", "processed")
        ya.get_results("t")
        ya.get_results("t", "token")
        ya.lookup_hash("h")
        ya.lookup_hash("h", "token")
        ya.get_yara("s")
        ya.get_yara("s", 50)
        ya.get_clamav("s")
        ya.get_imphash("s")
        ya.get_tlsh("s")
        ya.get_telfhash("s")
        ya.get_gimphash("s")
        ya.get_dhash_icon("s")
        ya.rescan_file("h")
        ya.recent_yararules()
        ya.show_deployed_yara_rules()
        ya.delete_yara_rule("uuid")
        ya.get_yara_rule("uuid")
        assert isinstance(ya.get_file(H), bytes)
        assert isinstance(ya.get_unpacked(H), bytes)
        ya.scan_file(b"x", "f.bin")
        ya.scan_file(b"x", "f.bin", ScanOptions("id", 1, 1, 1, 1, 1))
        ya.deploy_yara_rule(b"rule test {condition: true}", "r.yar")


async def test_yaraify_async(base_url: str) -> None:
    async with YaraifyAsync(auth_key="k", base_url=base_url) as ya:
        await ya.generate_identifier()
        await ya.list_tasks("id", "processed")
        await ya.get_results("t", "token")
        await ya.lookup_hash("h", "token")
        await ya.get_yara("s", 50)
        await ya.get_clamav("s")
        await ya.get_imphash("s")
        await ya.get_tlsh("s")
        await ya.get_telfhash("s")
        await ya.get_gimphash("s")
        await ya.get_dhash_icon("s")
        await ya.rescan_file("h")
        await ya.recent_yararules()
        await ya.show_deployed_yara_rules()
        await ya.delete_yara_rule("uuid")
        await ya.get_yara_rule("uuid")
        assert isinstance(await ya.get_file(H), bytes)
        assert isinstance(await ya.get_unpacked(H), bytes)
        await ya.scan_file(b"x", "f.bin", ScanOptions(identifier="id"))
        await ya.deploy_yara_rule(b"rule test {condition: true}", "r.yar")


def test_hunting_sync(base_url: str) -> None:
    with Hunting(auth_key="k", base_url=base_url) as hu:
        assert isinstance(hu.get_fplist(), dict)
        assert isinstance(hu.get_fplist("csv"), str)
        hu.create_collection("c")
        hu.create_collection("c", "desc", 1)


async def test_hunting_async(base_url: str) -> None:
    async with HuntingAsync(auth_key="k", base_url=base_url) as hu:
        assert isinstance(await hu.get_fplist(), dict)
        assert isinstance(await hu.get_fplist("csv"), str)
        await hu.create_collection("c")
        await hu.create_collection("c", "desc", 1)


# --------------------------------------------------------------------------- #
# Wire format — these endpoints are documented as a file part plus a json_data
# part, so assert the bytes rather than just that the call returns.
# --------------------------------------------------------------------------- #


def test_malwarebazaar_upload_wire_format(base_url: str, app: ReplyApp) -> None:
    with MalwareBazaar(auth_key="k", base_url=base_url) as mb:
        mb.upload(
            b"MZ\x90",
            "sample.exe",
            UploadOptions(
                anonymous=1,
                tags=["exe", "test"],
                references={"twitter": ["https://twitter.com/x/status/1"]},
                context={"comment": "very nasty"},
                delivery_method="email_attachment",
            ),
        )
    body = app.bodies[-1]
    assert json_data_part(body) == {
        "anonymous": 1,
        "tags": ["exe", "test"],
        "references": {"twitter": ["https://twitter.com/x/status/1"]},
        "context": {"comment": "very nasty"},
        "delivery_method": "email_attachment",
    }
    assert b'name="file"; filename="sample.exe"' in body
    # The endpoint has no query field; "upload_file" was never part of the API.
    assert b"upload_file" not in body


def test_yaraify_scan_wire_format(base_url: str, app: ReplyApp) -> None:
    with Yaraify(auth_key="k", base_url=base_url) as ya:
        ya.scan_file(b"MZ\x90", "sample.exe", ScanOptions(share_file=0, unpack=1, clamav_scan=0))
    body = app.bodies[-1]
    # share_file=0 is the opt-out that keeps a submitted sample private, so it
    # has to reach the server rather than be dropped as a flat form field.
    assert json_data_part(body) == {"clamav_scan": 0, "unpack": 1, "share_file": 0}
    assert b'name="file"; filename="sample.exe"' in body


def test_yaraify_deploy_wire_format(base_url: str, app: ReplyApp) -> None:
    # Like the scan endpoint, this one is chosen by which file part arrives.
    # "deploy_yara_rule" is not a query value the API accepts, so sending it
    # named a selector that does not exist.
    with Yaraify(auth_key="k", base_url=base_url) as ya:
        ya.deploy_yara_rule(b"rule t {condition: true}", "r.yar")
    body = app.bodies[-1]
    assert b'name="yara_file"; filename="r.yar"' in body
    assert b"query" not in body


_SELECTORS = [
    ("get_taginfo", "tag"),
    ("get_siginfo", "signature"),
    ("get_file_type", "file_type"),
    ("get_clamavinfo", "clamav"),
    ("get_imphash", "imphash"),
    ("get_tlsh", "tlsh"),
    ("get_telfhash", "telfhash"),
    ("get_gimphash", "gimphash"),
    ("get_dhash_icon", "dhash_icon"),
    ("get_yarainfo", "yara_rule"),
]


@pytest.mark.parametrize(("method", "field"), _SELECTORS)
def test_each_selector_lookup_names_its_own_query(
    base_url: str, app: ReplyApp, method: str, field: str
) -> None:
    """Ten endpoints share one builder, and only the field name was pinned.

    Every one of them posts ``query=<method>`` beside its search field, but the
    query came from an argument nothing checked: pointing the whole family at a
    single action left the suite green, and every lookup would have asked
    abuse.ch the same question with the wrong field beside it.
    """
    with MalwareBazaar(auth_key="k", base_url=base_url) as mb:
        getattr(mb, method)("value", 5)
    assert app.bodies[-1] == f"query={method}&{field}=value&limit=5".encode()


def test_get_recent_names_its_query(base_url: str, app: ReplyApp) -> None:
    with MalwareBazaar(auth_key="k", base_url=base_url) as mb:
        mb.get_recent("100")
    assert app.bodies[-1] == b"query=get_recent&selector=100"


def test_malwarebazaar_get_certificate_sends_the_field_the_api_reads(
    base_url: str, app: ReplyApp
) -> None:
    """abuse.ch names this field three ways in one section of its own docs.

    The parameter table says ``subject_cn``, the runnable wget example posts
    ``serial_number``, and the sentence introducing it says ``issuer_cn``.
    Asked directly, the live endpoint answers only to ``serial_number``; the
    other two come back ``no_issuer_cn``.
    """
    serial = "05a6cf9108f6941e492c3d2a1dc4dc9631b2"
    with MalwareBazaar(auth_key="k", base_url=base_url) as mb:
        mb.get_certificate(serial)
    assert app.bodies[-1] == f"query=get_certificate&serial_number={serial}".encode()


def _retryable(spec: object) -> bool:
    assert isinstance(spec, RequestSpec)
    return spec.retryable


# One spec per builder that marks itself as a write, keyed by the builder's
# name so the set below can be checked against the source. upload_spec appears
# once for both submissions: MalwareBazaar's upload and YARAify's scan are the
# same builder, differing only in which options it reads.
_WRITES = {
    "_spec_update": _spec_update("h", "add_tag", "exe"),
    "_spec_add_comment": _spec_add_comment("h", "c"),
    "_spec_rescan": _spec_rescan("h"),
    "upload_spec": upload_spec(UploadOptions(), "f", b"x"),
    "_spec_deploy": _spec_deploy(b"x", "f"),
    "_spec_submit_ioc": _spec_submit_ioc("t", "i", "m", ["1.2.3.4"], SubmitIocOptions()),
    "_spec_submit": _spec_submit(0, [{"url": "http://x/"}]),
    "_spec_create_collection": _spec_create_collection("c", None, None),
}


def _builders_that_refuse_retries() -> set[str]:
    """Every function in src that builds a spec marked ``retryable=False``.

    Found rather than trusted: the dict above was complete, but only because
    someone kept it so. A write endpoint added to the library and not to that
    dict is one whose send-once guarantee nothing exercises, and the guarantee
    is the reason the flag exists — a timeout can land after the server has
    already committed, so a retried submission files it twice.
    """
    src = REPO_ROOT / "src"
    found: set[str] = set()
    for path in src.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if any(
                isinstance(inner, ast.keyword)
                and inner.arg == "retryable"
                and isinstance(inner.value, ast.Constant)
                and inner.value.value is False
                for inner in ast.walk(node)
            ):
                found.add(node.name)
    return found


def test_every_builder_that_refuses_retries_is_exercised() -> None:
    """The send-once list is written out; that it is all of them is derived."""
    assert set(_WRITES) == _builders_that_refuse_retries()


def test_only_idempotent_calls_are_retried() -> None:
    """A timeout can land after the server committed, so retrying must be safe.

    ``update`` appends — its documented keys are ``add_tag`` and reference
    links, and the endpoint calls ``value`` "the information you want to add".
    ``rescan_file`` answers ``queued`` with a fresh ``task_id``, so a retry
    leaves a second scan against the caller's quota. Both used to be retried.
    """
    assert not any(_retryable(spec) for spec in _WRITES.values())
    # Reads and idempotent writes stay retryable: a lost response to either is
    # worth another attempt and costs nothing when the first one landed.
    reads = [_spec_get_info("h"), _spec_get_certificate("s"), _spec_download("h")]
    assert all(_retryable(spec) for spec in reads)


# Each row: the client, the write that must be sent once, and a read on the
# same client that must still be retried. URLhaus is here because its writes go
# out over a second transport on another host, which has to honour the flag too.
_RETRY_CASES = [
    pytest.param(
        (
            ThreatFox,
            ("submit_ioc", ("botnet_cc", "ip:port", "Cobalt Strike", ["1.2.3.4:443"])),
            ("search_hash", ("abc",)),
        ),
        id="threatfox submit_ioc",
    ),
    pytest.param(
        (
            Urlhaus,
            ("submit", ([{"url": "http://x/", "threat": "malware_download"}],)),
            ("host", ("x",)),
        ),
        id="urlhaus submit, over the submission transport",
    ),
]


@pytest.mark.parametrize("case", _RETRY_CASES)
def test_a_write_is_sent_once_but_a_read_is_retried(
    base_url: str,
    app: ReplyApp,
    case: tuple[Any, tuple[str, tuple[Any, ...]], tuple[str, tuple[Any, ...]]],
) -> None:
    """A timeout can land after the server committed, so a retried write files it twice."""
    retries = 3
    client_cls, (write, write_args), (read, read_args) = case
    app.reply = (500, b"boom")
    with client_cls(auth_key="k", base_url=base_url, retries=retries) as client:
        with pytest.raises(TransportError):
            getattr(client, write)(*write_args)
        submissions = len(app.bodies)
        app.bodies.clear()
        with pytest.raises(TransportError):
            getattr(client, read)(*read_args)
        reads = len(app.bodies)
    assert submissions == 1
    assert reads == retries + 1  # a read is safe to retry


@pytest.mark.parametrize(
    "secret",
    [
        "SUPERSECRETAUTHKEY123",
        # Characters that path_segment escapes: matching only the raw key
        # walked straight past the percent-encoded form in the URL.
        "SUPER SECRET+KEY/123",
        "ab+cd=ef",
        "a/b?c#d",
    ],
)
def test_auth_key_is_not_echoed_in_errors(secret: str) -> None:
    # URLhaus exports carry the key in the URL path, so a message quoting the
    # URL would print the caller's credential to stderr and into any log.
    with pytest.raises(TransportError) as caught:
        Urlhaus(auth_key=secret, base_url="::bad url::").export("recent.csv")
    message = str(caught.value)
    assert secret not in message
    assert quote(secret, safe="") not in message
    assert "***" in message


@pytest.mark.parametrize(
    ("body", "expected"),
    [(b"", "was empty"), (b'{"query_status":"not_found"}', "not_found")],
)
def test_an_export_that_is_not_a_feed_is_refused(
    base_url: str, app: ReplyApp, body: bytes, expected: str
) -> None:
    # An export answers HTTP 200 either way, so without this a zero-byte file
    # or a JSON error was written out under the feed's name and reported as a
    # successful download — the same trap ensure_download closes for samples.
    app.reply = (200, body)
    with (
        Urlhaus(auth_key="KEY", base_url=base_url) as uh,
        pytest.raises(TransportError, match=expected),
    ):
        uh.export()


async def test_an_async_export_that_is_not_a_feed_is_refused(base_url: str, app: ReplyApp) -> None:
    app.reply = (200, b"")
    async with UrlhausAsync(auth_key="KEY", base_url=base_url) as uh:
        with pytest.raises(TransportError, match="was empty"):
            await uh.export()


@pytest.mark.parametrize("name", ["recent.csv", "a#b.csv", "a?b.csv"])
def test_urlhaus_export_name_reaches_the_server_intact(
    base_url: str, app: ReplyApp, name: str
) -> None:
    with Urlhaus(auth_key="KEY", base_url=base_url) as uh:
        uh.export(name)
    assert app.paths[-1] == f"/v2/files/exports/KEY/{name}"


@pytest.mark.parametrize("name", ["", "   "])
def test_export_needs_a_name(base_url: str, name: str) -> None:
    # An empty segment addresses the exports directory for the key, whose
    # answer would be saved under the name the caller asked to export.
    with (
        Urlhaus(auth_key="KEY", base_url=base_url) as uh,
        pytest.raises(BazaarTIError, match="export name is required"),
    ):
        uh.export(name)


@pytest.mark.parametrize("count", [0, -1])
def test_a_result_count_below_one_is_refused_before_the_request(
    base_url: str, app: ReplyApp, count: int
) -> None:
    # None of the four endpoints answers "fewer than one" with an error: they
    # return their default page, the whole feed, or rows beside a no_result
    # status. So the caller gets records they did not ask for and no sign of it.
    with (
        MalwareBazaar(auth_key="k", base_url=base_url) as mb,
        Urlhaus(auth_key="k", base_url=base_url) as uh,
        ThreatFox(auth_key="k", base_url=base_url) as tf,
        Yaraify(auth_key="k", base_url=base_url) as ya,
    ):
        refused = pytest.raises(BazaarTIError, match="must be 1 or more")
        with refused:
            mb.get_taginfo("exe", count)
        with refused:
            uh.urls_recent(count)
        with refused:
            tf.taginfo("mirai", count)
        with refused:
            ya.get_yara("mirai", count)
    assert app.paths == []


def test_payload_lookup_needs_a_hash(base_url: str) -> None:
    # Neither hash means an empty POST body the endpoint cannot answer.
    with (
        Urlhaus(auth_key="k", base_url=base_url) as uh,
        pytest.raises(BazaarTIError, match="needs md5_hash or sha256_hash"),
    ):
        uh.payload()


@pytest.mark.parametrize("fmt", ["CSV", "xml", "", "json "])
def test_fplist_rejects_an_unsupported_format(base_url: str, fmt: str) -> None:
    # The return type depends on this value, so an unsupported one would fetch
    # something and then fail parsing it as the wrong thing.
    with (
        Hunting(auth_key="k", base_url=base_url) as hu,
        pytest.raises(BazaarTIError, match="Unsupported fplist format"),
    ):
        hu.get_fplist(fmt)


def test_fplist_as_csv_refuses_a_json_error_body(base_url: str, app: ReplyApp) -> None:
    # The CSV format never reaches the JSON decoder, so the auth failure the
    # JSON format raises on was handed back as the list — and redirected to a
    # file, saved as fplist.csv and reported as a success.
    app.reply = (200, b'{"query_status":"unknown_auth_key","data":"The Auth-Key is unknown."}')
    with (
        Hunting(auth_key="k", base_url=base_url) as hu,
        pytest.raises(AuthError, match="Server rejected the Auth-Key"),
    ):
        hu.get_fplist("csv")


@pytest.mark.parametrize("fmt", list(FPLIST_FORMATS))
def test_fplist_accepts_the_documented_formats(base_url: str, fmt: str) -> None:
    with Hunting(auth_key="k", base_url=base_url) as hu:
        assert hu.get_fplist(fmt) is not None


def test_urlhaus_wire_format(base_url: str, app: ReplyApp) -> None:
    """Pin every URL this client builds and every body it posts.

    URLhaus is the one service that encodes arguments into the path, and the
    documented shapes are quoted beside each assertion. Only asserting that the
    calls return leaves the paths free to drift into something the API answers
    with an empty result set rather than an error.
    """
    with Urlhaus(auth_key="KEY", base_url=base_url) as uh:
        uh.urls_recent()
        uh.urls_recent(3)
        uh.payloads_recent(3)
        uh.download("a" * 64)
        uh.export()
        uh.export("recent.json")
    assert app.paths == [
        "/v1/urls/recent/",  # wget .../v1/urls/recent/
        "/v1/urls/recent/limit/3/",  # wget .../v1/urls/recent/limit/3/
        "/v1/payloads/recent/limit/3/",
        f"/v1/download/{'a' * 64}/",  # .../v1/download/<sha256>/
        "/v2/files/exports/KEY/recent.csv",  # curl .../v2/files/exports/<key>/recent.csv
        "/v2/files/exports/KEY/recent.json",
    ]


def test_urlhaus_query_bodies(base_url: str, app: ReplyApp) -> None:
    with Urlhaus(auth_key="k", base_url=base_url) as uh:
        uh.url("http://x/")
        uh.urlid("233833")
        uh.host("vektorex.com")
        uh.payload(md5_hash="m" * 32)
        uh.payload(sha256_hash="s" * 64)
        uh.tag("Retefe")
        uh.signature("Gozi")
    assert [body.decode() for body in app.bodies] == [
        "url=http%3A%2F%2Fx%2F",
        "urlid=233833",  # the documented key is urlid, not id
        "host=vektorex.com",
        f"md5_hash={'m' * 32}",  # only the hash that was given is sent
        f"sha256_hash={'s' * 64}",
        "tag=Retefe",
        "signature=Gozi",
    ]


def test_urlhaus_submission_is_not_anonymous_unless_asked(base_url: str, app: ReplyApp) -> None:
    # anonymous decides whether the reporter's abuse.ch handle is published, so
    # the default has to stay the one the caller would expect.
    #
    # This also pins the base-url override on the second transport that carries
    # submissions: ignoring it would send this run to the live platform instead
    # of the local server, and no body would arrive here at all. Both clients
    # open that transport in one shared hook, so proving it once proves it for
    # the async client too.
    entry = {"url": "http://x/", "threat": "malware_download"}
    with Urlhaus(auth_key="k", base_url=base_url) as uh:
        uh.submit([entry])
        uh.submit([entry], anonymous=1)
    assert json.loads(app.bodies[0]) == {"anonymous": 0, "submission": [entry]}
    assert json.loads(app.bodies[1]) == {"anonymous": 1, "submission": [entry]}


# One row per file-submitting endpoint: the two clients, the method they spell
# it with, an options object, and the json_data those options should produce.
_SUBMISSION_CASES = [
    pytest.param(
        (
            MalwareBazaar,
            MalwareBazaarAsync,
            "upload",
            UploadOptions(anonymous=1, tags=["exe"]),
            {"anonymous": 1, "tags": ["exe"]},
        ),
        id="malwarebazaar upload",
    ),
    pytest.param(
        (
            Yaraify,
            YaraifyAsync,
            "scan_file",
            ScanOptions(share_file=0, unpack=1),
            {"share_file": 0, "unpack": 1},
        ),
        id="yaraify scan_file",
    ),
]


@pytest.mark.parametrize("case", _SUBMISSION_CASES)
async def test_options_default_the_same_way_on_both_clients(
    base_url: str, app: ReplyApp, case: tuple[Any, Any, str, Any, dict[str, Any]]
) -> None:
    """A client that reached for a fresh Options would drop what the caller set.

    Both file-submitting endpoints take the same shape, and both have to behave
    the same way on the sync and the async client. What it costs to get wrong
    differs: an upload loses its tags and references, and a scan loses
    ``share_file=0`` — the opt-out that keeps a submitted sample private, so
    the sample would be published instead.
    """
    sync_cls, async_cls, method, options, sent = case
    with sync_cls(auth_key="k", base_url=base_url) as client:
        getattr(client, method)(b"MZ", "s.exe", options)
        getattr(client, method)(b"MZ", "s.exe")
    sync_with, sync_without = app.bodies[-2], app.bodies[-1]

    async with async_cls(auth_key="k", base_url=base_url) as client:
        await getattr(client, method)(b"MZ", "s.exe", options)
        await getattr(client, method)(b"MZ", "s.exe")
    assert json_data_part(sync_with) == sent
    assert json_data_part(sync_without) == {}
    assert json_data_part(app.bodies[-2]) == json_data_part(sync_with)
    assert json_data_part(app.bodies[-1]) == json_data_part(sync_without)


def test_threatfox_query_bodies(base_url: str, app: ReplyApp) -> None:
    """Pin the JSON these queries post, with and without their optionals.

    The optional fields are dropped when unset by a single ``is not None``
    check; inverted, every query would carry nothing but its nulls.
    """
    with ThreatFox(auth_key="k", base_url=base_url) as tf:
        tf.get_iocs()
        tf.get_iocs(7)
        tf.ioc(41)
        tf.search_ioc("139.180.203.104", exact_match=True)
        tf.search_hash("2151c4b970eff0071948dbbc19066aa4")
        tf.taginfo("Magecart", 10)
        tf.get_label("warzone", "win")
    assert [json.loads(body) for body in app.bodies] == [
        {"query": "get_iocs"},
        {"query": "get_iocs", "days": 7},
        {"query": "ioc", "id": 41},
        {"query": "search_ioc", "search_term": "139.180.203.104", "exact_match": True},
        {"query": "search_hash", "hash": "2151c4b970eff0071948dbbc19066aa4"},
        {"query": "taginfo", "tag": "Magecart", "limit": 10},
        {"query": "get_label", "malware": "warzone", "platform": "win"},
    ]


def test_threatfox_submit_ioc_body(base_url: str, app: ReplyApp) -> None:
    with ThreatFox(auth_key="k", base_url=base_url) as tf:
        tf.submit_ioc("botnet_cc", "domain", "win.zloader", ["evil.tld"])
        tf.submit_ioc(
            "botnet_cc",
            "domain",
            "win.zloader",
            ["evil.tld"],
            SubmitIocOptions(75, True, "https://x/1", ["TA505"], "very evil", 1),
        )
    bare, full = (json.loads(body) for body in app.bodies)
    assert bare == {
        "query": "submit_ioc",
        "threat_type": "botnet_cc",
        "ioc_type": "domain",
        "malware": "win.zloader",
        "iocs": ["evil.tld"],
    }
    assert full == bare | {
        "confidence_level": 75,
        "is_compromised": True,
        "reference": "https://x/1",
        "tags": ["TA505"],
        "comment": "very evil",
        "anonymous": 1,
    }


def test_yaraify_query_bodies(base_url: str, app: ReplyApp) -> None:
    with Yaraify(auth_key="k", base_url=base_url) as ya:
        ya.generate_identifier()
        ya.list_tasks("xxxxxxxx")
        ya.list_tasks("xxxxxxxx", "processed")
        ya.get_results("fb2763e9")
        ya.get_results("fb2763e9", "MALPEDIA")
        ya.lookup_hash("b0bb095d")
        ya.lookup_hash("b0bb095d", "MALPEDIA")
        ya.get_yara("MALWARE_Win_Neshta")
        ya.get_yara("MALWARE_Win_Neshta", 50)
        ya.rescan_file("3cf9260a")
        ya.delete_yara_rule("bcbf6764")
        ya.get_yara_rule("1b95ce79")
    assert [json.loads(body) for body in app.bodies] == [
        {"query": "generate_identifier"},
        {"query": "list_tasks", "identifier": "xxxxxxxx"},
        {"query": "list_tasks", "identifier": "xxxxxxxx", "task_status": "processed"},
        {"query": "get_results", "task_id": "fb2763e9"},
        # The documented key is hyphenated, which no keyword argument can spell.
        {"query": "get_results", "task_id": "fb2763e9", "malpedia-token": "MALPEDIA"},
        {"query": "lookup_hash", "search_term": "b0bb095d"},
        {"query": "lookup_hash", "search_term": "b0bb095d", "malpedia-token": "MALPEDIA"},
        {"query": "get_yara", "search_term": "MALWARE_Win_Neshta"},
        {"query": "get_yara", "search_term": "MALWARE_Win_Neshta", "result_max": 50},
        {"query": "rescan_file", "hash": "3cf9260a"},
        {"query": "delete_yara_rule", "yarahub_uuid": "bcbf6764"},
        {"query": "get_yara_rule", "uuid": "1b95ce79"},
    ]


def test_hunting_bodies(base_url: str, app: ReplyApp) -> None:
    with Hunting(auth_key="k", base_url=base_url) as hu:
        hu.get_fplist()
        hu.get_fplist("csv")
        hu.create_collection("test1234")
        hu.create_collection("test1234", "This is just a test!", 0)
    assert [json.loads(body) for body in app.bodies] == [
        {"query": "get_fplist", "format": "json"},
        {"query": "get_fplist", "format": "csv"},
        {"query": "create_collection", "collection_name": "test1234"},
        {
            "query": "create_collection",
            "collection_name": "test1234",
            "description": "This is just a test!",
            # anonymous=0 is a real choice, not an absent one, so it has to
            # survive the filter that drops unset options.
            "anonymous": 0,
        },
    ]


async def test_async_submissions_keep_the_defaults_the_sync_ones_are_held_to(
    base_url: str, app: ReplyApp
) -> None:
    """The async half of two submission defaults had nothing holding it.

    UrlhausAsync.submit defaults anonymous to 0, and ThreatFoxAsync.submit_ioc
    reaches for a fresh SubmitIocOptions only when the caller passed none. Both
    are pinned on the sync clients; the async tests passed values explicitly and
    never read the body back, so anonymous could default to 1 — publishing the
    reporter's abuse.ch handle — and submit_ioc could drop everything the caller
    set, with the suite still green.
    """
    entry = {"url": "http://x/", "threat": "malware_download"}
    options = SubmitIocOptions(confidence_level=75, tags=["TA505"], anonymous=1)

    async with UrlhausAsync(auth_key="k", base_url=base_url) as uh:
        await uh.submit([entry])
    async with ThreatFoxAsync(auth_key="k", base_url=base_url) as tf:
        await tf.submit_ioc("botnet_cc", "domain", "win.z", ["evil.tld"], options)
    submitted, ioc = (json.loads(body) for body in app.bodies[-2:])
    assert submitted == {"anonymous": 0, "submission": [entry]}
    assert {k: ioc[k] for k in ("confidence_level", "tags", "anonymous")} == {
        "confidence_level": options.confidence_level,
        "tags": options.tags,
        "anonymous": options.anonymous,
    }
