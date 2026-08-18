"""Live integration tests against the real abuse.ch API (require a token)."""

from __future__ import annotations

import pytest

from bazaar_ti import Hunting, MalwareBazaar, ThreatFox, Urlhaus, Yaraify, download_batch
from bazaar_ti.datalake import MALWAREBAZAAR
from tests.conftest import KNOWN_SHA256

pytestmark = pytest.mark.live


def test_datalake_live(live_key: str) -> None:
    # The datalake needs no Auth-Key, but a configured key is what opts this
    # module in to real network access; without the fixture this test ran on
    # every plain `pytest`, downloading an archive from abuse.ch in CI.
    del live_key
    data = download_batch(MALWAREBAZAAR, "daily", "2020-02-24.zip")
    assert data[:2] == b"PK"


def test_malwarebazaar_live(live_key: str) -> None:
    with MalwareBazaar(auth_key=live_key) as mb:
        assert mb.get_info(KNOWN_SHA256)["query_status"] == "ok"
        assert isinstance(mb.download(KNOWN_SHA256), bytes)


def test_threatfox_live(live_key: str) -> None:
    with ThreatFox(auth_key=live_key) as tf:
        assert tf.types()["query_status"] == "ok"


def test_urlhaus_live(live_key: str) -> None:
    with Urlhaus(auth_key=live_key) as uh:
        assert uh.urls_recent(3)["query_status"] == "ok"


def test_yaraify_live(live_key: str) -> None:
    with Yaraify(auth_key=live_key) as ya:
        assert ya.recent_yararules()["query_status"] == "ok"


def test_hunting_live(live_key: str) -> None:
    """The false-positive list, checked by the shape only a real one has.

    The four tests above assert ``query_status == "ok"``. This one cannot: a
    successful fplist is entries keyed by entry id with no status field beside
    them, which is the whole reason ``formats._records`` treats "nothing but
    mappings" as the marker of this shape.

    So it asserted the type instead — and every error abuse.ch returns is a
    dict too. Run against a key Hunting rejects, ``get_fplist`` answers
    ``{"query_status": "unknown_auth_key", ...}`` and the old assertion passed
    on it: the one live test that could not fail for the most likely reason a
    live test fails. The absence of the field is the discriminator, so that is
    what this checks, and it pins the assumption the SARIF unwrapper is built
    on at the same time.
    """
    with Hunting(auth_key=live_key) as hu:
        fplist = hu.get_fplist()
    assert isinstance(fplist, dict)
    assert "query_status" not in fplist, f"not a false-positive list: {fplist}"
    assert fplist, "the false-positive list came back empty"
