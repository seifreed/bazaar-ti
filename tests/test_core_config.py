"""Tests for auth-key and config-path resolution."""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from bazaar_ti.core.config import (
    ENV_AUTH_KEY,
    _config_root,
    default_config_path,
    resolve_auth_key,
)
from bazaar_ti.core.errors import AuthError
from bazaar_ti.services.malwarebazaar import MalwareBazaar


@pytest.fixture
def clean_env() -> Iterator[None]:
    saved = os.environ.pop(ENV_AUTH_KEY, None)
    try:
        yield
    finally:
        if saved is not None:
            os.environ[ENV_AUTH_KEY] = saved


def test_explicit_key_wins(clean_env: None) -> None:
    assert resolve_auth_key("explicit") == "explicit"


@pytest.mark.parametrize(
    "content",
    [
        pytest.param(b"[other]\nx = 1\n", id="no [auth] section"),
        pytest.param(b"[auth]\nother = 1\n", id="[auth] without a key"),
        pytest.param(b"this is [ not valid = = =\n", id="not valid TOML at all"),
        # Undecodable bytes have to surface as AuthError too, not as an escaping
        # UnicodeDecodeError, which is a ValueError the CLI does not catch.
        pytest.param(b'[auth]\nkey = "\xff\xfe\x00"\n', id="not valid UTF-8"),
    ],
)
def test_config_file_without_a_usable_key_is_refused(
    clean_env: None, tmp_path: Path, content: bytes
) -> None:
    cfg = tmp_path / "config.toml"
    cfg.write_bytes(content)
    with pytest.raises(AuthError):
        resolve_auth_key(config_path=cfg)


def test_config_file_absent(clean_env: None, tmp_path: Path) -> None:
    with pytest.raises(AuthError):
        resolve_auth_key(config_path=tmp_path / "nope.toml")


def test_config_file_with_utf8_bom(clean_env: None, tmp_path: Path) -> None:
    # Windows editors default to UTF-8-with-BOM; tomllib rejects the BOM.
    cfg = tmp_path / "config.toml"
    cfg.write_bytes('[auth]\nkey = "from-bom-file"\n'.encode("utf-8-sig"))
    assert resolve_auth_key(config_path=cfg) == "from-bom-file"


@pytest.mark.parametrize("line", ["key = 123", "key = true", 'key = ""', "key = [1]"])
def test_config_file_key_that_is_not_a_string(clean_env: None, tmp_path: Path, line: str) -> None:
    # An unquoted all-digit key is a TOML integer, and the caller used to be
    # told to "add [auth] key" to the very file where they already had.
    cfg = tmp_path / "config.toml"
    cfg.write_text(f"[auth]\n{line}\n", encoding="utf-8")
    with pytest.raises(AuthError, match="must be a non-empty, quoted string"):
        resolve_auth_key(config_path=cfg)


@pytest.mark.parametrize("raw", ["  key123  ", "key123\n", "\tkey123\r\n"])
def test_surrounding_whitespace_is_stripped(clean_env: None, raw: str) -> None:
    # A trailing newline survives some ways of loading a key and then reaches
    # httpx as an illegal header value, which the transport retried as if it
    # were a transient network failure.
    assert resolve_auth_key(raw) == "key123"


@pytest.mark.parametrize("raw", ["ab\ncd", "ab\tcd", "abcü123", "ab\x00cd", "ab\x7fcd"])
def test_unusable_key_is_rejected_without_echoing_it(clean_env: None, raw: str) -> None:
    with pytest.raises(AuthError) as caught:
        resolve_auth_key(raw)
    assert raw not in str(caught.value)


def test_blank_key_is_rejected(clean_env: None) -> None:
    with pytest.raises(AuthError, match="blank"):
        resolve_auth_key("   ")


def test_key_from_env_and_file_are_validated(clean_env: None, tmp_path: Path) -> None:
    """The two indirect sources, each resolved and each put through _usable_key.

    A plain key from each had a test of its own as well, and neither could fail
    without this one failing first: stripping a key that needs no stripping is
    the same call on the same path, so they said this twice with less.
    """
    os.environ[ENV_AUTH_KEY] = "  from-env\n"
    try:
        assert resolve_auth_key() == "from-env"
    finally:
        del os.environ[ENV_AUTH_KEY]
    cfg = tmp_path / "config.toml"
    cfg.write_text('[auth]\nkey = " from-file "\n', encoding="utf-8")
    assert resolve_auth_key(config_path=cfg) == "from-file"


def test_config_root_variants() -> None:
    assert _config_root("win32", {"APPDATA": "/appdata"}) == Path("/appdata")
    assert _config_root("win32", {}).parts[-2:] == ("AppData", "Roaming")
    assert _config_root("linux", {"XDG_CONFIG_HOME": "/xdg"}) == Path("/xdg")
    assert _config_root("linux", {}).name == ".config"


def test_default_config_path() -> None:
    path = default_config_path()
    assert path.name == "config.toml"
    # The directory is half the address, and the half a caller has already
    # created by hand: dropping it points the client at ~/.config/config.toml,
    # where nobody's key lives, and the error tells them to add one to a file
    # they wrote months ago.
    assert path.parent.name == "bazaar-ti"


def test_a_client_resolves_its_key_rather_than_taking_what_it_is_handed(
    clean_env: None, tmp_path: Path
) -> None:
    """Every other test passes auth_key="k", so nothing watched the lookup.

    A client built without one has to go to the environment and then to the
    config file, and refuse to be built when neither has it — which is the
    error the CLI prints when a first-time user runs a command. Handed the
    argument straight through instead, the client is built with an empty key
    and the refusal arrives from the server much later, as an auth failure.
    """
    with pytest.raises(AuthError, match="No Auth-Key provided"):
        MalwareBazaar(config_path=tmp_path / "absent.toml")
    os.environ[ENV_AUTH_KEY] = "from-the-environment"
    try:
        with MalwareBazaar(config_path=tmp_path / "absent.toml") as mb:
            assert mb._key == "from-the-environment"
    finally:
        del os.environ[ENV_AUTH_KEY]
