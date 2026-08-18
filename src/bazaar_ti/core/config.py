"""Auth-key resolution, base URLs, and shared defaults."""

from __future__ import annotations

import os
import sys
import tomllib
from collections.abc import Mapping
from pathlib import Path

from .._version import PROJECT_URL, __version__
from .errors import AuthError

ENV_AUTH_KEY = "BAZAAR_TI_AUTH_KEY"

USER_AGENT = f"bazaar-ti/{__version__} (+{PROJECT_URL})"
"""How this client names itself to abuse.ch.

Left unset, httpx sends its own default and every bazaar-ti user looks like
anonymous ``python-httpx`` traffic. abuse.ch runs a Fair Use Policy and rate
limits accounts with unusual query volumes, so being identifiable is the
difference between an operator who can see what a client is and attribute it,
and one whose only option is to throttle it.
"""

DEFAULT_TIMEOUT = 30.0
DEFAULT_RETRIES = 2

MAX_RETRIES = 10
"""Most retries a single call will make.

Each one waits, so the count bounds how long a failing call can take: capping
the backoff alone still lets ``--retries 100000`` sit there for weeks. Ten
attempts spend under three minutes sleeping, and abuse.ch is not coming back
within one call if it has not by then.
"""

MALWAREBAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"
URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/"
URLHAUS_SUBMIT_URL = "https://urlhaus.abuse.ch/api/"
THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
YARAIFY_URL = "https://yaraify-api.abuse.ch/api/v1/"
HUNTING_URL = "https://hunting-api.abuse.ch/api/v1/"

DATALAKE_URL = "https://datalake.abuse.ch/"


def _config_root(platform: str, environ: Mapping[str, str]) -> Path:
    if platform == "win32":
        base = environ.get("APPDATA")
        return Path(base) if base else Path.home() / "AppData" / "Roaming"
    base = environ.get("XDG_CONFIG_HOME")
    return Path(base) if base else Path.home() / ".config"


def default_config_path() -> Path:
    """Return the OS-appropriate config file path (no third-party deps)."""
    return _config_root(sys.platform, os.environ) / "bazaar-ti" / "config.toml"


def _key_from_config(config_path: Path) -> str | None:
    if not config_path.is_file():
        return None
    # "utf-8-sig" drops the BOM that Windows editors prepend by default and is
    # identical to "utf-8" for files without one.
    try:
        data = tomllib.loads(config_path.read_text(encoding="utf-8-sig"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise AuthError(f"Config file {config_path} is not valid UTF-8 TOML: {exc}") from exc
    section = data.get("auth")
    if isinstance(section, dict):
        value = section.get("key")
        if isinstance(value, str) and value:
            return value
        if value is not None:
            # Otherwise the caller is told to "add [auth] key" to a file where
            # they already did, and goes looking anywhere but at the value.
            # An unquoted key that happens to be all digits is a TOML integer.
            raise AuthError(f"[auth] key in {config_path} must be a non-empty, quoted string.")
    return None


def _usable_key(key: str, source: str) -> str:
    """Normalize a key and reject one that cannot be an HTTP header value.

    A trailing newline survives some ways of loading a key, and httpx then
    rejects the header as an illegal value — which the transport reads as a
    transient failure, so it retries a deterministic error and quotes the key
    back in the message. A non-ASCII key raises UnicodeEncodeError, which the
    CLI does not catch at all. The key itself is never echoed here.
    """
    key = key.strip()
    if not key:
        raise AuthError(f"The Auth-Key from {source} is blank.")
    if not key.isascii() or any(char < " " or char == "\x7f" for char in key):
        raise AuthError(
            f"The Auth-Key from {source} contains characters that cannot be sent "
            "in an HTTP header; expected printable ASCII."
        )
    return key


def resolve_auth_key(
    explicit: str | None = None,
    config_path: Path | None = None,
) -> str:
    """Resolve the Auth-Key: explicit argument, then env var, then config file.

    Raises :class:`AuthError` when no key can be found or it is unusable.
    """
    if explicit:
        return _usable_key(explicit, "the auth_key argument")
    env_value = os.environ.get(ENV_AUTH_KEY)
    if env_value:
        return _usable_key(env_value, f"${ENV_AUTH_KEY}")
    path = config_path if config_path is not None else default_config_path()
    from_file = _key_from_config(path)
    if from_file:
        return _usable_key(from_file, str(path))
    raise AuthError(
        "No Auth-Key provided. Pass one explicitly, set "
        f"${ENV_AUTH_KEY}, or add [auth] key = ... to {path}."
    )
