"""Exception hierarchy shared by every abuse.ch service client."""

from __future__ import annotations


class BazaarTIError(Exception):
    """Base class for every error raised by this library."""


class AuthError(BazaarTIError):
    """The Auth-Key is missing, invalid, or rejected by the server."""


class RateLimitError(BazaarTIError):
    """The server answered with HTTP 429 (too many requests)."""


class TransportError(BazaarTIError):
    """A network failure, timeout, unexpected HTTP status, or malformed body."""
