"""Core building blocks shared by every abuse.ch service client."""

from __future__ import annotations

from .batch import gather_async, threaded_map
from .config import resolve_auth_key
from .errors import AuthError, BazaarTIError, RateLimitError, TransportError
from .transport import RequestSpec, Transport

__all__ = [
    "AuthError",
    "BazaarTIError",
    "RateLimitError",
    "RequestSpec",
    "Transport",
    "TransportError",
    "gather_async",
    "resolve_auth_key",
    "threaded_map",
]
