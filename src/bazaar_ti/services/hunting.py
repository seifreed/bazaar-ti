"""Hunting API client (https://hunting.abuse.ch/api/)."""

from __future__ import annotations

from typing import Any

from ..core.config import HUNTING_URL
from ..core.errors import BazaarTIError
from ..core.response import ensure_not_an_error
from ..core.transport import RequestSpec
from .base import AsyncService, SyncService
from .base import json_query as _q

FPLIST_FORMATS = ("json", "csv")


def _spec_get_fplist(fmt: str) -> RequestSpec:
    """Build the request, refusing a format the endpoint does not serve.

    The return type depends on this value, so an unsupported one would fetch
    something and then fail while parsing it as the wrong thing.
    """
    if fmt not in FPLIST_FORMATS:
        raise BazaarTIError(f"Unsupported fplist format {fmt!r}; expected json or csv.")
    return _q("get_fplist", format=fmt)


def _spec_create_collection(
    collection_name: str,
    description: str | None,
    anonymous: int | None,
) -> RequestSpec:
    """Create a collection — which is a write, so never retry it."""
    return _q(
        "create_collection",
        collection_name=collection_name,
        description=description,
        anonymous=anonymous,
        retryable=False,
    )


class HuntingAsync(AsyncService):
    """Async Hunting API client."""

    base_url = HUNTING_URL

    async def get_fplist(self, fmt: str = "json") -> dict[str, Any] | str:
        spec = _spec_get_fplist(fmt)
        if fmt == "csv":
            return ensure_not_an_error(await self._t.request_text(spec))
        return await self._t.request_json(spec)

    async def create_collection(
        self,
        collection_name: str,
        description: str | None = None,
        anonymous: int | None = None,
    ) -> dict[str, Any]:
        return await self._t.request_json(
            _spec_create_collection(collection_name, description, anonymous)
        )


class Hunting(SyncService):
    """Synchronous Hunting API client."""

    base_url = HUNTING_URL

    def get_fplist(self, fmt: str = "json") -> dict[str, Any] | str:
        spec = _spec_get_fplist(fmt)
        if fmt == "csv":
            return ensure_not_an_error(self._t.request_text_sync(spec))
        return self._t.request_json_sync(spec)

    def create_collection(
        self,
        collection_name: str,
        description: str | None = None,
        anonymous: int | None = None,
    ) -> dict[str, Any]:
        return self._t.request_json_sync(
            _spec_create_collection(collection_name, description, anonymous)
        )
