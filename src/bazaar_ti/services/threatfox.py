"""ThreatFox client (https://threatfox.abuse.ch/api/)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..core.config import THREATFOX_URL
from ..core.errors import BazaarTIError
from ..core.transport import RequestSpec
from .base import AsyncService, SyncService, result_count, set_options
from .base import json_query as _q


@dataclass(frozen=True, slots=True)
class SubmitIocOptions:
    """Optional parameters for a ThreatFox IOC submission."""

    confidence_level: int | None = None
    is_compromised: bool | None = None
    reference: str | None = None
    tags: list[str] | None = None
    comment: str | None = None
    anonymous: int | None = None


def _spec_limited(query: str, field: str, value: str, limit: int | None) -> RequestSpec:
    """The two calls that take a result count, which is refused below one."""
    fields: dict[str, Any] = {field: value, "limit": result_count("limit", limit)}
    return _q(query, **fields)


def _spec_submit_ioc(
    threat_type: str,
    ioc_type: str,
    malware: str,
    iocs: list[str],
    options: SubmitIocOptions,
) -> RequestSpec:
    """Build the submission, refusing one that carries no IOC.

    An empty list is a write the endpoint cannot honour, and submissions are
    not retryable, so sending it spends the one attempt there is on nothing.
    """
    if not iocs:
        raise BazaarTIError("Submitting to ThreatFox needs at least one IOC value.")
    return _q(
        "submit_ioc",
        threat_type=threat_type,
        ioc_type=ioc_type,
        malware=malware,
        iocs=iocs,
        retryable=False,
        **set_options(options),
    )


class ThreatFoxAsync(AsyncService):
    """Async ThreatFox client."""

    base_url = THREATFOX_URL

    async def get_iocs(self, days: int | None = None) -> dict[str, Any]:
        return await self._t.request_json(_q("get_iocs", days=days))

    async def ioc(self, ioc_id: int) -> dict[str, Any]:
        return await self._t.request_json(_q("ioc", id=ioc_id))

    async def search_ioc(self, search_term: str, exact_match: bool | None = None) -> dict[str, Any]:
        return await self._t.request_json(
            _q("search_ioc", search_term=search_term, exact_match=exact_match)
        )

    async def search_hash(self, file_hash: str) -> dict[str, Any]:
        return await self._t.request_json(_q("search_hash", hash=file_hash))

    async def taginfo(self, tag: str, limit: int | None = None) -> dict[str, Any]:
        return await self._t.request_json(_spec_limited("taginfo", "tag", tag, limit))

    async def malwareinfo(self, malware: str, limit: int | None = None) -> dict[str, Any]:
        return await self._t.request_json(_spec_limited("malwareinfo", "malware", malware, limit))

    async def get_label(self, malware: str, platform: str | None = None) -> dict[str, Any]:
        return await self._t.request_json(_q("get_label", malware=malware, platform=platform))

    async def malware_list(self) -> dict[str, Any]:
        return await self._t.request_json(_q("malware_list"))

    async def types(self) -> dict[str, Any]:
        return await self._t.request_json(_q("types"))

    async def tag_list(self) -> dict[str, Any]:
        return await self._t.request_json(_q("tag_list"))

    async def submit_ioc(
        self,
        threat_type: str,
        ioc_type: str,
        malware: str,
        iocs: list[str],
        options: SubmitIocOptions | None = None,
    ) -> dict[str, Any]:
        spec = _spec_submit_ioc(threat_type, ioc_type, malware, iocs, options or SubmitIocOptions())
        return await self._t.request_json(spec)


class ThreatFox(SyncService):
    """Synchronous ThreatFox client."""

    base_url = THREATFOX_URL

    def get_iocs(self, days: int | None = None) -> dict[str, Any]:
        return self._t.request_json_sync(_q("get_iocs", days=days))

    def ioc(self, ioc_id: int) -> dict[str, Any]:
        return self._t.request_json_sync(_q("ioc", id=ioc_id))

    def search_ioc(self, search_term: str, exact_match: bool | None = None) -> dict[str, Any]:
        return self._t.request_json_sync(
            _q("search_ioc", search_term=search_term, exact_match=exact_match)
        )

    def search_hash(self, file_hash: str) -> dict[str, Any]:
        return self._t.request_json_sync(_q("search_hash", hash=file_hash))

    def taginfo(self, tag: str, limit: int | None = None) -> dict[str, Any]:
        return self._t.request_json_sync(_spec_limited("taginfo", "tag", tag, limit))

    def malwareinfo(self, malware: str, limit: int | None = None) -> dict[str, Any]:
        return self._t.request_json_sync(_spec_limited("malwareinfo", "malware", malware, limit))

    def get_label(self, malware: str, platform: str | None = None) -> dict[str, Any]:
        return self._t.request_json_sync(_q("get_label", malware=malware, platform=platform))

    def malware_list(self) -> dict[str, Any]:
        return self._t.request_json_sync(_q("malware_list"))

    def types(self) -> dict[str, Any]:
        return self._t.request_json_sync(_q("types"))

    def tag_list(self) -> dict[str, Any]:
        return self._t.request_json_sync(_q("tag_list"))

    def submit_ioc(
        self,
        threat_type: str,
        ioc_type: str,
        malware: str,
        iocs: list[str],
        options: SubmitIocOptions | None = None,
    ) -> dict[str, Any]:
        spec = _spec_submit_ioc(threat_type, ioc_type, malware, iocs, options or SubmitIocOptions())
        return self._t.request_json_sync(spec)
