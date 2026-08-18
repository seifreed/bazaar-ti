"""URLhaus client: bulk-query API, submission API, and feed exports."""

from __future__ import annotations

from typing import Any

from ..core.config import URLHAUS_API_URL, URLHAUS_SUBMIT_URL
from ..core.errors import BazaarTIError
from ..core.transport import RequestSpec, Transport, path_segment
from .base import AsyncService, SyncService, _ServiceBase, drop_unset, result_count


def _recent_path(kind: str, limit: int | None) -> str:
    if limit is not None:
        return f"v1/{kind}/recent/limit/{result_count('limit', limit)}/"
    return f"v1/{kind}/recent/"


def _spec_recent(kind: str, limit: int | None) -> RequestSpec:
    return RequestSpec(method="GET", path=_recent_path(kind, limit))


def _post_form(path: str, **fields: Any) -> RequestSpec:
    """URLhaus selects the endpoint by path rather than by a ``query`` field."""
    return RequestSpec(method="POST", path=path, encoding="form", data=drop_unset(fields))


def _spec_payload(md5_hash: str | None, sha256_hash: str | None) -> RequestSpec:
    """The endpoint takes one hash or the other; neither means an empty POST."""
    if not (md5_hash or sha256_hash):
        raise BazaarTIError("Looking up a payload needs md5_hash or sha256_hash.")
    return _post_form("v1/payload/", md5_hash=md5_hash, sha256_hash=sha256_hash)


def _spec_download(sha256_hash: str) -> RequestSpec:
    return RequestSpec(method="GET", path=f"v1/download/{path_segment(sha256_hash)}/")


def _export_path(key: str, name: str) -> str:
    """Build the export path, refusing a name that addresses the directory.

    An empty segment collapses the path onto the exports directory for this
    key, which is a different request than the caller made and whose answer
    would be written out under the name they asked to save.
    """
    if not name.strip():
        raise BazaarTIError("An export name is required (got an empty one).")
    return f"v2/files/exports/{path_segment(key)}/{path_segment(name)}"


def _spec_submit(anonymous: int, submission: list[dict[str, Any]]) -> RequestSpec:
    return RequestSpec(
        encoding="json",
        data={"anonymous": anonymous, "submission": submission},
        retryable=False,
    )


class _UrlhausBase(_ServiceBase):
    """Opens the second transport URLhaus submissions need.

    Queries and submissions live on different hosts, so this client is the one
    that owns two transports. The async and sync halves differ only in how they
    close them, so the opening is here rather than written out twice.
    """

    base_url = URLHAUS_API_URL

    def _open_extra_transports(self, base_url: str | None, *, timeout: float, retries: int) -> None:
        # Submissions live on a different host, unless the caller pointed the
        # client at a mirror or test server, which serves both.
        self._submit_t = Transport(
            base_url or URLHAUS_SUBMIT_URL, self._key, timeout=timeout, retries=retries
        )


class UrlhausAsync(_UrlhausBase, AsyncService):
    """Async URLhaus client (query + submission + exports)."""

    async def aclose(self) -> None:
        await super().aclose()
        await self._submit_t.aclose()

    async def urls_recent(self, limit: int | None = None) -> dict[str, Any]:
        return await self._t.request_json(_spec_recent("urls", limit))

    async def payloads_recent(self, limit: int | None = None) -> dict[str, Any]:
        return await self._t.request_json(_spec_recent("payloads", limit))

    async def url(self, url: str) -> dict[str, Any]:
        return await self._t.request_json(_post_form("v1/url/", url=url))

    async def urlid(self, url_id: str) -> dict[str, Any]:
        return await self._t.request_json(_post_form("v1/urlid/", urlid=url_id))

    async def host(self, host: str) -> dict[str, Any]:
        return await self._t.request_json(_post_form("v1/host/", host=host))

    async def payload(
        self, md5_hash: str | None = None, sha256_hash: str | None = None
    ) -> dict[str, Any]:
        return await self._t.request_json(_spec_payload(md5_hash, sha256_hash))

    async def tag(self, tag: str) -> dict[str, Any]:
        return await self._t.request_json(_post_form("v1/tag/", tag=tag))

    async def signature(self, signature: str) -> dict[str, Any]:
        return await self._t.request_json(_post_form("v1/signature/", signature=signature))

    async def download(self, sha256_hash: str) -> bytes:
        return await self._t.request_download(_spec_download(sha256_hash))

    async def export(self, name: str = "recent.csv") -> bytes:
        spec = RequestSpec(method="GET", path=_export_path(self._key, name))
        return await self._t.request_download(spec)

    async def submit(self, submission: list[dict[str, Any]], anonymous: int = 0) -> str:
        return await self._submit_t.request_text(_spec_submit(anonymous, submission))


class Urlhaus(_UrlhausBase, SyncService):
    """Synchronous URLhaus client (query + submission + exports)."""

    def close(self) -> None:
        super().close()
        self._submit_t.close()

    def urls_recent(self, limit: int | None = None) -> dict[str, Any]:
        return self._t.request_json_sync(_spec_recent("urls", limit))

    def payloads_recent(self, limit: int | None = None) -> dict[str, Any]:
        return self._t.request_json_sync(_spec_recent("payloads", limit))

    def url(self, url: str) -> dict[str, Any]:
        return self._t.request_json_sync(_post_form("v1/url/", url=url))

    def urlid(self, url_id: str) -> dict[str, Any]:
        return self._t.request_json_sync(_post_form("v1/urlid/", urlid=url_id))

    def host(self, host: str) -> dict[str, Any]:
        return self._t.request_json_sync(_post_form("v1/host/", host=host))

    def payload(
        self, md5_hash: str | None = None, sha256_hash: str | None = None
    ) -> dict[str, Any]:
        return self._t.request_json_sync(_spec_payload(md5_hash, sha256_hash))

    def tag(self, tag: str) -> dict[str, Any]:
        return self._t.request_json_sync(_post_form("v1/tag/", tag=tag))

    def signature(self, signature: str) -> dict[str, Any]:
        return self._t.request_json_sync(_post_form("v1/signature/", signature=signature))

    def download(self, sha256_hash: str) -> bytes:
        return self._t.request_download_sync(_spec_download(sha256_hash))

    def export(self, name: str = "recent.csv") -> bytes:
        spec = RequestSpec(method="GET", path=_export_path(self._key, name))
        return self._t.request_download_sync(spec)

    def submit(self, submission: list[dict[str, Any]], anonymous: int = 0) -> str:
        return self._submit_t.request_text_sync(_spec_submit(anonymous, submission))
