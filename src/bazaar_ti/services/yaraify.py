"""YARAify client (https://yaraify.abuse.ch/api/)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..core.config import YARAIFY_URL
from ..core.transport import RequestSpec, file_part
from .base import AsyncService, SyncService, result_count, upload_spec
from .base import json_query as _q


@dataclass(frozen=True, slots=True)
class ScanOptions:
    """Optional parameters for a YARAify file scan."""

    identifier: str | None = None
    clamav_scan: int | None = None
    unpack: int | None = None
    share_file: int | None = None
    skip_known: int | None = None
    skip_noisy: int | None = None


def _spec_search(query: str, search_term: str, result_max: int | None) -> RequestSpec:
    return _q(query, search_term=search_term, result_max=result_count("result_max", result_max))


def _spec_with_token(query: str, field: str, value: str, malpedia_token: str | None) -> RequestSpec:
    """Build the two calls that accept a Malpedia token, which ``_q`` cannot.

    The endpoint spells it ``malpedia-token``, and a hyphen is not a Python
    identifier, so it cannot ride along as a keyword argument. ``lookup_hash``
    and ``get_results`` differ only in the query name and the field carrying
    the thing being looked up.
    """
    data: dict[str, Any] = {"query": query, field: value}
    if malpedia_token is not None:
        data["malpedia-token"] = malpedia_token
    return RequestSpec(encoding="json", data=data)


def _spec_rescan(file_hash: str) -> RequestSpec:
    """Trigger a rescan — which queues a task, so never retry it.

    The endpoint answers ``query_status: queued`` with a fresh ``task_id``, so
    a timeout landing after the server committed would leave a second scan
    queued against the caller's quota and no way to tell which task is which.
    """
    return _q("rescan_file", hash=file_hash, retryable=False)


def _spec_download(query: str, sha256_hash: str) -> RequestSpec:
    return _q(query, sha256_hash=sha256_hash)


def _spec_deploy(rule_content: bytes, filename: str) -> RequestSpec:
    """Upload a rule as the endpoint documents it: a lone ``yara_file`` part.

    Like the scan endpoint, this one is selected by which file part it gets,
    not by a ``query`` field — and ``deploy_yara_rule`` is not among the query
    values the API accepts, so sending it named a selector that does not exist.
    """
    return RequestSpec(
        encoding="multipart",
        files={"yara_file": file_part(filename, rule_content)},
        retryable=False,
    )


class YaraifyAsync(AsyncService):
    """Async YARAify client."""

    base_url = YARAIFY_URL

    async def generate_identifier(self) -> dict[str, Any]:
        return await self._t.request_json(_q("generate_identifier"))

    async def list_tasks(self, identifier: str, task_status: str | None = None) -> dict[str, Any]:
        return await self._t.request_json(
            _q("list_tasks", identifier=identifier, task_status=task_status)
        )

    async def get_results(self, task_id: str, malpedia_token: str | None = None) -> dict[str, Any]:
        return await self._t.request_json(
            _spec_with_token("get_results", "task_id", task_id, malpedia_token)
        )

    async def lookup_hash(
        self, search_term: str, malpedia_token: str | None = None
    ) -> dict[str, Any]:
        return await self._t.request_json(
            _spec_with_token("lookup_hash", "search_term", search_term, malpedia_token)
        )

    async def get_yara(self, search_term: str, result_max: int | None = None) -> dict[str, Any]:
        return await self._t.request_json(_spec_search("get_yara", search_term, result_max))

    async def get_clamav(self, search_term: str, result_max: int | None = None) -> dict[str, Any]:
        return await self._t.request_json(_spec_search("get_clamav", search_term, result_max))

    async def get_imphash(self, search_term: str, result_max: int | None = None) -> dict[str, Any]:
        return await self._t.request_json(_spec_search("get_imphash", search_term, result_max))

    async def get_tlsh(self, search_term: str, result_max: int | None = None) -> dict[str, Any]:
        return await self._t.request_json(_spec_search("get_tlsh", search_term, result_max))

    async def get_telfhash(self, search_term: str, result_max: int | None = None) -> dict[str, Any]:
        return await self._t.request_json(_spec_search("get_telfhash", search_term, result_max))

    async def get_gimphash(self, search_term: str, result_max: int | None = None) -> dict[str, Any]:
        return await self._t.request_json(_spec_search("get_gimphash", search_term, result_max))

    async def get_dhash_icon(
        self, search_term: str, result_max: int | None = None
    ) -> dict[str, Any]:
        return await self._t.request_json(_spec_search("get_dhash_icon", search_term, result_max))

    async def rescan_file(self, file_hash: str) -> dict[str, Any]:
        return await self._t.request_json(_spec_rescan(file_hash))

    async def recent_yararules(self) -> dict[str, Any]:
        return await self._t.request_json(_q("recent_yararules"))

    async def show_deployed_yara_rules(self) -> dict[str, Any]:
        return await self._t.request_json(_q("show_deployed_yara_rules"))

    async def delete_yara_rule(self, yarahub_uuid: str) -> dict[str, Any]:
        return await self._t.request_json(_q("delete_yara_rule", yarahub_uuid=yarahub_uuid))

    async def get_yara_rule(self, uuid: str) -> dict[str, Any]:
        return await self._t.request_json(_q("get_yara_rule", uuid=uuid))

    async def get_file(self, sha256_hash: str) -> bytes:
        return await self._t.request_download(_spec_download("get_file", sha256_hash))

    async def get_unpacked(self, sha256_hash: str) -> bytes:
        return await self._t.request_download(_spec_download("get_unpacked", sha256_hash))

    async def scan_file(
        self, content: bytes, filename: str, options: ScanOptions | None = None
    ) -> dict[str, Any]:
        return await self._t.request_json(upload_spec(options or ScanOptions(), filename, content))

    async def deploy_yara_rule(self, rule_content: bytes, filename: str) -> dict[str, Any]:
        return await self._t.request_json(_spec_deploy(rule_content, filename))


class Yaraify(SyncService):
    """Synchronous YARAify client."""

    base_url = YARAIFY_URL

    def generate_identifier(self) -> dict[str, Any]:
        return self._t.request_json_sync(_q("generate_identifier"))

    def list_tasks(self, identifier: str, task_status: str | None = None) -> dict[str, Any]:
        return self._t.request_json_sync(
            _q("list_tasks", identifier=identifier, task_status=task_status)
        )

    def get_results(self, task_id: str, malpedia_token: str | None = None) -> dict[str, Any]:
        return self._t.request_json_sync(
            _spec_with_token("get_results", "task_id", task_id, malpedia_token)
        )

    def lookup_hash(self, search_term: str, malpedia_token: str | None = None) -> dict[str, Any]:
        return self._t.request_json_sync(
            _spec_with_token("lookup_hash", "search_term", search_term, malpedia_token)
        )

    def get_yara(self, search_term: str, result_max: int | None = None) -> dict[str, Any]:
        return self._t.request_json_sync(_spec_search("get_yara", search_term, result_max))

    def get_clamav(self, search_term: str, result_max: int | None = None) -> dict[str, Any]:
        return self._t.request_json_sync(_spec_search("get_clamav", search_term, result_max))

    def get_imphash(self, search_term: str, result_max: int | None = None) -> dict[str, Any]:
        return self._t.request_json_sync(_spec_search("get_imphash", search_term, result_max))

    def get_tlsh(self, search_term: str, result_max: int | None = None) -> dict[str, Any]:
        return self._t.request_json_sync(_spec_search("get_tlsh", search_term, result_max))

    def get_telfhash(self, search_term: str, result_max: int | None = None) -> dict[str, Any]:
        return self._t.request_json_sync(_spec_search("get_telfhash", search_term, result_max))

    def get_gimphash(self, search_term: str, result_max: int | None = None) -> dict[str, Any]:
        return self._t.request_json_sync(_spec_search("get_gimphash", search_term, result_max))

    def get_dhash_icon(self, search_term: str, result_max: int | None = None) -> dict[str, Any]:
        return self._t.request_json_sync(_spec_search("get_dhash_icon", search_term, result_max))

    def rescan_file(self, file_hash: str) -> dict[str, Any]:
        return self._t.request_json_sync(_spec_rescan(file_hash))

    def recent_yararules(self) -> dict[str, Any]:
        return self._t.request_json_sync(_q("recent_yararules"))

    def show_deployed_yara_rules(self) -> dict[str, Any]:
        return self._t.request_json_sync(_q("show_deployed_yara_rules"))

    def delete_yara_rule(self, yarahub_uuid: str) -> dict[str, Any]:
        return self._t.request_json_sync(_q("delete_yara_rule", yarahub_uuid=yarahub_uuid))

    def get_yara_rule(self, uuid: str) -> dict[str, Any]:
        return self._t.request_json_sync(_q("get_yara_rule", uuid=uuid))

    def get_file(self, sha256_hash: str) -> bytes:
        return self._t.request_download_sync(_spec_download("get_file", sha256_hash))

    def get_unpacked(self, sha256_hash: str) -> bytes:
        return self._t.request_download_sync(_spec_download("get_unpacked", sha256_hash))

    def scan_file(
        self, content: bytes, filename: str, options: ScanOptions | None = None
    ) -> dict[str, Any]:
        return self._t.request_json_sync(upload_spec(options or ScanOptions(), filename, content))

    def deploy_yara_rule(self, rule_content: bytes, filename: str) -> dict[str, Any]:
        return self._t.request_json_sync(_spec_deploy(rule_content, filename))
