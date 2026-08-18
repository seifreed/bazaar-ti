"""Shared base classes and request shape for async and sync service clients."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import fields
from pathlib import Path
from types import TracebackType
from typing import TYPE_CHECKING, Any, ClassVar, Self

from ..core.config import DEFAULT_RETRIES, DEFAULT_TIMEOUT, resolve_auth_key
from ..core.errors import BazaarTIError
from ..core.transport import Encoding, RequestSpec, Transport, file_part, json_part

if TYPE_CHECKING:
    from _typeshed import DataclassInstance


def drop_unset(fields_: Mapping[str, Any]) -> dict[str, Any]:
    """Keep the arguments the caller actually gave, in the order they were given.

    Every endpoint here means the same thing by an absent argument, and none of
    them reads an explicit null as one: sending ``{"limit": null}`` is not the
    same request as omitting ``limit``. So this is the single place that decides
    what "unset" means, rather than each builder deciding again — and it tests
    ``is not None`` rather than truthiness, because ``share_file=0`` and
    ``anonymous=0`` are choices, not omissions.
    """
    return {key: value for key, value in fields_.items() if value is not None}


def result_count(name: str, value: int | None) -> int | None:
    """Refuse a result count no endpoint reads as one, and pass any other through.

    Asked for fewer than one record, none of the three services says so. URLhaus
    puts the number in the URL path and answers ``limit/0/`` with the whole
    recent feed — 881 URLs for a caller who asked for none. MalwareBazaar and
    YARAify read a negative one as "unset" and send their default hundred, and
    ThreatFox answers ``query_status: no_result`` with rows in ``data`` beside
    it. Four different wrong answers to the same unanswerable question, none of
    them an error, so the caller sees a result set and no sign it is not the one
    they asked for.
    """
    if value is not None and value < 1:
        raise BazaarTIError(f"{name} must be 1 or more (got {value}).")
    return value


def query_spec(
    query: str, encoding: Encoding, *, retryable: bool = True, **fields_: Any
) -> RequestSpec:
    """Build the ``query``-selected call four of the five services share.

    They all name the action in a ``query`` field beside the arguments; only how
    those arguments travel differs, which is what the two bindings below are for.

    ``retryable=False`` marks the calls that create or queue something, so the
    one property that turns a timed-out submission into a duplicate is set here
    beside the request rather than restated with :func:`dataclasses.replace` at
    every write endpoint.
    """
    return RequestSpec(
        encoding=encoding, data={"query": query} | drop_unset(fields_), retryable=retryable
    )


def json_query(query: str, *, retryable: bool = True, **fields_: Any) -> RequestSpec:
    """A ``query`` call whose arguments travel as a JSON document."""
    return query_spec(query, "json", retryable=retryable, **fields_)


def form_query(query: str, *, retryable: bool = True, **fields_: Any) -> RequestSpec:
    """A ``query`` call whose arguments travel as form fields."""
    return query_spec(query, "form", retryable=retryable, **fields_)


def set_options(options: DataclassInstance) -> dict[str, Any]:
    """Return the options the caller actually set, in declaration order.

    Reading the field list off the dataclass keeps the three options types from
    each restating their own fields by hand, where adding one to the class and
    forgetting the list would silently stop sending it.
    """
    return drop_unset({field.name: getattr(options, field.name) for field in fields(options)})


def upload_spec(options: DataclassInstance, filename: str, content: bytes) -> RequestSpec:
    """Build the file submission MalwareBazaar's upload and YARAify's scan share.

    Both are selected by the parts they carry rather than by a ``query`` field,
    and both want the metadata as one ``json_data`` document beside the file —
    sent as flat form fields it is ignored, which silently defeats YARAify's
    ``share_file=0``, the opt-out that keeps a submitted sample private. Neither
    is retryable: a timeout landing after the server committed would file the
    sample twice.
    """
    return RequestSpec(
        encoding="multipart",
        files={
            "json_data": json_part(set_options(options)),
            "file": file_part(filename, content),
        },
        retryable=False,
    )


class _ServiceBase:
    """Resolves the Auth-Key and owns the :class:`Transport` for one service."""

    base_url: ClassVar[str]

    def __init__(
        self,
        auth_key: str | None = None,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
        config_path: Path | None = None,
        base_url: str | None = None,
    ) -> None:
        key = resolve_auth_key(auth_key, config_path)
        self._key = key
        self._t = Transport(base_url or self.base_url, key, timeout=timeout, retries=retries)
        self._open_extra_transports(base_url, timeout=timeout, retries=retries)

    def _open_extra_transports(self, base_url: str | None, *, timeout: float, retries: int) -> None:
        """Open any transport a service needs beside the one for its base URL.

        Only URLhaus does — its submissions go to a different host than its
        queries. A hook rather than a second ``__init__`` there because the
        only way to override one and forward it unchanged is to restate all six
        parameters, and that copy is held by nothing: one added here and not
        there would be accepted by the Urlhaus constructor and dropped without
        a word. Forwarding with ``*args`` instead is not available — the
        clients ship ``py.typed``, and a var-args signature turns off argument
        checking for every caller, which is what ``test_clients_expose_a_
        checkable_signature`` exists to prevent.
        """


class AsyncService(_ServiceBase):
    """Async client base with async context-manager support."""

    async def aclose(self) -> None:
        await self._t.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()


class SyncService(_ServiceBase):
    """Sync client base with context-manager support."""

    def close(self) -> None:
        self._t.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()
