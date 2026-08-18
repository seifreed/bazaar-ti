"""URLhaus CLI subcommands."""

from __future__ import annotations

import argparse
from typing import Any, cast

from ..services.base import SyncService
from ..services.urlhaus import Urlhaus
from ._common import (
    ANONYMOUS,
    LIMIT,
    TAGS,
    Command,
    Param,
    comma_list,
    register_service,
)
from .output import emit


def _submit(client: SyncService, args: argparse.Namespace) -> None:
    uh = cast("Urlhaus", client)
    entry: dict[str, Any] = {"url": args.url, "threat": args.threat or "malware_download"}
    tags = comma_list(args.tags)
    if tags is not None:
        entry["tags"] = tags
    anonymous = args.anonymous if args.anonymous is not None else 0
    emit(uh.submit([entry], anonymous), args)


COMMANDS: tuple[Command, ...] = (
    Command("urls_recent", (LIMIT,)),
    Command("payloads_recent", (LIMIT,)),
    Command("url", (Param("url"),)),
    Command("urlid", (Param("url_id"),)),
    Command("host", (Param("host"),), bulkable=True),
    Command(
        "payload",
        (Param("md5_hash", optional=True), Param("sha256_hash", optional=True)),
    ),
    Command("tag", (Param("tag"),)),
    Command("signature", (Param("signature"),)),
    Command("download", (Param("sha256_hash"),)),
    Command("export", (Param("name", optional=True),)),
    Command(
        "submit",
        (
            Param("url"),
            Param("threat", optional=True, help="Defaults to malware_download."),
            TAGS,
            ANONYMOUS,
        ),
        handler=_submit,
    ),
)


def register(root: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    register_service(root, "urlhaus", Urlhaus, COMMANDS)
