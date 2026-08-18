"""YARAify CLI subcommands."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import cast

from ..services.base import SyncService
from ..services.yaraify import ScanOptions, Yaraify
from ._common import Command, Param, options_from, register_service
from .output import emit


def _scan(client: SyncService, args: argparse.Namespace) -> None:
    ya = cast("Yaraify", client)
    path = Path(args.file)
    # Every scan option is an int or a string the flag already carries, so
    # there is nothing here to convert and nothing to name twice.
    options = options_from(ScanOptions, args)
    emit(ya.scan_file(path.read_bytes(), path.name, options), args)


def _deploy(client: SyncService, args: argparse.Namespace) -> None:
    ya = cast("Yaraify", client)
    path = Path(args.file)
    emit(ya.deploy_yara_rule(path.read_bytes(), path.name), args)


_RMAX = Param("result_max", is_int=True, optional=True, help="Max results (default 25).")

COMMANDS: tuple[Command, ...] = (
    Command("generate_identifier"),
    Command("list_tasks", (Param("identifier"), Param("task_status", optional=True))),
    Command(
        "get_results",
        (Param("task_id"), Param("malpedia_token", optional=True)),
    ),
    Command(
        "lookup_hash",
        (Param("search_term"), Param("malpedia_token", optional=True)),
        bulkable=True,
    ),
    Command("get_yara", (Param("search_term"), _RMAX)),
    Command("get_clamav", (Param("search_term"), _RMAX)),
    Command("get_imphash", (Param("search_term"), _RMAX)),
    Command("get_tlsh", (Param("search_term"), _RMAX)),
    Command("get_telfhash", (Param("search_term"), _RMAX)),
    Command("get_gimphash", (Param("search_term"), _RMAX)),
    Command("get_dhash_icon", (Param("search_term"), _RMAX)),
    Command("rescan_file", (Param("file_hash"),)),
    Command("recent_yararules"),
    Command("show_deployed_yara_rules"),
    Command("delete_yara_rule", (Param("yarahub_uuid"),)),
    Command("get_yara_rule", (Param("uuid"),)),
    Command("get_file", (Param("sha256_hash"),)),
    Command("get_unpacked", (Param("sha256_hash"),)),
    Command(
        "scan_file",
        (
            Param("file", help="Path to the file to scan."),
            Param("identifier", optional=True),
            Param("clamav_scan", is_int=True, optional=True),
            Param("unpack", is_int=True, optional=True),
            Param("share_file", is_int=True, optional=True),
            Param("skip_known", is_int=True, optional=True),
            Param("skip_noisy", is_int=True, optional=True),
        ),
        handler=_scan,
    ),
    Command(
        "deploy_yara_rule",
        (Param("file", help="Path to the YARA rule file."),),
        handler=_deploy,
    ),
)


def register(root: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    register_service(root, "yaraify", Yaraify, COMMANDS)
