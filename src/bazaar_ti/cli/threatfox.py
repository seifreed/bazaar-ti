"""ThreatFox CLI subcommands."""

from __future__ import annotations

import argparse
from typing import cast

from ..services.base import SyncService
from ..services.threatfox import SubmitIocOptions, ThreatFox
from ._common import (
    ANONYMOUS,
    LIMIT,
    TAGS,
    Command,
    Param,
    comma_list,
    options_from,
    register_service,
)
from .output import emit


def _submit_ioc(client: SyncService, args: argparse.Namespace) -> None:
    tf = cast("ThreatFox", client)
    options = options_from(
        SubmitIocOptions,
        args,
        is_compromised=bool(args.is_compromised) if args.is_compromised is not None else None,
        tags=comma_list(args.tags),
    )
    iocs = comma_list(args.iocs) or []
    emit(tf.submit_ioc(args.threat_type, args.ioc_type, args.malware, iocs, options), args)


COMMANDS: tuple[Command, ...] = (
    Command("get_iocs", (Param("days", is_int=True, optional=True),)),
    Command("ioc", (Param("ioc_id", is_int=True),)),
    Command(
        "search_ioc",
        (
            Param("search_term"),
            Param("exact_match", optional=True, is_bool=True, help="1 for an exact match."),
        ),
    ),
    Command("search_hash", (Param("file_hash"),), bulkable=True),
    Command("taginfo", (Param("tag"), LIMIT)),
    Command("malwareinfo", (Param("malware"), LIMIT)),
    Command("get_label", (Param("malware"), Param("platform", optional=True))),
    Command("malware_list"),
    Command("types"),
    Command("tag_list"),
    Command(
        "submit_ioc",
        (
            Param("threat_type"),
            Param("ioc_type"),
            Param("malware"),
            Param("iocs", help="Comma-separated IOC values."),
            Param("confidence_level", is_int=True, optional=True),
            Param(
                "is_compromised",
                optional=True,
                is_bool=True,
                help="1 if the host was compromised rather than attacker-owned.",
            ),
            Param("reference", optional=True),
            TAGS,
            Param("comment", optional=True),
            ANONYMOUS,
        ),
        handler=_submit_ioc,
    ),
)


def register(root: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    register_service(root, "threatfox", ThreatFox, COMMANDS)
