"""Hunting API CLI subcommands."""

from __future__ import annotations

import argparse

from ..services.hunting import FPLIST_FORMATS, Hunting
from ._common import ANONYMOUS, Command, Param, register_service

COMMANDS: tuple[Command, ...] = (
    Command(
        "get_fplist",
        (Param("fmt", optional=True, help=f"{' or '.join(FPLIST_FORMATS)}."),),
    ),
    Command(
        "create_collection",
        (
            Param("collection_name"),
            Param("description", optional=True),
            ANONYMOUS,
        ),
    ),
)


def register(root: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    register_service(root, "hunting", Hunting, COMMANDS)
