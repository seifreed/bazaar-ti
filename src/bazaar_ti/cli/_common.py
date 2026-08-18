"""Shared CLI machinery: a small declarative command-table engine."""

from __future__ import annotations

import argparse
import inspect
from collections.abc import Callable, Sequence
from dataclasses import dataclass, fields
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..core.batch import DEFAULT_CONCURRENCY, MAX_CONCURRENCY
from ..core.errors import BazaarTIError
from ..services.base import SyncService

if TYPE_CHECKING:
    from _typeshed import DataclassInstance


@dataclass(frozen=True, slots=True)
class Param:
    """One method parameter exposed as a CLI argument.

    ``name`` matches the client method's parameter name (used as the keyword
    when the method is called). A parameter is positional/required unless
    ``optional`` is set, in which case it becomes ``--name``.
    """

    name: str
    is_int: bool = False
    optional: bool = False
    help: str = ""
    is_bool: bool = False
    """Taken as 0/1 on the command line and passed on as a real boolean."""

    def parse(self) -> Callable[[str], int] | type[str]:
        if self.is_bool:
            return _parse_bool
        return int if self.is_int else str


@dataclass(frozen=True, slots=True)
class Command:
    """A single CLI subcommand, named after the client method it runs.

    These were two fields, and all 65 rows passed the same string to both: no
    subcommand has ever been spelled differently from the method behind it. The
    second copy carried nothing, and a rename could move one and leave the
    other naming a method that was gone — caught only by the test that pins the
    tables to their clients, or by whoever ran that subcommand. One that
    genuinely needs a different method name can grow the override then.
    """

    name: str
    params: tuple[Param, ...] = ()
    bulkable: bool = False
    help: str = ""
    handler: Callable[[SyncService, argparse.Namespace], None] | None = None


Factory = Callable[[argparse.Namespace], SyncService]


def _flag(name: str) -> str:
    return "--" + name.replace("_", "-")


def _parse_bool(value: str) -> int:
    if value not in {"0", "1"}:
        raise argparse.ArgumentTypeError("must be 0 or 1")
    return int(value)


LIMIT = Param("limit", is_int=True, optional=True, help="Max results (1-1000).")
TAGS = Param("tags", optional=True, help="Comma-separated tags.")
ANONYMOUS = Param("anonymous", is_int=True, optional=True, help="1 to submit anonymously.")
"""Flags several services share, defined once so their help text cannot drift.

Each of these was written out per module, and two had already drifted.
``--anonymous`` explained itself under ``malwarebazaar upload`` and nowhere
else, though it decides the same thing — whether the reporter's abuse.ch handle
is published — for every endpoint that takes it. ``--limit`` was rebuilt by hand
for URLhaus's two recent-feed commands, which left them the only ones offering
it with no help text at all.
"""


def comma_list(value: str | None) -> list[str] | None:
    """Split a comma-separated flag into the list of strings the API expects.

    Every list-valued flag across the services — tags, IOC values — is written
    the same way, so ``--tags "exe, test ,"`` gives ``["exe", "test"]``: padding
    around a value is the shell's doing rather than part of it, and a trailing
    comma is a typo, not an empty tag. ``None`` stays ``None``, since an omitted
    flag and an empty one mean different things to the endpoints.
    """
    if value is None:
        return None
    return [item.strip() for item in value.split(",") if item.strip()]


def options_from[T: DataclassInstance](cls: type[T], args: argparse.Namespace, **parsed: Any) -> T:
    """Build an options dataclass from the flags named after its fields.

    Each of the three option types had its field list written a third time, in
    the handler that fills it — after the dataclass that declares it and the
    command table that gives each field a flag. That third copy is the one
    nothing could catch: a field added to the dataclass and to the table but
    not here is an option the CLI accepts on the command line and then drops
    before the request is built, which looks exactly like the endpoint ignoring
    it. Reading the names off the dataclass is what :func:`set_options` already
    does on the way out, so this is the same decision made on the way in.

    Fields whose flag needs converting first — a comma-separated list, a JSON
    object, a real bool — are passed in ``parsed`` and win over the namespace.
    """
    values = {field.name: getattr(args, field.name) for field in fields(cls)}
    return cls(**(values | parsed))


def bulk_key_of(command: Command) -> str | None:
    """Name of the parameter that ``--input-file`` supplies values for."""
    if not command.bulkable:
        return None
    positional = [p for p in command.params if not p.optional]
    return positional[0].name if positional else None


def client_factory(cls: type[SyncService]) -> Factory:
    """Build a factory that constructs one sync client from parsed args."""

    def make(args: argparse.Namespace) -> SyncService:
        return cls(
            auth_key=args.auth_key,
            timeout=args.timeout,
            retries=args.retries,
            config_path=args.config,
            base_url=args.base_url,
        )

    return make


def register_service(
    root: argparse._SubParsersAction[argparse.ArgumentParser],
    name: str,
    service: type[SyncService],
    commands: Sequence[Command],
) -> None:
    """Attach one service, with all its subcommands, under the root parser."""
    factory = client_factory(service)
    service_parser = root.add_parser(name, help=f"{name} API")
    sub = service_parser.add_subparsers(dest="command", required=True)
    for command in commands:
        _validate_command(service, command)
        parser = sub.add_parser(command.name, help=command.help or command.name)
        bulk_key = bulk_key_of(command)
        for param in command.params:
            if param.optional:
                parser.add_argument(
                    _flag(param.name),
                    type=param.parse(),
                    default=None,
                    help=param.help,
                )
            elif param.name == bulk_key:
                # --input-file supplies these, so the value is optional there.
                parser.add_argument(
                    param.name,
                    nargs="?",
                    default=None,
                    type=param.parse(),
                    help=param.help,
                )
            else:
                parser.add_argument(
                    param.name,
                    type=param.parse(),
                    help=param.help,
                )
        parser.add_argument("--output", "-o", default=None, help="Write the response to this file.")
        if command.bulkable:
            parser.add_argument(
                "--input-file",
                type=Path,
                default=None,
                help="Read one value per line and query each (bulk mode).",
            )
            parser.add_argument(
                "--concurrency",
                type=int,
                default=DEFAULT_CONCURRENCY,
                help=(
                    f"Bulk worker threads (default {DEFAULT_CONCURRENCY}, "
                    f"capped at {MAX_CONCURRENCY})."
                ),
            )
        parser.set_defaults(_command=command, _factory=factory)


def _validate_command(service: type[SyncService], command: Command) -> None:
    """Fail parser construction when a command table no longer matches a client."""
    if command.handler is not None:
        return
    method = getattr(service, command.name, None)
    if not callable(method):
        raise BazaarTIError(f"CLI command {command.name!r} is not on {service.__name__}.")
    parameters = inspect.signature(method).parameters
    declared = {param.name for param in command.params}
    required = {
        parameter.name
        for parameter in parameters.values()
        if parameter.name != "self" and parameter.default is inspect.Parameter.empty
    }
    unknown = declared - parameters.keys()
    missing = required - declared
    if unknown or missing:
        raise BazaarTIError(
            f"CLI command {command.name!r} does not match {service.__name__}: "
            f"unknown={sorted(unknown)!r}, missing={sorted(missing)!r}."
        )


def _call(client: SyncService, command: Command, values: dict[str, Any]) -> Any:
    return getattr(client, command.name)(**values)


def _values(command: Command, args: argparse.Namespace) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for param in command.params:
        value = getattr(args, param.name)
        if value is not None:
            result[param.name] = bool(value) if param.is_bool else value
    return result


__all__ = [
    "ANONYMOUS",
    "LIMIT",
    "TAGS",
    "Command",
    "Param",
    "bulk_key_of",
    "client_factory",
    "comma_list",
    "options_from",
    "register_service",
]
