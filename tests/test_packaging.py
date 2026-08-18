"""Packaging and structural-contract regression checks."""

from __future__ import annotations

import ast
import importlib
import inspect
import pkgutil
import re
import textwrap
import tomllib
from dataclasses import fields, is_dataclass
from importlib.resources import files
from inspect import Parameter
from types import FunctionType, ModuleType
from typing import TYPE_CHECKING, Any

import pytest
from _pytest.mark import ParameterSet

import bazaar_ti
from bazaar_ti import (
    BatchOptions,
    Hunting,
    MalwareBazaar,
    ScanOptions,
    SubmitIocOptions,
    ThreatFox,
    UploadOptions,
    Urlhaus,
    Yaraify,
    core,
    datalake,
    services,
)
from bazaar_ti.cli import hunting as cli_hunting
from bazaar_ti.cli import malwarebazaar as cli_malwarebazaar
from bazaar_ti.cli import threatfox as cli_threatfox
from bazaar_ti.cli import urlhaus as cli_urlhaus
from bazaar_ti.cli import yaraify as cli_yaraify
from bazaar_ti.cli._common import Command, Param
from bazaar_ti.cli.main import SERVICES
from bazaar_ti.core import RequestSpec, Transport
from bazaar_ti.core.batch import MAX_CONCURRENCY
from bazaar_ti.formats import FORMATS
from bazaar_ti.services.base import AsyncService, SyncService
from tests.conftest import REPO_ROOT

if TYPE_CHECKING:
    from _typeshed import DataclassInstance

_SERVICES = [
    pytest.param(cli_malwarebazaar.COMMANDS, MalwareBazaar, id="malwarebazaar"),
    pytest.param(cli_urlhaus.COMMANDS, Urlhaus, id="urlhaus"),
    pytest.param(cli_threatfox.COMMANDS, ThreatFox, id="threatfox"),
    pytest.param(cli_yaraify.COMMANDS, Yaraify, id="yaraify"),
    pytest.param(cli_hunting.COMMANDS, Hunting, id="hunting"),
]


_README = (REPO_ROOT / "README.md").read_text(encoding="utf-8")

_SUBCOMMAND_CLAIM = re.compile(r"(\d+) subcommands")
_PYTHON_CLAIM = re.compile(r"Python (\d+\.\d+)\+")
_SERVICE_CLAIM = re.compile(r"`bazaar-ti (\w+)`")
_FORMAT_CLAIM = re.compile(r"`--format (\w+)`")
# \s+ rather than a literal space: the claim wraps across a line in the README,
# and a pattern that only matched it unwrapped would go quiet the next time the
# paragraph is reflowed — passing by finding nothing is the one way this fails
# without saying so, which is what the "no longer states" assertion is for.
_CONCURRENCY_CLAIM = re.compile(r"cap\s+concurrency\s+at\s+(\d+)")


def test_the_readme_states_the_python_version_the_package_requires() -> None:
    """ "Python 3.14+" is pyproject's requires-python, written out again.

    Six other places state this version too, but each of those is a tool's own
    key — black, ruff and mypy each need it in their own spelling, and the
    classifier is PyPI metadata. None can be derived from another. The README
    can, and it is the one a reader believes: left behind after a bump it sends
    someone to install a package pip will refuse them.
    """
    required = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    floor = str(required["project"]["requires-python"]).removeprefix(">=").strip()
    claimed = _PYTHON_CLAIM.search(_README)
    assert claimed is not None, "the README no longer states a Python version"
    assert claimed.group(1) == floor


def test_the_source_archive_ships_only_the_project() -> None:
    """hatchling's default is everything git does not ignore, and that is more.

    A working checkout also holds a local code-index database, a hypothesis
    cache and two editors' rule files, none of them ignored at the root: the
    archive went out at 2.5 MB, 7.9 MB of it an index naming paths from the
    machine that built it. An allowlist is what keeps a new tool's directory
    from being published the first time someone runs it, and it has to stay an
    allowlist — a list of things to leave out goes stale by definition.

    tests are on the list on purpose: a downstream packager builds from this
    archive and runs them.
    """
    config = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    sdist = config["tool"]["hatch"]["build"]["targets"]["sdist"]
    assert "exclude" not in sdist, "the source archive must be an allowlist"
    assert set(sdist["include"]) == {"src", "tests", "README.md", "LICENSE", "pyproject.toml"}


def _commands(module: ModuleType) -> tuple[Command, ...]:
    """The module's command table, or none for a service that registers its own."""
    table: tuple[Command, ...] = getattr(module, "COMMANDS", ())
    return table


def test_every_table_driven_service_is_walked_by_these_tests() -> None:
    """_SERVICES pairs each table with its client, which nothing can derive.

    So it is the one list still written by hand, and this is what keeps it
    whole: a service registered with a command table but left out of the pairs
    below is one whose table nothing checks against the client it drives.
    """
    walked = {commands for commands, _ in (p.values for p in _SERVICES)}
    assert walked == {_commands(m) for m in SERVICES if _commands(m)}


def test_the_readme_subcommand_count_is_the_one_the_tables_register() -> None:
    """The README states a number only the command tables know.

    "66 subcommands covering every documented action and query" is the five
    tables plus the datalake command, which registers its own parser instead of
    carrying one. Nothing recomputed it, so adding a subcommand left the README
    quietly claiming the old count — an unheld copy of the same kind the tables
    themselves had before they were pinned to the methods they drive. The
    number lives in the README alone now; this is what keeps it true.
    """
    claimed = _SUBCOMMAND_CLAIM.search(_README)
    assert claimed is not None, "the README no longer states a subcommand count"
    tabled = sum(len(_commands(module)) for module in SERVICES)
    # datalake registers its one subcommand directly, so it contributes no table.
    untabled = [module for module in SERVICES if not _commands(module)]
    assert int(claimed.group(1)) == tabled + len(untabled)


def test_the_readme_names_the_services_the_root_parser_registers() -> None:
    """The "Available Services" table is SERVICES, written out in prose.

    It cannot be derived — each row carries a description only a person can
    write — so the copy stays, and this is what keeps it honest. Both
    directions matter and fail differently: a service registered and left out
    of the table is one nobody reading the README knows exists, and a row for
    one that was removed sends them to a subcommand argparse will reject.

    Two other claims in this file are held the same way, for the same reason;
    these were the ones still resting on someone remembering.
    """
    assert set(_SERVICE_CLAIM.findall(_README)) == {
        module.__name__.rsplit(".", 1)[-1] for module in SERVICES
    }


def test_the_readme_names_the_formats_render_offers() -> None:
    """The third copy of FORMATS, and the one nothing was holding.

    ``formats.FORMATS`` is already the single source the CLI reads for its
    argparse choices, precisely so the two cannot disagree about which names
    ``--format`` takes. The README's flag table is the same list a third time,
    and it fails in the direction the other two cannot: a format added to the
    tuple is simply undocumented, and one removed leaves the README offering a
    flag value the parser now refuses.
    """
    assert set(_FORMAT_CLAIM.findall(_README)) == set(FORMATS)


def test_the_readme_states_the_concurrency_ceiling_the_helpers_enforce() -> None:
    """Both bulk helpers cap at MAX_CONCURRENCY, and the README says the number.

    A reader sizing a batch believes it, and it is the kind of value that gets
    tuned: raised in the module and left alone here, the README quietly
    understates what the library will do with a ``concurrency=`` it was handed.
    """
    claimed = _CONCURRENCY_CLAIM.search(_README)
    assert claimed is not None, "the README no longer states the concurrency ceiling"
    assert int(claimed.group(1)) == MAX_CONCURRENCY


def _every_annotated_object() -> list[tuple[str, Any]]:
    """Every function, class and method this package defines, with its label."""
    found: list[tuple[str, Any]] = []
    for info in pkgutil.walk_packages(bazaar_ti.__path__, "bazaar_ti."):
        module = importlib.import_module(info.name)
        for name, value in vars(module).items():
            if getattr(value, "__module__", None) != info.name:
                continue
            if inspect.isfunction(value):
                found.append((f"{info.name}.{name}", value))
            elif inspect.isclass(value):
                found.append((f"{info.name}.{name}", value))
                found.extend(
                    (f"{info.name}.{name}.{sub}", member)
                    for sub, member in vars(value).items()
                    if inspect.isfunction(member)
                )
    return found


def test_reading_an_annotation_never_raises() -> None:
    """We ship py.typed, so consumers introspect these — it must not blow up.

    ``base.py`` annotates two public functions with ``DataclassInstance``, which
    is imported under ``if TYPE_CHECKING`` from ``_typeshed`` — a module that
    does not exist at runtime at all. What keeps that safe is
    ``from __future__ import annotations``: under PEP 563 the annotation is only
    ever the string "DataclassInstance", so nothing tries to resolve it.

    Python 3.14 makes PEP 649 the default, where annotations are real objects
    computed lazily instead. That is not the same guarantee — it defers the
    evaluation rather than removing it — so dropping the future import turns
    ``set_options.__annotations__`` into a NameError for anyone who reads it:
    Sphinx autodoc, a dataclass helper, an IDE inspecting at runtime.

    Nothing held this. The whole suite and ``mypy --strict`` both pass with the
    import removed from that file, because none of them reads an annotation off
    the objects that carry the unresolvable name. This does, on every function,
    class and method in the package.
    """
    failures: list[str] = []
    read = 0
    for label, obj in _every_annotated_object():
        try:
            read += len(obj.__annotations__)
        except NameError as exc:
            failures.append(f"{label}: {exc}")
    assert not failures, "annotations that cannot be read at runtime: " + "; ".join(failures)
    # Counting them is what stops this passing by having walked nothing: an
    # import that stopped yielding objects would otherwise look like a clean run.
    assert read > 0


def test_py_typed_marker_shipped() -> None:
    """The PEP 561 marker must ship so consumers get our type hints."""
    assert (files("bazaar_ti") / "py.typed").is_file()


def test_option_dataclasses_exported() -> None:
    """Option types are part of public method signatures, so they must be importable."""
    assert all(isinstance(cls, type) for cls in (UploadOptions, ScanOptions, SubmitIocOptions))


@pytest.mark.parametrize(
    "module",
    [
        pytest.param(bazaar_ti, id="bazaar_ti"),
        pytest.param(core, id="bazaar_ti.core"),
        pytest.param(services, id="bazaar_ti.services"),
    ],
)
def test_all_exports_resolve(module: ModuleType) -> None:
    """Every name in an __all__ must be a real attribute of its module."""
    assert all(hasattr(module, name) for name in module.__all__)


_CORE_ONLY = {"RequestSpec", "Transport", "resolve_auth_key"}
"""Core names the top level deliberately does not re-export.

They are how a client is built rather than something a caller of one needs.
"""


def test_the_subpackage_reexports_do_not_drift() -> None:
    """Two sub-packages re-export names the top level exports as well.

    Nothing inside the project imports through either — ``bazaar_ti/__init__``
    reaches past them to the submodules, and so does the CLI — so the lists are
    a second public surface that no call site would keep honest. Deriving the
    client half from the top level is what holds them together: a service added
    to one and not the other fails here rather than at whichever import a
    consumer happened to write.
    """
    clients = {
        name
        for name in bazaar_ti.__all__
        if isinstance(getattr(bazaar_ti, name), type)
        and issubclass(getattr(bazaar_ti, name), (AsyncService, SyncService))
    }
    assert set(services.__all__) == clients
    assert set(core.__all__) - _CORE_ONLY <= set(bazaar_ti.__all__)


_ASYNC_NAME = {
    "close": "aclose",
    "request_json_sync": "request_json",
    "request_text_sync": "request_text",
    "request_download_sync": "request_download",
    "stream_download_sync": "stream_download",
    "iter_bytes": "aiter_bytes",
    "_send_sync": "_send",
    "_open_stream_sync": "_open_stream",
    "_sclient": "_aclient",
    "_sync_client": "_async_client",
}
"""What each sync attribute is called on the async side.

These eleven are the whole difference between the two halves of anything here.
Every other name — the endpoint methods, the spec builders they call, the
arguments they pass — is spelled identically, which is what makes the
comparison below possible.
"""

_ASYNC_MODULE = {"time": "asyncio", "_spool_to_file": "_spool_to_file_async"}
"""The same names on the two sides that are not attributes of ``self``.

``time.sleep`` and ``asyncio.sleep`` are the same wait, and the two spools are
the same write loop over a sync and an async iterator.
"""


class _SameShape(ast.NodeTransformer):
    """Rewrite a method into the form its twin would have.

    Drops ``await``, renames the five sync-only attributes to their async
    spelling, and erases the name, decorators and return annotation. What is
    left is what the two halves are supposed to have in common: the calls they
    make, in order, with the same arguments.
    """

    def visit_Await(self, node: ast.Await) -> ast.expr:
        self.generic_visit(node)
        return node.value

    def visit_Attribute(self, node: ast.Attribute) -> ast.Attribute:
        self.generic_visit(node)
        node.attr = _ASYNC_NAME.get(node.attr, node.attr)
        return node

    def visit_Name(self, node: ast.Name) -> ast.Name:
        node.id = _ASYNC_MODULE.get(node.id, node.id)
        return node

    @staticmethod
    def _without_docstring(body: list[ast.stmt]) -> list[ast.stmt]:
        """Drop a leading docstring, which the two halves may word differently.

        ``download_batch`` says "synchronously" where its twin says
        "asynchronously". That is the pair describing itself, not the pair
        disagreeing, so it is not what this compares.
        """
        first = body[0] if body else None
        is_docstring = (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
        )
        return (body[1:] or [ast.Pass()]) if is_docstring else body

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)
        return ast.copy_location(
            ast.FunctionDef(
                name="_",
                args=node.args,
                body=self._without_docstring(node.body),
                decorator_list=[],
                returns=None,
                type_params=[],
            ),
            node,
        )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        self.generic_visit(node)
        node.name = "_"
        node.decorator_list = []
        node.returns = None
        node.type_params = []
        node.body = self._without_docstring(node.body)
        return node


def _shape(method: FunctionType) -> str:
    source = textwrap.dedent(inspect.getsource(method))
    return ast.dump(_SameShape().visit(ast.parse(source)))


def _public_methods(cls: type) -> set[str]:
    return {
        name
        for name, value in vars(cls).items()
        if inspect.isfunction(value) and not name.startswith("__")
    }


_TWINS = [
    pytest.param(
        getattr(services, name),
        getattr(services, name.removesuffix("Async")),
        id=name.removesuffix("Async").lower(),
    )
    for name in services.__all__
    if name.endswith("Async")
]


@pytest.mark.parametrize(("async_cls", "sync_cls"), _TWINS)
def test_the_two_halves_of_a_client_say_the_same_thing(async_cls: type, sync_cls: type) -> None:
    """The async and sync clients are the largest duplication here, and it stays.

    Collapsing them would mean generating the methods, and the package ships
    py.typed: a generated method has no signature to check, which is what
    test_clients_expose_a_checkable_signature exists to prevent. So the two
    halves are written out — 65 pairs of them — and until now nothing held them
    together. The drift that costs is the quiet kind: a request fixed on the
    sync side and not the async one looks like nothing at all, and this project
    has already had it, which is why test_async_submissions_keep_the_defaults_
    the_sync_ones_are_held_to exists for two specific methods.

    This holds all of them, by rewriting each method into the form its twin
    would have and requiring the two to match exactly.
    """
    async_names = _public_methods(async_cls)
    sync_names = _public_methods(sync_cls)
    expected = {_ASYNC_NAME.get(name, name) for name in sync_names}
    assert (
        async_names == expected
    ), f"{sync_cls.__name__} and its async half expose different methods"
    for name in sorted(sync_names):
        sync_method = getattr(sync_cls, name)
        async_method = getattr(async_cls, _ASYNC_NAME.get(name, name))
        assert _shape(async_method) == _shape(sync_method), (
            f"{async_cls.__name__}.{_ASYNC_NAME.get(name, name)} does not do what "
            f"{sync_cls.__name__}.{name} does"
        )


def _paired(namespace: object, label: str) -> list[ParameterSet]:
    """Every async/sync twin the naming convention exposes on one namespace.

    Derived rather than listed, so a new pair is covered by being written the
    way every other pair here is written.
    """
    names = {name for name in dir(namespace) if not name.startswith("__")}

    def twin(async_name: str, sync_name: str, base: str) -> ParameterSet:
        return pytest.param(
            getattr(namespace, async_name),
            getattr(namespace, sync_name),
            id=f"{label}.{base}",
        )

    pairs: list[ParameterSet] = []
    for name in sorted(names):
        if name.endswith("_sync") and name.removesuffix("_sync") in names:
            pairs.append(twin(name.removesuffix("_sync"), name, name.removesuffix("_sync")))
        if name.endswith("_async") and name.removesuffix("_async") in names:
            pairs.append(twin(name, name.removesuffix("_async"), name.removesuffix("_async")))
    if {"close", "aclose"} <= names:
        pairs.append(twin("aclose", "close", "close"))
    return pairs


_LOOSE_TWINS = _paired(Transport, "Transport") + _paired(datalake, "datalake")


@pytest.mark.parametrize(("async_fn", "sync_fn"), _LOOSE_TWINS)
def test_the_twins_outside_the_clients_say_the_same_thing(
    async_fn: FunctionType, sync_fn: FunctionType
) -> None:
    """Not every twin is a method of a service client.

    Transport carries six pairs of its own and the datalake exposes two module
    functions, and the guard above reaches none of them because it walks the
    client classes. download_batch and download_batch_async are the ones that
    matter most: they are public API, they own a transport's whole lifetime
    through a try/finally, and two tests each is all that watches them.
    """
    assert _shape(async_fn) == _shape(sync_fn)


@pytest.mark.parametrize(
    "client",
    [pytest.param(getattr(services, name), id=name) for name in services.__all__],
)
def test_clients_expose_a_checkable_signature(client: type) -> None:
    """We ship py.typed, so no client may hide behind (*args, **kwargs).

    Urlhaus once did, which silently disabled argument checking for callers.
    The clients were named here by hand and four of the ten were missing —
    every async half but UrlhausAsync — so the list is taken from what the
    package exports. A client that hides its signature cannot now do it by
    being new.
    """
    kinds = {p.kind for p in inspect.signature(client).parameters.values()}
    assert Parameter.VAR_POSITIONAL not in kinds, client.__name__
    assert Parameter.VAR_KEYWORD not in kinds, client.__name__
    assert inspect.signature(client).parameters["timeout"].annotation is not None


@pytest.mark.parametrize(("commands", "client"), _SERVICES)
def test_the_command_table_still_matches_the_client_it_drives(
    commands: tuple[Command, ...], client: type
) -> None:
    """Each Param restates part of a method signature, so pin them together.

    Half the entries in the tables carry nothing a signature has not already
    got — the name, whether it has a default, whether it is an int. Deriving
    them instead would leave the other half needing help text and CLI-only
    flags declared some other way, so the tables stay written out. What must
    not happen is the copy drifting from the original: a renamed parameter, or
    an int that stopped being one, would then only surface when someone ran
    that subcommand.

    Both directions are checked. Only the table-to-client one used to be, and
    the gap it left is the quiet kind: an endpoint added to a client and not to
    the table is one the CLI cannot reach at all, and nothing said so. Not the
    subcommand count either — that is the sum of the tables, so a method with
    no row leaves it unchanged and the README goes on claiming every documented
    action is covered while one of them has no way to be run.
    """
    # close is lifecycle, not an endpoint. Only Urlhaus declares it on the class
    # itself — it closes the second transport its submissions go out over — so
    # it is the one name that would otherwise read as a missing subcommand.
    endpoints = _public_methods(client) - {"close"}
    assert endpoints == {command.name for command in commands}, (
        f"{client.__name__} methods with no subcommand: "
        f"{sorted(endpoints - {c.name for c in commands})}"
    )
    for command in commands:
        method = getattr(client, command.name, None)
        assert method is not None, f"{command.name} names no method on {client.__name__}"
        if command.handler is not None:
            continue  # a hand-written handler reads argparse itself
        params = inspect.signature(method).parameters
        for param in command.params:
            assert param.name in params, f"{command.name}: no parameter {param.name!r}"
            annotation = str(params[param.name].annotation)
            assert param.is_int == ("int" in annotation), f"{command.name}.{param.name}"
        required = [
            name
            for name, value in params.items()
            if name != "self" and value.default is Parameter.empty
        ]
        assert required == [p.name for p in command.params if not p.optional], command.name


@pytest.mark.parametrize(
    ("options_cls", "commands", "command_name"),
    [
        pytest.param(UploadOptions, cli_malwarebazaar.COMMANDS, "upload", id="upload"),
        pytest.param(ScanOptions, cli_yaraify.COMMANDS, "scan_file", id="scan_file"),
        pytest.param(SubmitIocOptions, cli_threatfox.COMMANDS, "submit_ioc", id="submit_ioc"),
    ],
)
def test_every_option_field_has_a_flag_to_set_it(
    options_cls: type, commands: tuple[Command, ...], command_name: str
) -> None:
    """A field with no flag is one the CLI can never send.

    The handlers used to name these fields a third time; they build the options
    off the dataclass now, so the list survives in two places — the dataclass
    that declares it and the table that gives each field a flag. This is what
    holds those two together: adding a field to the dataclass and stopping
    there leaves an option that exists in the library and is unreachable from
    the CLI, and it now fails as an AttributeError deep in a handler rather
    than as a value quietly dropped.
    """
    command = next(c for c in commands if c.name == command_name)
    flags = {p.name for p in command.params}
    missing = {f.name for f in fields(options_cls)} - flags
    assert not missing, f"{options_cls.__name__} fields with no CLI flag: {sorted(missing)}"


def _declared_dataclasses() -> set[str]:
    """Every dataclass this package defines, found rather than named.

    Found because the list below cannot be: two of these need a constructor
    argument, so the instances stay written out. What can be derived is whether
    the list is still all of them.
    """
    found: set[str] = set()
    for info in pkgutil.walk_packages(bazaar_ti.__path__, "bazaar_ti."):
        module = importlib.import_module(info.name)
        for name, value in vars(module).items():
            if isinstance(value, type) and is_dataclass(value) and value.__module__ == info.name:
                found.add(name)
    return found


_IMMUTABLE = [
    pytest.param(UploadOptions(), id="UploadOptions"),
    pytest.param(ScanOptions(), id="ScanOptions"),
    pytest.param(SubmitIocOptions(), id="SubmitIocOptions"),
    pytest.param(BatchOptions(), id="BatchOptions"),
    pytest.param(RequestSpec(), id="RequestSpec"),
    pytest.param(Param("x"), id="Param"),
    pytest.param(Command("n"), id="Command"),
]


def test_every_declared_type_is_held_to_being_immutable() -> None:
    """The instances above are written out; that they are all of them is not.

    Two of these need a constructor argument, so the list cannot be derived.
    What can be derived is whether it is still complete: a dataclass added
    anywhere in the package and left off it is one whose frozen and slots
    nothing checks, and both are part of what these types promise.
    """
    assert {param.id for param in _IMMUTABLE} == _declared_dataclasses()


@pytest.mark.parametrize("options", _IMMUTABLE)
def test_declared_types_cannot_be_mutated(options: DataclassInstance) -> None:
    """These are exported, so a caller may build one and reuse it across calls.

    frozen=True is what makes that safe, and slots=True is what turns a typo in
    an attribute name into an error rather than a field nothing reads. Both are
    part of what these types promise and neither had anything holding it: the
    whole suite passes with either dropped.

    RequestSpec is here for a second reason: four spec builders call
    ``replace(spec, retryable=False)`` to mark a write, and that idiom is only
    safe to read as "a new spec" while the original cannot be changed underneath
    whoever else is holding it.
    """
    first = fields(options)[0].name
    with pytest.raises(AttributeError):
        setattr(options, first, "changed")
    # No instance dict is the observable half of slots, and it survives even
    # when frozen would have refused the assignment above for its own reasons.
    assert not hasattr(options, "__dict__")
