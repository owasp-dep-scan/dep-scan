"""The ``depscan config`` verb: show effective options, write a config file.

``config show`` accepts the scan options, builds the internal namespace the
same way the scan verb will (the v6 parser's environment-backed defaults,
overridden by the TOML file ``--config`` names or the default config path),
and prints every internal option with its value and where the value came
from: the command line, ``--checks`` or ``--profile``, the TOML file, an
environment variable or the default. Precedence: command line, then the
checks and profile, then the TOML file, then environment-backed defaults,
then defaults.

``config init`` writes ``./depscan.toml`` with the same content a scan writes
to ``depscan.toml.sample`` and refuses to overwrite an existing file.
"""

import argparse
import json
import os
import sys
import tomllib

from depscan.cli_options import build_parser
from depscan.commands import checks as checks_table
from depscan.commands.scan import add_scan_options, internal_argv, resolved_namespace
from depscan.lib import pipeline

#: Maps an internal option dest to the environment variable that feeds its
#: default in the internal parser. ``config show`` reports the variable as the
#: value's source when removing it changes the parsed value.
DEST_TO_ENV = {
    "src_dir_image": "DEPSCAN_SOURCE_DIR_IMAGE",
    "reports_dir": "DEPSCAN_REPORTS_DIR",
    "rust_analyzer_backend": "DEPSCAN_RUSI_BACKEND",
    "go_analyzer_network": "DEPSCAN_GO_ANALYZER_NETWORK",
    "go_analyzer_cgo": "DEPSCAN_GO_ANALYZER_CGO",
    "dotnet_analyzer_mode": "DEPSCAN_DOTNET_ANALYZER_MODE",
    "risk_audit": "ENABLE_OSS_RISK",
    "fail_on_error": "DEPSCAN_FAIL_ON_ERROR",
    "cdxgen_args": "CDXGEN_ARGS",
    "spec_version": "CDX_SPEC_VERSION",
    "private_ns": "PKG_PRIVATE_NAMESPACE",
    "project_type": "DEPSCAN_PROJECT_TYPE",
    "severity": "DEPSCAN_SEVERITY",
    "server_host": "DEPSCAN_HOST",
    "server_port": "DEPSCAN_PORT",
    "cdxgen_server": "CDXGEN_SERVER_URL",
    "config": "DEPSCAN_CONFIG",
}

SOURCE_COMMAND_LINE = "command line"
SOURCE_CHECKS = "checks or profile"
SOURCE_CONFIG_FILE = "depscan.toml"
SOURCE_ENVIRONMENT = "environment"
SOURCE_DEFAULT = "default"


def register(subparsers) -> None:
    parser = subparsers.add_parser(
        "config",
        help="Show the effective scan options or write a config file.",
    )
    sub = parser.add_subparsers(dest="subcommand", required=True)
    show = sub.add_parser(
        "show",
        help="Print every scan option with its value and its source.",
    )
    add_scan_options(show)
    init = sub.add_parser(
        "init",
        help="Write ./depscan.toml with the effective scan options.",
    )
    init.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="text for people, json for scripts (default: text)",
    )


def run(args: argparse.Namespace) -> int:
    if args.subcommand == "init":
        return _run_init(args)
    return _run_show(args)


def _internal_dests() -> list:
    """The internal option dests, in the internal parser's registration order.

    The help action's dest never receives a value, so dests the parsed
    namespace does not carry are dropped along with it.
    """
    parser = build_parser()
    namespace = parser.parse_args([])
    return [
        action.dest
        for action in parser._actions
        if action.dest != argparse.SUPPRESS and hasattr(namespace, action.dest)
    ]


def _toml_dests(internal) -> set:
    """The dests the TOML file the internal parser loaded has set."""
    path = getattr(internal, "config", None)
    if not path or not os.path.isfile(path):
        return set()
    try:
        with open(path, "rb") as fp:
            data = tomllib.load(fp)
    except (OSError, tomllib.TOMLDecodeError):
        return set()
    return {key.replace("-", "_") for key, value in data.items() if not isinstance(value, dict)}


def _env_produced(argv: list, dest: str, env_var: str, internal) -> bool:
    """Whether ``env_var`` produced ``dest``'s value in the internal parse.

    The internal namespace is parsed again with the variable removed; when
    the dest's value changes, the variable produced it. Transformations the
    parser applies to the raw value (splitting, boolean parsing) are covered
    by the comparison for free.
    """
    original = os.environ.pop(env_var, None)
    try:
        without = build_parser().parse_args(list(argv))
    finally:
        if original is not None:
            os.environ[env_var] = original
    return getattr(without, dest, None) != getattr(internal, dest, None)


def _option_sources(args: argparse.Namespace, internal, set_by: dict) -> dict:
    """Every internal option with its value and its source."""
    toml_dests = _toml_dests(internal)
    entries = {}
    for dest in _internal_dests():
        if set_by.get(dest) == "command line":
            source = SOURCE_COMMAND_LINE
        elif dest in set_by:
            source = SOURCE_CHECKS
        elif dest in toml_dests:
            source = SOURCE_CONFIG_FILE
        elif (
            dest in DEST_TO_ENV
            and os.environ.get(DEST_TO_ENV[dest]) is not None
            and _env_produced(internal_argv(args), dest, DEST_TO_ENV[dest], internal)
        ):
            source = SOURCE_ENVIRONMENT
        else:
            source = SOURCE_DEFAULT
        entries[dest] = {"value": getattr(internal, dest), "source": source}
    return entries


def _run_show(args: argparse.Namespace) -> int:
    names = checks_table.parse_checks(getattr(args, "checks", None))
    unknown = checks_table.unknown_checks(names)
    if unknown:
        print(
            f"depscan config show: unknown check {', '.join(unknown)}; known checks: "
            f"{', '.join(checks_table.CHECK_NAMES)}",
            file=sys.stderr,
        )
        return 2
    internal, set_by = resolved_namespace(args, checks_table.resolve(args))
    entries = _option_sources(args, internal, set_by)
    if args.format == "json":
        print(json.dumps({"options": entries}, indent=2))
        return 0
    name_width = max(len(dest) for dest in entries)
    source_width = max(len(entry["source"]) for entry in entries.values())
    print(f"{'option':<{name_width}}  {'source':<{source_width}}  value")
    for dest, entry in entries.items():
        value = json.dumps(entry["value"], default=str)
        source = entry["source"]
        print(f"{dest:<{name_width}}  {source:<{source_width}}  {value}")
    return 0


def _run_init(args: argparse.Namespace) -> int:
    path = os.path.join(os.getcwd(), "depscan.toml")
    if os.path.exists(path):
        print(
            f"depscan config init: {path} already exists; not overwriting it.",
            file=sys.stderr,
        )
        return 1
    internal = build_parser().parse_args(internal_argv(args))
    if not pipeline.write_config_file(vars(internal), path):
        print(f"depscan config init: {path} could not be written.", file=sys.stderr)
        return 1
    if args.format == "json":
        print(json.dumps({"written": path.replace(os.sep, "/")}))
    else:
        print(f"Wrote the effective scan options to {path.replace(os.sep, '/')}.")
    return 0
