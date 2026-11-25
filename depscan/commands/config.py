"""The ``depscan config`` verb: show effective options, write a config file.

``config show`` accepts the scan options, builds the internal namespace the
same way the scan verb will (the v6 parser's environment-backed defaults,
overridden by the TOML file ``--config`` names or the default config path),
and prints every internal option with its value and where the value came
from: the command line, ``--checks`` or ``--profile``, the TOML file, an
environment variable or the default. Precedence: command line, then the
checks and profile, then the TOML file, then environment-backed defaults,
then defaults.

``config init`` writes the file the next scan reads by default, which is
``$DEPSCAN_CONFIG`` when that variable is set and ``.config/depscan.toml``
under the current directory otherwise, creating its directory when needed.
The content is the same a scan writes to ``depscan.toml.sample``, and the
command refuses to overwrite an existing file.

In json format each subcommand writes exactly one document to stdout:
``{"options": ...}`` for show and ``{"written": ...}`` for init, with
``show``'s values verbatim, as the scan receives them. A failure writes the
error document instead, with the unknown check names or the failed path in
``details``, and carries the same message on stderr as text.
"""

import argparse
import json
import os
import sys
import tomllib

from depscan.cli_options import build_parser
from depscan.commands import checks as checks_table
from depscan.commands.output import (
    EXIT_FAILURE,
    EXIT_USAGE,
    json_path,
    print_error_document,
    print_json_document,
)
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
        help=(
            "Write the effective scan options to the file a scan reads by default: "
            "$DEPSCAN_CONFIG, or .config/depscan.toml in the current directory."
        ),
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


#: The bundled rule table's published location, as config show names it.
BUNDLED_RULES_LOCATION = "analysis_lib/data/exploitability_rules.yaml"


def _rules_origin(internal) -> dict:
    """Where the exploitability rule table of the next scan comes from."""
    path = getattr(internal, "exploitability_rules", None)
    if path:
        return {"source": "override", "path": str(path)}
    return {"source": "bundled", "path": BUNDLED_RULES_LOCATION}


def _run_show(args: argparse.Namespace) -> int:
    names = checks_table.parse_checks(getattr(args, "checks", None))
    unknown = checks_table.unknown_checks(names)
    if unknown:
        message = (
            f"depscan config show: unknown check {', '.join(unknown)}; known checks: "
            f"{', '.join(checks_table.CHECK_NAMES)}"
        )
        if args.format == "json":
            print_error_document(EXIT_USAGE, "config", message, {"unknownChecks": list(unknown)})
        else:
            print(message, file=sys.stderr)
        return EXIT_USAGE
    internal, set_by = resolved_namespace(args, checks_table.resolve(args))
    entries = _option_sources(args, internal, set_by)
    origin = _rules_origin(internal)
    if args.format == "json":
        print_json_document({"options": entries, "exploitabilityRules": origin})
        return 0
    name_width = max(len(dest) for dest in entries)
    source_width = max(len(entry["source"]) for entry in entries.values())
    print(f"{'option':<{name_width}}  {'source':<{source_width}}  value")
    for dest, entry in entries.items():
        value = json.dumps(entry["value"], default=str)
        source = entry["source"]
        print(f"{dest:<{name_width}}  {source:<{source_width}}  {value}")
    print(f"Exploitability rules: {origin['path']} ({origin['source']})")
    return 0


def default_config_path() -> str:
    """The configuration file a scan reads when ``--config`` is not given.

    This mirrors the ``--config`` default of the internal parser, so the file
    ``config init`` writes is the one the next scan in the same directory and
    environment loads.
    """
    return os.path.abspath(
        os.getenv("DEPSCAN_CONFIG") or os.path.join(os.getcwd(), ".config", "depscan.toml")
    )


def _run_init(args: argparse.Namespace) -> int:
    path = default_config_path()
    if os.path.exists(path):
        message = f"depscan config init: {path} already exists; not overwriting it."
        if args.format == "json":
            print_error_document(EXIT_FAILURE, "config", message, {"path": json_path(path)})
        else:
            print(message, file=sys.stderr)
        return EXIT_FAILURE
    internal = build_parser().parse_args(internal_argv(args))
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
    except OSError:
        written = False
    else:
        written = pipeline.write_config_file(vars(internal), path)
    if not written:
        message = f"depscan config init: {path} could not be written."
        if args.format == "json":
            print_error_document(EXIT_FAILURE, "config", message, {"path": json_path(path)})
        else:
            print(message, file=sys.stderr)
        return EXIT_FAILURE
    if args.format == "json":
        print_json_document({"written": json_path(path)})
    else:
        print(f"Wrote the effective scan options to {path.replace(os.sep, '/')}.")
    return 0
