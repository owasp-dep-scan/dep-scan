"""Translate v6 invocations to the v7 verb command line.

v7 is verb first: ``depscan scan``, ``depscan serve``, ``depscan version``.
The v6 command line was one flat option list. This module turns a v6 argv
into the v7 command that does the same job, and renders the option table
the migration guide embeds.

Emission order: the program name and the verb, then the positional
targets (``--src``, ``--bom``, ``--bom-dir`` and ``--purl`` values, in
that order), then the remaining flags in the order the v6 options are
registered, each under its long v7 name. The verb is ``version`` when the
v6 version action fired, in which case nothing else is emitted (v6 itself
exits at the version flag), ``serve`` when ``--server`` was passed or any
of the server-only options ``--server-host``, ``--server-port``,
``--server-allowed-hosts`` or ``--server-allowed-paths`` was given, and
``scan`` otherwise. ``--config``, which the TOML-aware parser wrapper
registers before the v6 options, is emitted last. Values are emitted as
given, an option that takes several values emits all of them, and boolean
flags emit no value. ``--profile X`` is emitted as ``--bom-profile X``
and ``--risk-audit`` as ``--checks supply-chain``. Unknown tokens are
dropped. An argv that sets nothing translatable (for example ``-h``) or
is not a valid v6 command line (a bad choice, a mutually exclusive
conflict, an option without its value) translates to None.
"""

import argparse
import contextlib
import io
import re
import shlex
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from depscan.cli_options import build_parser

# Row kinds. TARGET rows move their value into the positional target,
# SERVER and VERSION rows switch the verb, FLAG rows emit v7_flag plus the
# value, CHECKS rows emit v7_flag plus the fixed v7_value.
TARGET = "target"
FLAG = "flag"
CHECKS = "checks"
SERVER = "server"
VERSION = "version"


@dataclass(frozen=True)
class OptionRow:
    """One v6 option: its flags, its argparse dest and how it is emitted.

    ``v7_display`` is the equivalent shown in the option table and
    ``note`` the sentence next to it; empty strings fill the spots a kind
    does not use (``v7_flag`` for TARGET, SERVER and VERSION rows).
    """

    v6_flags: tuple[str, ...]
    dest: str | None
    kind: str
    v7_flag: str = ""
    v7_value: str = ""
    v7_display: str = ""
    note: str = ""


OPTION_TABLE: tuple[OptionRow, ...] = (
    OptionRow(
        v6_flags=("--no-banner",),
        dest="no_banner",
        kind=FLAG,
        v7_flag="--no-banner",
        v7_display="depscan scan --no-banner",
        note="Unchanged.",
    ),
    OptionRow(
        v6_flags=("-i", "--src"),
        dest="src_dir_image",
        kind=TARGET,
        v7_display="depscan scan <target>",
        note="The value becomes the positional target; the kind is detected.",
    ),
    OptionRow(
        v6_flags=("-o", "--reports-dir"),
        dest="reports_dir",
        kind=FLAG,
        v7_flag="--reports-dir",
        v7_display="depscan scan --reports-dir",
        note="Unchanged.",
    ),
    OptionRow(
        v6_flags=("--csaf",),
        dest="csaf",
        kind=FLAG,
        v7_flag="--csaf",
        v7_display="depscan scan --csaf",
        note="Unchanged.",
    ),
    OptionRow(
        v6_flags=("--csaf-version",),
        dest="csaf_version",
        kind=FLAG,
        v7_flag="--csaf-version",
        v7_display="depscan scan --csaf-version",
        note="Unchanged.",
    ),
    OptionRow(
        v6_flags=("--profile",),
        dest="profile",
        kind=FLAG,
        v7_flag="--bom-profile",
        v7_display="depscan scan --bom-profile",
        note="The cdxgen BOM profile flag is renamed.",
    ),
    OptionRow(
        v6_flags=("--lifecycle",),
        dest="lifecycles",
        kind=FLAG,
        v7_flag="--lifecycle",
        v7_display="depscan scan --lifecycle",
        note="Unchanged.",
    ),
    OptionRow(
        v6_flags=("--technique",),
        dest="techniques",
        kind=FLAG,
        v7_flag="--technique",
        v7_display="depscan scan --technique",
        note="Unchanged.",
    ),
    OptionRow(
        v6_flags=("--bom-engine",),
        dest="bom_engine",
        kind=FLAG,
        v7_flag="--bom-engine",
        v7_display="depscan scan --bom-engine",
        note="Unchanged.",
    ),
    OptionRow(
        v6_flags=("--vulnerability-analyzer",),
        dest="vuln_analyzer",
        kind=FLAG,
        v7_flag="--vulnerability-analyzer",
        v7_display="depscan scan --vulnerability-analyzer",
        note="Unchanged.",
    ),
    OptionRow(
        v6_flags=("--reachability-analyzer",),
        dest="reachability_analyzer",
        kind=FLAG,
        v7_flag="--reachability-analyzer",
        v7_display="depscan scan --reachability-analyzer",
        note="Unchanged.",
    ),
    OptionRow(
        v6_flags=("--rust-analyzer-backend",),
        dest="rust_analyzer_backend",
        kind=FLAG,
        v7_flag="--rust-analyzer-backend",
        v7_display="depscan scan --rust-analyzer-backend",
        note="Unchanged.",
    ),
    OptionRow(
        v6_flags=("--go-analyzer-network",),
        dest="go_analyzer_network",
        kind=FLAG,
        v7_flag="--go-analyzer-network",
        v7_display="depscan scan --go-analyzer-network",
        note="Unchanged.",
    ),
    OptionRow(
        v6_flags=("--go-analyzer-cgo",),
        dest="go_analyzer_cgo",
        kind=FLAG,
        v7_flag="--go-analyzer-cgo",
        v7_display="depscan scan --go-analyzer-cgo",
        note="Unchanged.",
    ),
    OptionRow(
        v6_flags=("--dotnet-analyzer-mode",),
        dest="dotnet_analyzer_mode",
        kind=FLAG,
        v7_flag="--dotnet-analyzer-mode",
        v7_display="depscan scan --dotnet-analyzer-mode",
        note="Unchanged.",
    ),
    OptionRow(
        v6_flags=("--no-suggest",),
        dest="suggest",
        kind=FLAG,
        v7_flag="--no-suggest",
        v7_display="depscan scan --no-suggest",
        note="Unchanged.",
    ),
    OptionRow(
        v6_flags=("--risk-audit",),
        dest="risk_audit",
        kind=CHECKS,
        v7_flag="--checks",
        v7_value="supply-chain",
        v7_display="depscan scan --checks supply-chain",
        note="The package risk audit became the supply-chain check.",
    ),
    OptionRow(
        v6_flags=("--fail-on-error",),
        dest="fail_on_error",
        kind=FLAG,
        v7_flag="--fail-on-error",
        v7_display="depscan scan --fail-on-error",
        note="Unchanged.",
    ),
    OptionRow(
        v6_flags=("--cdxgen-args",),
        dest="cdxgen_args",
        kind=FLAG,
        v7_flag="--cdxgen-args",
        v7_display="depscan scan --cdxgen-args",
        note="Unchanged.",
    ),
    OptionRow(
        v6_flags=("--spec-version",),
        dest="spec_version",
        kind=FLAG,
        v7_flag="--spec-version",
        v7_display="depscan scan --spec-version",
        note="Unchanged.",
    ),
    OptionRow(
        v6_flags=("--private-ns",),
        dest="private_ns",
        kind=FLAG,
        v7_flag="--private-ns",
        v7_display="depscan scan --private-ns",
        note="Unchanged.",
    ),
    OptionRow(
        v6_flags=("-t", "--type"),
        dest="project_type",
        kind=FLAG,
        v7_flag="--type",
        v7_display="depscan scan --type",
        note="Unchanged.",
    ),
    OptionRow(
        v6_flags=("--bom",),
        dest="bom",
        kind=TARGET,
        v7_display="depscan scan <bom-file>",
        note="The value becomes the positional target; the kind is bom.",
    ),
    OptionRow(
        v6_flags=("--bom-dir",),
        dest="bom_dir",
        kind=TARGET,
        v7_display="depscan scan <dir>",
        note="The value becomes the positional target; the kind is bom-dir.",
    ),
    OptionRow(
        v6_flags=("--purl",),
        dest="search_purl",
        kind=TARGET,
        v7_display="depscan scan <purl>",
        note="The value becomes the positional target; the kind is purl.",
    ),
    OptionRow(
        v6_flags=("--custom-data",),
        dest="custom_data",
        kind=FLAG,
        v7_flag="--custom-data",
        v7_display="depscan scan --custom-data",
        note="Unchanged; also accepted by depscan serve.",
    ),
    OptionRow(
        v6_flags=("--report-template",),
        dest="report_template",
        kind=FLAG,
        v7_flag="--report-template",
        v7_display="depscan scan --report-template",
        note="Unchanged.",
    ),
    OptionRow(
        v6_flags=("--report-name",),
        dest="report_name",
        kind=FLAG,
        v7_flag="--report-name",
        v7_display="depscan scan --report-name",
        note="Unchanged.",
    ),
    OptionRow(
        v6_flags=("--deep",),
        dest="deep_scan",
        kind=FLAG,
        v7_flag="--deep",
        v7_display="depscan scan --deep",
        note="Unchanged.",
    ),
    OptionRow(
        v6_flags=("--fuzzy-search",),
        dest="fuzzy_search",
        kind=FLAG,
        v7_flag="--fuzzy-search",
        v7_display="depscan scan --fuzzy-search",
        note="Unchanged.",
    ),
    OptionRow(
        v6_flags=("--search-order",),
        dest="search_order",
        kind=FLAG,
        v7_flag="--search-order",
        v7_display="depscan scan --search-order",
        note="Unchanged.",
    ),
    OptionRow(
        v6_flags=("--severity",),
        dest="severity",
        kind=FLAG,
        v7_flag="--severity",
        v7_display="depscan scan --severity",
        note="Unchanged.",
    ),
    OptionRow(
        v6_flags=("--malware-only",),
        dest="malware_only",
        kind=FLAG,
        v7_flag="--malware-only",
        v7_display="depscan scan --malware-only",
        note="Unchanged.",
    ),
    OptionRow(
        v6_flags=("--vdb-flavor",),
        dest="vdb_flavor",
        kind=FLAG,
        v7_flag="--vdb-flavor",
        v7_display="depscan scan --vdb-flavor",
        note="Unchanged; also accepted by depscan serve.",
    ),
    OptionRow(
        v6_flags=("--vdb-scope",),
        dest="vdb_scope",
        kind=FLAG,
        v7_flag="--vdb-scope",
        v7_display="depscan scan --vdb-scope",
        note="Unchanged; deprecated.",
    ),
    OptionRow(
        v6_flags=("--vdb-time",),
        dest="vdb_time",
        kind=FLAG,
        v7_flag="--vdb-time",
        v7_display="depscan scan --vdb-time",
        note="Unchanged; deprecated.",
    ),
    OptionRow(
        v6_flags=("--vdb-extended",),
        dest="vdb_extended",
        kind=FLAG,
        v7_flag="--vdb-extended",
        v7_display="depscan scan --vdb-extended",
        note="Unchanged; deprecated.",
    ),
    OptionRow(
        v6_flags=("--vdb-compression",),
        dest="vdb_compression",
        kind=FLAG,
        v7_flag="--vdb-compression",
        v7_display="depscan scan --vdb-compression",
        note="Unchanged; also accepted by depscan serve.",
    ),
    OptionRow(
        v6_flags=("--vdb-distro",),
        dest="vdb_distro",
        kind=FLAG,
        v7_flag="--vdb-distro",
        v7_display="depscan scan --vdb-distro",
        note="Unchanged; rejected with the flavor list.",
    ),
    OptionRow(
        v6_flags=("--vdb-image",),
        dest="vdb_image",
        kind=FLAG,
        v7_flag="--vdb-image",
        v7_display="depscan scan --vdb-image",
        note="Unchanged; also accepted by depscan serve.",
    ),
    OptionRow(
        v6_flags=("--no-universal",),
        dest="non_universal_scan",
        kind=FLAG,
        v7_flag="--no-universal",
        v7_display="depscan scan --no-universal",
        note="Unchanged.",
    ),
    OptionRow(
        v6_flags=("--no-vuln-table",),
        dest="no_vuln_table",
        kind=FLAG,
        v7_flag="--no-vuln-table",
        v7_display="depscan scan --no-vuln-table",
        note="Unchanged.",
    ),
    OptionRow(
        v6_flags=("--server",),
        dest="server_mode",
        kind=SERVER,
        v7_display="depscan serve",
        note="Removed as a flag; it switches the verb to serve.",
    ),
    OptionRow(
        v6_flags=("--server-host",),
        dest="server_host",
        kind=FLAG,
        v7_flag="--server-host",
        v7_display="depscan serve --server-host",
        note="Now on the serve verb.",
    ),
    OptionRow(
        v6_flags=("--server-port",),
        dest="server_port",
        kind=FLAG,
        v7_flag="--server-port",
        v7_display="depscan serve --server-port",
        note="Now on the serve verb.",
    ),
    OptionRow(
        v6_flags=("--server-allowed-hosts",),
        dest="server_allowed_hosts",
        kind=FLAG,
        v7_flag="--server-allowed-hosts",
        v7_display="depscan serve --server-allowed-hosts",
        note="Now on the serve verb.",
    ),
    OptionRow(
        v6_flags=("--server-allowed-paths",),
        dest="server_allowed_paths",
        kind=FLAG,
        v7_flag="--server-allowed-paths",
        v7_display="depscan serve --server-allowed-paths",
        note="Now on the serve verb.",
    ),
    OptionRow(
        v6_flags=("--cdxgen-server",),
        dest="cdxgen_server",
        kind=FLAG,
        v7_flag="--cdxgen-server",
        v7_display="depscan scan --cdxgen-server",
        note="Unchanged; also accepted by depscan serve.",
    ),
    OptionRow(
        v6_flags=("--debug",),
        dest="enable_debug",
        kind=FLAG,
        v7_flag="--debug",
        v7_display="depscan scan --debug",
        note="Unchanged; also accepted by depscan serve.",
    ),
    OptionRow(
        v6_flags=("-q", "--quiet"),
        dest="quiet",
        kind=FLAG,
        v7_flag="--quiet",
        v7_display="depscan scan --quiet",
        note="Unchanged.",
    ),
    OptionRow(
        v6_flags=("--explain",),
        dest="explain",
        kind=FLAG,
        v7_flag="--explain",
        v7_display="depscan scan --explain",
        note="Unchanged.",
    ),
    OptionRow(
        v6_flags=("--explanation-mode",),
        dest="explanation_mode",
        kind=FLAG,
        v7_flag="--explanation-mode",
        v7_display="depscan scan --explanation-mode",
        note="Unchanged.",
    ),
    OptionRow(
        v6_flags=("--annotate",),
        dest="annotate",
        kind=FLAG,
        v7_flag="--annotate",
        v7_display="depscan scan --annotate",
        note="Unchanged.",
    ),
    OptionRow(
        v6_flags=("-v", "--version"),
        dest=None,
        kind=VERSION,
        v7_display="depscan version",
        note="Removed as a flag; use the version verb.",
    ),
    OptionRow(
        v6_flags=("--config",),
        dest="config",
        kind=FLAG,
        v7_flag="--config",
        v7_display="depscan scan --config",
        note="Unchanged; the flat TOML file keeps its v6 semantics.",
    ),
)

_RECORDABLE_ACTIONS = {
    "-h": "recorded_help",
    "--help": "recorded_help",
    "-v": "recorded_version",
    "--version": "recorded_version",
}

# v7-internal parser options with no v6 equivalent: they are internal
# schema entries the pipeline reads, so they have no row and must not
# appear in the option table.
V7_INTERNAL_DESTS: frozenset[str] = frozenset({"exclude_types", "vdb_offline"})

# Options that exist on the serve verb only; passing one of them without
# --server is still a server invocation.
_SERVER_ONLY_DESTS = frozenset(
    {
        "server_host",
        "server_port",
        "server_allowed_hosts",
        "server_allowed_paths",
    }
)


class _RecordAction(argparse.Action):
    """Stand-in for the help and version actions.

    Those actions print and exit; the translator needs to know they fired
    without the print and the exit, so they are swapped for this action
    while argv is parsed.
    """

    def __init__(self, option_strings: list[str], dest: str) -> None:
        super().__init__(
            option_strings=option_strings, dest=dest, nargs=0, default=False
        )

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Any,
        option_string: str | None = None,
    ) -> None:
        setattr(namespace, self.dest, True)


def _install_recorders(parser: argparse.ArgumentParser) -> None:
    """Swap the parser's help and version actions for recording actions."""
    for action in list(parser._actions):
        option_strings = [
            flag for flag in action.option_strings if flag in _RECORDABLE_ACTIONS
        ]
        if not option_strings:
            continue
        recorder = _RecordAction(
            option_strings, _RECORDABLE_ACTIONS[option_strings[0]]
        )
        for flag in option_strings:
            parser._option_string_actions[flag] = recorder


def _parse_explicit(
    argv: Sequence[str],
) -> tuple[argparse.Namespace, dict[str, Any]] | None:
    """Parse ``argv`` and return the namespace and the explicitly set dests.

    Every default is replaced by a unique sentinel for the parse, so a dest
    whose value is not its sentinel was given on the command line even when
    the value equals the real default. The parse uses the plain argparse
    ``parse_known_args``: unknown tokens are dropped and no TOML file is
    loaded. The parser's own ``find_changed_args`` cannot be used here
    because it parses strictly, so unknown tokens would fail the parse and
    the help and version actions would print and exit.

    An argv the v6 parser rejects (a bad choice, a mutually exclusive
    conflict, an option without its value) returns None; argparse's usage
    and error text is discarded rather than printed.
    """
    parser = build_parser()
    _install_recorders(parser)
    sentinels: dict[str, Any] = {}
    originals: dict[int, Any] = {}
    for action in parser._actions:
        if action.dest is argparse.SUPPRESS:
            continue
        originals[id(action)] = action.default
        sentinel = object()
        sentinels[action.dest] = sentinel
        action.default = sentinel
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            parsed, _unknown = parser.parse_known_args(argv)
    except SystemExit:
        return None
    finally:
        for action in parser._actions:
            if id(action) in originals:
                action.default = originals[id(action)]
    explicit = {
        dest: getattr(parsed, dest)
        for dest, sentinel in sentinels.items()
        if getattr(parsed, dest, sentinel) is not sentinel
    }
    return parsed, explicit


def translate(argv: Sequence[str]) -> str | None:
    """Translate a v6 argv into the v7 command line.

    Returns None for an argv that is not a valid v6 command line or that
    sets nothing translatable, for example ``-h``/``--help`` or no options
    at all.
    """
    parsed_explicit = _parse_explicit(argv)
    if parsed_explicit is None:
        return None
    parsed, explicit = parsed_explicit
    if getattr(parsed, "recorded_help", False):
        return None
    if getattr(parsed, "recorded_version", False):
        return "depscan version"
    if explicit.get("server_mode") is True or any(
        dest in explicit for dest in _SERVER_ONLY_DESTS
    ):
        verb = "serve"
    else:
        verb = "scan"
    words: list[str] = ["depscan", verb]
    for row in OPTION_TABLE:
        if row.kind == TARGET and row.dest in explicit:
            words.append(str(explicit[row.dest]))
    for row in OPTION_TABLE:
        if row.kind not in (FLAG, CHECKS) or row.dest not in explicit:
            continue
        words.append(row.v7_flag)
        if row.v7_value:
            words.append(row.v7_value)
            continue
        value = explicit[row.dest]
        if isinstance(value, (list, tuple)):
            words.extend(str(item) for item in value)
        elif not isinstance(value, bool) and str(value).startswith("-"):
            # A value that looks like an option only parses joined to its flag.
            words[-1] = f"{row.v7_flag}={value}"
        elif not isinstance(value, bool):
            words.append(str(value))
    if verb == "scan" and len(words) == 2:
        return None
    return " ".join(_quote(word) for word in words)


#: Words made only of these characters print unquoted. ``$``, ``{`` and ``}``
#: are included so a shell variable in a workflow line stays expandable.
_UNQUOTED_WORD_RE = re.compile(r"^[\w@%+=:,./${}~-]+$")


def _quote(word: str) -> str:
    """Quote a word for a POSIX shell when it needs it, so a value with spaces
    or an empty value stays one argument when the command is pasted back."""
    return word if _UNQUOTED_WORD_RE.match(word) else shlex.quote(word)


def option_table_markdown() -> str:
    """Return the v6 to v7 option table as markdown for the migration guide."""
    lines = [
        "| v6 option | v7 equivalent | note |",
        "| --- | --- | --- |",
    ]
    for row in OPTION_TABLE:
        v6 = ", ".join(f"`{flag}`" for flag in row.v6_flags)
        lines.append(f"| {v6} | `{row.v7_display}` | {row.note} |")
    return "\n".join(lines) + "\n"
