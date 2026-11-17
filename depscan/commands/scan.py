"""The ``depscan scan`` verb and the shared scan option parser.

:func:`add_scan_options` registers every scan option on any parser: the scan
verb's own subparser and the ``config show`` subparser both use it. The
options keep the flag names, choices and help texts of the v6 parser in
``depscan/cli_options.py``, which stays the source of truth for what each
option means once it reaches the internal namespace.

Every option uses ``default=argparse.SUPPRESS`` so the parsed namespace
carries only what the caller actually passed; the internal namespace is built
later from the v6 parser's defaults, the TOML file and the environment, and
the explicitly passed options are applied on top of it. Only ``--format`` and
the positional ``targets`` carry real defaults.

Two dests differ from the v6 names on purpose: ``--bom-profile`` (the cdxgen
BOM profile v6 called ``--profile``) lands on ``bom_profile`` because
``--profile`` now names the scan profile, and ``--exclude-type`` lands on
``exclude_types`` (repeatable) so it maps straight onto the internal option.

:func:`scan_namespace` builds the internal namespace from a parsed command
line, and :func:`run` drives the scans: one per target, with the target kind
detected (or forced), the requested checks gated against one doctor report
before any scan work, and one JSON document on stdout in json format.
"""

import argparse
import json
import os
import re
import sys

from analysis_lib.config import SUPPORTED_BOM_PROFILES

from depscan import api
from depscan.cli_options import build_parser, validate_spec_version
from depscan.commands import checks as checks_table
from depscan.commands.targets import FORCE_TARGET_KINDS, detect_kind
from depscan.lib import doctor as doctor_lib
from depscan.lib.logger import LOG, console

#: The checks a scan can run, as the ``--checks`` help lists them.
CHECK_NAMES = checks_table.CHECK_NAMES

#: The scan profiles, as the ``--profile`` help lists them.
PROFILE_NAMES = checks_table.PROFILE_NAMES

#: Dests of the scan parse that never map onto an internal option.
_NOT_INTERNAL_DESTS = (
    "verb",
    "subcommand",
    "targets",
    "target_kind",
    "checks",
    "profile",
    "format",
)

#: The scan flag whose dest differs from the internal option it sets: v6's
#: ``--profile`` (the cdxgen BOM profile) is v7's ``--bom-profile``.
_SCAN_TO_INTERNAL_DESTS = {"bom_profile": "profile"}

#: The project type each target kind forces when the user passed no ``-t``.
_TARGET_PROJECT_TYPES = {"container": "docker", "binary": "binary", "android": "apk"}

#: The characters a multi-target directory name replaces.
_DIRECTORY_NAME_SEPARATORS = re.compile(r"[/\\:@]")


def add_scan_options(parser: argparse.ArgumentParser) -> None:
    """Add every scan option to ``parser``."""
    _add_target_options(parser)
    _add_output_options(parser)
    _add_document_options(parser)
    _add_bom_generation_options(parser)
    _add_cdxgen_options(parser)
    _add_analyzer_options(parser)
    _add_search_options(parser)
    _add_filter_options(parser)
    _add_vdb_options(parser)
    _add_render_options(parser)


def _add_target_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "targets",
        nargs="*",
        default=[],
        metavar="target",
        help="What to scan: a source directory, git URL, container image "
        "reference, BOM file, BOM directory, purl or binary. The kind is "
        "detected; pass --target-kind to force one. Multiple targets run "
        "one scan each.",
    )
    parser.add_argument(
        "--target-kind",
        choices=FORCE_TARGET_KINDS,
        default=argparse.SUPPRESS,
        help="Force the kind of every target instead of detecting it. "
        "firmware is accepted only to be refused: it has no inventory path "
        "in this version.",
    )
    parser.add_argument(
        "--checks",
        default=argparse.SUPPRESS,
        metavar="CHECKS",
        help="Comma-separated list of checks to run: " + ", ".join(CHECK_NAMES) + ". "
        "An explicit list defines the whole optional set; vulnerabilities "
        "always runs.",
    )
    parser.add_argument(
        "--profile",
        choices=PROFILE_NAMES,
        default=argparse.SUPPRESS,
        help="Scan profile: quick (vulnerabilities only), ci (vulnerabilities "
        "and reachability, no explanations), deep (adds license and "
        "supply-chain with semantic reachability), research (deep plus "
        "cdxgen's research BOM profile), offline (no database download, no "
        "remote cdxgen). Explicit options win over the profile.",
    )
    parser.add_argument(
        "--bom-profile",
        choices=SUPPORTED_BOM_PROFILES,
        dest="bom_profile",
        default=argparse.SUPPRESS,
        help="Profile to use while generating the BOM. For granular control, use "
        "the arguments --bom-engine, --vulnerability-analyzer, or --reachability-analyzer.",
    )
    parser.add_argument(
        "--exclude-type",
        action="append",
        dest="exclude_types",
        default=argparse.SUPPRESS,
        metavar="TYPE",
        help="Project type dropped from the detected list before any stage "
        "runs, so no inventory or scan runs for it (an excluded os or docker "
        "type stops the OS and container scans), and passed to cdxgen as a "
        "repeated --exclude-type argument so the BOM contents are filtered "
        "the same way. Repeatable; comma-separated values are accepted.",
    )


def _add_output_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="text for people, json for scripts (default: text)",
    )
    parser.add_argument(
        "--config",
        default=argparse.SUPPRESS,
        help="Path to the configuration file. Default: $PWD/.config/depscan.toml",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        default=argparse.SUPPRESS,
        dest="no_banner",
        help="Do not display the logo and donation banner. Please make a donation to OWASP before using this argument.",
    )
    parser.add_argument(
        "-o",
        "--reports-dir",
        default=argparse.SUPPRESS,
        dest="reports_dir",
        help="Reports directory",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        default=argparse.SUPPRESS,
        dest="enable_debug",
        help="Run depscan in debug mode.",
    )
    output_group = parser.add_mutually_exclusive_group(required=False)
    output_group.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        default=argparse.SUPPRESS,
        dest="quiet",
        help="Makes depscan quiet.",
    )
    output_group.add_argument(
        "--explain",
        action="store_true",
        default=argparse.SUPPRESS,
        dest="explain",
        help="Makes depscan to explain the various analysis. Useful for creating detailed reports.",
    )


def _add_document_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--csaf",
        action="store_true",
        default=argparse.SUPPRESS,
        dest="csaf",
        help="Generate a OASIS CSAF VEX document",
    )
    parser.add_argument(
        "--csaf-version",
        default=argparse.SUPPRESS,
        choices=("2.0", "2.1"),
        dest="csaf_version",
        help="CSAF schema version to target (default: 2.1). CSAF 2.1 retains "
        "CVSS v4 scores; 2.0 drops them because the schema has no cvss_v4 slot.",
    )
    parser.add_argument(
        "--custom-data",
        default=argparse.SUPPRESS,
        dest="custom_data",
        help="Path to directory containing custom vulnerability data (JSON/YAML/TOML) to override/augment results.",
    )
    parser.add_argument(
        "--report-template",
        default=argparse.SUPPRESS,
        dest="report_template",
        help="Jinja template file used for rendering a custom report",
    )
    parser.add_argument(
        "--report-name",
        default=argparse.SUPPRESS,
        dest="report_name",
        help="Filename of the custom report written to the --reports-dir",
    )


def _add_bom_generation_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--lifecycle",
        choices=("pre-build", "build", "post-build"),
        nargs="+",
        type=str,
        default=argparse.SUPPRESS,
        dest="lifecycles",
        help="Product lifecycle for the generated BOM. Multiple values allowed.",
    )
    parser.add_argument(
        "--technique",
        choices=(
            "auto",
            "source-code-analysis",
            "binary-analysis",
            "manifest-analysis",
            "hash-comparison",
            "instrumentation",
            "filename",
        ),
        nargs="+",
        type=str,
        default=argparse.SUPPRESS,
        dest="techniques",
        help="Analysis technique to use for BOM generation. Multiple values allowed.",
    )
    engine_group = parser.add_mutually_exclusive_group(required=False)
    engine_group.add_argument(
        "--bom-engine",
        choices=(
            "auto",
            "CdxgenGenerator",
            "CdxgenServerGenerator",
            "CdxgenImageBasedGenerator",
            "BlintGenerator",
        ),
        default=argparse.SUPPRESS,
        dest="bom_engine",
        help="BOM generation engine to use. Defaults to automatic selection based on project type and lifecycle.",
    )
    engine_group.add_argument(
        "--vulnerability-analyzer",
        choices=(
            "auto",
            "VDRAnalyzer",
            "LifecycleAnalyzer",
        ),
        default=argparse.SUPPRESS,
        dest="vuln_analyzer",
        help="Vulnerability analyzer to use. Defaults to automatic selection based on bom_dir argument.",
    )
    parser.add_argument(
        "--reachability-analyzer",
        choices=(
            "off",
            "FrameworkReachability",
            "SemanticReachability",
        ),
        default=argparse.SUPPRESS,
        dest="reachability_analyzer",
        help="Reachability analyzer to use. Default FrameworkReachability.",
    )


def _add_cdxgen_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--spec-version",
        type=validate_spec_version,
        default=argparse.SUPPRESS,
        dest="spec_version",
        help="CycloneDX specification version to request from cdxgen. "
        "Choices: 1.4, 1.5, 1.6, 1.7, 2.0. Defaults to 1.6 (1.7 is not yet "
        "supported by Dependency-Track and some other consumers).",
    )
    parser.add_argument(
        "--cdxgen-args",
        default=argparse.SUPPRESS,
        dest="cdxgen_args",
        help="Additional arguments to pass to cdxgen",
    )
    parser.add_argument(
        "--cdxgen-server",
        default=argparse.SUPPRESS,
        dest="cdxgen_server",
        help="cdxgen server url. Eg: http://cdxgen:9090",
    )


def _add_analyzer_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--rust-analyzer-backend",
        choices=("stable", "compiler"),
        default=argparse.SUPPRESS,
        dest="rust_analyzer_backend",
        help="rusi (Rust Source Inspector) backend for Rust reachability. "
        "``stable`` (default) is syn-based parsing with no cargo/rustc build "
        "and is safe on untrusted repos. ``compiler`` embeds nightly rustc "
        "and builds the target for higher fidelity -- only use on trusted "
        "input (see rusi THREAT_MODEL). Implied by --deep for Rust projects. "
        "Set DEPSCAN_RUSI_BINARY to point at a non-PATH rusi binary.",
    )
    parser.add_argument(
        "--go-analyzer-network",
        choices=("auto", "offline"),
        default=argparse.SUPPRESS,
        dest="go_analyzer_network",
        help="Network mode for golem (Go Source Inspector) reachability. "
        "golem runs with cgo off, so packages that need cgo are not loaded "
        "and their reachability is missing; pass --go-analyzer-cgo to enable "
        "cgo for trusted input. ``auto`` (default) allows golem's package "
        "loader to download missing modules per the user's Go env "
        "(GOFLAGS=-mod=readonly is still set to prevent go.mod rewrites). "
        "``offline`` sets GOPROXY=off to forbid all downloads -- requires a "
        "warm module cache (GOMODCACHE). "
        "Set DEPSCAN_GOLEM_BINARY to point at a non-PATH golem binary.",
    )
    parser.add_argument(
        "--go-analyzer-cgo",
        action="store_true",
        default=argparse.SUPPRESS,
        dest="go_analyzer_cgo",
        help="Allow cgo while golem loads Go packages. Default is cgo off: "
        "packages that need cgo are not loaded and their reachability is "
        "missing. With this flag the C compiler runs with flags taken from "
        "the scanned code and its dependencies, so use it only for input you "
        "trust. Can also be enabled with DEPSCAN_GO_ANALYZER_CGO.",
    )
    parser.add_argument(
        "--dotnet-analyzer-mode",
        choices=("source", "assembly", "auto"),
        default=argparse.SUPPRESS,
        dest="dotnet_analyzer_mode",
        help="dosai (Dotnet Source and Assembly Inspector) analysis mode for "
        ".NET reachability. ``auto`` (default) inspects source when a source "
        "tree is present and falls back to assembly inspection for bin/.nupkg-"
        "only inputs. ``source`` forces Roslyn-based C#/VB/F# source "
        "inspection; ``assembly`` forces Reflection-based .dll/.exe inspection. "
        "Pattern packs default to ``all``. dosai requires a .NET runtime (or a "
        "self-contained ``-full`` binary). Set DOSAI_CMD to point at a non-PATH "
        "dosai binary. dep-scan does NOT run ``dotnet restore``; a restored tree "
        "yields the best versioned NuGet purls.",
    )


def _add_search_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--no-suggest",
        action="store_false",
        default=argparse.SUPPRESS,
        dest="suggest",
        help="Disable suggest mode",
    )
    parser.add_argument(
        "--fail-on-error",
        action="store_true",
        default=argparse.SUPPRESS,
        dest="fail_on_error",
        help="Abort the scan with a non-zero exit code instead of silently degrading. "
        "Passed through to cdxgen so extractor failures fail BOM generation, and "
        "applied to blint, rusi, golem, and dosai failures, unreadable reachability "
        "reports, empty slices, and empty package lists.",
    )
    parser.add_argument(
        "-t",
        "--type",
        nargs="+",
        type=str,
        default=argparse.SUPPRESS,
        dest="project_type",
        help="Override project types if auto-detection is incorrect. Multiple values supported.",
    )
    parser.add_argument(
        "--private-ns",
        default=argparse.SUPPRESS,
        dest="private_ns",
        help="Private namespace to use while performing oss risk audit. "
        "Private packages should not be available in public registries "
        "by default. Comma separated values accepted.",
    )
    parser.add_argument(
        "--deep",
        action="store_true",
        default=argparse.SUPPRESS,
        dest="deep_scan",
        help="Perform deep scan by passing this --deep argument to cdxgen. "
        "Useful while scanning docker images and OS packages.",
    )
    parser.add_argument(
        "--fuzzy-search",
        action="store_true",
        default=argparse.SUPPRESS,
        dest="fuzzy_search",
        help="Perform fuzzy search by creating variations of package names. Use this when the input SBOM lacks a PURL.",
    )
    parser.add_argument(
        "--search-order",
        choices=(
            "purl",
            "pcu",
            "cpe",
            "cpu",
            "url",
        ),
        default=argparse.SUPPRESS,
        dest="search_order",
        help="Attributes to use while searching for vulnerabilities. Default: PURL, CPE, URL (pcu).",
    )


def _add_filter_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--severity",
        choices=("low", "medium", "high", "critical"),
        default=argparse.SUPPRESS,
        dest="severity",
        help="Minimum severity threshold to report (low, medium, high, critical). "
        "Only advisories at or above this severity are returned. depscan applies "
        "this floor to the final VDR on any database; on the extended vdb "
        "(VDB_INCLUDE_METADATA) it is additionally pushed down into the search "
        "for speed. Findings with no rated severity are kept.",
    )
    parser.add_argument(
        "--malware-only",
        action="store_true",
        default=argparse.SUPPRESS,
        dest="malware_only",
        help="Report only malware advisories (MAL-*). Works on the default vdb "
        "because is_malware is always populated via the MAL- fallback.",
    )


def _add_vdb_options(parser: argparse.ArgumentParser) -> None:
    vdb_group = parser.add_argument_group(
        "vulnerability database selection",
        "Select which published vdb database the scan downloads. These can also be "
        'persisted in the depscan config file (e.g. vdb_flavor = "app-only"). An '
        "explicit VDB_DATABASE_URL env pin always wins. The `depscan vdb download` "
        "command shares the same options for pre-fetching.",
    )
    vdb_group.add_argument(
        "--vdb-flavor",
        choices=("full", "app-only", "app-extended", "app-10y", "app-10y-extended"),
        default=argparse.SUPPRESS,
        dest="vdb_flavor",
        help="Which published database flavor to use: 'full' (app+OS), "
        "'app-only' (application ecosystems, NVD 2020+), 'app-extended' "
        "(adds metadata tables for severity, text, alias, reference, symbol "
        "and date search), 'app-10y' (NVD 2016+), 'app-10y-extended' "
        "(both). Default: full.",
    )
    vdb_group.add_argument(
        "--vdb-scope",
        choices=("app", "app+os"),
        default=argparse.SUPPRESS,
        dest="vdb_scope",
        help="Deprecated alias for --vdb-flavor: 'app' maps to app-only (or "
        "app-extended/app-10y/app-10y-extended with the other deprecated "
        "options), 'app+os' to full. Default: app+os.",
    )
    vdb_group.add_argument(
        "--vdb-time",
        choices=("2y", "default", "10y"),
        default=argparse.SUPPRESS,
        dest="vdb_time",
        help="Deprecated alias for --vdb-flavor: '10y' selects a 10-year "
        "flavor; '2y' has no v7 equivalent and is rejected. Default: default.",
    )
    vdb_group.add_argument(
        "--vdb-extended",
        action="store_true",
        default=argparse.SUPPRESS,
        dest="vdb_extended",
        help="Deprecated alias selecting the metadata flavor (app-extended or "
        "app-10y-extended), needed for severity, text, alias, reference, "
        "symbol, and date search. Auto-selected when --severity is set.",
    )
    vdb_group.add_argument(
        "--vdb-compression",
        choices=("xz", "zst"),
        default=argparse.SUPPRESS,
        dest="vdb_compression",
        help="Compression format. 'xz' (tar.xz) always works; 'zst' (zstd) is "
        "faster to decompress but needs a zstd decompressor. Default: xz.",
    )
    vdb_group.add_argument(
        "--vdb-distro",
        choices=("alpine", "debian", "redhat", "alma", "rocky", "ubuntu"),
        default=argparse.SUPPRESS,
        dest="vdb_distro",
        help="Rejected: vdb 7 publishes no per-distro complete database. Pass "
        "--vdb-flavor full and scan the distro packages, or fetch type shards "
        "with `depscan vdb download`.",
    )
    vdb_group.add_argument(
        "--vdb-image",
        default=argparse.SUPPRESS,
        dest="vdb_image",
        help="Override the vdb image URL verbatim (bypasses the resolver). "
        "Equivalent to setting VDB_DATABASE_URL.",
    )


def _add_render_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--no-universal",
        action="store_true",
        default=argparse.SUPPRESS,
        dest="non_universal_scan",
        help="Depscan would attempt to perform a single universal scan "
        "instead of individual scans per language type.",
    )
    parser.add_argument(
        "--no-vuln-table",
        action="store_true",
        default=argparse.SUPPRESS,
        dest="no_vuln_table",
        help="Do not print the table with the full list of vulnerabilities. "
        "This can help reduce console output.",
    )
    parser.add_argument(
        "--explanation-mode",
        choices=(
            "Endpoints",
            "EndpointsAndReachables",
            "NonReachables",
            "LLMPrompts",
        ),
        default=argparse.SUPPRESS,
        dest="explanation_mode",
        help="Style of explanation needed. Defaults to Endpoints and Reachables.",
    )
    parser.add_argument(
        "--annotate",
        action="store_true",
        default=argparse.SUPPRESS,
        dest="annotate",
        help="Include the generated text VDR report as an annotation. Defaults to true when explain is enabled; false otherwise.",
    )


def register(subparsers) -> None:
    parser = subparsers.add_parser(
        "scan",
        help="Scan a project, BOM, purl or container image for vulnerabilities.",
    )
    add_scan_options(parser)


# --- the internal namespace ------------------------------------------------------


def internal_argv(args: argparse.Namespace) -> list:
    """The argv the internal parser gets: only ``--config`` when given.

    Without it the internal parser falls back to its own default config path
    (``DEPSCAN_CONFIG`` or ``$PWD/.config/depscan.toml``), exactly as a v6
    scan did.
    """
    config = getattr(args, "config", None)
    return ["--config", config] if config else []


def apply_scan_options(args: argparse.Namespace, internal) -> set:
    """Apply the options this invocation passed onto the internal namespace.

    The internal namespace carries the environment-backed defaults and the
    TOML file's values, and the explicitly passed options win over both.
    Returns the internal dests the command line set. ``config show`` performs
    the same step to name "command line" as a value's source.
    """
    applied = set()
    for dest, value in vars(args).items():
        if dest in _NOT_INTERNAL_DESTS:
            continue
        internal_dest = _SCAN_TO_INTERNAL_DESTS.get(dest, dest)
        if hasattr(internal, internal_dest):
            setattr(internal, internal_dest, value)
            applied.add(internal_dest)
    return applied


def scan_namespace(args: argparse.Namespace, *, resolution=None) -> argparse.Namespace:
    """Build the internal namespace for the scan these arguments describe.

    The internal parser supplies the environment-backed defaults and the TOML
    file's values, the resolved checks and profile settings land on their
    internal dests, the explicitly passed options are applied on top of them
    (they win over every profile and check setting), and the ``--exclude-type``
    values are parsed onto the internal ``exclude_types`` list. Nothing
    downstream reads the v7 names.
    """
    internal = build_parser().parse_args(internal_argv(args))
    if resolution is None:
        resolution = checks_table.resolve(args)
    for dest, value in resolution.options.items():
        setattr(internal, dest, value)
    apply_scan_options(args, internal)
    _apply_excluded_types(args, internal)
    _append_check_lists(internal, resolution)
    if "license" in resolution.checks:
        # The license analysis turns on through this environment variable,
        # exactly as v6's ``-t license`` set it in finalize_setup. Appending
        # the pseudo type alone reaches only source scans: a BOM, BOM
        # directory or purl scan never reads the project types, and the
        # licenses stage consults this variable directly.
        os.environ["FETCH_LICENSE"] = "true"
    return internal


def _apply_excluded_types(args: argparse.Namespace, internal) -> None:
    """Parse the repeatable, comma-separated ``--exclude-type`` values."""
    raw = getattr(args, "exclude_types", None)
    if raw is None:
        return
    if isinstance(raw, str):
        raw = [raw]
    parsed = [name.strip() for item in raw for name in str(item).split(",") if name.strip()]
    internal.exclude_types = list(dict.fromkeys(parsed))


def _append_check_lists(internal, resolution) -> None:
    """Append the check-added types and techniques after the explicit options.

    The license check appends the ``license`` pseudo type and the binary check
    the ``binary-analysis`` technique, also to a value the user passed, so an
    explicit ``--type`` never silently drops a requested check.
    """
    for project_type in resolution.append_project_types:
        if project_type not in internal.project_type:
            internal.project_type = [*internal.project_type, project_type]
    techniques = list(internal.techniques or [])
    for technique in resolution.append_techniques:
        if technique not in techniques:
            techniques.append(technique)
    internal.techniques = techniques or None


# --- the targets -----------------------------------------------------------------

#: Forced kinds with no inventory path in this version. Naming one through
#: ``--target-kind`` refuses the run whether or not targets were given;
#: detection can additionally find an iOS app on a ``.ipa`` file.
_UNSCANNABLE_FORCED_KINDS = ("ios", "firmware")


def _refuse_forced_kind(kind: str) -> None:
    """Log why a forced kind cannot be scanned in this version."""
    if kind == "firmware":
        LOG.error("Firmware targets have no inventory path in this version.")
        return
    mobile = doctor_lib.capability_unavailable_reason("mobile", {}, {})
    LOG.error("iOS targets need the mobile capability, which cannot scan them: %s", mobile)


def _resolve_targets(args: argparse.Namespace):
    """Detect every target's kind; returns ``(targets, skipped_code)``.

    ``targets`` is a list of ``(target, kind)`` pairs, or None when the whole
    run is refused (exit 4 for a kind this version cannot scan). Each
    detection is logged with its reason. A source target that does not exist
    is skipped with exit 1, so a multi-target run still scans the remaining
    targets.
    """
    forced = getattr(args, "target_kind", None)
    if forced in _UNSCANNABLE_FORCED_KINDS:
        _refuse_forced_kind(forced)
        return None, 4
    resolved = []
    skipped = 0
    for target in getattr(args, "targets", None) or []:
        if forced:
            kind, reason = forced, f"forced with --target-kind {forced}"
        else:
            kind, reason = detect_kind(target)
        if kind == "ios":
            mobile = doctor_lib.capability_unavailable_reason("mobile", {}, {})
            LOG.error(
                "The target %s is an iOS app, which the mobile capability cannot scan: %s",
                target,
                mobile,
            )
            return None, 4
        if kind == "source" and not os.path.exists(target):
            LOG.error("The source target '%s' does not exist.", target)
            skipped = 1
            continue
        LOG.info("Target %s: kind %s (%s)", target, kind, reason)
        resolved.append((target, kind))
    return resolved, skipped


def _capability_gate(args: argparse.Namespace, names):
    """Collect one doctor report when checks or a profile were requested.

    Each explicitly requested check whose doctor capability is
    not-implemented or unavailable stops the verb with exit 4 before any scan
    work. A check named next to ``all`` is explicitly requested and gated the
    same way, while the ``all`` expansion itself never gates: its unavailable
    checks become not-assessed entries instead. Without ``--checks`` and
    without ``--profile`` no report is collected here at all: the scan
    directory's own setup collects the one it records. Returns
    ``(report, exit_code)``; the report is the one the scans reuse.
    """
    profile_name = getattr(args, "profile", None)
    named = [name for name in names if name != checks_table.ALL_CHECKS]
    if not names and profile_name is None:
        return None, 0
    report = doctor_lib.doctor()
    if named:
        requested = named
    elif profile_name is not None:
        requested = list(checks_table.PROFILES[profile_name].checks)
    else:
        # Only the all expansion was requested.
        return report, 0
    tools = report.tools_by_name()
    for name in requested:
        capability = checks_table.CHECKS[name].capability
        if capability is None:
            continue
        reason = doctor_lib.capability_unavailable_reason(capability, tools, report.data)
        if reason:
            LOG.error("The %s check cannot run on this machine: %s", name, reason)
            return None, 4
    return report, 0


# --- the scans -------------------------------------------------------------------


def run(args: argparse.Namespace) -> int:
    """Run the scan verb; the process exit code.

    Usage errors (an unknown check name) exit 2, a kind this version cannot
    scan exits 4, and the exit code of the scans themselves is the highest of
    them: a scan that stopped early counts 1.
    """
    names = checks_table.parse_checks(getattr(args, "checks", None))
    unknown = checks_table.unknown_checks(names)
    if unknown:
        print(
            f"depscan scan: unknown check {', '.join(unknown)}; known checks: "
            f"{', '.join(checks_table.CHECK_NAMES)}",
            file=sys.stderr,
        )
        return 2
    targets, skipped = _resolve_targets(args)
    if targets is None:
        return skipped
    report, gate_code = _capability_gate(args, names)
    if gate_code:
        return gate_code
    resolution = checks_table.resolve(args, doctor_report=report)
    internal = scan_namespace(args, resolution=resolution)
    if args.format == "json":
        # The stdout console moves to stderr for the duration, so stdout
        # carries exactly one JSON document: the tables, the banner and the
        # logs all print on stderr instead. ``_file`` is None while the
        # console follows sys.stdout, and None is what the restore puts back:
        # pinning the current sys.stdout object instead would break under a
        # harness that replaces the stream between runs.
        internal.no_banner = True
        saved_file = console._file
        console.file = sys.stderr
        try:
            outcomes = _run_all_scans(args, internal, resolution, targets, report)
        finally:
            # Assigning the private attribute is deliberate: the public
            # setter's declared type does not accept None, and None is the
            # value that makes the console follow sys.stdout again.
            console._file = saved_file
    else:
        outcomes = _run_all_scans(args, internal, resolution, targets, report)
    exit_code = max([skipped, *(code for code, _, _ in outcomes)])
    if args.format == "json":
        _print_json_outcomes(outcomes)
    return exit_code


def _run_all_scans(args, internal, resolution, targets, doctor_report):
    """One scan per target; a single scan for zero or one target.

    Returns one ``(exit_code, reports_dir, result)`` per scan, where ``result``
    is the :class:`depscan.api.ScanResult` or None for a scan that stopped
    early. More than one target writes each scan into
    ``<reports-dir>/<n>-<name>/``, with ``n`` the target's 1-based index in
    the given list (a refused target leaves its directory unwritten but keeps
    the numbering); zero or one target uses ``--reports-dir`` as given.
    """
    base_reports_dir = internal.reports_dir
    given = list(getattr(args, "targets", None) or [])
    kinds = dict(targets or [])
    multiple = len(given) > 1
    outcomes = []
    for index, target in enumerate(given, start=1):
        kind = kinds.get(target)
        if kind is None:
            # A target the detection refused; it was already logged.
            continue
        options = argparse.Namespace(**vars(internal))
        _apply_target_options(options, target, kind, args, resolution)
        if multiple:
            options.reports_dir = os.path.join(
                base_reports_dir, f"{index}-{_target_directory_name(target)}"
            )
        outcomes.append(_scan_one(options, resolution, doctor_report))
    if not given:
        # Zero targets means the current directory, with the internal
        # default and no per-target override.
        outcomes.append(_scan_one(argparse.Namespace(**vars(internal)), resolution, doctor_report))
    return outcomes


def _apply_target_options(options, target: str, kind: str, args, resolution) -> None:
    """Land one target on the internal namespace's inventory paths."""
    if kind == "purl":
        options.search_purl = target
    elif kind == "bom":
        options.bom = target
    elif kind == "bom-dir":
        options.bom_dir = target
    else:
        # git, container, binary, android and source all scan through the
        # source directory or image argument.
        options.src_dir_image = target
    forced_type = _TARGET_PROJECT_TYPES.get(kind)
    if forced_type and not hasattr(args, "project_type"):
        # The kind names the inventory path, so it names the type too; the
        # check-added types (license) survive the replacement.
        appended = [ptype for ptype in resolution.append_project_types if ptype != forced_type]
        options.project_type = [forced_type, *appended]


def _scan_one(options, resolution, doctor_report):
    """Run one scan, reusing the gate's doctor report and recording the
    not-assessed checks; a stopped scan counts exit 1."""
    try:
        result = api.scan(
            options,
            doctor_report=doctor_report,
            checks_not_assessed=resolution.not_assessed or None,
        )
    except api.ScanError:
        # The stage already logged why the scan stopped.
        return (1, options.reports_dir, None)
    return (0, result.reports_dir, result)


def _target_directory_name(target: str) -> str:
    """The directory name a multi-target scan writes this target into.

    The basename for an existing path, otherwise the sanitized reference with
    ``/``, ``\\``, ``:`` and ``@`` replaced, truncated to 60 characters.
    """
    if os.path.exists(target):
        name = os.path.basename(target)
    else:
        name = _DIRECTORY_NAME_SEPARATORS.sub("-", target)
    return name[:60] or "target"


# --- the json output -------------------------------------------------------------


def _print_json_outcomes(outcomes) -> None:
    """Print one JSON document with every scan's result on stdout."""
    documents = [_outcome_document(reports_dir, result) for _, reports_dir, result in outcomes]
    print(json.dumps(documents[0] if len(documents) == 1 else documents, indent=2))


def _outcome_document(reports_dir: str, result):
    """One scan as a ``{"scanDir", "manifest", "findings"}`` document."""
    if result is not None:
        return {
            "scanDir": result.reports_dir,
            "manifest": result.manifest,
            "findings": result.findings,
        }
    # A scan that stopped early still wrote its manifest naming the failed
    # stage; no findings ever existed.
    return {"scanDir": reports_dir, "manifest": _read_manifest(reports_dir), "findings": []}


def _read_manifest(reports_dir: str):
    """The manifest a stopped scan wrote, or None when it wrote none."""
    path = os.path.join(reports_dir, "depscan.manifest.json")
    try:
        with open(path, encoding="utf-8") as fp:
            return json.load(fp)
    except (OSError, ValueError):
        return None
