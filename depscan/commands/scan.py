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
"""

import argparse
import sys

from analysis_lib.config import SUPPORTED_BOM_PROFILES

from depscan.cli_options import validate_spec_version

#: The checks a scan can run, as the ``--checks`` help lists them.
CHECK_NAMES = (
    "all",
    "vulnerabilities",
    "reachability",
    "license",
    "supply-chain",
    "binary",
    "memory-safety",
    "mobile",
    "code",
    "crypto",
)

#: The scan profiles, as the ``--profile`` help lists them.
PROFILE_NAMES = ("quick", "ci", "deep", "research", "offline")

TARGET_KINDS = (
    "purl",
    "git",
    "container",
    "bom",
    "bom-dir",
    "binary",
    "android",
    "ios",
    "source",
)


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
        choices=TARGET_KINDS,
        default=argparse.SUPPRESS,
        help="Force the kind of every target instead of detecting it.",
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


def run(args: argparse.Namespace) -> int:
    print("the scan verb lands in the next piece", file=sys.stderr)
    return 2
