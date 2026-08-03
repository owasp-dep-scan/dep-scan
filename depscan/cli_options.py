import argparse
import os

from analysis_lib.config import SUPPORTED_BOM_PROFILES

from depscan import get_version
from depscan.lib import tomlparse

# CycloneDX spec versions depscan can request from cdxgen. Mirrors cdxgen's
# --spec-version choices. Defaults to 1.6 because Dependency-Track and several
# other consumers do not yet support 1.7.
SUPPORTED_SPEC_VERSIONS = ("1.4", "1.5", "1.6", "1.7", "2.0")
DEFAULT_SPEC_VERSION = "1.6"


def validate_spec_version(value):
    """Validate/normalize a CycloneDX spec version like cdxgen does.

    Accepts numeric or string forms (e.g. ``1.6``, ``"1.6"``, ``2``) and
    returns the canonical ``major.minor`` string. Raises
    ``argparse.ArgumentTypeError`` for anything outside the supported set.
    """
    try:
        canonical = f"{float(str(value).strip()):.1f}"
    except (TypeError, ValueError):
        canonical = None
    if canonical not in SUPPORTED_SPEC_VERSIONS:
        raise argparse.ArgumentTypeError(
            f"Invalid CycloneDX spec version '{value}'. "
            f"Supported versions: {', '.join(SUPPORTED_SPEC_VERSIONS)}."
        )
    return canonical


def build_parser():
    parser = tomlparse.ArgumentParser(
        description="Fully open-source security and license audit for "
        "application dependencies and container images based on "
        "known vulnerabilities and advisories.",
        epilog="Visit https://github.com/owasp-dep-scan/dep-scan to learn more",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        default=False,
        dest="no_banner",
        help="Do not display the logo and donation banner. Please make a donation to OWASP before using this argument.",
    )
    parser.add_argument(
        "-i",
        "--src",
        default=os.getenv("DEPSCAN_SOURCE_DIR_IMAGE", os.getcwd()),
        dest="src_dir_image",
        help="Source directory or container image or binary file",
    )
    parser.add_argument(
        "-o",
        "--reports-dir",
        default=os.getenv("DEPSCAN_REPORTS_DIR", os.path.join(os.getcwd(), "reports")),
        dest="reports_dir",
        help="Reports directory",
    )
    parser.add_argument(
        "--csaf",
        action="store_true",
        default=False,
        dest="csaf",
        help="Generate a OASIS CSAF VEX document",
    )
    parser.add_argument(
        "--csaf-version",
        default="2.1",
        choices=("2.0", "2.1"),
        dest="csaf_version",
        help="CSAF schema version to target (default: 2.1). CSAF 2.1 retains "
        "CVSS v4 scores; 2.0 drops them because the schema has no cvss_v4 slot.",
    )
    parser.add_argument(
        "--profile",
        default="generic",
        choices=SUPPORTED_BOM_PROFILES,
        dest="profile",
        help="Profile to use while generating the BOM. For granular control, use the arguments --bom-engine, --vulnerability-analyzer, or --reachability-analyzer.",
    )
    parser.add_argument(
        "--lifecycle",
        choices=("pre-build", "build", "post-build"),
        nargs="+",
        type=str,
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
        default="auto",
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
        default="auto",
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
        default="FrameworkReachability",
        dest="reachability_analyzer",
        help="Reachability analyzer to use. Default FrameworkReachability.",
    )
    parser.add_argument(
        "--rust-analyzer-backend",
        choices=("stable", "compiler"),
        default=os.getenv("DEPSCAN_RUSI_BACKEND", "stable"),
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
        default=os.getenv("DEPSCAN_GO_ANALYZER_NETWORK", "auto"),
        dest="go_analyzer_network",
        help="Network mode for golem (Go Source Inspector) reachability. "
        "``auto`` (default) allows golem's package loader to download missing "
        "modules per the user's Go env (GOFLAGS=-mod=readonly is still set to "
        "prevent go.mod rewrites). ``offline`` sets GOPROXY=off to forbid all "
        "downloads -- requires a warm module cache (GOMODCACHE). "
        "Set DEPSCAN_GOLEM_BINARY to point at a non-PATH golem binary.",
    )
    parser.add_argument(
        "--dotnet-analyzer-mode",
        choices=("source", "assembly", "auto"),
        default=os.getenv("DEPSCAN_DOTNET_ANALYZER_MODE", "auto"),
        dest="dotnet_analyzer_mode",
        help="dosai (Dotnet Source and Assembly Inspector) analysis mode for "
        ".NET reachability. ``auto`` (default) inspects source when a source "
        "tree is present and falls back to assembly inspection for bin/.nupkg-"
        "only inputs. ``source`` forces Roslyn-based C#/VB/F#/R source "
        "inspection; ``assembly`` forces Reflection-based .dll/.exe inspection. "
        "Pattern packs default to ``all``. dosai requires a .NET runtime (or a "
        "self-contained ``-full`` binary). Set DOSAI_CMD to point at a non-PATH "
        "dosai binary. dep-scan does NOT run ``dotnet restore``; a restored tree "
        "yields the best versioned NuGet purls.",
    )
    parser.add_argument(
        "--no-suggest",
        action="store_false",
        default=True,
        dest="suggest",
        help="Disable suggest mode",
    )
    parser.add_argument(
        "--risk-audit",
        action="store_true",
        default=os.getenv("ENABLE_OSS_RISK", "") in ("true", "1"),
        dest="risk_audit",
        help="Perform package risk audit (slow operation). Supported for npm, pypi, and cargo.",
    )
    parser.add_argument(
        "--cdxgen-args",
        default=os.getenv("CDXGEN_ARGS"),
        dest="cdxgen_args",
        help="Additional arguments to pass to cdxgen",
    )
    parser.add_argument(
        "--spec-version",
        type=validate_spec_version,
        default=validate_spec_version(os.getenv("CDX_SPEC_VERSION", DEFAULT_SPEC_VERSION)),
        dest="spec_version",
        help="CycloneDX specification version to request from cdxgen. "
        f"Choices: {', '.join(SUPPORTED_SPEC_VERSIONS)}. Defaults to "
        f"{DEFAULT_SPEC_VERSION} (1.7 is not yet supported by Dependency-Track "
        "and some other consumers).",
    )
    parser.add_argument(
        "--private-ns",
        dest="private_ns",
        default=os.getenv("PKG_PRIVATE_NAMESPACE"),
        help="Private namespace to use while performing oss risk audit. "
        "Private packages should not be available in public registries "
        "by default. Comma separated values accepted.",
    )
    parser.add_argument(
        "-t",
        "--type",
        nargs="+",
        type=str,
        dest="project_type",
        default=os.getenv("DEPSCAN_PROJECT_TYPE", "universal").split(","),
        help="Override project types if auto-detection is incorrect. Multiple values supported.",
    )
    bom_group = parser.add_mutually_exclusive_group(required=False)
    bom_group.add_argument(
        "--bom",
        dest="bom",
        help="Examine using the given Software Bill-of-Materials (SBOM) file "
        "in CycloneDX format. Use cdxgen command to produce one.",
    )
    bom_group.add_argument(
        "--bom-dir",
        dest="bom_dir",
        help="Examine all the Bill-of-Materials (BOM) files in the given directory.",
    )
    bom_group.add_argument(
        "--purl",
        dest="search_purl",
        help="Scan a single package url.",
    )
    parser.add_argument(
        "--custom-data",
        dest="custom_data",
        help="Path to directory containing custom vulnerability data (JSON/YAML/TOML) to override/augment results.",
    )
    parser.add_argument(
        "--report-template",
        dest="report_template",
        help="Jinja template file used for rendering a custom report",
    )
    parser.add_argument(
        "--report-name",
        default="rendered.report",
        dest="report_name",
        help="Filename of the custom report written to the --reports-dir",
    )
    parser.add_argument(
        "--deep",
        action="store_true",
        default=False,
        dest="deep_scan",
        help="Perform deep scan by passing this --deep argument to cdxgen. "
        "Useful while scanning docker images and OS packages.",
    )
    parser.add_argument(
        "--fuzzy-search",
        action="store_true",
        default=False,
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
        default="pcu",
        dest="search_order",
        help="Attributes to use while searching for vulnerabilities. Default: PURL, CPE, URL (pcu).",
    )
    parser.add_argument(
        "--severity",
        choices=("low", "medium", "high", "critical"),
        default=os.getenv("DEPSCAN_SEVERITY"),
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
        default=False,
        dest="malware_only",
        help="Report only malware advisories (MAL-*). Works on the default vdb "
        "because is_malware is always populated via the MAL- fallback.",
    )
    vdb_group = parser.add_argument_group(
        "vulnerability database selection",
        "Select which published vdb image the scan downloads. These can also be "
        'persisted in the depscan config file (e.g. vdb_scope = "app"). An '
        "explicit VDB_DATABASE_URL env pin always wins. The dedicated "
        "`depscan-vdb` command shares the same options for pre-fetching.",
    )
    vdb_group.add_argument(
        "--vdb-scope",
        choices=("app", "app+os"),
        default=None,
        dest="vdb_scope",
        help="Database scope. 'app' carries only application vulnerabilities; "
        "'app+os' adds OS distro data. Default: app+os.",
    )
    vdb_group.add_argument(
        "--vdb-time",
        choices=("2y", "default", "10y"),
        default=None,
        dest="vdb_time",
        help="Time window. '2y' covers 2024+, 'default' covers 2020+, '10y' "
        "covers 2016+. Default: default.",
    )
    vdb_group.add_argument(
        "--vdb-extended",
        action="store_true",
        default=None,
        dest="vdb_extended",
        help="Download the extended variant with metadata tables populated "
        "(needed for severity, text, alias, reference, symbol, and date search). "
        "Auto-selected when --severity is set.",
    )
    vdb_group.add_argument(
        "--vdb-compression",
        choices=("xz", "zst"),
        default=None,
        dest="vdb_compression",
        help="Compression format. 'xz' (tar.xz) is smaller; 'zst' (zstd) is "
        "faster to decompress. Default: xz.",
    )
    vdb_group.add_argument(
        "--vdb-distro",
        choices=("alpine", "debian", "redhat", "alma", "rocky", "ubuntu"),
        default=None,
        dest="vdb_distro",
        help="Use a distro-only database. Mutually exclusive with the scope, "
        "time, and extended options.",
    )
    vdb_group.add_argument(
        "--vdb-image",
        default=None,
        dest="vdb_image",
        help="Override the vdb image URL verbatim (bypasses the resolver). "
        "Equivalent to setting VDB_DATABASE_URL.",
    )
    parser.add_argument(
        "--no-universal",
        action="store_true",
        default=False,
        dest="non_universal_scan",
        help="Depscan would attempt to perform a single universal scan "
        "instead of individual scans per language type.",
    )
    parser.add_argument(
        "--no-vuln-table",
        action="store_true",
        default=False,
        dest="no_vuln_table",
        help="Do not print the table with the full list of vulnerabilities. "
        "This can help reduce console output.",
    )
    parser.add_argument(
        "--server",
        action="store_true",
        default=False,
        dest="server_mode",
        help="Run depscan as a server",
    )
    parser.add_argument(
        "--server-host",
        default=os.getenv("DEPSCAN_HOST", "127.0.0.1"),
        dest="server_host",
        help="depscan server host",
    )
    parser.add_argument(
        "--server-port",
        default=os.getenv("DEPSCAN_PORT", "7070"),
        dest="server_port",
        help="depscan server port",
    )
    parser.add_argument(
        "--server-allowed-hosts",
        nargs="*",
        help="List of allowed hostnames or IPs that can access the server (e.g., 'localhost 192.168.1.10'). If unspecified, no host allowlist is enforced.",
        default=None,
    )

    parser.add_argument(
        "--server-allowed-paths",
        nargs="*",
        help="List of allowed filesystem paths that can be scanned by the server. Restricts `path` parameter in /scan requests.",
        default=None,
    )
    parser.add_argument(
        "--cdxgen-server",
        default=os.getenv("CDXGEN_SERVER_URL"),
        dest="cdxgen_server",
        help="cdxgen server url. Eg: http://cdxgen:9090",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        default=False,
        dest="enable_debug",
        help="Run depscan in debug mode.",
    )
    output_group = parser.add_mutually_exclusive_group(required=False)
    output_group.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        default=False,
        dest="quiet",
        help="Makes depscan quiet.",
    )
    output_group.add_argument(
        "--explain",
        action="store_true",
        default=False,
        dest="explain",
        help="Makes depscan to explain the various analysis. Useful for creating detailed reports.",
    )
    parser.add_argument(
        "--explanation-mode",
        choices=(
            "Endpoints",
            "EndpointsAndReachables",
            "NonReachables",
            "LLMPrompts",
        ),
        default="EndpointsAndReachables",
        dest="explanation_mode",
        help="Style of explanation needed. Defaults to Endpoints and Reachables.",
    )
    parser.add_argument(
        "--annotate",
        action="store_true",
        default=False,
        dest="annotate",
        help="Include the generated text VDR report as an annotation. Defaults to true when explain is enabled; false otherwise.",
    )
    parser.add_argument(
        "-v",
        "--version",
        help="Display the version",
        action="version",
        version="%(prog)s " + get_version(),
    )
    return parser
