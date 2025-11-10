import os
from depscan import get_version
from depscan.lib import tomlparse


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
        "--profile",
        default="generic",
        choices=(
            "appsec",
            "research",
            "operational",
            "threat-modeling",
            "license-compliance",
            "generic",
            "machine-learning",
            "ml",
            "deep-learning",
            "ml-deep",
            "ml-tiny",
        ),
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
        help="Perform package risk audit (slow operation). Npm only.",
    )
    parser.add_argument(
        "--cdxgen-args",
        default=os.getenv("CDXGEN_ARGS"),
        dest="cdxgen_args",
        help="Additional arguments to pass to cdxgen",
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
