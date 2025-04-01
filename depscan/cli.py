#!/usr/bin/env python3 -W ignore::DeprecationWarning
# -*- coding: utf-8 -*-

import contextlib
import json
import os
import sys
import tempfile

from analysis_lib import VdrOptions
from analysis_lib.csaf import export_csaf, write_toml
from analysis_lib.search import get_pkgs_by_scope
from analysis_lib.utils import (
    find_purl_usages,
    licenses_risk_table,
    pkg_risks_table,
    summary_stats,
)
from analysis_lib.vdr import VDRAnalyzer
from custom_json_diff.lib.utils import file_write, json_dump, json_load
from defusedxml.ElementTree import parse
from rich.panel import Panel
from rich.terminal_theme import DEFAULT_TERMINAL_THEME, MONOKAI
from vdb.lib import config
from vdb.lib import db6 as db_lib
from vdb.lib.utils import parse_purl

from depscan import get_version
from depscan.lib import explainer, tomlparse, utils
from depscan.lib.audit import audit, risk_audit, risk_audit_map, type_audit_map
from depscan.lib.bom import (
    create_bom,
    get_pkg_by_type,
    get_pkg_list,
)
from depscan.lib.config import (
    UNIVERSAL_SCAN_TYPE,
    VDB_AGE_HOURS,
    license_data_dir,
    pkg_max_risk_score,
    spdx_license_list,
    vdb_database_url,
)
from depscan.lib.license import build_license_data, bulk_lookup
from depscan.lib.logger import DEBUG, LOG, SPINNER, console

if sys.platform == "win32" and os.environ.get("PYTHONIOENCODING") is None:
    sys.stdin.reconfigure(encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

LOGO = """
██████╗ ███████╗██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗
██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║
██║  ██║█████╗  ██████╔╝███████╗██║     ███████║██╔██╗ ██║
██║  ██║██╔══╝  ██╔═══╝ ╚════██║██║     ██╔══██║██║╚██╗██║
██████╔╝███████╗██║     ███████║╚██████╗██║  ██║██║ ╚████║
╚═════╝ ╚══════╝╚═╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
"""

QUART_AVAILABLE = False
try:
    from quart import Quart, request

    app = Quart(__name__, static_folder=None)
    app.config.from_prefixed_env()
    app.config["PROVIDE_AUTOMATIC_OPTIONS"] = True
    QUART_AVAILABLE = True
except ImportError:
    pass

ORAS_AVAILABLE = False
try:
    from vdb.lib.orasclient import download_image

    ORAS_AVAILABLE = True
except ImportError:
    pass


def build_args():
    """
    Constructs command line arguments for the depscan tool
    """
    parser = build_parser()
    return parser.parse_args()


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
        help="Profile to use while generating the BOM.",
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
    parser.add_argument(
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
    parser.add_argument(
        "--bom",
        dest="bom",
        help="Examine using the given Software Bill-of-Materials (SBOM) file "
        "in CycloneDX format. Use cdxgen command to produce one.",
    )
    parser.add_argument(
        "--bom-dir",
        dest="bom_dir",
        help="Examine all the Bill-of-Materials (BOM) files in the given directory.",
    )
    parser.add_argument(
        "-i",
        "--src",
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
    parser.add_argument(
        "--explain",
        action="store_true",
        default=False,
        dest="explain",
        help="Makes depscan to explain the various analysis. Useful for "
        "creating detailed reports.",
    )
    parser.add_argument(
        "--reachables-slices-file",
        dest="reachables_slices_file",
        help="Path for the reachables slices file created by atom.",
    )
    parser.add_argument(
        "--purl",
        dest="search_purl",
        help="Scan a single package url.",
    )
    parser.add_argument(
        "-v",
        "--version",
        help="Display the version",
        action="version",
        version="%(prog)s " + get_version(),
    )
    return parser


def summarise(
    project_type,
    results,
    suggest_mode,
    scoped_pkgs,
    bom_file,
    pkg_list,
    no_vuln_table=False,
    direct_purls=None,
    reached_purls=None,
):
    """
    Method to summarise the results
    :param project_type: Project type
    :param results: Scan or audit results
    :param suggest_mode: Normalize fix versions automatically
    :param scoped_pkgs: Dict containing package scopes
    :param bom_file: BOM file
    :param pkg_list: Direct list of packages when the bom file is empty
    :param no_vuln_table: Boolean to indicate if the results should get printed
            to the console
    :param direct_purls: Dict of direct purls
    :param reached_purls: Dict of reached purls
    :return: A dict of vulnerability and severity summary statistics
    """
    options = VdrOptions(
        project_type,
        results,
        pkg_aliases={},
        purl_aliases={},
        suggest_mode=suggest_mode,
        scoped_pkgs=scoped_pkgs,
        no_vuln_table=no_vuln_table,
        bom_file=bom_file,
        pkg_list=pkg_list,
        direct_purls=direct_purls,
        reached_purls=reached_purls,
        console=console,
        logger=LOG,
    )
    pkg_vulnerabilities = []
    summary = {}
    vdr_result = VDRAnalyzer(vdr_options=options).process()
    vdr_file = bom_file.replace(".json", ".vdr.json") if bom_file else None
    if vdr_result.success:
        pkg_vulnerabilities = vdr_result.pkg_vulnerabilities
        if pkg_vulnerabilities and bom_file:
            if bom_data := json_load(bom_file, log=LOG):
                export_bom(bom_data, pkg_vulnerabilities, vdr_file)
            else:
                LOG.warning("Unable to generate VDR file for this scan.")
        summary = summary_stats(pkg_vulnerabilities)
    return summary, vdr_file, pkg_vulnerabilities


def summarise_tools(tools, bom_data):
    """
    Helper function to add depscan information as metadata
    :param tools: Tools section of the SBOM
    :param bom_data: SBOM data
    :return: None
    """
    components = tools.get("components", [])
    ds_version = get_version()
    ds_purl = f"pkg:pypi/owasp-depscan@{ds_version}"
    components.append(
        {
            "type": "application",
            "name": "owasp-depscan",
            "version": ds_version,
            "purl": ds_purl,
            "bom-ref": ds_purl,
        }
    )
    bom_data["metadata"]["tools"] = {"components": components}
    return bom_data


def export_bom(bom_data, pkg_vulnerabilities, vdr_file):
    """
    Exports the Bill of Materials (BOM) data along with package vulnerabilities
    to a Vulnerability Data Report (VDR) file.

    :param bom_data: SBOM data
    :param pkg_vulnerabilities: Package vulnerabilities
    :param vdr_file: VDR file path
    """
    # Add depscan information as metadata
    metadata = bom_data.get("metadata", {})
    tools = metadata.get("tools", {})
    bom_version = str(bom_data.get("version", 0))
    # Update the version
    if bom_version.isdigit():
        bom_data["version"] = int(bom_version) + 1
    # Update the tools section
    if isinstance(tools, dict):
        bom_data = summarise_tools(tools, bom_data)
    bom_data["vulnerabilities"] = pkg_vulnerabilities
    json_dump(
        vdr_file,
        bom_data,
        error_msg=f"Unable to generate VDR file at {vdr_file}",
        log=LOG,
    )


def set_project_types(args, src_dir):
    """
    Detects the project types and perform the right type of scan

    :param args: cli arguments
    :param src_dir: source directory

    :return: A tuple containing the package list, the parsed package URL object,
    and the list of project types.
    """
    pkg_list, purl_obj = [], {}
    if args.search_purl:
        purl_obj = parse_purl(args.search_purl)
        purl_obj["purl"] = args.search_purl
        purl_obj["vendor"] = purl_obj.get("namespace")
        project_types_list = [purl_obj.get("type")]
        pkg_list = [purl_obj]
    elif args.bom:
        project_types_list = ["bom"]
    elif args.project_type:
        project_types_list = (
            args.project_type
            if isinstance(args.project_type, list)
            else args.project_type.split(",")
        )
        if len(project_types_list) == 1 and "," in project_types_list[0]:
            project_types_list = project_types_list[0].split(",")
    elif not args.non_universal_scan:
        project_types_list = [UNIVERSAL_SCAN_TYPE]
    else:
        project_types_list = utils.detect_project_type(src_dir)
    return pkg_list, project_types_list


if QUART_AVAILABLE:

    @app.get("/")
    async def index():
        """

        :return: An empty dictionary
        """
        return {}

    @app.get("/download-vdb")
    async def download_vdb():
        """

        :return: a JSON response indicating the status of the caching operation.
        """
        if db_lib.needs_update(days=0, hours=VDB_AGE_HOURS, default_status=False):
            if not ORAS_AVAILABLE:
                return {
                    "error": "true",
                    "message": "The oras package must be installed to automatically download the vulnerability database. Install depscan using `pip install owasp-depscan[all]` or use the official container image.",
                }
            if download_image(vdb_database_url, config.DATA_DIR):
                return {
                    "error": "false",
                    "message": "vulnerability database downloaded successfully",
                }
            return {
                "error": "true",
                "message": "vulnerability database did not get downloaded correctly. Check the server logs.",
            }
        return {
            "error": "false",
            "message": "vulnerability database already exists",
        }

    @app.route("/scan", methods=["GET", "POST"])
    async def run_scan():
        """
        :return: A JSON response containing the SBOM file path and a list of
        vulnerabilities found in the scanned packages
        """
        q = request.args
        params = await request.get_json()
        uploaded_bom_file = await request.files

        url = None
        path = None
        multi_project = None
        project_type = None
        results = []
        profile = "generic"
        deep = False
        suggest_mode = True if q.get("suggest") in ("true", "1") else False
        if q.get("url"):
            url = q.get("url")
        if q.get("path"):
            path = q.get("path")
        if q.get("multiProject"):
            multi_project = q.get("multiProject", "").lower() in ("true", "1")
        if q.get("deep"):
            deep = q.get("deep", "").lower() in ("true", "1")
        if q.get("type"):
            project_type = q.get("type")
        if q.get("profile"):
            profile = q.get("profile")
        if params is not None:
            if not url and params.get("url"):
                url = params.get("url")
            if not path and params.get("path"):
                path = params.get("path")
            if not multi_project and params.get("multiProject"):
                multi_project = params.get("multiProject", "").lower() in (
                    "true",
                    "1",
                )
            if not deep and params.get("deep"):
                deep = params.get("deep", "").lower() in (
                    "true",
                    "1",
                )
            if not project_type and params.get("type"):
                project_type = params.get("type")
            if not profile and params.get("profile"):
                profile = params.get("profile")

        if not path and not url and (uploaded_bom_file.get("file", None) is None):
            return {
                "error": "true",
                "message": "path or url or a bom file upload is required",
            }, 400
        if not project_type:
            return {"error": "true", "message": "project type is required"}, 400
        if db_lib.needs_update(days=0, hours=VDB_AGE_HOURS, default_status=False):
            return (
                {
                    "error": "true",
                    "message": "Vulnerability database is empty. Prepare the "
                    "vulnerability database by invoking /download-vdb endpoint "
                    "before running scans.",
                },
                500,
                {"Content-Type": "application/json"},
            )

        cdxgen_server = app.config.get("CDXGEN_SERVER_URL")
        bom_file_path = None

        if uploaded_bom_file.get("file", None) is not None:
            bom_file = uploaded_bom_file["file"]
            bom_file_content = bom_file.read().decode("utf-8")
            try:
                if str(bom_file.filename).endswith(".json"):
                    _ = json.loads(bom_file_content)
                else:
                    _ = parse(bom_file_content)
            except Exception as e:
                LOG.info(e)
                return (
                    {
                        "error": "true",
                        "message": "The uploaded file must be a valid JSON or XML.",
                    },
                    400,
                    {"Content-Type": "application/json"},
                )

            LOG.debug("Processing uploaded file")
            bom_file_suffix = str(bom_file.filename).rsplit(".", maxsplit=1)[-1]
            tmp_bom_file = tempfile.NamedTemporaryFile(
                delete=False, suffix=f".bom.{bom_file_suffix}"
            )
            path = tmp_bom_file.name
            file_write(path, bom_file_content)

        # Path points to a project directory
        # Bug# 233. Path could be a url
        if url or (path and os.path.isdir(path)):
            with tempfile.NamedTemporaryFile(delete=False, suffix=".bom.json") as bfp:
                project_type_list = project_type.split(",")
                bom_status = create_bom(
                    bfp.name,
                    path,
                    {
                        "url": url,
                        "path": path,
                        "project_type": project_type_list,
                        "multiProject": multi_project,
                        "cdxgen_server": cdxgen_server,
                        "profile": profile,
                        "deep": deep,
                    },
                )
                if bom_status:
                    LOG.debug("BOM file was generated successfully at %s", bfp.name)
                    bom_file_path = bfp.name

        # Path points to a SBOM file
        else:
            if os.path.exists(path):
                bom_file_path = path
        # Direct purl-based lookups are not supported yet.
        if bom_file_path is not None:
            pkg_list = get_pkg_list(bom_file_path)
            # Here we are assuming there will be only one type
            if project_type in type_audit_map:
                audit_results = audit(project_type, pkg_list)
                if audit_results:
                    results = results + audit_results
            if not pkg_list:
                LOG.debug("Empty package search attempted!")
            else:
                LOG.debug("Scanning %d oss dependencies for issues", len(pkg_list))
            # TODO: invoke find_vuls from within VDRAnalyzer
            bom_data = json_load(bom_file_path)
            if not bom_data:
                return (
                    {
                        "error": "true",
                        "message": "Unable to generate SBOM. Check your input path or url.",
                    },
                    400,
                    {"Content-Type": "application/json"},
                )
            options = VdrOptions(
                project_type,
                results,
                pkg_aliases={},
                purl_aliases={},
                suggest_mode=suggest_mode,
                scoped_pkgs={},
                no_vuln_table=True,
                bom_file=bom_file_path,
                pkg_list=[],
                direct_purls={},
                reached_purls={},
                console=console,
                logger=LOG,
            )
            vdr_result = VDRAnalyzer(vdr_options=options).process()
            if vdr_result.success:
                pkg_vulnerabilities = vdr_result.pkg_vulnerabilities
                if pkg_vulnerabilities:
                    bom_data["vulnerabilities"] = pkg_vulnerabilities
                return json.dumps(bom_data), 200, {"Content-Type": "application/json"}
        return (
            {
                "error": "true",
                "message": "Unable to generate SBOM. Check your input path or url.",
            },
            500,
            {"Content-Type": "application/json"},
        )

    def run_server(args):
        """
        Run depscan as server

        :param args: Command line arguments passed to the function.
        """
        print(LOGO)
        console.print(
            f"Depscan server running on {args.server_host}:{args.server_port}"
        )
        app.config["CDXGEN_SERVER_URL"] = args.cdxgen_server
        app.run(
            host=args.server_host,
            port=args.server_port,
            debug=os.getenv("SCAN_DEBUG_MODE") == "debug",
            use_reloader=False,
        )


def run_depscan(args):
    """
    Detects the project type, performs various scans and audits,
    and generates reports based on the results.
    """
    depscan_options = {**vars(args)}
    perform_risk_audit = args.risk_audit
    # declare variables that get initialized only conditionally
    (
        summary,
        vdr_file,
        bom_file,
        pkg_list,
        pkg_vulnerabilities,
        pkg_group_rows,
    ) = (None, None, None, None, None, None)
    if (
        os.getenv("CI")
        and not os.getenv("GITHUB_REPOSITORY", "").lower().startswith("owasp")
        and not args.no_banner
        and not os.getenv("INPUT_THANK_YOU", "") == "I have sponsored OWASP-dep-scan."
    ):
        console.print(
            Panel(
                "OWASP foundation relies on donations to fund our projects.\nPlease donate at: https://owasp.org/donate/?reponame=www-project-dep-scan&title=OWASP+depscan",
                title="Donate to the OWASP Foundation",
                expand=False,
            )
        )
    # Should we turn on the debug mode
    if args.enable_debug:
        os.environ["SCAN_DEBUG_MODE"] = "debug"
        os.environ["CDXGEN_DEBUG_MODE"] = "debug"
        LOG.setLevel(DEBUG)
    if args.server_mode:
        if QUART_AVAILABLE:
            return run_server(args)
        else:
            LOG.info(
                "The required packages for server mode are unavailable. Reinstall depscan using `pip install owasp-depscan[all]`."
            )
            return False
    if not args.no_banner:
        with contextlib.suppress(UnicodeEncodeError):
            print(LOGO)
    src_dir = args.src_dir_image
    if not src_dir or src_dir == ".":
        if src_dir == "." or args.search_purl:
            src_dir = os.getcwd()
        # Try to infer from the bom file
        elif args.bom and os.path.exists(args.bom):
            src_dir = os.path.dirname(os.path.realpath(args.bom))
        else:
            src_dir = os.getcwd()
    reports_dir = args.reports_dir
    # Should we download the latest vdb.
    if db_lib.needs_update(
        days=0,
        hours=VDB_AGE_HOURS,
        default_status=db_lib.get_db_file_metadata is not None,
    ):
        if ORAS_AVAILABLE:
            with console.status(
                f"Downloading the latest vulnerability database to {config.DATA_DIR}. Please wait ...",
                spinner=SPINNER,
            ):
                # This line may exit with an exception if the database cannot be downloaded.
                # Example: urllib3.exceptions.IncompleteRead, urllib3.exceptions.ProtocolError, requests.exceptions.ChunkedEncodingError
                download_image(vdb_database_url, config.DATA_DIR)
        else:
            LOG.warning(
                "The latest vulnerability database is not found. Follow the documentation to manually download it."
            )
    if args.csaf:
        toml_file_path = os.getenv(
            "DEPSCAN_CSAF_TEMPLATE", os.path.join(src_dir, "csaf.toml")
        )
        if not os.path.exists(toml_file_path):
            LOG.info("CSAF toml not found, creating template in %s", src_dir)
            write_toml(toml_file_path)
            LOG.info("Please fill out the toml with your details and rerun depscan.")
            LOG.info(
                "Check out our CSAF documentation for an explanation of "
                "this feature. https://github.com/owasp-dep-scan/dep-scan"
                "/blob/master/contrib/CSAF_README.md"
            )
            LOG.info(
                "If you're just checking out how our generator works, "
                "feel free to skip filling out the toml and just rerun "
                "depscan."
            )
            sys.exit(0)
    pkg_list, project_types_list = set_project_types(args, src_dir)
    if args.search_purl:
        # Automatically enable risk audit for single purl searches
        perform_risk_audit = True
    areport_file = os.path.join(reports_dir, "depscan.json")
    html_file = areport_file.replace(".json", ".html")
    pdf_file = areport_file.replace(".json", ".pdf")
    # Create reports directory
    if reports_dir and not os.path.exists(reports_dir):
        os.makedirs(reports_dir, exist_ok=True)
    if len(project_types_list) > 1:
        LOG.debug("Multiple project types found: %s", project_types_list)
    # Enable license scanning
    if "license" in project_types_list or "license" in args.profile:
        os.environ["FETCH_LICENSE"] = "true"
        project_types_list.remove("license")
        console.print(
            Panel(
                "License audit is enabled for this scan. This would increase "
                "the time by up to 10 minutes.",
                title="License Audit",
                expand=False,
            )
        )
    for project_type in project_types_list:
        results = []
        report_file = areport_file.replace(".json", f"-{project_type}.json")
        risk_report_file = areport_file.replace(".json", f"-risk.{project_type}.json")
        # Are we scanning a single purl
        if args.search_purl:
            bom_file = None
            creation_status = True
        # Are we scanning a bom file
        elif args.bom and os.path.exists(args.bom):
            bom_file = args.bom
            creation_status = True
        else:
            if args.profile in ("appsec", "research"):
                # The bom file has to be called bom.json for atom reachables :(
                bom_file = os.path.join(src_dir, "bom.json")
            else:
                bom_file = report_file.replace("depscan-", "sbom-")
            creation_status = create_bom(
                bom_file, src_dir, {**depscan_options, "project_type": [project_type]}
            )
        if not creation_status:
            LOG.warning(
                "The BOM file `%s` was not created successfully. Set the `SCAN_DEBUG_MODE=debug` environment variable to troubleshoot.",
                bom_file,
            )
            continue
        if bom_file:
            LOG.debug("Scanning using the bom file %s", bom_file)
            if not args.bom:
                LOG.info(
                    "To improve performance, cache the bom file and invoke "
                    "depscan with --bom %s instead of -i",
                    bom_file,
                )
            pkg_list = get_pkg_list(bom_file)
        if not pkg_list:
            LOG.info(
                "No packages were found in the project. Try generating the BOM manually or use the `CdxgenImageBasedGenerator` engine."
            )
            continue
        scoped_pkgs = get_pkgs_by_scope(pkg_list)
        if (
            os.getenv("FETCH_LICENSE", "") in (True, "1", "true")
            or "license" in args.profile
        ):
            licenses_results = bulk_lookup(
                build_license_data(license_data_dir, spdx_license_list),
                pkg_list=pkg_list,
            )
            license_report_file = os.path.join(
                reports_dir, f"license-{project_type}.json"
            )
            ltable = licenses_risk_table(
                project_type, licenses_results, license_report_file
            )
            if ltable and not args.no_vuln_table:
                console.print(ltable)
        if project_type in risk_audit_map:
            if perform_risk_audit:
                if len(pkg_list) > 1:
                    console.print(
                        Panel(
                            f"Performing OSS Risk Audit for packages from "
                            f"{src_dir}\nNo of packages [bold]{len(pkg_list)}"
                            f"[/bold]. This will take a while ...",
                            title="OSS Risk Audit",
                            expand=False,
                        )
                    )
                try:
                    risk_results = risk_audit(
                        project_type,
                        scoped_pkgs,
                        args.private_ns,
                        pkg_list,
                    )
                    rtable = pkg_risks_table(
                        project_type,
                        scoped_pkgs,
                        risk_results,
                        pkg_max_risk_score=pkg_max_risk_score,
                        risk_report_file=risk_report_file,
                    )
                    if not args.no_vuln_table:
                        console.print(rtable)
                except Exception as e:
                    LOG.error(e)
                    LOG.error("Risk audit was not successful")
            else:
                console.print(
                    Panel(
                        "Depscan supports OSS Risk audit for this "
                        "project.\nTo enable set the environment variable ["
                        "bold]ENABLE_OSS_RISK=true[/bold]",
                        title="Risk Audit Capability",
                        expand=False,
                    )
                )
        if project_type in type_audit_map:
            LOG.debug(
                "Performing remote audit for %s of type %s",
                src_dir,
                project_type,
            )
            LOG.debug("No of packages %d", len(pkg_list))
            try:
                audit_results = audit(project_type, pkg_list)
                if audit_results:
                    LOG.debug("Remote audit yielded %d results", len(audit_results))
                    results = results + audit_results
            except Exception as e:
                LOG.error("Remote audit was not successful")
                LOG.error(e)
                results = []
        # In case of docker, bom, or universal type, check if there are any
        # npm packages that can be audited remotely
        if project_type in (
            "podman",
            "docker",
            "oci",
            "container",
            "bom",
            "universal",
        ):
            npm_pkg_list = get_pkg_by_type(pkg_list, "npm")
            if npm_pkg_list:
                LOG.debug("No of npm packages %d", len(npm_pkg_list))
                try:
                    audit_results = audit("nodejs", npm_pkg_list)
                    if audit_results:
                        LOG.debug(
                            "Remote audit yielded %d results",
                            len(audit_results),
                        )
                        results = results + audit_results
                except Exception as e:
                    LOG.error("Remote audit was not successful")
                    LOG.error(e)
        else:
            LOG.debug("Vulnerability database loaded from %s", config.VDB_BIN_FILE)
        if len(pkg_list) > 1:
            if args.bom:
                LOG.info(
                    "Scanning %s with type %s",
                    args.bom,
                    project_type,
                )
            else:
                LOG.info(
                    "Scanning %s with type %s",
                    src_dir,
                    project_type,
                )
        if not pkg_list:
            LOG.debug("Empty package search attempted!")
        else:
            LOG.debug("Scanning %d oss dependencies for issues", len(pkg_list))
        direct_purls, reached_purls = find_purl_usages(
            bom_file, src_dir, args.reachables_slices_file
        )
        # Summarise and print results
        summary, vdr_file, pkg_vulnerabilities = summarise(
            project_type,
            results,
            suggest_mode=args.suggest,
            scoped_pkgs=scoped_pkgs,
            bom_file=bom_file,
            pkg_list=pkg_list,
            no_vuln_table=args.no_vuln_table,
            direct_purls=direct_purls,
            reached_purls=reached_purls,
        )
        # Explain the results
        if args.explain:
            explainer.explain(
                project_type,
                src_dir,
                args.reachables_slices_file,
                vdr_file,
                pkg_vulnerabilities,
                pkg_group_rows,
                direct_purls,
                reached_purls,
            )
        # CSAF VEX export
        if args.csaf:
            export_csaf(
                pkg_vulnerabilities,
                src_dir,
                reports_dir,
                bom_file,
            )
    console.save_html(
        html_file,
        theme=(MONOKAI if os.getenv("USE_DARK_THEME") else DEFAULT_TERMINAL_THEME),
    )
    utils.export_pdf(html_file, pdf_file)
    # render report into template if wished
    if args.report_template and os.path.isfile(args.report_template):
        utils.render_template_report(
            vdr_file=vdr_file,
            bom_file=bom_file,
            pkg_vulnerabilities=pkg_vulnerabilities,
            pkg_group_rows=pkg_group_rows,
            summary=summary,
            template_file=args.report_template,
            result_file=os.path.join(reports_dir, args.report_name),
        )
    elif args.report_template:
        LOG.warning(
            "Template file %s doesn't exist, custom report not created.",
            args.report_template,
        )


def main():
    cli_args = build_args()
    run_depscan(cli_args)


if __name__ == "__main__":
    main()
