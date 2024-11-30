#!/usr/bin/env python3 -W ignore::DeprecationWarning
# -*- coding: utf-8 -*-

import argparse
import contextlib
import json
import os
import sys
import tempfile

from custom_json_diff.lib.utils import json_load, json_dump, file_write
from defusedxml.ElementTree import parse
from quart import Quart, request
from rich.panel import Panel
from rich.terminal_theme import DEFAULT_TERMINAL_THEME, MONOKAI
from vdb.lib import config
from vdb.lib import db6 as db_lib
from vdb.lib.gha import GitHubSource
from vdb.lib.nvd import NvdSource
from vdb.lib.osv import OSVSource
from vdb.lib.utils import parse_purl

from depscan import get_version
from depscan.lib import explainer, github
from depscan.lib.utils import utils
from depscan.lib.analysis import (
    PrepareVdrOptions,
    analyse_licenses,
    analyse_pkg_risks,
    find_purl_usages,
    prepare_vdr,
    summary_stats,
)
from depscan.lib.audit import audit, risk_audit, risk_audit_map, type_audit_map
from depscan.lib.bom import (
    create_bom,
    get_pkg_by_type,
    get_pkg_list,
    submit_bom, set_bom_file_creation_status,
)
from depscan.lib.config import (
    UNIVERSAL_SCAN_TYPE,
    license_data_dir,
    spdx_license_list,
)
from depscan.lib.csaf import export_csaf, write_toml
from depscan.lib.license import build_license_data, bulk_lookup
from depscan.lib.logger import DEBUG, LOG, console
from depscan.lib.orasclient import download_image
from depscan.lib.utils.environment_utils import setup_debug, get_src_dir, csaf_toml_check, setup_license
from depscan.lib.utils.print_utils import sponsor_message, print_banner, caching_message, github_client_message

with contextlib.suppress(Exception):
    os.environ["PYTHONIOENCODING"] = "utf-8"
LOGO = """
██████╗ ███████╗██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗
██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║
██║  ██║█████╗  ██████╔╝███████╗██║     ███████║██╔██╗ ██║
██║  ██║██╔══╝  ██╔═══╝ ╚════██║██║     ██╔══██║██║╚██╗██║
██████╔╝███████╗██║     ███████║╚██████╗██║  ██║██║ ╚████║
╚═════╝ ╚══════╝╚═╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
"""


app = Quart(__name__, static_folder=None)
app.config.from_prefixed_env()
app.config["PROVIDE_AUTOMATIC_OPTIONS"] = True


def build_args():
    """
    Constructs command line arguments for the depscan tool
    """
    parser = build_parser()
    return parser.parse_args()


def build_parser():
    parser = argparse.ArgumentParser(
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
        "--cache",
        action="store_true",
        default=False,
        dest="cache",
        help="Cache vulnerability information in platform specific "
        "user_data_dir",
    )
    parser.add_argument(
        "--csaf",
        action="store_true",
        default=False,
        dest="csaf",
        help="Generate a OASIS CSAF VEX document",
    )
    parser.add_argument(
        "--sync",
        action="store_true",
        default=False,
        dest="sync",
        help="Sync to receive the latest vulnerability data. Should have "
        "invoked cache first.",
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
        ),
        dest="profile",
        help="Profile to use while generating the BOM.",
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
        "--binary-analysis",
        dest="binary_analysis",
        action="store_true",
        help="Enables binary SCA utilizing blint with default options"
    )
    parser.add_argument(
        "--blint-args",
        default=os.getenv("BLINT_ARGS"),
        dest="blint_args",
        help="Additional arguments to pass to blint"
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
        dest="project_type",
        default=os.getenv("DEPSCAN_PROJECT_TYPE"),
        help="Override project type if auto-detection is incorrect",
    )
    parser.add_argument(
        "--bom",
        dest="bom",
        help="Examine using the given Software Bill-of-Materials (SBOM) file "
        "in CycloneDX format. Use cdxgen command to produce one.",
    )
    parser.add_argument(
        "-i",
        "--src",
        dest="src_dir_image",
        help="Source directory or container image or binary file",
    )
    parser.add_argument(
        "-o",
        "--report_file",
        dest="report_file",
        help="DEPRECATED. Use reports directory since multiple files are "
        "created. Report filename with directory",
    )
    parser.add_argument(
        "--reports-dir",
        default=os.getenv(
            "DEPSCAN_REPORTS_DIR", os.path.join(os.getcwd(), "reports")
        ),
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
        "--no-error",
        action="store_true",
        default=False,
        dest="noerror",
        help="UNUSED: Continue on error to prevent build from breaking",
    )
    parser.add_argument(
        "--no-license-scan",
        action="store_true",
        default=False,
        dest="no_license_scan",
        help="UNUSED: dep-scan doesn't perform license scanning by default",
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
        "--threatdb-server",
        default=os.getenv("THREATDB_SERVER_URL"),
        dest="threatdb_server",
        help="ThreatDB server url. Eg: https://api.sbom.cx",
    )
    parser.add_argument(
        "--threatdb-username",
        default=os.getenv("THREATDB_USERNAME"),
        dest="threatdb_username",
        help="ThreatDB username",
    )
    parser.add_argument(
        "--threatdb-password",
        default=os.getenv("THREATDB_PASSWORD"),
        dest="threatdb_password",
        help="ThreatDB password",
    )
    parser.add_argument(
        "--threatdb-token",
        default=os.getenv("THREATDB_ACCESS_TOKEN"),
        dest="threatdb_token",
        help="ThreatDB token for token based submission",
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


# Deprecated
def scan(project_type, pkg_list):
    """
    Method to search packages in our vulnerability database

    :param project_type: Project Type
    :param pkg_list: List of packages
    :returns: A list of package issue objects or dictionaries.
              A dictionary mapping package names to their aliases.
              A dictionary mapping packages to their suggested fix versions.
              A dictionary mapping package URLs to their aliases.
    """
    if not pkg_list:
        LOG.debug("Empty package search attempted!")
    else:
        LOG.debug("Scanning %d oss dependencies for issues", len(pkg_list))
    results, pkg_aliases, purl_aliases = utils.search_pkgs(project_type, pkg_list)
    return results, pkg_aliases, purl_aliases


def summarise(
    project_type,
    results,
    pkg_aliases,
    purl_aliases,
    suggest_mode,
    scoped_pkgs,
    report_file,
    bom_file,
    no_vuln_table=False,
    direct_purls=None,
    reached_purls=None,
):
    """
    Method to summarise the results
    :param project_type: Project type
    :param results: Scan or audit results
    :param pkg_aliases: Package aliases used
    :param purl_aliases: Package URL to package name aliases
    :param scoped_pkgs: Dict containing package scopes
    :param report_file: Output report file
    :param bom_file: SBOM file
    :param no_vuln_table: Boolean to indicate if the results should get printed
            to the console
    :param direct_purls: Dict of direct purls
    :param reached_purls: Dict of reached purls
    :return: A dict of vulnerability and severity summary statistics
    """
    options = PrepareVdrOptions(
        project_type,
        results,
        pkg_aliases,
        purl_aliases,
        suggest_mode,
        scoped_pkgs=scoped_pkgs,
        no_vuln_table=no_vuln_table,
        bom_file=bom_file,
        direct_purls=direct_purls,
        reached_purls=reached_purls,
    )
    pkg_vulnerabilities, pkg_group_rows = prepare_vdr(options)
    vdr_file = bom_file.replace(".json", ".vdr.json") if bom_file else None
    if pkg_vulnerabilities and bom_file:
        if bom_data := json_load(bom_file, log=LOG):
            export_bom(bom_data, pkg_vulnerabilities, vdr_file)
        else:
            LOG.warning("Unable to generate VDR file for this scan.")
    summary = summary_stats(pkg_vulnerabilities)
    return summary, vdr_file, pkg_vulnerabilities, pkg_group_rows, options


def summarise_tools(tools, metadata, bom_data):
    """
    Helper function to add depscan information as metadata
    :param tools: Tools section of the SBOM
    :param metadata: Metadata section of the SBOM
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
        bom_data = summarise_tools(tools, metadata, bom_data)
    bom_data["vulnerabilities"] = pkg_vulnerabilities
    json_dump(vdr_file, bom_data, error_msg=f"Unable to generate VDR file at {vdr_file}", log=LOG)


def set_project_types(args, src_dir):
    """
    Detects the project types and perform the right type of scan

    :param args: cli arguments
    :param src_dir: source directory

    :return: A tuple containing the package list, the parsed package URL object,
    and the list of project types.
    """
    pkg_list, purl_obj = [], {}

    if args.project_type:
        project_types_list = args.project_type.split(",")
    elif args.search_purl:
        purl_obj = parse_purl(args.search_purl)
        purl_obj["purl"] = args.search_purl
        purl_obj["vendor"] = purl_obj.get("namespace")
        project_types_list = [purl_obj.get("type")]
        pkg_list = [purl_obj]
    elif args.bom:
        project_types_list = ["bom"]
    elif not args.non_universal_scan:
        project_types_list = [UNIVERSAL_SCAN_TYPE]
    else:
        project_types_list = utils.detect_project_type(src_dir)
    return pkg_list, project_types_list


@app.get("/")
async def index():
    """

    :return: An empty dictionary
    """
    return {}


@app.get("/cache")
async def cache():
    """

    :return: a JSON response indicating the status of the caching operation.
    """
    db = db_lib.get()
    if 0 in db_lib.stats():
        if download_image():
            return {
                "error": "false",
                "message": "vulnerability database cached successfully",
            }
        return {
            "error": "true",
            "message": "vulnerability database was not cached",
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
    db = db_lib.get()
    profile = "generic"
    deep = False
    suggest_mode = q.get("suggest") or True
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
    if 0 in db_lib.stats():
        return (
            {
                "error": "true",
                "message": "Vulnerability database is empty. Prepare the "
                "vulnerability database by invoking /cache endpoint "
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
        with tempfile.NamedTemporaryFile(
            delete=False, suffix=".bom.json"
        ) as bfp:
            bom_status = create_bom(
                project_type,
                bfp.name,
                path,
                deep,
                {
                    "url": url,
                    "path": path,
                    "type": project_type,
                    "multiProject": multi_project,
                    "cdxgen_server": cdxgen_server,
                    "profile": profile,
                },
            )
            if bom_status:
                LOG.debug("BOM file was generated successfully at %s", bfp.name)
                bom_file_path = bfp.name

    # Path points to a SBOM file
    else:
        if os.path.exists(path):
            bom_file_path = path

    if bom_file_path is not None:
        pkg_list = get_pkg_list(bom_file_path)
        if not pkg_list:
            return {}
        if project_type in type_audit_map:
            audit_results = audit(project_type, pkg_list)
            if audit_results:
                results = results + audit_results
        if not pkg_list:
            LOG.debug("Empty package search attempted!")
        else:
            LOG.debug("Scanning %d oss dependencies for issues", len(pkg_list))
        vdb_results, pkg_aliases, purl_aliases = utils.search_pkgs(project_type, pkg_list)
        results.extend(vdb_results)
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
        options = PrepareVdrOptions(
            project_type,
            results,
            pkg_aliases,
            purl_aliases,
            suggest_mode,
            scoped_pkgs={},
            no_vuln_table=True,
            bom_file=bom_file_path,
            direct_purls={},
            reached_purls={},
        )
        pkg_vulnerabilities, _ = prepare_vdr(options)
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
        debug=os.getenv("SCAN_DEBUG_MODE") == "debug"
        or os.getenv("AT_DEBUG_MODE") == "debug",
        use_reloader=False,
    )


def run_depscan(args):
    """
    Detects the project type, performs various scans and audits,
    and generates reports based on the results.
    """
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
    sponsor_message(args)
    # Should we turn on the debug mode
    setup_debug(args)
    if args.server_mode:
        return run_server(args)
    print_banner(args)
    src_dir = get_src_dir(args)
    reports_dir = args.reports_dir
    csaf_toml_check(args, src_dir)

    pkg_list, project_types_list = set_project_types(args, src_dir)
    if args.search_purl:
        # Automatically enable risk audit for single purl searches
        perform_risk_audit = True
    db = db_lib.get()
    run_cacher = args.cache
    report_filename = args.report_file or os.path.join(reports_dir, "depscan.json")
    html_filename = report_filename.replace(".json", ".html")
    pdf_filename = report_filename.replace(".json", ".pdf")

    # Create reports directory
    if reports_dir and not os.path.exists(reports_dir):
        os.makedirs(reports_dir, exist_ok=True)

    if len(project_types_list) > 1:
        LOG.debug("Multiple project types found: %s", project_types_list)

    # Enable license scanning
    setup_license(args, project_types_list)

    for project_type in project_types_list:
        results = []
        type_report_file = report_filename.replace(".json", f"-{project_type}.json")
        risk_report_file = report_filename.replace(
            ".json", f"-risk.{project_type}.json"
        )
        
        # bom_file set to None when scanning single_purl, in cases of error generating bom creation_status is None
        # if binary analysis is enabled then we utilize blint with --bom-src command
        bom_file, creation_status = set_bom_file_creation_status(args, type_report_file, project_type, src_dir)

        # If bom creation failed then skip this project_type
        if not creation_status:
            LOG.debug("Bom file %s was not created successfully", bom_file)
            continue
        if bom_file:
            caching_message(args, bom_file)
            pkg_list = get_pkg_list(bom_file)

        # if pkg_list does not contain any pkgs then skip project type
        if not pkg_list:
            LOG.debug("No packages found in the project!")
            continue

        # Extract the scope of the packages required in risk audit
        scoped_pkgs = utils.get_pkgs_by_scope(pkg_list)

        if (
            os.getenv("FETCH_LICENSE", "") in (True, "1", "true")
            or "license" in args.profile
        ):
            licenses_results = bulk_lookup(
                build_license_data(license_data_dir, spdx_license_list),
                pkg_list=pkg_list,
            )
            license_report_file = os.path.join(
                reports_dir, "license-" + project_type + ".json"
            )
            analyse_licenses(
                project_type, licenses_results, license_report_file
            )

        # Risk audit requests data from registry and is prone to errors
        # This usually includes Connection or Timeout Errors.
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
                    analyse_pkg_risks(
                        project_type,
                        scoped_pkgs,
                        risk_results,
                        risk_report_file,
                    )
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
                    LOG.debug(
                        "Remote audit yielded %d results", len(audit_results)
                    )
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
        if 0 in db_lib.stats():
            run_cacher = True
        else:
            LOG.debug(
                "Vulnerability database loaded from %s", config.VDB_BIN_FILE
            )

        sources_list = [OSVSource(), NvdSource()]
        github_client_message(sources_list)
        if run_cacher:
            paths_list = download_image()
            LOG.debug("VDB data is stored at: %s", paths_list)
            run_cacher = False
            db = db_lib.get()
        elif args.sync:
            for s in sources_list:
                LOG.debug("Syncing %s", s.__class__.__name__)
                try:
                    s.download_recent()
                except NotImplementedError:
                    pass
                run_cacher = False
        if len(pkg_list) > 1:
            if args.bom:
                LOG.info(
                    "Performing regular scan for %s using plugin %s",
                    args.bom,
                    project_type,
                )
            else:
                LOG.info(
                    "Performing regular scan for %s using plugin %s",
                    src_dir,
                    project_type,
                )
        if not pkg_list:
            LOG.debug("Empty package search attempted!")
        else:
            LOG.debug("Scanning %d oss dependencies for issues", len(pkg_list))
        vdb_results, pkg_aliases, purl_aliases = utils.search_pkgs(project_type, pkg_list)
        results.extend(vdb_results)
        direct_purls, reached_purls = find_purl_usages(
            bom_file, src_dir, args.reachables_slices_file
        )
        # Summarise and print results
        summary, vdr_file, pkg_vulnerabilities, sug_version_dict, pkg_group_rows = summarise(
            project_type,
            results,
            pkg_aliases,
            purl_aliases,
            args.suggest,
            scoped_pkgs=scoped_pkgs,
            report_file=type_report_file,
            bom_file=bom_file,
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
        html_filename,
        theme=(
            MONOKAI if os.getenv("USE_DARK_THEME") else DEFAULT_TERMINAL_THEME
        ),
    )
    utils.export_pdf(html_filename, pdf_filename)
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
    # Submit vdr/vex files to threatdb server
    if args.threatdb_server and (args.threatdb_username or args.threatdb_token):
        submit_bom(
            reports_dir,
            {
                "threatdb_server": args.threatdb_server,
                "threatdb_username": args.threatdb_username,
                "threatdb_password": args.threatdb_password,
                "threatdb_token": args.threatdb_token,
            },
        )


def main():
    cli_args = build_args()
    run_depscan(cli_args)


if __name__ == "__main__":
    main()
