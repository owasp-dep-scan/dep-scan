#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import os
import sys
import tempfile

from defusedxml.ElementTree import parse
from quart import Quart, request
from rich.panel import Panel
from rich.terminal_theme import DEFAULT_TERMINAL_THEME, MONOKAI
from vdb.lib import config
from vdb.lib import db as db_lib
from vdb.lib.gha import GitHubSource
from vdb.lib.nvd import NvdSource
from vdb.lib.osv import OSVSource
from vdb.lib.utils import parse_purl

from depscan.lib import explainer, github, utils
from depscan.lib.analysis import (
    PrepareVdrOptions,
    analyse_licenses,
    analyse_pkg_risks,
    find_purl_usages,
    jsonl_report,
    prepare_vdr,
    suggest_version,
    summary_stats,
)
from depscan.lib.audit import audit, risk_audit, risk_audit_map, type_audit_map
from depscan.lib.bom import (
    create_bom,
    get_pkg_by_type,
    get_pkg_list,
    submit_bom,
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

try:
    os.environ["PYTHONIOENCODING"] = "utf-8"
except Exception:
    pass

LOGO = """
██████╗ ███████╗██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗
██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║
██║  ██║█████╗  ██████╔╝███████╗██║     ███████║██╔██╗ ██║
██║  ██║██╔══╝  ██╔═══╝ ╚════██║██║     ██╔══██║██║╚██╗██║
██████╔╝███████╗██║     ███████║╚██████╗██║  ██║██║ ╚████║
╚═════╝ ╚══════╝╚═╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
"""


app = Quart(__name__)
app.config.from_prefixed_env()


def build_args():
    """
    Constructs command line arguments for the depscan tool
    """
    parser = argparse.ArgumentParser(
        description="Fully open-source security and license audit for "
        "application dependencies and container images based on "
        "known vulnerabilities and advisories.",
        epilog="Visit https://github.com/owasp-dep-scan/dep-scan to learn more.",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        default=False,
        dest="no_banner",
        help="Do not display banner",
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
        default="True",
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
        help="Makes depscan to explain the various analysis. Useful for creating detailed reports.",
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
        version="%(prog)s " + utils.get_version(),
    )
    return parser.parse_args()


def scan(db, project_type, pkg_list, suggest_mode):
    """
    Method to search packages in our vulnerability database

    :param db: Reference to db
    :param project_type: Project Type
    :param pkg_list: List of packages
    :param suggest_mode: True if package fix version should be normalized across
            findings
    :returns: A list of package issue objects or dictionaries.
              A dictionary mapping package names to their aliases.
              A dictionary mapping packages to their suggested fix versions.
              A dictionary mapping package URLs to their aliases.
    """
    if not pkg_list:
        LOG.debug("Empty package search attempted!")
    else:
        LOG.debug("Scanning %d oss dependencies for issues", len(pkg_list))
    results, pkg_aliases, purl_aliases = utils.search_pkgs(
        db, project_type, pkg_list
    )
    # pkg_aliases is a dict that can be used to find the original vendor and
    # package name This way we consistently use the same names used by the
    # caller irrespective of how the result was obtained
    sug_version_dict = {}
    if suggest_mode:
        # From the results identify optimal max version
        sug_version_dict = suggest_version(results, pkg_aliases, purl_aliases)
        if sug_version_dict:
            LOG.debug(
                "Adjusting fix version based on the initial suggestion %s",
                sug_version_dict,
            )
            # Recheck packages
            sug_pkg_list = []
            for k, v in sug_version_dict.items():
                if not v:
                    continue
                vendor = ""
                version = v
                # Key is already a purl
                if k.startswith("pkg:"):
                    try:
                        purl_obj = parse_purl(k)
                        vendor = purl_obj.get("namespace")
                        if not vendor:
                            vendor = purl_obj.get("type") or ""
                        name = purl_obj.get("name") or ""
                        version = purl_obj.get("version") or ""
                        sug_pkg_list.append(
                            {
                                "vendor": vendor,
                                "name": name,
                                "version": version,
                                "purl": k,
                            }
                        )
                        continue
                    except Exception:
                        pass
                tmp_a = k.split(":")
                if len(tmp_a) == 3:
                    vendor = tmp_a[0]
                    name = tmp_a[1]
                else:
                    name = tmp_a[0]
                # De-alias the vendor and package name
                full_pkg = f"{vendor}:{name}:{version}"
                full_pkg = pkg_aliases.get(full_pkg, full_pkg)
                vendor, name, version = full_pkg.split(":")
                sug_pkg_list.append(
                    {"vendor": vendor, "name": name, "version": version}
                )
            LOG.debug(
                "Re-checking our suggestion to ensure there are no further "
                "vulnerabilities"
            )
            override_results, _, _ = utils.search_pkgs(
                db, project_type, sug_pkg_list
            )
            if override_results:
                new_sug_dict = suggest_version(override_results)
                LOG.debug("Received override results: %s", new_sug_dict)
                for nk, nv in new_sug_dict.items():
                    sug_version_dict[nk] = nv
    return results, pkg_aliases, sug_version_dict, purl_aliases


def summarise(
    project_type,
    results,
    pkg_aliases,
    purl_aliases,
    sug_version_dict,
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
    :param purl_aliases: Package URL to package name aliase
    :param sug_version_dict: Dictionary containing version suggestions
    :param scoped_pkgs: Dict containing package scopes
    :param report_file: Output report file
    :param bom_file: SBOM file
    :param no_vuln_table: Boolean to indicate if the results should get printed
            to the console
    :return: A dict of vulnerability and severity summary statistics
    """
    if report_file:
        jsonl_report(
            project_type,
            results,
            pkg_aliases,
            purl_aliases,
            sug_version_dict,
            scoped_pkgs,
            report_file,
            direct_purls=direct_purls,
            reached_purls=reached_purls,
        )
    options = PrepareVdrOptions(
        project_type,
        results,
        pkg_aliases,
        purl_aliases,
        sug_version_dict,
        scoped_pkgs=scoped_pkgs,
        no_vuln_table=no_vuln_table,
        bom_file=bom_file,
        direct_purls=direct_purls,
        reached_purls=reached_purls,
    )
    pkg_vulnerabilities, pkg_group_rows = prepare_vdr(options)
    vdr_file = bom_file.replace(".json", ".vdr.json") if bom_file else None
    if pkg_vulnerabilities and bom_file:
        try:
            with open(bom_file, encoding="utf-8") as fp:
                bom_data = json.load(fp)
                if bom_data:
                    # Add depscan information as metadata
                    metadata = bom_data.get("metadata", {})
                    tools = metadata.get("tools", {})
                    bom_version = str(bom_data.get("version", 1))
                    # Update the version
                    if bom_version.isdigit():
                        bom_version = int(bom_version) + 1
                        bom_data["version"] = bom_version
                    # Update the tools section
                    if isinstance(tools, dict):
                        components = tools.get("components", [])
                        ds_version = utils.get_version()
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
                        tools["components"] = components
                        metadata["tools"] = tools
                        bom_data["metadata"] = metadata

                    bom_data["vulnerabilities"] = pkg_vulnerabilities
                    with open(vdr_file, mode="w", encoding="utf-8") as vdrfp:
                        json.dump(bom_data, vdrfp, indent=4)
                        LOG.debug(
                            "VDR file %s generated successfully", vdr_file
                        )
        except Exception:
            LOG.warning("Unable to generate VDR file for this scan")
    summary = summary_stats(results)
    return summary, vdr_file, pkg_vulnerabilities, pkg_group_rows


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
    if not db_lib.index_count(db["index_file"]):
        paths_list = download_image()
        if paths_list:
            return {
                "error": "false",
                "message": "vulnerability database cached successfully",
            }
        else:
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

    if not db_lib.index_count(db["index_file"]):
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
        with open(tmp_bom_file.name, "w", encoding="utf-8") as f:
            f.write(bom_file_content)
        path = tmp_bom_file.name

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
        vdb_results, pkg_aliases, sug_version_dict, purl_aliases = scan(
            db, project_type, pkg_list, True
        )
        if vdb_results:
            results += vdb_results
        results = [r.to_dict() for r in results]
        bom_data = None
        with open(bom_file_path, encoding="utf-8") as fp:
            bom_data = json.load(fp)
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
            sug_version_dict,
            scoped_pkgs={},
            no_vuln_table=True,
            bom_file=bom_file_path,
            direct_purls=None,
            reached_purls=None,
        )
        pkg_vulnerabilities, _ = prepare_vdr(options)
        if pkg_vulnerabilities:
            bom_data["vulnerabilities"] = pkg_vulnerabilities
        return json.dumps(bom_data), 200, {"Content-Type": "application/json"}

    else:
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


def main():
    """
    Detects the project type, performs various scans and audits,
    and generates reports based on the results.
    """
    args = build_args()
    # declare variables that get initialized only conditionally
    (
        summary,
        vdr_file,
        bom_file,
        pkg_list,
        pkg_vulnerabilities,
        pkg_group_rows,
    ) = (None, None, None, None, None, None)
    if os.getenv("GITHUB_ACTION", "").lower() == "__appthreat_dep-scan-action" \
        and not os.getenv("INPUT_THANK_YOU", "") == ("I have sponsored "
                                                 "OWASP-dep-scan."):
        console.print(
            Panel(
                "OWASP relies on donations to fund our projects.\n\n"
                "Donate at: https://owasp.org/donate/?reponame=www-project"
                "-dep-scan&title=OWASP+depscan.\n\nAfter you have done so, "
                "make sure you have configured the action with thank_you: 'I "
                "have sponsored OWASP-dep-scan.'",
                title="Please make a donation",
                expand=False,
            )
        )
        sys.exit(1)
    # Should we turn on the debug mode
    if args.enable_debug:
        os.environ["AT_DEBUG_MODE"] = "debug"
        LOG.setLevel(DEBUG)
    if args.server_mode:
        return run_server(args)
    if not args.no_banner:
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
    if args.csaf:
        toml_file_path = os.getenv(
            "DEPSCAN_CSAF_TEMPLATE", os.path.join(src_dir, "csaf.toml")
        )
        if not os.path.exists(toml_file_path):
            LOG.info("CSAF toml not found, creating template in %s", src_dir)
            write_toml(toml_file_path)
            LOG.info(
                "Please fill out the toml with your details and rerun depscan."
            )
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
    # Detect the project types and perform the right type of scan
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
    db = db_lib.get()
    run_cacher = args.cache
    areport_file = (
        args.report_file
        if args.report_file
        else os.path.join(reports_dir, "depscan.json")
    )
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
        risk_report_file = areport_file.replace(
            ".json", f"-risk.{project_type}.json"
        )
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
                # The bom file has to be called bom.json for atom reachables to work :(
                bom_file = os.path.join(src_dir, "bom.json")
            else:
                bom_file = report_file.replace("depscan-", "sbom-")
            creation_status = create_bom(
                project_type,
                bom_file,
                src_dir,
                args.deep_scan,
                {"cdxgen_server": args.cdxgen_server, "profile": args.profile},
            )
        if not creation_status:
            LOG.debug("Bom file %s was not created successfully", bom_file)
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
            LOG.debug("No packages found in the project!")
            continue
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
        if project_type in risk_audit_map:
            if args.risk_audit:
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
        if not db_lib.index_count(db["index_file"]):
            run_cacher = True
        else:
            LOG.debug(
                "Vulnerability database loaded from %s", config.vdb_bin_file
            )

        sources_list = [OSVSource(), NvdSource()]
        github_token = os.environ.get("GITHUB_TOKEN")
        if github_token and os.getenv("CI"):
            try:
                github_client = github.GitHub(github_token)

                if not github_client.can_authenticate():
                    LOG.error(
                        "The GitHub personal access token supplied appears to be invalid or expired. Please see: https://github.com/owasp-dep-scan/dep-scan#github-security-advisory"
                    )
                else:
                    sources_list.insert(0, GitHubSource())
                    scopes = github_client.get_token_scopes()
                    if scopes:
                        LOG.warning(
                            "The GitHub personal access token was granted more permissions than is necessary for depscan to operate, including the scopes of: %s. It is recommended to use a dedicated token with only the minimum scope necesary for depscan to operate. Please see: https://github.com/owasp-dep-scan/dep-scan#github-security-advisory",
                            ", ".join(scopes),
                        )
            except Exception:
                pass
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
        LOG.info(
            "Performing regular scan for %s using plugin %s",
            src_dir,
            project_type,
        )
        vdb_results, pkg_aliases, sug_version_dict, purl_aliases = scan(
            db, project_type, pkg_list, args.suggest
        )
        if vdb_results:
            results += vdb_results
        results = [r.to_dict() for r in results]
        direct_purls, reached_purls = find_purl_usages(
            bom_file, src_dir, args.reachables_slices_file
        )
        # Summarise and print results
        summary, vdr_file, pkg_vulnerabilities, pkg_group_rows = summarise(
            project_type,
            results,
            pkg_aliases,
            purl_aliases,
            sug_version_dict,
            scoped_pkgs=scoped_pkgs,
            report_file=report_file,
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
        html_file,
        theme=MONOKAI
        if os.getenv("USE_DARK_THEME")
        else DEFAULT_TERMINAL_THEME,
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


if __name__ == "__main__":
    main()
