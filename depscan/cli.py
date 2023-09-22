#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import os
import tempfile

from quart import Quart, request
from rich.panel import Panel
from rich.terminal_theme import MONOKAI
from vdb.lib import config
from vdb.lib import db as db_lib
from vdb.lib.aqua import AquaSource
from vdb.lib.config import data_dir
from vdb.lib.gha import GitHubSource
from vdb.lib.nvd import NvdSource
from vdb.lib.osv import OSVSource
from vdb.lib.utils import parse_purl

import oras.client

from depscan.lib import privado, utils
from depscan.lib.analysis import (
    PrepareVexOptions,
    analyse_licenses,
    analyse_pkg_risks,
    jsonl_report,
    prepare_vex,
    suggest_version,
    summary_stats,
)
from depscan.lib.audit import audit, risk_audit, risk_audit_map, type_audit_map
from depscan.lib.bom import create_bom, get_pkg_by_type, get_pkg_list, submit_bom
from depscan.lib.config import UNIVERSAL_SCAN_TYPE, license_data_dir, spdx_license_list, vdb_database_url
from depscan.lib.license import build_license_data, bulk_lookup
from depscan.lib.logger import LOG, console
from depscan.lib.utils import get_version

try:
    os.environ["PYTHONIOENCODING"] = "utf-8"
except Exception:
    pass

at_logo = """
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
        "known vulnerabilities and advisories."
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
        help="Cache vulnerability information in platform specific " "user_data_dir",
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
        "--suggest",
        action="store_true",
        default=True,
        dest="suggest",
        help="DEPRECATED: Suggest is the default mode for determining fix " "version.",
    )
    parser.add_argument(
        "--risk-audit",
        action="store_true",
        default=True if os.getenv("ENABLE_OSS_RISK", "") in ["true", "1"] else False,
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
        help="Examine using the given Software Bill-of-Materials (SBoM) file "
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
        default=os.getenv("DEPSCAN_REPORTS_DIR", os.path.join(os.getcwd(), "reports")),
        dest="reports_dir",
        help="Reports directory",
    )
    parser.add_argument(
        "--no-error",
        action="store_true",
        default=False,
        dest="noerror",
        help="Continue on error to prevent build from breaking",
    )
    parser.add_argument(
        "--no-license-scan",
        action="store_true",
        default=False,
        dest="no_license_scan",
        help="DEPRECATED: dep-scan doesn't perform license scanning by default",
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
        "--privado-json",
        dest="privado_json",
        default=os.path.join(os.getcwd(), ".privado", "privado.json"),
        help="Optional: Enrich the VEX report with information from "
        "privado.ai json report. cdxgen can process and include privado "
        "info automatically so this argument is usually not required.",
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
        "-v",
        "--version",
        help="Display the version",
        action="version",
        version="%(prog)s " + get_version(),
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
    results, pkg_aliases, purl_aliases = utils.search_pkgs(db, project_type, pkg_list)
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
                            vendor = purl_obj.get("type")
                        name = purl_obj.get("name")
                        version = purl_obj.get("version")
                        sug_pkg_list.append(
                            {
                                "vendor": vendor,
                                "name": name,
                                "version": version,
                                "purl": k,
                            }
                        )
                        continue
                    except Exception as e:
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
            override_results, _, _ = utils.search_pkgs(db, project_type, sug_pkg_list)
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
    scoped_pkgs={},
    report_file=None,
    bom_file=None,
    privado_json_file=None,
    no_vuln_table=False,
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
    :param bom_file: SBoM file
    :param privado_json_file Privado json file
    :param no_vuln_table: Boolean to indicate if the results should get printed
            to the console
    :return: A dict of vulnerability and severity summary statistics
    """
    if not results:
        LOG.info("No oss vulnerabilities detected for type %s ✅", project_type)
        return None
    if report_file:
        jsonl_report(
            project_type,
            results,
            pkg_aliases,
            purl_aliases,
            sug_version_dict,
            scoped_pkgs,
            report_file,
        )
    options = PrepareVexOptions(
        project_type,
        results,
        pkg_aliases,
        purl_aliases,
        sug_version_dict,
        scoped_pkgs=scoped_pkgs,
        no_vuln_table=no_vuln_table,
        bom_file=bom_file,
    )
    pkg_vulnerabilities = prepare_vex(options)
    if pkg_vulnerabilities and bom_file:
        vex_file = bom_file.replace(".json", ".vex.json")
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
                        tools["components"] = components
                        metadata["tools"] = tools
                        bom_data["metadata"] = metadata

                    bom_data["vulnerabilities"] = pkg_vulnerabilities
                    # Look for any privado json file
                    if os.path.exists(privado_json_file):
                        pservice = privado.process_report(privado_json_file)
                        if pservice:
                            LOG.info(
                                "Including the service identified by privado "
                                "from %s",
                                privado_json_file,
                            )
                            if not bom_data.get("services"):
                                bom_data["services"] = []
                            bom_data["services"].insert(0, pservice)
                    with open(vex_file, mode="w", encoding="utf-8") as vexfp:
                        json.dump(bom_data, vexfp)
                        LOG.info("VEX file %s generated successfully", vex_file)
        except Exception:
            LOG.warning("Unable to generate VEX file for this scan")
    summary = summary_stats(results)
    return summary


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
        oras_client = oras.client.OrasClient()
        paths_list = oras_client.pull(target = vdb_database_url, outdir = data_dir)
        LOG.debug(f'VDB data is stored at: {paths_list}')
        return {
            "error": "false",
            "message": "vulnerability database cached successfully",
        }
    return {
        "error": "false",
        "message": "vulnerability database already exists",
    }


@app.route("/scan", methods=["GET", "POST"])
async def run_scan():
    """
    :return: A JSON response containing the SBoM file path and a list of
    vulnerabilities found in the scanned packages
    """
    q = request.args
    params = await request.get_json()
    url = None
    path = None
    multi_project = None
    project_type = None
    results = []
    db = db_lib.get()
    if q.get("url"):
        url = q.get("url")
    if q.get("path"):
        path = q.get("path")
    if q.get("multiProject"):
        multi_project = q.get("multiProject", "").lower() in ("true", "1")
    if q.get("type"):
        project_type = q.get("type")
    if not url and params.get("url"):
        url = params.get("url")
    if not path and params.get("path"):
        path = params.get("path")
    if not multi_project and params.get("multiProject"):
        multi_project = params.get("multiProject", "").lower() in ("true", "1")
    if not project_type and params.get("type"):
        project_type = params.get("type")
    if not path and not url:
        return {"error": "true", "message": "path or url is required"}, 500
    if not db_lib.index_count(db["index_file"]):
        return {
            "error": "true",
            "message": "Vulnerability database is empty. Prepare the "
            "vulnerability database by invoking /cache endpoint "
            "before running scans.",
        }, 500
    cdxgen_server = app.config.get("CDXGEN_SERVER_URL")
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bom.json") as bfp:
        bom_status = create_bom(
            project_type,
            bfp.name,
            path,
            True,
            {
                "url": url,
                "path": path,
                "type": project_type,
                "multiProject": multi_project,
                "cdxgen_server": cdxgen_server,
            },
        )
        if bom_status:
            LOG.debug("BOM file was generated successfully at %s", bfp.name)
            pkg_list = get_pkg_list(bfp.name)
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
            bom_data = json.load(bfp)
            options = PrepareVexOptions(
                project_type,
                results,
                pkg_aliases,
                purl_aliases,
                sug_version_dict,
                scoped_pkgs={},
                no_vuln_table=True,
                bom_file=bfp.name,
            )
            pkg_vulnerabilities = prepare_vex(options)
            if pkg_vulnerabilities:
                bom_data["vulnerabilities"] = pkg_vulnerabilities
            return json.dumps(bom_data)
        else:
            return {
                "error": "true",
                "message": "Unable to generate SBoM. Check your input path or " "url.",
            }, 500


def run_server(args):
    """
    Run depscan as server

    :param args: Command line arguments passed to the function.
    """
    print(at_logo)
    console.print(f"Depscan server running on {args.server_host}:{args.server_port}")
    app.config["CDXGEN_SERVER_URL"] = args.cdxgen_server
    app.run(
        host=args.server_host,
        port=args.server_port,
        debug=True if os.getenv("SCAN_DEBUG_MODE") == "debug" else False,
        use_reloader=False,
    )


def main():
    """
    Detects the project type, performs various scans and audits,
    and generates reports based on the results.
    """
    args = build_args()
    if args.server_mode:
        return run_server(args)
    if not args.no_banner:
        print(at_logo)
    src_dir = args.src_dir_image
    if not src_dir:
        src_dir = os.getcwd()
    reports_dir = args.reports_dir
    # Detect the project types and perform the right type of scan
    if args.project_type:
        project_types_list = args.project_type.split(",")
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
    # Create reports directory
    if reports_dir and not os.path.exists(reports_dir):
        os.makedirs(reports_dir, exist_ok=True)
    if len(project_types_list) > 1:
        LOG.debug("Multiple project types found: %s", project_types_list)
    # Enable license scanning
    if "license" in project_types_list:
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
        LOG.info("=" * 80)
        if args.bom and os.path.exists(args.bom):
            bom_file = args.bom
            creation_status = True
        else:
            bom_file = report_file.replace("depscan-", "sbom-")
            creation_status = create_bom(
                project_type,
                bom_file,
                src_dir,
                args.deep_scan,
                {"cdxgen_server": args.cdxgen_server},
            )
        if not creation_status:
            LOG.debug("Bom file %s was not created successfully", bom_file)
            continue
        LOG.debug("Scanning using the bom file %s", bom_file)
        if not args.bom:
            LOG.info(
                "To improve performance, cache this bom file and invoke "
                "depscan with --bom %s instead of -i",
                bom_file,
            )
        pkg_list = get_pkg_list(bom_file)
        if not pkg_list:
            LOG.debug("No packages found in the project!")
            continue
        scoped_pkgs = utils.get_pkgs_by_scope(pkg_list)
        if os.getenv("FETCH_LICENSE", "") in (True, "1", "true"):
            licenses_results = bulk_lookup(
                build_license_data(license_data_dir, spdx_license_list),
                pkg_list=pkg_list,
            )
            license_report_file = os.path.join(
                reports_dir, "license-" + project_type + ".json"
            )
            analyse_licenses(project_type, licenses_results, license_report_file)
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
                        title="New Feature",
                        expand=False,
                    )
                )
        if project_type in type_audit_map:
            LOG.info(
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
        # In case of docker, bom, or universal type, check if there are any npm packages that can be
        # audited remotely
        if project_type in ("podman", "docker", "oci", "bom", "universal"):
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
            LOG.debug("Vulnerability database loaded from %s", config.vdb_bin_file)

        sources_list = [OSVSource(), NvdSource()]
        if os.environ.get("GITHUB_TOKEN"):
            sources_list.insert(0, GitHubSource())
        if run_cacher:
            oras_client = oras.client.OrasClient()
            paths_list = oras_client.pull(target = vdb_database_url, outdir = data_dir)
            LOG.debug(f'VDB data is stored at: {paths_list}')
            run_cacher = False
        elif args.sync:
            for s in sources_list:
                LOG.debug("Syncing %s", s.__class__.__name__)
                s.download_recent()
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
            results = results + vdb_results
        # Summarise and print results
        summarise(
            project_type,
            results,
            pkg_aliases,
            purl_aliases,
            sug_version_dict,
            scoped_pkgs=scoped_pkgs,
            report_file=report_file,
            bom_file=bom_file,
            privado_json_file=args.privado_json,
            no_vuln_table=args.no_vuln_table,
        )
    console.save_html(html_file, theme=MONOKAI)
    # Submit vex files to threatdb server
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
