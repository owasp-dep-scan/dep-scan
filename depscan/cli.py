#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import os
import tempfile

from quart import Quart, request
from rich.panel import Panel
from rich.terminal_theme import MONOKAI
from vdb.lib import config as config
from vdb.lib import db as dbLib
from vdb.lib.aqua import AquaSource
from vdb.lib.gha import GitHubSource
from vdb.lib.nvd import NvdSource
from vdb.lib.osv import OSVSource

from depscan.lib import privado
from depscan.lib import utils as utils
from depscan.lib.analysis import (
    analyse,
    analyse_licenses,
    analyse_pkg_risks,
    jsonl_report,
    prepare_vex,
    suggest_version,
)
from depscan.lib.audit import audit, risk_audit, risk_audit_map, type_audit_map
from depscan.lib.bom import create_bom, get_pkg_by_type, get_pkg_list, submit_bom
from depscan.lib.config import UNIVERSAL_SCAN_TYPE, license_data_dir, spdx_license_list
from depscan.lib.license import build_license_data, bulk_lookup
from depscan.lib.logger import LOG, console

try:
    os.environ["PYTHONIOENCODING"] = "utf-8"
except Exception:
    pass

at_logo = """
  ___            _____ _                    _
 / _ \          |_   _| |                  | |
/ /_\ \_ __  _ __ | | | |__  _ __ ___  __ _| |_
|  _  | '_ \| '_ \| | | '_ \| '__/ _ \/ _` | __|
| | | | |_) | |_) | | | | | | | |  __/ (_| | |_
\_| |_/ .__/| .__/\_/ |_| |_|_|  \___|\__,_|\__|
      | |   | |
      |_|   |_|
"""


app = Quart(__name__)
app.config.from_prefixed_env()


def build_args():
    """
    Constructs command line arguments for the depscan tool
    """
    parser = argparse.ArgumentParser(
        description="Fully open-source security and license audit for application dependencies and container images based on known vulnerabilities and advisories."
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
        help="Cache vulnerability information in platform specific user_data_dir",
    )
    parser.add_argument(
        "--cache-os",
        action="store_true",
        default=False,
        dest="cache_os",
        help="Cache OS vulnerability information in platform specific user_data_dir",
    )
    parser.add_argument(
        "--sync",
        action="store_true",
        default=False,
        dest="sync",
        help="Sync to receive the latest vulnerability data. Should have invoked cache first.",
    )
    parser.add_argument(
        "--suggest",
        action="store_true",
        default=True,
        dest="suggest",
        help="DEPRECATED: Suggest is the default mode for determining fix version.",
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
        help="Private namespace to use while performing oss risk audit. Private packages should not be available in public registries by default. Comma separated values accepted.",
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
        help="Examine using the given Software Bill-of-Materials (SBoM) file in CycloneDX format. Use cdxgen command to produce one.",
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
        help="DEPRECATED. Use reports directory since multiple files are created. Report filename with directory",
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
        help="Perform deep scan by passing this --deep argument to cdxgen. Useful while scanning docker images and OS packages.",
    )
    parser.add_argument(
        "--no-universal",
        action="store_true",
        default=False,
        dest="non_universal_scan",
        help="Depscan would attempt to perform a single universal scan instead of individual scans per language type.",
    )
    parser.add_argument(
        "--no-vuln-table",
        action="store_true",
        default=False,
        dest="no_vuln_table",
        help="Do not print the table with the full list of vulnerabilities. This can help reduce console output.",
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
        help="Optional: Enrich the VEX report with information from privado.ai json report. cdxgen can process and include privado info automatically so this argument is usually not required.",
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
    return parser.parse_args()


def scan(db, project_type, pkg_list, suggest_mode):
    """
    Method to search packages in our vulnerability database

    :param db: Reference to db
    :param project_type: Project Type
    :param pkg_list: List of packages
    :param suggest_mode: True if package fix version should be normalized across findings
    """
    if not pkg_list:
        LOG.debug("Empty package search attempted!")
    else:
        LOG.info("Scanning {} oss dependencies for issues".format(len(pkg_list)))
    results, pkg_aliases, purl_aliases = utils.search_pkgs(db, project_type, pkg_list)
    # pkg_aliases is a dict that can be used to find the original vendor and package name
    # This way we consistently use the same names used by the caller irrespective of how
    # the result was obtained
    sug_version_dict = {}
    if suggest_mode:
        # From the results identify optimal max version
        sug_version_dict = suggest_version(results, pkg_aliases)
        if sug_version_dict:
            LOG.debug(
                "Adjusting fix version based on the initial suggestion {}".format(
                    sug_version_dict
                )
            )
            # Recheck packages
            sug_pkg_list = []
            for k, v in sug_version_dict.items():
                if not v:
                    continue
                vendor = ""
                name = None
                version = v
                tmpA = k.split(":")
                if len(tmpA) == 2:
                    vendor = tmpA[0]
                    name = tmpA[1]
                else:
                    name = tmpA[0]
                # De-alias the vendor and package name
                full_pkg = "{}:{}".format(vendor, name)
                full_pkg = pkg_aliases.get(full_pkg, full_pkg)
                vendor, name = full_pkg.split(":")
                sug_pkg_list.append(
                    {"vendor": vendor, "name": name, "version": version}
                )
            LOG.debug(
                "Re-checking our suggestion to ensure there are no further vulnerabilities"
            )
            override_results, _, _ = utils.search_pkgs(db, project_type, sug_pkg_list)
            if override_results:
                new_sug_dict = suggest_version(override_results)
                LOG.debug("Received override results: {}".format(new_sug_dict))
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
    :param no_vuln_table: Boolean to indicate if the results should get printed to the console
    :return: Summary of the results
    """
    if not results:
        LOG.info(f"No oss vulnerabilities detected for type {project_type} ✅")
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
    pkg_vulnerabilities = prepare_vex(
        project_type,
        results,
        pkg_aliases,
        purl_aliases,
        sug_version_dict,
        scoped_pkgs,
        no_vuln_table,
    )

    if pkg_vulnerabilities and bom_file:
        vex_file = bom_file.replace(".json", ".vex.json")
        try:
            with open(bom_file) as fp:
                bom_data = json.load(fp)
                if bom_data:
                    bom_data["vulnerabilities"] = pkg_vulnerabilities
                    # Look for any privado json file
                    if os.path.exists(privado_json_file):
                        pservice = privado.process_report(privado_json_file)
                        if pservice:
                            LOG.info(
                                f"Including the service identified by privado from {privado_json_file}"
                            )
                            if not bom_data.get("services"):
                                bom_data["services"] = []
                            bom_data["services"].insert(0, pservice)
                    with open(vex_file, mode="w") as vexfp:
                        json.dump(bom_data, vexfp)
                        LOG.info(f"VEX file {vex_file} generated successfully")
        except Exception:
            LOG.warning("Unable to generate VEX file for this scan")
    summary = analyse(project_type, results)
    return summary


@app.get("/")
async def index():
    return {}


@app.get("/cache")
async def cache():
    db = dbLib.get()
    q = request.args
    if not dbLib.index_count(db["index_file"]):
        sources_list = [OSVSource(), NvdSource()]
        if os.environ.get("GITHUB_TOKEN"):
            sources_list.insert(0, GitHubSource())
        # Include aqua source when ?os=true query string is passed
        if q.get("os", "").lower() in ("true", "1"):
            sources_list.insert(0, AquaSource())
        for s in sources_list:
            LOG.debug("Refreshing {}".format(s.__class__.__name__))
            s.refresh()
        return {
            "error": "false",
            "message": "vulnerability database cached successfully",
        }
    return {"error": "false", "message": "vulnerability database already exists"}


@app.route("/scan", methods=["GET", "POST"])
async def run_scan():
    q = request.args
    params = await request.get_json()
    url = None
    path = None
    multiProject = None
    project_type = None
    results = []
    db = dbLib.get()
    if q.get("url"):
        url = q.get("url")
    if q.get("path"):
        path = q.get("path")
    if q.get("multiProject"):
        multiProject = q.get("multiProject", "").lower() in ("true", "1")
    if q.get("type"):
        project_type = q.get("type")
    if not url and params.get("url"):
        url = params.get("url")
    if not path and params.get("path"):
        path = params.get("path")
    if not multiProject and params.get("multiProject"):
        multiProject = params.get("multiProject", "").lower() in ("true", "1")
    if not project_type and params.get("type"):
        project_type = params.get("type")
    if not path and not url:
        return {"error": "true", "message": "path or url is required"}, 500
    if not dbLib.index_count(db["index_file"]):
        return {
            "error": "true",
            "message": "Vulnerability database is empty. Prepare the vulnerability database by invoking /cache endpoint before running scans.",
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
                "multiProject": multiProject,
                "cdxgen_server": cdxgen_server,
            },
        )
        if bom_status:
            LOG.debug(f"BOM file was generated successfully at {bfp.name}")
            pkg_list = get_pkg_list(bfp.name)
            if not pkg_list:
                return {}
            if project_type in type_audit_map.keys():
                audit_results = audit(project_type, pkg_list, None)
                if audit_results:
                    results = results + audit_results
            vdb_results, pkg_aliases, sug_version_dict, purl_aliases = scan(
                db, project_type, pkg_list, True
            )
            if vdb_results:
                results = results + vdb_results
            bom_data = json.load(bfp)
            pkg_vulnerabilities = prepare_vex(
                project_type,
                results,
                pkg_aliases,
                purl_aliases,
                sug_version_dict,
                {},
                True,
            )
            if pkg_vulnerabilities:
                bom_data["vulnerabilities"] = pkg_vulnerabilities
            return json.dumps(bom_data)
        else:
            return {
                "error": "true",
                "message": "Unable to generate SBoM. Check your input path or url.",
            }, 500
    return {}


def run_server(args):
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
    db = dbLib.get()
    run_cacher = args.cache or args.cache_os
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
        LOG.debug("Multiple project types found: {}".format(project_types_list))
    # Enable license scanning
    if "license" in project_types_list:
        os.environ["FETCH_LICENSE"] = "true"
        project_types_list.remove("license")
        console.print(
            Panel(
                "License audit is enabled for this scan. This would increase the time by up to 10 minutes.",
                title="License Audit",
                expand=False,
            )
        )
    for project_type in project_types_list:
        sug_version_dict = {}
        pkg_aliases = {}
        results = []
        report_file = areport_file.replace(".json", "-{}.json".format(project_type))
        risk_report_file = areport_file.replace(
            ".json", "-risk.{}.json".format(project_type)
        )
        LOG.info("=" * 80)
        creation_status = False
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
            LOG.debug("Bom file {} was not created successfully".format(bom_file))
            continue
        LOG.info("Scanning using the bom file {}".format(bom_file))
        if not args.bom:
            LOG.info(
                "To improve performance, cache this bom file and invoke depscan with --bom {} instead of -i".format(
                    bom_file
                )
            )
        pkg_list = get_pkg_list(bom_file)
        if not pkg_list:
            LOG.debug("No packages found in the project!")
            continue
        scoped_pkgs = {}
        if project_type in ["python"]:
            all_imports = utils.get_all_imports(src_dir)
            LOG.debug(f"Identified {len(all_imports)} imports in your project")
            scoped_pkgs = utils.get_scope_from_imports(
                project_type, pkg_list, all_imports
            )
        else:
            scoped_pkgs = utils.get_pkgs_by_scope(project_type, pkg_list)
        if os.getenv("FETCH_LICENSE", "") in (True, "1", "true"):
            licenses_results = bulk_lookup(
                build_license_data(license_data_dir, spdx_license_list),
                pkg_list=pkg_list,
            )
            license_report_file = os.path.join(
                reports_dir, "license-" + project_type + ".json"
            )
            analyse_licenses(project_type, licenses_results, license_report_file)
        if project_type in risk_audit_map.keys():
            if args.risk_audit:
                console.print(
                    Panel(
                        f"Performing OSS Risk Audit for packages from {src_dir}\nNo of packages [bold]{len(pkg_list)}[/bold]. This will take a while ...",
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
                        risk_report_file,
                    )
                    analyse_pkg_risks(
                        project_type,
                        scoped_pkgs,
                        args.private_ns,
                        risk_results,
                        risk_report_file,
                    )
                except Exception as e:
                    LOG.error(e)
                    LOG.error("Risk audit was not successful")
            else:
                console.print(
                    Panel(
                        "Depscan supports OSS Risk audit for this project.\nTo enable set the environment variable [bold]ENABLE_OSS_RISK=true[/bold]",
                        title="New Feature",
                        expand=False,
                    )
                )
        if project_type in type_audit_map.keys():
            LOG.info(
                "Performing remote audit for {} of type {}".format(
                    src_dir, project_type
                )
            )
            LOG.debug(f"No of packages {len(pkg_list)}")
            try:
                audit_results = audit(project_type, pkg_list, report_file)
                if audit_results:
                    LOG.debug(f"Remote audit yielded {len(audit_results)} results")
                    results = results + audit_results
            except Exception as e:
                LOG.error("Remote audit was not successful")
                LOG.error(e)
                results = []
        # In case of docker, check if there are any npm packages that can be audited remotely
        if project_type in ("podman", "docker", "oci"):
            npm_pkg_list = get_pkg_by_type(pkg_list, "npm")
            if npm_pkg_list:
                LOG.debug(f"No of npm packages {len(npm_pkg_list)}")
                try:
                    audit_results = audit("nodejs", npm_pkg_list, report_file)
                    if audit_results:
                        LOG.debug(f"Remote audit yielded {len(audit_results)} results")
                        results = results + audit_results
                except Exception as e:
                    LOG.error("Remote audit was not successful")
                    LOG.error(e)
        if not dbLib.index_count(db["index_file"]):
            run_cacher = True
        else:
            LOG.debug(
                "Vulnerability database loaded from {}".format(config.vdb_bin_file)
            )
        sources_list = [OSVSource(), NvdSource()]
        if os.environ.get("GITHUB_TOKEN"):
            sources_list.insert(0, GitHubSource())
        if run_cacher:
            if (
                args.cache_os
                or args.deep_scan
                or project_type in ("docker", "podman", "yaml-manifest", "os")
            ):
                sources_list.insert(0, AquaSource())
                LOG.info(
                    "OS Vulnerability database would be downloaded for the first time. This would take a few minutes ..."
                )
            for s in sources_list:
                LOG.debug("Refreshing {}".format(s.__class__.__name__))
                s.refresh()
                run_cacher = False
        elif args.sync:
            for s in sources_list:
                LOG.debug("Syncing {}".format(s.__class__.__name__))
                s.download_recent()
                run_cacher = False
        LOG.debug(
            "Vulnerability database contains {} records".format(
                dbLib.index_count(db["index_file"])
            )
        )
        LOG.info(
            "Performing regular scan for {} using plugin {}".format(
                src_dir, project_type
            )
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
