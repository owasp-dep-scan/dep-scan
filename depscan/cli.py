#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import logging
import os
import sys

from vdb.lib import config as config
from vdb.lib import db as dbLib
from vdb.lib.gha import GitHubSource
from vdb.lib.nvd import NvdSource

from depscan.lib import utils as utils
from depscan.lib.analysis import (
    analyse,
    analyse_licenses,
    jsonl_report,
    print_results,
    suggest_version,
)
from depscan.lib.audit import audit, type_audit_map
from depscan.lib.bom import create_bom, get_pkg_list
from depscan.lib.config import license_data_dir
from depscan.lib.license import build_license_data, bulk_lookup

logging.basicConfig(
    level=logging.INFO, format="%(levelname)s [%(asctime)s] %(message)s"
)
LOG = logging.getLogger(__name__)

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


def build_args():
    """
    Constructs command line arguments for the vulndb tool
    """
    parser = argparse.ArgumentParser(
        description="Fully open-source security audit for project dependencies based on known vulnerabilities and advisories."
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
        "--sync",
        action="store_true",
        default=False,
        dest="sync",
        help="Sync to receive the latest vulnerability data. Should have invoked cache first.",
    )
    parser.add_argument(
        "--suggest",
        action="store_true",
        default=False,
        dest="suggest",
        help="Suggest appropriate fix version for each identified vulnerability.",
    )
    parser.add_argument(
        "-t",
        "--type",
        dest="project_type",
        help="Override project type if auto-detection is incorrect",
    )
    parser.add_argument(
        "--bom",
        dest="bom",
        help="UNUSED: Examine using the given Software Bill-of-Materials (SBoM) file in CycloneDX format. Use cdxgen command to produce one.",
    )
    parser.add_argument(
        "-i", "--src", dest="src_dir", help="Source directory", required=True
    )
    parser.add_argument(
        "-o",
        "--report_file",
        dest="report_file",
        help="Report filename with directory",
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
        help="Do not perform a scan for license limitations",
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
    results, pkg_aliases = utils.search_pkgs(db, project_type, pkg_list)
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
            override_results, _ = utils.search_pkgs(db, sug_pkg_list)
            if override_results:
                new_sug_dict = suggest_version(override_results)
                LOG.debug("Received override results: {}".format(new_sug_dict))
                for nk, nv in new_sug_dict.items():
                    sug_version_dict[nk] = nv
    return results, pkg_aliases, sug_version_dict


def summarise(
    project_type,
    results,
    pkg_aliases,
    sug_version_dict,
    scoped_pkgs={},
    report_file=None,
    console_print=True,
):
    """
    Method to summarise the results
    :param project_type: Project type
    :param results: Scan or audit results
    :param pkg_aliases: Package aliases used
    :param sug_version_dict: Dictionary containing version suggestions
    :param scoped_pkgs: Dict containing package scopes
    :param report_file: Output report file
    :param print: Boolean to indicate if the results should get printed to the console
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
            sug_version_dict,
            scoped_pkgs,
            report_file,
        )
    if console_print:
        print_results(project_type, results, pkg_aliases, sug_version_dict, scoped_pkgs)
    summary = analyse(project_type, results)
    return summary


def main():
    args = build_args()
    if not args.no_banner:
        print(at_logo, flush=True)
    # Set logging level
    if os.environ.get("SCAN_DEBUG_MODE") == "debug":
        LOG.setLevel(logging.DEBUG)
    src_dir = args.src_dir
    if not args.src_dir:
        src_dir = os.getcwd()
    db = dbLib.get()
    run_cacher = args.cache
    areport_file = (
        args.report_file
        if args.report_file
        else os.path.join(src_dir, "reports", "depscan.json")
    )
    reports_dir = os.path.dirname(areport_file)
    # Create reports directory
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)
    # Detect the project types and perform the right type of scan
    if args.project_type:
        project_types_list = args.project_type.split(",")
    else:
        project_types_list = utils.detect_project_type(src_dir)
    if len(project_types_list) > 1:
        LOG.debug("Multiple project types found: {}".format(project_types_list))
    for project_type in project_types_list:
        sug_version_dict = {}
        pkg_aliases = {}
        report_file = areport_file.replace(".json", "-{}.json".format(project_type))
        LOG.info("=" * 80)
        bom_file = os.path.join(reports_dir, "bom-" + project_type + ".json")
        creation_status = create_bom(project_type, bom_file, src_dir)
        if not creation_status:
            LOG.debug("Bom file {} was not created successfully".format(bom_file))
            continue
        LOG.debug("Scanning using the bom file {}".format(bom_file))
        pkg_list = get_pkg_list(bom_file)
        if not pkg_list:
            LOG.debug("No packages found in the project!")
            continue
        scoped_pkgs = utils.get_pkgs_by_scope(pkg_list)
        if not args.no_license_scan:
            licenses_results = bulk_lookup(
                build_license_data(license_data_dir), pkg_list=pkg_list
            )
            license_report_file = os.path.join(
                reports_dir, "license-" + project_type + ".json"
            )
            analyse_licenses(project_type, licenses_results, license_report_file)
        if project_type in type_audit_map.keys():
            LOG.info(
                "Performing remote audit for {} of type {}".format(
                    src_dir, project_type
                )
            )
            LOG.debug(f"No of packages {len(pkg_list)}")
            try:
                results = audit(project_type, pkg_list, report_file)
            except Exception as e:
                LOG.error("Remote audit was not successful")
                LOG.error(e)
                results = None
        else:
            if not dbLib.index_count(db["index_file"]):
                run_cacher = True
            else:
                LOG.debug(
                    "Vulnerability database loaded from {}".format(config.vdb_bin_file)
                )
            sources_list = [NvdSource()]
            if os.environ.get("GITHUB_TOKEN"):
                sources_list.insert(0, GitHubSource())
            else:
                LOG.info(
                    "To use GitHub advisory source please set the environment variable GITHUB_TOKEN!"
                )
            if run_cacher:
                for s in sources_list:
                    LOG.debug("Refreshing {}".format(s.__class__.__name__))
                    s.refresh()
            elif args.sync:
                for s in sources_list:
                    LOG.debug("Syncing {}".format(s.__class__.__name__))
                    s.download_recent()
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
            results, pkg_aliases, sug_version_dict = scan(
                db, project_type, pkg_list, args.suggest
            )
        # Summarise and print results
        summary = summarise(
            project_type,
            results,
            pkg_aliases,
            sug_version_dict,
            scoped_pkgs,
            report_file,
            True,
        )
        if summary and not args.noerror and len(project_types_list) == 1:
            # Hard coded build break logic for now
            if summary.get("CRITICAL") > 0:
                sys.exit(1)


if __name__ == "__main__":
    main()
