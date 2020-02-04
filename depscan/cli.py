#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import logging
import os
import sys

import vulndb.lib.config as config
import vulndb.lib.db as dbLib
from vulndb.lib.gha import GitHubSource
from vulndb.lib.nvd import NvdSource

import depscan.lib.utils as utils
from depscan.lib.analysis import print_results, analyse, analyse_licenses, jsonl_report
from depscan.lib.audit import audit, type_audit_map
from depscan.lib.bom import get_pkg_list, create_bom
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
        description="Vulnerability database and package search for sources such as CVE, GitHub, and so on. Uses a built-in tinydb based storage engine."
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
        "--bom",
        dest="bom",
        help="Examine using the given Software Bill-of-Materials (SBoM) file in CycloneDX format. Use cdxgen command to produce one.",
    )
    parser.add_argument("--src", dest="src_dir", help="Source directory", required=True)
    parser.add_argument(
        "--report_file",
        dest="report_file",
        help="Report filename with directory",
        default="reports" + os.sep + "depscan.json",
    )
    parser.add_argument(
        "--no-error",
        action="store_true",
        default=False,
        dest="noerror",
        help="Continue on error to prevent build from breaking",
    )
    return parser.parse_args()


def scan(db, pkg_list):
    """
    Method to search packages in our vulnerability database

    :param db: Reference to db
    :param pkg_list: List of packages
    """
    return utils.search_pkgs(db, pkg_list)


def summarise(results, licenses_results, report_file=None, console_print=True):
    """
    Method to summarise the results
    :param results: Scan or audit results
    :param licenses_results: License scan result
    :param report_file: Output report file
    :param print: Boolean to indicate if the results should get printed to the console
    :return: Summary of the results
    """
    if report_file:
        jsonl_report(results, report_file)
    if console_print:
        print_results(results)
    summary = analyse(results)
    analyse_licenses(licenses_results)
    return summary


def main():
    args = build_args()
    if not args.no_banner:
        print(at_logo, flush=True)
    db = dbLib.get()
    run_cacher = args.cache
    reports_dir = os.path.dirname(args.report_file)
    # Create reports directory
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)

    bom_file = os.path.join(reports_dir, "bom.xml")
    if args.bom:
        bom_file = args.bom
    # Only create the bom file if it doesn't exist
    if not os.path.isfile(bom_file):
        create_bom(bom_file, args.src_dir)
    LOG.debug("Scanning using the bom file {}".format(bom_file))
    pkg_list = get_pkg_list(bom_file)
    if not pkg_list:
        LOG.warning("No packages found in the project!")
        return
    # Detect the project types and perform the right type of scan
    project_types_list = utils.detect_project_type(args.src_dir)
    for project_type in project_types_list:
        if project_type in type_audit_map.keys():
            LOG.info(
                "Performing remote audit for {} of type {}".format(
                    args.src_dir, project_type
                )
            )
            results = audit(project_type, pkg_list, args.report_file)
            licenses_results = bulk_lookup(
                build_license_data(license_data_dir), pkg_list=pkg_list
            )
        else:
            if not dbLib.index_count(db["index_file"]):
                run_cacher = True
            else:
                LOG.info(
                    "Vulnerability database loaded from {}".format(
                        config.vulndb_bin_file
                    )
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
                    LOG.info("Refreshing {}".format(s.__class__.__name__))
                    s.refresh()
            elif args.sync:
                for s in sources_list:
                    LOG.info("Syncing {}".format(s.__class__.__name__))
                    s.download_recent()
            LOG.debug(
                "Vulnerability database contains {} records".format(
                    dbLib.index_count(db["index_file"])
                )
            )
            results = scan(db, pkg_list)
            licenses_results = bulk_lookup(
                build_license_data(license_data_dir), pkg_list=pkg_list
            )
        # Summarise and print results
        summary = summarise(results, licenses_results, args.report_file)
        if summary and not args.noerror:
            # Hard coded build break logic for now
            if summary.get("CRITICAL") > 0:
                sys.exit(1)


if __name__ == "__main__":
    main()
