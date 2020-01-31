#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import logging
import os
import re

import depscan.lib.utils as utils
from depscan.lib.bom import get_pkg_list

import vulndb.lib.config as config
from vulndb.lib.nvd import NvdSource
from vulndb.lib.gha import GitHubSource
import vulndb.lib.db as dbLib

from tabulate import tabulate

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
    parser.add_argument("--out_dir", dest="reports_dir", help="Reports directory")
    parser.add_argument(
        "--no-error",
        action="store_true",
        default=False,
        dest="noerror",
        help="Continue on error to prevent build from breaking",
    )
    return parser.parse_args()


def print_results(results):
    """Pretty print report summary
    """
    table = []
    headers = ["Id", "Package", "Version", "CWE", "Severity", "Score", "Description"]
    for res in results:
        vuln_occ_dict = res.to_dict()
        id = vuln_occ_dict.get("id")
        package_issue = res.package_issue
        table.append(
            [
                id,
                package_issue.affected_location.package,
                package_issue.affected_location.version,
                vuln_occ_dict.get("problem_type"),
                vuln_occ_dict.get("severity"),
                vuln_occ_dict.get("cvss_score"),
                vuln_occ_dict.get("short_description"),
            ]
        )
    print(tabulate(table, headers, tablefmt="grid"))
    print("Total vulnerabilites found:", len(results))


def scan(db, pkg_list):
    """
    Method to search packages in our vulnerability database

    :param pkg_list: List of packages
    """
    results = utils.search_pkgs(db, pkg_list)
    print_results(results)


def main():
    args = build_args()
    print(at_logo, flush=True)
    db = dbLib.get()
    run_cacher = args.cache
    if not dbLib.index_count(db["index_file"]):
        run_cacher = True
    else:
        LOG.info("Vulnerability database loaded from {}".format(config.vulndb_bin_file))
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
    if args.bom:
        LOG.debug("Scanning using the bom file {}".format(args.bom))
        pkg_list = get_pkg_list(args.bom)
        scan(db, pkg_list)
    proj_type = utils.detect_project_type(args.src_dir)


if __name__ == "__main__":
    main()
