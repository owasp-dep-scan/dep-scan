#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import logging
import os
import sys

from depscan.lib.analysis import print_results, analyse, jsonl_report
import depscan.lib.utils as utils
from depscan.lib.bom import get_pkg_list, create_bom

import vulndb.lib.config as config
from vulndb.lib.nvd import NvdSource
from vulndb.lib.gha import GitHubSource
import vulndb.lib.db as dbLib

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


def scan(db, pkg_list, report_file):
    """
    Method to search packages in our vulnerability database

    :param pkg_list: List of packages
    """
    results = utils.search_pkgs(db, pkg_list)
    jsonl_report(results, report_file)
    print_results(results)
    summary = analyse(results)
    return summary


def main():
    args = build_args()
    print(at_logo, flush=True)
    db = dbLib.get()
    run_cacher = args.cache
    summary = None
    reports_dir = os.path.dirname(args.report_file)
    bom_file = os.path.join(reports_dir, "bom.xml")
    # Create reports directory
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)

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
        bom_file = args.bom
    # Only create the bom file if it doesn't exist
    if not os.path.isfile(bom_file):
        create_bom(bom_file, args.src_dir)
    LOG.debug("Scanning using the bom file {}".format(bom_file))
    pkg_list = get_pkg_list(bom_file)
    if not pkg_list:
        LOG.warning("No packages found in the project!")
        return
    summary = scan(db, pkg_list, args.report_file)
    if summary and not args.noerror:
        # Hard coded build break logic for now
        if summary.get("CRITICAL") > 0:
            sys.exit(1)


if __name__ == "__main__":
    main()
