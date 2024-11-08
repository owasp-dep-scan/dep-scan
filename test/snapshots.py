#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import logging
import os
import re
from typing import Set, List, Dict

from custom_json_diff.lib.custom_diff import (
    compare_dicts,
    perform_bom_diff,
    report_results, perform_csaf_diff,
)
from custom_json_diff.lib.custom_diff_classes import Options
from custom_json_diff.lib.utils import json_load, json_dump

from depscan.cli import build_parser, main as depscan
from depscan.lib.utils import get_description_detail

VERSION_REPLACE = re.compile(r"(?<=to version )\S+", re.IGNORECASE)

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)


def build_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--legacy",
        "-l",
        action="store_true",
        default=False,
        help="Use if original snapshots were generated using depscan v5.",
    )
    parser.add_argument(
        "--bom-dir",
        "-b",
        default="/home/runner/work/new_snapshots",
        help="Directory containing the BOM files to analyze",
    )
    parser.add_argument(
        '--snapshot-dirs',
        '-d',
        # Preserving with the intention of allowing an output directory in the depscan cli
        default=["/home/runner/work/original_snapshots", "/home/runner/work/new_snapshots"],
        help='Directories containing the snapshots to compare',
        nargs=2
    )
    parser.add_argument(
        "--projects",
        "-p",
        default=["node-goat", "django-goat", "java-sec-code", "rasa", "restic", "tinydb"],
        help="List of projects to compare",
        nargs="+",
    )
    return parser.parse_args()


def compare_snapshots(options: Options, v5: bool, repo: str):
    if not os.path.exists(options.file_1):
        return f"{options.file_1} not found.", f"{options.file_1} not found."
    if not os.path.exists(options.file_2):
        return f"{options.file_2} not found.", f"{options.file_2} not found."
    filter_normalize_jsons(options.file_1, options, v5)
    filter_normalize_jsons(options.file_2, options, v5)
    options.file_1 = options.file_1.replace(".json", ".parsed.json")
    options.file_2 = options.file_2.replace(".json", ".parsed.json")
    _, j1, j2 = compare_dicts(options)
    if options.preconfig_type == "bom":
        result, result_summary = perform_bom_diff(j1, j2)
    else:
        result, result_summary = perform_csaf_diff(j1, j2)
    report_results(result, result_summary, options, j1, j2)
    if result:
        return f"{repo} {options.preconfig_type} diff failed.", result_summary
    else:
        return f"{repo} {options.preconfig_type} diff succeeded.", result_summary


def filter_normalize_jsons(filename: str, options: Options, v5: bool):
    data = json_load(filename, log=logger)
    data["vulnerabilities"] = filter_years(data.get("vulnerabilities", []))
    if v5:
        data = handle_legacy_output(data, options, filename)
    json_dump(f"{filename.replace('.json', '.parsed.json')}", data, True, log=logger)


def filter_years(vdrs: List) -> List:
    new_vdrs= []
    for i in vdrs:
        if vid := (i.get("id") or i.get("cve", "")):
            vid = vid.upper()
            # Only include CVEs from 2020 - 2023
            if vid.startswith("CVE-") and int(vid[6:8]) not in range(20, 24):
                continue
            new_vdrs.append(i)
    return new_vdrs


def generate_new_snapshots(bom_dir: str, projects: Set):
    for p in projects:
        parser = build_parser()
        bom_file = os.path.join(bom_dir, f"{p}-bom.json")
        args = parser.parse_args(["--bom", bom_file, "--csaf", "--no-banner", "--no-vuln-table"])
        depscan(args)


def generate_snapshot_diffs(dir1: str, dir2: str, projects: List, v5: bool):
    bom_diff_options = Options(
        allow_new_versions=True,
        allow_new_data=True,
        preconfig_type="bom",
        exclude=["tools", "components", "dependencies", "services", "metadata", "vulnerabilities.[].source"],
    )
    csaf_diff_options = Options(
        allow_new_versions=True,
        allow_new_data=True,
        preconfig_type="csaf",
        exclude=["vulnerabilities.[].acknowledgements"],
    )
    failed_diffs = {"bom": {}, "csaf": {}}
    for p in projects:
        bom_diff_options.file_1 = f"{dir1}/{p}-bom.vdr.json"
        bom_diff_options.file_2 = f"{dir2}/{p}-bom.vdr.json"
        bom_diff_options.output = f"{dir2}/{p}-bom-diff.json"
        bom_result, bom_summary = compare_snapshots(bom_diff_options, v5, p)
        print(bom_result)
        if bom_result.endswith("failed."):
            failed_diffs["bom"] |= {p: bom_summary}
        csaf_diff_options.file_1 = f"{dir1}/{p}.csaf_v1.json"
        csaf_diff_options.file_2 = f"{dir2}/{p}.csaf_v1.json"
        csaf_diff_options.output = f"{dir2}/{p}.csaf-diff.json"
        csaf_result, csaf_summary = compare_snapshots(csaf_diff_options, v5, p)
        print(csaf_result)
        if csaf_result.endswith("failed."):
            failed_diffs["csaf"] |= {p: csaf_summary}
    return {k: v for k, v in failed_diffs.items() if v}


def handle_legacy_output(data: Dict, options: Options, filename: str) -> Dict:
    if options.preconfig_type == "bom":
        if filename == options.file_1:
            data = migrate_old_vdr_formatting(data)
        else:
            data = handle_new_recommendation_for_comparison(data)
    elif options.preconfig_type == "csaf":
        data = migrate_old_csaf_formatting(data)
    return data


def handle_new_recommendation_for_comparison(bom_data: Dict):
    for i, v in enumerate(bom_data.get("vulnerabilities", [])):
        if rec := v.get("recommendation"):
            if match := VERSION_REPLACE.findall(rec):
                new_rec = f"Update to version {match[-1]}".rstrip(".")
                bom_data["vulnerabilities"][i]["recommendation"] = f"{new_rec}."
    return bom_data


def migrate_old_csaf_formatting(csaf_data: Dict):
    for i, v in enumerate(csaf_data.get("vulnerabilities", [])):
        csaf_data["vulnerabilities"][i]["acknowledgements"] = [v.get("acknowledgements")] if v.get("acknowledgements") else []
    return csaf_data


def migrate_old_vdr_formatting(bom_data: Dict):
    for i, v in enumerate(bom_data.get("vulnerabilities", [])):
        if v.get("description"):
            description, detail = get_description_detail(v["description"])
            bom_data["vulnerabilities"][i]["description"] = description
            bom_data["vulnerabilities"][i]["detail"] = detail
        if v.get("recommendation"):
            new_rec = v["recommendation"].replace(" or later", "").replace("Update to version ", "Update to ").replace("Update to", "Update to version").rstrip(".")
            bom_data["vulnerabilities"][i]["recommendation"] = f"{new_rec}."
        if v.get("properties"):
            new_properties = [i for i in v["properties"] if i["name"] != "affectedVersionRange"]
            bom_data["vulnerabilities"][i]["properties"] = new_properties
    return bom_data


def perform_snapshot_tests(dir1: str, dir2: str, projects: List, v5: bool):
    if failed_diffs := generate_snapshot_diffs(dir1, dir2, projects, v5):
        diff_file = os.path.join(dir2, 'diffs.json')
        json_dump(diff_file, failed_diffs, success_msg=f"Results of failed diffs saved to {diff_file}", log=logger)
    else:
        print("Snapshot tests passed!")


def main():
    args = build_args()
    generate_new_snapshots(args.bom_dir, args.projects)
    perform_snapshot_tests(args.snapshot_dirs[0], args.snapshot_dirs[1], args.projects, args.legacy)


if __name__ == "__main__":
    main()
