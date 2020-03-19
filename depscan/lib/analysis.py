# -*- coding: utf-8 -*-

import json
import logging

from tabulate import tabulate

logging.basicConfig(
    level=logging.INFO, format="%(levelname)s [%(asctime)s] %(message)s"
)
LOG = logging.getLogger(__name__)


def print_results(results):
    """Pretty print report summary
    """
    if not len(results):
        return
    table = []
    headers = ["Id", "Package", "Version", "Severity", "Score", "Description"]
    for res in results:
        vuln_occ_dict = res.to_dict()
        id = vuln_occ_dict.get("id")
        package_issue = res.package_issue
        table.append(
            [
                id,
                package_issue.affected_location.package,
                package_issue.affected_location.version,
                vuln_occ_dict.get("severity"),
                vuln_occ_dict.get("cvss_score"),
                vuln_occ_dict.get("short_description"),
            ]
        )
    print("\n===Dependency scan results===\n")
    print(tabulate(table, headers, tablefmt="grid"))


def analyse(results):
    summary = {"UNSPECIFIED": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for res in results:
        summary[res.severity] += 1
    table = []
    headers = ["Severity", "Count", "Status"]
    hasValues = False
    for k, v in summary.items():
        status = "✅"
        if k in ["MEDIUM"] and v > 10:
            status = "❕"
        elif k in ["HIGH", "CRITICAL"] and v > 0:
            status = "❌"
        if v:
            hasValues = True
        table.append([k, v, status])
    if not hasValues:
        LOG.info("No oss vulnerabilities detected ✅")
        return None
    if len(table):
        print("\n===Dependency scan summary===\n")
        print(tabulate(table, headers, tablefmt="simple"))
    return summary


def jsonl_report(results, out_file_name):
    """Produce vulnerability occurrence report in jsonl format

    :param results: List of vulnerabilities found
    :param out_file_name: Output filename
    """
    with open(out_file_name, "w") as outfile:
        for data in results:
            vuln_occ_dict = data.to_dict()
            id = vuln_occ_dict.get("id")
            package_issue = data.package_issue
            data_obj = {
                "id": id,
                "package": package_issue.affected_location.package,
                "version": package_issue.affected_location.version,
                "severity": vuln_occ_dict.get("severity"),
                "cvss_score": vuln_occ_dict.get("cvss_score"),
                "short_description": vuln_occ_dict.get("short_description"),
                "related_urls": vuln_occ_dict.get("related_urls"),
            }
            json.dump(data_obj, outfile)
            outfile.write("\n")


def analyse_licenses(licenses_results):
    if not licenses_results:
        return
    table = []
    headers = ["Package", "Version", "License Id", "License conditions"]
    for pkg, ll in licenses_results.items():
        pkg_ver = pkg.split("@")
        for lic in ll:
            if not lic:
                table.append([*pkg_ver, "Unknown license"])
            elif lic["condition_flag"]:
                table.append([*pkg_ver, lic["spdx-id"], ", ".join(lic["conditions"])])

    if len(table):
        print("\n===License scan findings===\n")
        print(tabulate(table, headers, tablefmt="grid"))
    else:
        LOG.info("No license violation detected ✅")
