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


def analyse(results):
    summary = {"UNSPECIFIED": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for res in results:
        summary[res.severity] += 1
    table = []
    headers = ["Severity", "Count", "Status"]
    for k, v in summary.items():
        status = "✅"
        if k in ["MEDIUM"] and v > 10:
            status = "❕"
        elif k in ["HIGH", "CRITICAL"] and v > 0:
            status = "❌"
        table.append([k, v, status])
    print(tabulate(table, headers, tablefmt="grid"))
    return summary


def jsonl_report(results, out_file_name):
    """Produce vulnerability occurrence report in jsonl format

    :param results: List of vulnerabilities found
    :param out_file_name: Output filename
    """
    with open(out_file_name, "w") as outfile:
        for data in results:
            json.dump(data.to_dict(), outfile)
            outfile.write("\n")
