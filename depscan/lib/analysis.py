# -*- coding: utf-8 -*-

import json
import logging

from rich import box
from rich.console import Console
from rich.logging import RichHandler
from rich.markdown import Markdown
from rich.table import Table
from rich.theme import Theme

from depscan.lib.utils import max_version

custom_theme = Theme({"info": "cyan", "warning": "purple4", "danger": "bold red"})
console = Console(
    log_time=False,
    log_path=False,
    theme=custom_theme,
    width=200,
    color_system="256",
    force_terminal=True,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(console=console, show_path=False, enable_link_path=False)],
)
LOG = logging.getLogger(__name__)


def print_results(results, pkg_aliases, sug_version_dict):
    """Pretty print report summary
    """
    if not len(results):
        return
    table = Table(
        title="Dependency Scan Results",
        box=box.DOUBLE_EDGE,
        header_style="bold magenta",
    )
    for h in [
        "Id",
        "Package",
        "Version",
        "Fix Version",
        "Severity",
        "Score",
        "Description",
    ]:
        justify = "left"
        if h == "Score":
            justify = "right"
        width = None
        if h == "Id":
            width = 15
        elif h == "Fix Version":
            width = 10
        elif h == "Description":
            width = 60
        table.add_column(header=h, justify=justify, width=width, no_wrap=False)
    for res in results:
        vuln_occ_dict = res.to_dict()
        id = vuln_occ_dict.get("id")
        package_issue = res.package_issue
        full_pkg = package_issue.affected_location.package
        if package_issue.affected_location.vendor:
            full_pkg = "{}:{}".format(
                package_issue.affected_location.vendor,
                package_issue.affected_location.package,
            )
        # De-alias package names
        full_pkg = pkg_aliases.get(full_pkg, full_pkg)
        package = full_pkg.split(":")[-1]
        fixed_location = sug_version_dict.get(full_pkg, package_issue.fixed_location)
        table.add_row(
            "{}{}".format(
                "[bright_red]" if vuln_occ_dict.get("severity") == "CRITICAL" else "",
                id,
            ),
            package,
            package_issue.affected_location.version,
            fixed_location,
            "{}{}".format(
                "[bright_red]" if vuln_occ_dict.get("severity") == "CRITICAL" else "",
                vuln_occ_dict.get("severity"),
            ),
            "{}{}".format(
                "[bright_red]" if vuln_occ_dict.get("severity") == "CRITICAL" else "",
                vuln_occ_dict.get("cvss_score"),
            ),
            Markdown(vuln_occ_dict.get("short_description")),
        )
    console.print(table)


def analyse(results):
    summary = {"UNSPECIFIED": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for res in results:
        summary[res.severity] += 1
    table = Table(
        title="Dependency Scan Summary",
        box=box.DOUBLE_EDGE,
        header_style="bold magenta",
    )
    for h in ["Severity", "Count", "Status"]:
        justify = "left"
        if h == "Count":
            justify = "right"
        table.add_column(header=h, justify=justify)
    hasValues = False
    for k, v in summary.items():
        status = "✅"
        if k in ["MEDIUM"] and v > 10:
            status = "❕"
        elif k in ["HIGH", "CRITICAL"] and v > 0:
            status = "❌"
        if v:
            hasValues = True
        table.add_row(k, str(v), status)
    if not hasValues:
        LOG.info("No oss vulnerabilities detected ✅")
        return None
    console.print(table)
    return summary


def jsonl_report(results, pkg_aliases, sug_version_dict, out_file_name):
    """Produce vulnerability occurrence report in jsonl format

    :param results: List of vulnerabilities found
    :param pkg_aliases: Package alias
    :param out_file_name: Output filename
    """
    with open(out_file_name, "w") as outfile:
        for data in results:
            vuln_occ_dict = data.to_dict()
            id = vuln_occ_dict.get("id")
            package_issue = data.package_issue
            full_pkg = package_issue.affected_location.package
            if package_issue.affected_location.vendor:
                full_pkg = "{}:{}".format(
                    package_issue.affected_location.vendor,
                    package_issue.affected_location.package,
                )
            # De-alias package names
            full_pkg = pkg_aliases.get(full_pkg, full_pkg)
            fixed_location = sug_version_dict.get(
                full_pkg, package_issue.fixed_location
            )
            data_obj = {
                "id": id,
                "package": full_pkg,
                "version": package_issue.affected_location.version,
                "fix_version": fixed_location,
                "severity": vuln_occ_dict.get("severity"),
                "cvss_score": vuln_occ_dict.get("cvss_score"),
                "short_description": vuln_occ_dict.get("short_description"),
                "related_urls": vuln_occ_dict.get("related_urls"),
            }
            json.dump(data_obj, outfile)
            outfile.write("\n")


def analyse_licenses(licenses_results, license_report_file=None):
    if not licenses_results:
        return
    table = Table(
        title="License Scan Summary", box=box.DOUBLE_EDGE, header_style="bold magenta"
    )
    headers = ["Package", "Version", "License Id", "License conditions"]
    for h in headers:
        table.add_column(header=h)
    report_data = []
    for pkg, ll in licenses_results.items():
        pkg_ver = pkg.split("@")
        for lic in ll:
            if not lic:
                data = [*pkg_ver, "Unknown license"]
                table.add_row(*data)
                report_data.append(dict(zip(headers, data)))
            elif lic["condition_flag"]:
                data = [
                    *pkg_ver,
                    "{}{}".format(
                        "[cyan]" if lic["spdx-id"].startswith("GPL") else "",
                        lic["spdx-id"],
                    ),
                    ", ".join(lic["conditions"]),
                ]
                table.add_row(*data)
                report_data.append(dict(zip(headers, data)))
    if report_data:
        console.print(table)
        # Store the license scan findings in jsonl format
        if license_report_file:
            with open(license_report_file, "w") as outfile:
                for row in report_data:
                    json.dump(row, outfile)
                    outfile.write("\n")
    else:
        LOG.info("No license violation detected ✅")


def suggest_version(results, pkg_aliases={}):
    """Provide version suggestions
    """
    pkg_fix_map = {}
    sug_map = {}
    if not pkg_aliases:
        pkg_aliases = {}
    for res in results:
        if isinstance(res, dict):
            full_pkg = res.get("package")
            fixed_location = res.get("fix_version")
        else:
            package_issue = res.package_issue
            full_pkg = package_issue.affected_location.package
            fixed_location = package_issue.fixed_location
            if package_issue.affected_location.vendor:
                full_pkg = "{}:{}".format(
                    package_issue.affected_location.vendor,
                    package_issue.affected_location.package,
                )
        # De-alias package names
        full_pkg = pkg_aliases.get(full_pkg, full_pkg)
        version_upgrades = pkg_fix_map.get(full_pkg, set())
        version_upgrades.add(fixed_location)
        pkg_fix_map[full_pkg] = version_upgrades
    for k, v in pkg_fix_map.items():
        if v:
            mversion = max_version(list(v))
            if mversion:
                sug_map[k] = mversion
    return sug_map
