# -*- coding: utf-8 -*-

import json
import logging

from rich import box
from rich.console import Console
from rich.logging import RichHandler
from rich.markdown import Markdown
from rich.panel import Panel
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


def print_results(project_type, results, pkg_aliases, sug_version_dict, scoped_pkgs):
    """Pretty print report summary"""
    if not results:
        return
    table = Table(
        title=f"Dependency Scan Results ({project_type})",
        box=box.DOUBLE_EDGE,
        header_style="bold magenta",
    )
    required_pkgs = scoped_pkgs.get("required", [])
    optional_pkgs = scoped_pkgs.get("optional", [])
    pkg_attention_count = 0
    fix_version_count = 0
    for h in [
        "Id",
        "Package",
        "Used?",
        "Version",
        "Fix Version",
        "Severity",
        "Score",
    ]:
        justify = "left"
        if h == "Score":
            justify = "right"
        width = None
        if h == "Id":
            width = 20
        elif h == "Used?" or h == "Fix Version":
            width = 10
        elif h == "Description":
            width = 58
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
        fixed_location = sug_version_dict.get(full_pkg, package_issue.fixed_location)
        package_usage = "N/A"
        package_name_style = ""
        id_style = ""
        pkg_severity = vuln_occ_dict.get("severity")
        if full_pkg in required_pkgs and pkg_severity in ("CRITICAL", "HIGH"):
            id_style = ":point_right: "
            pkg_attention_count = pkg_attention_count + 1
            if fixed_location:
                fix_version_count = fix_version_count + 1
        if full_pkg in required_pkgs:
            package_usage = "[bright_green][bold]Yes"
            package_name_style = "[bold]"
        elif full_pkg in optional_pkgs:
            package_usage = "[magenta]No"
            package_name_style = "[italic]"
        package = full_pkg.split(":")[-1]
        table.add_row(
            "{}{}{}{}".format(
                id_style,
                package_name_style,
                "[bright_red]" if pkg_severity == "CRITICAL" else "",
                id,
            ),
            "{}{}".format(package_name_style, package),
            package_usage,
            package_issue.affected_location.version,
            fixed_location,
            "{}{}".format(
                "[bright_red]" if pkg_severity == "CRITICAL" else "",
                vuln_occ_dict.get("severity"),
            ),
            "{}{}".format(
                "[bright_red]" if pkg_severity == "CRITICAL" else "",
                vuln_occ_dict.get("cvss_score"),
            ),
        )
    console.print(table)
    if scoped_pkgs:
        if pkg_attention_count:
            rmessage = f":heavy_exclamation_mark: [magenta]{pkg_attention_count}[/magenta] out of {len(results)} vulnerabilities requires your attention."
            if fix_version_count:
                if fix_version_count == pkg_attention_count:
                    rmessage += "\n:white_heavy_check_mark: You can update [bright_green]all[/bright_green] the packages using the mentioned fix version to remediate."
                else:
                    rmessage += f"\nYou can remediate [bright_green]{fix_version_count}[/bright_green] {'vulnerability' if fix_version_count == 1 else 'vulnerabilities'} by updating the packages using the fix version :thumbsup:."
            console.print(
                Panel(
                    rmessage,
                    title="Recommendation",
                    expand=False,
                )
            )
        else:
            console.print(
                Panel(
                    ":white_check_mark: No package requires immediate attention since the major vulnerabilities are found only in dev packages and indirect dependencies.",
                    title="Recommendation",
                    expand=False,
                )
            )


def analyse(project_type, results):
    if not results:
        LOG.info("No oss vulnerabilities detected ✅")
        return None
    summary = {"UNSPECIFIED": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for res in results:
        summary[res.severity] += 1
    return summary


def jsonl_report(
    project_type, results, pkg_aliases, sug_version_dict, scoped_pkgs, out_file_name
):
    """Produce vulnerability occurrence report in jsonl format

    :param project_type: Project type
    :param results: List of vulnerabilities found
    :param pkg_aliases: Package alias
    :param out_file_name: Output filename
    """
    required_pkgs = scoped_pkgs.get("required", [])
    optional_pkgs = scoped_pkgs.get("optional", [])
    excluded_pkgs = scoped_pkgs.get("excluded", [])
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
            package_usage = "N/A"
            if full_pkg in required_pkgs:
                package_usage = "required"
            elif full_pkg in optional_pkgs:
                package_usage = "optional"
            elif full_pkg in excluded_pkgs:
                package_usage = "excluded"
            data_obj = {
                "id": id,
                "package": full_pkg,
                "package_type": vuln_occ_dict.get("type"),
                "package_usage": package_usage,
                "version": package_issue.affected_location.version,
                "fix_version": fixed_location,
                "severity": vuln_occ_dict.get("severity"),
                "cvss_score": vuln_occ_dict.get("cvss_score"),
                "short_description": vuln_occ_dict.get("short_description"),
                "related_urls": vuln_occ_dict.get("related_urls"),
            }
            json.dump(data_obj, outfile)
            outfile.write("\n")


def analyse_licenses(project_type, licenses_results, license_report_file=None):
    if not licenses_results:
        return
    table = Table(
        title=f"License Scan Summary ({project_type})",
        box=box.DOUBLE_EDGE,
        header_style="bold magenta",
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
    """Provide version suggestions"""
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
