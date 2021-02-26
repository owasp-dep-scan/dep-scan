# -*- coding: utf-8 -*-

import json

from rich import box
from rich.panel import Panel
from rich.table import Table

from depscan.lib import config as config
from depscan.lib.logger import LOG, console
from depscan.lib.utils import max_version


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


def analyse_pkg_risks(project_type, private_ns, risk_results, risk_report_file=None):
    if not risk_results:
        return
    table = Table(
        title=f"Risk Audit Summary ({project_type})",
        box=box.DOUBLE_EDGE,
        header_style="bold magenta",
    )
    report_data = []
    headers = ["Package", "Used?", "Risk Score", "Identified Risks"]
    for h in headers:
        justify = "left"
        if h == "Risk Score":
            justify = "right"
        table.add_column(header=h, justify=justify)
    for pkg, risk_obj in risk_results.items():
        if not risk_obj:
            continue
        risk_metrics = risk_obj.get("risk_metrics")
        scope = risk_obj.get("scope")
        package_usage = "N/A"
        package_usage_simple = "N/A"
        if scope == "required":
            package_usage = "[bright_green][bold]Yes"
            package_usage_simple = "Yes"
        if scope == "optional":
            package_usage = "[magenta]No"
            package_usage_simple = "No"
        if not risk_metrics:
            continue
        if risk_metrics.get("risk_score") and (
            risk_metrics.get("risk_score") > config.pkg_max_risk_score
            or risk_metrics.get("pkg_private_on_public_registry_risk")
        ):
            risk_score = f"""{round(risk_metrics.get("risk_score"), 2)}"""
            data = [
                pkg,
                package_usage,
                risk_score,
            ]
            edata = [
                pkg,
                package_usage_simple,
                risk_score,
            ]
            risk_categories = []
            risk_categories_simple = []
            for rk, rv in risk_metrics.items():
                if rk.endswith("_risk") and rv is True:
                    rcat = rk.replace("_risk", "")
                    help_text = config.risk_help_text.get(rcat)
                    # Only add texts that are available.
                    if help_text:
                        if rcat in ("pkg_deprecated", "pkg_private_on_public_registry"):
                            risk_categories.append(f":cross_mark: {help_text}")
                        else:
                            risk_categories.append(f":warning: {help_text}")
                        risk_categories_simple.append(help_text)
            data.append("\n".join(risk_categories))
            edata.append(", ".join(risk_categories_simple))
            table.add_row(*data)
            report_data.append(dict(zip(headers, edata)))
    if report_data:
        console.print(table)
        # Store the risk audit findings in jsonl format
        if risk_report_file:
            with open(risk_report_file, "w") as outfile:
                for row in report_data:
                    json.dump(row, outfile)
                    outfile.write("\n")
    else:
        LOG.info("No package risks detected ✅")


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
