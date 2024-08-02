# -*- coding: utf-8 -*-

import contextlib
import json
import os.path
import re
from collections import defaultdict, OrderedDict
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import cvss
from cvss import CVSSError
from packageurl import PackageURL
from rich import box
from rich.markdown import Markdown
from rich.panel import Panel
from rich.style import Style
from rich.table import Table
from rich.tree import Tree
from vdb.lib import CPE_FULL_REGEX, VulnerabilityOccurrence
from vdb.lib.config import PLACEHOLDER_FIX_VERSION, PLACEHOLDER_EXCLUDE_VERSION
from vdb.lib.cve_model import ProblemType, CVE, Reference
from vdb.lib.utils import parse_purl, parse_cpe

from depscan.lib import config
from depscan.lib.csaf import get_ref_summary_helper
from depscan.lib.logger import LOG, console
from depscan.lib.utils import max_version, get_description_detail, format_system_name


NEWLINE = "\\n"

CWE_SPLITTER = re.compile(r"(?<=CWE-)[0-9]\d{0,5}", re.IGNORECASE)
# VENDOR = re.compile(r"redhat.com|oracle.com|curl.haxx.se|nodejs.org|sec-consult.com|jenkins.io/security|support.f5.com|suricata-ids.org/|foxitsoftware.com/support/|success.trendmicro.com/|docs.jmf.com/|www.postgresql.org/about|apache.org|debian.org|gentoo.org|ubuntu.com|rubyonrails-security|support.apple.com|alpinelinux.org|bugs.busybox.net", re.IGNORECASE)
JFROG_ADVISORY = re.compile(r"(?P<id>jfsa\S+)", re.IGNORECASE)


def best_fixed_location(sug_version, orig_fixed_location):
    """
    Compares the suggested version with the version from the original fixed
    location and returns the best version based on the major versions.
    See: https://github.com/owasp-dep-scan/dep-scan/issues/72

    :param sug_version: Suggested version
    :param orig_fixed_location: Version from original fixed location
    :return: Version
    """
    if (
        not orig_fixed_location
        and sug_version
        and sug_version != PLACEHOLDER_FIX_VERSION
    ):
        return sug_version
    if sug_version and orig_fixed_location:
        if sug_version == PLACEHOLDER_FIX_VERSION:
            return ""
        tmp_a = sug_version.split(".")[0]
        tmp_b = orig_fixed_location.split(".")[0]
        if tmp_a == tmp_b:
            return sug_version
    # Handle the placeholder version used by OS distros
    if orig_fixed_location == PLACEHOLDER_FIX_VERSION:
        return ""
    return orig_fixed_location


def distro_package(cpe):
    """
    Determines if a given Common Platform Enumeration (CPE) belongs to an
    operating system (OS) distribution.
    :param cpe: cpe string
    :return: bool
    """
    if cpe:
        all_parts = CPE_FULL_REGEX.match(cpe)
        if (
            all_parts
            and all_parts.group("vendor")
            and all_parts.group("vendor") in config.LINUX_DISTRO_WITH_EDITIONS
            and all_parts.group("edition")
            and all_parts.group("edition") != "*"
        ):
            return True
    return False


def retrieve_bom_dependency_tree(bom_file):
    """
    Method to retrieve the dependency tree from a CycloneDX SBOM

    :param bom_file: Sbom to be loaded
    :return: Dependency tree as a list
    """
    if not bom_file:
        return [], None
    try:
        with open(bom_file, encoding="utf-8") as bfp:
            bom_data = json.load(bfp)
            if bom_data:
                return bom_data.get("dependencies", []), bom_data
    except json.JSONDecodeError:
        pass
    return [], None


def retrieve_oci_properties(bom_data):
    """
    Retrieves OCI properties from the given BOM data.

    :param bom_data: The BOM data to retrieve OCI properties from.
    :type bom_data: dict

    :return: A dictionary containing the retrieved OCI properties.
    :rtype: dict
    """
    props = {}
    if not bom_data:
        return props
    for p in bom_data.get("metadata", {}).get("properties", []):
        if p.get("name", "").startswith("oci:image:"):
            props[p.get("name")] = p.get("value")
    return props


def get_pkg_display(tree_pkg, current_pkg, extra_text=None):
    """
    Construct a string that can be used for display

    :param tree_pkg: Package to display
    :param current_pkg: The package currently being processed
    :param extra_text: Additional text to append to the display string
    :return: Constructed display string
    """
    full_pkg_display = current_pkg
    highlightable = tree_pkg and (
        tree_pkg == current_pkg or tree_pkg in current_pkg
    )
    if tree_pkg:
        if current_pkg.startswith("pkg:"):
            purl_obj = parse_purl(current_pkg)
            if purl_obj:
                version_used = purl_obj.get("version")
                if version_used:
                    full_pkg_display = (
                        f"""{purl_obj.get("name")}@{version_used}"""
                    )
    if extra_text and highlightable:
        full_pkg_display = f"{full_pkg_display} {extra_text}"
    return full_pkg_display


def get_tree_style(purl, p):
    """
    Return a rich style to be used in a tree

    :param purl: Package purl to compare
    :param p: Package reference to check against purl
    :return: The rich style to be used in a tree visualization.
    """
    if purl and (purl == p or purl in p):
        return Style(color="#FF753D", bold=True, italic=False)
    return Style(color="#7C8082", bold=False, italic=True)


def pkg_sub_tree(
    purl,
    full_pkg,
    bom_dependency_tree,
    pkg_severity=None,
    as_tree=False,
    extra_text=None,
):
    """
    Method to locate and return a package tree from a dependency tree

    :param purl: The package purl to compare.
    :param full_pkg: The package reference to check against purl.
    :param bom_dependency_tree: The dependency tree.
    :param pkg_severity: The severity of the package vulnerability.
    :param as_tree: Flag indicating whether to return as a rich tree object.
    :param extra_text: Additional text to append to the display string.
    """
    pkg_tree = []
    if full_pkg and not purl:
        purl = full_pkg
    if not bom_dependency_tree:
        return [purl], Tree(
            get_pkg_display(purl, purl, extra_text=extra_text),
            style=Style(
                color="bright_red" if pkg_severity == "CRITICAL" else None
            ),
        )
    if len(bom_dependency_tree) > 1:
        for dep in bom_dependency_tree[1:]:
            ref = dep.get("ref")
            depends_on = dep.get("dependsOn", [])
            if purl in ref:
                if not pkg_tree or (pkg_tree and ref != pkg_tree[-1]):
                    pkg_tree.append(ref)
            elif purl in depends_on and purl not in pkg_tree:
                pkg_tree.append(ref)
                pkg_tree.append(purl)
                break
    # We need to iterate again to identify any parent for the parent
    if pkg_tree and len(bom_dependency_tree) > 1:
        for dep in bom_dependency_tree[1:]:
            if pkg_tree[0] in dep.get("dependsOn", []):
                if dep.get("ref") not in pkg_tree:
                    pkg_tree.insert(0, dep.get("ref"))
                break
        if as_tree and pkg_tree:
            tree = Tree(
                get_pkg_display(purl, pkg_tree[0], extra_text=extra_text),
                style=get_tree_style(purl, pkg_tree[0]),
            )
            if len(pkg_tree) > 1:
                subtree = tree
                for p in pkg_tree[1:]:
                    subtree = subtree.add(
                        get_pkg_display(purl, p, extra_text=extra_text),
                        style=get_tree_style(purl, p),
                    )
            return pkg_tree, tree
    return pkg_tree, Tree(
        get_pkg_display(purl, purl, extra_text=extra_text),
        style=Style(color="bright_red" if pkg_severity == "CRITICAL" else None),
    )


def is_lang_sw_edition(package_issue):
    """Check if the specified sw_edition belongs to any application package type"""
    if package_issue and package_issue["affected_location"].get("cpe_uri"):
        all_parts = CPE_FULL_REGEX.match(
            package_issue["affected_location"].get("cpe_uri")
        )
        if not all_parts or all_parts.group("sw_edition") in ("*", "-"):
            return True
        if (
            config.LANG_PKG_TYPES.get(all_parts.group("sw_edition"))
            or all_parts.group("sw_edition") in config.LANG_PKG_TYPES.values()
        ):
            return True
        return False
    return True


def is_os_target_sw(package_issue):
    """
    Since we rely on NVD, we filter those target_sw that definitely belong to a language
    """
    if package_issue and package_issue["affected_location"].get("cpe_uri"):
        all_parts = CPE_FULL_REGEX.match(
            package_issue["affected_location"].get("cpe_uri")
        )
        if (
            all_parts
            and all_parts.group("target_sw") not in ("*", "-")
            and (
                config.LANG_PKG_TYPES.get(all_parts.group("target_sw"))
                or all_parts.group("target_sw")
                in config.LANG_PKG_TYPES.values()
            )
        ):
            return False
    return True


@dataclass
class PrepareVdrOptions:
    project_type: str
    results: List
    pkg_aliases: Dict
    purl_aliases: Dict
    sug_version_dict: Dict
    scoped_pkgs: Dict
    no_vuln_table: bool
    bom_file: Optional[str]
    direct_purls: Dict
    reached_purls: Dict


def prepare_vdr(options: PrepareVdrOptions):
    """
    Generates a report summary of the dependency scan results, creates a
    vulnerability table and a top priority table for packages that require
    attention, prints the recommendations, and returns a list of
    vulnerability details.

    :param options: An instance of PrepareVdrOptions containing the function parameters.
    :return: Vulnerability details, dictionary of prioritized items
    :rtype: Tuple[List, Dict]
    """
    if not options.results:
        return [], {}
    table = Table(
        title=f"Dependency Scan Results ({options.project_type.upper()})",
        box=box.DOUBLE_EDGE,
        header_style="bold magenta",
        show_lines=True,
        min_width=150,
    )
    direct_purls = options.direct_purls or {}
    reached_purls = options.reached_purls or {}
    required_pkgs = options.scoped_pkgs.get("required", [])
    optional_pkgs = options.scoped_pkgs.get("optional", [])
    pkg_group_rows = defaultdict(list)
    pkg_vulnerabilities = []
    # Retrieve any dependency tree from the SBOM
    bom_dependency_tree, bom_data = retrieve_bom_dependency_tree(
        options.bom_file
    )
    oci_props = retrieve_oci_properties(bom_data)
    oci_product_types = oci_props.get("oci:image:componentTypes", "")
    for h in [
        "Dependency Tree" if len(bom_dependency_tree) > 0 else "CVE",
        "Insights",
        "Fix Version",
        "Severity",
        "Score",
    ]:
        justify = "left"
        if h == "Score":
            justify = "right"
        table.add_column(header=h, justify=justify, vertical="top")
    counts = Counts()
    for vuln_occ_dict in options.results:
        if isinstance(vuln_occ_dict, VulnerabilityOccurrence):
            counts, pkg_group_rows, pkg_vulnerabilities, tmp_insights, tmp_plain_insights = process_vuln_occ(
                bom_dependency_tree, direct_purls, oci_product_types, optional_pkgs, options,
                pkg_group_rows, pkg_vulnerabilities, reached_purls, required_pkgs, table,
                vuln_occ_dict.to_dict(), counts
            )
            continue
        counts, vuln, table, pkg_group_rows = analyze_cve_vuln(
            vuln_occ_dict, reached_purls, direct_purls, optional_pkgs, required_pkgs,
            bom_dependency_tree, options, table, pkg_group_rows, counts)
        pkg_vulnerabilities.append(vuln)
        # If the user doesn't want any table output return quickly
    if options.no_vuln_table:
        return pkg_vulnerabilities, pkg_group_rows
    output_results(counts, direct_purls, options, pkg_group_rows, pkg_vulnerabilities, reached_purls, table)
    return pkg_vulnerabilities, pkg_group_rows


def output_results(counts, direct_purls, options, pkg_group_rows, pkg_vulnerabilities, reached_purls, table):
    with open("pkg_vulnerabilities.json", "w", encoding="utf-8") as fp:
        json.dump(pkg_vulnerabilities, fp)
    if pkg_vulnerabilities:
        console.print()
        console.print(table)
    if pkg_group_rows:
        psection = Markdown(
            """
Next Steps
----------

Below are the vulnerabilities prioritized by depscan. Follow your team's remediation workflow to mitigate these findings.
        """,
            justify="left",
        )
        console.print(psection)
        utable = Table(
            title=f"Top Priority ({options.project_type.upper()})",
            box=box.DOUBLE_EDGE,
            header_style="bold magenta",
            show_lines=True,
            min_width=150,
        )
        for h in ("Package", "CVEs", "Fix Version", "Reachable"):
            utable.add_column(header=h, vertical="top")
        for k, v in pkg_group_rows.items():
            cve_list = []
            fv = None
            for c in v:
                cve_list.append(c.get("id"))
                if not fv:
                    fv = c.get("fixed_location")
            utable.add_row(
                v[0].get("p_rich_tree"),
                "\n".join(sorted(cve_list, reverse=True)),
                f"[bright_green]{fv}[/bright_green]",
                "[warning]Yes[/warning]" if reached_purls.get(k) else "",
            )
        console.print()
        console.print(utable)
        console.print()
    if counts.malicious_count:
        rmessage = ":stop_sign: Malicious package found! Treat this as a [bold]security incident[/bold] and follow your organization's playbook to remove this package from all affected applications."
        if counts.malicious_count > 1:
            rmessage = f":stop_sign: {counts.malicious_count} malicious packages found in this project! Treat this as a [bold]security incident[/bold] and follow your organization's playbook to remove the packages from all affected applications."
        console.print(
            Panel(
                rmessage,
                title="Action Required",
                expand=False,
            )
        )
    elif options.scoped_pkgs or counts.has_exploit_count:
        if not counts.pkg_attention_count and counts.has_exploit_count:
            if counts.has_reachable_exploit_count:
                rmessage = (
                    f":point_right: [magenta]{counts.has_reachable_exploit_count}"
                    f"[/magenta] out of {len(pkg_vulnerabilities)} vulnerabilities "
                    f"have [dark magenta]reachable[/dark magenta] exploits and requires your ["
                    f"magenta]immediate[/magenta] attention."
                )
            else:
                rmessage = (
                    f":point_right: [magenta]{counts.has_exploit_count}"
                    f"[/magenta] out of {len(pkg_vulnerabilities)} vulnerabilities "
                    f"have known exploits and requires your ["
                    f"magenta]immediate[/magenta] attention."
                )
            if not counts.has_os_packages:
                rmessage += (
                    "\nAdditional workarounds and configuration "
                    "changes might be required to remediate these "
                    "vulnerabilities."
                )
                if not options.scoped_pkgs:
                    rmessage += (
                        "\nNOTE: Package usage analysis was not "
                        "performed for this project."
                    )
            else:
                rmessage += (
                    "\n:scissors: Consider trimming this image by removing any "
                    "unwanted packages. Alternatively, use a slim "
                    "base image."
                )
                if counts.distro_packages_count and counts.distro_packages_count < len(
                    pkg_vulnerabilities
                ):
                    if (
                        len(pkg_vulnerabilities)
                        > config.max_distro_vulnerabilities
                    ):
                        rmessage += "\nNOTE: Check if the base image or the kernel version used is End-of-Life (EOL)."
                    else:
                        rmessage += (
                            f"\nNOTE: [magenta]{counts.distro_packages_count}"
                            f"[/magenta] distro-specific vulnerabilities "
                            f"out of {len(pkg_vulnerabilities)} could be prioritized "
                            f"for updates."
                        )
                if counts.has_redhat_packages:
                    rmessage += """\nNOTE: Vulnerabilities in RedHat packages with status "out of support" or "won't fix" are excluded from this result."""
                if counts.has_ubuntu_packages:
                    rmessage += """\nNOTE: Vulnerabilities in Ubuntu packages with status "DNE" or "needs-triaging" are excluded from this result."""
            console.print(
                Panel(
                    rmessage,
                    title="Recommendation",
                    expand=False,
                )
            )
        elif counts.pkg_attention_count:
            if counts.has_reachable_exploit_count:
                rmessage = (
                    f":point_right: Prioritize the [magenta]{counts.has_reachable_exploit_count}"
                    f"[/magenta] [bold magenta]reachable[/bold magenta] vulnerabilities with known exploits."
                )
            elif counts.has_exploit_count:
                rmessage = (
                    f":point_right: Prioritize the [magenta]{counts.has_exploit_count}"
                    f"[/magenta] vulnerabilities with known exploits."
                )
            else:
                rmessage = (
                    f":point_right: [info]{counts.pkg_attention_count}"
                    f"[/info] out of {len(pkg_vulnerabilities)} vulnerabilities "
                    f"requires your attention."
                )
            if counts.fix_version_count:
                if counts.fix_version_count == counts.pkg_attention_count:
                    rmessage += (
                        "\n:white_heavy_check_mark: You can update ["
                        "bright_green]all[/bright_green] the "
                        "packages using the mentioned fix version to "
                        "remediate."
                    )
                else:
                    v_text = (
                        "vulnerability"
                        if counts.fix_version_count == 1
                        else "vulnerabilities"
                    )
                    rmessage += (
                        f"\nYou can remediate [bright_green]"
                        f"{counts.fix_version_count}[/bright_green] "
                        f"{v_text} "
                        f"by updating the packages using the fix "
                        f"version :thumbsup:"
                    )
            console.print(
                Panel(
                    rmessage,
                    title="Recommendation",
                    expand=False,
                )
            )
        elif counts.critical_count:
            console.print(
                Panel(
                    f":white_medium_small_square: Prioritize the [magenta]{counts.critical_count}"
                    f"[/magenta] critical vulnerabilities confirmed by the "
                    f"vendor.",
                    title="Recommendation",
                    expand=False,
                )
            )
        else:
            if counts.has_os_packages:
                rmessage = (
                    ":white_medium_small_square: Prioritize any vulnerabilities in libraries such "
                    "as glibc, openssl, or libcurl.\nAdditionally, "
                    "prioritize the vulnerabilities with 'Flagged weakness' under insights."
                )
                rmessage += (
                    "\nVulnerabilities in Linux Kernel packages can "
                    "be usually ignored in containerized "
                    "environments as long as the vulnerability "
                    "doesn't lead to any 'container-escape' type "
                    "vulnerabilities."
                )
                if counts.has_redhat_packages:
                    rmessage += """\nNOTE: Vulnerabilities in RedHat packages
                    with status "out of support" or "won't fix" are excluded
                    from this result."""
                if counts.has_ubuntu_packages:
                    rmessage += """\nNOTE: Vulnerabilities in Ubuntu packages
                    with status "DNE" or "needs-triaging" are excluded from
                    this result."""
                console.print(Panel(rmessage, title="Recommendation"))
            else:
                rmessage = None
                if reached_purls:
                    rmessage = ":white_check_mark: No package requires immediate attention since the major vulnerabilities are not reachable."
                elif direct_purls:
                    rmessage = ":white_check_mark: No package requires immediate attention since the major vulnerabilities are found only in dev packages and indirect dependencies."
                if rmessage:
                    console.print(
                        Panel(
                            rmessage,
                            title="Recommendation",
                            expand=False,
                        )
                    )
    elif counts.critical_count:
        console.print(
            Panel(
                f":white_medium_small_square: Prioritize the [magenta]{counts.critical_count}"
                f"[/magenta] critical vulnerabilities confirmed by the vendor.",
                title="Recommendation",
                expand=False,
            )
        )
    else:
        console.print(
            Panel(
                ":white_check_mark: No package requires immediate attention.",
                title="Recommendation",
                expand=False,
            )
        )
    if reached_purls:
        output_reached_purls(reached_purls)


def get_version_range(package_issue, purl):
    """
    Generates a version range object for inclusion in the vdr file.

    :param package_issue: Vulnerability data dict
    :param purl: Package URL string

    :return: A list containing a dictionary with version range information.
    """
    new_prop = {}
    if (affected_location := package_issue.get("affected_location")) and (
        affected_version := affected_location.get("version")
    ):
        try:
            ppurl = PackageURL.from_string(purl)
            new_prop = {
                "name": "affectedVersionRange",
                "value": f"{ppurl.name}@" f"{affected_version}",
            }
            if ppurl.namespace:
                new_prop["value"] = f'{ppurl.namespace}/{new_prop["value"]}'
        except ValueError:
            ppurl = purl.split("@")
            if len(ppurl) == 2:
                new_prop = {
                    "name": "affectedVersionRange",
                    "value": f"{ppurl[0]}@{affected_version}",
                }

    return new_prop


def cvss_to_vdr_rating(vuln_occ_dict):
    """
    Generates a rating object for inclusion in the vdr file.

    :param vuln_occ_dict: Vulnerability data

    :return: A list containing a dictionary with CVSS score information.
    """
    cvss_score = vuln_occ_dict.get("cvss_score", 2.0)
    with contextlib.suppress(ValueError, TypeError):
        cvss_score = float(cvss_score)
    if (pkg_severity := vuln_occ_dict.get("severity", "").lower()) not in (
        "critical",
        "high",
        "medium",
        "low",
        "info",
        "none",
    ):
        pkg_severity = "unknown"
    ratings = [
        {
            "score": cvss_score,
            "severity": pkg_severity.lower(),
        }
    ]
    method = "31"
    if vuln_occ_dict.get("cvss_v3") and (
        vector_string := vuln_occ_dict["cvss_v3"].get("vector_string")
    ):
        ratings[0]["vector"] = vector_string
        with contextlib.suppress(CVSSError):
            method = cvss.CVSS3(vector_string).as_json().get("version")
            method = method.replace(".", "").replace("0", "")
    ratings[0]["method"] = f"CVSSv{method}"

    return ratings


def split_cwe(cwe):
    """
    Split the given CWE string into a list of CWE IDs.

    :param cwe: The problem issue taken from a vulnerability object

    :return: A list of CWE IDs
    :rtype: list
    """
    cwe_ids = []

    if isinstance(cwe, str):
        cwe_ids = re.findall(CWE_SPLITTER, cwe)
    elif isinstance(cwe, list):
        cwes = "|".join(cwe)
        cwe_ids = re.findall(CWE_SPLITTER, cwes)

    with contextlib.suppress(ValueError, TypeError):
        cwe_ids = [int(cwe_id) for cwe_id in cwe_ids]
    return cwe_ids


def summary_stats(results):
    """
    Generate summary stats

    :param results: List of scan results objects with severity attribute.
    :return: A dictionary containing the summary statistics for the severity
    levels of the vulnerabilities in the results list.
    """
    if not results:
        LOG.info("No oss vulnerabilities detected ✅")
        return {}
    summary = {
        "UNSPECIFIED": 0,
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0,
    }

    for i in results:
        ratings = i.get("ratings")
        if ratings:
            sev = ratings[0].get("severity", "").upper()
            summary[sev] += 1

    return summary


def analyse_pkg_risks(
    project_type, scoped_pkgs, risk_results, risk_report_file=None
):
    """
    Identify package risk and write to a json file

    :param project_type: Project type
    :param scoped_pkgs: A dict of lists of required/optional/excluded packages.
    :param risk_results: A dict of the risk metrics and scope for each package.
    :param risk_report_file: Path to the JSON file for the risk audit findings.
    """
    if not risk_results:
        return
    table = Table(
        title=f"Risk Audit Summary ({project_type})",
        box=box.DOUBLE_EDGE,
        header_style="bold magenta",
        min_width=150,
    )
    report_data = []
    required_pkgs = scoped_pkgs.get("required", [])
    optional_pkgs = scoped_pkgs.get("optional", [])
    excluded_pkgs = scoped_pkgs.get("excluded", [])
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
        project_type_pkg = f"{project_type}:{pkg}".lower()
        if project_type_pkg in required_pkgs:
            scope = "required"
        elif project_type_pkg in optional_pkgs:
            scope = "optional"
        elif project_type_pkg in excluded_pkgs:
            scope = "excluded"
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
        # Some risks gets special treatment for display
        if risk_metrics.get("risk_score") and (
            risk_metrics.get("risk_score") > config.pkg_max_risk_score
            or risk_metrics.get("pkg_private_on_public_registry_risk")
            or risk_metrics.get("pkg_deprecated_risk")
            or risk_metrics.get("pkg_version_deprecated_risk")
            or risk_metrics.get("pkg_version_missing_risk")
            or risk_metrics.get("pkg_includes_binary_risk")
            or risk_metrics.get("pkg_attested_check")
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
                if (
                    rk.endswith("_risk") or rk.endswith("_check")
                ) and rv is True:
                    rcat = rk.removesuffix("_risk").removesuffix("_check")
                    help_text = config.risk_help_text.get(rcat)
                    extra_info = risk_metrics.get(f"{rcat}_info")
                    if extra_info:
                        help_text = f"{help_text}\n{extra_info}"
                    # Only add texts that are available.
                    if help_text:
                        if rcat in (
                            "pkg_deprecated",
                            "pkg_version_deprecated",
                            "pkg_includes_binary",
                            "pkg_private_on_public_registry",
                        ):
                            risk_categories.append(f":cross_mark: {help_text}")
                        elif rk.endswith("_check"):
                            risk_categories.append(
                                f":white_heavy_check_mark: {help_text}"
                            )
                        else:
                            risk_categories.append(f":warning: {help_text}")
                        risk_categories_simple.append(help_text)
            data.append("\n".join(risk_categories))
            edata.append("~~".join(risk_categories_simple))
            table.add_row(*data)
            report_data.append(dict(zip(headers, edata)))
    if report_data:
        console.print(table)
        # Store the risk audit findings in jsonl format
        if risk_report_file:
            with open(risk_report_file, "w", encoding="utf-8") as outfile:
                for row in report_data:
                    json.dump(row, outfile)
                    outfile.write("\n")
    else:
        LOG.info("No package risks detected ✅")


def analyse_licenses(project_type, licenses_results, license_report_file=None):
    """
    Analyze package licenses

    :param project_type: Project type
    :param licenses_results: A dict with the license results for each package.
    :param license_report_file: Output filename for the license report.
    """
    if not licenses_results:
        return
    table = Table(
        title=f"License Scan Summary ({project_type})",
        box=box.DOUBLE_EDGE,
        header_style="bold magenta",
        min_width=150,
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
                conditions_str = ", ".join(lic["conditions"])
                if "http" not in conditions_str:
                    conditions_str = (
                        conditions_str.replace("--", " for ")
                        .replace("-", " ")
                        .title()
                    )
                data = [
                    *pkg_ver,
                    "{}{}".format(
                        (
                            "[cyan]"
                            if "GPL" in lic["spdx-id"]
                            or "CC-BY-" in lic["spdx-id"]
                            or "Facebook" in lic["spdx-id"]
                            or "WTFPL" in lic["spdx-id"]
                            else ""
                        ),
                        lic["spdx-id"],
                    ),
                    conditions_str,
                ]
                table.add_row(*data)
                report_data.append(dict(zip(headers, data)))
    if report_data:
        console.print(table)
        # Store the license scan findings in jsonl format
        if license_report_file:
            with open(license_report_file, "w", encoding="utf-8") as outfile:
                for row in report_data:
                    json.dump(row, outfile)
                    outfile.write("\n")
    else:
        LOG.info("No license violation detected ✅")


def suggest_version(results, pkg_aliases=None, purl_aliases=None):
    """
    Provide version suggestions

    :param results: List of package issue objects or dicts
    :param pkg_aliases: Dict of package names and aliases
    :param purl_aliases: Dict of purl names and aliases
    :return: Dict mapping each package to its suggested version
    """
    pkg_fix_map = {}
    sug_map = {}
    if not pkg_aliases:
        pkg_aliases = {}
    if not purl_aliases:
        purl_aliases = {}
    for res in results:
        if isinstance(res, dict):
            full_pkg = res.get("package") or ""
            fixed_location = res.get("fix_version") or ""
            matched_by = res.get("matched_by") or ""
        else:
            package_issue = res.get("package_issue") or {}
            full_pkg = package_issue.get("affected_location") or {}
            full_pkg = full_pkg.get("package") or ""
            fixed_location = package_issue.get("fixed_location") or ""
            affected_location = package_issue.get("affected_location") or {}
            matched_by = res.get("matched_by") or ""
            if affected_location.get("vendor"):
                full_pkg = (
                    f"{affected_location.get('vendor')}:"
                    f"{affected_location.get('package')}"
                )
        if matched_by:
            version = matched_by.split("|")[-1]
            full_pkg = full_pkg + ":" + version
        # De-alias package names
        if purl_aliases.get(full_pkg):
            full_pkg = purl_aliases.get(full_pkg)
        else:
            full_pkg = pkg_aliases.get(full_pkg, full_pkg)
        version_upgrades = pkg_fix_map.get(full_pkg, set())
        if fixed_location not in (
            PLACEHOLDER_FIX_VERSION,
            PLACEHOLDER_EXCLUDE_VERSION,
        ):
            version_upgrades.add(fixed_location)
        pkg_fix_map[full_pkg] = version_upgrades
    for k, v in pkg_fix_map.items():
        # Don't go near certain packages
        if "kernel" in k or "openssl" in k or "openssh" in k:
            continue
        if v:
            mversion = max_version(list(v))
            if mversion:
                sug_map[k] = mversion
    return sug_map


def classify_links(related_urls):
    """
    Method to classify and identify well-known links

    :param related_urls: List of URLs
    :return: Dictionary of classified links and URLs
    """
    clinks = {}
    if not related_urls:
        return clinks
    for rurl in related_urls:
        if "github.com" in rurl and "/pull" in rurl:
            clinks["GitHub PR"] = rurl
        elif "github.com" in rurl and "/issues" in rurl:
            clinks["GitHub Issue"] = rurl
        elif "bitbucket.org" in rurl and "/issues" in rurl:
            clinks["Bitbucket Issue"] = rurl
        elif "poc" in rurl:
            clinks["poc"] = rurl
        elif "apache.org" in rurl and "security" in rurl:
            clinks["Apache Security"] = rurl
            clinks["vendor"] = rurl
        elif "debian.org" in rurl and "security" in rurl:
            clinks["Debian Security"] = rurl
            clinks["vendor"] = rurl
        elif "security.gentoo.org" in rurl:
            clinks["Gentoo Security"] = rurl
            clinks["vendor"] = rurl
        elif "usn.ubuntu.com" in rurl:
            clinks["Ubuntu Security"] = rurl
            clinks["vendor"] = rurl
        elif "rubyonrails-security" in rurl:
            clinks["Ruby Security"] = rurl
            clinks["vendor"] = rurl
        elif "support.apple.com" in rurl:
            clinks["Apple Security"] = rurl
            clinks["vendor"] = rurl
        elif "access.redhat.com" in rurl:
            clinks["Red Hat Security"] = rurl
            clinks["vendor"] = rurl
        elif "oracle.com" in rurl and "security" in rurl:
            clinks["Oracle Security"] = rurl
            clinks["vendor"] = rurl
        elif "gitlab.alpinelinux.org" in rurl or "bugs.busybox.net" in rurl:
            clinks["vendor"] = rurl
        elif (
            "redhat.com" in rurl
            or "oracle.com" in rurl
            or "curl.haxx.se" in rurl
            or "nodejs.org" in rurl
            or "/security." in rurl
            or "/securityadvisories." in rurl
            or "sec-consult.com" in rurl
            or "jenkins.io/security" in rurl
            or "support.f5.com" in rurl
            or "suricata-ids.org/" in rurl
            or "foxitsoftware.com/support/" in rurl
            or "success.trendmicro.com/" in rurl
            or "docs.jamf.com/" in rurl
            or "www.postgresql.org/about" in rurl
        ):
            clinks["vendor"] = rurl
        elif "wordpress" in rurl or "wpvulndb" in rurl:
            clinks["wordpress"] = rurl
        elif "chrome.google.com/webstore" in rurl:
            clinks["Chrome Extension"] = rurl
        elif (
            "openwall.com" in rurl
            or "oss-security" in rurl
            or "www.mail-archive.com" in rurl
            or "lists." in rurl
            or "portal.msrc.microsoft.com" in rurl
            or "mail." in rurl
            or "securityfocus." in rurl
            or "securitytracker." in rurl
            or "/discussion/" in rurl
            or "/archives/" in rurl
            or "groups." in rurl
        ):
            clinks["Mailing List"] = rurl
        elif (
            "exploit-db" in rurl
            or "exploit-database" in rurl
            or "seebug.org" in rurl
            or "seclists.org" in rurl
            or "nu11secur1ty" in rurl
            or "packetstormsecurity.com" in rurl
            or "coresecurity.com" in rurl
            or "project-zero" in rurl
            or "0dd.zone" in rurl
            or "snyk.io/research/" in rurl
            or "chromium.googlesource.com/infra" in rurl
            or "synacktiv.com" in rurl
            or "bishopfox.com" in rurl
            or "zerodayinitiative.com" in rurl
            or "www.samba.org/samba/security/" in rurl
            or "www.synology.com/support/security/" in rurl
            or "us-cert.gov/advisories" in rurl
        ):
            clinks["exploit"] = rurl
        elif "oss-fuzz" in rurl:
            clinks["OSS-Fuzz"] = rurl
        elif "github.com/advisories" in rurl:
            clinks["GitHub Advisory"] = rurl
        elif (
            "hackerone" in rurl
            or "bugcrowd" in rurl
            or "bug-bounty" in rurl
            or "huntr.dev" in rurl
            or "bounties" in rurl
        ):
            clinks["Bug Bounty"] = rurl
        elif "cwe.mitre.org" in rurl:
            clinks["cwe"] = rurl
        elif "/community" in rurl or "/forum" in rurl or "/discuss" in rurl:
            clinks["Forum"] = rurl
        elif "bugzilla." in rurl or "bugs." in rurl or "chat." in rurl:
            clinks["Issue"] = rurl
        else:
            clinks["other"] = rurl
    return clinks


def find_purl_usages(bom_file, src_dir, reachables_slices_file):
    """
    Generates a list of reachable elements based on the given BOM file.

    :param bom_file: The path to the BOM file.
    :type bom_file: str
    :param src_dir: Source directory
    :type src_dir: str
    :param reachables_slices_file: Path to the reachables slices file
    :type reachables_slices_file: str

    :return: Tuple of direct_purls and reached_purls based on the occurrence and
                callstack evidences from the BOM. If reachables slices json were
                found, the file is read first.
    """
    direct_purls = defaultdict(int)
    reached_purls = defaultdict(int)
    if (
        not reachables_slices_file
        and src_dir
        and os.path.exists(os.path.join(src_dir, "reachables.slices.json"))
    ):
        reachables_slices_file = os.path.join(src_dir, "reachables.slices.json")
    if reachables_slices_file:
        with open(reachables_slices_file, "r", encoding="utf-8") as f:
            reachables = json.load(f).get("reachables")
        for flow in reachables:
            if len(flow.get("purls", [])) > 0:
                for apurl in flow.get("purls"):
                    reached_purls[apurl] += 1
    if bom_file and os.path.exists(bom_file):
        # For now we will also include usability slice as well
        with open(bom_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        for c in data["components"]:
            purl = c.get("purl", "")
            if c.get("evidence") and c["evidence"].get("occurrences"):
                direct_purls[purl] += len(c["evidence"].get("occurrences"))
    return dict(direct_purls), dict(reached_purls)


def get_cwe_list(data: ProblemType) -> List:
    cwes = []
    if not data:
        return cwes
    data = data.root
    for i in data:
        if record := i.descriptions:
            for rec in record:
                if rec.type == "CWE":
                    cwes.append(int(rec.cweId.split("-")[1]))
    return cwes


def cve_to_vdr(cve: CVE, vid):
    advisories, references, bug_bounties, pocs, exploits, source = refs_to_vdr(cve.root.containers.cna.references, vid.lower())
    vector, method, severity, score = parse_metrics(cve.root.containers.cna.metrics)
    description, detail = get_description_detail(cve.root.containers.cna.descriptions)
    if not source:
        source = {"name": cve.root.cveMetadata.assignerShortName.root.capitalize()}
        if source.get("name") == "Github_m":
            source = {"name": "GitHub", "url": f"https://github.com/advisories/{vid}"}
            advisories.append({"title": f"GitHub Advisory {vid}", "url": f"https://github.com/advisories/{vid}"})
    cwes = get_cwe_list(cve.root.containers.cna.problemTypes)
    vendor = ""
    if cve.root.containers.cna.affected:
        vendor = cve.root.containers.cna.affected.root[0].vendor
    ratings = {}
    if vector:
        ratings = {"method": method, "severity": severity.lower(), "score": score, "vector": vector}
    return source, references, advisories, cwes, description, detail, ratings, bug_bounties, pocs, exploits, vendor


def parse_metrics(metrics):
    vector = ""
    method = ""
    severity = "unknown"
    score = ""
    if not metrics:
        return vector, method
    if metrics.root and (m := (metrics.root[0].cvssV3_1 or metrics.root[0].cvssV3_0)):
        vector = m.vectorString
        severity = m.baseSeverity.value
        method = "CVSSv31" if m.version.value == "3.1" else "CVSSv3"
        score = m.baseScore.root
    return vector, method, severity, score


def process_affected(options, vuln_occ_dict):
    # package_issue = vuln_occ_dict.get("package_issue") or {}
    matched_by = vuln_occ_dict.get("matched_by") or ""
    full_pkg = ""
    if affected := vuln_occ_dict.get("affected"):
        full_pkg = affected[0].get("ref")
    project_type_pkg = f"{options.project_type}:{full_pkg}"
    if matched_by:
        version = matched_by.split("|")[-1]
        full_pkg = f"{full_pkg}:{version}"
    # De-alias package names
    if options.pkg_aliases.get(full_pkg):
        full_pkg = options.pkg_aliases.get(full_pkg)
    else:
        full_pkg = options.pkg_aliases.get(full_pkg.lower(), full_pkg)
    version_used = vuln_occ_dict.get("matched_by")
    purl = options.purl_aliases.get(full_pkg, full_pkg)
    return full_pkg, {}, project_type_pkg, purl, version_used


def process_package_issue(options, vuln_occ_dict):
    package_issue = vuln_occ_dict.get("package_issue") or {}
    matched_by = vuln_occ_dict.get("matched_by") or ""
    full_pkg = vuln_occ_dict.get("affected") or package_issue.get("affected_location")
    full_pkg = full_pkg.get("package") or ""
    project_type_pkg = (
        f"{options.project_type}:"
        f"{package_issue.get('affected_location', {}).get('package')}"
    )
    if package_issue.get("affected_location", {}).get("vendor"):
        full_pkg = (
            f"{package_issue['affected_location'].get('vendor')}:"
            f"{package_issue['affected_location'].get('package')}"
        )
    elif package_issue.get("affected_location", {}).get("cpe_uri"):
        vendor, _, _, _ = parse_cpe(
            package_issue.get("affected_location", {}).get("cpe_uri")
        )
        if vendor:
            full_pkg = (
                f"{vendor}:"
                f"{package_issue['affected_location'].get('package')}"
            )
    if matched_by:
        version = matched_by.split("|")[-1]
        full_pkg = full_pkg + ":" + version
    # De-alias package names
    if options.pkg_aliases.get(full_pkg):
        full_pkg = options.pkg_aliases.get(full_pkg)
    else:
        full_pkg = options.pkg_aliases.get(full_pkg.lower(), full_pkg)
    version_used = package_issue.get("affected_location", {}).get("version") or ""
    purl = options.purl_aliases.get(full_pkg, full_pkg)
    return full_pkg, package_issue, project_type_pkg, purl, version_used


def analyze_cve_vuln(vuln, reached_purls, direct_purls, optional_pkgs, required_pkgs, bom_dependency_tree, options, table, pkg_group_rows, counts):
    insights = []
    plain_insights = []
    purl = vuln.get("matched_by") or ""
    purl_obj = PackageURL.from_string(purl) if purl else None
    package_type = vuln.get("type") or ""
    affects = [{
        "ref": purl,
        "versions": [{"range": vuln.get("matching_vers"), "status": "affected"}]
    }]
    recommendation = ""
    vid = vuln.get("cve_id") or ""
    fixed_location = ""
    has_flagged_cwe = False
    if unaffected := get_unaffected(vuln.get("matching_vers")):
        affects[0]["versions"].append(unaffected)
        recommendation = f"Update to version {unaffected.get('version')} or later."
        fixed_location = unaffected.get("version")
    vdict = {
        "id": vuln.get("cve_id"), "bom-ref": f"{vuln.get('cve_id')}/{vuln.get('matched_by')}",
        "affects": affects, "recommendation": recommendation
    }

    try:
        cve_record = vuln.get("source_data")
        if not isinstance(cve_record, CVE):
            return vdict
    except KeyError:
        return vdict

    if not cve_record:
        return vdict

    source, references, advisories, cwes, description, detail, rating, bounties, pocs, exploits, vendor = cve_to_vdr(cve_record, vid)
    vdict |= {
        "affects": affects, "source": source, "references": references, "advisories": advisories,
        "cwes": cwes, "description": description, "detail": detail, "ratings": [rating],
        "published": cve_record.root.cveMetadata.datePublished.strftime("%Y-%m-%dT%H:%M:%S"),
        "updated": cve_record.root.cveMetadata.dateUpdated.strftime("%Y-%m-%dT%H:%M:%S")
    }
    is_required = False
    package_usage = ""
    plain_package_usage = ""
    if direct_purls.get(purl) or purl in required_pkgs:
        is_required = True
    if pocs or bounties:
        if reached_purls.get(purl):
            insights.append("[yellow]:notebook_with_decorative_cover: Reachable Bounty target[/yellow]")
            plain_insights.append("Reachable Bounty target")
            counts.has_reachable_poc_count += 1
            counts.has_reachable_exploit_count += 1
        elif direct_purls.get(purl):
            insights.append("[yellow]:notebook_with_decorative_cover: Bug Bounty target[/yellow]")
            plain_insights.append("Bug Bounty target")
        else:
            insights.append("[yellow]:notebook_with_decorative_cover: Has PoC[/yellow]")
            plain_insights.append("Has PoC")
        counts.has_poc_count += 1
    # Locate this package in the tree
    pkg_tree_list, p_rich_tree = pkg_sub_tree(
        purl,
        purl.replace(":", "/"),
        bom_dependency_tree,
        pkg_severity=rating.get("severity"),
        as_tree=True,
        extra_text=f":left_arrow: {vid}",
    )
    if is_required and package_type not in config.OS_PKG_TYPES:
        if direct_purls.get(purl):
            package_usage = (
                f":direct_hit: Used in [info]"
                f"{str(direct_purls.get(purl))}"
                f"[/info] locations"
            )
            plain_package_usage = (
                f"Used in {str(direct_purls.get(purl))} locations"
            )
        else:
            package_usage = ":direct_hit: Direct dependency"
            plain_package_usage = "Direct dependency"
    elif (
        not optional_pkgs and pkg_tree_list and len(pkg_tree_list) > 1
    ) or (
        purl in optional_pkgs
        # or full_pkg in optional_pkgs
        # or project_type_pkg in optional_pkgs
    ):
        if package_type in config.OS_PKG_TYPES:
            package_usage = (
                "[spring_green4]:notebook: Local install[/spring_green4]"
            )
            plain_package_usage = "Local install"
            counts.has_os_packages = True
        else:
            package_usage = (
                "[spring_green4]:notebook: Indirect "
                "dependency[/spring_green4]"
            )
            plain_package_usage = "Indirect dependency"
    pkg_requires_attn = False
    if package_usage:
        insights.append(package_usage)
        plain_insights.append(plain_package_usage)
    if pocs or bounties:
        if reached_purls.get(purl):
            insights.append(
                "[yellow]:notebook_with_decorative_cover: Reachable Bounty target[/yellow]"
            )
            plain_insights.append("Reachable Bounty target")
            counts.has_reachable_poc_count += 1
            counts.has_reachable_exploit_count += 1
            pkg_requires_attn = True
        elif direct_purls.get(purl):
            insights.append(
                "[yellow]:notebook_with_decorative_cover: Bug Bounty target[/yellow]"
            )
            plain_insights.append("Bug Bounty target")
        else:
            insights.append(
                "[yellow]:notebook_with_decorative_cover: Has PoC[/yellow]"
            )
            plain_insights.append("Has PoC")
        counts.has_poc_count += 1
        if rating and rating.get("severity", "") in ("CRITICAL", "HIGH"):
            pkg_requires_attn = True
    if package_type not in config.OS_PKG_TYPES and reached_purls.get(purl):
        # If it has a poc, an insight might have gotten added above
        if not pkg_requires_attn:
            insights.append(":receipt: Reachable")
            plain_insights.append("Reachable")
        else:
            insights.append(":receipt: Vendor Confirmed")
            plain_insights.append("Vendor Confirmed")
    if exploits:
        if reached_purls.get(purl) or direct_purls.get(purl):
            insights.append(
                "[bright_red]:exclamation_mark: Reachable and Exploitable[/bright_red]"
            )
            plain_insights.append("Reachable and Exploitable")
            counts.has_reachable_exploit_count += 1
            # Fail safe. Packages with exploits and direct usage without
            # a reachable flow are still considered reachable to reduce
            # false negatives
            if not reached_purls.get(purl):
                reached_purls[purl] = 1
        elif has_flagged_cwe:
            if (vendor and vendor in ("gnu",)) or (
                purl_obj and purl_obj.get("name") in ("glibc", "openssl")
            ):
                insights.append(
                    "[bright_red]:exclamation_mark: Reachable and Exploitable[/bright_red]"
                )
                plain_insights.append("Reachable and Exploitable")
                counts.has_reachable_exploit_count += 1
            else:
                insights.append(
                    "[bright_red]:exclamation_mark: Exploitable[/bright_red]"
                )
                plain_insights.append("Exploitable")
                counts.has_exploit_count += 1
        else:
            insights.append(
                "[bright_red]:exclamation_mark: Known Exploits[/bright_red]"
            )
            plain_insights.append("Known Exploits")
        counts.has_exploit_count += 1
        pkg_requires_attn = True
    if cve_record.root.containers.cna.affected.root and (cpes := cve_record.root.containers.cna.affected.root[0].cpes):
        if all((distro_package(i.root) for i in cpes)):
            insights.append("[spring_green4]:direct_hit: Distro specific[/spring_green4]")
            plain_insights.append("Distro specific")
            counts.distro_packages_count += 1
            counts.has_os_packages = True
    if pkg_requires_attn and fixed_location and purl:
        pkg_group_rows[purl].append(
            {
                "id": vid,
                "fixed_location": fixed_location,
                "p_rich_tree": p_rich_tree,
            }
        )
    insights = list(set(insights))
    plain_insights = list(set(plain_insights))
    if not options.no_vuln_table:
        table.add_row(
            p_rich_tree,
            "\n".join(insights),
            fixed_location,
            f"""{"[bright_red]" if rating.get("severity", "") == "CRITICAL" else ""}{rating.get("severity", "")}""",
            f"""{"[bright_red]" if rating.get("severity", "") == "CRITICAL" else ""}{rating.get("score", "")}""",
        )
        analysis = {}
        if exploits:
            analysis = {
                "state": "exploitable",
                "detail": f'See {exploits[0]}',
            }
        elif pocs:
            analysis = {
                "state": "in_triage",
                "detail": f'See {pocs[0].get("url")}',
            }
        elif pkg_tree_list and len(pkg_tree_list) > 1:
            analysis = {
                "state": "in_triage",
                "detail": f"Dependency Tree: {json.dumps(pkg_tree_list)}",
            }
        properties = [
            {
                "name": "depscan:insights",
                "value": "\\n".join(plain_insights),
            },
            {
                "name": "depscan:prioritized",
                "value": "true" if pkg_group_rows.get(purl) else "false",
            },
        ]
        vuln |= {"properties": properties, "analysis": analysis}
    # if is_required and package_type not in config.OS_PKG_TYPES:
    #     if direct_purls.get(purl):
    #         package_usage = (
    #             f":direct_hit: Used in [info]"
    #             f"{str(direct_purls.get(purl))}"
    #             f"[/info] locations"
    #         )
    #         plain_package_usage = (
    #             f"Used in {str(direct_purls.get(purl))} locations"
    #         )
    #     else:
    #         package_usage = ":direct_hit: Direct dependency"
    #         plain_package_usage = "Direct dependency"
    # elif not optional_pkgs and pkg_tree_list and len(pkg_tree_list) > 1 or purl in optional_pkgs:
    #     if package_type in config.OS_PKG_TYPES:
    #         package_usage = (
    #             "[spring_green4]:notebook: Local install[/spring_green4]"
    #         )
    #         plain_package_usage = "Local install"
    #         counts.has_os_packages = True
    #     else:
    #         package_usage = (
    #             "[spring_green4]:notebook: Indirect "
    #             "dependency[/spring_green4]"
    #         )
    #         plain_package_usage = "Indirect dependency"
    # if rating.get("severity") in ("CRITICAL", "HIGH"):
    #     pkg_requires_attn = True
    #     if direct_purls.get(purl):
    #         counts.pkg_attention_count += 1
    #     if recommendation:
    #         counts.fix_version_count += 1
    #     if vendor in config.OS_PKG_TYPES and rating.get("severity", "") == "CRITICAL":
    #         counts.critical_count += 1
    return counts, vdict, table, pkg_group_rows


def get_unaffected(vers):
    if "|" in vers:
        vers = vers.split("|")[-1]
        if "<" in vers and "<=" not in vers:
            unaffected_vers = vers.replace("<", "")
            return {"version": unaffected_vers, "status": "unaffected"}
    return None


def refs_to_vdr(references: Reference, vid) -> Tuple[List, List, List, List, List, Dict]:
    """
    Parses the reference list provided by VDB and converts to VDR objects

    :param references: List of dictionaries of references
    :type references: list

    :return: Tuple of advisories, references for VDR
    :rtype: tuple[list, list]
    """
    if not references:
        return [], [], [], [], [], {}
    ref = {str(i.url.root) for i in references.root}
    # ref = {i.get("url") for i in references}
    advisories = []
    refs = []
    bug_bounty = []
    poc = []
    exploit = []
    source = {}
    for i in ref:
        category, match, system_name = get_ref_summary_helper(i, config.REF_MAP)
        if not match:
            continue
        if category == "CVE Record":
            record = {"id": match[0], "source": {"url": i}}
            if "nvd.nist.gov" in i:
                record["source"]["name"] = "NVD CVE Record"
            refs.append(record)
            if match[0].lower() == vid and not source:
                source = record["source"]
        elif "Advisory" in category:
            adv_id = match["id"]
            if system_name in {"Jfrog", "Gentoo"}:
                adv_id, system_name = adv_ref_parsing(adv_id, i, match, system_name)
            if adv_id.lower() == vid and not source:
                source = {"name": system_name, "url": i}
            advisories.append({"title": f"{system_name} {adv_id}", "url": i})
            if system_name == "NPM Advisory":
                adv_id = f"NPM-{adv_id}"
            refs.append({"id": adv_id, "source": {"name": system_name, "url": i}})
        elif category in ("POC", "Bug Bounty", "Exploit"):
            if category == "POC":
                poc.append(i)
            elif category == "Bug Bounty":
                bug_bounty.append(i)
            else:
                exploit.append(i)
        elif category == "Bugzilla":
            refs.append({"id": f"{match['org']}-bugzilla-{match['id']}", "source": {"name": f"{format_system_name(match['org'])} Bugzilla", "url": i}})
        elif system_name:
            refs.append({"id": category, "source": {"name": system_name, "url": i}})
    return advisories, refs, bug_bounty, poc, exploit, source


def adv_ref_parsing(adv_id, i, match, system_name):
    if system_name == "Gentoo":
        adv_id = f"glsa-{match['id']}"
    if system_name == "Jfrog":
        system_name = "JFrog"
        if id_match := JFROG_ADVISORY.search(i):
            adv_id = id_match["id"]
    return adv_id, system_name


class Counts:
    fp_count = 0
    pkg_attention_count = 0
    critical_count = 0
    malicious_count = 0
    has_poc_count = 0
    has_reachable_poc_count = 0
    has_exploit_count = 0
    has_reachable_exploit_count = 0
    fix_version_count = 0
    wont_fix_version_count = 0
    distro_packages_count = 0
    has_os_packages = False
    has_redhat_packages = False
    has_ubuntu_packages = False
    ids_seen = {}


def output_reached_purls(reached_purls):
    sorted_reached_purls = sorted(
        ((value, key) for (key, value) in reached_purls.items()),
        reverse=True,
    )[:3]
    sorted_reached_dict = OrderedDict(
        (k, v) for v, k in sorted_reached_purls
    )
    rsection = Markdown(
        """
Proactive Measures
------------------

Below are the top reachable packages identified by depscan. Setup alerts and notifications to actively monitor these packages for new vulnerabilities and exploits.
    """,
        justify="left",
    )
    console.print(rsection)
    rtable = Table(
        title="Top Reachable Packages",
        box=box.DOUBLE_EDGE,
        header_style="bold magenta",
        show_lines=True,
        min_width=150,
    )
    for h in ("Package", "Reachable Flows"):
        rtable.add_column(header=h, vertical="top")
    for k, v in sorted_reached_dict.items():
        rtable.add_row(k, str(v))
    console.print()
    console.print(rtable)
    console.print()


def process_vuln_occ(bom_dependency_tree, direct_purls, oci_product_types, optional_pkgs,
                options, pkg_group_rows, pkg_vulnerabilities, reached_purls, required_pkgs, table,
                vuln_occ_dict, counts):
    vid = vuln_occ_dict.get("id") or ""
    package_issue = {}
    purl = ""
    full_pkg = ""
    project_type_pkg = ""
    cwes = []
    version_used = ""
    if problem_type := vuln_occ_dict.get("problem_type"):
        cwes = split_cwe(problem_type)
        full_pkg, package_issue, project_type_pkg, purl, version_used = process_package_issue(
            options,
            vuln_occ_dict
        )
    has_flagged_cwe = False
    package_type = None
    insights = []
    plain_insights = []
    if vid.startswith("MAL-"):
        insights.append("[bright_red]:stop_sign: Malicious[/bright_red]")
        plain_insights.append("Malicious")
        counts.malicious_count += 1
    purl_obj = None
    vendor = package_issue.get("affected_location", {}).get("vendor")
    # If the match was based on name and version alone then the alias might legitimately lack a full purl
    # Such results are usually false positives but could yield good hits at times
    # So, instead of suppressing fully we try our best to tune and reduce the FP
    if not purl.startswith("pkg:"):
        if options.project_type in config.OS_PKG_TYPES:
            if vendor and (
                vendor in config.LANG_PKG_TYPES.values()
                or config.LANG_PKG_TYPES.get(vendor)
            ):
                counts.fp_count += 1
                return counts, pkg_group_rows, pkg_vulnerabilities
            # Some nvd data might match application CVEs for
            # OS vendors which can be filtered
            if not is_os_target_sw(package_issue):
                counts.fp_count += 1
                return counts, pkg_group_rows, pkg_vulnerabilities
        # Issue #320 - Malware matches without purl are false positives
        if vid.startswith("MAL-"):
            counts.fp_count += 1
            counts.malicious_count -= 1
            return counts, pkg_group_rows, pkg_vulnerabilities, insights, plain_insights
    else:
        purl_obj = parse_purl(purl)
        # Issue #320 - Malware matches without purl are false positives
        if not purl_obj and vid.startswith("MAL-"):
            counts.fp_count += 1
            counts.malicious_count -= 1
            return counts, pkg_group_rows, pkg_vulnerabilities, insights, plain_insights
        if purl_obj:
            version_used = purl_obj.get("version")
            package_type = purl_obj.get("type")
            qualifiers = purl_obj.get("qualifiers", {})
            # Filter application CVEs from distros
            if (
                config.LANG_PKG_TYPES.get(package_type)
                or package_type in config.LANG_PKG_TYPES.values()
            ) and (
                (vendor and vendor in config.OS_PKG_TYPES)
                or not is_lang_sw_edition(package_issue)
            ):
                counts.fp_count += 1
                return counts, pkg_group_rows, pkg_vulnerabilities, insights, plain_insights
            if package_type in config.OS_PKG_TYPES:
                # Bug #208 - do not report application CVEs
                if vendor and (
                    vendor in config.LANG_PKG_TYPES.values()
                    or config.LANG_PKG_TYPES.get(vendor)
                ):
                    counts.fp_count += 1
                    return counts, pkg_group_rows, pkg_vulnerabilities, insights, plain_insights
                if package_type and (
                    package_type in config.LANG_PKG_TYPES.values()
                    or config.LANG_PKG_TYPES.get(package_type)
                ):
                    counts.fp_count += 1
                    return counts, pkg_group_rows, pkg_vulnerabilities, insights, plain_insights
                if (
                    vendor
                    and oci_product_types
                    and vendor not in oci_product_types
                ):
                    # Bug #170 - do not report CVEs belonging to other distros
                    if vendor in config.OS_PKG_TYPES:
                        counts.fp_count += 1
                        return counts, pkg_group_rows, pkg_vulnerabilities, insights, plain_insights
                    # Some nvd data might match application CVEs for
                    # OS vendors which can be filtered
                    if not is_os_target_sw(package_issue):
                        counts.fp_count += 1
                        return counts, pkg_group_rows, pkg_vulnerabilities, insights, plain_insights
                    insights.append(
                        f"[#7C8082]:telescope: Vendor {vendor}[/#7C8082]"
                    )
                    plain_insights.append(f"Vendor {vendor}")
                counts.has_os_packages = True
                for acwe in cwes:
                    if acwe in config.OS_VULN_KEY_CWES:
                        has_flagged_cwe = True
                        break
                # Don't flag the cwe for ignorable os packages
                if has_flagged_cwe and (
                    purl_obj.get("name") in config.OS_PKG_UNINSTALLABLE
                    or purl_obj.get("name") in config.OS_PKG_IGNORABLE
                    or vendor in config.OS_PKG_IGNORABLE
                ):
                    has_flagged_cwe = False
                else:
                    if (
                        purl_obj.get("name") in config.OS_PKG_IGNORABLE
                        or vendor in config.OS_PKG_IGNORABLE
                    ):
                        insights.append(
                            "[#7C8082]:mute: Suppress for containers[/#7C8082]"
                        )
                        plain_insights.append("Suppress for containers")
                    elif (
                        purl_obj.get("name") in config.OS_PKG_UNINSTALLABLE
                    ):
                        insights.append(
                            "[#7C8082]:scissors: Uninstall candidate[/#7C8082]"
                        )
                        plain_insights.append("Uninstall candidate")
                # If the flag remains after all the suppressions then add it as an insight
                if has_flagged_cwe:
                    insights.append(
                        "[#7C8082]:triangular_flag: Flagged weakness[/#7C8082]"
                    )
                    plain_insights.append("Flagged weakness")
            if qualifiers:
                if "ubuntu" in qualifiers.get("distro", ""):
                    counts.has_ubuntu_packages = True
                if "rhel" in qualifiers.get("distro", ""):
                    counts.has_redhat_packages = True
    if counts.ids_seen.get(vid + purl):
        counts.fp_count += 1
        return counts, pkg_group_rows, pkg_vulnerabilities, insights, plain_insights
    # Mark this CVE + pkg as seen to avoid duplicates
    counts.ids_seen[vid + purl] = True
    # Find the best fix version
    fixed_location = best_fixed_location(
        options.sug_version_dict.get(purl), package_issue.get("fixed_location")
    )
    if (
        options.sug_version_dict.get(purl) == PLACEHOLDER_FIX_VERSION
        or package_issue.get("fixed_location") == PLACEHOLDER_FIX_VERSION
    ):
        counts.wont_fix_version_count += 1
    package_usage = "N/A"
    plain_package_usage = "N/A"
    pkg_severity = vuln_occ_dict.get("severity")
    is_required = False
    pkg_requires_attn = False
    related_urls = vuln_occ_dict.get("related_urls")
    clinks = classify_links(related_urls)
    if direct_purls.get(purl):
        is_required = True
    elif not direct_purls and (
        purl in required_pkgs
        or full_pkg in required_pkgs
        or project_type_pkg in required_pkgs
    ):
        is_required = True
    if pkg_severity in ("CRITICAL", "HIGH"):
        if is_required:
            counts.pkg_attention_count += 1
        if fixed_location:
            counts.fix_version_count += 1
        if (
            clinks.get("vendor") or package_type in config.OS_PKG_TYPES
        ) and pkg_severity == "CRITICAL":
            counts.critical_count += 1
    # Locate this package in the tree
    pkg_tree_list, p_rich_tree = pkg_sub_tree(
        purl,
        full_pkg.replace(":", "/"),
        bom_dependency_tree,
        pkg_severity=pkg_severity,
        as_tree=True,
        extra_text=f":left_arrow: {vid}",
    )
    if is_required and package_type not in config.OS_PKG_TYPES:
        if direct_purls.get(purl):
            package_usage = (
                f":direct_hit: Used in [info]"
                f"{str(direct_purls.get(purl))}"
                f"[/info] locations"
            )
            plain_package_usage = (
                f"Used in {str(direct_purls.get(purl))} locations"
            )
        else:
            package_usage = ":direct_hit: Direct dependency"
            plain_package_usage = "Direct dependency"
    elif (
        not optional_pkgs and pkg_tree_list and len(pkg_tree_list) > 1
    ) or (
        purl in optional_pkgs
        or full_pkg in optional_pkgs
        or project_type_pkg in optional_pkgs
    ):
        if package_type in config.OS_PKG_TYPES:
            package_usage = (
                "[spring_green4]:notebook: Local install[/spring_green4]"
            )
            plain_package_usage = "Local install"
            counts.has_os_packages = True
        else:
            package_usage = (
                "[spring_green4]:notebook: Indirect "
                "dependency[/spring_green4]"
            )
            plain_package_usage = "Indirect dependency"
    if package_usage != "N/A":
        insights.append(package_usage)
        plain_insights.append(plain_package_usage)
    if clinks.get("poc") or clinks.get("Bug Bounty"):
        if reached_purls.get(purl):
            insights.append(
                "[yellow]:notebook_with_decorative_cover: Reachable Bounty target[/yellow]"
            )
            plain_insights.append("Reachable Bounty target")
            counts.has_reachable_poc_count += 1
            counts.has_reachable_exploit_count += 1
            pkg_requires_attn = True
        elif direct_purls.get(purl):
            insights.append(
                "[yellow]:notebook_with_decorative_cover: Bug Bounty target[/yellow]"
            )
            plain_insights.append("Bug Bounty target")
        else:
            insights.append(
                "[yellow]:notebook_with_decorative_cover: Has PoC[/yellow]"
            )
            plain_insights.append("Has PoC")
        counts.has_poc_count += 1
        if pkg_severity in ("CRITICAL", "HIGH"):
            pkg_requires_attn = True
    if clinks.get("vendor") and package_type not in config.OS_PKG_TYPES:
        if reached_purls.get(purl):
            # If it has a poc, an insight might have gotten added above
            if not pkg_requires_attn:
                insights.append(":receipt: Reachable")
                plain_insights.append("Reachable")
        else:
            insights.append(":receipt: Vendor Confirmed")
            plain_insights.append("Vendor Confirmed")
    if clinks.get("exploit"):
        if reached_purls.get(purl) or direct_purls.get(purl):
            insights.append(
                "[bright_red]:exclamation_mark: Reachable and Exploitable[/bright_red]"
            )
            plain_insights.append("Reachable and Exploitable")
            counts.has_reachable_exploit_count += 1
            # Fail safe. Packages with exploits and direct usage without
            # a reachable flow are still considered reachable to reduce
            # false negatives
            if not reached_purls.get(purl):
                reached_purls[purl] = 1
        elif has_flagged_cwe:
            if (vendor and vendor in ("gnu",)) or (
                purl_obj and purl_obj.get("name") in ("glibc", "openssl")
            ):
                insights.append(
                    "[bright_red]:exclamation_mark: Reachable and Exploitable[/bright_red]"
                )
                plain_insights.append("Reachable and Exploitable")
                counts.has_reachable_exploit_count += 1
            else:
                insights.append(
                    "[bright_red]:exclamation_mark: Exploitable[/bright_red]"
                )
                plain_insights.append("Exploitable")
                counts.has_exploit_count += 1
        else:
            insights.append(
                "[bright_red]:exclamation_mark: Known Exploits[/bright_red]"
            )
            plain_insights.append("Known Exploits")
        counts.has_exploit_count += 1
        pkg_requires_attn = True
    if distro_package(package_issue["affected_location"].get("cpe_uri")):
        insights.append(
            "[spring_green4]:direct_hit: Distro specific[/spring_green4]"
        )
        plain_insights.append("Distro specific")
        counts.distro_packages_count += 1
        counts.has_os_packages = True
    if pkg_requires_attn and fixed_location and purl:
        pkg_group_rows[purl].append(
            {
                "id": vid,
                "fixed_location": fixed_location,
                "p_rich_tree": p_rich_tree,
            }
        )
    if not options.no_vuln_table:
        table.add_row(
            p_rich_tree,
            "\n".join(insights),
            fixed_location,
            f"""{"[bright_red]" if pkg_severity == "CRITICAL" else ""}{vuln_occ_dict.get("severity")}""",
            f"""{"[bright_red]" if pkg_severity == "CRITICAL" else ""}{vuln_occ_dict.get("cvss_score")}""",
        )
    if purl:
        source = {}
        if vid.startswith("CVE"):
            source = {
                "name": "NVD",
                "url": f"https://nvd.nist.gov/vuln/detail/{vid}",
            }
        elif vid.startswith("GHSA") or vid.startswith("npm"):
            source = {
                "name": "GitHub Advisory",
                "url": f"https://github.com/advisories/{vid}",
            }
        versions = [{"version": version_used, "status": "affected"}]
        recommendation = ""
        if fixed_location:
            versions.append(
                {"version": fixed_location, "status": "unaffected"}
            )
            recommendation = f"Update to {fixed_location} or later"
        affects = [{"ref": purl, "versions": versions}]
        analysis = {}
        if clinks.get("exploit"):
            analysis = {
                "state": "exploitable",
                "detail": f'See {clinks.get("exploit")}',
            }
        elif clinks.get("poc"):
            analysis = {
                "state": "in_triage",
                "detail": f'See {clinks.get("poc")}',
            }
        elif pkg_tree_list and len(pkg_tree_list) > 1:
            analysis = {
                "state": "in_triage",
                "detail": f"Dependency Tree: {json.dumps(pkg_tree_list)}",
            }
        ratings = cvss_to_vdr_rating(vuln_occ_dict)
        properties = [
            {
                "name": "depscan:insights",
                "value": "\\n".join(plain_insights),
            },
            {
                "name": "depscan:prioritized",
                "value": "true" if pkg_group_rows.get(purl) else "false",
            },
        ]
        affected_version_range = get_version_range(package_issue, purl)
        if affected_version_range:
            properties.append(affected_version_range)
        advisories = []
        for k, v in clinks.items():
            advisories.append({"title": k, "url": v})
        vuln = {
            "bom-ref": f"{vid}/{purl}",
            "id": vid,
            "source": source,
            "ratings": ratings,
            "cwes": cwes,
            "description": vuln_occ_dict.get("short_description"),
            "recommendation": recommendation,
            "advisories": advisories,
            "analysis": analysis,
            "affects": affects,
            "properties": properties,
        }
        if source_orig_time := vuln_occ_dict.get("source_orig_time"):
            vuln["published"] = source_orig_time
        if source_update_time := vuln_occ_dict.get("source_update_time"):
            vuln["updated"] = source_update_time
        pkg_vulnerabilities.append(vuln)
    return counts, pkg_group_rows, pkg_vulnerabilities, insights, plain_insights


def get_version_used(purl):
    if not purl:
        return ""
    purl_obj = PackageURL.from_string(purl)
    return purl_obj.version
