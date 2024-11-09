# -*- coding: utf-8 -*-

import contextlib
import json
import os.path
import re
from collections import defaultdict, OrderedDict
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import cvss
from custom_json_diff.lib.utils import compare_versions, json_load, json_dump, file_write
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
from vdb.lib.cve_model import CVE, ProblemTypes, References
from vdb.lib.utils import parse_purl, parse_cpe

from depscan.lib import config
from depscan.lib.config import (
    SEVERITY_REF, UPPER_VERSION_FROM_DETAIL_A, UPPER_VERSION_FROM_DETAIL_B, ADVISORY,
    CWE_SPLITTER, JFROG_ADVISORY
)
from depscan.lib.csaf import get_ref_summary_helper
from depscan.lib.logger import LOG, console
from depscan.lib.utils import (
    max_version,
    get_description_detail,
    format_system_name,
    make_version_suggestions, combine_vdrs, make_purl, combine_references
)

NEWLINE = "\\n"


# Deprecated
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
    if bom_data:= json_load(bom_file):
        return bom_data.get("dependencies", []), bom_data
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
    pkg_severity="unknown",
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
                color="bright_red" if pkg_severity.upper() == "CRITICAL" else None
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
        style=Style(color="bright_red" if pkg_severity.upper() == "CRITICAL" else None),
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
    suggest_mode: bool
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
    pkg_vulnerabilities = []
    if not options.results:
        return pkg_vulnerabilities, defaultdict(list)
    direct_purls = options.direct_purls or {}
    reached_purls = options.reached_purls or {}
    required_pkgs = options.scoped_pkgs.get("required", [])
    optional_pkgs = options.scoped_pkgs.get("optional", [])
    # Retrieve any dependency tree from the SBOM
    bom_dependency_tree, bom_data = retrieve_bom_dependency_tree(
        options.bom_file
    )
    oci_props = retrieve_oci_properties(bom_data)
    oci_product_types = oci_props.get("oci:image:componentTypes", "")
    counts = Counts()
    include_pkg_group_rows = set()
    for vuln_occ_dict in options.results:
        if not vuln_occ_dict:
            continue
        if isinstance(vuln_occ_dict, VulnerabilityOccurrence):
            counts, add_to_pkg_group_rows, vuln = process_vuln_occ(
                bom_dependency_tree, direct_purls, oci_product_types, optional_pkgs, options, reached_purls, required_pkgs,
                vuln_occ_dict.to_dict(), counts
            )
        else:
            counts, vuln, add_to_pkg_group_rows = analyze_cve_vuln(
                vuln_occ_dict, reached_purls, direct_purls, optional_pkgs, required_pkgs,
                bom_dependency_tree, counts)
        pkg_vulnerabilities.append(vuln)
        if add_to_pkg_group_rows:
            include_pkg_group_rows.add(vuln.get("bom-ref"))
        # If the user doesn't want any table output return quickly
    if options.suggest_mode:
        pkg_vulnerabilities = make_version_suggestions(pkg_vulnerabilities, options.project_type)
    pkg_vulnerabilities = dedupe_vdrs(pkg_vulnerabilities)
    pkg_group_rows, table = generate_console_output(pkg_vulnerabilities, bom_dependency_tree, include_pkg_group_rows, options)
    pkg_vulnerabilities = remove_extra_metadata(pkg_vulnerabilities)
    if options.no_vuln_table:
        return pkg_vulnerabilities, pkg_group_rows
    output_results(counts, direct_purls, options, pkg_group_rows, pkg_vulnerabilities, reached_purls, table)
    return pkg_vulnerabilities, pkg_group_rows


def remove_extra_metadata(vdrs):
    new_vdrs = []
    exclude = {"insights", "purl_prefix", "p_rich_tree", "fixed_location"}
    for vdr in vdrs:
        new_vdr = {}
        for key, value in vdr.items():
            if key not in exclude:
                new_vdr |= {key: value}
        new_vdrs.append(new_vdr)
    return new_vdrs


def dedupe_vdrs(vdrs):
    new_vdrs = {}
    for vdr in vdrs:
        if vdr.get("bom-ref", "") in new_vdrs:
            new_vdrs[vdr["bom-ref"]] = combine_vdrs(new_vdrs[vdr["bom-ref"]], vdr)
        else:
            new_vdrs[vdr["bom-ref"]] = vdr
    return list(new_vdrs.values())


def generate_console_output(pkg_vulnerabilities, bom_dependency_tree, include_pkg_group_rows, options):
    table = Table(
        title=f"Dependency Scan Results ({options.project_type.upper()})",
        box=box.DOUBLE_EDGE,
        header_style="bold magenta",
        show_lines=True,
        min_width=150,
    )
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
    pkg_group_rows = defaultdict(list)
    for vdr in pkg_vulnerabilities:
        if vdr["bom-ref"] in include_pkg_group_rows:
            pkg_group_rows[vdr["bom-ref"]].append(
                {
                    "id": vdr["id"],
                    "fixed_location": vdr["fixed_location"],
                    "p_rich_tree": vdr["p_rich_tree"],
                }
            )
        if rating := vdr.get("ratings", {}):
            rating = rating[0]
        table.add_row(
            vdr["p_rich_tree"],
            "\n".join(vdr["insights"]),
            vdr["fixed_location"],
            f"""{"[bright_red]" if rating.get("severity", "").upper() == "CRITICAL" else ""}{rating.get("severity", "").upper()}""",
            f"""{"[bright_red]" if rating.get("severity", "").upper() == "CRITICAL" else ""}{rating.get("score", "")}""",
        )
    return pkg_group_rows, table


def output_results(counts, direct_purls, options, pkg_group_rows, pkg_vulnerabilities, reached_purls, table):
    json_dump("pkg_vulnerabilities.json", pkg_vulnerabilities, True, log=LOG)
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
    if (pkg_severity := vuln_occ_dict.get("severity", "").lower()) not in SEVERITY_REF:
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
            file_write(risk_report_file, "\n".join([json.dumps(row) for row in report_data]), log=LOG)
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
            file_write(license_report_file, "\n".join([json.dumps(row) for row in report_data]))
    else:
        LOG.info("No license violation detected ✅")


# Deprecated
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
        reachables = json_load(reachables_slices_file).get("reachables")
        for flow in reachables:
            if len(flow.get("purls", [])) > 0:
                for apurl in flow.get("purls"):
                    reached_purls[apurl] += 1
    if bom_file and os.path.exists(bom_file):
        data = json_load(bom_file)
        # For now we will also include usability slice as well
        for c in data["components"]:
            purl = c.get("purl", "")
            if c.get("evidence") and c["evidence"].get("occurrences"):
                direct_purls[purl] += len(c["evidence"].get("occurrences"))
    return dict(direct_purls), dict(reached_purls)


def get_cwe_list(data: ProblemTypes | None) -> List:
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


def cve_to_vdr(cve: CVE, vid: str):
    advisories, references, bug_bounties, pocs, exploits, vendors, source = refs_to_vdr(cve.root.containers.cna.references, vid.lower())
    vector, method, severity, score = parse_metrics(cve.root.containers.cna.metrics)
    try:
        description, detail = get_description_detail(cve.root.containers.cna.descriptions)
    except AttributeError:
        description, detail = "", ""
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
    return source, references, advisories, cwes, description, detail, ratings, bug_bounties, pocs, exploits, vendors, vendor


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


def get_unaffected(vuln):
    vers = vuln.get("matching_vers", "")
    if "|" in vers and "<=" not in vers:
        vers = vers.split("|")[-1]
        return vers.replace("<", "")
    return ""


def get_version_from_detail(detail, affected_version):
    version = ""
    if match := UPPER_VERSION_FROM_DETAIL_A.search(detail):
        version = match["version"].rstrip(".")
    if match := UPPER_VERSION_FROM_DETAIL_B.search(detail):
        version = match["version"].rstrip(".")
    if affected_version and version and compare_versions(affected_version, version, "<="):
        return version
    return ""


def refs_to_vdr(references: References | None, vid) -> Tuple[List, List, List, List, List, List, Dict]:
    """
    Parses the reference list provided by VDB and converts to VDR objects

    :param references: List of dictionaries of references
    :param vid: str of vulnerability id

    :return: Tuple of advisories, references for VDR
    :rtype: tuple[list, list]
    """
    if not references:
        return [], [], [], [], [], [], {}
    with contextlib.suppress(AttributeError):
        ref = {str(i.url.root) for i in references.root}
    advisories = []
    refs = []
    bug_bounty = []
    poc = []
    exploit = []
    vendor = []
    source = {}
    for i in ref:
        category, rmatch, system_name = get_ref_summary_helper(i, config.REF_MAP)
        if not rmatch:
            continue
        if category == "CVE Record":
            record = {"id": rmatch[0], "source": {"url": i}}
            if "nvd.nist.gov" in i:
                record["source"]["name"] = "NVD"
            refs.append(record)
            if rmatch[0].lower() == vid and not source:
                source = record["source"]
            advisories.append({"title": rmatch[0], "url": i})
        elif "Advisory" in category:
            adv_id = rmatch["id"]
            if (tmp := adv_id.replace("-", "")) and tmp.isalpha() and len(tmp) < 20:
                continue
            if "vuldb" in i.lower():
                adv_id = f"vuldb-{adv_id}"
            if system_name in {"Jfrog Advisory", "Gentoo Advisory"}:
                adv_id, system_name = adv_ref_parsing(adv_id, i, system_name)
            if adv_id.lower() == vid and not source:
                source = {"name": system_name, "url": i}
            advisories.append({"title": f"{system_name} {adv_id}", "url": i})
            if system_name == "NPM Advisory":
                adv_id = f"NPM-{adv_id}"
            refs.append({"id": adv_id, "source": {"name": system_name, "url": i}})
            vendor.append(i)
        elif category in ("POC", "BugBounty", "Exploit"):
            if category == "POC":
                poc.append(i)
            elif category == "BugBounty":
                bug_bounty.append(i)
            else:
                adv_id = f"{system_name.lower().replace(' ', '-')}-{rmatch['id']}"
                refs.append({"id": adv_id, "source": {"name": system_name, "url": i}})
                if system_name in {"Synology", "Samba", "CISA", "Zero Day Initiative"}:
                    advisories.append({"title": f"{system_name} Advisory {rmatch['id']}", "url": i})
                    if system_name in {"Synology Exploits", "Samba Exploits"}:
                        vendor.append(i)
                exploit.append(i)
        elif category == "Bugzilla":
            refs.append({
                "id": f"{rmatch['org']}-bugzilla-{rmatch['id']}",
                "source": {"name": f"{format_system_name(rmatch['org'])} Bugzilla", "url": i}
            })
            vendor.append(i)
        elif category == "Vendor":
            if "announce" in i:
                vendor.append(i)
            if rmatch := ADVISORY.search(i):
                system_name = f"{format_system_name(rmatch['org'])} Mailing List"
                refs.append({
                    "id": f"{rmatch['org']}-msg-{rmatch['id']}",
                    "source": {"name": system_name, "url": i}
                })
        elif category == "Mailing List":
            if "openwall" in i:
                if not (rmatch := config.REF_MAP["openwall"].search(i)):
                    continue
                adv_id = f"openwall-{rmatch['list_type']}-msg-{rmatch['id'].replace('/', '-')}"
            else:
                rmatch = ADVISORY.search(i)
                if not rmatch:
                    continue
                adv_id = f"{rmatch['org']}-msg-{rmatch['id']}"
            if rmatch:
                system_name = f"{format_system_name(rmatch['org'])} {category}"
                refs.append({"id": adv_id, "source": {"name": system_name, "url": i}})
                vendor.append(i)
        elif category == "Generic":
            refs.append({
                "id": f"{rmatch['user']}-{rmatch['repo']}-{rmatch['type']}-{rmatch['id']}",
                "source": {
                    "name": f"{format_system_name(rmatch['host'])} {rmatch['type'].capitalize()}",
                    "url": i}
            })
    return combine_references(advisories, []), combine_references(refs, []), bug_bounty, poc, exploit, vendor, source


def adv_ref_parsing(adv_id, i, system_name):
    if system_name == "Gentoo Advisory":
        adv_id = f"glsa-{adv_id}"
    if system_name == "Jfrog Advisory":
        system_name = "JFrog Advisory"
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
                options, reached_purls, required_pkgs, vuln_occ_dict, counts):
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
    pkg_severity = vuln_occ_dict.get("severity") or "unknown"
    if vid.startswith("MAL-"):
        insights.append("[bright_red]:stop_sign: Malicious[/bright_red]")
        plain_insights.append("Malicious")
        counts.malicious_count += 1
    purl_obj = None
    vendor = package_issue.get("affected_location", {}).get("vendor")
    purl_prefix = ""
    if purl and "@" in purl:
        purl_prefix = purl.split("@")
        if len(purl_prefix) > 2:
            purl_prefix.pop()
        purl_prefix = "".join(purl_prefix)
    # If the match was based on name and version alone then the alias might legitimately lack a full purl
    # Such results are usually false positives but could yield good hits at times
    # So, instead of suppressing fully we try our best to tune and reduce the FP
    description, detail = get_description_detail(vuln_occ_dict.get("short_description", ""))
    # Find the best fix version
    recommendation = ""
    fixed_location = package_issue.get("fixed_location") or get_version_from_detail(detail, version_used)
    versions = [{"version": version_used, "status": "affected"}]
    if fixed_location:
        versions.append(
            {"version": fixed_location, "status": "unaffected"}
        )
        recommendation = f"Update to version {fixed_location}."
    affects = [{"ref": purl, "versions": versions}]
    if fixed_location == PLACEHOLDER_FIX_VERSION:
        counts.wont_fix_version_count += 1
    add_to_pkg_group_rows = False
    pkg_tree_list, p_rich_tree = pkg_sub_tree(
        purl,
        "",
        bom_dependency_tree,
        pkg_severity=pkg_severity,
        as_tree=True,
        extra_text=f":left_arrow: {vid}",
    )
    source = {}
    if purl:
        if vid.startswith("CVE"):
            source = {
                "name": "NVD",
                "url": f"https://nvd.nist.gov/vuln/detail/{vid}",
            }
        elif vid.startswith("GHSA") or vid.startswith("npm"):
            source = {
                "name": "GitHub",
                "url": f"https://github.com/advisories/{vid}",
            }
    related_urls = vuln_occ_dict.get("related_urls")
    clinks = classify_links(related_urls)
    advisories = []
    for k, v in clinks.items():
        advisories.append({"title": k, "url": v})
    vuln = {
        "advisories": advisories,
        "affects": affects,
        "analysis": get_analysis(clinks, pkg_tree_list),
        "bom-ref": f"{vid}/{purl}",
        "cwes": cwes,
        "description": description,
        "detail": detail,
        "id": vid,
        "properties": [],
        "published": vuln_occ_dict.get("source_orig_time", ""),
        "purl_prefix": purl_prefix,
        "ratings": cvss_to_vdr_rating(vuln_occ_dict),
        "recommendation": recommendation,
        "source": source,
        "updated": vuln_occ_dict.get("source_update_time", ""),
        "insights": [],
        "p_rich_tree": p_rich_tree,
        "fixed_location": fixed_location
    }
    if not purl.startswith("pkg:"):
        if options.project_type in config.OS_PKG_TYPES:
            if vendor and (
                vendor in config.LANG_PKG_TYPES.values()
                or config.LANG_PKG_TYPES.get(vendor)
            ):
                counts.fp_count += 1
                return counts, add_to_pkg_group_rows, vuln
            # Some nvd data might match application CVEs for
            # OS vendors which can be filtered
            if not is_os_target_sw(package_issue):
                counts.fp_count += 1
                return counts, add_to_pkg_group_rows, vuln
        # Issue #320 - Malware matches without purl are false positives
        if vid.startswith("MAL-"):
            counts.fp_count += 1
            counts.malicious_count -= 1
            return counts, add_to_pkg_group_rows, vuln
    else:
        purl_obj = parse_purl(purl)
        # Issue #320 - Malware matches without purl are false positives
        if not purl_obj and vid.startswith("MAL-"):
            counts.fp_count += 1
            counts.malicious_count -= 1
            return counts, add_to_pkg_group_rows, vuln
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
                return counts, add_to_pkg_group_rows, vuln
            if package_type in config.OS_PKG_TYPES:
                # Bug #208 - do not report application CVEs
                if vendor and (
                    vendor in config.LANG_PKG_TYPES.values()
                    or config.LANG_PKG_TYPES.get(vendor)
                ):
                    counts.fp_count += 1
                    return counts, add_to_pkg_group_rows, vuln
                if package_type and (
                    package_type in config.LANG_PKG_TYPES.values()
                    or config.LANG_PKG_TYPES.get(package_type)
                ):
                    counts.fp_count += 1
                    return counts, add_to_pkg_group_rows, vuln
                if (
                    vendor
                    and oci_product_types
                    and vendor not in oci_product_types
                ):
                    # Bug #170 - do not report CVEs belonging to other distros
                    if vendor in config.OS_PKG_TYPES:
                        counts.fp_count += 1
                        return counts, add_to_pkg_group_rows, vuln
                    # Some nvd data might match application CVEs for
                    # OS vendors which can be filtered
                    if not is_os_target_sw(package_issue):
                        counts.fp_count += 1
                        return counts, add_to_pkg_group_rows, vuln
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
    # if counts.ids_seen.get(vid + purl):
    #     counts.fp_count += 1
    #     return counts, add_to_pkg_group_rows, vuln
    # Mark this CVE + pkg as seen to avoid duplicates
    counts.ids_seen[vid + purl] = True
    package_usage = "N/A"
    plain_package_usage = "N/A"
    is_required = False
    pkg_requires_attn = False
    if direct_purls.get(purl):
        is_required = True
    elif not direct_purls and (
        purl in required_pkgs
        or full_pkg in required_pkgs
        or project_type_pkg in required_pkgs
    ):
        is_required = True
    if pkg_severity.upper() in ("CRITICAL", "HIGH"):
        if is_required:
            counts.pkg_attention_count += 1
        if fixed_location:
            counts.fix_version_count += 1
        if (
            clinks.get("vendor") or package_type in config.OS_PKG_TYPES
        ) and pkg_severity == "CRITICAL":
            counts.critical_count += 1
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
    if (clinks.get("vendor") and package_type not in config.OS_PKG_TYPES) or reached_purls.get(purl):
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
        add_to_pkg_group_rows = True
    vuln |= {
        "insights": insights,
        "properties": get_vuln_properties(fixed_location, pkg_requires_attn, plain_insights, purl)}
    return counts, add_to_pkg_group_rows, vuln


def get_analysis(clinks, pkg_tree_list):
    if clinks.get("exploit"):
        return {
            "state": "exploitable",
            "detail": f'See {clinks.get("exploit")}',
        }
    elif clinks.get("poc"):
        return {
            "state": "in_triage",
            "detail": f'See {clinks.get("poc")}',
        }
    elif pkg_tree_list and len(pkg_tree_list) > 1:
        return {
            "state": "in_triage",
            "detail": f"Dependency Tree: {json.dumps(pkg_tree_list)}",
        }
    return {}


def get_version_used(purl):
    if not purl:
        return ""
    version = make_purl(purl)
    if version:
        version = version.version
    elif "@" in purl:
        version = purl.split("@")[-1]
    return version


def analyze_cve_vuln(vuln, reached_purls, direct_purls, optional_pkgs, required_pkgs, bom_dependency_tree, counts):
    insights = []
    plain_insights = []
    purl = vuln.get("matched_by") or ""
    purl_obj = parse_purl(purl)
    version_used = get_version_used(purl)
    package_type = vuln.get("type") or ""
    affects = [{
        "ref": purl,
        "versions": [{"range": vuln.get("matching_vers"), "status": "affected"}]
    }]
    recommendation = ""
    vid = vuln.get("cve_id") or ""
    if vid.startswith("MAL-"):
        insights.append("[bright_red]:stop_sign: Malicious[/bright_red]")
        plain_insights.append("Malicious")
        counts.malicious_count += 1
    has_flagged_cwe = False
    add_to_pkg_group_rows = False
    if fixed_location := get_unaffected(vuln):
        affects[0]["versions"].append({"version": fixed_location, "status": "unaffected"})
        recommendation = f"Update to version {fixed_location}."
        if fixed_location == PLACEHOLDER_FIX_VERSION:
            counts.wont_fix_version_count += 1
    pkg_tree_list, p_rich_tree = pkg_sub_tree(
        purl,
        purl.replace(":", "/"),
        bom_dependency_tree,
        pkg_severity="unknown",
        as_tree=True,
        extra_text=f":left_arrow: {vid}",
    )
    vdict = {
        "id": vuln.get("cve_id"), "bom-ref": f"{vuln.get('cve_id')}/{vuln.get('matched_by')}",
        "affects": affects, "recommendation": recommendation, "purl_prefix": vuln['purl_prefix'],
        "source": {}, "references": [], "advisories": [], "cwes": [], "description": "",
        "fixed_location": fixed_location, "detail": "", "ratings": [], "published": "",
        "updated": "", "analysis": get_analysis({}, pkg_tree_list), "insights":[], "p_rich_tree": p_rich_tree
    }
    try:
        cve_record = vuln.get("source_data")
        if not isinstance(cve_record, CVE):
            return counts, vdict, add_to_pkg_group_rows
    except KeyError:
        return counts, vdict, add_to_pkg_group_rows

    if not cve_record:
        return counts, vdict, add_to_pkg_group_rows

    source, references, advisories, cwes, description, detail, rating, bounties, pocs, exploits, vendors, vendor = cve_to_vdr(cve_record, vid)
    if detail and not fixed_location and (fixed_location := get_version_from_detail(detail, version_used)):
        vdict["affects"][0]["versions"].append({"version": fixed_location, "status": "unaffected"})
        vdict["recommendation"] = f"Update to version {fixed_location}."
        vdict["fixed_location"] = fixed_location
    pkg_tree_list, p_rich_tree = pkg_sub_tree(
        purl,
        purl.replace(":", "/"),
        bom_dependency_tree,
        pkg_severity=rating.get("severity") or "unknown",
        as_tree=True,
        extra_text=f":left_arrow: {vid}",
    )
    published = cve_record.root.cveMetadata.datePublished
    updated = cve_record.root.cveMetadata.dateUpdated
    vdict |= {
        "source": source, "references": references, "advisories": advisories, "cwes": cwes,
        "description": description, "detail": detail, "ratings": [rating],
        "published": published.strftime("%Y-%m-%dT%H:%M:%S") if published else "",
        "updated": updated.strftime("%Y-%m-%dT%H:%M:%S") if updated else "",
    }
    is_required = False
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
    package_usage = ""
    plain_package_usage = ""
    if is_required and package_type not in config.OS_PKG_TYPES:
        if direct_purls.get(purl):
            package_usage = (f":direct_hit: Used in [info]{str(direct_purls.get(purl))}[/info] "
                             f"locations")
            plain_package_usage = f"Used in {str(direct_purls.get(purl))} locations"
        else:
            package_usage = ":direct_hit: Direct dependency"
            plain_package_usage = "Direct dependency"
    elif (
        not optional_pkgs and pkg_tree_list and len(pkg_tree_list) > 1
    ) or purl in optional_pkgs:
        if package_type in config.OS_PKG_TYPES:
            package_usage = "[spring_green4]:notebook: Local install[/spring_green4]"
            plain_package_usage = "Local install"
            counts.has_os_packages = True
        else:
            package_usage = "[spring_green4]:notebook: Indirect dependency[/spring_green4]"
            plain_package_usage = "Indirect dependency"
    pkg_requires_attn = False
    if pocs or bounties:
        if reached_purls.get(purl):
            insights.append(
                "[yellow]:notebook_with_decorative_cover: Reachable Bounty target[/yellow]")
            plain_insights.append("Reachable Bounty target")
            counts.has_reachable_poc_count += 1
            counts.has_reachable_exploit_count += 1
            pkg_requires_attn = True
        elif direct_purls.get(purl):
            insights.append("[yellow]:notebook_with_decorative_cover: Bug Bounty target[/yellow]")
            plain_insights.append("Bug Bounty target")
        else:
            insights.append("[yellow]:notebook_with_decorative_cover: Has PoC[/yellow]")
            plain_insights.append("Has PoC")
        counts.has_poc_count += 1
        if rating.get("severity", "").upper() in ("CRITICAL", "HIGH"):
            pkg_requires_attn = True
            if direct_purls.get(purl):
                counts.pkg_attention_count += 1
            if recommendation:
                counts.fix_version_count += 1
            if vendor in config.OS_PKG_TYPES and rating.get("severity", "") == "CRITICAL":
                counts.critical_count += 1
    if vendors and package_type not in config.OS_PKG_TYPES and reached_purls.get(purl):
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
                "[bright_red]:exclamation_mark: Reachable and Exploitable[/bright_red]")
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
                    "[bright_red]:exclamation_mark: Reachable and Exploitable[/bright_red]")
                plain_insights.append("Reachable and Exploitable")
                counts.has_reachable_exploit_count += 1
            else:
                insights.append("[bright_red]:exclamation_mark: Exploitable[/bright_red]")
                plain_insights.append("Exploitable")
                counts.has_exploit_count += 1
        else:
            insights.append("[bright_red]:exclamation_mark: Known Exploits[/bright_red]")
            plain_insights.append("Known Exploits")
        counts.has_exploit_count += 1
        pkg_requires_attn = True
    if cve_record.root.containers.cna.affected.root and (
            cpes := cve_record.root.containers.cna.affected.root[0].cpes):
        if all((distro_package(i.root) for i in cpes)):
            insights.append("[spring_green4]:direct_hit: Distro specific[/spring_green4]")
            plain_insights.append("Distro specific")
            counts.distro_packages_count += 1
            counts.has_os_packages = True
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
    elif not optional_pkgs and pkg_tree_list and len(pkg_tree_list) > 1 or purl in optional_pkgs:
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
    if package_usage:
        insights.append(package_usage)
        plain_insights.append(plain_package_usage)
    add_to_pkg_group_rows = pkg_requires_attn and fixed_location and purl
    insights = list(set(insights))
    plain_insights = list(set(plain_insights))
    if exploits or pocs:
        vdict["analysis"] = get_analysis(
            {"exploits": exploits[0] if exploits else [], "pocs": pocs[0] if pocs else []},
            pkg_tree_list
            )
    vdict |= {
        "insights": insights,
        "properties": get_vuln_properties(fixed_location, pkg_requires_attn, plain_insights, purl)}
    return counts, vdict, add_to_pkg_group_rows


def get_vuln_properties(fixed_location, pkg_requires_attn, plain_insights, purl):
    properties = [{
        "name": "depscan:prioritized",
        "value": "true" if pkg_requires_attn and fixed_location and purl else "false",
    }]
    if plain_insights:
        plain_insights.sort()
        properties.append({"name": "depscan:insights", "value": "\\n".join(plain_insights)})
    return properties
