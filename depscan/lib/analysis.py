# -*- coding: utf-8 -*-

import contextlib
import json
import os.path
import re
from collections import OrderedDict, defaultdict
from dataclasses import dataclass
from typing import Dict, List, Optional

import cvss
from cvss import CVSSError
from packageurl import PackageURL
from rich import box
from rich.markdown import Markdown
from rich.panel import Panel
from rich.style import Style
from rich.table import Table
from rich.tree import Tree
from vdb.lib import CPE_FULL_REGEX
from vdb.lib.config import placeholder_exclude_version, placeholder_fix_version
from vdb.lib.utils import parse_cpe, parse_purl

from depscan.lib import config
from depscan.lib.logger import LOG, console
from depscan.lib.utils import max_version

NEWLINE = "\\n"

CWE_SPLITTER = re.compile(r"(?<=CWE-)[0-9]\d{0,5}", re.IGNORECASE)


def best_fixed_location(sug_version, orig_fixed_location):
    """
    Compares the suggested version with the version from the original fixed
    location and returns the best version based on the major versions.
    See: https://github.com/AppThreat/dep-scan/issues/72

    :param sug_version: Suggested version
    :param orig_fixed_location: Version from original fixed location
    :return: Version
    """
    if (
        not orig_fixed_location
        and sug_version
        and sug_version != placeholder_fix_version
    ):
        return sug_version
    if sug_version and orig_fixed_location:
        if sug_version == placeholder_fix_version:
            return ""
        tmp_a = sug_version.split(".")[0]
        tmp_b = orig_fixed_location.split(".")[0]
        if tmp_a == tmp_b:
            return sug_version
    # Handle the placeholder version used by OS distros
    if orig_fixed_location == placeholder_fix_version:
        return ""
    return orig_fixed_location


def distro_package(package_issue):
    """
    Determines if a given Common Platform Enumeration (CPE) belongs to an
    operating system (OS) distribution.
    TODO: Clarify parameter
    :param package_issue: An object
    :return: bool
    """
    if package_issue:
        all_parts = CPE_FULL_REGEX.match(
            package_issue["affected_location"].get("cpe_uri")
        )
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
            and all_parts.group("target_sw") != "*"
            and (
                all_parts.group("target_sw") in config.LANG_PKG_TYPES.keys()
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
    ids_seen = {}
    direct_purls = options.direct_purls or {}
    reached_purls = options.reached_purls or {}
    required_pkgs = options.scoped_pkgs.get("required", [])
    optional_pkgs = options.scoped_pkgs.get("optional", [])
    fp_count = 0
    pkg_attention_count = 0
    critical_count = 0
    has_poc_count = 0
    has_reachable_poc_count = 0
    has_exploit_count = 0
    has_reachable_exploit_count = 0
    fix_version_count = 0
    wont_fix_version_count = 0
    has_os_packages = False
    has_redhat_packages = False
    has_ubuntu_packages = False
    distro_packages_count = 0
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
    for vuln_occ_dict in options.results:
        vid = vuln_occ_dict.get("id")
        problem_type = vuln_occ_dict.get("problem_type")
        cwes = []
        if problem_type:
            cwes = split_cwe(problem_type)
        has_flagged_cwe = False
        package_issue = vuln_occ_dict.get("package_issue")
        matched_by = vuln_occ_dict.get("matched_by")
        full_pkg = package_issue["affected_location"].get("package")
        project_type_pkg = (
            f"{options.project_type}:"
            f"{package_issue['affected_location'].get('package')}"
        )
        if package_issue["affected_location"].get("vendor"):
            full_pkg = (
                f"{package_issue['affected_location'].get('vendor')}:"
                f"{package_issue['affected_location'].get('package')}"
            )
        elif package_issue["affected_location"].get("cpe_uri"):
            vendor, _, _, _ = parse_cpe(
                package_issue["affected_location"].get("cpe_uri")
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
        version_used = package_issue["affected_location"].get("version")
        purl = options.purl_aliases.get(full_pkg, full_pkg)
        package_type = None
        insights = []
        plain_insights = []
        purl_obj = None
        vendor = package_issue["affected_location"].get("vendor")
        # If the match was based on name and version alone then the alias might legitimately lack a full purl
        # Such results are usually false positives but could yield good hits at times
        # So, instead of suppressing fully we try our best to tune and reduce the FP
        if not purl.startswith("pkg:"):
            if options.project_type in config.OS_PKG_TYPES:
                if vendor and (
                    vendor in config.LANG_PKG_TYPES.values()
                    or vendor in config.LANG_PKG_TYPES.keys()
                ):
                    fp_count += 1
                    continue
                # Some nvd data might match application CVEs for
                # OS vendors which can be filtered
                if not is_os_target_sw(package_issue):
                    fp_count += 1
                    continue
        else:
            purl_obj = parse_purl(purl)
            if purl_obj:
                version_used = purl_obj.get("version")
                package_type = purl_obj.get("type")
                qualifiers = purl_obj.get("qualifiers", {})
                if package_type in config.OS_PKG_TYPES:
                    # Bug #208 - do not report application CVEs
                    if vendor and (
                        vendor in config.LANG_PKG_TYPES.values()
                        or vendor in config.LANG_PKG_TYPES.keys()
                    ):
                        fp_count += 1
                        continue
                    if package_type and (
                        package_type in config.LANG_PKG_TYPES.values()
                        or package_type in config.LANG_PKG_TYPES.keys()
                    ):
                        fp_count += 1
                        continue
                    if (
                        vendor
                        and oci_product_types
                        and vendor not in oci_product_types
                    ):
                        # Bug #170 - do not report CVEs belonging to other distros
                        if vendor in config.OS_PKG_TYPES:
                            fp_count += 1
                            continue
                        # Some nvd data might match application CVEs for
                        # OS vendors which can be filtered
                        if not is_os_target_sw(package_issue):
                            fp_count += 1
                            continue
                        insights.append(
                            f"[#7C8082]:telescope: Vendor {vendor}[/#7C8082]"
                        )
                        plain_insights.append(f"Vendor {vendor}")
                    has_os_packages = True
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
                        has_ubuntu_packages = True
                    if "rhel" in qualifiers.get("distro", ""):
                        has_redhat_packages = True
        if ids_seen.get(vid + purl):
            fp_count += 1
            continue
        # Mark this CVE + pkg as seen to avoid duplicates
        ids_seen[vid + purl] = True
        # Find the best fix version
        fixed_location = best_fixed_location(
            options.sug_version_dict.get(purl), package_issue["fixed_location"]
        )
        if (
            options.sug_version_dict.get(purl) == placeholder_fix_version
            or package_issue["fixed_location"] == placeholder_fix_version
        ):
            wont_fix_version_count += 1
        package_usage = "N/A"
        plain_package_usage = "N/A"
        pkg_severity = vuln_occ_dict.get("severity")
        is_required = False
        pkg_requires_attn = False
        related_urls = vuln_occ_dict.get("related_urls")
        clinks = classify_links(
            related_urls,
        )
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
                pkg_attention_count += 1
            if fixed_location:
                fix_version_count += 1
            if (
                clinks.get("vendor") or package_type in config.OS_PKG_TYPES
            ) and pkg_severity == "CRITICAL":
                critical_count += 1
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
                has_os_packages = True
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
                has_reachable_poc_count += 1
                has_reachable_exploit_count += 1
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
            has_poc_count += 1
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
                has_reachable_exploit_count += 1
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
                    has_reachable_exploit_count += 1
                else:
                    insights.append(
                        "[bright_red]:exclamation_mark: Exploitable[/bright_red]"
                    )
                    plain_insights.append("Exploitable")
                    has_exploit_count += 1
            else:
                insights.append(
                    "[bright_red]:exclamation_mark: Known Exploits[/bright_red]"
                )
                plain_insights.append("Known Exploits")
            has_exploit_count += 1
            pkg_requires_attn = True
        if distro_package(package_issue):
            insights.append(
                "[spring_green4]:direct_hit: Distro specific[/spring_green4]"
            )
            plain_insights.append("Distro specific")
            distro_packages_count += 1
            has_os_packages = True
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
                    "name": "GitHub",
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
    # If the user doesn't want any table output return quickly
    if options.no_vuln_table:
        return pkg_vulnerabilities, pkg_group_rows
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
    if options.scoped_pkgs or has_exploit_count:
        if not pkg_attention_count and has_exploit_count:
            if has_reachable_exploit_count:
                rmessage = (
                    f":point_right: [magenta]{has_reachable_exploit_count}"
                    f"[/magenta] out of {len(pkg_vulnerabilities)} vulnerabilities "
                    f"have [dark magenta]reachable[/dark magenta] exploits and requires your ["
                    f"magenta]immediate[/magenta] attention."
                )
            else:
                rmessage = (
                    f":point_right: [magenta]{has_exploit_count}"
                    f"[/magenta] out of {len(pkg_vulnerabilities)} vulnerabilities "
                    f"have known exploits and requires your ["
                    f"magenta]immediate[/magenta] attention."
                )
            if not has_os_packages:
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
                if distro_packages_count and distro_packages_count < len(
                    pkg_vulnerabilities
                ):
                    if (
                        len(pkg_vulnerabilities)
                        > config.max_distro_vulnerabilities
                    ):
                        rmessage += f"\nNOTE: Check if the base image or the kernel version used is End-of-Life (EOL)."
                    else:
                        rmessage += (
                            f"\nNOTE: [magenta]{distro_packages_count}"
                            f"[/magenta] distro-specific vulnerabilities "
                            f"out of {len(pkg_vulnerabilities)} could be prioritized "
                            f"for updates."
                        )
                if has_redhat_packages:
                    rmessage += """\nNOTE: Vulnerabilities in RedHat packages with status "out of support" or "won't fix" are excluded from this result."""
                if has_ubuntu_packages:
                    rmessage += """\nNOTE: Vulnerabilities in Ubuntu packages with status "DNE" or "needs-triaging" are excluded from this result."""
            console.print(
                Panel(
                    rmessage,
                    title="Recommendation",
                    expand=False,
                )
            )
        elif pkg_attention_count:
            if has_reachable_exploit_count:
                rmessage = (
                    f":point_right: Prioritize the [magenta]{has_reachable_exploit_count}"
                    f"[/magenta] [bold magenta]reachable[/bold magenta] vulnerabilities with known exploits."
                )
            elif has_exploit_count:
                rmessage = (
                    f":point_right: Prioritize the [magenta]{has_exploit_count}"
                    f"[/magenta] vulnerabilities with known exploits."
                )
            else:
                rmessage = (
                    f":point_right: [info]{pkg_attention_count}"
                    f"[/info] out of {len(pkg_vulnerabilities)} vulnerabilities "
                    f"requires your attention."
                )
            if fix_version_count:
                if fix_version_count == pkg_attention_count:
                    rmessage += (
                        "\n:white_heavy_check_mark: You can update ["
                        "bright_green]all[/bright_green] the "
                        "packages using the mentioned fix version to "
                        "remediate."
                    )
                else:
                    v_text = (
                        "vulnerability"
                        if fix_version_count == 1
                        else "vulnerabilities"
                    )
                    rmessage += (
                        f"\nYou can remediate [bright_green]"
                        f"{fix_version_count}[/bright_green] "
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
        elif critical_count:
            console.print(
                Panel(
                    f":white_medium_small_square: Prioritize the [magenta]{critical_count}"
                    f"[/magenta] critical vulnerabilities confirmed by the "
                    f"vendor.",
                    title="Recommendation",
                    expand=False,
                )
            )
        else:
            if has_os_packages:
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
                if has_redhat_packages:
                    rmessage += """\nNOTE: Vulnerabilities in RedHat packages
                    with status "out of support" or "won't fix" are excluded
                    from this result."""
                if has_ubuntu_packages:
                    rmessage += """\nNOTE: Vulnerabilities in Ubuntu packages
                    with status "DNE" or "needs-triaging" are excluded from
                    this result."""
                console.print(Panel(rmessage, title="Recommendation"))
            else:
                rmessage = ":white_check_mark: No package requires immediate attention."
                if reached_purls:
                    rmessage = ":white_check_mark: No package requires immediate attention since the major vulnerabilities are not reachable."
                elif direct_purls:
                    rmessage = ":white_check_mark: No package requires immediate attention since the major vulnerabilities are found only in dev packages and indirect dependencies."
                console.print(
                    Panel(
                        rmessage,
                        title="Recommendation",
                        expand=False,
                    )
                )
    elif critical_count:
        console.print(
            Panel(
                f":white_medium_small_square: Prioritize the [magenta]{critical_count}"
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
    return pkg_vulnerabilities, pkg_group_rows


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
            "severity": pkg_severity,
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
        return None
    summary = {
        "UNSPECIFIED": 0,
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0,
    }
    for res in results:
        summary[res.get("severity")] += 1
    return summary


def jsonl_report(
    project_type,
    results,
    pkg_aliases,
    purl_aliases,
    sug_version_dict,
    scoped_pkgs,
    out_file_name,
    direct_purls,
    reached_purls,
):
    """
    DEPRECATED: Produce vulnerability occurrence report in jsonlines format
    This method should use the pkg_vulnerabilities from prepare_vdr

    :param scoped_pkgs: A dict of lists of required/optional/excluded packages.
    :param sug_version_dict: A dict mapping package names to suggested versions.
    :param purl_aliases: A dict mapping package names to their purl aliases.
    :param project_type: Project type
    :param results: List of vulnerabilities found
    :param pkg_aliases: Package alias
    :param out_file_name: Output filename
    :param direct_purls: A list of direct purls
    :param reached_purls: A list of reached purls
    """
    ids_seen = {}
    required_pkgs = scoped_pkgs.get("required", [])
    optional_pkgs = scoped_pkgs.get("optional", [])
    excluded_pkgs = scoped_pkgs.get("excluded", [])
    with open(out_file_name, "w", encoding="utf-8") as outfile:
        for vuln_occ_dict in results:
            vid = vuln_occ_dict.get("id")
            package_issue = vuln_occ_dict.get("package_issue")
            if not package_issue.get("affected_location"):
                continue
            full_pkg = package_issue["affected_location"].get("package")
            if package_issue["affected_location"].get("vendor"):
                full_pkg = (
                    f"{package_issue['affected_location'].get('vendor')}:"
                    f"{package_issue['affected_location'].get('package')}"
                )
            elif package_issue["affected_location"].get("cpe_uri"):
                vendor, _, _, _ = parse_cpe(
                    package_issue["affected_location"].get("cpe_uri")
                )
                if vendor:
                    full_pkg = (
                        f"{vendor}:"
                        f"{package_issue['affected_location'].get('package')}"
                    )
            # De-alias package names
            full_pkg = pkg_aliases.get(full_pkg, full_pkg)
            full_pkg_display = full_pkg
            version_used = package_issue["affected_location"].get("version")
            purl = purl_aliases.get(full_pkg, full_pkg)
            if purl:
                purl_obj = parse_purl(purl)
                if purl_obj:
                    version_used = purl_obj.get("version")
                    if purl_obj.get("namespace"):
                        full_pkg = f"""{purl_obj.get("namespace")}/
                        {purl_obj.get("name")}@{purl_obj.get("version")}"""
                    else:
                        full_pkg = f"""{purl_obj.get("name")}@{purl_obj
                            .get("version")}"""
            if ids_seen.get(vid + purl):
                continue
            # On occasions, this could still result in duplicates if the
            # package exists with and without a purl
            ids_seen[vid + purl] = True
            project_type_pkg = f"""{project_type}:{package_issue["affected_location"].get("package")}"""
            fixed_location = best_fixed_location(
                sug_version_dict.get(purl),
                package_issue["fixed_location"],
            )
            package_usage = "N/A"
            if (
                direct_purls.get(purl)
                or purl in required_pkgs
                or full_pkg in required_pkgs
                or project_type_pkg in required_pkgs
            ):
                package_usage = "required"
            elif (
                purl in optional_pkgs
                or full_pkg in optional_pkgs
                or project_type_pkg in optional_pkgs
            ):
                package_usage = "optional"
            elif (
                purl in excluded_pkgs
                or full_pkg in excluded_pkgs
                or project_type_pkg in excluded_pkgs
            ):
                package_usage = "excluded"
            data_obj = {
                "id": vid,
                "package": full_pkg_display,
                "purl": purl,
                "package_type": vuln_occ_dict.get("type"),
                "package_usage": package_usage,
                "version": version_used,
                "fix_version": fixed_location,
                "severity": vuln_occ_dict.get("severity"),
                "cvss_score": vuln_occ_dict.get("cvss_score"),
                "short_description": vuln_occ_dict.get("short_description"),
                "related_urls": vuln_occ_dict.get("related_urls"),
                "occurrence_count": direct_purls.get(purl, 0),
                "reachable_flows": reached_purls.get(purl, 0),
            }
            json.dump(data_obj, outfile)
            outfile.write("\n")


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
                        if rcat in (
                            "pkg_deprecated",
                            "pkg_private_on_public_registry",
                        ):
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
                        "[cyan]"
                        if "GPL" in lic["spdx-id"]
                        or "CC-BY-" in lic["spdx-id"]
                        or "Facebook" in lic["spdx-id"]
                        or "WTFPL" in lic["spdx-id"]
                        else "",
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
            full_pkg = res.get("package")
            fixed_location = res.get("fix_version")
            matched_by = res.get("matched_by")
        else:
            package_issue = res.package_issue
            full_pkg = package_issue.affected_location.package
            fixed_location = package_issue.fixed_location
            matched_by = res.matched_by
            if package_issue.affected_location.vendor:
                full_pkg = (
                    f"{package_issue.affected_location.vendor}:"
                    f"{package_issue.affected_location.package}"
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
            placeholder_fix_version,
            placeholder_exclude_version,
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
    for rurl in related_urls:
        if "github.com" in rurl and "/pull" in rurl:
            clinks["GitHub PR"] = rurl
        elif "github.com" in rurl and "/issues" in rurl:
            clinks["GitHub Issue"] = rurl
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
        elif "gitlab.alpinelinux.org" in rurl or "bugs.busybox.net" in rurl:
            clinks["vendor"] = rurl
        elif "redhat.com" in rurl or "oracle.com" in rurl:
            clinks["vendor"] = rurl
        elif (
            "openwall.com" in rurl
            or "oss-security" in rurl
            or "www.mail-archive.com" in rurl
            or "lists.debian.org" in rurl
            or "lists.fedoraproject.org" in rurl
            or "portal.msrc.microsoft.com" in rurl
            or "lists.opensuse.org" in rurl
        ):
            clinks["Mailing List"] = rurl
            clinks["vendor"] = rurl
        elif (
            "exploit-db" in rurl
            or "exploit-database" in rurl
            or "seebug.org" in rurl
            or "seclists.org" in rurl
            or "nu11secur1ty" in rurl
        ):
            clinks["exploit"] = rurl
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
