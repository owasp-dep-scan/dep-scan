"""Prioritisation and insight logic for vulnerability findings.

analyze_cve_vuln and process_vuln_occ turn raw matches into CycloneDX VDR
dicts carrying rich-tree renderables, plain-text insights, the
depscan:prioritized property and the analysis state. The helpers around them
gate on severity, classify OS/distro and language editions and decide whether
a purl counts as required, deployed or endpoint-filterable.

This module does not search the vulnerability database (see
analysis_lib.search), does not merge the entries it produces (see
analysis_lib.merge) and does not render output.
"""

import json
import re
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

from analysis_lib import Counts
from analysis_lib.advisory import (
    _cna,
    classify_links,
    cve_to_vdr,
    cvss_to_vdr_rating,
    get_description_detail,
    get_unaffected,
    get_version_from_detail,
    process_package_issue,
    split_cwe,
)
from analysis_lib.config import (
    CPE_FULL_REGEX,
    LANG_PKG_TYPES,
    LINUX_DISTRO_WITH_EDITIONS,
    OS_PKG_TYPES,
    OS_PKG_IGNORABLE,
    OS_PKG_UNINSTALLABLE,
    OS_VULN_KEY_CWES,
    TIME_FMT,
)
from analysis_lib.endpoints import is_endpoint_filterable
from analysis_lib.helpers import is_malware_vuln
from analysis_lib.output import pkg_sub_tree
from packageurl import PackageURL
from vdb.lib.config import PLACEHOLDER_FIX_VERSION
from vdb.lib.utils import parse_purl

CRITICAL_OR_HIGH = ("CRITICAL", "HIGH")

JUST_CRITICAL = ("CRITICAL",)

# Severity floor ranking for the --severity output filter. Higher is more
# severe. Ratings that carry no recognised severity (unknown/none/empty) are
# deliberately not ranked here so they are never silently dropped.
SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def vuln_meets_severity(vuln: Dict, threshold: Optional[str]) -> bool:
    """Return True when a VDR entry clears the ``--severity`` floor.

    This is depscan's own severity gating, applied to the finished VDR entries
    regardless of which vdb the scan ran against. The vdb push-down filter is a
    best-effort acceleration that only fires on the extended DB; this keeps
    ``--severity`` meaningful on the default DB too.

    A vuln passes when the highest ranked severity across its ``ratings`` is at
    or above ``threshold``. Findings whose ratings carry no recognised severity
    (unknown/none) are kept rather than dropped, so an unrated-but-possibly-
    severe advisory is never hidden by a threshold.
    """
    if not threshold:
        return True
    floor = SEVERITY_RANK.get(str(threshold).upper())
    if not floor:
        return True
    ranks = [
        SEVERITY_RANK[sev]
        for rating in (vuln.get("ratings") or [])
        if (sev := str(rating.get("severity", "")).upper()) in SEVERITY_RANK
    ]
    if not ranks:
        return True
    return max(ranks) >= floor


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
            and all_parts.group("vendor") in LINUX_DISTRO_WITH_EDITIONS
            and all_parts.group("edition")
            and all_parts.group("edition") != "*"
        ):
            return True
    return False


def is_lang_sw_edition(package_issue):
    """Check if the specified sw_edition belongs to any application package type"""
    if package_issue and package_issue["affected_location"].get("cpe_uri"):
        all_parts = CPE_FULL_REGEX.match(package_issue["affected_location"].get("cpe_uri"))
        if not all_parts or all_parts.group("sw_edition") in ("*", "-"):
            return True
        if (
            LANG_PKG_TYPES.get(all_parts.group("sw_edition"))
            or all_parts.group("sw_edition") in LANG_PKG_TYPES.values()
        ):
            return True
        return False
    return True


def is_os_target_sw(package_issue):
    """
    Since we rely on NVD, we filter those target_sw that definitely belong to a language
    """
    if package_issue and package_issue["affected_location"].get("cpe_uri"):
        all_parts = CPE_FULL_REGEX.match(package_issue["affected_location"].get("cpe_uri"))
        if (
            all_parts
            and all_parts.group("target_sw") not in ("*", "-")
            and (
                LANG_PKG_TYPES.get(all_parts.group("target_sw"))
                or all_parts.group("target_sw") in LANG_PKG_TYPES.values()
            )
        ):
            return False
    return True


def _iso_datetime(value):
    """Normalise a CVE-5 date string to the VDR's ``TIME_FMT`` form.

    The hydrated record carries ISO strings ("2024-03-10T23:15:00.000Z");
    anything unparseable is returned verbatim rather than dropped.
    """
    if not value:
        return ""
    if isinstance(value, datetime):
        return value.strftime(TIME_FMT)
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).strftime(TIME_FMT)
    except ValueError:
        return str(value)


def make_purl(purl):
    try:
        return PackageURL.from_string(purl)
    except ValueError:
        return ""


def process_vuln_occ(
    bom_dependency_tree,
    direct_purls,
    oci_product_types,
    optional_pkgs,
    options,
    reached_purls,
    required_pkgs,
    vuln_occ_dict,
    counts,
) -> Tuple[Counts, bool, Dict[str, Any]]:
    """Convert one vulnerability occurrence into a CycloneDX VDR dict.

    :return: (counts, add_to_pkg_group_rows, vuln) where vuln maps
        CycloneDX field names to heterogeneous values (strings, lists,
        rich Tree renderables).
    """
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
            options, vuln_occ_dict
        )
    has_flagged_cwe = False
    package_type = None
    insights = []
    plain_insights = []
    pkg_severity = vuln_occ_dict.get("severity") or "unknown"
    if is_malware_vuln(vuln_occ_dict):
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
    fixed_location = package_issue.get("fixed_location") or get_version_from_detail(
        detail, version_used
    )
    versions = [{"version": version_used, "status": "affected"}]
    if fixed_location:
        versions.append({"version": fixed_location, "status": "unaffected"})
        recommendation = f"Update to version {fixed_location}."
    affects = [{"ref": purl, "versions": versions}]
    if fixed_location in (PLACEHOLDER_FIX_VERSION, "*"):
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
                "name": "GitHub Advisory Database",
                "url": f"https://github.com/advisories/{vid}",
            }
    related_urls = vuln_occ_dict.get("related_urls")
    clinks = classify_links(related_urls)
    advisories = []
    for k, v in clinks.items():
        advisories.append({"title": k, "url": v})
    # CycloneDX VDR entry: field values are heterogeneous by design.
    vuln: Dict[str, Any] = {
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
        "references": [],
        "source": source,
        "updated": vuln_occ_dict.get("source_update_time", ""),
        "insights": [],
        "p_rich_tree": p_rich_tree,
        "fixed_location": fixed_location,
    }
    if not purl.startswith("pkg:"):
        if options.project_type in OS_PKG_TYPES:
            if vendor and (vendor in LANG_PKG_TYPES.values() or LANG_PKG_TYPES.get(vendor)):
                counts.fp_count += 1
                return counts, add_to_pkg_group_rows, vuln
            # Some nvd data might match application CVEs for
            # OS vendors which can be filtered
            if not is_os_target_sw(package_issue):
                counts.fp_count += 1
                return counts, add_to_pkg_group_rows, vuln
        # Issue #320 - Malware matches without purl are false positives
        if is_malware_vuln(vuln_occ_dict):
            counts.fp_count += 1
            counts.malicious_count -= 1
            return counts, add_to_pkg_group_rows, vuln
    else:
        purl_obj = parse_purl(purl)
        # Issue #320 - Malware matches without purl are false positives
        if not purl_obj and is_malware_vuln(vuln_occ_dict):
            counts.fp_count += 1
            counts.malicious_count -= 1
            return counts, add_to_pkg_group_rows, vuln
        if purl_obj:
            version_used = purl_obj.get("version")
            package_type = purl_obj.get("type") or ""
            qualifiers = purl_obj.get("qualifiers", {})
            # Filter application CVEs from distros
            if (LANG_PKG_TYPES.get(package_type) or package_type in LANG_PKG_TYPES.values()) and (
                (vendor and vendor in OS_PKG_TYPES) or not is_lang_sw_edition(package_issue)
            ):
                counts.fp_count += 1
                return counts, add_to_pkg_group_rows, vuln
            if package_type in OS_PKG_TYPES:
                # Bug #208 - do not report application CVEs
                if vendor and (vendor in LANG_PKG_TYPES.values() or LANG_PKG_TYPES.get(vendor)):
                    counts.fp_count += 1
                    return counts, add_to_pkg_group_rows, vuln
                if package_type and (
                    package_type in LANG_PKG_TYPES.values() or LANG_PKG_TYPES.get(package_type)
                ):
                    counts.fp_count += 1
                    return counts, add_to_pkg_group_rows, vuln
                if vendor and oci_product_types and vendor not in oci_product_types:
                    # Bug #170 - do not report CVEs belonging to other distros
                    if vendor in OS_PKG_TYPES:
                        counts.fp_count += 1
                        return counts, add_to_pkg_group_rows, vuln
                    # Some nvd data might match application CVEs for
                    # OS vendors which can be filtered
                    if not is_os_target_sw(package_issue):
                        counts.fp_count += 1
                        return counts, add_to_pkg_group_rows, vuln
                    insights.append(f"[#7C8082]:telescope: Vendor {vendor}[/#7C8082]")
                    plain_insights.append(f"Vendor {vendor}")
                counts.has_os_packages = True
                for acwe in cwes:
                    if acwe in OS_VULN_KEY_CWES:
                        has_flagged_cwe = True
                        break
                # Don't flag the cwe for ignorable os packages
                if has_flagged_cwe and (
                    purl_obj.get("name") in OS_PKG_UNINSTALLABLE
                    or purl_obj.get("name") in OS_PKG_IGNORABLE
                    or vendor in OS_PKG_IGNORABLE
                ):
                    has_flagged_cwe = False
                else:
                    if purl_obj.get("name") in OS_PKG_IGNORABLE or vendor in OS_PKG_IGNORABLE:
                        insights.append("[#7C8082]:mute: Suppress for containers[/#7C8082]")
                        plain_insights.append("Suppress for containers")
                    elif purl_obj.get("name") in OS_PKG_UNINSTALLABLE:
                        insights.append("[#7C8082]:scissors: Uninstall candidate[/#7C8082]")
                        plain_insights.append("Uninstall candidate")
                # If the flag remains after all the suppressions then add it as an insight
                if has_flagged_cwe:
                    insights.append("[#7C8082]:triangular_flag: Flagged weakness[/#7C8082]")
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
        purl in required_pkgs or full_pkg in required_pkgs or project_type_pkg in required_pkgs
    ):
        is_required = True
    if pkg_severity.upper() in CRITICAL_OR_HIGH:
        if is_required:
            counts.pkg_attention_count += 1
        if fixed_location:
            counts.fix_version_count += 1
        if (
            clinks.get("vendor") or package_type in OS_PKG_TYPES
        ) and pkg_severity.upper() == "CRITICAL":
            counts.critical_count += 1
    if is_required and package_type not in OS_PKG_TYPES:
        if direct_purls.get(purl):
            label_str = "locations" if direct_purls.get(purl) > 1 else "location"
            package_usage = (
                f":direct_hit: Used in [info]{str(direct_purls.get(purl))}[/info] {label_str}"
            )
            plain_package_usage = f"Used in {str(direct_purls.get(purl))} {label_str}"
        else:
            package_usage = ":direct_hit: Direct dependency"
            plain_package_usage = "Direct dependency"
    elif (not optional_pkgs and pkg_tree_list and len(pkg_tree_list) > 1) or (
        purl in optional_pkgs or full_pkg in optional_pkgs or project_type_pkg in optional_pkgs
    ):
        if package_type in OS_PKG_TYPES:
            counts.has_os_packages = True
        else:
            package_usage = "[spring_green4]:notebook: Indirect dependency[/spring_green4]"
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
            insights.append("[yellow]:notebook_with_decorative_cover: Bug Bounty target[/yellow]")
            plain_insights.append("Bug Bounty target")
        else:
            insights.append("[yellow]:notebook_with_decorative_cover: Has PoC[/yellow]")
            plain_insights.append("Has PoC")
        counts.has_poc_count += 1
        if pkg_severity.upper() in CRITICAL_OR_HIGH:
            pkg_requires_attn = True
    if (clinks.get("vendor") and package_type not in OS_PKG_TYPES) or reached_purls.get(purl):
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
                insights.append("[bright_red]:exclamation_mark: Exploitable[/bright_red]")
                plain_insights.append("Exploitable")
                counts.has_exploit_count += 1
        else:
            insights.append("[bright_red]:exclamation_mark: Known Exploits[/bright_red]")
            plain_insights.append("Known Exploits")
        counts.has_exploit_count += 1
        pkg_requires_attn = True
    if distro_package(package_issue["affected_location"].get("cpe_uri")):
        insights.append("[spring_green4]:direct_hit: Distro specific[/spring_green4]")
        plain_insights.append("Distro specific")
        counts.distro_packages_count += 1
        counts.has_os_packages = True
    if pkg_requires_attn and fixed_location and purl:
        add_to_pkg_group_rows = True
    vuln |= {
        "insights": insights,
        "properties": get_vuln_properties(fixed_location, pkg_requires_attn, plain_insights, purl),
    }
    return counts, add_to_pkg_group_rows, vuln


def get_analysis(clinks, pkg_tree_list):
    if clinks.get("exploit"):
        return {
            "state": "exploitable",
            "detail": f"See {clinks.get('exploit')}",
        }
    elif clinks.get("poc"):
        return {
            "state": "in_triage",
            "detail": f"See {clinks.get('poc')}",
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


def is_purl_in_postbuild(purl, postbuild_purls):
    if not purl or not postbuild_purls:
        return False
    purl_no_version = purl.split("@")[0]
    return postbuild_purls.get(purl) or postbuild_purls.get(purl_no_version)


def analyze_cve_vuln(
    vuln,
    reached_purls,
    direct_purls,
    reached_services,
    endpoint_reached_purls,
    optional_pkgs,
    required_pkgs,
    prebuild_purls,
    build_purls,
    postbuild_purls,
    purl_identities,
    bom_dependency_tree,
    counts,
) -> Tuple[Counts, Dict[str, Any], bool, bool]:
    insights = []
    plain_insights = []
    cve_requires_attn = False
    likely_false_positive = False
    purl = vuln.get("matched_by") or ""
    purl_obj = parse_purl(purl)
    version_used = get_version_used(purl)
    if purl.startswith("pkg:generic/") and not version_used:
        likely_false_positive = True
    package_type = vuln.get("type") or ""
    affects = [
        {
            "ref": purl,
            "versions": [{"range": vuln.get("matching_vers"), "status": "affected"}],
        }
    ]
    recommendation = ""
    vid = vuln.get("cve_id") or ""
    vid = vid.strip()
    if not re.match(r"^[A-Za-z0-9\-]+$", vid):
        vid = re.sub(r"[^A-Za-z0-9\-]", "", vid)
    if is_malware_vuln(vuln):
        insights.append("[bright_red]:stop_sign: Malicious[/bright_red]")
        plain_insights.append("Malicious")
        counts.malicious_count += 1
        cve_requires_attn = True
    has_flagged_cwe = False
    add_to_pkg_group_rows = False
    if fixed_location := get_unaffected(vuln):
        affects[0]["versions"].append({"version": fixed_location, "status": "unaffected"})
        # This is a basic recommendation
        recommendation = f"Update to version {fixed_location}."
        if fixed_location in (PLACEHOLDER_FIX_VERSION, "*"):
            counts.wont_fix_version_count += 1
            recommendation = "Fix unavailable."
            if fixed_location == "*":
                insights.append("Not maintained")
                plain_insights.append("Not maintained")
            else:
                insights.append("Not fixed")
                plain_insights.append("Not fixed")
                likely_false_positive = True
            fixed_location = ""
    pkg_tree_list, p_rich_tree = pkg_sub_tree(
        purl,
        purl.replace(":", "/"),
        bom_dependency_tree,
        pkg_severity="unknown",
        as_tree=True,
        extra_text=f":left_arrow: {vid}",
    )
    # CycloneDX VDR entry: field values are heterogeneous by design.
    vdict: Dict[str, Any] = {
        "id": vuln.get("cve_id"),
        "matched_by": vuln.get("matched_by"),
        "bom-ref": f"{vuln.get('cve_id')}/{vuln.get('matched_by')}",
        "affects": affects,
        "recommendation": recommendation,
        "purl_prefix": vuln["purl_prefix"],
        "source": {},
        "references": [],
        "advisories": [],
        "cwes": [],
        "description": "",
        "fixed_location": fixed_location,
        "detail": "",
        "ratings": [],
        "published": "",
        "updated": "",
        "analysis": get_analysis({}, pkg_tree_list),
        "insights": [],
        "p_rich_tree": p_rich_tree,
        "properties": [],
    }
    cve_record = vuln.get("source_data")
    if not isinstance(cve_record, dict) or not cve_record:
        return counts, vdict, add_to_pkg_group_rows, likely_false_positive

    (
        source,
        references,
        advisories,
        cwes,
        description,
        detail,
        rating,
        bounties,
        pocs,
        exploits,
        vendors,
        vendor,
    ) = cve_to_vdr(cve_record, vid)
    if (
        detail
        and not fixed_location
        and (fixed_location := get_version_from_detail(detail, version_used))
    ):
        vdict["affects"][0]["versions"].append({"version": fixed_location, "status": "unaffected"})
        vdict["recommendation"] = f"Update to version {fixed_location}."
        vdict["fixed_location"] = fixed_location
    # FIXME: This looks similar to another block above with a subtle
    # difference in pkg_severity
    pkg_tree_list, p_rich_tree = pkg_sub_tree(
        purl,
        purl.replace(":", "/"),
        bom_dependency_tree,
        pkg_severity=rating.get("severity") or "unknown",
        as_tree=True,
        extra_text=f":left_arrow: {vid}",
    )
    metadata = cve_record.get("cveMetadata") or {}
    published = metadata.get("datePublished")
    updated = metadata.get("dateUpdated")
    vdict |= {
        "source": source,
        "references": references,
        "advisories": advisories,
        "cwes": cwes,
        "description": description,
        "detail": detail,
        "ratings": [rating],
        "published": _iso_datetime(published),
        "updated": _iso_datetime(updated),
        "p_rich_tree": p_rich_tree,
    }
    is_required = False
    # The given purl is considered required if it exists in any of these 3 data structures.
    if (
        direct_purls.get(purl)
        or purl in required_pkgs
        or is_purl_in_postbuild(purl, postbuild_purls)
    ):
        is_required = True
    package_usage = ""
    plain_package_usage = ""
    if rating.get("severity", "").upper() in JUST_CRITICAL and not likely_false_positive:
        counts.critical_count += 1
    # We are dealing with a required non-os package
    if is_required and package_type not in OS_PKG_TYPES and not likely_false_positive:
        # Is the package also present in post-build BOM
        if is_purl_in_postbuild(purl, postbuild_purls):
            package_usage = ":package: Deployed dependency"
            plain_package_usage = "Deployed dependency"
            # Does this require attention
            if rating.get("severity", "").upper() in JUST_CRITICAL:
                cve_requires_attn = True
                counts.pkg_attention_count += 1
        elif direct_purls.get(purl):
            package_usage = (
                f":direct_hit: Used in [info]{str(direct_purls.get(purl))}[/info] locations"
            )
            plain_package_usage = f"Used in {str(direct_purls.get(purl))} locations"
        else:
            package_usage = ":direct_hit: Direct dependency"
            plain_package_usage = "Direct dependency"
    elif (not optional_pkgs and pkg_tree_list and len(pkg_tree_list) > 1) or purl in optional_pkgs:
        if package_type in OS_PKG_TYPES:
            counts.has_os_packages = True
        else:
            package_usage = "[spring_green4]:notebook: Indirect dependency[/spring_green4]"
            plain_package_usage = "Indirect dependency"
    # There are pocs or bounties against this vulnerability
    if pocs or bounties:
        # Reachable purls
        if reached_purls.get(purl) or endpoint_reached_purls.get(purl):
            if endpoint_reached_purls.get(purl):
                insights.append(
                    "[yellow]:heavy_large_circle: Endpoint-Reachable Bounty target[/yellow]"
                )
                plain_insights.append("Endpoint-Reachable Bounty target")
            elif reached_purls.get(purl):
                insights.append(
                    "[yellow]:notebook_with_decorative_cover: Reachable Bounty target[/yellow]"
                )
                plain_insights.append("Reachable Bounty target")
            counts.has_reachable_poc_count += 1
            counts.has_reachable_exploit_count += 1
            cve_requires_attn = True
        # Direct usage
        elif direct_purls.get(purl) or is_purl_in_postbuild(purl, postbuild_purls):
            insights.append("[yellow]:notebook_with_decorative_cover: Bug Bounty target[/yellow]")
            plain_insights.append("Bug Bounty target")
        else:  # Just PoC
            insights.append("[yellow]:notebook_with_decorative_cover: Has PoC[/yellow]")
            plain_insights.append("Has PoC")
        counts.has_poc_count += 1
        if rating.get("severity", "").upper() in JUST_CRITICAL:
            cve_requires_attn = True
            if direct_purls.get(purl) or is_purl_in_postbuild(purl, postbuild_purls):
                counts.pkg_attention_count += 1
            if recommendation:
                counts.fix_version_count += 1
            counts.critical_count += 1
    # App Purl is reachable
    if (
        vendors
        and package_type not in OS_PKG_TYPES
        and (reached_purls.get(purl) or endpoint_reached_purls.get(purl))
    ):
        # If it has a poc, an insight might have gotten added above
        if not cve_requires_attn:
            if endpoint_reached_purls.get(purl):
                insights.append(":heavy_large_circle: Endpoint-Reachable")
                plain_insights.append("Endpoint-Reachable")
                if rating.get("severity", "").upper() in CRITICAL_OR_HIGH:
                    cve_requires_attn = True
            else:
                insights.append(":receipt: Reachable")
                plain_insights.append("Reachable")
        else:
            insights.append(":receipt: Vendor Confirmed")
            plain_insights.append("Vendor Confirmed")
    # There are exploits
    if exploits and not likely_false_positive:
        cve_requires_attn = True
        # Also reachable
        if (
            reached_purls.get(purl)
            or endpoint_reached_purls.get(purl)
            or direct_purls.get(purl)
            or is_purl_in_postbuild(purl, postbuild_purls)
        ):
            if endpoint_reached_purls.get(purl):
                insights.append(
                    "[bright_red]:collision: Endpoint-Reachable and Exploitable[/bright_red]"
                )
                plain_insights.append("Endpoint-Reachable and Exploitable")
            else:
                insights.append(
                    "[bright_red]:exclamation_mark: Reachable and Exploitable[/bright_red]"
                )
            if reached_purls.get(purl) or endpoint_reached_purls.get(purl):
                plain_insights.append("Reachable and Exploitable")
                # Remove any simple reachable insights
                if ":receipt: Reachable" in insights:
                    insights.remove(":receipt: Reachable")
                if "Reachable" in plain_insights:
                    plain_insights.remove("Reachable")
                if ":heavy_large_circle: Endpoint-Reachable" in insights:
                    insights.remove(":heavy_large_circle: Endpoint-Reachable")
                if "Endpoint-Reachable" in plain_insights:
                    plain_insights.remove("Endpoint-Reachable")
            counts.has_reachable_exploit_count += 1
            # Fail safe. Packages with exploits and direct usage without
            # a reachable flow are still considered reachable to reduce
            # false negatives
            if not reached_purls.get(purl):
                reached_purls[purl] = 1
        # A flagged CWE
        elif has_flagged_cwe:
            if (vendor and vendor in ("gnu",)) or (
                purl_obj and purl_obj.get("name") in ("glibc", "openssl", "curl", "wget", "git")
            ):
                insights.append(
                    "[bright_red]:exclamation_mark: Reachable and Exploitable[/bright_red]"
                )
                plain_insights.append("Reachable and Exploitable")
                counts.has_reachable_exploit_count += 1
            else:
                insights.append("[bright_red]:exclamation_mark: Exploitable[/bright_red]")
                plain_insights.append("Exploitable")
                counts.has_exploit_count += 1
        else:
            insights.append("[bright_red]:exclamation_mark: Known Exploits[/bright_red]")
            plain_insights.append("Known Exploits")
            # Just known exploits without usage is not a priority
            if reached_purls or direct_purls:
                cve_requires_attn = False
    affected = _cna(cve_record).get("affected") or []
    if affected and (cpes := affected[0].get("cpes")):
        # Distro-specific package
        if all((distro_package(cpe) for cpe in cpes)):
            insights.append("[spring_green4]:direct_hit: Distro specific[/spring_green4]")
            plain_insights.append("Distro specific")
            counts.distro_packages_count += 1
            counts.has_os_packages = True
    if package_usage:
        insights.append(package_usage)
        plain_insights.append(plain_package_usage)
    # bool() normalises the and-chain, whose value is purl (a str) when
    # every other condition holds.
    add_to_pkg_group_rows = bool(
        not likely_false_positive
        and cve_requires_attn
        and purl
        and not is_endpoint_filterable(purl)
    )
    insights = list(set(insights))
    plain_insights = list(set(plain_insights))
    if exploits or pocs:
        vdict["analysis"] = get_analysis(
            {
                "exploits": exploits[0] if exploits else [],
                "pocs": pocs[0] if pocs else [],
            },
            pkg_tree_list,
        )
    vdict |= {
        "insights": insights,
        "properties": get_vuln_properties(fixed_location, cve_requires_attn, plain_insights, purl),
    }
    return counts, vdict, add_to_pkg_group_rows, likely_false_positive


def get_vuln_properties(fixed_location, pkg_requires_attn, plain_insights, purl):
    properties = [
        {
            "name": "depscan:prioritized",
            "value": "true" if pkg_requires_attn and purl else "false",
        }
    ]
    if plain_insights:
        plain_insights.sort()
        properties.append({"name": "depscan:insights", "value": "\\n".join(plain_insights)})
    return properties
