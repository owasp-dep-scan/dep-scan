import contextlib
import encodings.utf_8
from datetime import datetime
from typing import Dict, List, Tuple

import cvss
from custom_json_diff.lib.utils import compare_versions, json_load
from cvss import CVSSError
from packageurl import PackageURL
from vdb.lib.config import PLACEHOLDER_EXCLUDE_VERSION, PLACEHOLDER_FIX_VERSION
from vdb.lib.cve_model import (
    CVE,
    Description,
    Descriptions,
    ProblemTypes,
    References,
    Status,
    Versions,
    Product,
)
from vdb.lib.utils import parse_cpe, parse_purl, version_compare

from analysis_lib import get_all_bom_files
from analysis_lib.config import *
from analysis_lib.output import *
from analysis_lib.search import find_vulns

CRITICAL_OR_HIGH = ("CRITICAL", "HIGH")

JUST_CRITICAL = ("CRITICAL",)


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


def retrieve_bom_dependency_tree(bom_file, bom_dir):
    """
    Method to retrieve the dependency tree from CycloneDX SBOM files

    :param bom_file: BOM file
    :param bom_dir: BOM directory
    :return: Dependency tree as a list
    """
    if not bom_file and not bom_dir:
        return []
    dependencies = []
    if bom_dir:
        bom_files = get_all_bom_files(bom_dir)
    else:
        bom_files = [bom_file]
    for file_path in bom_files:
        if bom_data := json_load(file_path):
            dependencies += bom_data.get("dependencies", [])
    return dependencies


def retrieve_oci_properties(bom_file, bom_dir):
    """
    Retrieves OCI properties from from CycloneDX SBOM files

    :param bom_file: BOM file
    :param bom_dir: BOM directory

    :return: A dictionary containing the retrieved OCI properties.
    :rtype: dict
    """
    props = {}
    if not bom_file and not bom_dir:
        return props
    if bom_dir:
        bom_files = get_all_bom_files(bom_dir)
    else:
        bom_files = [bom_file]
    for file_path in bom_files:
        if bom_data := json_load(file_path):
            for p in bom_data.get("metadata", {}).get("properties", []):
                if p.get("name", "").startswith("oci:image:"):
                    props[p.get("name")] = p.get("value")
    return props


def is_lang_sw_edition(package_issue):
    """Check if the specified sw_edition belongs to any application package type"""
    if package_issue and package_issue["affected_location"].get("cpe_uri"):
        all_parts = CPE_FULL_REGEX.match(
            package_issue["affected_location"].get("cpe_uri")
        )
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
        all_parts = CPE_FULL_REGEX.match(
            package_issue["affected_location"].get("cpe_uri")
        )
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


def remove_extra_metadata(vdrs):
    new_vdrs = []
    exclude = {
        "insights",
        "matched_by",
        "purl_prefix",
        "p_rich_tree",
        "fixed_location",
    }
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


def format_system_name(system_name):
    system_name = (
        system_name.capitalize()
        .replace("Redhat", "Red Hat")
        .replace("Zerodayinitiative", "Zero Day Initiative")
        .replace("Github", "GitHub")
        .replace("Netapp", "NetApp")
        .replace("Npmjs", "NPM")
        .replace("Alpinelinux", "Alpine Linux")
        .replace("Fedoraproject", "Fedora Project")
        .replace("Djangoproject", "Django Project")
        .replace("Opensuse", "Open Suse")
        .replace("Securityfocus", "Security Focus")
    )
    return system_name


def get_description_detail(data: Descriptions | str) -> Tuple[str, str]:
    if not data:
        return "", ""
    if (
        isinstance(data, Descriptions)
        and data.root
        and isinstance(data.root[0], Description)
    ):
        data = data.root[0].value
    description = ""
    detail = data or ""
    if detail and "\\n" in detail:
        description = detail.split("\\n")[0]
    elif "." in detail:
        description = detail.split(".")[0]
    detail = (
        detail.replace("\\n", " ")
        .replace("\\t", " ")
        .replace("\\r", " ")
        .replace("\n", " ")
        .replace("\t", " ")
        .replace("\r", " ")
        .replace("\\`", "")
    )
    detail = bytes.decode(encodings.utf_8.encode(detail)[0], errors="replace")
    description = description.lstrip("# ")
    return description, detail


def choose_date(d1, d2, choice):
    if not d1 or not d2 or choice not in {"max", "min"}:
        return d1 or d2
    try:
        d1 = datetime.fromisoformat(d1)
        d2 = datetime.fromisoformat(d2)
        d3 = max(d1, d2) if choice == "max" else min(d1, d2)
        return d3.strftime(TIME_FMT)
    except ValueError:
        return d1 or d2
    except TypeError:
        d3 = max(d1.date(), d2.date()) if choice == "max" else min(d1.date(), d2.date())
        return d3.strftime(TIME_FMT)


def combine_affects(v1, v2):
    affects = {}
    seen_refs = set()
    if not v1 or not v2:
        return v1 or v2
    v1.extend(v2)
    for i in v1:
        ref = i.get("ref", "")
        for vers in i.get("versions", []):
            version = vers.get("version", "") or vers.get("range", "")
            status = vers.get("status", "")
            vers_ref = f"{ref}/{version}/{status}"
            if vers_ref not in seen_refs:
                if ref in affects:
                    affects[ref]["versions"].append(vers)
                else:
                    affects[ref] = {"ref": ref, "versions": [vers]}
                seen_refs.add(vers_ref)
    return list(affects.values())


def combine_generic(v1, v2, keys):
    """Combines two lists of flat dicts"""
    if not v1 or not v2:
        return v1 or v2
    seen_keys = set()
    v3 = []
    for i in v1 + v2:
        seen_id = "".join([str(i.get(k, "")) for k in keys])
        if seen_id not in seen_keys:
            v3.append(i)
            seen_keys.add(seen_id)
    return v3


def combine_references(v1, v2):
    if not v1 and not v2:
        return []
    seen_urls = set()
    v3 = []
    for i in v1 + v2:
        url = i.get("url") or f"{i.get('id', '')}.{i.get('source', {}).get('url', '')}"
        if url and url not in seen_urls:
            v3.append(i)
            seen_urls.add(url)
    return v3


def combine_vdrs(v1, v2):
    return {
        "advisories": combine_references(
            v1.get("advisories", []), v2.get("advisories", [])
        ),
        "affects": combine_affects(v1.get("affects", []), v2.get("affects", [])),
        "analysis": v1.get("analysis", "") or v2.get("analysis", ""),
        "bom-ref": v1.get("bom-ref"),
        "cwes": list(set(v1["cwes"] + v2["cwes"])),
        "detail": v1.get("detail", "") or v2.get("detail", ""),
        "description": v1.get("description", "") or v2.get("description", ""),
        "id": v1.get("id"),
        "properties": combine_generic(
            v1.get("properties", []), v2.get("properties", []), ["name", "value"]
        ),
        "published": choose_date(v1.get("published"), v2.get("published"), "min"),
        "ratings": combine_generic(
            v1.get("ratings", []),
            v2.get("ratings", []),
            ["method", "score", "severity", "vector"],
        ),
        "recommendation": v1.get("recommendation", "") or v2.get("recommendation", ""),
        "references": combine_references(
            v1.get("references", []), v2.get("references", [])
        ),
        "source": v1.get("source", "") or v2.get("source", ""),
        "updated": choose_date(v1.get("updated"), v2.get("updated"), "max"),
        "p_rich_tree": v1.get("p_rich_tree") or v2.get("p_rich_tree"),
        "insights": v1.get("insights") or v2.get("insights"),
        "purl_prefix": v1.get("purl_prefix") or v2.get("purl_prefix"),
        "fixed_location": v1.get("fixed_location") or v2.get("fixed_location"),
    }


def choose_source(v1, v2):
    if v1.get("name", "") >= v2.get("name", ""):
        return v1
    return v2


def max_version(version_list):
    """
    Method to return the highest version from the list

    :param version_list: single version string or set of versions
    :return: max version
    """
    if isinstance(version_list, str):
        return version_list
    if isinstance(version_list, set):
        version_list = list(version_list)
    if len(version_list) == 1:
        return version_list[0]
    min_ver = "0"
    max_ver = version_list[0]
    for i, vl in enumerate(version_list):
        if not vl:
            continue
        if not version_compare(vl, min_ver, max_ver):
            max_ver = vl
    return max_ver


def get_suggested_version_map(pkg_vulnerabilities: List[Dict]) -> Dict[str, str]:
    suggested_version_map = {}
    for i, v in enumerate(pkg_vulnerabilities):
        fixed_location = v.get("fixed_location")
        if not fixed_location or fixed_location in (
            PLACEHOLDER_FIX_VERSION,
            PLACEHOLDER_EXCLUDE_VERSION,
            "*",
        ):
            continue
        purl_prefix = v.get("purl_prefix") or ""
        # Don't go near certain packages
        if (
            "kernel" in purl_prefix
            or "openssl" in purl_prefix
            or "openssh" in purl_prefix
        ):
            continue
        if purl_prefix in suggested_version_map:
            suggested_version_map[purl_prefix] = max_version(
                [suggested_version_map[purl_prefix], fixed_location]
            )
        else:
            suggested_version_map[purl_prefix] = fixed_location
    return suggested_version_map


def get_suggested_versions(pkg_list, project_type):
    sug_version_dict = get_suggested_version_map(pkg_list)
    pkg_aliases = {}
    if sug_version_dict:
        # Recheck packages
        sug_pkg_list = []
        for k, v in sug_version_dict.items():
            if not v:
                continue
            sug, aliases = process_suggestions(k, v)
            if sug:
                sug_pkg_list.extend(sug)
            if aliases:
                pkg_aliases |= aliases
        # We need only direct purl-based hits
        override_results, _, _ = find_vulns(project_type, sug_pkg_list, False, "purl")
        if override_results:
            new_sug_dict = get_suggested_version_map(override_results)
            for nk, nv in new_sug_dict.items():
                sug_version_dict[nk] = nv
    return sug_version_dict, pkg_aliases


def make_version_suggestions(vdrs, project_type):
    suggested_version_map, aliases = get_suggested_versions(vdrs, project_type)
    for i, v in enumerate(vdrs):
        if suggested_version := suggested_version_map.get(v["purl_prefix"]):
            if old_rec := v.get("recommendation"):
                vdrs[i]["fixed_location"] = suggested_version
                if suggested_version not in old_rec:
                    old_rec = old_rec.replace("Update to version ", "").rstrip(".")
                    vdrs[i]["recommendation"] = (
                        f"Update to version {old_rec} to resolve "
                        f"{v['id']} or update to version "
                        f"{suggested_version} to resolve additional "
                        f"vulnerabilities for this package."
                    )
            else:
                vdrs[i]["recommendation"] = (
                    f"No recommendation found for {v['id']}. Updating to "
                    f"version {suggested_version} is recommended "
                    f"nonetheless in order to address additional "
                    f"vulnerabilities identified for this package."
                )
    return vdrs


def make_purl(purl):
    try:
        return PackageURL.from_string(purl)
    except ValueError:
        return ""


def process_suggestions(k, v):
    """
    Processes suggestions for package information and returns a list of packages
    along with their aliases.

    :param k: Package URL
    :param v: Suggested version

    :returns: A list of packages and a dict of aliases
    :rtype: tuple[list, dict]
    """
    vendor = ""
    version = v
    pkg_list = []
    aliases = {}
    # Key is already a purl
    if k.startswith("pkg:"):
        with contextlib.suppress(Exception):
            purl_obj = parse_purl(k)
            vendor = purl_obj.get("namespace", purl_obj.get("type"))
            name = purl_obj.get("name")
            version = purl_obj.get("version")
            pkg_list.append(
                {
                    "vendor": vendor,
                    "name": name,
                    "version": version,
                    "purl": k,
                }
            )
    else:
        tmp_a = k.split(":")
        if len(tmp_a) == 3:
            vendor = tmp_a[0]
            name = tmp_a[1]
        else:
            name = tmp_a[0]
        # De-alias the vendor and package name
        full_pkg = f"{vendor}:{name}:{version}"
        full_pkg = aliases.get(full_pkg, full_pkg)
        split_pkg = full_pkg.split(":")
        if len(split_pkg) == 3:
            vendor, name, version = split_pkg
        elif split_pkg:
            name = split_pkg[0]
        pkg_list.append({"vendor": vendor, "name": name, "version": version})
    return pkg_list, aliases


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
                "value": f"{ppurl.name}@{affected_version}",
            }
            if ppurl.namespace:
                new_prop["value"] = f"{ppurl.namespace}/{new_prop['value']}"
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
            method = cvss.CVSS3(vector_string).as_json().get("version", "")
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
    advisories, references, bug_bounties, pocs, exploits, vendors, source = refs_to_vdr(
        cve.root.containers.cna.references, vid.lower()
    )
    vector, method, severity, score = parse_metrics(cve.root.containers.cna.metrics)
    try:
        description, detail = get_description_detail(
            cve.root.containers.cna.descriptions
        )
    except AttributeError:
        description, detail = "", ""
    if not source:
        source = {"name": cve.root.cveMetadata.assignerShortName.root.capitalize()}
        if source.get("name") == "Github_m":
            source = {
                "name": "GitHub Advisory Database",
                "url": f"https://github.com/advisories/{vid}",
            }
            advisories.append(
                {
                    "title": f"GitHub Advisory {vid}",
                    "url": f"https://github.com/advisories/{vid}",
                }
            )
    cwes = get_cwe_list(cve.root.containers.cna.problemTypes)
    vendor = ""
    if cve.root.containers.cna.affected:
        vendor = cve.root.containers.cna.affected.root[0].vendor
    ratings = {}
    if vector:
        ratings = {
            "method": method,
            "severity": severity.lower(),
            "score": score,
            "vector": vector,
        }
    return (
        source,
        references,
        advisories,
        cwes,
        description,
        detail,
        ratings,
        bug_bounties,
        pocs,
        exploits,
        vendors,
        vendor,
    )


def parse_metrics(metrics):
    vector = ""
    method = ""
    severity = "unknown"
    score = ""
    if not metrics:
        return vector, method, severity, score
    if metrics.root:
        for metric in metrics.root:
            if metric.cvssV4_0:
                vector = metric.cvssV4_0.vectorString
                method = "CVSSv4"
                severity = metric.cvssV4_0.baseSeverity.value
                score = metric.cvssV4_0.baseScore.value
                break
            elif method != "CVSSv31" and (m := (metric.cvssV3_1 or metric.cvssV3_0)):
                vector = m.vectorString
                method = "CVSSv31" if m.version.value == "3.1" else "CVSSv3"
                severity = m.baseSeverity.value
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
            full_pkg = f"{vendor}:{package_issue['affected_location'].get('package')}"
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
    # Do we have a pre-computed fix_version from vdb already?
    if vuln.get("fix_version"):
        return vuln.get("fix_version")
    source_data = vuln.get("source_data")
    if source_data and source_data.root.containers:
        products: List[Product] = source_data.root.containers.cna.affected.root
        for p in products:
            versions: List[Versions] = p.versions
            if versions:
                for ver in versions:
                    if ver.status == Status.unaffected:
                        if ver.version:
                            return ver.version.root
    vers = vuln.get("matching_vers", "")
    if "|" in vers:
        vers = vers.split("|")[-1]
        if "!=" in vers or "<=" not in vers:
            return vers.replace("<", "").replace("!=", "")
    elif "/<" in vers and "/<=" not in vers:
        return vers.split("/<")[-1]
    elif vers.endswith(f"<{PLACEHOLDER_EXCLUDE_VERSION}"):
        return PLACEHOLDER_EXCLUDE_VERSION
    elif vers.endswith(f"<{PLACEHOLDER_FIX_VERSION}"):
        return PLACEHOLDER_FIX_VERSION
    return ""


def get_version_from_detail(detail, affected_version):
    version = ""
    if match := UPPER_VERSION_FROM_DETAIL_A.search(detail):
        version = match["version"].rstrip(".")
    if match := UPPER_VERSION_FROM_DETAIL_B.search(detail):
        version = match["version"].rstrip(".")
    if (
        affected_version
        and version
        and compare_versions(affected_version, version, "<=")
    ):
        return version
    return ""


def get_ref_summary(url, patterns):
    """
    Returns the summary string associated with a given URL.

    :param url: The URL to match against the patterns in the REF_MAP.
    :type url: str

    :param patterns: Regex patterns to match against the URL
    :type patterns: dict

    :return: The summary string corresponding to the matched pattern in REF_MAP.
    :rtype: str

    :raises: TypeError if url is not a string
    """
    if not isinstance(url, str):
        raise TypeError("url must be a string")
    for pattern, value in patterns.items():
        if match := pattern.search(url):
            return value, match
    return "Other", None


def get_ref_summary_helper(url, patterns):
    lower_url = url.lower().rstrip("/")
    if (
        any(
            (
                "github.com" in lower_url,
                "bitbucket.org" in lower_url,
                "chromium" in lower_url,
            )
        )
        and "advisory" not in lower_url
        and "advisories" not in lower_url
        and "nvd.nist.gov/vuln/detail/CVE" not in lower_url
    ):
        value, match = get_ref_summary(url, patterns["repo_hosts"])
        if match:
            if value == "Generic":
                return (
                    (
                        f"{match['host']}-{match['type']}-{match['user']}-{match['repo']}-"
                        f"{match['id']}"
                    ).replace("[p/", "["),
                    match,
                    f"{format_system_name(match['host'])} {match['type'].capitalize()} "
                    f"[{match['user']}/{match['repo']}]".replace("[p/", "["),
                )
            if value == "GitHub Blob":
                return (
                    f"github-blob-{match['user']}/{match['repo']}-{match['file']}@{match['ref']}",
                    match,
                    f"GitHub Blob [{match['user']}/{match['repo']}]",
                )
            if value == "GitHub Gist":
                return (
                    f"github-gist-{match['user']}-{match['id']}",
                    match,
                    f"GitHub Gist [{match['user']}]",
                )
        return value, match, ""
    value, match = get_ref_summary(url, patterns["other"])
    if value == "Advisory":
        return value, match, f"{format_system_name(match['org'])} Advisory"
    elif value == "Exploit":
        if "seclists" in lower_url:
            _, match = get_ref_summary(
                url, {patterns["exploits"]["seclists"]: "seclists"}
            )
            value = value.replace("/", "-")
        else:
            _, match = get_ref_summary(
                url, {patterns["exploits"]["generic"]: "generic"}
            )
        return (
            (value, match, f"{format_system_name(match['org'])} Exploit")
            if match
            else (value, None, "Exploit")
        )
    return value, match, value


def refs_to_vdr(
    references: References | None, vid
) -> Tuple[List, List, List, List, List, List, Dict]:
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
        category, rmatch, system_name = get_ref_summary_helper(i, REF_MAP)
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
                    advisories.append(
                        {"title": f"{system_name} Advisory {rmatch['id']}", "url": i}
                    )
                    if system_name in {"Synology Exploits", "Samba Exploits"}:
                        vendor.append(i)
                exploit.append(i)
        elif category == "Bugzilla":
            refs.append(
                {
                    "id": f"{rmatch['org']}-bugzilla-{rmatch['id']}",
                    "source": {
                        "name": f"{format_system_name(rmatch['org'])} Bugzilla",
                        "url": i,
                    },
                }
            )
            vendor.append(i)
        elif category == "Vendor":
            if "announce" in i:
                vendor.append(i)
            if rmatch := ADVISORY.search(i):
                system_name = f"{format_system_name(rmatch['org'])} Mailing List"
                refs.append(
                    {
                        "id": f"{rmatch['org']}-msg-{rmatch['id']}",
                        "source": {"name": system_name, "url": i},
                    }
                )
        elif category == "Mailing List":
            if "openwall" in i:
                if not (rmatch := REF_MAP["openwall"].search(i)):
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
            refs.append(
                {
                    "id": f"{rmatch['user']}-{rmatch['repo']}-{rmatch['type']}-{rmatch['id']}",
                    "source": {
                        "name": f"{format_system_name(rmatch['host'])} {rmatch['type'].capitalize()}",
                        "url": i,
                    },
                }
            )
    return (
        combine_references(advisories, []),
        combine_references(refs, []),
        bug_bounty,
        poc,
        exploit,
        vendor,
        source,
    )


def adv_ref_parsing(adv_id, i, system_name):
    if system_name == "Gentoo Advisory":
        adv_id = f"glsa-{adv_id}"
    if system_name == "Jfrog Advisory":
        system_name = "JFrog Advisory"
        if id_match := JFROG_ADVISORY.search(i):
            adv_id = id_match["id"]
    return adv_id, system_name


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
):
    vid = vuln_occ_dict.get("id") or ""
    package_issue = {}
    purl = ""
    full_pkg = ""
    project_type_pkg = ""
    cwes = []
    version_used = ""
    if problem_type := vuln_occ_dict.get("problem_type"):
        cwes = split_cwe(problem_type)
        full_pkg, package_issue, project_type_pkg, purl, version_used = (
            process_package_issue(options, vuln_occ_dict)
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
    description, detail = get_description_detail(
        vuln_occ_dict.get("short_description", "")
    )
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
        "fixed_location": fixed_location,
    }
    if not purl.startswith("pkg:"):
        if options.project_type in OS_PKG_TYPES:
            if vendor and (
                vendor in LANG_PKG_TYPES.values() or LANG_PKG_TYPES.get(vendor)
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
                LANG_PKG_TYPES.get(package_type)
                or package_type in LANG_PKG_TYPES.values()
            ) and (
                (vendor and vendor in OS_PKG_TYPES)
                or not is_lang_sw_edition(package_issue)
            ):
                counts.fp_count += 1
                return counts, add_to_pkg_group_rows, vuln
            if package_type in OS_PKG_TYPES:
                # Bug #208 - do not report application CVEs
                if vendor and (
                    vendor in LANG_PKG_TYPES.values() or LANG_PKG_TYPES.get(vendor)
                ):
                    counts.fp_count += 1
                    return counts, add_to_pkg_group_rows, vuln
                if package_type and (
                    package_type in LANG_PKG_TYPES.values()
                    or LANG_PKG_TYPES.get(package_type)
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
                    if (
                        purl_obj.get("name") in OS_PKG_IGNORABLE
                        or vendor in OS_PKG_IGNORABLE
                    ):
                        insights.append(
                            "[#7C8082]:mute: Suppress for containers[/#7C8082]"
                        )
                        plain_insights.append("Suppress for containers")
                    elif purl_obj.get("name") in OS_PKG_UNINSTALLABLE:
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
                f":direct_hit: Used in [info]"
                f"{str(direct_purls.get(purl))}"
                f"[/info] {label_str}"
            )
            plain_package_usage = f"Used in {str(direct_purls.get(purl))} {label_str}"
        else:
            package_usage = ":direct_hit: Direct dependency"
            plain_package_usage = "Direct dependency"
    elif (not optional_pkgs and pkg_tree_list and len(pkg_tree_list) > 1) or (
        purl in optional_pkgs
        or full_pkg in optional_pkgs
        or project_type_pkg in optional_pkgs
    ):
        if package_type in OS_PKG_TYPES:
            counts.has_os_packages = True
        else:
            package_usage = (
                "[spring_green4]:notebook: Indirect dependency[/spring_green4]"
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
            insights.append("[yellow]:notebook_with_decorative_cover: Has PoC[/yellow]")
            plain_insights.append("Has PoC")
        counts.has_poc_count += 1
        if pkg_severity.upper() in CRITICAL_OR_HIGH:
            pkg_requires_attn = True
    if (clinks.get("vendor") and package_type not in OS_PKG_TYPES) or reached_purls.get(
        purl
    ):
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
        insights.append("[spring_green4]:direct_hit: Distro specific[/spring_green4]")
        plain_insights.append("Distro specific")
        counts.distro_packages_count += 1
        counts.has_os_packages = True
    if pkg_requires_attn and fixed_location and purl:
        add_to_pkg_group_rows = True
    vuln |= {
        "insights": insights,
        "properties": get_vuln_properties(
            fixed_location, pkg_requires_attn, plain_insights, purl
        ),
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
):
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
    if vid.startswith("MAL-"):
        insights.append("[bright_red]:stop_sign: Malicious[/bright_red]")
        plain_insights.append("Malicious")
        counts.malicious_count += 1
        cve_requires_attn = True
    has_flagged_cwe = False
    add_to_pkg_group_rows = False
    if fixed_location := get_unaffected(vuln):
        affects[0]["versions"].append(
            {"version": fixed_location, "status": "unaffected"}
        )
        # This is a basic recommendation
        recommendation = f"Update to version {fixed_location}."
        if fixed_location in (PLACEHOLDER_EXCLUDE_VERSION,):
            likely_false_positive = True
            return counts, {}, False, likely_false_positive
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
    vdict = {
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
    }
    try:
        cve_record = vuln.get("source_data")
        if not isinstance(cve_record, CVE):
            return counts, vdict, add_to_pkg_group_rows, likely_false_positive
    except KeyError:
        return counts, vdict, add_to_pkg_group_rows, likely_false_positive

    if not cve_record:
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
        vdict["affects"][0]["versions"].append(
            {"version": fixed_location, "status": "unaffected"}
        )
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
    published = cve_record.root.cveMetadata.datePublished
    updated = cve_record.root.cveMetadata.dateUpdated
    vdict |= {
        "source": source,
        "references": references,
        "advisories": advisories,
        "cwes": cwes,
        "description": description,
        "detail": detail,
        "ratings": [rating],
        "published": published.strftime("%Y-%m-%dT%H:%M:%S") if published else "",
        "updated": updated.strftime("%Y-%m-%dT%H:%M:%S") if updated else "",
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
    if (
        rating.get("severity", "").upper() in JUST_CRITICAL
        and not likely_false_positive
    ):
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
                f":direct_hit: Used in [info]{str(direct_purls.get(purl))}[/info] "
                f"locations"
            )
            plain_package_usage = f"Used in {str(direct_purls.get(purl))} locations"
        else:
            package_usage = ":direct_hit: Direct dependency"
            plain_package_usage = "Direct dependency"
    elif (
        not optional_pkgs and pkg_tree_list and len(pkg_tree_list) > 1
    ) or purl in optional_pkgs:
        if package_type in OS_PKG_TYPES:
            counts.has_os_packages = True
        else:
            package_usage = (
                "[spring_green4]:notebook: Indirect dependency[/spring_green4]"
            )
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
            insights.append(
                "[yellow]:notebook_with_decorative_cover: Bug Bounty target[/yellow]"
            )
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
                purl_obj
                and purl_obj.get("name") in ("glibc", "openssl", "curl", "wget", "git")
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
            # Just known exploits without usage is not a priority
            if reached_purls or direct_purls:
                cve_requires_attn = False
    if cve_record.root.containers.cna.affected.root and (
        cpes := cve_record.root.containers.cna.affected.root[0].cpes
    ):
        # Distro-specific package
        if all((distro_package(i.root) for i in cpes)):
            insights.append(
                "[spring_green4]:direct_hit: Distro specific[/spring_green4]"
            )
            plain_insights.append("Distro specific")
            counts.distro_packages_count += 1
            counts.has_os_packages = True
    if package_usage:
        insights.append(package_usage)
        plain_insights.append(plain_package_usage)
    add_to_pkg_group_rows = (
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
        "properties": get_vuln_properties(
            fixed_location, cve_requires_attn, plain_insights, purl
        ),
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
        properties.append(
            {"name": "depscan:insights", "value": "\\n".join(plain_insights)}
        )
    return properties


def get_pkg_list(jsonfile):
    """
    Method to extract packages from a bom json file

    :param jsonfile: Path to a bom json file.
    return List of dicts representing extracted packages
    """
    pkgs = []
    lifecycles = []
    if bom_data := json_load(jsonfile):
        # Start with parsing the metadata section
        if bom_data.get("metadata", {}):
            metadata = bom_data.get("metadata", {})
            # Collect the lifecycles listed in the BOM
            if metadata.get("lifecycles"):
                lifecycles = bom_data["metadata"]["lifecycles"]
            # Track from metadata.component.components
            for mcomp in metadata.get("component", {}).get("components", []):
                # Skip component types that do not require checking
                if mcomp.get("type", "") in ("application", "data"):
                    continue
                licenses, vendor, url = get_vendor_url(mcomp)
                pkgs.append(
                    {**mcomp, "vendor": vendor, "licenses": licenses, "url": url}
                )
        for comp in bom_data.get("components", []):
            if comp.get("type", "") in ("data",):
                continue
            licenses, vendor, url = get_vendor_url(comp)
            pkgs.append({**comp, "vendor": vendor, "licenses": licenses, "url": url})
            # nested components
            for nc in comp.get("components", []):
                # Skip component types that do not require checking
                if nc.get("type", "") in ("application", "data"):
                    continue
                licenses, vendor, url = get_vendor_url(nc)
                pkgs.append({**nc, "vendor": vendor, "licenses": licenses, "url": url})
    return pkgs, lifecycles


def get_all_pkg_list(from_dir):
    """
    Method to extract packages from a bom json file

    :param jsonfile: Path to a bom json file.
    return List of dicts representing extracted packages
    """
    bom_files = get_all_bom_files(from_dir)
    unique_packages = []
    seen_bom_refs = set()
    # Retain the identity evidences to identify the file to patch
    component_identities = defaultdict(list)
    for file_path in bom_files:
        pkg_list, lifecycles = get_pkg_list(file_path)
        lifecycle_mode = get_lifecycle(lifecycles)
        for pkg in pkg_list:
            identity_evidences = pkg.get("evidence", {}).get("identity", []) or []
            if isinstance(identity_evidences, dict):
                identity_evidences = [identity_evidences]
            purl = pkg.get("purl")
            # Ignore unversioned components in post-build
            if lifecycle_mode == "post-build" and purl and "@" not in purl:
                continue
            bom_ref = pkg.get("bom-ref") or purl
            if not bom_ref:
                continue
            component_identities[bom_ref] += identity_evidences
            if bom_ref not in seen_bom_refs:
                unique_packages.append(pkg)
                seen_bom_refs.add(bom_ref)
    for comp in unique_packages:
        ref = comp.get("bom-ref") or comp.get("purl")
        identity_evidences = component_identities[ref]
        comp["evidence"] = {"identity": identity_evidences}
    return unique_packages


def get_vendor_url(comp):
    licenses = []
    vendor = comp.get("group") or ""
    if comp.get("licenses"):
        for lic in comp.get("licenses"):
            license_obj = lic
            if isinstance(lic, str):
                continue
            if lic.get("license"):
                license_obj = lic.get("license")
            if license_obj.get("id"):
                licenses.append(license_obj.get("id"))
    url = ""
    for aref in comp.get("externalReferences", []):
        if aref.get("type") == "vcs":
            url = aref.get("url", "")
            break
    return licenses, vendor, url


def get_lifecycle(lifecycles):
    lifecycle_mode = "pre-build"
    if not lifecycles or not isinstance(lifecycles, list):
        return "pre-build"
    for l in lifecycles:
        phase = l.get("phase", "")
        if phase == "build":
            lifecycle_mode = "build"
        if phase == "post-build":
            lifecycle_mode = "post-build"
            break
    return lifecycle_mode


def versionify_postbuild_purls(prebuild_purls, build_purls, postbuild_purls):
    matcher_purls = {}
    mpostbuild_purls = {}
    for p in prebuild_purls.keys():
        matcher_purls[p.split("@")[0]] = p
    for p in build_purls.keys():
        matcher_purls[p.split("@")[0]] = p
    for k, v in postbuild_purls.items():
        if matcher_purls.get(k):
            mpostbuild_purls[matcher_purls.get(k)] = v
        else:
            mpostbuild_purls[k] = v
    return mpostbuild_purls


def track_executables(
    file_path, pkg, executable_purls, setuid_executable_purls, setgid_executable_purls
):
    if not pkg or not pkg.get("type", "") == "file" or not pkg.get("properties"):
        return
    props = pkg.get("properties")
    ref = pkg.get("purl") or pkg.get("bom-ref")
    if not ref:
        return
    for p in props:
        if p.get("name", "") == "internal:is_executable" and p["value"] == "true":
            executable_purls[ref].append(file_path)
        if p.get("name", "") == "internal:has_setuid" and p["value"] == "true":
            setuid_executable_purls[ref].append(file_path)
        if p.get("name", "") == "internal:has_setgid" and p["value"] == "true":
            setgid_executable_purls[ref].append(file_path)


def get_lifecycle_pkgs(file_path):
    prebuild_purls = {}
    build_purls = {}
    postbuild_purls = {}
    executable_purls = defaultdict(list)
    setuid_executable_purls = defaultdict(list)
    setgid_executable_purls = defaultdict(list)
    purl_identities = defaultdict(list)
    lifecycle_mode = "pre-build"
    populate_dict = prebuild_purls
    if file_path and os.path.exists(file_path):
        pkg_list, lifecycles = get_pkg_list(file_path)
        lifecycle_mode = get_lifecycle(lifecycles)
        if lifecycle_mode == "pre-build":
            populate_dict = prebuild_purls
        elif lifecycle_mode == "build":
            populate_dict = build_purls
        elif lifecycle_mode == "post-build":
            populate_dict = postbuild_purls
        for pkg in pkg_list:
            ref = pkg.get("purl") or pkg.get("bom-ref")
            if not ref:
                continue
            identity_evidences = pkg.get("evidence", {}).get("identity", []) or []
            if isinstance(identity_evidences, dict):
                identity_evidences = [identity_evidences]
            purl_identities[ref] += identity_evidences
            if not populate_dict.get(ref):
                populate_dict[ref] = []
            populate_dict[ref].append(file_path)
            track_executables(
                file_path,
                pkg,
                executable_purls,
                setuid_executable_purls,
                setgid_executable_purls,
            )
    # Include version numbers to postbuild purls
    postbuild_purls = versionify_postbuild_purls(
        prebuild_purls, build_purls, postbuild_purls
    )
    return (
        prebuild_purls,
        build_purls,
        postbuild_purls,
        executable_purls,
        setuid_executable_purls,
        setgid_executable_purls,
        purl_identities,
    )


def get_all_lifecycle_pkgs(from_dir):
    prebuild_purls = {}
    build_purls = {}
    postbuild_purls = {}
    executable_purls = {}
    setuid_executable_purls = {}
    setgid_executable_purls = {}
    purl_identities = {}
    if from_dir and os.path.exists(from_dir):
        bom_files = get_all_bom_files(from_dir)
        for file_path in bom_files:
            pre, build, post, exe, uid, gid, identities = get_lifecycle_pkgs(file_path)
            prebuild_purls |= pre
            build_purls |= build
            postbuild_purls |= post
            executable_purls |= exe
            setuid_executable_purls |= uid
            setgid_executable_purls |= gid
            purl_identities |= identities
    # Include version numbers to postbuild purls
    postbuild_purls = versionify_postbuild_purls(
        prebuild_purls, build_purls, postbuild_purls
    )
    return (
        prebuild_purls,
        build_purls,
        postbuild_purls,
        executable_purls,
        setuid_executable_purls,
        setgid_executable_purls,
        purl_identities,
    )


def strip_version(purl_str: str) -> str:
    """Remove the '@version' suffix if present."""
    purl_no_version, *_ = purl_str.split("@", 1)
    return purl_no_version


def is_service_like_tag(tags):
    if not tags:
        return False
    return any([t for t in tags if t in SERVICE_TAGS])


def is_endpoint_filterable(purl):
    for p in SAFE_ENDPOINT_REACHABLE_PURLS:
        if purl.startswith(p):
            return True
    return False
