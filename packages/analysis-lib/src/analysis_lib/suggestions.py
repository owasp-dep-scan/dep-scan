"""Fix-version suggestions for vulnerable packages.

Turns the fixed locations already present in scan results into per-purl
suggested versions, re-checks the suggested versions against the database and
writes the outcome into the VDR recommendations (make_version_suggestions).

It does not compute which versions are affected (the matching stage owns
that) and does not decide priority.
"""

import contextlib
from typing import Dict, List

from analysis_lib.helpers import max_version
from analysis_lib.search import find_vulns
from packageurl import PackageURL
from vdb.lib.config import PLACEHOLDER_FIX_VERSION
from vdb.lib.utils import parse_purl


def get_suggested_version_map(pkg_vulnerabilities: List[Dict]) -> Dict[str, str]:
    suggested_version_map = {}
    for i, v in enumerate(pkg_vulnerabilities):
        fixed_location = v.get("fixed_location")
        if not fixed_location or fixed_location in (PLACEHOLDER_FIX_VERSION, "*"):
            continue
        purl_prefix = v.get("purl_prefix") or ""
        # Don't go near certain packages
        if "kernel" in purl_prefix or "openssl" in purl_prefix or "openssh" in purl_prefix:
            continue
        if purl_prefix in suggested_version_map:
            suggested_version_map[purl_prefix] = max_version(
                [suggested_version_map[purl_prefix], fixed_location], purl=purl_prefix
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
