import json

import yaml

from depscan.lib.utils import find_files


def build_license_data(license_dir, spdx_license_list):
    """Build license data based on the txt files"""
    licenses_dict = {}
    with open(spdx_license_list, encoding="utf-8") as fp:
        spdx_license_data = json.load(fp)
        for slic in spdx_license_data.get("licenses"):
            licenses_dict[slic["licenseId"]] = {
                "title": slic["name"],
                "spdx-id": slic["licenseId"],
                "osi_approved": slic.get("isOsiApproved"),
                "fsf_libre": slic.get("isFsfLibre"),
                "conditions": [f"See {slic['detailsUrl']}"],
                "condition_flag": not slic.get("isOsiApproved"),
            }
    license_files = find_files(license_dir, "txt")
    for lfile in license_files:
        with open(lfile, encoding="utf-8") as fp:
            raw_data = fp.read().split("---")[1]
            ldata = yaml.safe_load(raw_data)
            ldata["condition_flag"] = False
            for cond in ldata["conditions"]:
                if cond in [
                    "document-changes",
                    "network-use-disclose",
                    "disclose-source",
                    "same-license",
                    "same-license--file",
                    "same-license--library",
                ]:
                    ldata["condition_flag"] = True

            licenses_dict[ldata.get("spdx-id").strip().upper()] = ldata
    return licenses_dict


def bulk_lookup(license_dict, pkg_list):
    """Lookup package licenses"""
    pkg_licenses = {}
    for pkg in pkg_list:
        # Failsafe in case the bom file contains incorrect entries
        if not pkg.get("name") or not pkg.get("version"):
            continue
        pkg_key = pkg["name"] + "@" + pkg["version"]
        if pkg.get("vendor"):
            pkg_key = pkg.get("vendor") + ":" + pkg["name"] + "@" + pkg["version"]
        for lic in pkg.get("licenses"):
            if lic == "X11":
                lic = "MIT"
            elif "MIT" in lic:
                lic = "MIT"
            curr_list = pkg_licenses.get(pkg_key, [])
            match_lic = license_dict.get(lic)
            if match_lic:
                curr_list.append(match_lic)
            pkg_licenses[pkg_key] = curr_list
    return pkg_licenses
