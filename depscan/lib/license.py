import re

import yaml

from depscan.lib.utils import find_files

lic_symbol_regex = re.compile(r"[\(\)\,]")


def build_license_data(license_dir):
    """
    """
    licenses_dict = {}
    license_files = find_files(license_dir, "txt")
    for lfile in license_files:
        with open(lfile) as fp:
            raw_data = fp.read().split("---")[1]
            ldata = yaml.safe_load(raw_data)
            ldata["condition_flag"] = False
            for cond in ldata["conditions"]:
                if cond in [
                    "disclose-source",
                    "same-license",
                    "same-license--file",
                    "same-license--library",
                ]:
                    ldata["condition_flag"] = True

            licenses_dict[ldata.get("spdx-id").strip().upper()] = ldata
    return licenses_dict


def bulk_lookup(license_dict, pkg_list):
    """
    """
    pkg_licenses = {}
    for pkg in pkg_list:
        pkg_key = pkg["vendor"] + ":" + pkg["name"] + "@" + pkg["version"]
        for lic in pkg["licenses"]:
            lic = lic.replace(" ", "-")
            lic = lic_symbol_regex.sub("", lic)
            lic = lic.upper()
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
