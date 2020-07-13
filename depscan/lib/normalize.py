from depscan.lib import config as config


def normalize_pkg(pkg_dict):
    """
    Normalize the package vendor and name

    :param pkg_dict: Dict containing package vendor, name and version
    :return: Normalized version
    """
    vendor = pkg_dict.get("vendor")
    name = pkg_dict.get("name")
    for k, v in config.vendor_alias.items():
        if vendor.lower().startswith(k):
            pkg_dict["vendor"] = v
    for k, v in config.package_alias.items():
        if name.lower() == k:
            pkg_dict["name"] = v
    return pkg_dict


def create_pkg_variations(pkg_dict):
    """
    Method to create variations of the given package by considering vendor and package aliases

    :param pkg_dict: Dict containing package vendor, name and version
    :return: List of possible variations to the package
    """
    pkg_list = []
    vendor_aliases = set()
    name_aliases = set()
    vendor = pkg_dict.get("vendor")
    name = pkg_dict.get("name")
    if vendor:
        vendor_aliases.add(vendor)
        for k, v in config.vendor_alias.items():
            if vendor in k or k in vendor:
                vendor_aliases.add(k)
                vendor_aliases.add(v)
    name_aliases.add(name)
    for k, v in config.package_alias.items():
        if name in k or k in name:
            name_aliases.add(k)
            name_aliases.add(v)
    if len(vendor_aliases):
        for vvar in list(vendor_aliases):
            for nvar in list(name_aliases):
                pkg_list.append(
                    {
                        "vendor": vvar,
                        "name": nvar,
                        "version": pkg_dict.get("version"),
                        "licenses": pkg_dict.get("licenses"),
                    }
                )
    else:
        for nvar in list(name_aliases):
            pkg_list.append(
                {
                    "vendor": pkg_dict.get("vendor"),
                    "name": nvar,
                    "version": pkg_dict.get("version"),
                    "licenses": pkg_dict.get("licenses"),
                }
            )
    return pkg_list
