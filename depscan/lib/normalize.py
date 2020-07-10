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
