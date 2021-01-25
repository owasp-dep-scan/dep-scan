from vdb.lib import KNOWN_PKG_TYPES

from depscan.lib import config as config

# Common package suffixes
COMMON_SUFFIXES = [
    "-core",
    ".core",
    "-client-core",
    "-classic",
    "-api",
    "-complete",
    "-full",
    "-all",
    "-ex",
    "-server",
    ".js",
    "-handler",
    "apache-",
    "-web",
    "-broker",
    "-netty",
    "-plugin",
    "-web-console",
    "-main",
    "-war",
]


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
    purl = pkg_dict.get("purl", "")
    if vendor:
        vendor_aliases.add(vendor)
        short_vendor = None
        if (
            vendor.startswith("org.")
            or vendor.startswith("io.")
            or vendor.startswith("com.")
            or vendor.startswith("net.")
        ):
            tmpA = vendor.split(".")
            # Automatically add short vendor forms
            if len(tmpA) > 2 and len(tmpA[1]) > 3:
                if tmpA[1] != name:
                    vendor_aliases.add(tmpA[1])
                short_vendor = tmpA[1]
    # Add some common vendor aliases
    if purl.startswith("pkg:composer") or purl.startswith("pkg:pypi"):
        vendor_aliases.add(name)
    if purl.startswith("pkg:golang") and not name.startswith("go"):
        # Ignore third party alternatives for builtins
        if "golang" not in vendor and name not in ["net", "crypto", "http"]:
            vendor_aliases.add("golang")
    if not purl.startswith("pkg:golang"):
        vendor_aliases.add("get" + name)
        vendor_aliases.add(name + "_project")
    for k, v in config.vendor_alias.items():
        if vendor.startswith(k) or k.startswith(vendor):
            vendor_aliases.add(k)
            vendor_aliases.add(v)
        elif name == k:
            vendor_aliases.add(v)
    name_aliases.add(name)
    name_aliases.add(name.lower())
    name_aliases.add(name.replace("-", "_"))
    name_aliases.add("package_" + name)
    # Pypi specific vendor aliases
    if purl.startswith("pkg:pypi"):
        if not name.startswith("python-"):
            name_aliases.add("python-" + name)
            name_aliases.add("python-" + name + "_project")
        vendor_aliases.add("pip")
        vendor_aliases.add("python")
        vendor_aliases.add("python-" + name)
        vendor_aliases.add(name + "project")
    elif purl.startswith("pkg:npm") and not name.startswith("node-"):
        name_aliases.add("node-" + name)
    elif purl.startswith("pkg:crates") and not name.startswith("rust-"):
        name_aliases.add("rust-" + name)
    elif purl.startswith("pkg:composer") and not name.startswith("php-"):
        name_aliases.add("php-" + name)
    elif purl.startswith("pkg:nuget"):
        vendor_aliases.add("nuget")
    elif purl.startswith("pkg:rubygems"):
        vendor_aliases.add("rubygems")
        vendor_aliases.add("rubyonrails")
    for suffix in COMMON_SUFFIXES:
        if name.endswith(suffix):
            name_aliases.add(name.replace(suffix, ""))
    for k, v in config.package_alias.items():
        if name.startswith(k) or k.startswith(name):
            name_aliases.add(k)
            name_aliases.add(v)
    if len(vendor_aliases):
        for vvar in list(vendor_aliases):
            for nvar in list(name_aliases):
                pkg_list.append({**pkg_dict, "vendor": vvar, "name": nvar})
    else:
        for nvar in list(name_aliases):
            pkg_list.append({**pkg_dict, "name": nvar})
    return pkg_list


def dealias_packages(project_type, pkg_list, pkg_aliases):
    """Method to dealias package names by looking up vendor and name information
    in the aliases list

    :param project_type: Project type
    :param pkg_list: List of packages to dealias
    :param pkg_aliases: Package aliases
    """
    if not pkg_aliases:
        return {}
    dealias_dict = {}
    for res in pkg_list:
        package_issue = res.package_issue
        full_pkg = package_issue.affected_location.package
        if package_issue.affected_location.vendor:
            full_pkg = "{}:{}".format(
                package_issue.affected_location.vendor,
                package_issue.affected_location.package,
            )
        for k, v in pkg_aliases.items():
            if (
                full_pkg in v or (":" + package_issue.affected_location.package) in v
            ) and full_pkg != k:
                dealias_dict[full_pkg] = k
                break
    return dealias_dict


def dedup(project_type, pkg_list, pkg_aliases):
    """Method to trim duplicates in the results based on the id. The logic should ideally be based on package alias but is kept simple for now.

    :param project_type: Project type
    :param pkg_list: List of packages to dedup
    :param pkg_aliases: Package aliases
    """
    dedup_dict = {}
    ret_list = []
    for res in pkg_list:
        vid = res.id
        vuln_occ_dict = res.to_dict()
        package_type = vuln_occ_dict.get("type")
        allowed_type = config.LANG_PKG_TYPES.get(project_type)
        if package_type and package_type in KNOWN_PKG_TYPES and allowed_type:
            if allowed_type != package_type:
                dedup_dict[vid] = True
        if vid not in dedup_dict:
            ret_list.append(res)
            dedup_dict[vid] = True
    return ret_list
