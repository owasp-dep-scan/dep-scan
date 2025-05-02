from typing import Any, Dict

from vdb.lib.config import PLACEHOLDER_EXCLUDE_VERSION
from vdb.lib.utils import parse_purl

from analysis_lib import config

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
    Method to create variations of the given package by considering vendor
    and package aliases

    :param pkg_dict: Dict containing package vendor, name and version
    :return: List of possible variations to the package
    """
    pkg_list = [{**pkg_dict}]
    vendor_aliases = set()
    name_aliases = set()
    vendor = pkg_dict.get("vendor") or ""
    name = pkg_dict.get("name") or ""
    purl = pkg_dict.get("purl") or ""
    pkg_type = pkg_dict.get("type") or ""
    name_aliases.add(name)
    name_aliases.add(name.lower())
    name_aliases.add(name.replace("-", "_"))
    os_distro = None
    if purl:
        try:
            purl_obj: Dict[str, Any] | None = parse_purl(purl)
            if purl_obj:
                pkg_type = purl_obj.get("type")
                qualifiers = purl_obj.get("qualifiers", {})
                # Issue #320. Mandate version number for generic packages to reduce FPs
                if pkg_type in ("generic",) and not purl_obj.get("version"):
                    return None
                if pkg_type in ("npm",):
                    # vendorless package could have npm as the vendor name from sources such as osv
                    # So we need 1 more alias
                    if not purl_obj.get("namespace") and not vendor:
                        pkg_list.append(
                            {
                                "vendor": "npm",
                                "name": pkg_dict.get("name"),
                                "version": pkg_dict.get("version"),
                            }
                        )
                    return pkg_list
                # For Rubygems, version string could include the plaform.
                # So we create an alias without the platform to improve the results
                if pkg_type in ("gem",):
                    for plaform_marker in config.RUBY_PLATFORM_MARKERS:
                        if (
                            pkg_dict.get("version")
                            and plaform_marker in pkg_dict["version"]
                        ):
                            pkg_list.append(
                                {
                                    "vendor": vendor,
                                    "name": pkg_dict.get("name"),
                                    "version": pkg_dict["version"].split(
                                        plaform_marker
                                    )[0],
                                }
                            )
                            break
                if qualifiers and qualifiers.get("distro_name"):
                    os_distro_name = qualifiers.get("distro_name")
                    name_aliases.add(f"""{os_distro_name}/{name}""")
                if qualifiers and qualifiers.get("distro"):
                    os_distro = qualifiers.get("distro")
                    name_aliases.add(f"""{os_distro}/{name}""")
                    # almalinux-9.2 becomes almalinux-9
                    if "-" in os_distro and "." in os_distro:
                        name_aliases.add(f"""{os_distro.rsplit(".", 1)[0]}/{name}""")
        except Exception:
            tmp_parts = purl.split(":")
            if tmp_parts and len(tmp_parts) > 1:
                vendor_aliases.add(tmp_parts[1])
    if vendor:
        vendor_aliases.add(vendor)
        vendor_aliases.add(vendor.lower())
        vendor_aliases.add(vendor.lstrip("@"))
    # Add some common vendor aliases
    if purl.startswith("pkg:golang") and not name.startswith("go"):
        vendor_aliases.add("go")
        # Ignore third party alternatives for builtins
        if "golang" not in vendor and name not in [
            "net",
            "crypto",
            "http",
            "text",
        ]:
            vendor_aliases.add("golang")
    if pkg_type not in config.OS_PKG_TYPES:
        if not vendor and purl.startswith("pkg:composer"):
            vendor_aliases.add("get" + name)
            vendor_aliases.add(name + "_project")
        for k, v in config.vendor_alias.items():
            if vendor and (vendor.startswith(k) or k.startswith(vendor)):
                vendor_aliases.add(k)
                vendor_aliases.add(v)
            elif name == k:
                vendor_aliases.add(v)
            elif name.startswith(v):
                vendor_aliases.add(k)
    # This will add false positives to ubuntu
    if "/" in name and os_distro and "ubuntu" not in os_distro:
        name_aliases.add(name.split("/")[-1])
    # Pypi specific vendor aliases
    if purl.startswith("pkg:pypi"):
        if not name.startswith("python-"):
            name_aliases.add("python-" + name)
            name_aliases.add("python-" + name + "_project")
            # Eg: numpy:numpy
            vendor_aliases.add(name)
            # Issue #262
            # Eg: cpe:2.3:a:microsoft:azure_storage_blobs:*:*:*:*:*:python:*:*
            # pypi name is pkg:pypi/azure-storage-blob@12.8.0
            # Issue #341 - do not change colorama to coloramas
            if not name.endswith("s") and "-" in name:
                name_aliases.add(name.replace("-", "_") + "s")
        vendor_aliases.add("pip")
        vendor_aliases.add("pypi")
        vendor_aliases.add("python")
        vendor_aliases.add("python-" + name)
    elif purl.startswith("pkg:npm"):
        # pg-promise CVE is filed as pg
        if name.endswith("-promise"):
            name_aliases.add(name.replace("-promise", ""))
    elif purl.startswith("pkg:crates") and not name.startswith("rust-"):
        name_aliases.add("rust-" + name)
    elif purl.startswith("pkg:composer") and not name.startswith("php-"):
        name_aliases.add("php-" + name)
    elif purl.startswith("pkg:nuget"):
        vendor_aliases.add("nuget")
        name_parts = name.split(".")
        vendor_aliases.add(name_parts[0])
        vendor_aliases.add(name_parts[0].lower())
        # We don't want this to match Microsoft Windows
        if "windows" not in name_parts[-1].lower():
            name_aliases.add(name_parts[-1])
            name_aliases.add(name_parts[-1].lower())
        if name.lower().startswith("system"):
            vendor_aliases.add("microsoft")
        # Support for runtime components
        # See #294
        if name.lower().startswith("runtime.") and "system." in name.lower():
            runtime_part = name.split(".System")[0]
            name_with_runtime = (
                name.replace(f"{runtime_part}.", "") + "." + runtime_part
            )
            name_aliases.add(name_with_runtime)
            name_aliases.add(name_with_runtime.replace(".runtime.native", ""))
    elif purl.startswith("pkg:gem") or purl.startswith("pkg:rubygems"):
        vendor_aliases.add("gem")
        vendor_aliases.add("rubygems")
        vendor_aliases.add("rubyonrails")
    elif purl.startswith("pkg:hex") or purl.startswith("pkg:elixir"):
        vendor_aliases.add("hex")
        vendor_aliases.add("elixir")
    elif purl.startswith("pkg:pub") or purl.startswith("pkg:dart"):
        vendor_aliases.add("pub")
        vendor_aliases.add("dart")
    elif purl.startswith("pkg:github"):
        vendor_aliases.add("github actions")
        name_aliases.add(f"{vendor}/{name}")
    if pkg_type not in config.OS_PKG_TYPES:
        for suffix in COMMON_SUFFIXES:
            if name.endswith(suffix):
                name_aliases.add(name.replace(suffix, ""))
        # The below aliasing is resulting in several false positives for npm
        if pkg_type not in ("npm",):
            for k, v in config.package_alias.items():
                if name.startswith(k) or k.startswith(name) or v.startswith(name):
                    name_aliases.add(k)
                    name_aliases.add(v)
    if pkg_type in config.OS_PKG_TYPES:
        if "lib" in name:
            name_aliases.add(name.replace("lib", ""))
        elif "lib" not in name:
            name_aliases.add("lib" + name)
        if "-bin" not in name:
            name_aliases.add(name + "-bin")
    else:
        # Filter vendor aliases that are also name aliases
        # This is needed for numpy which has the vendor name numpy
        # Also needed for nuget. Eg: selenium:selenium
        if not purl.startswith("pkg:nuget"):
            vendor_aliases = [
                x
                for x in vendor_aliases
                if x not in name_aliases
                or x == vendor
                or config.package_alias.get(x) is not None
            ]
    if len(vendor_aliases) > 1:
        for vvar in list(vendor_aliases):
            for nvar in list(name_aliases):
                pkg_list.append(
                    {
                        "vendor": vvar,
                        "name": nvar,
                        "version": pkg_dict["version"],
                    }
                )
    elif len(name_aliases) > 1:
        for nvar in list(name_aliases):
            # vendor could be none which is fine
            pkg_list.append(
                {
                    "vendor": pkg_dict.get("vendor"),
                    "name": nvar,
                    "version": pkg_dict.get("version", ""),
                }
            )
    return pkg_list


def dealias_packages(pkg_list, pkg_aliases, purl_aliases):
    """
    Method to dealias package names by looking up vendor and name information
    in the aliases list

    :param pkg_list: List of packages to dealias
    :param pkg_aliases: A dictionary of package aliases
    :param purl_aliases: A dictionary of package URL aliases
    :return: Dictionary of dealiased package names and their aliases
    """
    if not pkg_aliases:
        return {}
    dealias_dict = {}
    for res in pkg_list:
        version = None
        if v := res.get("matched_by"):
            if "|" in v:
                version = v.split("|")[-1]
            else:
                version = v.split("@")[-1]
        package_issue = res.get("package_issue") or {}
        full_pkg = package_issue.get("affected_location", {}).get("package", "")
        if package_issue.get("affected_location", {}).get("vendor", ""):
            full_pkg = (
                f"{package_issue.affected_location.vendor}:"
                f"{package_issue.affected_location.package}"
            )
        if version:
            full_pkg = full_pkg + ":" + version
        if purl_aliases.get(full_pkg):
            dealias_dict[full_pkg] = purl_aliases.get(full_pkg)
        elif purl_aliases.get(full_pkg.lower()):
            dealias_dict[full_pkg] = purl_aliases.get(full_pkg.lower())
        else:
            for k, v in pkg_aliases.items():
                if (
                    full_pkg in v
                    or (
                        ":"
                        + package_issue.get("affected_location", {}).get("package", "")
                    )
                    in v
                ) and full_pkg != k:
                    dealias_dict[full_pkg] = k
                    break
    return dealias_dict


def dedup(project_type, pkg_list):
    """Method to trim duplicates in the results based on the id. The logic
    should ideally be based on package alias but is kept simple for now.

    :param project_type: Project type
    :param pkg_list: List of packages to dedup
    :return: List of packages with duplicates removed
    """
    dedup_dict = {}
    ret_list = []
    for res in pkg_list:
        vid = res.get("cve_id") or res.get("id") or ""
        package_issue = res.get("package_issue") or {}
        # fix_version is available in vdb >= 6.4.0
        fixed_location = res.get("fix_version") or package_issue.get("fixed_issue")
        version = None
        matched_by = res.get("matched_by")
        if matched_by:
            version = matched_by
            if "|" in version:
                version = version.split("|")[-1]
            else:
                version = version.split("@")[-1]
            full_pkg = matched_by
        else:
            full_pkg = package_issue.get("affected_location", {}).get("package", "")
            if package_issue.get("affected_location", {}).get("vendor", ""):
                full_pkg = (
                    f"{package_issue.affected_location.vendor}:"
                    f"{package_issue.affected_location.package}"
                )
            if version:
                full_pkg = full_pkg + ":" + version
        full_pkg = vid + ":" + full_pkg
        # Ignore any result with the exclude fix location
        # Required for debian
        if fixed_location and fixed_location == PLACEHOLDER_EXCLUDE_VERSION:
            dedup_dict[full_pkg] = True
            continue
        if full_pkg not in dedup_dict:
            ret_list.append(res)
            dedup_dict[full_pkg] = True
    return ret_list
