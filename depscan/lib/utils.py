import os
import re

from vdb.lib import db as dbLib
from vdb.lib.utils import version_compare

from depscan.lib import config as config
from depscan.lib import normalize as normalize

lic_symbol_regex = re.compile(r"[\(\)\,]")


def filter_ignored_dirs(dirs):
    """
    Method to filter directory list to remove ignored directories
    :param dirs: Directories to ignore
    :return: Filtered directory list
    """
    [
        dirs.remove(d)
        for d in list(dirs)
        if d.lower() in config.ignore_directories or d.startswith(".")
    ]
    return dirs


def find_python_reqfiles(path):
    """
    Method to find python requirements files

    Args:
      path Project dir
    Returns:
      List of python requirement files
    """
    result = []
    req_files = [
        "requirements.txt",
        "Pipfile",
        "poetry.lock",
        "Pipfile.lock",
        "conda.yml",
    ]
    for root, dirs, files in os.walk(path):
        filter_ignored_dirs(dirs)
        for name in req_files:
            if name in files:
                result.append(os.path.join(root, name))
    return result


def find_files(src, src_ext_name, quick=False):
    """
    Method to find files with given extenstion
    """
    result = []
    for root, dirs, files in os.walk(src):
        filter_ignored_dirs(dirs)
        for file in files:
            if file == src_ext_name or file.endswith(src_ext_name):
                result.append(os.path.join(root, file))
                if quick:
                    return result
    return result


def detect_project_type(src_dir):
    """Detect project type by looking for certain files

    :param src_dir: Source directory

    :return List of detected types
    """
    project_types = []
    if find_python_reqfiles(src_dir):
        project_types.append("python")
    if find_files(src_dir, "pom.xml", quick=True) or find_files(
        src_dir, ".gradle", quick=True
    ):
        project_types.append("java")
    if find_files(src_dir, ".gradle.kts", quick=True):
        project_types.append("kotlin")
    if find_files(src_dir, "build.sbt", quick=True):
        project_types.append("scala")
    if (
        find_files(src_dir, "package.json", quick=True)
        or find_files(src_dir, "yarn.lock", quick=True)
        or find_files(src_dir, "rush.json", quick=True)
    ):
        project_types.append("nodejs")
    if find_files(src_dir, "go.sum", quick=True) or find_files(
        src_dir, "Gopkg.lock", quick=True
    ):
        project_types.append("go")
    if find_files(src_dir, "Cargo.lock", quick=True):
        project_types.append("rust")
    if find_files(src_dir, "composer.json", quick=True):
        project_types.append("php")
    if find_files(src_dir, ".csproj", quick=True):
        project_types.append("dotnet")
    if find_files(src_dir, "Gemfile", quick=True) or find_files(
        src_dir, "Gemfile.lock", quick=True
    ):
        project_types.append("ruby")
    return project_types


def get_pkg_vendor_name(pkg):
    """
    Method to extract vendor and name information from package. If vendor information is not available
    package url is used to extract the package registry provider such as pypi, maven
    """
    vendor = pkg.get("vendor")
    if not vendor:
        purl = pkg.get("purl")
        if purl:
            purl_parts = purl.split("/")
            if purl_parts:
                vendor = purl_parts[0].replace("pkg:", "")
        else:
            vendor = ""
    name = pkg.get("name")
    return vendor, name


def search_pkgs(db, project_type, pkg_list):
    """
    Method to search packages in our vulnerability database

    :param db: DB instance
    :param project_type: Project type
    :param pkg_list: List of packages to search
    """
    expanded_list = []
    pkg_aliases = {}
    for pkg in pkg_list:
        variations = normalize.create_pkg_variations(pkg)
        expanded_list += variations
        vendor, name = get_pkg_vendor_name(pkg)
        # TODO: Use purl here
        pkg_aliases[vendor + ":" + name] = [
            "{}:{}".format(vari.get("vendor"), vari.get("name")) for vari in variations
        ]
    quick_res = dbLib.bulk_index_search(expanded_list)
    raw_results = dbLib.pkg_bulk_search(db, quick_res)
    raw_results = normalize.dedup(project_type, raw_results, pkg_aliases=pkg_aliases)
    pkg_aliases = normalize.dealias_packages(
        project_type, raw_results, pkg_aliases=pkg_aliases
    )
    return raw_results, pkg_aliases


def get_pkgs_by_scope(pkg_list):
    """
    Method to return the packages by scope as defined in CycloneDX spec - required, optional and excluded

    :param pkg_list: List of packages
    :return: Dictionary of packages categorized by scope if available. Empty if no scope information is available
    """
    scoped_pkgs = {}
    for pkg in pkg_list:
        if pkg.get("scope"):
            vendor, name = get_pkg_vendor_name(pkg)
            scope = pkg.get("scope").lower()
            # TODO: Use purl here
            scoped_pkgs.setdefault(scope, []).append(f"{vendor}:{name}")
    return scoped_pkgs


def cleanup_license_string(license_str):
    """
    Method to cleanup license string by removing problematic symbols and making certain keywords consistent
    :param license_str: String to clean up
    :return: Cleaned up version
    """
    if not license_str:
        license_str = ""
    license_str = (
        license_str.replace(" / ", " OR ")
        .replace("/", " OR ")
        .replace(" & ", " OR ")
        .replace("&", " OR ")
    )
    license_str = lic_symbol_regex.sub("", license_str)
    return license_str.upper()


def max_version(version_list):
    """Method to return the highest version from the list"""
    if isinstance(version_list, str):
        return version_list
    if isinstance(version_list, set):
        version_list = list(version_list)
    if len(version_list) == 1:
        return version_list[0]
    min_ver = "0"
    max_ver = version_list[0]
    for i in range(len(version_list)):
        if not version_list[i]:
            continue
        if not version_compare(version_list[i], min_ver, max_ver):
            max_ver = version_list[i]
    return max_ver
