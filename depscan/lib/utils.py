import os
import re

from vdb.lib import db as dbLib

from depscan.lib import config as config

lic_symbol_regex = re.compile(r"[\(\)\,]")


def filter_ignored_dirs(dirs):
    """
    Method to filter directory list to remove ignored directories
    :param dirs: Directories to ignore
    :return: Filtered directory list
    """
    [dirs.remove(d) for d in list(dirs) if d.lower() in config.ignore_directories]
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
    return project_types


def search_pkgs(db, pkg_list):
    """
    Method to search packages in our vulnerability database

    :param db: DB instance
    :param pkg_list: List of packages to search
    """
    quick_res = dbLib.bulk_index_search(pkg_list)
    return dbLib.pkg_bulk_search(db, quick_res)


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
