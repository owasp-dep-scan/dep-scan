import os

import vdb.lib.db as dbLib


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
        for name in req_files:
            if name in files:
                result.append(os.path.join(root, name))
    return result


def find_files(src, src_ext_name):
    """
    Method to find files with given extenstion
    """
    result = []
    for root, dirs, files in os.walk(src):
        for file in files:
            if file == src_ext_name or file.endswith(src_ext_name):
                result.append(os.path.join(root, file))
    return result


def detect_project_type(src_dir):
    """Detect project type by looking for certain files

    :param src_dir: Source directory

    :return List of detected types
    """
    project_types = []
    if find_python_reqfiles(src_dir):
        project_types.append("python")
    if find_files(src_dir, "pom.xml") or find_files(src_dir, ".gradle"):
        project_types.append("java")
    if find_files(src_dir, "package.json"):
        project_types.append("nodejs")
    if find_files(src_dir, "go.sum") or find_files(src_dir, "Gopkg.lock"):
        project_types.append("golang")
    if find_files(src_dir, "Cargo.lock"):
        project_types.append("rust")
    if find_files(src_dir, ".csproj"):
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
