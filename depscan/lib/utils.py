import ast
import os
import re
from collections import defaultdict

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


def find_files(src, src_ext_name, quick=False, filter=True):
    """
    Method to find files with given extenstion
    """
    result = []
    for root, dirs, files in os.walk(src):
        if filter:
            filter_ignored_dirs(dirs)
        for file in files:
            if file == src_ext_name or file.endswith(src_ext_name):
                result.append(os.path.join(root, file))
                if quick:
                    return result
    return result


def is_binary_string(content):
    """
    Method to check if the given content is a binary string
    """
    textchars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7F})
    return bool(content.translate(None, textchars))


def is_exe(src):
    """Detect if the source is a binary file
    :param src: Source path
    :return True if binary file. False otherwise.
    """
    if os.path.isfile(src):
        try:
            return is_binary_string(open(src, "rb").read(1024))
        except Exception:
            return False
    return False


def detect_project_type(src_dir):
    """Detect project type by looking for certain files

    :param src_dir: Source directory

    :return List of detected types
    """
    # container image support
    if (
        "docker.io" in src_dir
        or "quay.io" in src_dir
        or ":latest" in src_dir
        or "@sha256" in src_dir
        or src_dir.endswith(".tar")
        or src_dir.endswith(".tar.gz")
    ):
        return ["docker"]
    # Check if the source is an exe file. Assume go for all binaries for now
    if is_exe(src_dir):
        return ["go", "binary"]
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
    if find_files(src_dir, "deps.edn", quick=True) or find_files(
        src_dir, "project.clj", quick=True
    ):
        project_types.append("clojure")
    if find_files(src_dir, "conan.lock", quick=True) or find_files(
        src_dir, "conanfile.txt", quick=True
    ):
        project_types.append("cpp")
    if find_files(src_dir, "pubspec.lock", quick=True) or find_files(
        src_dir, "pubspec.yaml", quick=True
    ):
        project_types.append("dart")
    if find_files(src_dir, "cabal.project.freeze", quick=True):
        project_types.append("haskell")
    if find_files(src_dir, "mix.lock", quick=True):
        project_types.append("elixir")
    if find_files(
        os.path.join(src_dir, ".github", "workflows"), ".yml", quick=True, filter=False
    ):
        project_types.append("github")
    # jars
    if "java" not in project_types and find_files(src_dir, ".jar", quick=True):
        project_types.append("jar")
    # Jenkins plugins or plain old jars
    if "java" not in project_types and find_files(src_dir, ".hpi", quick=True):
        project_types.append("jenkins")
    if find_files(src_dir, ".yml", quick=True) or find_files(
        src_dir, ".yaml", quick=True
    ):
        project_types.append("yaml-manifest")
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
    # The challenge we have is to broaden our search and create several variations of the package and vendor names to perform a broad search.
    # We then have to map the results back to the original package names and package urls.
    pkg_aliases = defaultdict(list)
    purl_aliases = {}
    for pkg in pkg_list:
        variations = normalize.create_pkg_variations(pkg)
        if variations:
            expanded_list += variations
        vendor, name = get_pkg_vendor_name(pkg)
        version = pkg.get("version")
        purl_aliases[f"{vendor.lower()}:{name.lower()}"] = pkg.get("purl")
        purl_aliases[f"{vendor.lower()}:{name.lower()}:{version}"] = pkg.get("purl")
        if variations:
            for vari in variations:
                vari_full_pkg = "{}:{}".format(vari.get("vendor"), vari.get("name"))
                pkg_aliases[vendor.lower() + ":" + name.lower()].append(vari_full_pkg)
                purl_aliases[f"{vari_full_pkg.lower()}"] = pkg.get("purl")
                purl_aliases[f"{vari_full_pkg.lower()}:{version}"] = pkg.get("purl")
    quick_res = dbLib.bulk_index_search(expanded_list)
    raw_results = dbLib.pkg_bulk_search(db, quick_res)
    raw_results = normalize.dedup(project_type, raw_results, pkg_aliases=pkg_aliases)
    pkg_aliases = normalize.dealias_packages(
        project_type, raw_results, pkg_aliases=pkg_aliases, purl_aliases=purl_aliases
    )
    return raw_results, pkg_aliases, purl_aliases


def get_pkgs_by_scope(project_type, pkg_list):
    """
    Method to return the packages by scope as defined in CycloneDX spec - required, optional and excluded

    :param project_type: Project type
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


def get_scope_from_imports(project_type, pkg_list, all_imports):
    """
    Method to compute the packages scope as defined in CycloneDX spec - required, optional and excluded

    :param project_type: Project type
    :param pkg_list: List of packages
    :param all_imports: List of imports detected

    :return: Dictionary of packages categorized by scope if available. Empty if no scope information is available
    """
    scoped_pkgs = {}
    if not pkg_list or not all_imports:
        return scoped_pkgs
    for pkg in pkg_list:
        scope = "optional"
        vendor, name = get_pkg_vendor_name(pkg)
        if name in all_imports or name.lower().replace("py", "") in all_imports:
            scope = "required"
        scoped_pkgs.setdefault(scope, []).append(f"{vendor}:{name}")
        scoped_pkgs[scope].append(f"{project_type}:{name.lower()}")
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


def get_all_imports(src_dir):
    """Method to collect all package imports from a python file"""
    import_list = set()
    py_files = find_files(src_dir, ".py", quick=False)
    if not py_files:
        return import_list
    for afile in py_files:
        with open(os.path.join(afile), "rb") as f:
            content = f.read()
        parsed = ast.parse(content)
        for node in ast.walk(parsed):
            if isinstance(node, ast.Import):
                for name in node.names:
                    pkg = name.name.split(".")[0]
                    import_list.add(pkg)
                    import_list.add(pkg.lower().replace("py", ""))
            elif isinstance(node, ast.ImportFrom):
                if node.level > 0:
                    continue
                if getattr(node, "module"):
                    if node.module:
                        pkg = node.module.split(".")[0]
                        import_list.add(pkg)
                        import_list.add(pkg.lower().replace("py", ""))
    return import_list
