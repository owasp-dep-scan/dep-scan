import ast
import os
import re

from custom_json_diff.lib.utils import file_read, file_write, json_load
from jinja2 import Environment

from depscan.lib.config import ignore_directories
from depscan.lib.logger import LOG

LIC_SYMBOL_REGEX = re.compile(r"[(),]")


def filter_ignored_dirs(dirs):
    """
    Method to filter directory list to remove ignored directories

    :param dirs: Directories to ignore
    :return: Filtered directory list
    """
    [
        dirs.remove(d)
        for d in list(dirs)
        if d.lower() in ignore_directories or d.startswith(".")
    ]
    return dirs


def find_python_reqfiles(path):
    """
    Method to find python requirements files

    :param path: Project directory
    :return: List of python requirement files
    """
    result = []
    req_files = [
        "requirements.txt",
        "Pipfile",
        "poetry.lock",
        "Pipfile.lock",
        "conda.yml",
        "pyproject.toml",
    ]
    for root, dirs, files in os.walk(path):
        filter_ignored_dirs(dirs)
        result.extend(os.path.join(root, name) for name in req_files if name in files)
    return result


def find_files(src, src_ext_name, quick=False, filter_dirs=True):
    """
    Method to find files with given extension

    :param src: source directory to search
    :param src_ext_name: type of source file
    :param quick: only return first match found
    :param filter_dirs: filter out ignored directories
    """
    result = []
    for root, dirs, files in os.walk(src):
        if filter_dirs:
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
    """
    Detect if the source is a binary file

    :param src: Source path
    :return: True if binary file. False otherwise.
    """
    if os.path.isfile(src):
        try:
            with open(src, "rb") as f:
                return is_binary_string(f.read(1024))
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
    if find_python_reqfiles(src_dir) or find_files(src_dir, ".py", quick=True):
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
        os.path.join(src_dir, ".github", "workflows"),
        ".yml",
        quick=True,
        filter_dirs=False,
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


def cleanup_license_string(license_str):
    """
    Method to clean up license string by removing problematic symbols and
    making certain keywords consistent

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
    license_str = LIC_SYMBOL_REGEX.sub("", license_str)
    return license_str.upper()


def get_all_imports(src_dir):
    """
    Method to collect all package imports from a python file
    No longer required since cdxgen does python analysis already
    """
    import_list = set()
    py_files = find_files(src_dir, ".py")
    if not py_files:
        return import_list
    for afile in py_files:
        parsed = ast.parse(file_read(os.path.join(afile), True, log=LOG))
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


def render_template_report(
    vdr_file,
    bom_file,
    pkg_vulnerabilities,
    pkg_group_rows,
    summary,
    template_file,
    result_file,
    depscan_options={},
):
    """
    Render the given vdr_file (falling back to bom_file if no vdr was written)
    and summary dict using the template_file with Jinja, rendered output is written
    to named result_file in reports directory.
    """
    bom = {}
    if vdr_file:
        bom = json_load(vdr_file, log=LOG)
    if not bom:
        bom = json_load(bom_file, log=LOG)
    template = file_read(template_file, log=LOG)
    jinja_env = Environment(autoescape=True)
    jinja_tmpl = jinja_env.from_string(template)
    report_result = jinja_tmpl.render(
        metadata=bom.get("metadata"),
        vulnerabilities=bom.get("vulnerabilities"),
        components=bom.get("components"),
        dependencies=bom.get("dependencies"),
        services=bom.get("services"),
        summary=summary,
        pkg_vulnerabilities=pkg_vulnerabilities,
        pkg_group_rows=pkg_group_rows,
    )
    file_write(
        result_file,
        report_result,
        error_msg=f"Failed to export report: {result_file}",
        success_msg=f"Report written to {result_file}.",
        log=LOG,
    )
