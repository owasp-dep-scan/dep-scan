import ast
import contextlib
import encodings.utf_8
import json
import os
import re
import shutil
from collections import defaultdict
from datetime import datetime
from typing import List, Dict, Any, Tuple

import semver
from jinja2 import Environment
from packageurl import PackageURL
from vdb.lib.cve_model import Description, Descriptions
from vdb.lib.search import search_by_purl_like
from vdb.lib.utils import version_compare

from depscan.lib import config, normalize
from depscan.lib.config import TIME_FMT


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
        if d.lower() in config.ignore_directories or d.startswith(".")
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
        for name in req_files:
            if name in files:
                result.append(os.path.join(root, name))
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
    textchars = bytearray(
        {7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7F}
    )
    return bool(content.translate(None, textchars))


def is_exe(src):
    """
    Detect if the source is a binary file

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


def get_pkg_vendor_name(pkg):
    """
    Method to extract vendor and name information from package. If vendor
    information is not available package url is used to extract the package
    registry provider such as pypi, maven

    :param pkg: a dictionary representing a package
    :return: vendor and name as a tuple
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


def search_pkgs(project_type: str | None, pkg_list: List[Dict[str, Any]]):
    """
    Method to search packages in our vulnerability database

    :param db: DB instance
    :param project_type: Project type
    :param pkg_list: List of packages to search
    :returns: raw_results, pkg_aliases, purl_aliases
    """
    expanded_list = []
    # The challenge we have is to broaden our search and create several
    # variations of the package and vendor names to perform a broad search.
    # We then have to map the results back to the original package names and
    # package urls.
    pkg_aliases = defaultdict(list)
    purl_aliases = {}
    for pkg in pkg_list:
        variations = normalize.create_pkg_variations(pkg)
        if variations:
            expanded_list += variations
        vendor, name = get_pkg_vendor_name(pkg)
        version = pkg.get("version")
        if pkg.get("purl"):
            ppurl = pkg.get("purl")
            purl_aliases[pkg.get("purl")] = pkg.get("purl")
            purl_aliases[f"{vendor.lower()}:{name.lower()}:{version}"] = ppurl
            if ppurl.startswith("pkg:npm"):
                purl_aliases[f"npm:{vendor.lower()}/{name.lower()}:{version}"] = ppurl
            if not purl_aliases.get(f"{vendor.lower()}:{name.lower()}"):
                purl_aliases[f"{vendor.lower()}:{name.lower()}"] = ppurl
        if variations:
            for vari in variations:
                vari_full_pkg = f"""{vari.get("vendor")}:{vari.get("name")}"""
                pkg_aliases[
                    f"{vendor.lower()}:{name.lower()}:{version}"
                ].append(vari_full_pkg)
                if pkg.get("purl"):
                    purl_aliases[f"{vari_full_pkg.lower()}:{version}"] = pkg.get("purl")
    raw_results = []
    for i in expanded_list:
        search_term = i.get("purl") or i.get("name")
        if res := search_by_purl_like(search_term, with_data=True):
            raw_results.extend(res)
    raw_results = normalize.dedup(project_type, raw_results)
    pkg_aliases = normalize.dealias_packages(
        raw_results,
        pkg_aliases=pkg_aliases,
        purl_aliases=purl_aliases,
    )
    return raw_results, pkg_aliases, purl_aliases


def get_pkgs_by_scope(pkg_list):
    """
    Method to return the packages by scope as defined in CycloneDX spec -
    required, optional and excluded

    :param pkg_list: List of packages
    :return: Dictionary of packages categorized by scope if available. Empty if
                no scope information is available
    """
    scoped_pkgs = {}
    for pkg in pkg_list:
        if pkg.get("scope"):
            vendor, name = get_pkg_vendor_name(pkg)
            scope = pkg.get("scope").lower()
            if pkg.get("purl"):
                scoped_pkgs.setdefault(scope, []).append(pkg.get("purl"))
            else:
                scoped_pkgs.setdefault(scope, []).append(f"{vendor}:{name}")
    return scoped_pkgs


def get_scope_from_imports(project_type, pkg_list, all_imports):
    """
    Method to compute the packages scope defined in CycloneDX spec - required,
    optional and excluded

    :param project_type: Project type
    :param pkg_list: List of packages
    :param all_imports: List of imports detected
    :return: Dictionary of packages categorized by scope if available. Empty if
                no scope information is available
    """
    scoped_pkgs = {}
    if not pkg_list or not all_imports:
        return scoped_pkgs
    for pkg in pkg_list:
        scope = "optional"
        vendor, name = get_pkg_vendor_name(pkg)
        if name in all_imports or name.lower().replace("py", "") in all_imports:
            scope = "required"
        if pkg.get("purl"):
            scoped_pkgs.setdefault(scope, []).append(pkg.get("purl"))
        else:
            scoped_pkgs.setdefault(scope, []).append(f"{vendor}:{name}")
        scoped_pkgs[scope].append(f"{project_type}:{name.lower()}")
    return scoped_pkgs


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


def max_version(version_list):
    """
    Method to return the highest version from the list

    :param version_list: single version string or set of versions
    :return: max version
    """
    if isinstance(version_list, str):
        return version_list
    if isinstance(version_list, set):
        version_list = list(version_list)
    if len(version_list) == 1:
        return version_list[0]
    min_ver = "0"
    max_ver = version_list[0]
    for i, vl in enumerate(version_list):
        if not vl:
            continue
        if not version_compare(vl, min_ver, max_ver):
            max_ver = vl
    return max_ver


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
        with open(os.path.join(afile), "rb", encoding="utf-8") as f:
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


def export_pdf(
    html_file,
    pdf_file,
    title="DepScan Analysis",
    footer=f'Report generated by OWASP dep-scan at {datetime.now().strftime("%B %d, %Y %H:%M")}',
):
    """
    Method to export html as pdf using pdfkit
    """
    pdf_options = {
        "page-size": "A2",
        "margin-top": "0.5in",
        "margin-right": "0.25in",
        "margin-bottom": "0.5in",
        "margin-left": "0.25in",
        "encoding": "UTF-8",
        "outline": None,
        "title": title,
        "footer-right": footer,
        "minimum-font-size": "12",
        "disable-smart-shrinking": "",
    }
    if shutil.which("wkhtmltopdf"):
        try:
            import pdfkit

            if not pdf_file and html_file:
                pdf_file = html_file.replace(".html", ".pdf")
            if os.path.exists(html_file):
                pdfkit.from_file(html_file, pdf_file, options=pdf_options)
        except Exception:
            pass


def render_template_report(
    vdr_file,
    bom_file,
    pkg_vulnerabilities,
    pkg_group_rows,
    summary,
    template_file,
    result_file,
):
    """
    Render the given vdr_file (falling back to bom_file if no vdr was written)
    and summary dict using the template_file with Jinja, rendered output is written
    to named result_file in reports directory.
    """
    if vdr_file and os.path.isfile(vdr_file):
        with open(vdr_file, "r", encoding="utf-8") as f:
            bom = json.load(f)
    else:
        with open(bom_file, "r", encoding="utf-8") as f:
            bom = json.load(f)
    with open(template_file, "r", encoding="utf-8") as tmpl_file:
        template = tmpl_file.read()
    jinja_env = Environment(autoescape=False)
    jinja_tmpl = jinja_env.from_string(template)
    report_result = jinja_tmpl.render(
        metadata=bom.get("metadata", None),
        vulnerabilities=bom.get("vulnerabilities", None),
        components=bom.get("components", None),
        dependencies=bom.get("dependencies", None),
        services=bom.get("services", None),
        summary=summary,
        pkg_vulnerabilities=pkg_vulnerabilities,
        pkg_group_rows=pkg_group_rows,
    )
    with open(result_file, "w", encoding="utf-8") as outfile:
        outfile.write(report_result)


def format_system_name(system_name):
    system_name = (
        system_name.capitalize()
        .replace("Redhat", "Red Hat")
        .replace("Zerodayinitiative", "Zero Day Initiative")
        .replace("Github", "GitHub")
        .replace("Netapp", "NetApp")
        .replace("Npmjs", "NPM")
        .replace("Alpinelinux", "Alpine Linux")
        .replace("Fedoraproject", "Fedora Project")
        .replace("Djangoproject", "Django Project")
        .replace("Opensuse", "Open Suse")
        .replace("Securityfocus", "Security Focus"))
    return system_name


def get_description_detail(data: Description | str) -> Tuple[str, str]:
    if not data:
        return "", ""
    if isinstance(data, Descriptions) and data.root and isinstance(data.root[0], Description):
        data = data.root[0].value
    description = ""
    detail = data or ""
    if detail and "\\n" in detail:
        description = detail.split("\\n")[0]
    elif "." in detail:
        description = detail.split(".")[0]
    detail = detail.replace("\\n", " ").replace("\\t", " ").replace("\\r", " ").replace("\n", " ").replace("\t", " ").replace("\r", " ")
    detail = bytes.decode(encodings.utf_8.encode(detail)[0], errors="replace")
    description = description.lstrip("# ")
    return description, detail


def choose_date(d1, d2, choice):
    if not d1 or not d2 or choice not in {"max", "min"}:
        return d1 or d2
    try:
        d1 = datetime.fromisoformat(d1)
        d2 = datetime.fromisoformat(d2)
        d3 = max(d1, d2) if choice == "max" else min(d1, d2)
        return d3.strftime(TIME_FMT)
    except ValueError:
        return d1 or d2
    except TypeError:
        d3 = max(d1.date(), d2.date()) if choice == "max" else min(d1.date(), d2.date())
        return d3.strftime(TIME_FMT)


def combine_advisories(v1, v2):
    if not v1 or not v2:
        return v1 or v2
    seen_adv = set()
    v3 = []
    for i in v1 + v2:
        url = i.get("url", "")
        if url not in seen_adv:
            v3.append(i)
            seen_adv.add(url)
    return v3


def combine_affects(v1, v2):
    affects = {}
    seen_refs = set()
    if not v1 or not v2:
        return v1 or v2
    v1.extend(v2)
    for i in v1:
        ref = i.get("ref", "")
        for vers in i.get("versions", []):
            version = vers.get("version", "") or vers.get("range", "")
            status = vers.get("status", "")
            vers_ref = f"{ref}/{version}/{status}"
            if vers_ref not in seen_refs:
                if ref in affects:
                    affects[ref]["versions"].append(vers)
                else:
                    affects[ref] = {"ref": ref, "versions": [vers]}
                seen_refs.add(vers_ref)
    return list(affects.values())


def combine_generic(v1, v2, keys):
    """Combines two lists of flat dicts"""
    if not v1 or not v2:
        return v1 or v2
    seen_keys = set()
    v3 = []
    for i in v1 + v2:
        seen_id = "".join([str(i.get(k, '')) for k in keys])
        if seen_id not in seen_keys:
            v3.append(i)
            seen_keys.add(seen_id)
    return v3


def combine_references(v1, v2):
    if not v1 or not v2:
        return v1 or v2
    seen_urls = set()
    v3 = []
    for i in v1 + v2:
        url = i.get("url", "")
        if url not in seen_urls:
            v3.append(i)
            seen_urls.add(url)
    return v3


def combine_vdrs(v1, v2):
    return {
        "advisories": combine_advisories(v1.get("advisories", []), v2.get("advisories", [])),
        "affects": combine_affects(v1.get("affects", []), v2.get("affects", [])),
        "analysis": v1.get("analysis", "") or v2.get("analysis", ""),
        "bom-ref": v1.get("bom-ref"),
        "cwes": list(set(v1["cwes"] + v2["cwes"])),
        "detail": v1.get("detail", "") or v2.get("detail", ""),
        "description": v1.get("description", "") or v2.get("description", ""),
        "id": v1.get("id"),
        "properties": combine_generic(v1.get("properties", []), v2.get("properties", []), ["name", "value"]),
        "published": choose_date(v1.get("published"), v2.get("published"), "min"),
        "ratings": combine_generic(v1.get("ratings", []), v2.get("ratings", []), ["method", "score", "severity", "vector"]),
        "recommendation": v1.get("recommendation", "") or v2.get("recommendation", ""),
        "references": combine_references(v1.get("references", []), v2.get("references", [])),
        "source": v1.get("source", "") or v2.get("source", ""),
        "updated": choose_date(v1.get("updated"), v2.get("updated"), "max"),
        "p_rich_tree": v1.get("p_rich_tree") or v2.get("p_rich_tree"),
        "insights": v1.get("insights") or v2.get("insights"),
        "purl_prefix": v1.get("purl_prefix") or v2.get("purl_prefix"),
        "fixed_location": v1.get("fixed_location") or v2.get("fixed_location")
    }


def get_suggested_version_map(pkg_vulnerabilities: List[Dict]):
    suggested_version_map = {}
    for i, v in enumerate(pkg_vulnerabilities):
        purl = v.get("bom-ref", "").replace(f"{v.get('id')}/", "")
        if not (purl_prefix := v.get("purl_prefix")):
            purl_prefix = purl
            if "@" in purl_prefix:
                purl_prefix = purl_prefix.split("@", 1)[0]
        pkg_vulnerabilities[i]["purl_prefix"] = purl_prefix
        if v.get("recommendation"):
            for a in v.get("affects"):
                for j in a.get("versions"):
                    if j.get("status") == "unaffected":
                        # if purl in version_map:
                        #     version_map[purl] = max_version([version_map[purl], j.get("version")])
                        # else:
                        #     version_map[purl] = j.get("version")
                        if purl_prefix in suggested_version_map:
                            suggested_version_map[purl_prefix] = max_version([suggested_version_map[purl_prefix], j.get("version")])
                        else:
                            suggested_version_map[purl_prefix] = j.get("version")
    return suggested_version_map, pkg_vulnerabilities


def make_version_suggestions(vdrs):
    suggested_version_map, vdrs = get_suggested_version_map(vdrs)
    for i, v in enumerate(vdrs):
        if suggested_version := suggested_version_map.get(v["purl_prefix"]):
            if old_rec := v.get("recommendation"):
                vdrs[i]["fixed_location"] = suggested_version
                if suggested_version not in old_rec:
                    old_rec = old_rec.replace("Update to version ", "").rstrip(".")
                    vdrs[i]["recommendation"] = (f"Update to version {old_rec} to resolve "
                                                 f"{v['id']} or update to version "
                                                 f"{suggested_version} to resolve additional "
                                                 f"vulnerabilities for this package.")
            else:
                vdrs[i]["recommendation"] = (f"No recommendation found for {v['id']}. Updating to "
                                             f"version {suggested_version} is recommended "
                                             f"nonetheless in order to address additional "
                                             f"vulnerabilities identified for this package.")
    return vdrs


def make_purl(purl):
    try:
        return PackageURL.from_string(purl)
    except ValueError:
        return ""
