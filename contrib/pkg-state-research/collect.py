import argparse
import csv
import logging
import re

from rich.progress import Progress

from vdb.lib.search import search_by_purl_like

from depscan.lib.logger import LOG, console
from depscan.lib.package_query.metadata import metadata_from_registry
from depscan.lib.package_query.npm_pkg import search_npm

for log_name, log_obj in logging.Logger.manager.loggerDict.items():
    if log_name != __name__:
        log_obj.disabled = True


def build_args():
    """
    Constructs command line arguments
    """
    parser = argparse.ArgumentParser(
        description="Collect popular packages from registries for analysis."
    )
    parser.add_argument(
        "--keywords",
        dest="keywords",
        default="framework,library,cloud,crypto,react",
        help="Comma separated list of keywords to search.",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        dest="insecure_only",
        default=False,
        help="Top insecure packages only.",
    )
    parser.add_argument(
        "--unstable",
        action="store_true",
        dest="unstable_only",
        default=False,
        help="Top unstable packages only.",
    )
    parser.add_argument(
        "-o",
        "--output-file",
        dest="output_file",
        default="report.csv",
        help="Output CSV file.",
    )
    parser.add_argument(
        "--pages",
        type=int,
        dest="pages",
        default=5,
        help="Page count.",
    )
    return parser.parse_args()


def analyze_with_npm(keywords, insecure_only, unstable_only, pages, output_file):
    pkg_list = search_npm(keywords=keywords, insecure_only=insecure_only, unstable_only=unstable_only, pages=pages)
    analyze_pkgs(output_file, pkg_list, insecure_only)


def analyze_pkgs(output_file, pkg_list, insecure_only):
    if not pkg_list:
        LOG.info("No results found!")
        return
    console.print("About to check", len(pkg_list), "packages for vulnerabilities.")
    with open(output_file, "w", encoding="utf-8", newline="") as csvfile:
        rwriter = csv.writer(
            csvfile,
            delimiter=",",
            quotechar="|",
            quoting=csv.QUOTE_MINIMAL,
            escapechar="\\",
        )
        rwriter.writerow(
            [
                "purl",
                "url",
                "commit_sha",
                "is_insecure",
                "has_insecure_dependencies",
                "is_unstable",
                "git_head",
                "dependencies_vulnerabilities_count",
                "dev_dependencies_vulnerabilities_count"
            ]
        )
        with Progress(
            console=console,
            transient=True,
            redirect_stderr=False,
            redirect_stdout=False,
            refresh_per_second=1,
        ) as progress:
            task = progress.add_task(
                "[green] Searching for packages",
                total=len(pkg_list),
            )
            for pkg in pkg_list:
                purl = pkg.get("purl")
                progress.update(
                    task,
                    description=f"Checking the package {purl}",
                )
                metadata_dict = metadata_from_registry("npm", {}, [pkg], None)
                version = pkg.get("version")
                is_insecure = pkg.get("insecure")
                has_insecure_dependencies = pkg.get("has_insecure_dependencies")
                is_unstable = pkg.get("unstable")
                deps_vulnerabilities_count = 0
                dev_deps_vulnerabilities_count = 0
                if insecure_only and not has_insecure_dependencies:
                    progress.advance(task)
                    continue
                for name, value in metadata_dict.items():
                    pkg_metadata = value.get("pkg_metadata")
                    the_version = pkg_metadata.get("versions", {}).get(version)
                    # This is an edge case where there could be a version the registry doesn't know about
                    if not the_version:
                        continue
                    version_deps = the_version.get("dependencies", {})
                    version_dev_deps = the_version.get("devDependencies", {})
                    the_version_git_head = the_version.get("gitHead")
                    version_repository = the_version.get("repository", {})
                    for k, v in version_deps.items():
                        progress.update(
                            task,
                            description=f"Checking the dependency `{k}` for vulnerabilities",
                        )
                        if res := search_by_purl_like(f'pkg:npm/{k.replace("@", "%40")}@{re.sub("[<>=^~]", "", v)}', with_data=False):
                            deps_vulnerabilities_count += len(res)
                    for k, v in version_dev_deps.items():
                        if k.startswith("@types/"):
                            continue
                        progress.update(
                            task,
                            description=f"Checking the dev dependency `{k}` for vulnerabilities",
                        )
                        if res := search_by_purl_like(f'pkg:npm/{k.replace("@", "%40")}@{re.sub("[<>=^~]", "", v)}', with_data=False):
                            dev_deps_vulnerabilities_count += len(res)
                    rwriter.writerow(
                        [
                            purl,
                            version_repository.get("url", "") if isinstance(version_repository, dict) else str(version_repository).strip(),
                            the_version_git_head,
                            is_insecure,
                            has_insecure_dependencies,
                            is_unstable,
                            the_version_git_head,
                            deps_vulnerabilities_count,
                            dev_deps_vulnerabilities_count
                        ]
                    )
                progress.advance(task)


def main():
    args = build_args()
    keywords = args.keywords.split(",")
    analyze_with_npm(keywords, args.insecure_only, args.unstable_only, args.pages, args.output_file)


if __name__ == "__main__":
    main()
