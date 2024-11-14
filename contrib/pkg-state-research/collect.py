import argparse
import csv
import logging
import re
from collections import defaultdict
from datetime import datetime, timezone

from rich.progress import Progress
from semver import Version
from vdb.lib.cve_model import CVE
from vdb.lib.search import search_by_purl_like

from depscan.lib.analysis import cve_to_vdr
from depscan.lib.logger import LOG, console
from depscan.lib.package_query.metadata import metadata_from_registry
from depscan.lib.package_query.npm_pkg import search_npm, get_npm_download_stats

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


def get_vuln_stats(search_results, vuln_stats):
    added_row_keys = {}
    for res in search_results:
        row_key = f"""{res["matched_by"]}|{res.get("source_data_hash")}"""
        # Filter duplicate rows from getting printed
        if added_row_keys.get(row_key):
            return
        source_data: CVE = res.get("source_data")
        source, references, advisories, cwes, description, detail, rating, bounties, pocs, exploits, vendors, vendor = cve_to_vdr(source_data, res.get("cve_id"))
        severity = rating.get("severity")
        vuln_stats[severity] += 1


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
                "name",
                "version",
                "yearly_downloads_latest",
                "is_insecure",
                "has_insecure_dependencies",
                "created",
                "latest_version_time",
                "age_days",
                "package_critical",
                "package_high",
                "package_medium",
                "package_low",
                "dependencies_critical",
                "dependencies_high",
                "dependencies_medium",
                "dependencies_low"
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
                ind_versions_count = 0
                for name, value in metadata_dict.items():
                    download_stats = get_npm_download_stats(name)
                    pkg_metadata = value.get("pkg_metadata")

                    # Time related checks
                    time_info = pkg_metadata.get("time", {})
                    created = time_info.get("created", "").replace("Z", "")
                    if not created and pkg_metadata.get("ctime"):
                        created = pkg_metadata.get("ctime").replace("Z", "")
                    latest_version = pkg_metadata.get("dist-tags", {}).get("latest")
                    latest_version_time = time_info.get(latest_version, "").replace("Z", "")

                    all_versions = pkg_metadata.get("versions", {})
                    all_versions_str = list(all_versions.keys())
                    all_versions_str.sort(
                        key=lambda x: Version.parse(x, optional_minor_and_patch=True),
                        reverse=True,
                    )
                    for the_version_str in all_versions_str:
                        is_insecure = False
                        has_insecure_dependencies = False
                        package_vuln_stats = defaultdict(int)
                        deps_vuln_stats = defaultdict(int)
                        the_version = all_versions.get(the_version_str)
                        # This is an edge case where there could be a version the registry doesn't know about
                        if not the_version or ind_versions_count > 4:
                            continue
                        ind_versions_count += 1
                        progress.update(
                            task,
                            description=f"Checking the version {the_version.get("name")}@{the_version_str}",
                        )
                        if res := search_by_purl_like(f'pkg:npm/{the_version.get("name").replace("@", "%40")}@{the_version_str}', with_data=True):
                            get_vuln_stats(res, package_vuln_stats)
                        for k, v in package_vuln_stats.items():
                            if v:
                                is_insecure = True
                                break
                        if not insecure_only and is_insecure:
                            progress.advance(task)
                            continue
                        version_deps = the_version.get("dependencies", {})
                        version_dev_deps = the_version.get("devDependencies", {})
                        if time_info.get(the_version_str):
                            created = time_info.get(the_version_str)
                        for k, v in version_deps.items():
                            progress.update(
                                task,
                                description=f"Checking the dependency `{k}` for vulnerabilities",
                            )
                            if res := search_by_purl_like(f'pkg:npm/{k.replace("@", "%40")}@{re.sub("[<>=^~]", "", v)}', with_data=True):
                                get_vuln_stats(res, deps_vuln_stats)
                        for k, v in version_dev_deps.items():
                            if k.startswith("@types/"):
                                continue
                            progress.update(
                                task,
                                description=f"Checking the dev dependency `{k}` for vulnerabilities",
                            )
                            if res := search_by_purl_like(f'pkg:npm/{k.replace("@", "%40")}@{re.sub("[<>=^~]", "", v)}', with_data=True):
                                get_vuln_stats(res, deps_vuln_stats)
                        for k, v in deps_vuln_stats.items():
                            if v:
                                has_insecure_dependencies = True
                                break
                        if insecure_only and not has_insecure_dependencies:
                            progress.advance(task)
                            continue
                        created_dt = datetime.fromisoformat(created).replace(tzinfo=timezone.utc)
                        created_now_diff = datetime.now().replace(tzinfo=timezone.utc) - created_dt
                        rwriter.writerow(
                            [
                                name,
                                the_version_str,
                                download_stats.get("downloads") if the_version_str == latest_version else None,
                                is_insecure,
                                has_insecure_dependencies,
                                created,
                                latest_version_time,
                                created_now_diff.days,
                                package_vuln_stats.get("critical", 0),
                                package_vuln_stats.get("high", 0),
                                package_vuln_stats.get("medium", 0),
                                package_vuln_stats.get("low", 0),
                                deps_vuln_stats.get("critical", 0),
                                deps_vuln_stats.get("high", 0),
                                deps_vuln_stats.get("medium", 0),
                                deps_vuln_stats.get("low", 0)
                            ]
                        )
                progress.advance(task)


def main():
    args = build_args()
    keywords = args.keywords.split(",") if args.keywords else None
    analyze_with_npm(keywords, args.insecure_only, args.unstable_only, args.pages, args.output_file)


if __name__ == "__main__":
    main()
