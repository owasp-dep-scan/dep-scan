import argparse
import csv
import logging
import os

from rich.progress import Progress
from semver import Version

from depscan.lib.logger import LOG, console
from depscan.lib.package_query import metadata_from_registry
from depscan.lib.package_query import search_npm, get_npm_download_stats

for log_name, log_obj in logging.Logger.manager.loggerDict.items():
    if log_name != __name__:
        log_obj.disabled = True

pkg_versions = {}
pkg_rank = {}
pkg_stars = {}
pkg_dependents_count = {}
risky_binary_pkgs = {}


def build_args():
    """
    Constructs command line arguments
    """
    parser = argparse.ArgumentParser(
        description="Collect npm packages for given search strings."
    )
    parser.add_argument(
        "--keywords",
        dest="keywords",
        default="binary,prebuilt",
        help="Comma separated list of keywords to search.",
    )
    parser.add_argument(
        "-s",
        "--sort",
        dest="sort_option",
        default="rank",
        choices=(
            "rank",
            "stars",
            "dependents_count",
            "dependent_repos_count",
            "contributions_count",
        ),
        help="Sort options.",
    )
    parser.add_argument(
        "-t",
        "--type",
        dest="package_type",
        default="npm",
        choices=("npm",),
        help="Package type.",
    )
    parser.add_argument(
        "-o",
        "--output-file",
        dest="output_file",
        default="report.csv",
        help="Output CSV file.",
    )
    parser.add_argument(
        "--popular",
        action="store_true",
        dest="popular_only",
        default=False,
        help="Top popular packages.",
    )
    parser.add_argument(
        "--pages",
        type=int,
        dest="pages",
        default=20,
        help="Page count.",
    )
    parser.add_argument(
        "--per-page",
        type=int,
        dest="per_page",
        default=100,
        help="Page count.",
    )
    return parser.parse_args()


def analyze_with_npm(keywords, pages, output_file):
    pkg_list = search_npm(keywords, pages)
    analyze_pkgs(output_file, pkg_list)


def collect_pkgs(search_result):
    if not search_result:
        return
    for res in search_result:
        pkg_name = res.get("name")
        if pkg_name.startswith("@types") or pkg_versions.get(pkg_name):
            continue
        versions = [v.get("number") for v in res.get("versions")]
        if not versions:
            continue
        try:
            versions.sort(
                key=lambda x: Version.parse(x, optional_minor_and_patch=True),
                reverse=True,
            )
        except ValueError:
            pass
        pkg_versions[pkg_name] = versions
        pkg_rank[pkg_name] = res.get("rank")
        pkg_stars[pkg_name] = res.get("stars")
        pkg_dependents_count[pkg_name] = res.get("dependents_count")
    LOG.debug(len(search_result), "processed successfully.")


def analyze_pkgs(output_file, pkg_list=None):
    risky_pkg_found = False
    if not pkg_list:
        pkg_list = []
        if not pkg_versions:
            return
        for name, versions in pkg_versions.items():
            version = versions[0]
            pkg_list.append(
                {
                    "name": name,
                    "version": version,
                    "purl": f"pkg:npm/{name.replace('@', '%40')}@{version}",
                }
            )
    console.print("About to check", len(pkg_list), "packages for binaries.")
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
                "risk_score",
                "pkg_includes_binary_risk",
                "pkg_includes_binary_info",
                "pkg_attested_check",
                "pkg_deprecated_risk",
                "pkg_version_deprecated_risk",
                "pkg_version_missing_risk",
                "rank",
                "stars",
                "dependents_count",
                "yearly_downloads",
            ]
        )
        for pkg in pkg_list:
            metadata_dict = metadata_from_registry("npm", {}, [pkg], None)
            for name, value in metadata_dict.items():
                risk_metrics = value.get("risk_metrics")
                purl = value.get("purl")
                if (
                    risk_metrics
                    and risk_metrics.get("pkg_includes_binary_risk")
                    and risk_metrics.get("pkg_includes_binary_info")
                ):
                    risk_metrics["rank"] = pkg_rank.get(name)
                    risk_metrics["stars"] = pkg_stars.get(name)
                    risk_metrics["dependents_count"] = pkg_dependents_count.get(
                        name
                    )
                    download_stats = get_npm_download_stats(name)
                    rwriter.writerow(
                        [
                            purl,
                            risk_metrics.get("risk_score"),
                            risk_metrics.get("pkg_includes_binary_risk"),
                            risk_metrics.get(
                                "pkg_includes_binary_info", ""
                            ).replace("\n", "\\n"),
                            risk_metrics.get("pkg_attested_check"),
                            risk_metrics.get("pkg_deprecated_risk"),
                            risk_metrics.get("pkg_version_deprecated_risk"),
                            risk_metrics.get("pkg_version_missing_risk"),
                            risk_metrics.get("rank"),
                            risk_metrics.get("stars"),
                            risk_metrics.get("dependents_count"),
                            download_stats.get("downloads"),
                        ]
                    )
                    risky_pkg_found = True
                    console.print(name, "with", download_stats.get("downloads"), "downloads matched the critieria")
    if risky_pkg_found:
        console.print("Report", output_file, "created successfully")
    else:
        console.print(
            "No risks identified. Try searching with a different keyword."
        )


def main():
    popular_only = False
    if not os.getenv("LIBRARIES_API_KEY"):
        print(
            "Set the environment variable LIBRARIES_API_KEY with a valid libraries.io API key"
        )
        popular_only = True
    args = build_args()
    keywords = args.keywords.split(",")
    if not popular_only and args.popular_only:
        popular_only = True
    if popular_only:
        analyze_with_npm(keywords, args.pages, args.output_file)
    else:
        from pybraries.search import Search
        search = Search()
        with Progress(
            console=console,
            transient=True,
            redirect_stderr=False,
            redirect_stdout=False,
            refresh_per_second=1,
        ) as progress:
            task = progress.add_task(
                "[green] Searching for packages",
                total=len(keywords) * args.pages,
            )
            for keyword in keywords:
                progress.update(
                    task,
                    description=f"Search for packages with keyword `{keyword}`",
                )
                for page in range(0, args.pages):
                    search_result = search.project_search(
                        keywords=keyword,
                        sort=args.sort_option,
                        platforms=args.package_type,
                        page=page + 1,
                        per_page=args.per_page,
                    )
                    collect_pkgs(search_result)
                    progress.advance(task)
    analyze_pkgs(args.output_file)


if __name__ == "__main__":
    main()
