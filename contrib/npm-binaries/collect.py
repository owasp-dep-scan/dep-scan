import argparse
import csv
import logging
import os
import sys

from pybraries.search import Search
from semver import Version

from depscan.lib.logger import console
from depscan.lib.pkg_query import npm_metadata

for log_name, log_obj in logging.Logger.manager.loggerDict.items():
    if log_name != __name__:
        log_obj.disabled = True

PAGES = 21
PER_PAGE = 100

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
        choices=("npm"),
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
    return parser.parse_args()


def collect_pkgs(search_result):
    for res in search_result:
        pkg_name = res.get("name")
        versions = [v.get("number") for v in res.get("versions")]
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


def analyze_pkgs():
    pkg_list = []
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
    metadata_dict = npm_metadata({}, pkg_list, None)
    for name, value in metadata_dict.items():
        risk_metrics = value.get("risk_metrics")
        purl = value.get("purl")
        if risk_metrics and risk_metrics.get("pkg_includes_binary_risk"):
            risk_metrics["rank"] = pkg_rank.get(name)
            risk_metrics["stars"] = pkg_stars.get(name)
            risk_metrics["dependents_count"] = pkg_dependents_count.get(name)
            risky_binary_pkgs[purl] = risk_metrics


def export_risky_pkgs(output_file):
    if risky_binary_pkgs:
        with open(output_file, "w", encoding="utf-8", newline="") as csvfile:
            rwriter = csv.writer(
                csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_NONE, escapechar='\\'
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
                    "dependents_count"
                ]
            )
            for purl, metrics in risky_binary_pkgs.items():
                rwriter.writerow(
                    [
                        purl,
                        metrics.get("risk_score"),
                        metrics.get("pkg_includes_binary_risk"),
                        metrics.get("pkg_includes_binary_info"),
                        metrics.get("pkg_attested_check"),
                        metrics.get("pkg_deprecated_risk"),
                        metrics.get("pkg_version_deprecated_risk"),
                        metrics.get("pkg_version_missing_risk"),
                        metrics.get("rank"),
                        metrics.get("stars"),
                        metrics.get("dependents_count"),
                    ]
                )
        console.print("Report", output_file, "created successfully")
    else:
        console.print(
            "No risks identified. Try searching with a different keyword or increasing the page count"
        )


def main():
    if not os.getenv("LIBRARIES_API_KEY"):
        print(
            "Set the environment variable LIBRARIES_API_KEY with a valid libraries.io API key"
        )
        sys.exit(1)
    args = build_args()
    search = Search()
    if args.popular_only:
        console.print("Searching for top", PER_PAGE * (PAGES - 1),"popular packages")
        for page in range(1, PAGES):
            search_result = search.project_search(
                keywords="",
                sort=args.sort_option,
                platforms=args.package_type,
                page=page,
                per_page=PER_PAGE,
                order="desc"
            )
            collect_pkgs(search_result)
    else:
        for keyword in args.keywords.split(","):
            console.print("Search for packages with keyword", keyword)
            for page in range(1, PAGES):
                search_result = search.project_search(
                    keywords=keyword,
                    sort=args.sort_option,
                    platforms=args.package_type,
                    page=page,
                    per_page=PER_PAGE,
                    order="desc"
                )
                collect_pkgs(search_result)
    analyze_pkgs()
    export_risky_pkgs(args.output_file)


if __name__ == "__main__":
    main()
