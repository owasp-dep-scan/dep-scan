import argparse
import csv
import logging
import os
import sys

from pybraries.search import Search
from rich.progress import Progress
from semver import Version

from depscan.lib.logger import console
from depscan.lib.pkg_query import npm_metadata

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


def collect_pkgs(search_result):
    if not search_result:
        return
    for res in search_result:
        pkg_name = res.get("name")
        if pkg_name.startswith("@types"):
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


def analyze_pkgs(output_file):
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
    metadata_dict = npm_metadata({}, pkg_list, None)
    if metadata_dict:
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
                ]
            )
            for name, value in metadata_dict.items():
                risk_metrics = value.get("risk_metrics")
                purl = value.get("purl")
                if risk_metrics and risk_metrics.get("pkg_includes_binary_risk"):
                    risk_metrics["rank"] = pkg_rank.get(name)
                    risk_metrics["stars"] = pkg_stars.get(name)
                    risk_metrics["dependents_count"] = pkg_dependents_count.get(name)
                    rwriter.writerow(
                        [
                            purl,
                            risk_metrics.get("risk_score"),
                            risk_metrics.get("pkg_includes_binary_risk"),
                            risk_metrics.get("pkg_includes_binary_info", "").replace("\n", "\\n"),
                            risk_metrics.get("pkg_attested_check"),
                            risk_metrics.get("pkg_deprecated_risk"),
                            risk_metrics.get("pkg_version_deprecated_risk"),
                            risk_metrics.get("pkg_version_missing_risk"),
                            risk_metrics.get("rank"),
                            risk_metrics.get("stars"),
                            risk_metrics.get("dependents_count"),
                        ]
                    )
            console.print("Report", output_file, "created successfully")
    else:
        console.print(
            "No risks identified. Try searching with a different keyword."
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
        console.print(
            "Searching for top", args.per_page * (args.pages), "popular packages"
        )
        for page in range(0, args.pages):
            search_result = search.project_search(
                keywords="",
                sort=args.sort_option,
                platforms=args.package_type,
                page=page + 1,
                per_page=args.per_page,
                order="desc",
            )
            collect_pkgs(search_result)
    else:
        keywords = args.keywords.split(",")
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
                        order="desc",
                    )
                    collect_pkgs(search_result)
                    progress.advance(task)
    analyze_pkgs(args.output_file)


if __name__ == "__main__":
    main()
