import argparse
import csv
import json
import logging
import os
import re

from custom_json_diff.lib.custom_diff import (
    compare_dicts,
    perform_bom_diff,
    report_results, perform_csaf_diff,
)
from custom_json_diff.lib.custom_diff_classes import Options

from depscan.lib.utils import get_description_detail


VERSION_REPLACE = re.compile(r"(?<=to version )\S+", re.IGNORECASE)

logging.basicConfig(level=logging.DEBUG)


def build_args(dir1, dir2,):
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--directories',
        '-d',
        default=[dir1, dir2],
        help='Directories containing the snapshots to compare',
        nargs=2
    )
    return parser.parse_args()


def compare_snapshots(options, repo):
    if not os.path.exists(options.file_1):
        return f"{options.file_1} not found.", f"{options.file_1} not found."
    if not os.path.exists(options.file_2):
        return f"{options.file_2} not found.", f"{options.file_2} not found."
    filter_normalize_jsons(options.file_1, options)
    filter_normalize_jsons(options.file_2, options)
    options.file_1 = options.file_1.replace(".json", ".parsed.json")
    options.file_2 = options.file_2.replace(".json", ".parsed.json")
    _, j1, j2 = compare_dicts(options)
    if options.preconfig_type == "bom":
        result, result_summary = perform_bom_diff(j1, j2)
    else:
        result, result_summary = perform_csaf_diff(j1, j2)
    report_results(result, result_summary, options, j1, j2)
    if result != 0:
        return f"{repo['project']} {options.preconfig_type} diff failed.", result_summary
    else:
        return f"{repo['project']} {options.preconfig_type} diff succeeded.", result_summary


def filter_normalize_jsons(filename, options):
    data = read_write_json(filename)
    data["vulnerabilities"] = filter_years(data.get("vulnerabilities", []))
    if options.preconfig_type == "bom":
        if filename == options.file_1:
            data = migrate_old_vdr_formatting(data)
        else:
            data = handle_new_recommendation_for_comparison(data)
    elif options.preconfig_type == "csaf":
        data = migrate_old_csaf_formatting(data)
    read_write_json(f"{filename.replace('.json', '.parsed.json')}", data)


def filter_years(vdrs):
    new_vdrs= []
    for i in vdrs:
        if vid := (i.get("id") or i.get("cve", "")):
            vid = vid.upper()
            # Only include CVEs from 2020 - 2023
            if vid.startswith("CVE-") and int(vid[6:8]) not in range(20, 24):
                continue
            new_vdrs.append(i)
    return new_vdrs


def get_all_purls(bom):
    bom_data = read_write_json(bom)
    components = bom_data.get("components", [])
    components.extend(bom_data.get("metadata", {}).get("tools", {}).get("components", []))
    if comp := bom_data.get("metadata", {}).get("component"):
        components.append(comp)
    return [i["purl"] for i in components if i.get("purl")]


def generate_snapshot_diffs(dir1, dir2, repo_data):
    bom_diff_options = Options(
        allow_new_versions=True,
        allow_new_data=True,
        preconfig_type="bom",
        include=["properties", "evidence", "licenses"],
        exclude=[
            "tools.components", "components", "dependencies","services",
                 # "vulnerabilities.[].ratings.[].vector",
                 # "vulnerabilities.[].description",
                 # "vulnerabilities.[].detail",
                 # "vulnerabilities.[].advisories",
                 # "vulnerabilities.[].affects",
                 # "vulnerabilities.[].source",
                 # "vulnerabilities.[].analysis",
                 # "vulnerabilities.[].updated",
                 # "vulnerabilities.[].properties",
                 # "vulnerabilities.[].references",
                 # "vulnerabilities.[].published",
                 # "vulnerabilities.[].recommendation",
                 # "vulnerabilities.[].ratings",
                 # "vulnerabilities.[].cwes"
                 ],
        sort_keys=["cve", "text", "url"]
    )
    csaf_diff_options = Options(
        allow_new_versions=True,
        allow_new_data=True,
        preconfig_type="csaf",
        include=[],
        exclude=[
            # "vulnerabilities.[].acknowledgements",
            # "vulnerabilities.[].discovery_date",
            # "vulnerabilities.[].ids",
            # "vulnerabilities.[].notes",
            # "vulnerabilities.[].product_status",
            # "vulnerabilities.[].references",
            # "vulnerabilities.[].scores.[].products",
        ],
        sort_keys=[]
    )
    failed_diffs = {"bom": {}, "csaf": {}}
    for repo in repo_data:
        bom_diff_options.file_1 = f"{dir1}/{repo['project']}-bom.vdr.json"
        bom_diff_options.file_2 = f"{dir2}/{repo['project']}-bom.vdr.json"
        bom_diff_options.output = f"{dir2}/{repo['project']}-bom-diff.json"
        bom_result, bom_summary = compare_snapshots(bom_diff_options, repo)
        if bom_result:
            print(bom_result)
            failed_diffs["bom"] |= {repo["project"]: bom_summary}
        csaf_diff_options.file_1 = f"{dir1}/{repo['project']}/csaf_v1.json"
        csaf_diff_options.file_2 = f"{dir2}/{repo['project']}/csaf_v1.json"
        csaf_diff_options.output = f"{dir2}/{repo['project']}-csaf-diff.json"
        csaf_result, csaf_summary = compare_snapshots(csaf_diff_options, repo)
        if csaf_result:
            print(csaf_result)
            failed_diffs["csaf"] |= {repo["project"]: csaf_summary}
    return failed_diffs


def get_descriptions(bom):
    return [i.detail for i in bom.vdrs if not i.recommendation]


def get_purl_names(purls):
    package_names = set()
    for p in purls:
        if "@" in p:
            package_names.add(p.split("@")[0])
        else:
            package_names.add(p.lower())
        # purl = PackageURL.from_string(p)
        # package_names.add(purl.name.lower())
    package_names = sorted(package_names)
    with open("purl_names.txt", 'w') as f:
        for purl in package_names:
            f.write(f"{purl}\n")


def handle_new_recommendation_for_comparison(bom_data):
    for i, v in enumerate(bom_data.get("vulnerabilities", [])):
        if rec := v.get("recommendation"):
            if match := VERSION_REPLACE.findall(rec):
                new_rec = f"Update to version {match[-1]}".rstrip(".")
                bom_data["vulnerabilities"][i]["recommendation"] = f"{new_rec}."
    return bom_data


def migrate_old_csaf_formatting(csaf_data):
    for i, v in enumerate(csaf_data.get("vulnerabilities", [])):
        csaf_data["vulnerabilities"][i]["acknowledgements"] = [v.get("acknowledgements")] if v.get("acknowledgements") else []
    return csaf_data


def migrate_old_vdr_formatting(bom_data):
    for i, v in enumerate(bom_data.get("vulnerabilities", [])):
        if v.get("description"):
            description, detail = get_description_detail(v["description"])
            bom_data["vulnerabilities"][i]["description"] = description
            bom_data["vulnerabilities"][i]["detail"] = detail
        if v.get("recommendation"):
            new_rec = v["recommendation"].replace(" or later", "").replace("Update to version ", "Update to ").replace("Update to", "Update to version").rstrip(".")
            bom_data["vulnerabilities"][i]["recommendation"] = f"{new_rec}."
        if v.get("properties"):
            new_properties = [i for i in v["properties"] if i["name"] != "affectedVersionRange"]
            bom_data["vulnerabilities"][i]["properties"] = new_properties
    return bom_data


def perform_snapshot_tests(dir1, dir2):
    if failed_diffs := generate_snapshot_diffs(dir1, dir2, read_csv()):
        diff_file = os.path.join(dir2, 'diffs.json')
        read_write_json(diff_file, failed_diffs)
        print(f"Results of failed diffs saved to {diff_file}")
    else:
        print("Snapshot tests passed!")


def read_csv():
    csv_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), "data", "repos.csv")
    with open(csv_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        repo_data = list(reader)
    return repo_data


def read_write_json(filename, data = None):
    if data:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return {}
    else:
        with open(filename, 'r', encoding='utf-8') as f:
            return json.load(f)


if __name__ == '__main__':
    args = build_args(r'C:\Users\user\PycharmProjects\depscan-samples\v5', r'C:\Users\user\PycharmProjects\depscan-samples\v6')
    perform_snapshot_tests(args.directories[0], args.directories[1])
