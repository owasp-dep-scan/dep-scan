import argparse
import csv
import json
import os

from custom_json_diff.custom_diff import compare_dicts, perform_bom_diff, report_results
from custom_json_diff.custom_diff_classes import Options

from depscan.lib.utils import get_description_detail, combine_vdrs, consolidate


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


def compare_snapshot(dir1, dir2, options, repo):
    bom_1 = f"{dir1}/{repo['project']}-bom.vdr.json"
    bom_2 = f"{dir2}/{repo['project']}-bom.vdr.json"
    # purls = get_all_purls(bom_1) + get_all_purls(bom_2)
    # return "", "", purls
    options.file_1 = bom_1
    options.file_2 = bom_2
    options.output = f"{dir2}/{repo['project']}-diff.json"
    if not os.path.exists(bom_1):
        return f"{bom_1} not found.", f"{bom_1} not found."
    consolidate_vdrs(bom_1, True)
    consolidate_vdrs(bom_2)
    options.file_1 = f"{dir1}/{repo['project']}-bom.vdr.consolidated.json"
    options.file_2 = f"{dir2}/{repo['project']}-bom.vdr.consolidated.json"
    result, j1, j2 = compare_dicts(options)
    result, result_summary = perform_bom_diff(j1, j2)
    report_results(result, result_summary, options, j1, j2)
    if result != 0:
            return f"{repo['project']} failed.", result_summary
    else:
        return f"{repo['project']} succeeded.", result_summary


def get_all_purls(bom):
    bom_data = read_write_json(bom)
    components = bom_data.get("components", [])
    components.extend(bom_data.get("metadata", {}).get("tools", {}).get("components", []))
    if comp := bom_data.get("metadata", {}).get("component"):
        components.append(comp)
    return [i["purl"] for i in components if i.get("purl")]


def consolidate_vdrs(bom, desc=False):
    bom_data = read_write_json(bom)
    vdrs = bom_data.get("vulnerabilities", [])
    consolidated = {}
    suggested_version_map, purl_to_cve_map, cve_to_purl_map = consolidate(vdrs)
    for i in vdrs:
        if i["id"].startswith("CVE-") and int(i["id"][6:8]) in range(12, 19):
            continue
        new_bom_ref = f"{i['id']}/{i['partial_purl']}"
        i["bom-ref"] = new_bom_ref
        if i["partial_purl"] in suggested_version_map:
            i["recommendation"] = f"Update to version {suggested_version_map[i['partial_purl']]}."
        del i["partial_purl"]
        if new_bom_ref in consolidated:
            consolidated[new_bom_ref] = combine_vdrs(consolidated.get(new_bom_ref), i)
        else:
            consolidated[new_bom_ref] = i
    result = []
    for k, v in consolidated.items():
        result.append(v)
    bom_data["vulnerabilities"] = result
    if desc:
        bom_data = handle_old_description(bom_data)
    read_write_json(f"{bom.replace('.json', '.consolidated.json')}", bom_data)


def perform_snapshot_tests(dir1, dir2):
    repo_data = read_csv()
    options = Options(
        allow_new_versions=True,
        allow_new_data=True,
        bom_diff=True,
        include=["properties", "evidence", "licenses"],
        exclude=["metadata.tools.[].components.[].hashes", "components", "dependencies",
                 "vulnerabilities.[].affects",
                 "vulnerabilities.[].ratings.[].vector",
                 # "vulnerabilities.[].description",
                 # "vulnerabilities.[].detail",
                 "vulnerabilities.[].advisories",
                 # "vulnerabilities.[].source",
                 # "vulnerabilities.[].analysis",
                 # "vulnerabilities.[].updated",
                 "vulnerabilities.[].properties",
                 "vulnerabilities.[].references",
                 # "vulnerabilities.[].published",
                 # "vulnerabilities.[].recommendation",
                 # "vulnerabilities.[].ratings.[].score"
                 ],
    )

    failed_diffs = {}
    for repo in repo_data:
        result, summary = compare_snapshot(dir1, dir2, options, repo)
        if result:
            print(result)
            failed_diffs[repo["project"]] = summary

    if failed_diffs:
        diff_file = os.path.join(dir2, 'diffs.json')
        with open(diff_file, 'w') as f:
            json.dump(failed_diffs, f)
        print(f"Results of failed diffs saved to {diff_file}")
    else:
        print("Snapshot tests passed!")


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


def read_csv():
    csv_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), "data", "repos.csv")
    with open(csv_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        repo_data = list(reader)
    return repo_data


def handle_old_description(bom_data):
    for i, v in enumerate(bom_data.get("vulnerabilities", [])):
        description, detail = get_description_detail(v["description"])
        bom_data["vulnerabilities"][i]["description"] = description
        bom_data["vulnerabilities"][i]["detail"] = detail
    return bom_data


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
