import argparse
import json
from packageurl import PackageURL


def build_args():
    """
    Constructs command line arguments for the comparison tool
    """
    parser = argparse.ArgumentParser(description="Compare depscan and trivy results.")
    parser.add_argument(
        "--trivy-json",
        dest="trivy_json",
        default="trivy.json",
        help="Trivy json file.",
    )
    parser.add_argument(
        "--depscan-json",
        dest="depscan_json",
        default="depscan-docker.json",
        help="Depscan json file.",
    )
    return parser.parse_args()


def compare(trivy_json, depscan_json):
    trivy_cves = set()
    trivy_pkgs = set()
    depscan_cves = set()
    depscan_pkgs = set()
    with open(trivy_json, "r") as tj:
        trivy_json_obj = json.load(tj)
        for res in trivy_json_obj.get("Results", []):
            for tvuln in res.get("Vulnerabilities", []):
                cveid = tvuln.get("VulnerabilityID", "")
                if cveid.startswith("CVE"):
                    if (
                        cveid.startswith("CVE-2018-")
                        or cveid.startswith("CVE-2019-")
                        or cveid.startswith("CVE-2020-")
                        or cveid.startswith("CVE-2021-")
                        or cveid.startswith("CVE-2022-")
                        or cveid.startswith("CVE-2023-")
                    ):
                        trivy_cves.add(cveid)
                        trivy_pkgs.add(
                            f"""{tvuln.get("PkgName")}:{tvuln.get("InstalledVersion")}:{tvuln.get("FixedVersion", "")}"""
                        )
                        if tvuln.get("FixedVersion"):
                            print(
                                tvuln.get("InstalledVersion"),
                                tvuln.get("FixedVersion", ""),
                            )
                else:
                    trivy_cves.add(cveid)
                    trivy_pkgs.add(
                        f"""{tvuln.get("PkgName")}:{tvuln.get("InstalledVersion")}:{tvuln.get("FixedVersion", "")}"""
                    )
    print("\n------------- depscan ------------")
    for line in open(depscan_json, "r"):
        line_obj = json.loads(line)
        depscan_cves.add(line_obj.get("id"))
        purl = line_obj.get("purl")
        purl_obj = PackageURL.from_string(purl).to_dict()
        name = purl_obj.get("name")
        depscan_pkgs.add(f"""{name}:{purl_obj.get("version")}:{line_obj.get("fix_version", "")}""")
        print(line_obj.get("id"), purl_obj.get("version"), line_obj.get("fix_version", ""))
    print("-----------------------------------\n")

    print("Packages in Trivy but not in depscan")
    print(trivy_pkgs.difference(depscan_pkgs))

    print("Packages in depscan but not in Trivy")
    print(depscan_pkgs.difference(trivy_pkgs))

    print("CVEs in Trivy but not in depscan. Ignore any CVE which is older than 2018.")
    print(trivy_cves.difference(depscan_cves))

    print("CVEs in depscan but not in Trivy")
    print(depscan_cves.difference(trivy_cves))


def main():
    args = build_args()
    compare(args.trivy_json, args.depscan_json)


if __name__ == "__main__":
    main()
