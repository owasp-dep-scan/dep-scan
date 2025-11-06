import os
import re
from copy import deepcopy
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import cvss
import toml
from custom_json_diff.lib.utils import file_read, file_write, json_dump, json_load
from packageurl import PackageURL
from vdb.lib import convert_time

from analysis_lib import get_version
from analysis_lib.config import (
    CWE_MAP,
    SEVERITY_REF,
    TIME_FMT,
    TOML_TEMPLATE,
)


def vdr_to_csaf(res):
    """
    Processes a vulnerability from the VDR format to CSAF format.

    :param res: The metadata for a single vulnerability.
    :type res: dict

    :return: The processed vulnerability in CSAF format.
    :rtype: dict
    """
    cve = res.get("id", "")
    acknowledgements = get_acknowledgements(res.get("source", {}))
    products, product_status = get_products(res.get("affects", []))
    cwe, notes = parse_cwe(res.get("cwes", []))
    scores = parse_cvss(res.get("ratings", []))
    description = res.get("description", "").replace("\n", " ").replace("\t", " ")
    details = res.get("detail", "").replace("\n", " ").replace("\t", " ")
    refs_to_add = res.get("references", [])
    refs_to_add.extend(res.get("advisories", []))
    ids, references = format_references(refs_to_add)
    discovery_date = res.get("published") or res.get("updated")
    notes.extend(
        [
            {
                "category": "description",
                "text": description,
                "details": "Vulnerability Description",
            },
            {
                "category": "details",
                "text": details,
                "details": "Vulnerability Details",
            },
        ]
    )
    if res.get("recommendation"):
        notes.append(
            {
                "category": "other",
                "title": "Recommended Action",
                "text": res["recommendation"],
            }
        )
    vuln = {
        "cwe": cwe,
        "acknowledgements": acknowledgements,
        "discovery_date": discovery_date,
        "product_status": product_status,
        "references": references,
        "ids": ids,
        "scores": [{"cvss_v3": score, "products": products} for score in scores],
        "notes": notes,
        "title": res.get("bom-ref", ""),
    }
    if cve.startswith("CVE"):
        vuln["cve"] = cve
    return vuln


def get_products(affects):
    """
    Generates a list of unique products and a dictionary of version statuses for
    the vulnerability.

    :param affects: Affected and fixed versions with associated purls
    :type affects: list[dict]

    :return: Packages affected by the vulnerability and their statuses
    :rtype: tuple[list[str], dict[str, str]]
    """
    if not affects:
        return [], {}
    known_affected = set()
    not_affected = set()
    products = set()
    for i in affects:
        product = ""
        try:
            purl = PackageURL.from_string(i.get("ref", ""))
            namespace = purl.namespace or ""
            pkg_name = purl.name
            if namespace:
                product += f"{namespace}/"
        except ValueError:
            pkg_name = i.get("ref", "").split("@")
            products.add(i.get("ref", ""))
        for v in i.get("versions", []):
            entry = f"{product}{pkg_name}@{v.get('version') or v.get('range')}"
            if v.get("status") == "affected":
                known_affected.add(entry)
                products.add(entry)
            elif v.get("status") == "unaffected":
                not_affected.add(entry)
    return list(products), {
        "known_affected": list(known_affected),
        "known_not_affected": list(not_affected),
    }


def get_acknowledgements(source):
    """
    Generates the acknowledgements from the source data information
    :param source: A dictionary with the source information
    :type source: dict

    :return: A dictionary containing the acknowledgements
    :rtype: list[dict]
    """
    if not source.get("name"):
        return []

    if not source.get("url"):
        return [{"organization": source["name"].replace(" Advisory", "")}]

    return [
        {
            "organization": source["name"].replace(" Advisory", ""),
            "urls": [source.get("url")],
        }
    ]


def parse_cwe(cwe):
    """
    Takes a list of CWE numbers and returns a single CSAF CWE entry, with any
    additional CWEs returned in notes (CSAF 2.0 only allows one CWE).

    :param cwe: A list of CWE numbers
    :type cwe: list

    :return: A single CSAF CWE entry (dict) and notes (list)
    :rtype: tuple
    """
    fmt_cwe = None
    new_notes = []

    if not cwe:
        return fmt_cwe, new_notes

    for i, cwe_id in enumerate(cwe):
        cwe_name = CWE_MAP.get(cwe_id, "UNABLE TO LOCATE CWE NAME")
        if i == 0:
            fmt_cwe = {
                "id": str(cwe_id),
                "name": cwe_name,
            }
        else:
            new_notes.append(
                {
                    "title": f"Additional CWE: {cwe_id}",
                    "audience": "developers",
                    "category": "other",
                    "text": cwe_name,
                }
            )

    return fmt_cwe, new_notes


def parse_cvss(ratings: List[Optional[Dict]]) -> List[Optional[Dict]]:
    """
    Parses the CVSS information from pkg_vulnerabilities

    :param ratings: The ratings data
    :type ratings: list[dict]

    :return: The parsed CVSS information as a single dictionary
    :rtype: list[dict]
    """
    scores = []
    if not ratings:
        return scores
    for rating in ratings:
        if not (vector_string := rating.get("vector")) or not vector_string.startswith(
            "CVSS:3"
        ):
            continue
        try:
            cvss_v3 = cvss.CVSS3(vector_string)
            cvss_v3.check_mandatory()
        except Exception:
            continue
        cvss_v3_dict = cvss_v3.as_json()
        cvss_v3 = {k: v for k, v in cvss_v3_dict.items() if v != "NOT_DEFINED"}
        scores.append(cvss_v3)
    return scores


def format_references(references: List) -> Tuple[List[Dict], List[Dict]]:
    """
    Parses VDR references and outputs CSAF formatted objects.

    :param references: List of dictionaries of vulnerability references
    :type references: list

    :return: lists of csaf ids and references
    :rtype: tuple[list[dict], list[dict]]
    """
    if not references:
        return [], []
    fmt_refs = []
    ids = []
    refs = [i for i in references if i.get("source", {}).get("name") or i.get("title")]
    id_types = {"issues", "pull", "commit", "release"}
    for r in refs:
        if r.get("source", {}).get("name"):
            ref_id = r.get("id")
            system_name = r["source"]["name"]
            url = r["source"]["url"]
        else:
            ref_id, system_name = extract_ids(r.get("title", ""))
            url = r.get("url", "")
        if (tmp := ref_id.replace("-", "")) and tmp.isalpha():
            continue
        if "Bugzilla" in system_name:
            ids.append({"system_name": system_name, "text": ref_id})
        elif "cve-" in ref_id.lower() and len(ref_id) >= 5 and ref_id[4].isdigit():
            ref_id = f"CVE-{ref_id.lower().split('cve-')[1]}"
            ref_id = "-".join(ref_id.split("-")[:3])
            if len(ref_id) in range(13, 15):
                system_name = "CVE Record"
                ids.append({"system_name": system_name, "text": ref_id})
        elif any((i in ref_id for i in id_types)):
            ids.append({"system_name": system_name, "text": ref_id})
        if (
            "Advisory" in system_name
            and "blog" not in system_name
            and (tmp := ref_id.replace("-", ""))
            and not tmp.isalpha()
        ):
            ids.append({"system_name": system_name, "text": ref_id})
        fmt_refs.append({"summary": system_name, "url": url})
    # remove duplicates
    new_ids = {
        (idx["system_name"], idx["text"])
        for idx in ids
        if not idx["text"].replace("-", "").isalpha()
    }
    ids = [{"system_name": idx[0], "text": idx[1].upper()} for idx in new_ids]
    ids = sorted(ids, key=lambda x: x["text"])
    new_refs = {
        (idx["summary"], idx["url"])
        for idx in fmt_refs
        if not idx["summary"].startswith("Cve ")
    }
    fmt_refs = [{"summary": idx[0], "url": idx[1]} for idx in new_refs]
    fmt_refs = sorted(fmt_refs, key=lambda x: x["url"])
    return ids, fmt_refs


def extract_ids(ref):
    if " " in ref:
        refs = ref.split(" ")
        if len(refs) > 1:
            return refs.pop(), " ".join(refs)
    elif "-" in ref:
        refs = ref.split("-")
        if len(refs) > 1:
            return refs.pop(), " ".join(refs).capitalize().replace("Pr", "PR")
    return None, ref


def parse_revision_history(tracking):
    """
    Parses the revision history from the tracking data.

    :param tracking: The tracking object containing the revision history
    :type tracking: dict

    :return: The updated tracking object
    :rtype: dict
    """
    hx = deepcopy(tracking.get("revision_history")) or []
    if not hx and (tracking.get("version")) != "1":
        tracking["version"] = 1

    elif hx and (len(hx) > 0):
        hx = cleanup_list(hx)
        if tracking.get("status") == "final" and int(tracking.get("version", 1)) > (
            len(hx) + 1
        ):
            tracking["version"] = int(len(hx) + 1)
    status = tracking.get("status")
    if not status or len(status) == 0:
        status = "draft"
    dt = datetime.now().strftime(TIME_FMT)
    tracking = cleanup_dict(tracking)
    # Format dates
    try:
        tracking["initial_release_date"] = (
            convert_time(
                tracking.get(
                    "initial_release_date",
                    tracking.get("current_release_date", dt),
                )
            )
        ).strftime(TIME_FMT)
        tracking["current_release_date"] = (
            convert_time(
                tracking.get(
                    "current_release_date", tracking.get("initial_release_date")
                )
            )
        ).strftime(TIME_FMT)
    except AttributeError:
        pass
    if status == "final" and (not hx or len(hx) == 0):
        choose_date = max(
            tracking.get("initial_release_date"),
            tracking.get("current_release_date"),
        )
        hx.append(
            {
                "date": choose_date,
                "number": "1",
                "summary": "Initial",
            }
        )
        tracking["current_release_date"] = choose_date
        tracking["initial_release_date"] = choose_date
    elif status == "final":
        hx = sorted(hx, key=lambda x: x["number"])
        tracking["initial_release_date"] = hx[0]["date"]
        if tracking["current_release_date"] == hx[-1]["date"]:
            tracking["current_release_date"] = dt
        hx.append(
            {
                "date": tracking["current_release_date"],
                "number": str(len(hx) + 1),
                "summary": "Update",
            }
        )
    if len(hx) > 0:
        tracking["version"] = str(
            max(int(tracking.get("version", 0)), int(hx[-1]["number"]))
        )
    else:
        tracking["version"] = "1"
    if not tracking.get("id") or len(tracking.get("id")) == 0:
        tracking["id"] = f"{dt}_v{tracking['version']}"
    hx = sorted(hx, key=lambda x: x["number"])

    tracking["revision_history"] = hx
    tracking["status"] = status
    return tracking


def import_product_tree(tree):
    """
    Set the product tree by loading it from a file.

    :param tree: The dictionary representing the tree.
    :type tree: dict

    :return: The product tree loaded from the file, or None if file is empty.
    :rtype: dict or None
    """
    product_tree = None
    if len(tree.get("easy_import", "")) > 0:
        product_tree = json_load(
            tree["easy_import"],
            (
                "Unable to load product tree file. Please verify your filepath and that your product "
                "tree is valid json. Visit "
                "https://github.com/owasp-dep-scan/dep-scan/blob/master/test/data/product_tree.json "
                "for an example."
            ),
        )
    return product_tree


def parse_toml(metadata):
    """
    Parses the given metadata from csaf.toml and generates an output dictionary.

    :param metadata: The data read from csaf.toml

    :return: The processed metadata ready to use in the CSAF document.
    """
    tracking = parse_revision_history(metadata.get("tracking"))
    refs = list(metadata.get("reference"))
    notes = list(metadata.get("note"))
    product_tree = import_product_tree(metadata["product_tree"])
    return {
        "document": {
            "aggregate_severity": {},
            "category": metadata["document"]["category"],
            "title": metadata["document"]["title"] or "Test",
            "csaf_version": "2.0",
            "distribution": metadata.get("distribution"),
            "lang": "en",
            "notes": notes,
            "publisher": {
                "category": metadata["publisher"]["category"],
                "contact_details": metadata["publisher"].get("contact_details"),
                "name": metadata["publisher"]["name"],
                "namespace": metadata["publisher"]["namespace"],
            },
            "references": refs,
            "tracking": tracking,
        },
        "product_tree": product_tree,
        "vulnerabilities": [],
    }


def toml_compatibility(metadata):
    """
    Applies any changes to the formatting of the TOML after a depscan
    minor or patch update

    :param metadata: The toml data
    """

    return metadata


def export_csaf(vdr_result, src_dir, reports_dir, bom_file):
    """
    Generates a CSAF 2.0 JSON document from the results.

    :param vdr_result: VDR Result
    :type vdr_result: VDRResult
    :param src_dir: The source directory.
    :type src_dir: str
    :param reports_dir: The reports directory.
    :type reports_dir: str
    :param bom_file: The BOM file path
    :type bom_file: str

    """
    pkg_vulnerabilities = vdr_result.pkg_vulnerabilities
    toml_file_path = os.getenv("DEPSCAN_CSAF_TEMPLATE")
    if not toml_file_path:
        toml_file_path = os.path.join(src_dir, "csaf.toml")
    metadata = import_csaf_toml(toml_file_path)
    metadata = toml_compatibility(metadata)
    template = parse_toml(metadata)
    new_results = add_vulnerabilities(template, pkg_vulnerabilities)
    new_results = cleanup_dict(new_results)
    new_results, metadata = verify_components_present(new_results, metadata, bom_file)
    fn = bom_file.replace(
        ".cdx.json", f".csaf_v{new_results['document']['tracking']['version']}.json"
    )
    outfile = os.path.join(reports_dir, fn)
    json_dump(
        outfile,
        new_results,
        success_msg=f"CSAF report written to {outfile}",
        error_msg=f"CSAF report could not be written to {outfile}",
    )
    write_toml(toml_file_path, metadata)


def import_csaf_toml(toml_file_path):
    """
    Reads the csaf.toml file and returns it as a dictionary.

    :param toml_file_path: The path to the csaf.toml file.
    :type toml_file_path: str

    :return: A dictionary containing the parsed contents of the csaf.toml.
    :rtype: dict

    :raises TOMLDecodeError: If the TOML is invalid.
    """

    if not os.path.isfile(toml_file_path):
        write_toml(toml_file_path)
        return import_csaf_toml(toml_file_path)
    try:
        toml_data = toml.loads(
            file_read(
                toml_file_path,
                error_msg=f"Unable to read settings from {toml_file_path}.",
            )
        )
    except toml.TomlDecodeError:
        raise ValueError(
            "Invalid TOML. Please make sure you do not have any "
            "duplicate keys and that any filepaths are properly escaped"
            "if using Windows."
        )
    return toml_compatibility(toml_data)


def write_toml(toml_file_path, metadata=None, write_version=True):
    """
    Writes the toml data out to file. If no toml data is provided, a toml is
    generated based on the default template.

    :param toml_file_path: The filepath to save the TOML template to.
    :type toml_file_path: str
    :param metadata: A dictionary containing the TOML metadata.
    :type metadata: dict
    :param write_version: Include the depscan version
    :type write_version: bool

    """
    if not metadata:
        metadata = TOML_TEMPLATE
    metadata["depscan_version"] = get_version()
    try:
        file_write(
            toml_file_path,
            toml.dumps(metadata),
            error_msg=f"Unable to write settings to {toml_file_path}.",
        )
    except toml.TomlDecodeError:
        raise ValueError("Unable to write settings to file.")


def cleanup_list(d):
    """
    Cleans up a list by removing empty or None values recursively.

    :param d: The list to be cleaned up.

    :return: The new list or None
    """
    new_lst = []
    for dl in d:
        if isinstance(dl, dict):
            if entry := cleanup_dict(dl):
                new_lst.append(entry)
        elif isinstance(dl, str):
            new_lst.append(dl)
    return new_lst


def cleanup_dict(d):
    """
    Cleans up a dictionary by removing empty or None values recursively.

    :param d: The dictionary to be cleaned up.

    :return: The new dictionary or None
    """
    new_dict = {}
    for key, value in d.items():
        entry = None
        if value and str(value) != "":
            if isinstance(value, list):
                entry = cleanup_list(value)
            elif isinstance(value, dict):
                entry = cleanup_dict(value)
            else:
                entry = value
        if entry:
            new_dict[key] = entry
    return new_dict


def import_root_component(bom_file):
    """
    Import the root component from the VDR file if no product tree is present
    and gene    external references.

    :param bom_file: The path to the VDR file.
    :type bom_file: str

    :returns: The product tree (dict) and additional references (list of dicts).
    :rtype: tuple
    """
    bom = json_load(bom_file)
    refs = []
    product_tree = {}
    if component := bom.get("metadata", {}).get("component"):
        product_tree = {
            "full_product_names": [
                {
                    "name": component.get("name"),
                    "product_id": f"{component.get('name')}:{component.get('version')}",
                    "product_identification_helper": {
                        "purl": component.get("purl"),
                    },
                }
            ]
        }
        if external_references := component.get("externalReferences"):
            refs.extend(
                {
                    "summary": r.get("type"),
                    "url": r.get("url"),
                }
                for r in external_references
            )
    return product_tree, refs


def verify_components_present(data, metadata, bom_file):
    """
    Verify if the required components are present

    :param data: The dictionary representing the csaf document itself.
    :type data: dict
    :param metadata: The dictionary that will be written back to the csaf.toml.
    :type metadata: dict
    :param bom_file: The path to the vdr_file.
    :type bom_file: str

    :return: The modified template and metadata dictionaries.
    :rtype: tuple
    """
    template = deepcopy(data)
    new_metadata = deepcopy(metadata)
    disclaimer = {
        "category": "legal_disclaimer",
        "text": "Depscan reachable code only covers the project source code, "
        "not the code of dependencies. A dependency may execute "
        "vulnerable code when called even if it is not in the "
        "project's source code. Regard the Depscan-set flag of "
        "'code_not_in_execute_path' with this in mind.",
    }
    if template["document"].get("notes"):
        template["document"]["notes"].append(
            {"category": "legal_disclaimer", "text": disclaimer}
        )
    else:
        template["document"]["notes"] = [disclaimer]

    # Add product tree if not present
    if not template.get("product_tree"):
        [template["product_tree"], extra_ref] = import_root_component(bom_file)
        if extra_ref and template["document"].get("references"):
            template["document"]["references"] += extra_ref
        elif extra_ref:
            template["document"]["references"] = extra_ref

    # CSAF forbids revision entries unless the status is final, but requires
    # this to be here nonetheless
    if not template["document"]["tracking"].get("revision_history"):
        template["document"]["tracking"]["revision_history"] = []
    else:
        new_metadata["tracking"] = deepcopy(template["document"]["tracking"])

    # Reset the id if it's one we've generated
    if re.match(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}_v", new_metadata["tracking"]["id"]
    ):
        new_metadata["tracking"]["id"] = ""

    return template, new_metadata


def add_vulnerabilities(template, pkg_vulnerabilities):
    """
    Add vulnerabilities to the given data.

    :param template: The CSAF data so far.
    :type template: dict
    :param pkg_vulnerabilities: The vulnerabilities to add.
    :type pkg_vulnerabilities: list

    :return: The modified data with added vulnerability information.
    :rtype: dict
    """
    new_results = deepcopy(template)
    agg_score = set()
    if not pkg_vulnerabilities:
        return new_results
    for r in pkg_vulnerabilities:
        new_vuln = vdr_to_csaf(r)
        if sev := get_severity(new_vuln["scores"]):
            agg_score.add(sev)
        new_results["vulnerabilities"].append(new_vuln)
    if agg_score := list(agg_score):
        agg_score.sort()
        severity_ref = {v: k for k, v in SEVERITY_REF.items()}
        agg_severity = (
            severity_ref[agg_score[0]][0] + severity_ref[agg_score[0]][1:].lower()
        )
        new_results["document"]["aggregate_severity"] = {
            "text": agg_severity.capitalize()
        }

    return new_results


def get_severity(scores: List):
    severities = []
    for score in scores:
        if s := score.get("cvss_v3", {}).get("baseSeverity"):
            severities.append(s)
    if not severities:
        return None
    severities.sort()
    return SEVERITY_REF.get(severities[-1].lower())
