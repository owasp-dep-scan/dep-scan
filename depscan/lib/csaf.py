import json
import os
import re
import sys
from copy import deepcopy
from datetime import datetime
from json import JSONDecodeError
from typing import List, Dict, Tuple

import cvss
import toml
from cvss import CVSSError
from packageurl import PackageURL
from vdb.lib import convert_time

from depscan.lib.config import (
    SEVERITY_REF,
    TIME_FMT,
    CWE_MAP, TOML_TEMPLATE,
)
from depscan.lib.logger import LOG
from depscan.lib.utils import format_system_name
from depscan import get_version


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
    [products, product_status] = get_products(
        res.get("affects", []), res.get("properties", [])
    )
    cwe, notes = parse_cwe(res.get("cwes", []))
    cvss_v3 = parse_cvss(res.get("ratings", [{}]))
    description = (
        res.get("description", "")
        .replace("\n", " ")
        .replace("\t", " ")
        .replace("\n", " ")
        .replace("\t", " ")
    )
    ids, references = format_references(res.get("references", []))
    orig_date = res.get("published")
    update_date = res.get("updated")
    discovery_date = orig_date or update_date
    vuln = {}
    if cve.startswith("CVE"):
        vuln["cve"] = cve
    vuln["cwe"] = cwe
    vuln["acknowledgements"] = acknowledgements
    vuln["discovery_date"] = discovery_date
    vuln["product_status"] = product_status
    vuln["references"] = references
    vuln["ids"] = ids
    vuln["scores"] = [{"cvss_v3": cvss_v3, "products": products}]
    notes.append(
        {
            "category": "general",
            "text": description,
            "details": "Vulnerability Description",
        }
    )
    vuln["notes"] = notes

    return vuln


def get_products(affects, props):
    """
    Generates a list of unique products and a dictionary of version statuses for
    the vulnerability.

    :param affects: Affected and fixed versions with associated purls
    :type affects: list[dict]
    :param props: List of properties
    :type props: list[dict]

    :return: Packages affected by the vulnerability and their statuses
    :rtype: tuple[list[str], dict[str, str]]
    """
    if not affects and not props:
        return [], {}

    known_affected = []
    fixed = []
    products = set()
    for i in affects:
        for v in i.get("versions", []):
            try:
                purl = PackageURL.from_string(i.get("ref", ""))
                namespace = purl.namespace
                pkg_name = purl.name
                version = purl.version
            except ValueError:
                purl = i.get("ref", "")
                namespace = None
                pkg_name = i.get("ref", "")
                version = None
            if purl and v.get("status") == "affected":
                known_affected.append(
                    f'{namespace}/{pkg_name}@{version}')
            elif purl and v.get("status") == "unaffected":
                fixed.append(f'{namespace}/{pkg_name}@{v.get("version")}')
            elif not purl and v.get("status") == "affected":
                known_affected.append(i.get("ref"))
        product = ""
        try:
            purl = PackageURL.from_string(i.get("ref", ""))
            if purl.namespace:
                product += f"{purl.namespace}/"
            product += f"{purl.name}@{purl.version}"
        except ValueError:
            product = i.get("ref", "")
        products.add(product)

    if version_range := [
        {i["name"]: i["value"]}
        for i in props
        if i["name"] == "affectedVersionRange"
    ]:
        for v in version_range:
            products.add(v["affectedVersionRange"])
            known_affected.append(v["affectedVersionRange"])

    known_affected = [
        i.replace("None/", "").replace("@None", "")
        for i in known_affected
    ]
    fixed = [
        i.replace("None/", "").replace("@None", "") for i in fixed
    ]

    return list(products), {"known_affected": known_affected, "fixed": fixed}


def get_acknowledgements(source):
    """
    Generates the acknowledgements from the source data information
    :param source: A dictionary with the source information
    :type source: dict

    :return: A dictionary containing the acknowledgements
    :rtype: dict
    """
    if not source.get("name"):
        return {}

    return {
        "organization": source["name"],
        "urls": [source.get("url")]
    }


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
        if not cwe_name:
            LOG.warning(
                "We couldn't locate the name of the CWE with the following "
                "id: %s. Help us out by reporting the id at "
                "https://github.com/owasp-dep-scan/dep-scan/issues.", i, )
        if i == 0:
            fmt_cwe = {"id": str(cwe_id), "name": cwe_name, }
        else:
            new_notes.append(
                {"title": f"Additional CWE: {cwe_id}", "audience": "developers",
                    "category": "other", "text": cwe_name, })

    return fmt_cwe, new_notes


def parse_cvss(ratings: List[Dict]) -> Dict:
    """
    Parses the CVSS information from pkg_vulnerabilities

    :param ratings: The ratings data
    :type ratings: list[dict]

    :return: The parsed CVSS information as a single dictionary
    :rtype: dict
    """
    if not ratings or not (vector_string := ratings[0].get("vector")):
        return {}
    if vector_string == "None":
        return {}
    try:
        cvss_v3 = cvss.CVSS3(vector_string)
        cvss_v3.check_mandatory()
    except (CVSSError, ValueError):
        return {}
    cvss_v3_dict = cvss_v3.as_json()
    cvss_v3 = {k: v for k, v in cvss_v3_dict.items() if v != "NOT_DEFINED"}
    return cleanup_dict(cvss_v3)


def format_references(references: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
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
    refs = [i for i in references if i.get("source")]
    id_types = {"issues", "pull", "commit", "release"}
    for r in refs:
        ref_id = r.get("id")
        system_name = r["source"]["name"]
        if "bugzilla" in ref_id or "gist" in ref_id:
            ids.append({"system_name": system_name, "text": ref_id.split("bugzilla-")[-1]})
        elif any((i in ref_id for i in id_types)):
            ids.append({"system_name": system_name, "text": ref_id.split("-")[-1]})
        elif "Advisory" in system_name:
            ids.append({"system_name": system_name, "text": ref_id})
            system_name += f" {ref_id}"
        fmt_refs.append({"summary": system_name, "url": r["source"]["url"]})
    # remove duplicates
    new_ids = {(idx["system_name"], idx["text"]) for idx in ids}
    ids = [{"system_name": idx[0], "text": idx[1]} for idx in new_ids]
    ids = sorted(ids, key=lambda x: x["text"])
    return ids, fmt_refs


def get_ref_summary(url, patterns):
    """
    Returns the summary string associated with a given URL.

    :param url: The URL to match against the patterns in the REF_MAP.
    :type url: str

    :param patterns: Regex patterns to match against the URL
    :type patterns: dict

    :return: The summary string corresponding to the matched pattern in REF_MAP.
    :rtype: str

    :raises: TypeError if url is not a string
    """
    if not isinstance(url, str):
        raise TypeError("url must be a string")
    for pattern, value in patterns.items():
        if match := pattern.search(url):
            return value, match
    return "Other", None


def get_ref_summary_helper(url, patterns):
    lower_url = url.lower()
    if any(("github.com" in lower_url, "bitbucket.org" in lower_url, "chromium" in lower_url)) and "advisory" not in lower_url and "advisories" not in lower_url:
        value, match = get_ref_summary(url, patterns["repo_hosts"])
        if match:
            if value == "Generic":
                return ((f"{match['host']}-{match['type']}-{match['user']}-{match['repo']}-"
                        f"{match['id']}").replace("[p/", "["),
                        match, f"{format_system_name(match['host'])} {match['type'].capitalize()} "
                               f"[{match['user']}/{match['repo']}]".replace("[p/", "["))
            if value == "GitHub Blob":
                return f"github-blob-{match['user']}/{match['repo']}-{match['file']}@{match['ref']}", match, f"GitHub Blob [{match['user']}/{match['repo']}]"
            if value == "GitHub Gist":
                return f"github-gist-{match['user']}-{match['id']}", match, f"GitHub Gist [{match['user']}]"
        return value, match, ""
    value, match = get_ref_summary(url, patterns["other"])
    if value == "Advisory":
        return value, match, f"{format_system_name(match['org'])} Advisory"
    elif "VulDB" in value:
        return f"vuldb-{match['id']}", match, value
    elif "Snyk" in value:
        return f"{match['id']}", match, value
    return value, match, value


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
        LOG.warning("Revision history is empty. Correcting the version number.")
        tracking["version"] = 1

    elif hx and (len(hx) > 0):
        hx = cleanup_list(hx)
        if tracking.get("status") == "final" and int(
            tracking.get("version", 1)
        ) > (len(hx) + 1):
            LOG.warning(
                "Revision history is inconsistent with the version "
                "number. Correcting the version number."
            )
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
        LOG.warning("Your dates don't appear to be in ISO format.")
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
        LOG.info("No tracking id, generating one.")
        tracking["id"] = f"{dt}_v{tracking['version']}"
    if (tracking["initial_release_date"]) > (tracking["current_release_date"]):
        LOG.warning(
            "Your initial release date is later than the current release date."
        )
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
    if len(tree["easy_import"]) > 0:
        try:
            with open(tree["easy_import"], "r", encoding="utf-8") as f:
                product_tree = json.load(f)
        except JSONDecodeError:
            LOG.warning(
                "Unable to load product tree file. Please verify that your "
                "product tree is a valid json file. Visit "
                "https://github.com/owasp-dep-scan/dep-scan/blob/master/test"
                "/data/product_tree.json for an example."
            )
        except FileNotFoundError:
            LOG.warning(
                "Cannot locate product tree at %s. Please verify you "
                "have entered the correct filepath in your csaf.toml.",
                tree["easy_import"],
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


def export_csaf(pkg_vulnerabilities, src_dir, reports_dir, bom_file):
    """
    Generates a CSAF 2.0 JSON document from the results.

    :param pkg_vulnerabilities: List of vulnerabilities
    :type pkg_vulnerabilities: list
    :param src_dir: The source directory.
    :type src_dir: str
    :param reports_dir: The reports directory.
    :type reports_dir: str
    :param bom_file: The BOM file path
    :type bom_file: str

    """
    toml_file_path = os.getenv(
        "DEPSCAN_CSAF_TEMPLATE", os.path.join(src_dir, "csaf.toml")
    )
    metadata = import_csaf_toml(toml_file_path)
    metadata = toml_compatibility(metadata)
    template = parse_toml(metadata)
    new_results = add_vulnerabilities(template, pkg_vulnerabilities)
    new_results = cleanup_dict(new_results)
    [new_results, metadata] = verify_components_present(
        new_results, metadata, bom_file
    )

    outfile = os.path.join(
        reports_dir,
        f"csaf_v{new_results['document']['tracking']['version']}.json",
    )

    with open(outfile, "w", encoding="utf-8") as f:
        json.dump(new_results, f, indent=4, sort_keys=True)
    LOG.info("CSAF report written to %s", outfile)
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
    try:
        with open(toml_file_path, "r", encoding="utf-8") as f:
            try:
                toml_data = toml.load(f)
            except toml.TomlDecodeError:
                LOG.error(
                    "Invalid TOML. Please make sure you do not have any "
                    "duplicate keys and that any filepaths are properly escaped"
                    "if using Windows."
                )
                sys.exit(1)
    except FileNotFoundError:
        write_toml(toml_file_path)
        return import_csaf_toml(toml_file_path)

    return toml_compatibility(toml_data)


def write_toml(toml_file_path, metadata=None):
    """
    Writes the toml data out to file. If no toml data is provided, a toml is
    generated based on the default template.

    :param toml_file_path: The filepath to save the TOML template to.
    :type toml_file_path: str
    :param metadata: A dictionary containing the TOML metadata.
    :type metadata: dict

    """
    if not metadata:
        metadata = TOML_TEMPLATE
    metadata["depscan_version"] = get_version()
    with open(toml_file_path, "w", encoding="utf-8") as f:
        toml.dump(metadata, f)
    LOG.debug("The csaf.toml has been updated at %s", toml_file_path)


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
    with open(bom_file, "r", encoding="utf-8") as f:
        bom = json.load(f)

    refs = []
    product_tree = {}

    if component := bom["metadata"].get("component"):
        product_tree = {
            "full_product_names": [
                {
                    "name": component.get("name"),
                    "product_id": f"{component.get('name')}:"
                    f"{component.get('version')}",
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
    if product_tree:
        LOG.debug("Successfully imported root component into the product tree.")
    else:
        LOG.debug(
            "Unable to import root component for product tree, so product "
            "tree will not be included."
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
    for r in pkg_vulnerabilities:
        new_vuln = vdr_to_csaf(r)
        if sev := new_vuln["scores"][0]["cvss_v3"].get("baseSeverity"):
            agg_score.add(SEVERITY_REF.get(sev.lower()))
        new_results["vulnerabilities"].append(new_vuln)
    if agg_score := list(agg_score):
        agg_score.sort()
        severity_ref = {v: k for k, v in SEVERITY_REF.items()}
        agg_severity = (
            severity_ref[agg_score[0]][0]
            + severity_ref[agg_score[0]][1:].lower()
        )
        new_results["document"]["aggregate_severity"] = {"text": agg_severity}

    return new_results
