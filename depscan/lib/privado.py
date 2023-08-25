# -*- coding: utf-8 -*-

import json
import os

from depscan.lib.logger import LOG


def identify_processing_flow():
    """

    :return:
    """
    return "unknown"


def identify_sink_processing_flow(sink_processing_obj):
    """
    Takes a dictionary object sink_processing_obj as input and returns a
    string indicating the flow type based on the value of the "sinkId" key in
    the input dictionary.

    :param sink_processing_obj: A dictionary
    :return: A string indicating the flow type
    """
    flow = "unknown"
    sink_id = sink_processing_obj.get("sinkId", "").lower()
    if sink_id.endswith("write"):
        flow = "inbound"
    if sink_id.endswith("read"):
        flow = "outbound"
    return flow


def convert_processing(processing_list):
    """
    Takes a list of processing objects as input and converts them into a list
    of dictionaries with specific keys and values.

    :param processing_list: List of processing objects
    :return: A list of processing object dictionaries
    """
    data_list = []
    for p in processing_list:
        data_list.append(
            {
                "classification": p.get("sourceId"),
                "flow": identify_processing_flow(),
            }
        )
    return data_list


def convert_sink_processing(sink_processing_list):
    """
    Takes a list of sink processing objects as input and converts each object
    into a dictionary with the classification and flow properties.

    :param sink_processing_list: List of sink processing objects
    :return: List of dictionaries of converted sink objects
    """
    data_list = []
    for p in sink_processing_list:
        data_list.append(
            {
                "classification": p.get("sinkId"),
                "flow": identify_sink_processing_flow(p),
            }
        )
    return data_list


def find_endpoints(collections_list):
    """
    Takes a list of collections as input and returns a list of unique
    endpoints found in those collections

    :param collections_list: collections from a json object
    :return: A list of unique endpoints
    """
    endpoints = set()
    for c in collections_list:
        for occ in c.get("collections", []):
            for e in occ.get("occurrences", []):
                if e.get("endPoint"):
                    endpoints.add(e.get("endPoint"))
    return list(endpoints)


def convert_violations(violations):
    """
    Takes a list of violations as input and converts them into a list of
    property dictionaries. Each violation in the input list is transformed
    into a property dictionary with the name "privado_violations" and the
    value of the "policyId" attribute of the violation.

    :param violations: Dictionary of violations
    :return: List of privado violation dictionaries
    """
    prop_list = []
    for v in violations:
        prop_list.append({"name": "privado_violations", "value": v.get("policyId")})
    return prop_list


def process_report(report_file):
    """
    Takes a report_file as input and processes the JSON data in the file to
    extract relevant information. It converts the processing objects,
    sink processing objects, violations, and collections into a structured
    format. The function returns a dictionary containing the extracted
    information.

    :param report_file: Path to the json report file.
    :return: A dict of extracted information from the JSON report file.
    """
    if not report_file or not os.path.exists(report_file):
        return {}
    with open(report_file) as fp:
        try:
            json_obj = json.load(fp)
        except Exception as ex:
            LOG.exception(ex)
            return {}
        service = {}
        # Capture generic metadata
        if json_obj.get("repoName"):
            service["name"] = json_obj.get("repoName")
            service["properties"] = []
            if json_obj.get("gitMetadata"):
                service["version"] = json_obj.get("gitMetadata").get("commitId", "")
                service["properties"].append(
                    {
                        "name": "privadoCoreVersion",
                        "value": json_obj.get("privadoCoreVersion"),
                    }
                )
                service["properties"].append(
                    {
                        "name": "privadoCLIVersion",
                        "value": json_obj.get("privadoCLIVersion"),
                    }
                )
                service["properties"].append(
                    {
                        "name": "localScanPath",
                        "value": json_obj.get("localScanPath"),
                    }
                )
        service["data"] = []
        # Convert processing block
        if json_obj.get("processing"):
            service["data"] += convert_processing(json_obj.get("processing"))
        # Convert sink processing block
        if json_obj.get("sinkProcessing"):
            service["data"] += convert_sink_processing(json_obj.get("sinkProcessing"))
        if json_obj.get("collections"):
            service["endpoints"] = find_endpoints(json_obj.get("collections"))
        if json_obj.get("violations"):
            service["properties"] += convert_violations(json_obj.get("violations"))
        return service
