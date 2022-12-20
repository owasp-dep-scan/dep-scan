# -*- coding: utf-8 -*-

import json
import os

from depscan.lib.logger import LOG


def identify_processing_flow(processing_obj):
    return "unknown"


def identify_sink_processing_flow(sink_processing_obj):
    flow = "unknown"
    sinkId = sink_processing_obj.get("sinkId", "").lower()
    if sinkId.endswith("write"):
        flow = "inbound"
    if sinkId.endswith("read"):
        flow = "outbound"
    return flow


def convert_processing(processing_list):
    data_list = []
    for p in processing_list:
        data_list.append(
            {"classification": p.get("sourceId"), "flow": identify_processing_flow(p)}
        )
    return data_list


def convert_sink_processing(sink_processing_list):
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
    endpoints = set()
    for c in collections_list:
        for occ in c.get("collections", []):
            for e in occ.get("occurrences", []):
                if e.get("endPoint"):
                    endpoints.add(e.get("endPoint"))
    return list(endpoints)


def convert_violations(violations):
    prop_list = []
    for v in violations:
        prop_list.append({"name": "privado_violations", "value": v.get("policyId")})
    return prop_list


def process_report(report_file):
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
                    {"name": "localScanPath", "value": json_obj.get("localScanPath")}
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
