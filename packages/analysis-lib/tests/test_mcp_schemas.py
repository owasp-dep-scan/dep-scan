"""Tests for the published `depscan mcp` tool schemas.

The twenty files pin the ten tools of the `depscan mcp` server: each tool's
arguments and its result document. The sample documents here are built from
the tool table and the committed scan-directory fixture, and validate against
the output schemas through the published validation entry point, which
resolves a schema's references to its sibling files.
"""

import json
from pathlib import Path
from typing import Any, Dict, List

import pytest
from jsonschema import Draft202012Validator

from analysis_lib.findings.schemas import load_schema, schema_names, validate

#: The ten tools, in the order the server registers them and the listing
#: carries their schemas: each tool's input schema, then its output schema.
MCP_TOOL_NAMES = (
    "scan_summary",
    "list_findings",
    "get_finding",
    "explain_finding",
    "coverage",
    "list_components",
    "diff_scans",
    "doctor",
    "vdb_status",
    "run_scan",
)

MCP_SCHEMA_NAMES = tuple(
    f"depscan-mcp-{tool}-{direction}"
    for tool in MCP_TOOL_NAMES
    for direction in ("input", "output")
)

_FIXTURE_DIR = (
    Path(__file__).parent.parent.parent.parent / "test" / "data" / "scan-directory"
)

#: The committed manifest of a real scan directory, the source of the
#: summary, stage and component examples below.
MANIFEST: Dict[str, Any] = json.loads(
    (_FIXTURE_DIR / "depscan.manifest.json").read_text(encoding="utf-8")
)

#: The first finding of the same fixture.
FINDING: Dict[str, Any] = json.loads(
    (_FIXTURE_DIR / "depscan.findings.json").read_text(encoding="utf-8")
)["findings"][0]

#: The fixture's BOM, the source of the component example.
BOM: Dict[str, Any] = json.loads(
    (_FIXTURE_DIR / "django-app.cdx.json").read_text(encoding="utf-8")
)

#: The fixture VDR's vulnerability, the shape the diff entries embed.
VULN: Dict[str, Any] = json.loads(
    (_FIXTURE_DIR / "django-app.vdr.json").read_text(encoding="utf-8")
)["vulnerabilities"][0]

_SCAN_DIR = "/tmp/scan/depscan-requests"

#: The cursor the examples carry: the base64url encoding of {"o": 1}, which
#: is the page-offset token shape the server documents.
_CURSOR = "eyJvIjogMX0="


def _valid(name: str, document: Any) -> None:
    validate(name, document)


def _invalid(name: str, document: Any) -> None:
    with pytest.raises(ValueError):
        validate(name, document)


# --- the listing places the twenty names in the tool table order -----------------


def test_the_listing_carries_the_twenty_names_in_the_tool_table_order():
    names = schema_names()
    mcp_names = [name for name in names if name.startswith("depscan-mcp-")]
    assert mcp_names == list(MCP_SCHEMA_NAMES)
    # After the verb outputs, before the error schema.
    assert names[names.index("depscan-help-output") + 1] == MCP_SCHEMA_NAMES[0]
    assert names[names.index(MCP_SCHEMA_NAMES[-1]) + 1] == "depscan-error"


@pytest.mark.parametrize("name", MCP_SCHEMA_NAMES)
def test_every_mcp_schema_is_valid_2020_12(name):
    Draft202012Validator.check_schema(load_schema(name))


@pytest.mark.parametrize("name", MCP_SCHEMA_NAMES)
def test_every_mcp_schema_carries_the_urn_id(name):
    schema = load_schema(name)
    assert schema["$id"] == f"urn:owasp:depscan:schema:{name[len('depscan-'):]}:1"


@pytest.mark.parametrize("name", MCP_SCHEMA_NAMES)
def test_every_mcp_property_has_a_description(name):
    """Walk the whole schema: every named property carries a description."""
    def _walk(node: Any) -> None:
        if isinstance(node, dict):
            for prop_name, prop in (node.get("properties") or {}).items():
                assert isinstance(prop.get("description"), str) and prop["description"], (
                    f"{name}: property {prop_name} has no description"
                )
            for value in node.values():
                _walk(value)
        elif isinstance(node, list):
            for value in node:
                _walk(value)

    _walk(load_schema(name))


# --- the scan_summary examples ---------------------------------------------------


def _stages_by_status(stages: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for stage in stages:
        counts[stage["status"]] = counts.get(stage["status"], 0) + 1
    return counts


def _project_types(stages: List[Dict[str, Any]]) -> List[str]:
    types = []
    for stage in stages:
        project_type = stage.get("projectType")
        if project_type and project_type not in types:
            types.append(project_type)
    return types


def _scan_summary_document() -> Dict[str, Any]:
    return {
        "scanDir": _SCAN_DIR,
        "manifestSummary": {
            "layoutVersion": MANIFEST["layoutVersion"],
            "depscanVersion": MANIFEST["depscanVersion"],
            "startUtc": MANIFEST["startUtc"],
            "endUtc": MANIFEST["endUtc"],
            "projectTypes": _project_types(MANIFEST["stages"]),
            "stageCount": len(MANIFEST["stages"]),
            "stagesByStatus": _stages_by_status(MANIFEST["stages"]),
            "inputCount": len(MANIFEST["inputs"]),
            "fileCount": len(MANIFEST["files"]),
        },
        "findingCount": 1,
        "countsByCategory": {"vulnerability": 1},
        "countsBySeverity": {"high": 1},
    }


def test_scan_summary_output_validates():
    _valid("depscan-mcp-scan_summary-output", _scan_summary_document())


def test_scan_summary_output_validates_without_a_manifest():
    document = _scan_summary_document()
    document["manifestSummary"] = None
    document["findingCount"] = 3
    document["countsByCategory"] = {}
    document["countsBySeverity"] = {"unknown": 3}
    _valid("depscan-mcp-scan_summary-output", document)


def test_scan_summary_output_counts_agree_with_the_fixture():
    document = _scan_summary_document()
    summary = document["manifestSummary"]
    statuses = [stage["status"] for stage in MANIFEST["stages"]]
    assert summary["stageCount"] == len(statuses) == 8
    assert summary["stagesByStatus"] == {"completed": 6, "skipped": 2}
    assert summary["projectTypes"] == ["bom"]
    assert summary["inputCount"] == 1 and summary["fileCount"] == 6
    # The finding counts say what the fixture findings carry.
    assert document["findingCount"] == 1
    assert document["countsByCategory"] == {"vulnerability": 1}
    assert document["countsBySeverity"] == {"high": 1}


def test_scan_summary_output_rejects():
    _invalid("depscan-mcp-scan_summary-output", {"scanDir": _SCAN_DIR})
    # The manifestSummary carries the summary, not the manifest itself.
    document = _scan_summary_document()
    document["manifestSummary"] = MANIFEST
    _invalid("depscan-mcp-scan_summary-output", document)
    _invalid("depscan-mcp-scan_summary-output", _scan_summary_document() | {"extra": True})


# --- the list_findings envelopes -------------------------------------------------


def test_list_findings_output_validates_as_a_page():
    _valid("depscan-mcp-list_findings-output", {"findings": [FINDING]})
    _valid("depscan-mcp-list_findings-output", {"findings": [], "nextCursor": _CURSOR})


def test_list_findings_output_validates_as_a_spill():
    _valid(
        "depscan-mcp-list_findings-output",
        {"file": f"{_SCAN_DIR}/mcp/list_findings-3f2ac1bf.json", "count": 240},
    )


def test_list_findings_output_rejects_a_mixed_or_incomplete_envelope():
    _invalid(
        "depscan-mcp-list_findings-output",
        {"findings": [FINDING], "file": f"{_SCAN_DIR}/mcp/x.json", "count": 1},
    )
    _invalid("depscan-mcp-list_findings-output", {"findings": [FINDING], "nextCursor": ""})
    _invalid("depscan-mcp-list_findings-output", {"file": f"{_SCAN_DIR}/mcp/x.json"})
    # The page carries findings, not the raw manifest.
    _invalid("depscan-mcp-list_findings-output", {"findings": [MANIFEST]})


# --- the get_finding result ------------------------------------------------------


def test_get_finding_output_validates():
    _valid("depscan-mcp-get_finding-output", FINDING)


def test_get_finding_output_rejects_anything_that_is_not_a_finding():
    _invalid("depscan-mcp-get_finding-output", {"findings": [FINDING]})
    partial = dict(FINDING)
    del partial["severity"]
    _invalid("depscan-mcp-get_finding-output", partial)


# --- the explain_finding result --------------------------------------------------


def test_explain_finding_output_validates():
    _valid(
        "depscan-mcp-explain_finding-output",
        {"finding": FINDING, "explanation": "Reachable Flows\n\nThe function handle() is reachable."},
    )


def test_explain_finding_output_rejects_an_empty_or_missing_explanation():
    _invalid("depscan-mcp-explain_finding-output", {"finding": FINDING})
    _invalid("depscan-mcp-explain_finding-output", {"finding": FINDING, "explanation": ""})


# --- the coverage example --------------------------------------------------------


def _coverage_document() -> Dict[str, Any]:
    not_assessed = []
    for stage in MANIFEST["stages"]:
        for reason in stage.get("notAssessed") or []:
            not_assessed.append({"stage": stage["name"], "reason": reason})
        for analyzer in stage.get("analyzers") or []:
            if analyzer["status"] == "not-assessed":
                not_assessed.append(
                    {
                        "stage": stage["name"],
                        "analyzer": analyzer["name"],
                        "reason": analyzer["reason"],
                    }
                )
    return {
        "scanDir": _SCAN_DIR,
        "stages": MANIFEST["stages"],
        "notAssessedReasons": not_assessed,
        "checksNotRun": [],
    }


def test_coverage_output_validates():
    _valid("depscan-mcp-coverage-output", _coverage_document())


def test_coverage_output_validates_with_a_check_not_run():
    document = _coverage_document()
    document["checksNotRun"] = [{"name": "license", "reason": "license analysis was not requested"}]
    _valid("depscan-mcp-coverage-output", document)


def test_coverage_output_reasons_come_from_the_fixture_stages():
    document = _coverage_document()
    analyzers = [entry["analyzer"] for entry in document["notAssessedReasons"]]
    # The fixture's enrichment stage recorded five analyzers, none of whose
    # adapters read a report for this scan.
    assert analyzers == ["atom", "rusi", "golem", "kosi", "dosai"]
    assert all(entry["stage"] == "enrichment" for entry in document["notAssessedReasons"])


def test_coverage_output_rejects():
    _invalid("depscan-mcp-coverage-output", {"scanDir": _SCAN_DIR, "stages": []})
    document = _coverage_document()
    document["checksNotRun"] = [{"reason": "a check entry without a name"}]
    _invalid("depscan-mcp-coverage-output", document)
    document = _coverage_document()
    document["notAssessedReasons"][0]["severity"] = "unknown field"
    _invalid("depscan-mcp-coverage-output", document)


# --- the list_components envelopes -----------------------------------------------


def _component_projection(component: Dict[str, Any]) -> Dict[str, Any]:
    document: Dict[str, Any] = {"name": component["name"], "type": component["type"]}
    for source, target in (("version", "version"), ("purl", "purl"), ("bom-ref", "bomRef")):
        if component.get(source):
            document[target] = component[source]
    return document


def _components_page() -> Dict[str, Any]:
    return {
        "components": [_component_projection(c) for c in BOM.get("components") or []],
    }


def test_list_components_output_validates_as_a_page():
    _valid("depscan-mcp-list_components-output", _components_page())
    page = _components_page()
    page["nextCursor"] = _CURSOR
    _valid("depscan-mcp-list_components-output", page)


def test_list_components_output_validates_as_a_spill():
    _valid(
        "depscan-mcp-list_components-output",
        {"file": f"{_SCAN_DIR}/mcp/list_components-9b1d0c4e.json", "count": 512},
    )


def test_list_components_output_carries_the_identity_fields():
    page = _components_page()
    # The fixture BOM holds one library whose purl and bom-ref are the same.
    assert page["components"] == [
        {
            "name": "requests",
            "type": "library",
            "version": "2.32.1",
            "purl": "pkg:pypi/requests@2.32.1",
            "bomRef": "pkg:pypi/requests@2.32.1",
        }
    ]


def test_list_components_output_rejects():
    _invalid("depscan-mcp-list_components-output", {"components": [{"name": "requests"}]})
    _invalid("depscan-mcp-list_components-output", {"components": [{"name": "r", "type": "library"}], "file": "x"})
    _invalid(
        "depscan-mcp-list_components-output",
        {"components": [_component_projection(BOM["components"][0]) | {"hashes": []}]},
    )


# --- the diff_scans example ------------------------------------------------------


def _vuln_ref(vuln: Dict[str, Any]) -> Any:
    affects = vuln.get("affects") or []
    return affects[0]["ref"] if affects else None


def _changed_vuln() -> Dict[str, Any]:
    rating = dict(VULN["ratings"][0])
    rating.update(severity="critical", score=9.8)
    return VULN | {"ratings": [rating]}


def _diff_document() -> Dict[str, Any]:
    return {
        "new": [{"id": VULN["id"], "ref": _vuln_ref(VULN), "old": None, "new": VULN}],
        "fixed": [
            {
                "id": "CVE-2020-8203",
                "ref": "pkg:pypi/lodash@4.6.1",
                "old": VULN,
                "new": None,
            }
        ],
        "changed": [
            {
                "id": VULN["id"],
                "ref": _vuln_ref(VULN),
                "old": VULN,
                "new": _changed_vuln(),
            }
        ],
    }


def test_diff_scans_output_validates():
    _valid("depscan-mcp-diff_scans-output", _diff_document())


def test_diff_scans_output_validates_when_empty():
    _valid(
        "depscan-mcp-diff_scans-output",
        {"new": [], "fixed": [], "changed": []},
    )


def test_diff_scans_output_rejects():
    document = _diff_document()
    del document["fixed"]
    _invalid("depscan-mcp-diff_scans-output", document)
    document = _diff_document()
    del document["new"][0]["ref"]
    _invalid("depscan-mcp-diff_scans-output", document)
    document = _diff_document()
    document["new"][0]["old"] = "the earlier vulnerability as a string"
    _invalid("depscan-mcp-diff_scans-output", document)


# --- the doctor and vdb_status results -------------------------------------------

#: The smallest document the doctor schema accepts, hand-built from its
#: required fields: one report with no tools and no capabilities, whose
#: database was never downloaded.
MINIMAL_DOCTOR_REPORT = {
    "schemaVersion": "1",
    "depscanVersion": "7.0.0",
    "platform": {"os": "linux", "arch": "x86_64", "libc": None},
    "tools": [],
    "data": {
        "vulnerabilityDatabase": {
            "present": False,
            "directory": None,
            "image": None,
            "flavor": None,
            "shards": {"enabled": False, "present": []},
            "createdUtc": None,
            "ageHours": None,
            "stale": None,
            "maxAgeHours": 72,
            "cveDataCount": None,
            "cveIndexCount": None,
            "extendedMetadataPresent": None,
            "cveMetadataRows": None,
        }
    },
    "capabilities": [],
}


def test_doctor_output_validates():
    _valid("depscan-mcp-doctor-output", MINIMAL_DOCTOR_REPORT)
    _invalid("depscan-mcp-doctor-output", {"schemaVersion": "1"})


def _vdb_info_document() -> Dict[str, Any]:
    return {
        "vdbHome": "/tmp/vdb",
        "marker": "ghcr.io/appthreat/vdb7-app-only:main",
        "markerKind": "image",
        "flavor": "app-only",
        "mainDb": {
            "builtUtc": "2026-11-01T00:00:00Z",
            "stale": False,
            "maxAgeHours": 72,
            "completeness": "full",
            "dataRows": 300000,
            "indexRows": 280000,
        },
        "metadataRows": 0,
        "extendedFlavor": False,
        "shardStore": {
            "storeDir": "/tmp/vdb/shards",
            "shards": [],
            "coverage": "full",
            "mixedBuilds": False,
            "missingGroupShards": [],
        },
    }


def test_vdb_status_output_validates():
    _valid("depscan-mcp-vdb_status-output", _vdb_info_document())
    _invalid("depscan-mcp-vdb_status-output", {"vdbHome": "/tmp/vdb"})


# --- the run_scan results --------------------------------------------------------


def _dry_run_document() -> Dict[str, Any]:
    return {
        "argv": ["depscan", "scan", "--profile", "quick", "/tmp/project/src"],
        "options": {
            "options": {
                "profile": {"value": "quick", "source": "command line"},
                "reachability_analyzer": {"value": "FrameworkReachability", "source": "default"},
                "reports_dir": {"value": None, "source": "default"},
            }
        },
    }


def _scan_entry() -> Dict[str, Any]:
    return {
        "target": "pkg:pypi/requests@2.31.0",
        "kind": "purl",
        "scanDir": _SCAN_DIR,
        "manifest": MANIFEST,
        "findings": [FINDING],
    }


def test_run_scan_output_validates_as_a_dry_run():
    _valid("depscan-mcp-run_scan-output", _dry_run_document())


def test_run_scan_output_validates_as_a_scanned_entry():
    _valid("depscan-mcp-run_scan-output", _scan_entry())


def test_run_scan_output_validates_as_a_refused_entry():
    _valid(
        "depscan-mcp-run_scan-output",
        {"target": "/tmp/project/missing", "kind": None, "error": "The source target does not exist."},
    )


def test_run_scan_output_rejects_a_bare_dry_run_or_a_neither_shape():
    _invalid("depscan-mcp-run_scan-output", {"argv": ["depscan", "scan", "/tmp/project/src"]})
    _invalid("depscan-mcp-run_scan-output", {"options": {"options": {}}})
    _invalid("depscan-mcp-run_scan-output", {"target": "t", "kind": "bogus-kind"})


# --- the input schemas -----------------------------------------------------------


def test_scan_summary_input_validates():
    _valid("depscan-mcp-scan_summary-input", {"scan_dir": _SCAN_DIR})
    _invalid("depscan-mcp-scan_summary-input", {})
    _invalid("depscan-mcp-scan_summary-input", {"scan_dir": _SCAN_DIR, "category": "vulnerability"})


def test_list_findings_input_validates_with_every_filter():
    _valid(
        "depscan-mcp-list_findings-input",
        {
            "scan_dir": _SCAN_DIR,
            "category": "vulnerability",
            "severity": "high",
            "purl": "pkg:pypi/requests@2.32.1",
            "cwe": 400,
            "rule": "CVE-2024-1111",
            "reachable": True,
            "cursor": _CURSOR,
            "limit": 200,
        },
    )
    _valid("depscan-mcp-list_findings-input", {"scan_dir": _SCAN_DIR})


def test_list_findings_input_rejects_a_filter_outside_the_finding_schema():
    _invalid(
        "depscan-mcp-list_findings-input",
        {"scan_dir": _SCAN_DIR, "license": "MIT"},
    )
    _invalid(
        "depscan-mcp-list_findings-input",
        {"scan_dir": _SCAN_DIR, "category": "everything"},
    )


def test_list_findings_input_rejects_a_limit_over_200():
    _invalid("depscan-mcp-list_findings-input", {"scan_dir": _SCAN_DIR, "limit": 201})
    _invalid("depscan-mcp-list_findings-input", {"scan_dir": _SCAN_DIR, "limit": 0})
    _invalid("depscan-mcp-list_findings-input", {"scan_dir": _SCAN_DIR, "cursor": 5})


def test_get_finding_input_validates():
    _valid("depscan-mcp-get_finding-input", {"scan_dir": _SCAN_DIR, "finding_id": FINDING["id"]})
    _invalid("depscan-mcp-get_finding-input", {"scan_dir": _SCAN_DIR})
    _invalid(
        "depscan-mcp-get_finding-input",
        {"scan_dir": _SCAN_DIR, "finding_id": "CVE-2024-1111"},
    )


def test_explain_finding_input_validates():
    arguments = {"scan_dir": _SCAN_DIR, "finding_id": FINDING["id"]}
    _valid("depscan-mcp-explain_finding-input", arguments)
    _valid("depscan-mcp-explain_finding-input", arguments | {"mode": "Endpoints"})
    _valid("depscan-mcp-explain_finding-input", arguments | {"mode": "LLMPrompts"})
    _invalid("depscan-mcp-explain_finding-input", arguments | {"mode": "FlowGraph"})
    _invalid("depscan-mcp-explain_finding-input", {"scan_dir": _SCAN_DIR})


def test_coverage_input_validates():
    _valid("depscan-mcp-coverage-input", {"scan_dir": _SCAN_DIR})
    _invalid("depscan-mcp-coverage-input", {})


def test_list_components_input_validates():
    _valid("depscan-mcp-list_components-input", {"scan_dir": _SCAN_DIR, "limit": 50})
    _invalid("depscan-mcp-list_components-input", {"scan_dir": _SCAN_DIR, "limit": 201})
    _invalid("depscan-mcp-list_components-input", {"scan_dir": _SCAN_DIR, "purl": "pkg:pypi/x"})


def test_diff_scans_input_validates():
    _valid("depscan-mcp-diff_scans-input", {"old_scan_dir": _SCAN_DIR, "new_scan_dir": "/tmp/scan/new"})
    _invalid("depscan-mcp-diff_scans-input", {"old_scan_dir": _SCAN_DIR})
    _invalid(
        "depscan-mcp-diff_scans-input",
        {"old_scan_dir": _SCAN_DIR, "new_scan_dir": "/tmp/scan/new", "profile": "quick"},
    )


@pytest.mark.parametrize("name", ["depscan-mcp-doctor-input", "depscan-mcp-vdb_status-input"])
def test_the_no_argument_inputs_accept_only_the_empty_object(name):
    _valid(name, {})
    _invalid(name, {"scan_dir": _SCAN_DIR})


def test_run_scan_input_validates():
    _valid("depscan-mcp-run_scan-input", {"target": "/tmp/project/src"})
    _valid(
        "depscan-mcp-run_scan-input",
        {
            "target": "pkg:pypi/requests@2.31.0",
            "execute": True,
            "reports_dir": "/tmp/scan/out",
            "profile": "deep",
            "checks": ["reachability", "license"],
            "reachability_analyzer": "SemanticReachability",
            "explain": True,
        },
    )


def test_run_scan_input_rejects_unknown_or_wrong_typed_arguments():
    _invalid("depscan-mcp-run_scan-input", {})
    _invalid("depscan-mcp-run_scan-input", {"target": "/tmp/project/src", "execute": "yes"})
    _invalid(
        "depscan-mcp-run_scan-input",
        {"target": "/tmp/project/src", "checks": ["vulnerabilities", "vulnerabilities"]},
    )
    _invalid(
        "depscan-mcp-run_scan-input",
        {"target": "/tmp/project/src", "checks": ["policy"]},
    )
    _invalid(
        "depscan-mcp-run_scan-input",
        {"target": "/tmp/project/src", "reachability_analyzer": "atom"},
    )
    _invalid(
        "depscan-mcp-run_scan-input",
        {"target": "/tmp/project/src", "profile": "thorough"},
    )
