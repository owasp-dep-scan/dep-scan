"""Tests for the published verb output schemas and the error schema.

Every file in the schemas directory must itself be a valid draft 2020-12
schema that carries the published $id and a title, and the sample documents
hand-built here pin what each verb output schema accepts and refuses.
"""

import copy
import json
from pathlib import Path
from typing import Any, Dict

import pytest
from jsonschema import Draft202012Validator

import analysis_lib.findings.schemas as schemas_module
from analysis_lib.findings.schemas import (
    load_schema,
    published_files,
    schema_names,
    schema_summaries,
    validate,
)

SCHEMA_NAMES = schema_names()

#: A manifest-shaped document: the committed fixture of a real scan directory.
MANIFEST = json.loads(
    (
        Path(__file__).parent.parent.parent.parent
        / "test"
        / "data"
        / "scan-directory"
        / "depscan.manifest.json"
    ).read_text(encoding="utf-8")
)

#: A finding-shaped document: the first finding of the same fixture.
FINDING = json.loads(
    (
        Path(__file__).parent.parent.parent.parent
        / "test"
        / "data"
        / "scan-directory"
        / "depscan.findings.json"
    ).read_text(encoding="utf-8")
)["findings"][0]


def _valid(name: str, document: Any) -> None:
    """The published validation entry point accepts ``document``.

    The loader's registry is what resolves a schema's references to its
    sibling files, so the tests go through it instead of a bare validator,
    which would fetch the referenced schemas from the network.
    """
    validate(name, document)


def _invalid(name: str, document: Any) -> None:
    with pytest.raises(ValueError):
        validate(name, document)


# --- every published file is a valid schema with its $id and a title -------------


@pytest.mark.parametrize("name", SCHEMA_NAMES)
def test_every_schema_is_valid_2020_12(name):
    Draft202012Validator.check_schema(load_schema(name))


@pytest.mark.parametrize("name", SCHEMA_NAMES)
def test_every_schema_carries_the_published_id_and_a_title(name):
    schema = load_schema(name)
    # The finding schema moved to version 2 when its exploitability axes
    # dropped Pressure and gained sources, and to version 3 when its triage
    # object gained approver and proposed_by beside a per-finding baseline
    # state; the manifest schema moved to version 2 when analyzer entries
    # gained their caveats array and to version 3 when it gained the
    # decisions record and the expectations file role; the report output
    # moved to version 2 when it gained the expectations document; every
    # other schema is at 1.
    versions = {
        "depscan-finding": 3,
        "depscan-manifest": 3,
        "depscan-report-output": 2,
        "depscan-scan-output": 2,
        "depscan-mcp-scan_summary-output": 2,
    }
    version = versions.get(name, 1)
    assert schema["$id"] == f"urn:owasp:depscan:schema:{name[len('depscan-') :]}:{version}"
    assert isinstance(schema["title"], str) and schema["title"]
    assert isinstance(schema.get("description"), str) and schema["description"]


def test_every_file_in_the_directory_is_listed():
    assert {schemas_module._STEM_TO_FILE[name] for name in SCHEMA_NAMES} == set(published_files())


def test_the_listing_order_is_the_registration_order():
    summaries = schema_summaries()
    assert [entry["name"] for entry in summaries] == SCHEMA_NAMES
    assert summaries[0] == {
        "name": "depscan-finding",
        "$id": "urn:owasp:depscan:schema:finding:3",
        "title": "dep-scan finding",
    }
    assert summaries[-1]["name"] == "depscan-error"
    for entry in summaries:
        schema = load_schema(entry["name"])
        assert entry["$id"] == schema["$id"]
        assert entry["title"] == schema["title"]


def test_the_document_schemas_come_first_and_the_error_schema_last():
    assert SCHEMA_NAMES[:5] == [
        "depscan-finding",
        "depscan-doctor",
        "depscan-manifest",
        "depscan-evidence",
        "depscan-exploitability-rules",
    ]
    assert SCHEMA_NAMES[-1] == "depscan-error"


# --- the error document ----------------------------------------------------------


def test_error_document_validates():
    _valid(
        "depscan-error",
        {
            "error": {
                "exitCode": 2,
                "verb": "scan",
                "message": "depscan scan: unknown check bogus",
                "details": {"unknownChecks": ["bogus"]},
            }
        },
    )
    _valid(
        "depscan-error",
        {"error": {"exitCode": 4, "verb": "doctor", "message": "unmet requirement"}},
    )


@pytest.mark.parametrize(
    "document",
    [
        # An exit code outside the table.
        {"error": {"exitCode": 3, "verb": "scan", "message": "nope"}},
        {"error": {"exitCode": 0, "verb": "scan", "message": "fine"}},
        # A missing field.
        {"error": {"exitCode": 1, "message": "no verb named"}},
        {"error": {"exitCode": 1, "verb": "vdb"}},
        # An unknown field at either level.
        {"error": {"exitCode": 1, "verb": "vdb", "message": "m", "hint": "x"}},
        {"error": {"exitCode": 1, "verb": "vdb", "message": "m"}, "extra": True},
    ],
)
def test_error_document_rejects(document):
    _invalid("depscan-error", document)


# --- the scan output -------------------------------------------------------------


def _scanned_entry() -> Dict[str, Any]:
    return {
        "target": "pkg:pypi/requests@2.31.0",
        "kind": "purl",
        "scanDir": "/tmp/scan/depscan-requests",
        "manifest": MANIFEST,
        "findings": [FINDING],
    }


def test_scan_output_validates_with_a_scanned_entry():
    _valid("depscan-scan-output", {"scans": [_scanned_entry()]})


def test_scan_output_validates_with_a_refused_entry():
    _valid(
        "depscan-scan-output",
        {
            "scans": [
                {"target": "./missing", "kind": None, "error": "The source target does not exist."}
            ]
        },
    )


def test_scan_output_manifest_may_be_null_for_a_stopped_scan():
    entry = _scanned_entry()
    entry["manifest"] = None
    entry["findings"] = []
    _valid("depscan-scan-output", {"scans": [entry]})


def test_scan_output_rejects_a_bare_array_or_a_kindless_success():
    _invalid("depscan-scan-output", [_scanned_entry()])
    entry = _scanned_entry()
    del entry["scanDir"]
    _invalid("depscan-scan-output", {"scans": [entry]})
    _invalid("depscan-scan-output", {"scans": [{"target": "t", "kind": "bogus-kind"}]})


def test_scan_output_rejects_an_entry_that_is_neither_scanned_nor_refused():
    _invalid("depscan-scan-output", {"scans": [{"target": "t", "kind": None}]})
    _invalid("depscan-scan-output", {"scans": [{"target": "t", "kind": "source", "error": "x"}]})


# --- the report output -----------------------------------------------------------


def test_report_output_validates():
    _valid(
        "depscan-report-output",
        {
            "scanDir": "/tmp/scan/depscan-requests",
            "manifest": MANIFEST,
            "findings": [FINDING],
        },
    )
    _invalid("depscan-report-output", {"scanDir": "/tmp/scan", "manifest": MANIFEST})


def test_report_output_carries_the_expectations_document():
    from analysis_lib.findings.decisions import decisions_from_document, evaluate_gate

    decisions = decisions_from_document(
        {"expect": [{"id": "no-high", "severity": "high", "action": "fail"}]}
    )
    expectations = evaluate_gate([FINDING], [], decisions).to_document(
        evaluated_utc="2026-11-27T12:00:00Z", source="report"
    )
    document = {
        "scanDir": "/tmp/scan/depscan-requests",
        "manifest": MANIFEST,
        "findings": [FINDING],
        "expectations": expectations,
    }
    _valid("depscan-report-output", document)
    _invalid("depscan-report-output", dict(document, expectations={"summary": {}}))


# --- the manifest's analyzer caveats ----------------------------------------------


def _manifest_with_analyzer_caveats() -> Dict[str, Any]:
    manifest = copy.deepcopy(MANIFEST)
    for stage in manifest["stages"]:
        for analyzer in stage.get("analyzers") or []:
            analyzer["caveats"] = [
                {"kind": "timeout", "detail": "the atom run stopped at its timeout"}
            ]
            return manifest
    raise AssertionError("the fixture manifest carries no analyzer entries")


def test_a_manifest_analyzer_entry_may_carry_caveats():
    _valid("depscan-manifest", _manifest_with_analyzer_caveats())


def test_a_manifest_analyzer_caveat_names_a_known_kind_and_a_detail():
    manifest = _manifest_with_analyzer_caveats()
    for stage in manifest["stages"]:
        for analyzer in stage.get("analyzers") or []:
            analyzer["caveats"] = [{"kind": "vibes", "detail": "unknown kind"}]
    _invalid("depscan-manifest", manifest)
    manifest = _manifest_with_analyzer_caveats()
    for stage in manifest["stages"]:
        for analyzer in stage.get("analyzers") or []:
            analyzer["caveats"] = [{"kind": "timeout"}]
    _invalid("depscan-manifest", manifest)


# --- the doctor output -----------------------------------------------------------

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


def test_doctor_output_is_the_doctor_schema():
    _valid("depscan-doctor-output", MINIMAL_DOCTOR_REPORT)
    # The reference bites: a document that is not a doctor report is refused.
    _invalid("depscan-doctor-output", {"schemaVersion": "1"})


# --- the vdb outputs -------------------------------------------------------------


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
            "shards": [
                {
                    "name": "npm",
                    "buildId": "2026.11.1",
                    "builtUtc": "2026-11-01T00:00:00Z",
                    "ageDays": 2.5,
                    "typeCount": 3,
                    "types": ["npm"],
                    "stale": False,
                }
            ],
            "coverage": "partial (missing: pypi)",
            "mixedBuilds": False,
            "missingGroupShards": ["pypi"],
        },
    }


def test_vdb_info_output_validates_with_and_without_a_database():
    _valid("depscan-vdb-info-output", _vdb_info_document())
    empty = _vdb_info_document()
    empty.update(marker=None, markerKind=None, flavor=None, mainDb=None, metadataRows=0)
    empty["shardStore"].update(shards=[], coverage="full", missingGroupShards=[])
    _valid("depscan-vdb-info-output", empty)
    # A row count the metadata does not carry is the string ?.
    partial = _vdb_info_document()
    partial["mainDb"]["dataRows"] = "?"
    partial["mainDb"]["indexRows"] = "?"
    _valid("depscan-vdb-info-output", partial)


def test_vdb_download_output_validates_both_variants():
    # The download document's marker is the path of the marker file the
    # download wrote, .depscan-vdb-image under the vdb home, not the
    # recorded image reference or shard-set marker the info document
    # reports under the same field name.
    marker_path = "/tmp/vdb/.depscan-vdb-image"
    _valid(
        "depscan-vdb-download-output",
        {"image": "ghcr.io/appthreat/vdb7:main", "marker": marker_path},
    )
    _valid("depscan-vdb-download-output", {"shards": ["npm", "pypi"], "marker": marker_path})
    _invalid("depscan-vdb-download-output", {"marker": marker_path})
    _invalid(
        "depscan-vdb-download-output", {"image": "x", "shards": ["npm"], "marker": marker_path}
    )


def test_vdb_path_output_validates():
    _valid("depscan-vdb-path-output", {"path": "/tmp/vdb"})
    _invalid("depscan-vdb-path-output", {"path": "/tmp/vdb", "extra": 1})


# --- the schema listing ----------------------------------------------------------


def test_schema_output_matches_what_the_listing_prints():
    _valid("depscan-schema-output", {"schemas": schema_summaries()})
    _invalid("depscan-schema-output", {"schemas": ["depscan-finding"]})
    _invalid(
        "depscan-schema-output",
        {"schemas": [{"name": "depscan-finding", "title": "no id"}]},
    )


# --- the config outputs ----------------------------------------------------------


def test_config_show_output_validates():
    _valid(
        "depscan-config-show-output",
        {
            "options": {
                "reports_dir": {"value": "/tmp/reports", "source": "command line"},
                "project_type": {"value": ["python"], "source": "checks or profile"},
                "spec_version": {"value": "1.6", "source": "depscan.toml"},
                "deep_scan": {"value": True, "source": "environment"},
                "severity": {"value": None, "source": "default"},
            }
        },
    )
    _invalid(
        "depscan-config-show-output",
        {"options": {"reports_dir": {"value": "/tmp/reports", "source": "somewhere"}}},
    )


def test_config_init_output_validates():
    _valid("depscan-config-init-output", {"written": "/tmp/project/depscan.toml"})
    _invalid("depscan-config-init-output", {"written": None})


# --- the serve, validate, version and help outputs -------------------------------


def test_serve_output_validates():
    _valid(
        "depscan-serve-output",
        {"serving": {"host": "127.0.0.1", "port": 7070, "url": "http://127.0.0.1:7070"}},
    )
    _valid(
        "depscan-serve-output",
        {"serving": {"host": "0.0.0.0", "port": 7070, "url": "http://127.0.0.1:7070"}},
    )
    _invalid(
        "depscan-serve-output",
        {"serving": {"host": "127.0.0.1", "port": "7070"}},
    )
    # The port is a number, and an IPv6 host is bracketed in the URL.
    _valid(
        "depscan-serve-output",
        {"serving": {"host": "::1", "port": 7070, "url": "http://[::1]:7070"}},
    )
    _invalid(
        "depscan-serve-output",
        {"serving": {"host": "127.0.0.1", "port": "7070", "url": "http://127.0.0.1:7070"}},
    )
    _invalid(
        "depscan-serve-output",
        {"serving": {"host": "::1", "port": 7070, "url": "http://::1:7070"}},
    )


def _validate_result(file: str, fmt, valid: bool, errors) -> Dict[str, Any]:
    return {"file": file, "format": fmt, "valid": valid, "errors": errors}


def test_validate_output_validates():
    _valid(
        "depscan-validate-output",
        {
            "results": [
                _validate_result("/tmp/doc.csaf.json", "csaf", True, []),
                _validate_result(
                    "/tmp/doc.vdr.json", "cyclonedx", False, ["specVersion is missing"]
                ),
                _validate_result("/tmp/missing.json", None, False, ["could not read JSON"]),
                _validate_result("/tmp/other.json", "unknown", False, ["format not detected"]),
            ]
        },
    )
    _invalid(
        "depscan-validate-output",
        {"results": [{"file": "/tmp/doc.json", "format": "csaf", "valid": True}]},
    )


def test_version_output_validates():
    _valid(
        "depscan-version-output", {"version": "7.0.0", "tools": {"cdxgen": "11.1.0", "rusi": None}}
    )
    _invalid("depscan-version-output", {"version": "7.0.0"})


def test_help_output_validates():
    _valid("depscan-help-output", {"help": "usage: depscan ..."})
    _invalid("depscan-help-output", {"help": ""})
