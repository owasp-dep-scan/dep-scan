"""Tests for the cdx-audit report adapter.

The fixtures under ``data/cdx_audit/`` are cut from real cdx-audit JSON
reports (a direct audit of a PyPI BOM, a bounded predictive audit of the
same BOM), trimmed to the fields the adapter reads and scrubbed of the
recording machine's paths.
"""

import json
from pathlib import Path

import pytest

from analysis_lib.evidence.adapters import cdx_audit as adapter

DATA_DIR = Path(__file__).parent / "data" / "cdx_audit"


def load(name):
    return json.loads((DATA_DIR / name).read_text())


def test_direct_report_yields_annotation_records():
    report = load("direct-report.json")
    result = adapter.extract(
        report,
        source="cdx-audit-bom.json",
        producer_version="13.10.0",
        source_root="/src",
    )
    assert result.status == "completed"
    assert len(result.records) == 2
    rule_ids = {record.attributes["id"] for record in result.records}
    assert rule_ids == {"CI-002", "PKG-006"}
    for record in result.records:
        assert record.producer.name == "cdx-audit"
        assert record.producer.version == "13.10.0"
        assert record.kind == "annotation"
        assert record.polarity == "negative"


def test_direct_records_name_their_component_and_file():
    report = load("direct-report.json")
    result = adapter.extract(
        report,
        source="cdx-audit-bom.json",
        producer_version="13.10.0",
        source_root="/src",
    )
    by_rule = {record.attributes["id"]: record for record in result.records}
    ci002 = by_rule["CI-002"]
    assert ci002.subject.purls == ["pkg:github/pypa/gh-action-pypi-publish@ed0c53931b1dc9bd32cbe73a98c7f6766f8a527e"]
    assert ci002.attributes["severity"] == "high"
    assert ci002.attributes["auditMode"] == "direct"
    pkg006 = by_rule["PKG-006"]
    assert pkg006.subject.purls, "every finding names its component"


def test_direct_records_store_file_paths_relative_to_the_root():
    report = load("direct-report.json")
    finding = next(
        f
        for f in report["results"][0]["findings"]
        if f.get("location", {}).get("file")
    )
    finding["location"]["file"] = "/src/.github/workflows/publish.yml"
    result = adapter.extract(
        report,
        source="cdx-audit-bom.json",
        producer_version="13.10.0",
        source_root="/src",
    )
    located = [
        record
        for record in result.records
        if record.locations and record.locations[0].file == ".github/workflows/publish.yml"
    ]
    assert located, "the file is stored relative to the source root"


def test_predictive_report_records_cover_the_shortfalls():
    """The skipped and errored targets, the target-selection skips and the
    summary markers each become a coverage caveat; the audited target's
    finding names the dependency the user's BOM carries."""
    report = load("predictive-report.json")
    result = adapter.extract(
        report,
        source="cdx-audit-predictive-bom.json",
        producer_version="13.10.0",
        source_root="/src",
    )
    assert result.status == "completed"
    caveats = [caveat.detail for caveat in result.caveats if caveat.kind == "coverage-gap"]
    assert any("did not select" in detail for detail in caveats), "selection skips counted"
    assert any("target cap" in detail for detail in caveats), "the exhausted cap counted"
    assert any("time budget" in detail for detail in caveats), "the spent budget counted"
    findings = [record for record in result.records if record.polarity == "negative"]
    assert findings, "the audited target's finding became a record"
    record = findings[0]
    assert record.subject.purls, "the record names the audited dependency"
    assert record.attributes["auditMode"] == "predictive"
    assert record.attributes["targetPurl"] == record.subject.purls[0]


def test_errored_target_becomes_a_coverage_caveat():
    """A target whose clone failed is coverage the audit did not get.

    The entry shape follows the report's documented errored-result shape:
    status error, an errorType, and the error text."""
    report = {
        "version": 1,
        "results": [
            {
                "target": {"purl": "pkg:npm/left-pad@1.3.0", "bomRefs": ["pkg:npm/left-pad@1.3.0"]},
                "status": "error",
                "error": "Unable to clone 'https://github.com/x/y.git' after 3 attempt(s)",
                "errorType": "clone",
                "findings": [],
                "assessment": {"severity": "none", "score": 0},
            }
        ],
        "skipped": [],
        "summary": {},
        "tool": {"name": "cdx-audit", "version": "13.10.0"},
    }
    result = adapter.extract(
        report,
        source="audit.json",
        producer_version="13.10.0",
    )
    caveats = [caveat.detail for caveat in result.caveats if caveat.kind == "coverage-gap"]
    assert any("it failed (clone)" in detail for detail in caveats), caveats
    assert result.records == [], "an errored target yields no finding record"


def test_offline_summary_is_a_caveat():
    report = {
        "version": 1,
        "results": [],
        "skipped": [],
        "summary": {"offline": True, "totalTargets": 3, "skippedTargets": 3},
        "tool": {"name": "cdx-audit", "version": "13.10.0"},
    }
    result = adapter.extract(report, source="audit.json", producer_version="13.10.0")
    caveats = [caveat.detail for caveat in result.caveats if caveat.kind == "coverage-gap"]
    assert any("offline" in detail for detail in caveats)


def test_report_without_a_version_is_accepted_with_a_caveat():
    report = load("direct-report.json")
    del report["version"]
    result = adapter.extract(report, source="audit.json", producer_version="13.10.0")
    assert result.status == "completed"
    assert any(caveat.kind == "schema-unknown" for caveat in result.caveats)


def test_unsupported_report_shape_is_not_assessed():
    report = load("direct-report.json")
    report["version"] = "2.0"
    result = adapter.extract(report, source="audit.json", producer_version="13.10.0")
    assert result.status == "not-assessed"
    assert "not supported" in result.reason


def test_malformed_report_is_not_assessed():
    result = adapter.extract("{not json", source="audit.json", producer_version="13.10.0")
    assert result.status == "not-assessed"
    assert "not valid JSON" in result.reason
    result = adapter.extract([1, 2, 3], source="audit.json", producer_version="13.10.0")
    assert result.status == "not-assessed"


@pytest.mark.parametrize(
    "mutation,why",
    [
        ({"results": [None]}, "a null result entry"),
        (
            {"results": [{"status": "audited", "target": {"purl": 5}, "findings": "no"}]},
            "wrong types one level down",
        ),
        (
            {"results": [{"status": "audited", "target": {}, "findings": [{"severity": {}}]}]},
            "a finding whose fields are objects",
        ),
    ],
)
def test_nested_hostile_input_never_raises(mutation, why):
    """Wrong types inside the report are skipped and counted, never a
    crash and never a silent clean result."""
    report = load("direct-report.json")
    report.update(mutation)
    result = adapter.extract(report, source="audit.json", producer_version="13.10.0")
    assert result.status == "completed"
    assert any(
        caveat.kind in ("record-skipped", "coverage-gap") for caveat in result.caveats
    ), why


def test_results_of_the_wrong_type_are_not_assessed():
    """A results value that is not an array means the report cannot be read
    at all, so the honest answer is not-assessed, never zero findings."""
    report = load("direct-report.json")
    report["results"] = {"not": "a list"}
    result = adapter.extract(report, source="audit.json", producer_version="13.10.0")
    assert result.status == "not-assessed"
    assert "expected an array" in result.reason


def test_finding_without_a_rule_id_is_counted_not_silently_dropped():
    report = load("direct-report.json")
    report["results"][0]["findings"].append({"severity": "high", "message": "no rule id"})
    result = adapter.extract(report, source="audit.json", producer_version="13.10.0")
    assert result.status == "completed"
    assert any(
        caveat.kind == "record-skipped" and "no rule id" in caveat.detail
        for caveat in result.caveats
    )


def test_record_ids_survive_a_moved_root():
    """The same audit of the same tree, scanned from another directory,
    gives the same record ids."""
    report = load("direct-report.json")
    first = adapter.extract(
        report,
        source="audit.json",
        producer_version="13.10.0",
        source_root="/work/tree-a",
    )
    second = adapter.extract(
        report,
        source="audit.json",
        producer_version="13.10.0",
        source_root="/elsewhere/tree-b",
    )
    assert [record.id for record in first.records] == [record.id for record in second.records]


def _direct_with_coverage(coverage):
    report = load("direct-report.json")
    report["results"][0]["coverage"] = coverage
    return report


def _gap_details(result):
    return [caveat.detail for caveat in result.caveats if caveat.kind == "coverage-gap"]


def test_offline_registry_coverage_is_a_caveat_on_the_result_and_its_records():
    """A direct audit that ran offline could not look any package up, so
    the registry rules assessed nothing. The gap names the count and rides
    on every record the audit still produced."""
    result = adapter.extract(
        _direct_with_coverage(
            {"registryMetadata": "offline", "components": 50, "eligible": 12, "answered": 0, "withoutMetadata": 12}
        ),
        source="audit.json",
        producer_version="13.10.0",
    )
    details = _gap_details(result)
    assert any(
        "the audit ran offline and made no registry request" in detail
        and "did not assess 12 npm, PyPI or Cargo component(s)" in detail
        for detail in details
    ), details
    assert result.records, "the audit's own findings still became records"
    for record in result.records:
        assert any(caveat.kind == "coverage-gap" for caveat in record.caveats), (
            "a finding from an audit with a registry gap carries the gap"
        )


def test_an_unrequested_registry_lookup_is_named_as_such():
    result = adapter.extract(
        _direct_with_coverage({"registryMetadata": "not-requested", "eligible": 3, "withoutMetadata": 3}),
        source="audit.json",
        producer_version="13.10.0",
    )
    assert any(
        "was not asked for registry lookups (not-requested)" in detail
        for detail in _gap_details(result)
    )


def test_components_no_registry_answered_for_are_counted():
    """Online, a lookup that ran still leaves the components no registry
    answered for unassessed by the registry rules; they are counted. When
    every eligible component was answered for, there is no registry gap."""
    partial = adapter.extract(
        _direct_with_coverage(
            {"registryMetadata": "fetched", "components": 44, "eligible": 40, "answered": 37, "withoutMetadata": 3}
        ),
        source="audit.json",
        producer_version="13.10.0",
    )
    details = _gap_details(partial)
    assert any(
        detail.startswith("3 of 40 npm, PyPI or Cargo component(s) carry no registry metadata")
        for detail in details
    ), details
    assert not any("did not look up registry metadata" in detail for detail in details)

    complete = adapter.extract(
        _direct_with_coverage(
            {"registryMetadata": "fetched", "components": 44, "eligible": 40, "answered": 40, "withoutMetadata": 0}
        ),
        source="audit.json",
        producer_version="13.10.0",
    )
    assert not any("registry" in detail for detail in _gap_details(complete))


def test_a_report_without_a_coverage_block_adds_no_registry_caveat():
    """Reports from a cdx-audit before the coverage block carry none, and
    nothing is invented about the registry rules."""
    result = adapter.extract(
        load("direct-report.json"), source="audit.json", producer_version="13.10.0"
    )
    assert not any("registry" in detail for detail in _gap_details(result))


@pytest.mark.parametrize(
    "coverage",
    [
        "offline",
        12,
        None,
        {"registryMetadata": 5, "eligible": "12", "withoutMetadata": "3"},
        {"registryMetadata": "fetched", "eligible": -4, "withoutMetadata": -1},
        {"registryMetadata": "fetched", "eligible": True, "withoutMetadata": True},
        {"registryMetadata": "fetched", "withoutMetadata": {"n": 3}},
    ],
)
def test_a_malformed_coverage_block_raises_nothing_and_claims_nothing(coverage):
    """Wrong types inside the coverage block are skipped: no exception, and
    no caveat that states a count the report never gave."""
    result = adapter.extract(
        _direct_with_coverage(coverage), source="audit.json", producer_version="13.10.0"
    )
    assert result.status == "completed"
    assert len(result.records) == 2
    assert not any("registry" in detail for detail in _gap_details(result))
