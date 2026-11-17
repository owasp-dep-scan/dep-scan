"""Tests for the VDR-to-findings conversion in analysis_lib.findings."""

import pytest
from jsonschema import Draft202012Validator

from analysis_lib.findings.fingerprint import finding_fingerprint
from analysis_lib.findings.model import Finding
from analysis_lib.findings.schemas import load_schema, validate
from analysis_lib.findings.vdr_convert import (
    finding_from_vdr,
    findings_from_vdr,
    highest_severity,
)

VULN = {
    "id": "CVE-2024-1111",
    "bom-ref": "CVE-2024-1111/pkg:pypi/requests@2.32.1",
    "affects": [{"ref": "pkg:pypi/requests@2.32.1"}],
    "ratings": [
        {"severity": "low", "score": 3.1, "method": "CVSSv31"},
        {"severity": "high", "score": 8.1, "method": "CVSSv31"},
    ],
    "fixed_location": "2.32.2",
    "advisories": [
        {"title": "NVD entry", "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-1111"}
    ],
    "cwes": [400, 400, "not-a-number"],
    "properties": [{"name": "depscan:prioritized", "value": "true"}],
}


def test_one_finding_per_advisory_and_component():
    vuln = dict(VULN)
    vuln["affects"] = [{"ref": "pkg:pypi/requests@2.32.1"}, {"ref": "pkg:pypi/urllib3@2.2.0"}]
    findings = findings_from_vdr([vuln], producer_version="7.0.0.dev0")
    assert len(findings) == 2
    components = [finding.components for finding in findings]
    assert components == [
        ["pkg:pypi/requests@2.32.1"],
        ["pkg:pypi/urllib3@2.2.0"],
    ]
    # Each id is the fingerprint of the (advisory, component) pair.
    for finding in findings:
        pair_components = finding.components
        assert pair_components is not None
        assert finding.id == finding_fingerprint("vulnerability", "CVE-2024-1111", pair_components)


def test_entry_without_affects_produces_no_finding():
    assert findings_from_vdr([{"id": "CVE-1"}], producer_version="1") == []
    assert findings_from_vdr([], producer_version="1") == []


def test_finding_validates_against_the_schema():
    finding = finding_from_vdr(VULN, "pkg:pypi/requests@2.32.1", producer_version="7.0.0.dev0")
    validate("finding", finding.to_dict())


def test_fields_carry_the_entry_knowledge():
    finding = finding_from_vdr(VULN, "pkg:pypi/requests@2.32.1", producer_version="7.0.0.dev0")
    assert isinstance(finding, Finding)
    assert finding.category == "vulnerability"
    assert finding.rule == "CVE-2024-1111"
    assert finding.severity == "high"
    assert finding.coverage.state == "assessed"
    assert finding.producer.name == "dep-scan"
    assert finding.producer.version == "7.0.0.dev0"
    fix = finding.fix
    assert fix is not None and fix.fixed_versions == ["2.32.2"]
    references = finding.references
    assert references is not None
    assert references[0].url == "https://nvd.nist.gov/vuln/detail/CVE-2024-1111"
    assert references[0].type == "advisory"
    assert finding.cwes == [400]
    properties = finding.properties
    assert properties is not None and properties[0].name == "depscan:prioritized"
    assert finding.title == "CVE-2024-1111 affects pkg:pypi/requests@2.32.1"


def test_two_entries_differing_only_in_component_version_share_the_fingerprint():
    other = dict(VULN)
    other["affects"] = [{"ref": "pkg:pypi/requests@2.30.0"}]
    findings = findings_from_vdr([VULN, other], producer_version="7.0.0.dev0")
    assert findings[0].id == findings[1].id, "the fingerprint leaves the version out"
    assert [f.components for f in findings] == [
        ["pkg:pypi/requests@2.32.1"],
        ["pkg:pypi/requests@2.30.0"],
    ], "each version the project ships keeps its own finding"


def test_a_repeated_advisory_and_component_pair_collapses():
    findings = findings_from_vdr([VULN, dict(VULN)], producer_version="7.0.0.dev0")
    assert len(findings) == 1


def test_fixed_versions_come_from_the_unaffected_versions_too():
    vuln = {
        "id": "GHSA-aaaa-bbbb-cccc",
        "affects": [
            {
                "ref": "pkg:npm/lodash@4.17.20",
                "versions": [
                    {"range": "< 4.17.21", "status": "affected"},
                    {"version": "4.17.21", "status": "unaffected"},
                ],
            }
        ],
    }
    fixed = finding_from_vdr(vuln, "pkg:npm/lodash@4.17.20", producer_version="1")
    assert fixed.fix is not None
    assert fixed.fix.fixed_versions == ["4.17.21"]
    unresolved = finding_from_vdr(
        {"id": "CVE-1", "affects": []}, "pkg:npm/lodash@4.17.20", producer_version="1"
    )
    assert unresolved.fix is None


def test_unresolved_finding_fields_stay_out_of_the_json():
    vuln = {"id": "CVE-1", "affects": [{"ref": "pkg:npm/a@1"}]}
    document = finding_from_vdr(vuln, "pkg:npm/a@1", producer_version="1").to_dict()
    assert set(document) == {
        "id",
        "category",
        "rule",
        "title",
        "severity",
        "coverage",
        "producer",
        "components",
    }
    assert document["severity"] == "unknown"
    assert "fix" not in document and "references" not in document


def test_entries_without_an_advisory_id_are_rejected():
    with pytest.raises(ValueError) as excinfo:
        findings_from_vdr([{"id": "", "affects": [{"ref": "pkg:npm/a@1"}]}], producer_version="1")
    assert "advisory id" in str(excinfo.value)


def test_invalid_component_refs_are_rejected():
    with pytest.raises(ValueError) as excinfo:
        findings_from_vdr(
            [{"id": "CVE-1", "affects": [{"ref": "not-a-purl"}]}], producer_version="1"
        )
    assert "not-a-purl" in str(excinfo.value)


@pytest.mark.parametrize(
    "ratings,expected",
    [
        ([{"severity": "critical", "score": 9.8}], "critical"),
        ([{"severity": "LOW", "score": 3.1}], "low"),
        ([{"severity": "none"}], "info"),
        ([{"severity": "unspecified"}], "unknown"),
        ([], "unknown"),
        ([{"severity": "high", "score": 8.1}, {"severity": "medium", "score": 9.0}], "high"),
        ([{"severity": "medium"}, {"severity": "medium", "score": 5.0}], "medium"),
    ],
)
def test_highest_severity(ratings, expected):
    assert highest_severity({"ratings": ratings}) == expected


def test_finding_schema_publishes_the_severity_names_the_conversion_emits():
    published = load_schema("finding")["properties"]["severity"]["enum"]
    for name in ("critical", "high", "medium", "low", "info", "unknown"):
        assert name in published


def test_every_produced_document_validates_with_the_published_validator():
    validator = Draft202012Validator(load_schema("finding"))
    cases = [
        ("pkg:pypi/requests@2.32.1", VULN),
        ("pkg:npm/a@1", {"id": "CVE-1", "affects": [{"ref": "pkg:npm/a@1"}]}),
    ]
    for ref, vuln in cases:
        finding = finding_from_vdr(vuln, ref, producer_version="1")
        errors = list(validator.iter_errors(finding.to_dict()))
        assert not errors
