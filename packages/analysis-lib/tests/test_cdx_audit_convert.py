"""Tests for the cdx-audit record-to-finding conversion.

The records come from the adapter over the real-report fixtures under
``data/cdx_audit/``, so the mapping is tested on producer output, not on
hand-built shapes.
"""

import json
from pathlib import Path

from analysis_lib.evidence.adapters import cdx_audit as adapter
from analysis_lib.findings.cdx_audit_convert import findings_from_cdx_audit_records

DATA_DIR = Path(__file__).parent / "data" / "cdx_audit"


def load_records(name, **kwargs):
    report = json.loads((DATA_DIR / name).read_text())
    return adapter.extract(report, source="audit.json", producer_version="13.10.0", **kwargs)


def test_direct_records_map_onto_supply_chain_findings():
    result = load_records("direct-report.json", source_root="/src")
    findings = findings_from_cdx_audit_records(result.records)
    by_rule = {finding.rule: finding for finding in findings}
    assert set(by_rule) == {"CI-002", "PKG-006"}
    ci002 = by_rule["CI-002"]
    assert ci002.category == "supply-chain"
    assert ci002.severity == "high"
    assert ci002.title == "OIDC token issuance to non-official action"
    assert ci002.producer.name == "cdx-audit"
    assert ci002.producer.version == "13.10.0"
    assert ci002.components == [
        "pkg:github/pypa/gh-action-pypi-publish@ed0c53931b1dc9bd32cbe73a98c7f6766f8a527e"
    ]
    assert ci002.evidence, "the finding carries the audit's evidence"


def test_predictive_records_carry_the_audited_dependency():
    result = load_records("predictive-report.json", source_root="/src")
    findings = findings_from_cdx_audit_records(result.records)
    assert findings, "the audited target's finding mapped"
    finding = findings[0]
    assert finding.category == "supply-chain"
    assert finding.properties, "the audit context rides in properties"


def test_audit_categories_map_onto_their_own_finding_categories():
    """The cbom-security pack is crypto and rootfs-hardening is
    binary-hardening, where plan D1 assigns them; everything else is
    supply-chain."""
    from analysis_lib.evidence import (
        Evidence,
        EvidenceProducer,
        EvidenceSubject,
    )

    def record_with(rule, category):
        return Evidence(
            schema_version="1",
            id=f"ev-{rule}",
            producer=EvidenceProducer(
                name="cdx-audit", version="13.10.0", report_schema_version="1"
            ),
            kind="annotation",
            polarity="negative",
            subject=EvidenceSubject(purls=["pkg:pypi/demo@1.0.0"]),
            source="audit.json",
            locations=[],
            caveats=[],
            attributes={"id": rule, "category": category, "severity": "high"},
        )

    records = [
        record_with("CBS-001", "cbom-security"),
        record_with("RFS-001", "rootfs-hardening"),
        record_with("CI-002", "ci-permission"),
        # A category the audit spelled no category for still maps through
        # the rule id.
        record_with("CBC-003", None),
    ]
    findings = findings_from_cdx_audit_records(records)
    categories = {finding.rule: finding.category for finding in findings}
    assert categories == {
        "CBS-001": "crypto",
        "RFS-001": "binary-hardening",
        "CI-002": "supply-chain",
        "CBC-003": "crypto",
    }


def test_caveats_become_coverage_reasons():
    """A bounded audit's caveats ride on every finding, so a cut-short audit
    never reads as a complete one; the state stays assessed because the
    audit ran."""
    result = load_records("predictive-report.json", source_root="/src")
    findings = findings_from_cdx_audit_records(result.records)
    for finding in findings:
        reasons = finding.coverage.reasons or []
        assert any(reason.reason == "coverage-gap" for reason in reasons)
        assert finding.coverage.state == "assessed"


def test_fingerprints_survive_a_rescan_from_a_moved_root():
    """The same audit of the same tree gives the same finding ids whatever
    directory the scan ran from, so a baseline keyed on them holds."""
    first = findings_from_cdx_audit_records(
        load_records("direct-report.json", source_root="/work/tree-a").records
    )
    second = findings_from_cdx_audit_records(
        load_records("direct-report.json", source_root="/elsewhere/tree-b").records
    )
    assert [f.id for f in first] == [f.id for f in second]
    assert all(f.id.startswith("dsf1:") for f in first)


def test_same_rule_on_two_components_gives_two_findings():
    """The fingerprint carries the component, so suppressions key on one
    finding without swallowing the other."""
    report = json.loads((DATA_DIR / "direct-report.json").read_text())
    finding = report["results"][0]["findings"][0]
    report["results"][0]["findings"] = [
        dict(finding, location={"purl": "pkg:pypi/one@1.0.0", "bomRef": "pkg:pypi/one@1.0.0"}),
        dict(finding, location={"purl": "pkg:pypi/two@2.0.0", "bomRef": "pkg:pypi/two@2.0.0"}),
    ]
    records = adapter.extract(report, source="audit.json", producer_version="13.10.0").records
    findings = findings_from_cdx_audit_records(records)
    assert len(findings) == 2
    assert len({f.id for f in findings}) == 2
    assert {f.components[0] for f in findings} == {"pkg:pypi/one@1.0.0", "pkg:pypi/two@2.0.0"}


def test_records_of_other_producers_and_kinds_are_ignored():
    """The converter reads only cdx-audit's own negative annotations; a
    reachability record that happens to be an annotation is not supply
    chain's to say."""
    records = load_records("direct-report.json", source_root="/src").records
    from analysis_lib.evidence import Evidence, EvidenceProducer, EvidenceSubject

    stranger = Evidence(
        schema_version="1",
        id="ev-y",
        producer=EvidenceProducer(name="atom", version="4.0.0", report_schema_version="1"),
        kind="annotation",
        polarity="negative",
        subject=EvidenceSubject(purls=["pkg:npm/x@1"]),
        source="slices.json",
        locations=[],
        caveats=[],
        attributes={"id": "INT-001"},
    )
    findings = findings_from_cdx_audit_records(list(records) + [stranger])
    assert all(f.producer.name == "cdx-audit" for f in findings)
    assert not any(f.rule == "INT-001" and f.producer.name == "atom" for f in findings)


def test_two_versions_of_one_package_merge_into_one_finding():
    """The fingerprint keys on the package, so the same rule on two
    versions of one package is one finding that names both versions'
    purls; no component the audit named disappears."""
    report = json.loads((DATA_DIR / "direct-report.json").read_text())
    finding = report["results"][0]["findings"][0]
    report["results"][0]["findings"] = [
        dict(finding, location={"purl": "pkg:pypi/acorn@8.11.3", "bomRef": "pkg:pypi/acorn@8.11.3"}),
        dict(finding, location={"purl": "pkg:pypi/acorn@8.14.1", "bomRef": "pkg:pypi/acorn@8.14.1"}),
    ]
    records = adapter.extract(report, source="audit.json", producer_version="13.10.0").records
    assert len(records) == 2
    findings = findings_from_cdx_audit_records(records)
    assert len(findings) == 1
    assert findings[0].components == ["pkg:pypi/acorn@8.11.3", "pkg:pypi/acorn@8.14.1"]
