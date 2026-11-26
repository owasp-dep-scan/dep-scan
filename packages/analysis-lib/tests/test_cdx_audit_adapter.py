"""Tests for the cdx-audit report adapter.

The fixtures under ``data/cdx_audit/`` are cut from real cdx-audit JSON
reports, trimmed to the fields the adapter reads (the matched component's
``internal:SrcFile`` properties among them) and scrubbed of the recording
machine's paths: a direct audit of an npm monorepo BOM with the categories
dep-scan passes and a registry lookup, a direct audit of a container BOM
with the image packs, offline, and a bounded predictive audit of a PyPI
BOM.
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
        source="cdx-audit-npm.json",
        producer_version="13.9.0",
        source_root="/src",
    )
    assert result.status == "completed"
    # Six findings; left-pad@1.3.0 is declared by two lockfiles, so each of
    # its two findings becomes one record per lockfile.
    assert len(result.records) == 8
    rule_ids = {record.attributes["id"] for record in result.records}
    assert rule_ids == {"INT-005", "INT-026"}
    for record in result.records:
        assert record.producer.name == "cdx-audit"
        assert record.producer.version == "13.9.0"
        assert record.kind == "annotation"
        assert record.polarity == "negative"


def test_direct_records_name_their_component_and_file():
    report = load("direct-report.json")
    result = adapter.extract(
        report,
        source="cdx-audit-npm.json",
        producer_version="13.9.0",
        source_root="/src",
    )
    deprecated = [record for record in result.records if record.attributes["id"] == "INT-005"]
    located = sorted(
        (record.subject.purls[0], record.locations[0].file) for record in deprecated
    )
    assert located == [
        ("pkg:npm/left-pad@1.3.0", "svc-a/package-lock.json"),
        ("pkg:npm/left-pad@1.3.0", "svc-b/package-lock.json"),
        ("pkg:npm/request@2.88.0", "svc-b/package-lock.json"),
        ("pkg:npm/request@2.88.2", "svc-a/package-lock.json"),
    ], "each record names its component and the lockfile that declared it"
    for record in deprecated:
        assert record.attributes["severity"] == "low"
        assert record.attributes["auditMode"] == "direct"


def test_monorepo_copies_are_told_apart_by_their_lockfile():
    """The file comes from the matched component's ``internal:SrcFile``
    properties. Without it the two lockfiles that pin left-pad would give
    one record, and two versions of request would carry no file at all."""
    report = load("direct-report.json")
    result = adapter.extract(report, source="a.json", producer_version="13.9.0")
    left_pad = [
        record
        for record in result.records
        if record.attributes["id"] == "INT-005"
        and record.subject.purls == ["pkg:npm/left-pad@1.3.0"]
    ]
    assert len(left_pad) == 2
    assert len({record.id for record in left_pad}) == 2

    # Negative control: the same report without the matched components
    # gives one record per finding and no file.
    for finding in report["results"][0]["findings"]:
        finding.pop("_match")
    bare = adapter.extract(report, source="a.json", producer_version="13.9.0")
    assert len(bare.records) == 6
    assert all(not record.locations for record in bare.records)


def test_container_report_keeps_bom_refs_that_are_no_purls():
    """A real container audit: the crypto findings name their component by a
    bom-ref that is no purl (``crypto/algorithm/md5@...``), one repository
    finding by the ``pkg:generic/os-repository/...`` purl cdxgen writes for
    a repository source, and one by a ``urn:uuid:`` bom-ref. A record names
    only the purl that parses, keeps the bom-ref as its component
    reference, and a declaring file inside the image is no location in the
    scanned tree."""
    result = adapter.extract(
        load("container-report.json"), source="c.json", producer_version="13.9.0", source_root="/src"
    )
    assert result.status == "completed"
    by_ref = {record.subject.component_ref: record for record in result.records}
    assert sorted(by_ref) == [
        "crypto/algorithm/md5@1.2.840.113549.2.5",
        "crypto/algorithm/sha-1@1.3.14.3.2.26",
        "pkg:generic/os-repository/legacy-mirror@configured",
        "urn:uuid:0d9f3c2a-1b4e-4f6a-9c8d-2e7f1a0b3c4d",
    ]
    assert by_ref["pkg:generic/os-repository/legacy-mirror@configured"].subject.purls == [
        "pkg:generic/os-repository/legacy-mirror@configured"
    ]
    for ref, record in by_ref.items():
        if not ref.startswith("pkg:"):
            assert record.subject.purls == []
            assert record.attributes["bomRef"] == ref
        assert not record.locations
    assert not any(caveat.kind == "location-outside-root" for caveat in result.caveats)


@pytest.mark.parametrize(
    "location",
    [
        {"bomRef": "file:/usr/bin/su"},
        {"bomRef": "urn:uuid:59e7b709-955a-410e-9e03-91dc28edefb3"},
        {"bomRef": "pkg:npm/a@1", "purl": "crypto/algorithm/md5"},
        [{"purl": "pkg:npm/a@1"}],
        "pkg:npm/a@1",
    ],
)
def test_odd_locations_never_reach_the_purls(location):
    """Only values that parse as purls become subject purls; a location
    that is an array or a string is read as no location at all."""
    report = load("direct-report.json")
    finding = report["results"][0]["findings"][0]
    finding["location"] = location
    finding.pop("_match")
    result = adapter.extract(report, source="a.json", producer_version="13.9.0")
    assert result.status == "completed"
    first = next(r for r in result.records if r.attributes["message"] == finding["message"])
    for purl in first.subject.purls:
        assert purl.startswith("pkg:")


def test_direct_records_store_file_paths_relative_to_the_root():
    report = load("direct-report.json")
    finding = report["results"][0]["findings"][0]
    finding["location"]["file"] = "/src/.github/workflows/publish.yml"
    result = adapter.extract(
        report,
        source="cdx-audit-npm.json",
        producer_version="13.9.0",
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
        producer_version="13.9.0",
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
        "tool": {"name": "cdx-audit", "version": "13.9.0"},
    }
    result = adapter.extract(
        report,
        source="audit.json",
        producer_version="13.9.0",
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
        "tool": {"name": "cdx-audit", "version": "13.9.0"},
    }
    result = adapter.extract(report, source="audit.json", producer_version="13.9.0")
    caveats = [caveat.detail for caveat in result.caveats if caveat.kind == "coverage-gap"]
    assert any("offline" in detail for detail in caveats)


def test_report_without_a_version_is_accepted_with_a_caveat():
    report = load("direct-report.json")
    del report["version"]
    result = adapter.extract(report, source="audit.json", producer_version="13.9.0")
    assert result.status == "completed"
    assert any(caveat.kind == "schema-unknown" for caveat in result.caveats)


def test_unsupported_report_shape_is_not_assessed():
    report = load("direct-report.json")
    report["version"] = "2.0"
    result = adapter.extract(report, source="audit.json", producer_version="13.9.0")
    assert result.status == "not-assessed"
    assert "not supported" in result.reason


def test_malformed_report_is_not_assessed():
    result = adapter.extract("{not json", source="audit.json", producer_version="13.9.0")
    assert result.status == "not-assessed"
    assert "not valid JSON" in result.reason
    result = adapter.extract([1, 2, 3], source="audit.json", producer_version="13.9.0")
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
    result = adapter.extract(report, source="audit.json", producer_version="13.9.0")
    assert result.status == "completed"
    assert any(
        caveat.kind in ("record-skipped", "coverage-gap") for caveat in result.caveats
    ), why


def test_results_of_the_wrong_type_are_not_assessed():
    """A results value that is not an array means the report cannot be read
    at all, so the honest answer is not-assessed, never zero findings."""
    report = load("direct-report.json")
    report["results"] = {"not": "a list"}
    result = adapter.extract(report, source="audit.json", producer_version="13.9.0")
    assert result.status == "not-assessed"
    assert "expected an array" in result.reason


def test_finding_without_a_rule_id_is_counted_not_silently_dropped():
    report = load("direct-report.json")
    report["results"][0]["findings"].append({"severity": "high", "message": "no rule id"})
    result = adapter.extract(report, source="audit.json", producer_version="13.9.0")
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
        producer_version="13.9.0",
        source_root="/work/tree-a",
    )
    second = adapter.extract(
        report,
        source="audit.json",
        producer_version="13.9.0",
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
        producer_version="13.9.0",
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
        producer_version="13.9.0",
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
        producer_version="13.9.0",
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
        producer_version="13.9.0",
    )
    assert not any("registry" in detail for detail in _gap_details(complete))


def test_a_report_without_a_coverage_block_adds_no_registry_caveat():
    """Reports from a cdx-audit before the coverage block carry none, and
    nothing is invented about the registry rules."""
    report = load("direct-report.json")
    report["results"][0].pop("coverage")
    result = adapter.extract(report, source="audit.json", producer_version="13.9.0")
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
        _direct_with_coverage(coverage), source="audit.json", producer_version="13.9.0"
    )
    assert result.status == "completed"
    assert len(result.records) == 8
    assert not any("registry" in detail for detail in _gap_details(result))


def test_every_record_of_a_run_carries_the_same_run_caveats():
    """Run-level caveats are collected before any record is built, so the
    order of the results never decides which record carries which gap."""
    report = load("predictive-report.json")
    audited = report["results"][0]
    second = json.loads(json.dumps(audited))
    second["target"]["purl"] = "pkg:pypi/other@1.0.0"
    second["target"]["bomRefs"] = ["pkg:pypi/other@1.0.0"]
    report["results"].append(second)
    for order in (report["results"], list(reversed(report["results"]))):
        report["results"] = order
        result = adapter.extract(report, source="p.json", producer_version="13.9.0")
        details = [
            sorted(caveat.detail for caveat in record.caveats) for record in result.records
        ]
        assert len(details) >= 2
        assert all(entry == details[0] for entry in details), details
        assert any("did not audit pkg:pypi/django-otp" in d for d in details[0])


def test_direct_result_coverage_stays_on_its_own_records():
    """In a report of two BOMs, a BOM's registry gap rides only on the
    records of that BOM."""
    report = load("direct-report.json")
    gap = json.loads(json.dumps(report["results"][0]))
    gap["coverage"] = {
        "registryMetadata": "fetched",
        "eligible": 3,
        "answered": 2,
        "withoutMetadata": 1,
    }
    gap["findings"] = gap["findings"][:1]
    gap["findings"][0]["message"] = "from the second BOM"
    report["results"].append(gap)
    result = adapter.extract(report, source="d.json", producer_version="13.9.0")
    for record in result.records:
        has_gap = any("1 of 3" in caveat.detail for caveat in record.caveats)
        assert has_gap == (record.attributes["message"] == "from the second BOM")


def test_target_selection_skips_are_counted_per_reason():
    """Hundreds of purls skipped for one reason are one caveat with a count,
    so the manifest never lists them one by one."""
    report = load("predictive-report.json")
    report["skipped"] = [
        {"reason": "unsupported-ecosystem", "purl": f"pkg:maven/org.x/lib{i}@1.0"}
        for i in range(200)
    ] + [{"reason": "allowlisted", "purl": "pkg:npm/react@18.0.0"}]
    result = adapter.extract(report, source="p.json", producer_version="13.9.0")
    selection = [c.detail for c in result.caveats if "did not select" in c.detail]
    assert selection == [
        "the audit did not select 200 purls for analysis: unsupported-ecosystem",
        "the audit did not select pkg:npm/react@18.0.0 for analysis: allowlisted",
    ]


def test_predictive_upstream_files_never_become_locations():
    """A predictive finding's file is in the target's upstream repository.
    It stays an attribute next to the target and is never a location in the
    scanned tree."""
    report = load("predictive-report.json")
    report["results"][0]["findings"][0]["location"]["file"] = ".github/workflows/release.yml"
    result = adapter.extract(
        report, source="p.json", producer_version="13.9.0", source_root="/Users/alice/app"
    )
    record = result.records[0]
    assert not record.locations
    assert record.attributes["upstreamFile"] == ".github/workflows/release.yml"
    assert record.attributes["targetPurl"] == "pkg:pypi/django-grappelli@5.0.1"


def test_predictive_error_text_is_redacted():
    report = load("predictive-report.json")
    skipped = next(entry for entry in report["results"] if entry.get("status") != "audited")
    skipped["error"] = "ENOENT: open '/Users/alice/app/node_modules/x/package.json'"
    result = adapter.extract(
        report, source="p.json", producer_version="13.9.0", source_root="/Users/alice/app"
    )
    details = [caveat.detail for caveat in result.caveats]
    assert not any("/Users/alice" in detail for detail in details), details
    assert any("node_modules/x/package.json" in detail for detail in details)


def test_offline_coverage_states_one_gap_not_two():
    """Offline, every eligible component is without registry metadata; the
    caveat that says the lookups did not run covers it, and the per-component
    count is stated only when the lookups ran."""
    result = adapter.extract(
        _direct_with_coverage(
            {"registryMetadata": "offline", "eligible": 3, "answered": 0, "withoutMetadata": 3}
        ),
        source="audit.json",
        producer_version="13.9.0",
    )
    details = _gap_details(result)
    assert any("did not look up registry metadata" in detail for detail in details)
    assert not any("carry no registry metadata" in detail for detail in details), details


def test_two_findings_differing_only_by_message_stay_two_records():
    """The record discriminator carries the message, so two findings of one
    rule on one component and file stay apart."""
    report = load("direct-report.json")
    findings = report["results"][0]["findings"]
    twin = json.loads(json.dumps(findings[0]))
    twin["message"] = findings[0]["message"] + " (second signal)"
    findings.append(twin)
    result = adapter.extract(report, source="d.json", producer_version="13.9.0")
    same_place = [
        record
        for record in result.records
        if record.attributes["id"] == findings[0]["ruleId"]
        and record.subject.purls == [findings[0]["location"]["purl"]]
    ]
    assert len(same_place) == 2
    assert len({record.id for record in same_place}) == 2
