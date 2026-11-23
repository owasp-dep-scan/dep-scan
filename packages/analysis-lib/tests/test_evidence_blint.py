"""Tests for the blint evidence adapter.

The fixtures under ``tests/data/blint`` are real blint 4.0.1 reports over
the two ELF corpus binaries, plus the SBOM whose ``metadata.tools`` names
the producer version, trimmed per the README next to them. The tests cover
the version gate on the tool version, malformed input at the document and
entry level, ids and paths that do not depend on the directory the review
ran in, Windows-style binary paths, the reconciliation of a binary onto a
BOM component, the coverage caveats, and the producer's values being kept
as given. The hostile cases mutate in-memory copies; the fixture files are
never rewritten.
"""

import json
from pathlib import Path

from analysis_lib.evidence.adapters import STATUS_COMPLETED, STATUS_NOT_ASSESSED
from analysis_lib.evidence.adapters.blint import extract
from analysis_lib.findings.schemas import validate

DATA = Path(__file__).parent / "data" / "blint"
FINDINGS_SOURCE = "analysis/blint/findings.json"
REVIEWS_SOURCE = "analysis/blint/reviews.json"
COVERAGE_SOURCE = "analysis/blint/analysis-coverage.json"

# The purl the plain corpus binary's component carries in the recorded SBOM.
PLAIN_BINARY_PURL = "pkg:generic/plain-libc-demo.elf"


def _load(name):
    return json.loads((DATA / name).read_text(encoding="utf-8"))


def _deep(value):
    return json.loads(json.dumps(value))


def _sbom():
    return _load("sbom-blint.json")


def _bom_blint_version():
    """The version the SBOM's metadata.tools names for blint, the version
    source the scan wiring uses."""
    tools = (_sbom().get("metadata") or {}).get("tools") or {}
    for entry in tools.get("components") or []:
        if isinstance(entry, dict) and entry.get("name") == "blint":
            return str(entry.get("version") or "")
    return ""


def _extract(findings=None, **overrides):
    kwargs = {
        "source": FINDINGS_SOURCE,
        "producer_version": _bom_blint_version(),
        "reviews_document": _load("reviews.json"),
        "reviews_source": REVIEWS_SOURCE,
        "coverage_document": _load("analysis-coverage.json"),
        "coverage_source": COVERAGE_SOURCE,
        "bom_components": _sbom().get("components") or [],
        "extra_components": [(_sbom().get("metadata") or {}).get("component")],
    }
    kwargs.update(overrides)
    return extract(findings, **kwargs)


def _under_root(document, root):
    """A copy of a report whose binary paths sit under ``root``."""
    document = _deep(document)
    for key in ("findings", "reviews"):
        for entry in document.get(key) or []:
            if isinstance(entry, dict):
                for field in ("filename", "exe_name"):
                    if isinstance(entry.get(field), str):
                        entry[field] = root + "/" + entry[field]
    return document


def _caveat_kinds(caveats):
    return [c.kind for c in caveats]


# ---------------------------------------------------------------------------
# The recording: records, kinds, polarity, kept values
# ---------------------------------------------------------------------------


def test_findings_become_negative_presence_records_with_values_as_given():
    result = _extract(_load("findings.json"))
    assert result.status == STATUS_COMPLETED
    findings_records = [r for r in result.records if r.polarity == "negative"]
    assert len(findings_records) == 3
    canary = next(r for r in findings_records if r.attributes.get("id") == "CHECK_CANARY")
    assert canary.kind == "presence"
    assert canary.subject.purls == []  # the fortified binary has no BOM component
    assert [(loc.file, loc.line, loc.method) for loc in canary.locations] == [
        ("corpus/fortified-libc-demo.elf", None, None)
    ]
    # every non-path value the producer stated is kept as given, the path
    # fields are relative, and the binary path itself lives in the location
    assert canary.attributes["title"] == "Missing Canary Protection"
    assert canary.attributes["severity"] == "medium"
    assert canary.attributes["exe_type"] == "genericbinary"
    assert canary.attributes["finding_id"] == "0d534158c6e6430c7b58b4afd945e25b"
    assert canary.attributes["exe_types"] == [
        "genericbinary",
        "x86_64-executable",
        "x86_64-exec",
        "mips-executable",
        "aarch64-dyn",
        "arm-dyn",
        "x86_64-dyn",
        "x86-dyn",
        "riscv-dyn",
    ]
    assert canary.attributes["exe_name"] == "corpus/fortified-libc-demo.elf"
    assert "filename" not in canary.attributes
    assert "description" in canary.attributes
    abi = [r for r in findings_records if r.attributes.get("id") == "CHECK_ABI_FLOOR"]
    assert {r.attributes["baseline_version"] for r in abi} == {"2.28"}
    assert {r.locations[0].file for r in abi} == {
        "corpus/fortified-libc-demo.elf",
        "corpus/plain-libc-demo.elf",
    }


def test_reviews_become_positive_presence_records_with_one_location_per_symbol():
    result = _extract(_load("findings.json"))
    reviews = [r for r in result.records if r.polarity == "positive"]
    assert len(reviews) == 1
    review = reviews[0]
    assert review.kind == "presence"
    assert review.source == REVIEWS_SOURCE
    assert [(loc.file, loc.method) for loc in review.locations] == [
        ("corpus/fortified-libc-demo.elf", "__fprintf_chk")
    ]
    assert review.attributes["id"] == "FORTIFIED_LIBC_IN_USE"
    assert review.attributes["summary"] == "Binary was built with libc hardening checks enabled"
    assert review.attributes["evidence"] == [
        {"pattern": "__fprintf_chk", "function": "__fprintf_chk"}
    ]
    assert review.attributes["exe_name"] == "corpus/fortified-libc-demo.elf"


def test_review_with_empty_evidence_keeps_one_location_for_the_file():
    document = _deep(_load("reviews.json"))
    document["reviews"][0]["evidence"] = []
    result = _extract(None, reviews_document=document)
    assert result.status == STATUS_COMPLETED
    (review,) = result.records
    assert [(loc.file, loc.method) for loc in review.locations] == [
        ("corpus/fortified-libc-demo.elf", None)
    ]


def test_binary_reconciles_to_the_bom_component_by_basename():
    result = _extract(_load("findings.json"))
    by_rule = {}
    for record in result.records:
        if record.polarity == "negative":
            by_rule.setdefault(record.attributes.get("id"), []).append(record)
    plain = next(
        r
        for r in by_rule["CHECK_ABI_FLOOR"]
        if r.locations and r.locations[0].file == "corpus/plain-libc-demo.elf"
    )
    assert plain.subject.purls == [PLAIN_BINARY_PURL]
    assert plain.subject.component_ref == "pkg:generic/plain-libc-demo.elf"


def test_no_reconciliation_leaves_empty_purls_and_the_location_carries_the_record():
    result = _extract(_load("findings.json"))
    canary = next(
        r
        for r in result.records
        if r.polarity == "negative" and r.attributes.get("id") == "CHECK_CANARY"
    )
    assert canary.subject.purls == []
    assert canary.locations[0].file == "corpus/fortified-libc-demo.elf"


def test_records_validate_against_the_evidence_schema_and_are_byte_stable():
    first = _extract(_load("findings.json"))
    second = _extract(_load("findings.json"))
    lines = [json.dumps(r.to_dict(), sort_keys=True) for r in first.records]
    assert lines == [json.dumps(r.to_dict(), sort_keys=True) for r in second.records]
    assert len({r.id for r in first.records}) == len(first.records) == 4
    for record in first.records:
        assert record.schema_version == "1"
        assert record.producer.name == "blint"
        assert record.producer.version == "4.0.1"
        # the reports name no schema version of their own; the gated tool
        # version is the producer version, never a report schema version
        assert record.producer.report_schema_version == "unknown"
        validate("depscan-evidence", record.to_dict())


# ---------------------------------------------------------------------------
# The version gate on the blint tool version
# ---------------------------------------------------------------------------


def test_unknown_major_version_is_refused_naming_the_version():
    result = _extract(_load("findings.json"), producer_version="5.0.0")
    assert result.status == STATUS_NOT_ASSESSED
    assert "5.0.0" in result.reason
    assert result.records == []


def test_newer_minor_version_is_accepted_with_a_schema_minor_caveat():
    result = _extract(_load("findings.json"), producer_version="4.1.0")
    assert result.status == STATUS_COMPLETED
    assert len(result.records) == 4
    assert "schema-minor" in _caveat_kinds(result.caveats)
    for record in result.records:
        assert "schema-minor" in _caveat_kinds(record.caveats)
        assert record.producer.version == "4.1.0"
        assert record.producer.report_schema_version == "unknown"


def test_missing_version_is_accepted_with_a_schema_unknown_caveat():
    result = _extract(_load("findings.json"), producer_version="")
    assert result.status == STATUS_COMPLETED
    assert "schema-unknown" in _caveat_kinds(result.caveats)
    for record in result.records:
        assert "schema-unknown" in _caveat_kinds(record.caveats)
        assert record.producer.version == "unknown"
        assert record.producer.report_schema_version == "unknown"


# ---------------------------------------------------------------------------
# Malformed input
# ---------------------------------------------------------------------------


def test_malformed_findings_document_is_not_assessed():
    for bad in ([], 42, "not json", {"findings": "text"}, {"findings": {"id": "X"}}):
        result = _extract(bad)
        assert result.status == STATUS_NOT_ASSESSED, bad
        assert result.records == []
        assert result.reason


def test_findings_entry_that_is_not_an_object_is_counted_not_dropped_silently():
    document = _load("findings.json")
    document["findings"].insert(0, "a string entry")
    result = _extract(document)
    assert result.status == STATUS_COMPLETED
    assert len(result.records) == 4  # the real entries still became records
    counted = [c for c in result.caveats if c.kind == "record-skipped"]
    assert len(counted) == 1
    assert "1 findings entries are not JSON objects" in counted[0].detail


def test_reviews_evidence_that_is_not_a_list_is_counted_never_an_exception():
    document = _deep(_load("reviews.json"))
    document["reviews"][0]["evidence"] = 42
    result = _extract(None, reviews_document=document)
    assert result.status == STATUS_COMPLETED
    (review,) = result.records
    assert [(loc.file, loc.method) for loc in review.locations] == [
        ("corpus/fortified-libc-demo.elf", None)
    ]
    counted = [c for c in result.caveats if c.kind == "record-skipped"]
    assert any("evidence value that is not an array" in c.detail for c in counted)


def test_reviews_evidence_entries_that_are_not_objects_are_counted():
    document = _deep(_load("reviews.json"))
    document["reviews"][0]["evidence"] = [
        7,
        {"pattern": "__sprintf_chk", "function": "__sprintf_chk"},
    ]
    result = _extract(None, reviews_document=document)
    assert result.status == STATUS_COMPLETED
    (review,) = result.records
    assert [loc.method for loc in review.locations] == ["__sprintf_chk"]
    counted = [c for c in result.caveats if c.kind == "record-skipped"]
    assert any("1 reviews evidence entries are not JSON objects" in c.detail for c in counted)


def test_malformed_reviews_document_is_counted_not_assessed_clean():
    for bad in ("text", {"reviews": "text"}):
        result = _extract(_load("findings.json"), reviews_document=bad)
        assert result.status == STATUS_COMPLETED, bad
        assert len(result.records) == 3
        counted = [c for c in result.caveats if c.kind == "record-skipped"]
        assert counted, bad


def test_coverage_units_that_is_not_an_object_is_counted_never_an_exception():
    coverage = _deep(_load("analysis-coverage.json"))
    coverage["units"] = [{"failed": 1}]
    result = _extract(_load("findings.json"), coverage_document=coverage)
    assert result.status == STATUS_COMPLETED
    assert len(result.records) == 4
    counted = [c for c in result.caveats if c.kind == "record-skipped"]
    assert any("units" in c.detail for c in counted)
    assert "coverage-gap" not in _caveat_kinds(result.caveats)


def test_no_documents_at_all_is_not_assessed():
    result = _extract(None, reviews_document=None, coverage_document=None)
    assert result.status == STATUS_NOT_ASSESSED
    assert result.records == []


def test_coverage_only_scan_completes_with_zero_records():
    result = _extract(None, reviews_document=None)
    assert result.status == STATUS_COMPLETED
    assert result.records == []
    assert result.caveats == []


# ---------------------------------------------------------------------------
# The coverage caveats
# ---------------------------------------------------------------------------


def test_failed_and_skipped_units_become_coverage_gap_caveats_on_every_record():
    coverage = _deep(_load("analysis-coverage.json"))
    coverage["units"] = {"attempted": 3, "succeeded": 0, "failed": 1, "skipped": 2}
    result = _extract(_load("findings.json"), coverage_document=coverage)
    gaps = sorted(c.detail for c in result.caveats if c.kind == "coverage-gap")
    assert len(gaps) == 2
    assert any("1 failed analysis unit" in detail and COVERAGE_SOURCE in detail for detail in gaps)
    assert any("2 skipped analysis unit" in detail for detail in gaps)
    for record in result.records:
        details = [c.detail for c in record.caveats if c.kind == "coverage-gap"]
        assert sorted(details) == gaps


def test_clean_coverage_adds_no_caveat():
    result = _extract(_load("findings.json"))
    assert "coverage-gap" not in _caveat_kinds(result.caveats)
    assert "record-skipped" not in _caveat_kinds(result.caveats)


# ---------------------------------------------------------------------------
# Root independence and Windows paths
# ---------------------------------------------------------------------------


def test_moved_source_root_gives_identical_ids_and_relative_paths():
    findings = _load("findings.json")
    reviews = _load("reviews.json")
    relative = _extract(findings, reviews_document=reviews)
    left = _extract(
        _under_root(findings, "/scans/demo-a"),
        reviews_document=_under_root(reviews, "/scans/demo-a"),
        source_root="/scans/demo-a",
    )
    right = _extract(
        _under_root(findings, "/scans/demo-b"),
        reviews_document=_under_root(reviews, "/scans/demo-b"),
        source_root="/scans/demo-b",
    )

    def as_text(result):
        return [json.dumps(r.to_dict(), sort_keys=True) for r in result.records]

    assert as_text(left) == as_text(right) == as_text(relative)
    assert relative.records[0].locations[0].file == "corpus/fortified-libc-demo.elf"


def test_windows_style_binary_path_never_reaches_a_location_or_id():
    document = _deep(_load("findings.json"))
    entry = document["findings"][0]
    entry["filename"] = entry["exe_name"] = "C:\\build\\out\\server.exe"
    document["findings"] = [entry]
    result = _extract(document, reviews_document=None)
    assert result.status == STATUS_COMPLETED
    (record,) = result.records
    assert record.locations == []
    # the basename of a path left out keeps the record usable without
    # carrying the absolute path anywhere
    assert record.attributes["fileName"] == "server.exe"
    assert "exe_name" not in record.attributes
    assert "C:" not in json.dumps(record.to_dict())
    assert "location-outside-root" in _caveat_kinds(record.caveats)
    assert "location-outside-root" in _caveat_kinds(result.caveats)
    # the id is the one the same entry with no path fields gives, so the
    # Windows path contributes nothing to it
    stripped = {k: v for k, v in entry.items() if k not in ("filename", "exe_name")}
    without_paths = _extract({"findings": [stripped]}, reviews_document=None)
    assert without_paths.records[0].id == record.id


def test_windows_style_binary_path_under_a_windows_root_is_relativized():
    document = _deep(_load("findings.json"))
    entry = document["findings"][0]
    entry["filename"] = entry["exe_name"] = "C:\\build\\out\\server.exe"
    document["findings"] = [entry]
    result = _extract(document, reviews_document=None, source_root="C:\\build\\out")
    (record,) = result.records
    assert record.locations[0].file == "server.exe"
    assert record.attributes["exe_name"] == "server.exe"


# ---------------------------------------------------------------------------
# Ids: the rule id and blint's finding_id
# ---------------------------------------------------------------------------


def _one_finding(**changes):
    entry = _deep(_load("findings.json")["findings"][0])
    entry.update(changes)
    return entry


def test_repeats_blint_numbers_itself_get_their_own_ids_in_any_order():
    """blint tells apart repeats of one rule on one binary only by its
    finding_id; two entries that differ in nothing else get two content
    ids, and each id is the same whatever the order of the report."""
    first = _one_finding()
    second = _one_finding(finding_id="f" * 32)
    forward = _extract({"findings": [first, second]}, reviews_document=None)
    backward = _extract({"findings": [second, first]}, reviews_document=None)
    ids = [r.id for r in forward.records]
    assert len(set(ids)) == 2
    assert all("-" not in record_id[3:] for record_id in ids)
    assert sorted(ids) == sorted(r.id for r in backward.records)


def test_two_rules_that_differ_only_in_rule_id_get_two_ids():
    result = _extract(
        {"findings": [_one_finding(), _one_finding(id="CHECK_OTHER")]}, reviews_document=None
    )
    assert len({r.id for r in result.records}) == 2


# ---------------------------------------------------------------------------
# Reconciliation onto the names blint's own SBOM writes
# ---------------------------------------------------------------------------


def _subject_for(filename, components):
    result = _extract(
        {"findings": [_one_finding(filename=filename, exe_name=filename)]},
        reviews_document=None,
        bom_components=components,
        extra_components=[],
        source_root="C:\\app",
    )
    return result.records[0].subject


def test_a_dll_reconciles_to_the_component_blint_names_without_the_suffix():
    subject = _subject_for(
        "C:\\app\\bin\\foo.dll",
        [{"name": "foo", "purl": "pkg:generic/foo", "bom-ref": "pkg:generic/foo"}],
    )
    assert subject.purls == ["pkg:generic/foo"]
    assert subject.component_ref == "pkg:generic/foo"


def test_a_managed_dll_reconciles_to_its_versioned_nuget_identity():
    subject = _subject_for(
        "C:\\app\\bin\\MyApp.dll",
        [{"name": "MyApp", "purl": "pkg:nuget/MyApp@1.2.0", "bom-ref": "pkg:nuget/MyApp@1.2.0"}],
    )
    assert subject.purls == ["pkg:nuget/MyApp@1.2.0"]


def test_versioned_and_encoded_generic_purls_reconcile_by_name():
    subject = _subject_for(
        "C:\\app\\lib\\libfoo++.so",
        [
            {"name": "x", "purl": "pkg:generic/libfoo%2B%2B.so"},
            {"name": "y", "purl": "pkg:generic/libfoo%2B%2B.so@1.0?arch=x86_64"},
            {"name": "z", "purl": "pkg:generic/libfoo.so@1.0"},
        ],
    )
    assert subject.purls == [
        "pkg:generic/libfoo%2B%2B.so",
        "pkg:generic/libfoo%2B%2B.so@1.0?arch=x86_64",
    ]


# ---------------------------------------------------------------------------
# Caveat text, unreadable values and deep input
# ---------------------------------------------------------------------------


def test_the_gate_caveats_name_the_blint_version_the_bom_states():
    missing = _extract(_load("findings.json"), producer_version="")
    assert ("schema-unknown", "the BOM names no blint version") in [
        (c.kind, c.detail) for c in missing.caveats
    ]
    newer = _extract(_load("findings.json"), producer_version="4.1.0")
    assert (
        "schema-minor",
        "the BOM names blint version 4.1.0; this adapter knows 4.0 and earlier",
    ) in [(c.kind, c.detail) for c in newer.caveats]


def test_unreadable_filenames_and_unit_counts_are_counted():
    result = _extract(
        {"findings": [_one_finding(filename=5, exe_name=None)]},
        reviews_document=None,
        coverage_document={"units": {"failed": "3", "skipped": [1]}},
    )
    assert result.status == STATUS_COMPLETED
    details = [(c.kind, c.detail) for c in result.caveats]
    assert (
        "record-skipped",
        "1 entries name a filename that is not a string and carry no location or file name",
    ) in details
    assert (
        "record-skipped",
        "1 coverage units skipped counts are not numbers and were not read as a coverage gap",
    ) in details
    # A count blint wrote as a string of digits still names the gap.
    assert (
        "coverage-gap",
        f"blint's coverage report {COVERAGE_SOURCE} names 3 failed analysis unit(s)",
    ) in details


def test_a_deep_evidence_value_costs_its_own_entry_alone():
    deep = []
    for _ in range(3000):
        deep = [deep]
    findings = _load("findings.json")
    findings["findings"][0]["evidence"] = deep
    result = _extract(findings)
    assert result.status == STATUS_COMPLETED
    assert len(result.records) == 3
    assert any(
        c.kind == "record-skipped" and c.detail.startswith("1 report objects nest deeper")
        for c in result.caveats
    )


def test_home_directories_never_reach_the_attributes():
    entry = _one_finding(
        filename="/home/alice/proj/corpus/fortified-libc-demo.elf",
        exe_name="/home/alice/proj/corpus/fortified-libc-demo.elf",
        title="Missing Canary Protection (RUNPATH /home/alice/lib)",
        evidence={"rpath": "/home/alice/proj/build/lib"},
    )
    result = _extract({"findings": [entry]}, reviews_document=None, source_root=None)
    text = json.dumps(result.records[0].to_dict())
    assert "alice" not in text
    assert result.records[0].attributes["title"] == "Missing Canary Protection (RUNPATH ~/lib)"


def test_a_companion_document_nested_too_deep_to_parse_costs_itself_alone():
    deep = "[" * 100000 + "]" * 100000
    result = _extract(_load("findings.json"), reviews_document=deep)
    assert result.status == STATUS_COMPLETED
    assert len(result.records) == len(_load("findings.json")["findings"])
    assert any("nests its values deeper" in c.detail for c in result.caveats)
