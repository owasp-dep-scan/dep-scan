"""Tests for ``analysis_lib.findings.blint_convert``, the mapping of blint
security check findings onto the ``binary-hardening`` finding category.

The findings come from the presence records the blint evidence adapter
built. The expected findings below are literals recorded from the committed
blint 4.0.1 recording under ``tests/data/blint`` and then checked field by
field against the recording itself: every rule id, title, severity, binary
path, exe type and finding id is the report's own value, the producer
version is the one the blint-written SBOM's ``metadata.tools`` names, and
the fingerprints were verified to differ per binary and to keep the
record's relative path spelling.
"""

import dataclasses
import json
from pathlib import Path

from analysis_lib.evidence.adapters import STATUS_COMPLETED
from analysis_lib.evidence.adapters.blint import extract
from analysis_lib.findings.blint_convert import findings_from_blint_records
from analysis_lib.findings.schemas import validate

BLINT_DATA = Path(__file__).parent / "data" / "blint"

# The three binary-hardening findings the recording's checks become, in the
# recording's order: the missing canary on the fortified binary and the two
# GLIBC-floor checks, one per corpus binary. The titles are the report's own
# sentences; the long one is kept whole because the finding schema carries
# the producer's text as given.
EXPECTED_FINDINGS = [
    {
        "id": "dsf1:5e6f5b7a9f96031b3bb1a8c1312b6af7cf34fd7d8deef3b704ffd74bf78a69f1",
        "category": "binary-hardening",
        "rule": "CHECK_CANARY",
        "title": "Missing Canary Protection",
        "severity": "medium",
        "coverage": {"state": "assessed"},
        "producer": {"name": "blint", "version": "4.0.1"},
        "locations": [{"binary": "corpus/fortified-libc-demo.elf"}],
        "properties": [
            {"name": "blint:exeType", "value": "genericbinary"},
            {"name": "blint:findingId", "value": "0d534158c6e6430c7b58b4afd945e25b"},
            {"name": "blint:exeName", "value": "corpus/fortified-libc-demo.elf"},
        ],
    },
    {
        "id": "dsf1:fba6581dd6ebe8ff5ffce5735cacca8b9219e1c7f196441fd468a75176ef59f6",
        "category": "binary-hardening",
        "rule": "CHECK_ABI_FLOOR",
        "title": (
            "Requires a Newer Runtime Than the Deployment Baseline (GLIBC floor 2.34 exceeds "
            "the built-in default baseline 2.28; set --glibc-baseline or BLINT_GLIBC_BASELINE "
            "to your deployment target to make this a policy finding)"
        ),
        "severity": "info",
        "coverage": {"state": "assessed"},
        "producer": {"name": "blint", "version": "4.0.1"},
        "locations": [{"binary": "corpus/fortified-libc-demo.elf"}],
        "properties": [
            {"name": "blint:exeType", "value": "genericbinary"},
            {"name": "blint:findingId", "value": "27ef6a560f059a570deb3930892a0e59"},
            {"name": "blint:exeName", "value": "corpus/fortified-libc-demo.elf"},
        ],
    },
    {
        "id": "dsf1:8269c8793a5d4bd0190139d6783ff309efeb4bb4394fc1c1e49e072727a375f2",
        "category": "binary-hardening",
        "rule": "CHECK_ABI_FLOOR",
        "title": (
            "Requires a Newer Runtime Than the Deployment Baseline (GLIBC floor 2.34 exceeds "
            "the built-in default baseline 2.28; set --glibc-baseline or BLINT_GLIBC_BASELINE "
            "to your deployment target to make this a policy finding)"
        ),
        "severity": "info",
        "coverage": {"state": "assessed"},
        "producer": {"name": "blint", "version": "4.0.1"},
        "locations": [{"binary": "corpus/plain-libc-demo.elf"}],
        "properties": [
            {"name": "blint:exeType", "value": "genericbinary"},
            {"name": "blint:findingId", "value": "7353638ece12802f2859c401cfa1ade6"},
            {"name": "blint:exeName", "value": "corpus/plain-libc-demo.elf"},
        ],
    },
]


def _recording(name):
    return json.loads((BLINT_DATA / name).read_text(encoding="utf-8"))


def _records(document, **overrides):
    kwargs = {
        "source": "analysis/blint/findings.json",
        "producer_version": "4.0.1",
        "reviews_document": _recording("reviews.json"),
        "coverage_document": _recording("analysis-coverage.json"),
    }
    kwargs.update(overrides)
    result = extract(document, **kwargs)
    assert result.status == STATUS_COMPLETED
    return result.records


def test_the_recordings_checks_become_the_recorded_findings():
    """The adapter's records over the recording become exactly the three
    findings pinned above, in the recording's order, and each validates
    against the published finding schema."""
    findings = findings_from_blint_records(_records(_recording("findings.json")))
    assert [finding.to_dict() for finding in findings] == EXPECTED_FINDINGS
    for finding in findings:
        validate("finding", finding.to_dict())


def test_records_under_a_scan_root_with_absolute_paths_keep_the_ids():
    """A report whose binary paths are absolute under a source root gives the
    same finding ids and fields as the relative recording: the adapter
    relativizes the paths, and the finding follows the record."""
    document = _recording("findings.json")
    for entry in document["findings"]:
        entry["filename"] = entry["exe_name"] = "/scans/demo/" + entry["filename"]
    findings = findings_from_blint_records(_records(document, source_root="/scans/demo"))
    assert [finding.to_dict() for finding in findings] == EXPECTED_FINDINGS


def test_findings_read_only_blint_negative_presence_records():
    records = _records(_recording("findings.json"))
    # the recording's review record is positive presence and no finding
    assert len(records) == 4
    assert len(findings_from_blint_records(records)) == 3
    review = next(r for r in records if r.polarity == "positive")
    assert findings_from_blint_records([review]) == []
    # a negative presence record whose attributes carry no rule id is skipped
    check = next(r for r in records if r.polarity == "negative")
    no_rule = dataclasses.replace(check, attributes={"title": "no rule id"})
    assert findings_from_blint_records([no_rule]) == []


def test_outside_root_binaries_stay_separate_findings_by_basename():
    """Two same-rule findings on binaries outside the scan root must not
    merge onto one location-less finding: the record keeps the basename and
    the finding uses it."""
    document = _recording("findings.json")
    under = document["findings"][0]
    under["filename"] = under["exe_name"] = "/scans/demo/" + under["filename"]
    outside = document["findings"][1:]
    outside[0]["filename"] = outside[0]["exe_name"] = "/elsewhere/agent.elf"
    outside[1]["filename"] = outside[1]["exe_name"] = "/other/root/scanner.elf"
    records = _records(document, source_root="/scans/demo")
    location_less = [r for r in records if r.polarity == "negative" and not r.locations]
    assert {r.attributes.get("fileName") for r in location_less} == {"agent.elf", "scanner.elf"}
    assert "/elsewhere" not in json.dumps([r.to_dict() for r in records])
    assert "/other/root" not in json.dumps([r.to_dict() for r in records])
    findings = findings_from_blint_records(records)
    assert len(findings) == 3
    assert len({finding.id for finding in findings}) == 3
    assert [(finding.locations or [])[0].binary for finding in findings] == [
        "corpus/fortified-libc-demo.elf",
        "agent.elf",
        "scanner.elf",
    ]


def test_unknown_values_are_kept_as_unknowns():
    """A check whose severity and confidence are names the finding schema
    does not publish, with an evidence object, keeps them as the schema's
    unknown forms: severity unknown, no confidence, and the evidence
    serialized as given."""
    document = _recording("findings.json")
    entry = document["findings"][0]
    entry["severity"] = "none"
    entry["confidence"] = "none"
    entry["evidence"] = {"b": 1, "a": 2}
    records = _records(document)
    (finding,) = findings_from_blint_records(records[:1])
    assert finding.severity == "unknown"
    assert finding.confidence is None
    assert finding.evidence == ['{"a": 2, "b": 1}']
    validate("finding", finding.to_dict())
