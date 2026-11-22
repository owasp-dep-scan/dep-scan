"""Tests for ``analysis_lib.findings.blint_convert``, the mapping of blint
security check findings onto the ``binary-hardening`` finding category."""

import dataclasses
import json
import os
from pathlib import Path

from analysis_lib.evidence.adapters import STATUS_COMPLETED
from analysis_lib.evidence.adapters.blint import extract
from analysis_lib.findings.blint_convert import (
    finding_from_blint,
    findings_from_blint,
    findings_from_blint_records,
)
from analysis_lib.findings.schemas import validate

NX = {
    "id": "CHECK_NX",
    "title": "Missing Non-Executable Memory Protection",
    "description": "Do not disable this protection.",
    "severity": "critical",
    "exe_type": "genericbinary",
    "exe_name": "server",
    "filename": os.path.join(os.sep, "src", "app", "bin", "server"),
}


def _root():
    return os.path.join(os.sep, "src", "app")


def test_check_becomes_a_binary_hardening_finding():
    finding = finding_from_blint(NX, producer_version="4.0.1", scan_root=_root())
    assert finding.category == "binary-hardening"
    assert finding.rule == "CHECK_NX"
    assert finding.severity == "critical"
    assert finding.producer.name == "blint" and finding.producer.version == "4.0.1"
    assert finding.coverage.state == "assessed"
    assert (finding.locations or [])[0].binary == "bin/server"
    assert {p.name: p.value for p in finding.properties or []}["blint:exeType"] == "genericbinary"
    validate("finding", finding.to_dict())


def test_fingerprint_is_stable_across_scan_roots_and_separate_per_binary():
    moved = dict(NX, filename=os.path.join(os.sep, "other", "checkout", "bin", "server"))
    first = finding_from_blint(NX, producer_version="4", scan_root=_root())
    second = finding_from_blint(
        moved, producer_version="4", scan_root=os.path.join(os.sep, "other", "checkout")
    )
    elsewhere = dict(NX, filename=os.path.join(os.sep, "src", "app", "lib", "server"))
    third = finding_from_blint(elsewhere, producer_version="4", scan_root=_root())
    assert first.id == second.id
    assert first.id != third.id
    assert "/src/app" not in first.to_dict()["locations"][0]["binary"]


def test_path_outside_the_root_keeps_only_the_file_name():
    outside = dict(NX, filename=os.path.join(os.sep, "elsewhere", "server"))
    finding = finding_from_blint(outside, producer_version="4", scan_root=_root())
    assert (finding.locations or [])[0].binary == "server"
    no_root = finding_from_blint(NX, producer_version="4")
    assert (no_root.locations or [])[0].binary == "server"


def test_windows_drive_path_never_reaches_the_fingerprint():
    win = dict(NX, filename="C:\\build\\out\\server.exe")
    finding = finding_from_blint(win, producer_version="4")
    assert (finding.locations or [])[0].binary == "server.exe"
    assert finding.id.startswith("dsf1:")


def test_unknown_severity_and_confidence_and_evidence():
    odd = dict(NX, severity="none", confidence="none", evidence={"b": 1, "a": 2})
    finding = finding_from_blint(odd, producer_version="4")
    assert finding.severity == "unknown"
    assert finding.confidence is None
    assert finding.evidence == ['{"a": 2, "b": 1}']
    validate("finding", finding.to_dict())


def test_findings_from_document_skips_damaged_entries_and_repeats():
    document = {"findings": [NX, NX, {"title": "no id"}, "text", dict(NX, id="CHECK_PIE")]}
    findings = findings_from_blint(document, producer_version="4", scan_root=_root())
    assert [f.rule for f in findings] == ["CHECK_NX", "CHECK_PIE"]
    assert findings_from_blint(None, producer_version="4") == []
    assert findings_from_blint({"findings": "x"}, producer_version="4") == []


def _binary(filename, root):
    finding = finding_from_blint(dict(NX, filename=filename), producer_version="4", scan_root=root)
    return (finding.locations or [])[0].binary, finding.id


def test_single_binary_target_uses_the_file_name_not_a_dot(tmp_path):
    binary = tmp_path / "server"
    binary.write_text("x")
    assert _binary(str(binary), str(binary))[0] == "server"


def test_relative_and_absolute_directory_targets_agree(tmp_path, monkeypatch):
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "server").write_text("x")
    monkeypatch.chdir(tmp_path)
    relative = _binary(os.path.join("target", "bin", "server"), "target")
    absolute = _binary(str(tmp_path / "target" / "bin" / "server"), str(tmp_path / "target"))
    assert relative == absolute
    assert relative[0] == "bin/server"
    dotted = _binary(os.path.join(".", "target", "bin", "server"), os.path.join(".", "target"))
    assert dotted == relative


def test_windows_style_paths_match_the_posix_result():
    windows, windows_id = _binary("C:\\src\\app\\bin\\server.exe", "C:\\src\\app")
    posix, posix_id = _binary("/src/app/bin/server.exe", "/src/app")
    assert windows == posix == "bin/server.exe"
    assert windows_id == posix_id
    assert _binary("C:\\src\\app\\server.exe", "C:\\src\\app\\server.exe")[0] == "server.exe"
    assert _binary("C:\\src\\app\\bin\\a.exe", "c:/src/app")[0] == "bin/a.exe"


# ---------------------------------------------------------------------------
# findings_from_blint_records: the same findings from the adapter's records
# ---------------------------------------------------------------------------

BLINT_DATA = Path(__file__).parent / "data" / "blint"


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


def test_findings_from_blint_records_agrees_field_for_field_with_findings_from_blint():
    document = _recording("findings.json")
    from_records = findings_from_blint_records(_records(document))
    from_document = findings_from_blint(document, producer_version="4.0.1")
    assert [f.to_dict() for f in from_records] == [f.to_dict() for f in from_document]
    assert len(from_records) == 3
    assert {f.rule for f in from_records} == {"CHECK_CANARY", "CHECK_ABI_FLOOR"}
    for finding in from_records:
        validate("finding", finding.to_dict())


def test_agreement_holds_under_a_scan_root_with_absolute_paths():
    document = _recording("findings.json")
    for entry in document["findings"]:
        entry["filename"] = entry["exe_name"] = "/scans/demo/" + entry["filename"]
    from_records = findings_from_blint_records(_records(document, source_root="/scans/demo"))
    from_document = findings_from_blint(document, producer_version="4.0.1", scan_root="/scans/demo")
    assert [f.to_dict() for f in from_records] == [f.to_dict() for f in from_document]
    assert {f.locations[0].binary for f in from_records} == {
        "corpus/fortified-libc-demo.elf",
        "corpus/plain-libc-demo.elf",
    }


def test_findings_from_blint_records_reads_only_blint_negative_presence_records():
    records = _records(_recording("findings.json"))
    # the recording's review record is positive presence and no finding
    assert len(records) == 4
    assert len(findings_from_blint_records(records)) == 3
    review = next(r for r in records if r.polarity == "positive")
    assert findings_from_blint_records([review]) == []
    # a negative presence record whose attributes carry no rule id is skipped,
    # as the document reader skips an entry with no id
    check = next(r for r in records if r.polarity == "negative")
    no_rule = dataclasses.replace(check, attributes={"title": "no rule id"})
    assert findings_from_blint_records([no_rule]) == []
