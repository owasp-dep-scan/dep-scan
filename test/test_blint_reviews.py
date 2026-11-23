"""blint's security review: when it runs, where its reports are kept and how
its check findings reach ``depscan.findings.json`` through the evidence
records the blint adapter built."""

import json
import os
import shutil
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from depscan.lib import bom as bom_mod
from depscan.lib import scan_directory
from xbom_lib import blint as blint_mod

pytestmark = pytest.mark.skipif(not blint_mod.BLINT_AVAILABLE, reason="blint is not installed")

#: The committed blint recordings, the input the records
#: reader is proven against.
BLINT_DATA = Path(__file__).resolve().parent.parent / "packages" / "analysis-lib" / "tests" / "data" / "blint"


@pytest.mark.parametrize(
    "options, expected",
    [
        ({}, False),
        (None, False),
        ({"techniques": ["binary-analysis"]}, True),
        ({"project_type": ["binary"]}, True),
        ({"project_type": ["apk"]}, True),
        ({"bom_engine": "BlintGenerator"}, True),
        # the post-build BOM of a lifecycle scan is not a binary review
        ({"lifecycles": ["post-build"]}, False),
        ({"project_type": ["java"], "techniques": ["source-code-analysis"]}, False),
    ],
)
def test_blint_reviews_requested(options, expected):
    assert bom_mod.blint_reviews_requested(options) is expected


class _StubGenerator:
    seen_options: dict = {}

    def __init__(self, src_dir, bom_file, logger=None, options=None):
        type(self).seen_options = options or {}
        self.bom_file = bom_file

    def generate(self):
        with open(self.bom_file, "w", encoding="utf-8") as fp:
            fp.write("{}")
        return SimpleNamespace(success=True)


def test_review_reports_go_under_analysis_blint_next_to_the_bom(monkeypatch, tmp_path):
    monkeypatch.setattr(bom_mod, "BlintGenerator", _StubGenerator)
    bom_file = str(tmp_path / "sbom-binary.cdx.json")
    assert bom_mod.create_blint_bom(bom_file, str(tmp_path), options={}, reviews=True)
    expected = str(tmp_path / "analysis" / "blint")
    assert _StubGenerator.seen_options["blint_reviews_dir"] == expected
    assert os.path.isdir(expected)


def test_no_review_directory_without_a_review_request(monkeypatch, tmp_path):
    monkeypatch.setattr(bom_mod, "BlintGenerator", _StubGenerator)
    bom_file = str(tmp_path / "sbom-binary.cdx.json")
    assert bom_mod.create_blint_bom(bom_file, str(tmp_path), options={})
    assert "blint_reviews_dir" not in _StubGenerator.seen_options
    assert not (tmp_path / "analysis").exists()


def test_create_bom_asks_for_reviews_on_the_binary_check(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(
        bom_mod,
        "create_blint_bom",
        lambda bom_file, src_dir, options=None, reviews=False: calls.append(reviews) or False,
    )
    bom_mod.create_bom(str(tmp_path / "b.json"), str(tmp_path), {"techniques": ["binary-analysis"]})
    bom_mod.create_bom(str(tmp_path / "b.json"), str(tmp_path), {"lifecycles": ["post-build"]})
    assert calls == [True, False]


def _copy_binary(tmp_path):
    source = os.path.realpath(sys.executable)
    target = tmp_path / "bins" / os.path.basename(source)
    target.parent.mkdir()
    shutil.copy(source, target)
    return target.parent


def test_real_review_keeps_reports_and_the_manifest_lists_them(tmp_path):
    reports = tmp_path / "reports" / "analysis" / "blint"
    result = blint_mod.run_blint_reviews([str(_copy_binary(tmp_path))], str(reports))
    assert result.success, result.command_output
    assert blint_mod.BLINT_COVERAGE_FILE in result.files
    coverage = json.loads((reports / blint_mod.BLINT_COVERAGE_FILE).read_text())
    assert coverage["units"]["attempted"] == 1
    entry = scan_directory.classify_file(f"analysis/blint/{blint_mod.BLINT_COVERAGE_FILE}")
    assert entry["role"] == "raw-report" and entry["producer"] == "blint"
    listed = {e["path"] for e in scan_directory.walk_files(str(tmp_path / "reports"))}
    assert f"analysis/blint/{blint_mod.BLINT_COVERAGE_FILE}" in listed


class _FakeRunner:
    def __init__(self, **kwargs):
        pass

    def start(self, options, exe_files):
        finding = {"id": "CHECK_NX", "title": "NX", "severity": "high", "filename": "/s/app"}
        return [finding], [{"id": "ENVIRONMENT_ACCESS"}], [], []

    def analysis_coverage(self):
        return {"units": {"attempted": 1, "succeeded": 1, "failed": 0, "skipped": 0}}


def test_review_writes_findings_and_reviews_and_drops_stale_reports(monkeypatch, tmp_path):
    monkeypatch.setattr(blint_mod, "AnalysisRunner", _FakeRunner)
    reports = tmp_path / "analysis" / "blint"
    reports.mkdir(parents=True)
    (reports / blint_mod.BLINT_FINDINGS_FILE).write_text('{"findings": [{"id": "OLD"}]}')
    result = blint_mod.run_blint_reviews([str(tmp_path)], str(reports))
    assert result.success
    document = json.loads((reports / blint_mod.BLINT_FINDINGS_FILE).read_text())
    assert [f["id"] for f in document["findings"]] == ["CHECK_NX"]
    assert (reports / blint_mod.BLINT_REVIEWS_FILE).is_file()


def test_review_failure_is_returned_not_raised(monkeypatch, tmp_path):
    class Broken(_FakeRunner):
        def start(self, options, exe_files):
            raise RuntimeError("boom")

    monkeypatch.setattr(blint_mod, "AnalysisRunner", Broken)
    result = blint_mod.run_blint_reviews([str(tmp_path)], str(tmp_path / "r"))
    assert result.success is False and "boom" in (result.command_output or "")


@pytest.mark.parametrize("fail_on_error, expected", [(False, True), (True, False)])
def test_generator_survives_a_review_failure_unless_fail_on_error(
    monkeypatch, tmp_path, fail_on_error, expected
):
    monkeypatch.setattr(blint_mod, "run_sbom_mode", lambda options: "sbom")
    monkeypatch.setattr(blint_mod, "blintdb_setup", lambda options: None)
    monkeypatch.setattr(
        blint_mod,
        "run_blint_reviews",
        lambda *a, **k: blint_mod.BlintReviewResult(success=False, command_output="no review"),
    )
    generator = blint_mod.BlintGenerator(
        str(tmp_path),
        str(tmp_path / "bom.json"),
        options={"blint_reviews_dir": str(tmp_path / "r"), "fail_on_error": fail_on_error},
    )
    assert generator.generate().success is expected


def test_findings_file_carries_the_blint_check_findings(tmp_path):
    """The findings file builds its binary-hardening findings from the scan's
    blint evidence records: the producer version is the record's own (the
    version the blint-written BOM's metadata.tools names) and the binary
    path is the location's relative spelling."""
    reports = tmp_path / "reports"
    reports.mkdir()
    document = scan_directory.write_findings(
        str(reports), [], "7.0.0", blint_reviews=True, evidence_records=_review_records()
    )
    assert len(document["findings"]) == 3, "the three recorded checks become findings"
    finding = next(f for f in document["findings"] if f["rule"] == "CHECK_CANARY")
    assert finding["category"] == "binary-hardening"
    assert finding["producer"] == {"name": "blint", "version": "4.0.1"}
    assert finding["locations"] == [{"binary": "corpus/fortified-libc-demo.elf"}]
    on_disk = json.loads((reports / scan_directory.FINDINGS_FILE).read_text())
    assert on_disk == document


def test_records_are_ignored_without_a_review_request(tmp_path):
    """The review request, not the presence of records, gates the binary
    findings: a scan that did not ask for the review never writes them, the
    records of a report an earlier scan left included."""
    reports = tmp_path / "reports"
    reports.mkdir()
    document = scan_directory.write_findings(
        str(reports), [], "7.0.0", blint_reviews=False, evidence_records=_review_records()
    )
    assert document["findings"] == []


def test_a_review_request_without_records_writes_no_binary_findings(tmp_path):
    """A review that was requested but produced no records (a report the
    adapter refused) writes no binary findings rather than failing the
    findings file."""
    reports = tmp_path / "reports"
    reports.mkdir()
    document = scan_directory.write_findings(str(reports), [], "7.0.0", blint_reviews=True)
    assert document["findings"] == []


def test_the_document_reader_of_the_findings_report_is_gone():
    """The findings file reads the blint records, not the raw findings.json
    document: the document reader and its local-package version lookup no
    longer exist."""
    assert not hasattr(scan_directory, "blint_findings")
    assert not hasattr(scan_directory, "BLINT_FINDINGS_PATH")


def _review_records():
    """The blint adapter's records over the committed recordings, the way a
    scan that requested the review builds them: the three documents with
    their scan-directory-relative sources, versioned from the blint-written
    BOM's metadata.tools."""
    from analysis_lib.evidence.adapters import blint as blint_adapter

    result = blint_adapter.extract(
        (BLINT_DATA / "findings.json").read_text(encoding="utf-8"),
        source="analysis/blint/findings.json",
        producer_version="4.0.1",
        reviews_document=(BLINT_DATA / "reviews.json").read_text(encoding="utf-8"),
        reviews_source="analysis/blint/reviews.json",
        coverage_document=(BLINT_DATA / "analysis-coverage.json").read_text(encoding="utf-8"),
        coverage_source="analysis/blint/analysis-coverage.json",
    )
    assert result.status == "completed", result.reason
    return result.records


def test_reviews_remove_the_reports_of_an_earlier_scan_before_they_start(tmp_path, monkeypatch):
    reports = tmp_path / "reports"
    reports.mkdir()
    names = (
        blint_mod.BLINT_FINDINGS_FILE,
        blint_mod.BLINT_REVIEWS_FILE,
        blint_mod.BLINT_COVERAGE_FILE,
    )
    for name in names:
        (reports / name).write_text("{}")

    def boom(*a, **k):
        raise RuntimeError("runner failed")

    monkeypatch.setattr(blint_mod, "AnalysisRunner", boom)
    result = blint_mod.run_blint_reviews([str(tmp_path)], str(reports))
    assert result.success is False
    assert [n for n in names if (reports / n).exists()] == []
