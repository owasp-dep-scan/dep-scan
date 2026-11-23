"""The blint binary review's rendering in the reports.

A binary scan's hardening findings reach ``depscan.findings.json`` but
never the console, so ``depscan.txt`` and ``depscan.html`` said nothing
about them and ``depscan report`` printed an empty vulnerability table over
a silent review. The rendering tested here prints the review's table on the
console the scan records and on the one the report verb prints from a saved
directory, with a count that agrees with the findings file.

The scan tests stub only the BOM generation step, the one place the
external blint runs, with a recorder; the evidence adapters, the findings
conversion and the renderers are the real ones. The saved-directory test
reads a fixture cut from a real scan.
"""

import json
import os
from pathlib import Path

import pytest

from depscan import api
from depscan.lib import binary_review, pipeline
from depscan.lib import doctor as doctor_mod
from depscan.lib import report as report_lib
from depscan.lib import vdb_setup
from depscan.lib.bom import BomResult

from test.test_scan_directory import _FULL_VDB_DATA

DATA_DIR = Path(__file__).parent / "data"
BINARY_FIXTURE_DIR = DATA_DIR / "report-binary"
CLEAN_FIXTURE_DIR = DATA_DIR / "report-binary-clean"


class _StubVdrResult:
    success = True
    prioritized_pkg_vuln_trees = {}
    exploitability = None

    def __init__(self, pkg_vulnerabilities):
        self.pkg_vulnerabilities = pkg_vulnerabilities


@pytest.fixture
def scan_stubs(monkeypatch):
    """Stub a binary scan's database and matching stages, and the HTML save.

    Everything else is the real pipeline: the package loader reads the BOM
    the stubbed generator wrote, the blint adapter reads the review reports
    it wrote, and the findings and rendering stages run for real. The
    database inspection is a known state, as in the scan directory tests.
    """
    calls = {"matching": [], "database": []}
    monkeypatch.setattr(
        vdb_setup, "resolve_scan_vdb_image", lambda args: ("oras://vdb", False, "app-only")
    )
    monkeypatch.setattr(vdb_setup, "vdb_download_needed", lambda url, d: (False, ""))
    monkeypatch.setattr(vdb_setup, "configure_vdb_readonly", lambda: None)
    monkeypatch.setattr(vdb_setup, "ensure_vdb_usable", lambda: calls["database"].append(1))
    monkeypatch.setattr(pipeline.ReportGenerator, "parse_and_generate_report", lambda self: None)
    monkeypatch.setattr(pipeline.console, "save_html", lambda *a, **k: None)

    class StubVDRAnalyzer:
        def __init__(self, vdr_options):
            calls["matching"].append(vdr_options)

        def process(self):
            return _StubVdrResult([])

    monkeypatch.setattr(pipeline, "VDRAnalyzer", StubVDRAnalyzer)
    monkeypatch.setattr(doctor_mod, "_vdb_status", lambda: dict(_FULL_VDB_DATA))
    return calls


def _blint_bom_document(binary_name="demo-tool"):
    """The blint-shaped BOM the real generator writes, reduced to what the
    scan reads: the tool version the evidence adapter gates on, the binary
    as the metadata component a finding reconciles to, and one library so
    the package list is not empty."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "metadata": {
            "tools": {"components": [{"type": "application", "name": "blint", "version": "4.1.0"}]},
            "component": {
                "type": "application",
                "bom-ref": f"pkg:generic/{binary_name}",
                "name": binary_name,
                "purl": f"pkg:generic/{binary_name}",
            },
        },
        "components": [
            {
                "type": "library",
                "name": "libdemo.so",
                "version": "0.0.0",
                "purl": "pkg:file/libdemo.so@0.0.0",
                "bom-ref": "pkg:file/libdemo.so@0.0.0",
            }
        ],
    }


def _finding_entry(binary_name="demo-tool"):
    """One blint security check finding, shaped like the report's entries."""
    return {
        "id": "CHECK_CANARY",
        "title": "Missing Canary Protection",
        "severity": "medium",
        "filename": binary_name,
        "exe_name": binary_name,
        "exe_type": "genericbinary",
        "finding_id": "0d534158c6e6430c7b58b4afd945e25f",
    }


def _stub_create_bom(calls, *, findings_entries, coverage_units):
    """A ``create_bom`` stand-in that writes what a blint review writes.

    The review's findings report lands under ``analysis/blint/`` next to
    the BOM, the place the scan's own blint adapter reads it from, and the
    coverage report with it; ``coverage_units`` of None writes no coverage
    report, the case of a review that left none behind. Every call is
    recorded so a test can prove the stub ran.
    """

    def create_bom(bom_file, src_dir, options=None, **kwargs):
        calls.append(bom_file)
        with open(bom_file, "w", encoding="utf-8") as fp:
            json.dump(_blint_bom_document(), fp)
        directory = os.path.join(os.path.dirname(bom_file), "analysis", "blint")
        os.makedirs(directory, exist_ok=True)
        with open(os.path.join(directory, "findings.json"), "w", encoding="utf-8") as fp:
            json.dump({"findings": findings_entries}, fp)
        if coverage_units is not None:
            with open(os.path.join(directory, "analysis-coverage.json"), "w", encoding="utf-8") as fp:
                json.dump({"units": coverage_units}, fp)
        return BomResult(success=True, bom_files=[bom_file], primary=bom_file)

    return create_bom


def _run_binary_scan(scan_stubs, monkeypatch, tmp_path, *, findings_entries, coverage_units):
    """Run a binary scan with the stubbed review; (depscan.txt, reports dir).

    Only the BOM generation step is stubbed, so the review's reports go
    through the real adapters, findings conversion and rendering stages.
    """
    monkeypatch.setenv("COLUMNS", "200")
    calls = []
    monkeypatch.setattr(
        pipeline,
        "create_bom",
        _stub_create_bom(calls, findings_entries=findings_entries, coverage_units=coverage_units),
    )
    saved = {}

    def save_text(path, clear=False, styles=False):
        saved[str(path)] = pipeline.console.export_text(clear=False)

    monkeypatch.setattr(pipeline.console, "save_text", save_text)
    # The console is module-global; drop whatever an earlier test recorded
    # so each scan's export holds only its own output.
    was_recording = pipeline.console.record
    pipeline.console.record = True
    pipeline.console.export_text(clear=True)
    pipeline.console.record = was_recording
    src = tmp_path / "src"
    src.mkdir()
    reports = tmp_path / "reports"
    api.scan(
        api.scan_options(
            src_dir_image=str(src),
            reports_dir=str(reports),
            project_type="binary",
            reachability_analyzer="off",
            no_banner=True,
        )
    )
    assert calls, "the BOM generation step never ran"
    return saved[str(reports / "depscan.txt")], reports


def test_hardening_rows_keeps_only_the_review_category():
    rows = binary_review.hardening_rows(
        [
            {"category": "vulnerability", "rule": "CVE-2026-1"},
            {"category": "binary-hardening", "rule": "CHECK_CANARY"},
            "not a finding",
            None,
        ]
    )
    assert [row["rule"] for row in rows] == ["CHECK_CANARY"]


def test_report_renders_the_hardening_findings_of_a_saved_scan(capsys, monkeypatch):
    """``depscan report`` shows the binary-hardening findings the scan's
    findings file holds, with the caption counting the same rows."""
    monkeypatch.setenv("COLUMNS", "200")
    exit_code = report_lib.run_report_command([str(BINARY_FIXTURE_DIR)])
    assert exit_code == 0
    out = capsys.readouterr().out
    findings_doc = json.loads((BINARY_FIXTURE_DIR / "depscan.findings.json").read_text())
    count = len(binary_review.hardening_rows(findings_doc["findings"]))
    assert count == 1, "the fixture holds the one hardening finding of the scan"
    assert "Binary Hardening Results" in out
    assert "CHECK_UNUSED_DEPENDENCIES" in out
    assert "golem-darwin-arm64" in out
    assert f"Binary hardening findings count: {count}" in out


def test_a_binary_scan_writes_the_hardening_table_into_its_reports(
    scan_stubs, tmp_path, monkeypatch
):
    """The scan's console carries the review's table, so depscan.txt and
    depscan.html carry it too, with a count that agrees with the findings
    file the same scan writes."""
    text, reports = _run_binary_scan(
        scan_stubs,
        monkeypatch,
        tmp_path,
        findings_entries=[_finding_entry()],
        coverage_units={"attempted": 1, "succeeded": 1, "failed": 0, "skipped": 0},
    )
    assert "Binary Hardening Results" in text
    assert "CHECK_CANARY" in text
    assert "Missing Canary Protection" in text
    findings_doc = json.loads((reports / "depscan.findings.json").read_text())
    count = len(binary_review.hardening_rows(findings_doc["findings"]))
    assert count == 1
    assert f"Binary hardening findings count: {count}" in text


def test_a_clean_binary_review_states_its_coverage_in_the_reports(
    scan_stubs, tmp_path, monkeypatch
):
    """A review that ran and completed with no findings says so, with the
    unit counts of blint's coverage report, instead of leaving only a
    "No vulnerabilities found" line."""
    text, _reports = _run_binary_scan(
        scan_stubs,
        monkeypatch,
        tmp_path,
        findings_entries=[],
        coverage_units={"attempted": 1, "succeeded": 1, "failed": 0, "skipped": 0},
    )
    assert (
        "Binary hardening checks completed with no findings: "
        "1 attempted, 1 succeeded, 0 failed, 0 skipped units." in text
    )


def test_a_binary_review_with_gaps_names_them(scan_stubs, tmp_path, monkeypatch):
    """A coverage report with failed or skipped units is stated as a gap,
    never folded into a clean statement."""
    text, _reports = _run_binary_scan(
        scan_stubs,
        monkeypatch,
        tmp_path,
        findings_entries=[_finding_entry()],
        coverage_units={"attempted": 2, "succeeded": 1, "failed": 1, "skipped": 0},
    )
    assert (
        "Binary hardening checks completed with gaps: "
        "2 attempted, 1 succeeded, 1 failed, 0 skipped units." in text
    )
    assert "with no findings" not in text


def test_a_binary_review_without_a_coverage_report_says_so(scan_stubs, tmp_path, monkeypatch):
    """A review that completed but left no coverage report behind is named
    as not assessed, so its silence never reads as a clean run."""
    text, _reports = _run_binary_scan(
        scan_stubs,
        monkeypatch,
        tmp_path,
        findings_entries=[],
        coverage_units=None,
    )
    assert (
        "Binary hardening checks ran, but the coverage report "
        "analysis/blint/analysis-coverage.json is missing or unreadable, "
        "so their coverage was not assessed." in text
    )
    assert "with no findings:" not in text


def test_report_states_the_coverage_of_a_saved_clean_scan(capsys, monkeypatch):
    """The report verb states a saved clean review's coverage from blint's
    coverage report, with the unit counts it carries."""
    monkeypatch.setenv("COLUMNS", "200")
    exit_code = report_lib.run_report_command([str(CLEAN_FIXTURE_DIR)])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert (
        "Binary hardening checks completed with no findings: "
        "1 attempted, 1 succeeded, 0 failed, 0 skipped units." in out
    )
