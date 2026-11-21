"""dep-scan runs kosi for Kotlin scans and keeps its raw report.

kosi itself is faked with a recorded report, so the test covers the
wiring in depscan.lib.bom: the project types that select kosi, the raw
report under analysis/kosi/, which the adapter reads, and the converted
slice file name, which this version no longer writes and clears when a
previous run left one. The name must also not be the kotlin-reachables
file atom writes for a kotlin scan.
"""

import json
import os
import shutil
from pathlib import Path

from depscan.lib import bom as bom_mod
from depscan.lib.config import KOSI_REACHABLES_SLICE_FILE

FIXTURE = (
    Path(__file__).resolve().parent.parent
    / "packages"
    / "analysis-lib"
    / "tests"
    / "data"
    / "kosi"
    / "kosi-resolved-report.json"
)


def _bom(path):
    path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [
                    {
                        "type": "library",
                        "name": "okhttp",
                        "group": "com.squareup.okhttp3",
                        "version": "4.12.0",
                        "purl": "pkg:maven/com.squareup.okhttp3/okhttp@4.12.0",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return str(path)


def _fake_run_kosi(calls):
    from xbom_lib.kosi import KosiResult

    def run_kosi(src_dir, out_path, *, backend, logger=None, timeout=None):
        calls.append((src_dir, out_path, backend))
        shutil.copyfile(FIXTURE, out_path)
        return KosiResult(success=True, report_path=out_path, backend=backend)

    return run_kosi


def test_kotlin_scan_runs_kosi_and_reads_its_report(tmp_path, monkeypatch):
    import xbom_lib.kosi as kosi_mod

    calls = []
    monkeypatch.setattr(kosi_mod, "run_kosi", _fake_run_kosi(calls))
    bom_file = _bom(tmp_path / "sbom-kotlin.cdx.json")
    result = bom_mod.run_kosi_reachability(
        bom_file, str(tmp_path), options={"project_type": ["kotlin"]}
    )
    assert result is not None and result.status == "completed"
    assert result.records, "the adapter turned the recorded report into records"
    assert calls and calls[0][2] == "syntax", "the default backend starts no build"
    assert os.path.isfile(tmp_path / "analysis" / "kosi" / "kosi.json")
    assert KOSI_REACHABLES_SLICE_FILE == "kosi-reachables.slices.json"
    assert not os.path.isfile(tmp_path / KOSI_REACHABLES_SLICE_FILE), (
        "the converted slice is no longer written"
    )
    assert not os.path.exists(tmp_path / "kotlin-reachables.slices.json")


def test_a_stale_converted_slice_is_cleared_when_kosi_runs(tmp_path, monkeypatch):
    import xbom_lib.kosi as kosi_mod

    calls = []
    monkeypatch.setattr(kosi_mod, "run_kosi", _fake_run_kosi(calls))
    bom_file = _bom(tmp_path / "sbom-kotlin.cdx.json")
    stale = tmp_path / KOSI_REACHABLES_SLICE_FILE
    stale.write_text("[]")
    bom_mod.run_kosi_reachability(
        bom_file, str(tmp_path), options={"project_type": ["kotlin"]}
    )
    assert not stale.exists(), "a slice left by an earlier run must not survive"


def test_a_stale_converted_slice_is_cleared_even_without_a_report(tmp_path, monkeypatch):
    import xbom_lib.kosi as kosi_mod

    def failing_run_kosi(src_dir, out_path, *, backend, logger=None, timeout=None):
        from xbom_lib.kosi import KosiResult

        return KosiResult(success=False, skipped=True, report_path=out_path, backend=backend)

    monkeypatch.setattr(kosi_mod, "run_kosi", failing_run_kosi)
    bom_file = _bom(tmp_path / "sbom-kotlin.cdx.json")
    stale = tmp_path / KOSI_REACHABLES_SLICE_FILE
    stale.write_text("[]")
    result = bom_mod.run_kosi_reachability(
        bom_file, str(tmp_path), options={"project_type": ["kotlin"]}
    )
    assert result is not None and result.status == "not-assessed"
    assert result.reason
    assert not stale.exists()


def test_other_types_and_reachability_off_do_not_run_kosi(tmp_path, monkeypatch):
    import xbom_lib.kosi as kosi_mod

    calls = []
    monkeypatch.setattr(kosi_mod, "run_kosi", _fake_run_kosi(calls))
    bom_file = _bom(tmp_path / "sbom-python.cdx.json")
    assert not bom_mod.run_kosi_reachability(
        bom_file, str(tmp_path), options={"project_type": ["python"]}
    )
    assert not bom_mod.run_kosi_reachability(
        bom_file,
        str(tmp_path),
        options={"project_type": ["kotlin"], "reachability_analyzer": "off"},
    )
    assert calls == []
