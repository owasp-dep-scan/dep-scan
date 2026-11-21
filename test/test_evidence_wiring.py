"""The evidence store wiring, end to end.

The scans here run the real enrichment stage over the trimmed repotests
fixtures: an atom-only Python project and a .NET project whose dosai report
the pinned data carries. Everything around them (the database, the matching
stage, the rendering) is stubbed the way the scan-directory tests stub it, so
the tests assert exactly what the BOM step, the enrichment stage and the
finish stage write.
"""

import hashlib
import json
import shutil
from pathlib import Path

import pytest

from depscan import api
from depscan.lib import doctor as doctor_mod
from depscan.lib import pipeline, vdb_setup

DATA_DIR = Path(__file__).parent / "data"
FIXTURES = DATA_DIR / "repotests"

# The reached purls the trimmed dejacode fixture carries: the atom adapter
# turns its reachables slices into reached-flow records, and the engine counts
# exactly these purls.
DEJACODE_REACHED_PURLS = {
    "pkg:pypi/defusedxml@0.7.1",
    "pkg:pypi/django-axes@8.3.1",
    "pkg:pypi/django-crispy-forms@2.7",
    "pkg:pypi/django-guardian@3.5.2",
    "pkg:pypi/django-otp@1.7.5",
    "pkg:pypi/django-registration@5.2.1",
    "pkg:pypi/django@6.1.2",
    "pkg:pypi/license-expression@30.4.4",
    "pkg:pypi/odfdo@3.27.3",
    "pkg:pypi/qrcode@8.2",
    "pkg:pypi/requests@2.34.2",
}


@pytest.fixture
def scan_stubs(monkeypatch):
    """Stub the database, the matching stage and the rendering of a scan."""
    monkeypatch.setattr(vdb_setup, "resolve_scan_vdb_image", lambda args: ("oras://vdb", False, "app-only"))
    monkeypatch.setattr(vdb_setup, "vdb_download_needed", lambda url, d: (False, ""))
    monkeypatch.setattr(vdb_setup, "configure_vdb_readonly", lambda: None)
    monkeypatch.setattr(vdb_setup, "ensure_vdb_usable", lambda: None)
    monkeypatch.setattr(pipeline, "get_pkgs_by_scope", lambda pkg_list: {})

    class StubResult:
        success = True
        prioritized_pkg_vuln_trees = {}

        def __init__(self, pkg_vulnerabilities):
            self.pkg_vulnerabilities = pkg_vulnerabilities

    class StubVDRAnalyzer:
        def __init__(self, vdr_options):
            self.vdr_options = vdr_options

        def process(self):
            from analysis_lib.findings.exploitability import annotate_exploitability

            vulns = [
                {
                    "id": "CVE-2024-1111",
                    "bom-ref": "CVE-2024-1111/pkg:pypi/requests@2.32.1",
                    "affects": [{"ref": "pkg:pypi/requests@2.32.1"}],
                    "ratings": [{"severity": "high", "score": 8.1, "method": "CVSSv31"}],
                }
            ]
            result = StubResult(vulns)
            result.exploitability = annotate_exploitability(
                vulns, self.vdr_options.exploitability_inputs
            )
            return result

    monkeypatch.setattr(pipeline, "VDRAnalyzer", StubVDRAnalyzer)
    monkeypatch.setattr(pipeline.ReportGenerator, "parse_and_generate_report", lambda self: None)
    monkeypatch.setattr(pipeline.console, "save_html", lambda *a, **k: None)
    monkeypatch.setattr(pipeline.console, "save_text", lambda *a, **k: None)
    monkeypatch.setattr(doctor_mod, "_vdb_status", lambda: dict(_FULL_VDB_DATA))


_FULL_VDB_DATA = {
    "present": True,
    "directory": "/tmp/vdb",
    "image": "ghcr.io/appthreat/vdb7-app-only:v7.0.x-xz",
    "flavor": "app-only",
    "shards": {"enabled": False, "present": []},
    "createdUtc": "2026-11-01T00:00:00+00:00",
    "ageHours": 10.0,
    "stale": False,
    "maxAgeHours": 48,
    "cveDataCount": 100,
    "cveIndexCount": 100,
    "extendedMetadataPresent": False,
    "cveMetadataRows": 0,
}


def _scan_fixture(tmp_path, name, **overrides):
    """Copy one fixture project into a temporary BOM directory and scan it.

    The reports directory is left to default to the BOM directory copy, so
    the scan directory holds the VDR and can be loaded back.
    """
    bom_dir = tmp_path / name
    bom_dir.mkdir()
    for entry in (FIXTURES / name).iterdir():
        if entry.is_file():
            shutil.copy2(entry, bom_dir / entry.name)
    options = {
        "bom_dir": str(bom_dir),
        "no_banner": True,
        "reachability_analyzer": "SemanticReachability",
    }
    options.update(overrides)
    return api.scan(api.scan_options(**options), render=False)


def _manifest_of(reports_dir):
    return json.loads((Path(reports_dir) / "depscan.manifest.json").read_text())


def _enrichment_stage(manifest):
    return next(stage for stage in manifest["stages"] if stage["name"] == "enrichment")


def test_a_bom_dir_scan_writes_the_evidence_store_and_lists_it(scan_stubs, tmp_path):
    result = _scan_fixture(tmp_path, "dejacode")
    reports = Path(result.reports_dir)
    store = reports / "evidence.jsonl"
    index = reports / "evidence.index.json"
    assert store.is_file(), "the enrichment stage writes the store even before the findings exist"
    assert index.is_file(), "the finish stage writes the index after the findings exist"
    lines = store.read_text(encoding="utf-8").splitlines()
    assert lines, "the atom adapter produced records for the atom-only project"
    records = [json.loads(line) for line in lines]
    assert records == sorted(records, key=lambda r: r["id"]), "the store is sorted by id"
    index_document = json.loads(index.read_text())
    assert index_document["schemaVersion"] == "1"
    manifest = result.manifest
    digests = {entry["path"]: entry for entry in manifest["files"]}
    assert digests["evidence.jsonl"]["role"] == "evidence"
    assert digests["evidence.index.json"]["role"] == "evidence"
    assert digests["evidence.jsonl"]["producer"] == "dep-scan"
    for name in ("evidence.jsonl", "evidence.index.json"):
        expected = hashlib.sha256((reports / name).read_bytes()).hexdigest()
        assert digests[name]["sha256"] == expected
    enrichment = _enrichment_stage(manifest)
    assert enrichment["outputs"] == [{"file": "evidence.jsonl", "status": "completed"}]


def test_the_engine_counts_the_fixture_purls_from_the_records(scan_stubs, tmp_path):
    from analysis_lib import ReachabilityAnalysisKV
    from analysis_lib.reachability import SemanticReachability

    result = _scan_fixture(tmp_path, "dejacode")
    opts = ReachabilityAnalysisKV(
        project_types=["bom"], src_dir=str(tmp_path), bom_dir=result.reports_dir
    )
    res = SemanticReachability(opts).process()
    assert set((res.reached_purls or {}).keys()) == DEJACODE_REACHED_PURLS


def test_analyzer_entries_come_from_the_adapter_results(scan_stubs, tmp_path):
    result = _scan_fixture(tmp_path, "dejacode")
    analyzers = {
        entry["name"]: entry for entry in _enrichment_stage(result.manifest)["analyzers"]
    }
    assert set(analyzers) == {"atom", "rusi", "golem", "kosi", "dosai"}
    assert analyzers["atom"]["status"] == "completed", "the adapter read the atom slices"
    assert analyzers["atom"]["capability"] == "reachability"
    for name in ("rusi", "golem", "kosi", "dosai"):
        assert analyzers[name]["status"] == "not-assessed", name
        assert "no report" in analyzers[name]["reason"], name


def test_a_dosai_bom_dir_scan_completes_dosai_from_the_raw_report(scan_stubs, tmp_path):
    result = _scan_fixture(tmp_path, "dotnet-podcasts")
    analyzers = {
        entry["name"]: entry for entry in _enrichment_stage(result.manifest)["analyzers"]
    }
    assert analyzers["dosai"]["status"] == "completed", (
        "the adapter found and read the dosai report in the BOM directory"
    )
    assert analyzers["atom"]["status"] == "not-assessed", (
        "the .NET project carries no atom slices"
    )
    # dosai's raw report and the record kinds it supports.
    store = Path(result.reports_dir) / "evidence.jsonl"
    kinds = {}
    for line in store.read_text(encoding="utf-8").splitlines():
        record = json.loads(line)
        if record["producer"]["name"] == "dosai":
            kinds[record["kind"]] = kinds.get(record["kind"], 0) + 1
    assert kinds.get("reached-flow"), "dosai's reachability became reached-flow records"
    assert kinds.get("entry-point"), "dosai's attack surface became entry-point records"
    assert kinds.get("exploit-chain"), "dosai's exploit chains became exploit-chain records"
    index_document = json.loads((Path(result.reports_dir) / "evidence.index.json").read_text())
    assert index_document["byComponent"], "the index maps the dosai purls to their records"


def test_a_just_scanned_directory_loads_and_reports(scan_stubs, tmp_path, capsys):
    from depscan.lib import report as report_lib

    result = _scan_fixture(tmp_path, "dejacode")
    loaded = api.load_scan(result.reports_dir)
    assert loaded.manifest is not None
    assert loaded.manifest["layoutVersion"] == "2.0"
    assert report_lib.run_report_command([str(result.reports_dir)]) == 0
    output = capsys.readouterr().out
    assert "layout" in output and "2.0" in output


def test_a_layout_1_scan_directory_of_a_just_scanned_dir_is_refused(scan_stubs, tmp_path):
    result = _scan_fixture(tmp_path, "dejacode")
    manifest_path = Path(result.reports_dir) / "depscan.manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["layoutVersion"] = "1.0"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    with pytest.raises(api.ScanError) as excinfo:
        api.load_scan(result.reports_dir)
    message = str(excinfo.value)
    assert "1.0" in message and "2.0" in message


def test_reachability_off_still_writes_an_empty_store(scan_stubs, tmp_path):
    result = _scan_fixture(tmp_path, "dejacode", reachability_analyzer="off")
    store = Path(result.reports_dir) / "evidence.jsonl"
    assert store.is_file()
    assert store.read_text(encoding="utf-8") == ""
    index = Path(result.reports_dir) / "evidence.index.json"
    assert index.is_file()
    index_document = json.loads(index.read_text())
    assert index_document["byComponent"] == {}
    enrichment = _enrichment_stage(result.manifest)
    assert enrichment["status"] == "skipped"
    assert enrichment["analyzers"] == []
