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


# The tool versions the fake scripts print, exactly as the doctor tests and
# the scan-directory tests fake them.
FAKE_TOOLS = {
    "cdxgen": ("CDXGEN_CMD", "CycloneDX Generator 13.8.0"),
    "golem": ("GOLEM_CMD", "golem 9.9.9"),
    "rusi": ("RUSI_CMD", "rusi 9.9.9"),
    "dosai": ("DOSAI_CMD", "dosai 9.9.9+deadbeef"),
    "kosi": ("KOSI_CMD", '{"name": "kosi", "version": "9.9.9"}'),
    "go": (None, "go version go9.9.9 test"),
    "dotnet": (None, "9.9.100"),
}


@pytest.fixture
def fake_tools(tmp_path, monkeypatch):
    """Install one fake per tool the reachability capabilities name, so the
    capability table never explains a missing report: what the analyzers
    then say is what their adapters said. The fakes live on a PATH of their
    own; everything else stays unreachable there."""
    empty_path = tmp_path / "stripped-path"
    empty_path.mkdir()
    for var in (
        "CDXGEN_PLUGINS_DIR",
        "CDXGEN_CMD",
        "GOLEM_CMD",
        "DEPSCAN_GOLEM_BINARY",
        "RUSI_CMD",
        "DEPSCAN_RUSI_BINARY",
        "DOSAI_CMD",
        "DEPSCAN_DOSAI_BINARY",
        "KOSI_CMD",
        "DEPSCAN_KOSI_BINARY",
    ):
        monkeypatch.delenv(var, raising=False)

    real_version_command = doctor_mod._version_command

    def version_command(path, args):
        try:
            with open(path, encoding="utf-8", errors="replace") as fp:
                is_fake = fp.readline().startswith("#!/usr/bin/env python3")
        except OSError:
            is_fake = False
        if is_fake:
            import sys

            return [sys.executable, str(path), *args]
        return real_version_command(path, args)

    monkeypatch.setattr(doctor_mod, "_version_command", version_command)
    fake_paths = {}
    for name, (env_name, output) in FAKE_TOOLS.items():
        script = tmp_path / f"fake-{name}.py"
        script.write_text(
            "#!/usr/bin/env python3\nimport sys\nprint({!r})\n".format(output),
            encoding="utf-8",
        )
        script.chmod(0o755)
        fake_paths[name] = str(script)
        if env_name:
            monkeypatch.setenv(env_name, str(script))
    real_find = doctor_mod.find_executable

    def find(name):
        return fake_paths.get(name) or real_find(name)

    monkeypatch.setattr(doctor_mod, "find_executable", find)
    monkeypatch.setenv("PATH", str(empty_path))
    monkeypatch.setenv("APPDATA", str(empty_path))


#: The package the stubbed matching stage reports a finding for: one of the
#: purls the dejacode fixture reaches, so the finding joins its evidence.
STUB_FINDING_PURL = "pkg:pypi/requests@2.34.2"


def install_scan_stubs(patch):
    """Stub the database, the matching stage and the rendering of a scan.

    ``patch(target, name, value)`` installs each stub: ``monkeypatch.setattr``
    inside a test, plain ``setattr`` in the subprocess scans of the
    determinism test.
    """
    patch(vdb_setup, "resolve_scan_vdb_image", lambda args: ("oras://vdb", False, "app-only"))
    patch(vdb_setup, "vdb_download_needed", lambda url, d: (False, ""))
    patch(vdb_setup, "configure_vdb_readonly", lambda: None)
    patch(vdb_setup, "ensure_vdb_usable", lambda: None)
    patch(pipeline, "get_pkgs_by_scope", lambda pkg_list: {})

    class StubResult:
        success = True
        prioritized_pkg_vuln_trees = {}
        exploitability = None

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
                    "bom-ref": f"CVE-2024-1111/{STUB_FINDING_PURL}",
                    "affects": [{"ref": STUB_FINDING_PURL}],
                    "ratings": [{"severity": "high", "score": 8.1, "method": "CVSSv31"}],
                }
            ]
            result = StubResult(vulns)
            result.exploitability = annotate_exploitability(
                vulns, self.vdr_options.exploitability_inputs
            )
            return result

    patch(pipeline, "VDRAnalyzer", StubVDRAnalyzer)
    patch(pipeline.ReportGenerator, "parse_and_generate_report", lambda self: None)
    patch(pipeline.console, "save_html", lambda *a, **k: None)
    patch(pipeline.console, "save_text", lambda *a, **k: None)
    patch(doctor_mod, "_vdb_status", lambda: dict(_FULL_VDB_DATA))


@pytest.fixture
def scan_stubs(monkeypatch):
    """Stub the database, the matching stage and the rendering of a scan."""
    install_scan_stubs(monkeypatch.setattr)


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

    The BOM directory copy is also the reports directory, the way a scan
    without an explicit reports directory treats its single BOM directory
    target, so the scan directory holds the VDR and can be loaded back.
    """
    bom_dir = tmp_path / name
    bom_dir.mkdir()
    for entry in (FIXTURES / name).iterdir():
        if entry.is_file():
            shutil.copy2(entry, bom_dir / entry.name)
    options = {
        "bom_dir": str(bom_dir),
        "reports_dir": str(bom_dir),
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
    assert manifest is not None
    digests = {entry["path"]: entry for entry in manifest["files"]}
    assert digests["evidence.jsonl"]["role"] == "evidence"
    assert digests["evidence.index.json"]["role"] == "evidence"
    assert digests["evidence.jsonl"]["producer"] == "dep-scan"
    for name in ("evidence.jsonl", "evidence.index.json"):
        expected = hashlib.sha256((reports / name).read_bytes()).hexdigest()
        assert digests[name]["sha256"] == expected
    enrichment = _enrichment_stage(manifest)
    assert enrichment["outputs"] == [{"file": "evidence.jsonl", "status": "completed"}]


def test_a_stale_converted_slice_in_a_bom_dir_is_never_atom_evidence(scan_stubs, tmp_path):
    """A BOM directory that an earlier dep-scan version scanned may still
    carry a converted language-tool slice (rust-, go- or dotnet-). Those
    files are no longer written or read, and atom's adapter must not adopt
    one as atom evidence: the stems filter excludes them, so the store holds
    no record sourced from the stale file and its purls stay unreached."""
    bom_dir = tmp_path / "dejacode"
    bom_dir.mkdir()
    for entry in (FIXTURES / "dejacode").iterdir():
        if entry.is_file():
            shutil.copy2(entry, bom_dir / entry.name)
    (bom_dir / "rust-reachables.slices.json").write_text(
        json.dumps(
            [{"flows": [{"tags": "pkg:cargo/stale@9.9.9, rust"}], "purls": ["pkg:cargo/stale@9.9.9"]}]
        ),
        encoding="utf-8",
    )
    result = api.scan(
        api.scan_options(
            bom_dir=str(bom_dir),
            reports_dir=str(bom_dir),
            reachability_analyzer="SemanticReachability",
            no_banner=True,
        )
    )
    records = [
        json.loads(line)
        for line in (Path(result.reports_dir) / "evidence.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert records, "the atom adapter produced records for the atom-only project"
    assert not any(r["source"] == "rust-reachables.slices.json" for r in records), (
        "a stale converted slice must not be read as atom's own output"
    )
    assert not any("pkg:cargo/stale@9.9.9" in r["subject"]["purls"] for r in records)


def test_a_rescan_of_a_reused_bom_dir_drops_deleted_reports_records(scan_stubs, tmp_path):
    """A reused BOM directory must not keep a previous scan's records for a
    report this scan no longer finds: the store is written from this scan's
    adapters alone, so deleting a slice file (or truncating it, which the
    atom adapter refuses) removes its records and its purls stop counting,
    exactly as the stale converted slices are cleared, never read."""
    bom_dir = tmp_path / "dejacode"
    bom_dir.mkdir()
    for entry in (FIXTURES / "dejacode").iterdir():
        if entry.is_file():
            shutil.copy2(entry, bom_dir / entry.name)
    options = {
        "bom_dir": str(bom_dir),
        "reports_dir": str(bom_dir),
        "reachability_analyzer": "SemanticReachability",
        "no_banner": True,
    }
    api.scan(api.scan_options(**options))
    store = json.loads("[" + ",".join(l for l in (bom_dir / "evidence.jsonl").read_text().splitlines() if l) + "]")
    assert any(r["source"] == "python-usages.slices.json" for r in store)
    usages = bom_dir / "python-usages.slices.json"
    usages.unlink()
    api.scan(api.scan_options(**options))
    store = json.loads("[" + ",".join(l for l in (bom_dir / "evidence.jsonl").read_text().splitlines() if l) + "]")
    assert not any(r["source"] == "python-usages.slices.json" for r in store), (
        "a deleted report's records must not survive the rescan"
    )
    # A report this scan cannot read is refused by the adapter; its records
    # must not survive either, so the engine cannot count stale evidence.
    (bom_dir / "python-reachables.slices.json").write_text("{ truncated")
    api.scan(api.scan_options(**options))
    store = json.loads("[" + ",".join(l for l in (bom_dir / "evidence.jsonl").read_text().splitlines() if l) + "]")
    assert not any(r["source"] == "python-reachables.slices.json" for r in store), (
        "a report the adapter refused must leave no records behind"
    )


def test_the_same_scan_twice_writes_byte_identical_stores(scan_stubs, tmp_path):
    """Two scans of the same BOM directory produce the same evidence.jsonl
    and evidence.index.json byte for byte: the record ids are hashes of what
    the producers stated, so nothing run-dependent may leak into the store."""
    first_dir = tmp_path / "first"
    second_dir = tmp_path / "second"
    for target in (first_dir, second_dir):
        target.mkdir()
        for entry in (FIXTURES / "dotnet-podcasts").iterdir():
            if entry.is_file():
                shutil.copy2(entry, target / entry.name)
    options = {
        "bom_dir": str(first_dir),
        "reports_dir": str(first_dir),
        "reachability_analyzer": "SemanticReachability",
        "no_banner": True,
    }
    api.scan(api.scan_options(**options))
    options.update(bom_dir=str(second_dir), reports_dir=str(second_dir))
    api.scan(api.scan_options(**options))
    for name in ("evidence.jsonl", "evidence.index.json"):
        first = (first_dir / name).read_bytes()
        second = (second_dir / name).read_bytes()
        assert first and first == second, f"{name} differs between two scans of the same input"


def test_the_engine_counts_the_fixture_purls_from_the_records(scan_stubs, tmp_path):
    from analysis_lib import ReachabilityAnalysisKV
    from analysis_lib.reachability import SemanticReachability

    result = _scan_fixture(tmp_path, "dejacode")
    opts = ReachabilityAnalysisKV(
        project_types=["bom"], src_dir=str(tmp_path), bom_dir=result.reports_dir
    )
    res = SemanticReachability(opts).process()
    assert set((res.reached_purls or {}).keys()) == DEJACODE_REACHED_PURLS


def test_analyzer_entries_come_from_the_adapter_results(scan_stubs, fake_tools, tmp_path):
    result = _scan_fixture(tmp_path, "dejacode")
    analyzers = {
        entry["name"]: entry for entry in _enrichment_stage(result.manifest)["analyzers"]
    }
    assert set(analyzers) == {"atom", "rusi", "golem", "kosi", "dosai"}
    assert analyzers["atom"]["status"] == "completed", "the adapter read the atom slices"
    assert analyzers["atom"]["capability"] == "reachability"
    for name in ("rusi", "golem", "kosi", "dosai"):
        assert analyzers[name]["status"] == "not-assessed", name
        assert f"no {name} report was found in the BOM directory" in analyzers[name]["reason"], (
            f"{name}: {analyzers[name]['reason']}"
        )


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


@pytest.mark.parametrize("left_behind", [("evidence.jsonl", "evidence.index.json"), ("evidence.index.json",)])
def test_a_scan_that_never_reaches_enrichment_lists_no_earlier_evidence(
    scan_stubs, tmp_path, left_behind
):
    """A BOM directory scan whose BOM has no packages stops before the
    enrichment stage, so it writes no store. The store and index an earlier
    scan left in that directory must not be indexed and listed in the
    manifest as this scan's evidence, and an index left without its store
    must not survive either."""
    bom_dir = tmp_path / "empty"
    bom_dir.mkdir()
    (bom_dir / "sbom-python.cdx.json").write_text(
        json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []})
    )
    stale = {
        "schemaVersion": "1",
        "id": "ev-0000000000000001",
        "producer": {"name": "atom", "version": "x", "reportSchemaVersion": "unknown"},
        "kind": "reached-flow",
        "polarity": "positive",
        "subject": {"purls": ["pkg:pypi/stale@1.0"]},
        "source": "old.json",
        "locations": [],
        "caveats": [],
    }
    if "evidence.jsonl" in left_behind:
        (bom_dir / "evidence.jsonl").write_text(json.dumps(stale) + "\n")
    (bom_dir / "evidence.index.json").write_text(
        json.dumps({"schemaVersion": "1", "byComponent": {"pkg:pypi/stale@1.0": [stale["id"]]}})
    )
    result = api.scan(
        api.scan_options(
            bom_dir=str(bom_dir),
            reports_dir=str(bom_dir),
            no_banner=True,
            reachability_analyzer="SemanticReachability",
        ),
        render=False,
    )
    stages = {stage["name"]: stage["status"] for stage in result.manifest["stages"]}
    assert stages["inventory"] == "skipped"
    assert "enrichment" not in stages
    listed = {entry["path"] for entry in result.manifest["files"]}
    assert "evidence.jsonl" not in listed and "evidence.index.json" not in listed
    assert not (bom_dir / "evidence.jsonl").exists()
    assert not (bom_dir / "evidence.index.json").exists()


def test_the_finding_joins_its_evidence_and_names_a_witness(scan_stubs, tmp_path):
    """The stubbed matching stage reports one finding for a package the
    fixture reaches. The finding must be graded on that package's records:
    the index maps the finding to them, and its exploitability names one of
    them, a reached-counted atom record with a path, as the witness."""
    result = _scan_fixture(tmp_path, "dejacode")
    assert len(result.findings) == 1, "the stubbed matching stage ran"
    finding = result.findings[0]
    assert finding["components"] == [STUB_FINDING_PURL]
    reports = Path(result.reports_dir)
    index = json.loads((reports / "evidence.index.json").read_text())
    joined = index["byFinding"][finding["id"]]
    assert joined, "the index joins the finding to the records of its package"
    records = {
        record["id"]: record
        for record in map(json.loads, (reports / "evidence.jsonl").read_text().splitlines())
    }
    assert set(joined) <= set(records)
    exploitability = finding["exploitability"]
    assert exploitability["axes"]["reach"] == "likely"
    witness = exploitability.get("witness")
    assert witness in joined, "the witness is one of the finding's own records"
    record = records[witness]
    assert record["producer"]["name"] == "atom"
    assert record["kind"] in ("reached-flow", "usage", "entry-point")
    assert record.get("path"), "a witness carries a path"
    assert STUB_FINDING_PURL in record["subject"]["purls"]


_SUBPROCESS_SCAN = """
import sys
sys.path.insert(0, sys.argv[1])
from test.test_evidence_wiring import install_scan_stubs
from depscan import api
install_scan_stubs(setattr)
for target in sys.argv[2:]:
    api.scan(
        api.scan_options(
            bom_dir=target,
            reports_dir=target,
            no_banner=True,
            reachability_analyzer="SemanticReachability",
        ),
        render=False,
    )
"""


def test_two_processes_with_different_hash_seeds_write_identical_stores(tmp_path):
    """Two scans of the same inputs in two interpreter processes, each with
    its own string hash seed, write byte-identical stores and indexes, so
    nothing in the record ids or the file order depends on set or dict
    iteration that hashing could reorder."""
    import os
    import subprocess
    import sys

    repo_root = Path(__file__).resolve().parent.parent
    runs = {}
    for seed in ("1", "2"):
        targets = []
        for name in ("dejacode", "dotnet-podcasts"):
            target = tmp_path / seed / name
            target.mkdir(parents=True)
            for entry in (FIXTURES / name).iterdir():
                if entry.is_file():
                    shutil.copy2(entry, target / entry.name)
            targets.append(str(target))
        env = {**os.environ, "PYTHONHASHSEED": seed}
        completed = subprocess.run(
            [sys.executable, "-c", _SUBPROCESS_SCAN, str(repo_root), *targets],
            env=env,
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr[-4000:]
        runs[seed] = targets
    for first, second in zip(runs["1"], runs["2"]):
        for name in ("evidence.jsonl", "evidence.index.json"):
            one = (Path(first) / name).read_bytes()
            two = (Path(second) / name).read_bytes()
            assert one and one == two, f"{name} of {Path(first).name} differs between processes"
