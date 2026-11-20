"""The scan directory: manifest, findings, analyzers, and loading it back.

The scan tests stub the database, the matching stage and the rendering the
way the API tests do, so no test here touches the network or a host
database; every stub records its calls and the tests assert the recording.
The doctor report is real, pointed at fake tools the way the doctor tests
point at them, so the capability entries in a manifest say what a machine
with (or without) those tools would say.

The checked-in fixture under ``test/data/scan-directory`` was written by
api.scan with a stubbed doctor report (cdxgen present, the language tools
and their toolchains missing); the input path was then made relative and
the home directory replaced. Its manifest is hand-checked field by field in
the compatibility tests.
"""

import dataclasses
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from types import SimpleNamespace
from pathlib import Path

import pytest

from analysis_lib.findings.schemas import validate
from depscan import api
from depscan.lib import doctor as doctor_mod
from depscan.lib import pipeline, scan_directory, vdb_setup
from depscan.lib import report as report_lib
from depscan.lib.scan_directory import (
    REDACTED,
    atomic_write_json,
    classify_file,
    home_relative,
    option_holds_secret,
    redact_options,
)

DATA_DIR = Path(__file__).parent / "data"
FIXTURE_DIR = DATA_DIR / "scan-directory"

VULN_REQUESTS = {
    "id": "CVE-2024-1111",
    "bom-ref": "CVE-2024-1111/pkg:pypi/requests@2.32.1",
    "affects": [{"ref": "pkg:pypi/requests@2.32.1"}],
    "ratings": [{"severity": "high", "score": 8.1, "method": "CVSSv31"}],
    "fixed_location": "2.32.2",
    "advisories": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-1111"}],
    "cwes": [400],
}


def _write_bom(path, name="app"):
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {"component": {"name": name, "type": "application"}},
        "components": [
            {
                "name": "requests",
                "version": "2.32.1",
                "purl": "pkg:pypi/requests@2.32.1",
                "bom-ref": "pkg:pypi/requests@2.32.1",
                "type": "library",
            }
        ],
    }
    path.write_text(json.dumps(bom))
    return str(path)


class _StubVdrResult:
    success = True
    prioritized_pkg_vuln_trees = {}
    exploitability = None

    def __init__(self, pkg_vulnerabilities, success=True):
        self.pkg_vulnerabilities = pkg_vulnerabilities
        self.success = success


@pytest.fixture
def scan_stubs(monkeypatch):
    """Stub the database and matching stages of a scan and record the calls.

    The doctor report stays real, with the database inspection replaced by a
    known state so no test depends on, or touches, the machine's database.
    """
    calls = {"matching": [], "database": []}
    monkeypatch.setattr(
        vdb_setup, "resolve_scan_vdb_image", lambda args: ("oras://vdb", False, "app-only")
    )
    monkeypatch.setattr(vdb_setup, "vdb_download_needed", lambda url, d: (False, ""))
    monkeypatch.setattr(vdb_setup, "configure_vdb_readonly", lambda: None)
    monkeypatch.setattr(vdb_setup, "ensure_vdb_usable", lambda: calls["database"].append(1))
    monkeypatch.setattr(pipeline, "get_pkgs_by_scope", lambda pkg_list: {})
    monkeypatch.setattr(
        pipeline,
        "get_pkg_list",
        lambda f: ([{"purl": "pkg:pypi/requests@2.32.1", "name": "requests"}], []),
    )
    monkeypatch.setattr(pipeline.ReportGenerator, "parse_and_generate_report", lambda self: None)
    monkeypatch.setattr(pipeline.console, "save_html", lambda *a, **k: None)
    monkeypatch.setattr(pipeline.console, "save_text", lambda *a, **k: None)

    class StubVDRAnalyzer:
        def __init__(self, vdr_options):
            calls["matching"].append(vdr_options)
            self.vdr_options = vdr_options

        def process(self):
            # The stub replaces only the vulnerability search, so it runs the
            # same exploitability grading step the real analyzer runs.
            from analysis_lib.findings.exploitability import annotate_exploitability

            vulns = [dict(VULN_REQUESTS)]
            result = _StubVdrResult(vulns)
            result.exploitability = annotate_exploitability(
                vulns, self.vdr_options.exploitability_inputs
            )
            return result

    monkeypatch.setattr(pipeline, "VDRAnalyzer", StubVDRAnalyzer)
    monkeypatch.setattr(doctor_mod, "_vdb_status", lambda: dict(_FULL_VDB_DATA))
    return calls


# The doctor data state the fake tools are evaluated against: a present,
# fresh, populated database.
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

# The tools the reachability capabilities name, with their env overrides and
# the version line the fake prints, exactly as the doctor tests fake them.
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
    """Install one fake per tool the capabilities name, then strip the PATH.

    ``remove`` makes one tool unresolvable again, which is how the
    missing-analyzer tests take one analyzer away at a time.
    """
    empty_path = tmp_path / "stripped-path"
    empty_path.mkdir()
    monkeypatch.setenv("PATH", str(empty_path))
    # On Windows cdxgen is also looked up under %APPDATA%\npm.
    monkeypatch.setenv("APPDATA", str(empty_path))
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

    installed = {}

    def script(name):
        path = tmp_path / f"fake-{name}.py"
        path.write_text(
            f"#!/usr/bin/env python3\nimport sys\nprint({FAKE_TOOLS[name][1]!r})\n",
            encoding="utf-8",
        )
        path.chmod(0o755)
        return str(path)

    real_version_command = doctor_mod._version_command

    def version_command(path, args):
        try:
            with open(path, encoding="utf-8", errors="replace") as fp:
                is_fake = fp.readline().startswith("#!/usr/bin/env python3")
        except OSError:
            is_fake = False
        if is_fake:
            return [sys.executable, str(path), *args]
        return real_version_command(path, args)

    monkeypatch.setattr(doctor_mod, "_version_command", version_command)
    fake_paths = {name: script(name) for name in FAKE_TOOLS}

    def install():
        for name, (env_name, _output) in FAKE_TOOLS.items():
            if env_name:
                monkeypatch.setenv(env_name, fake_paths[name])
            else:
                installed[name] = fake_paths[name]

    def remove(name):
        env_name = FAKE_TOOLS[name][0]
        if env_name:
            monkeypatch.delenv(env_name, raising=False)
        installed.pop(name, None)

    real_find = doctor_mod.find_executable

    def find(name):
        return installed.get(name) or real_find(name)

    monkeypatch.setattr(doctor_mod, "find_executable", find)
    install()
    return {"remove": remove, "paths": fake_paths, "install": install}


def _manifest_of(reports_dir):
    return json.loads((Path(reports_dir) / "depscan.manifest.json").read_text())


# ---------------------------------------------------------------------------
# the round trip: scan, load, report
# ---------------------------------------------------------------------------


def test_round_trip_scan_load_and_report(scan_stubs, tmp_path, capsys):
    """A scan, load_scan and depscan report on the same directory agree.

    The vulnerabilities and the project types the scan returned are what the
    directory loads back, the findings file carries the conversion of the
    same entries, and the report renders them again.
    """
    bom = _write_bom(tmp_path / "given.cdx.json")
    reports = tmp_path / "reports"
    result = api.scan(api.scan_options(bom=bom, reports_dir=str(reports), no_banner=True))

    # Positive controls: the stubbed matching stage and database guard ran.
    assert scan_stubs["matching"], "the matching stage never ran"
    assert scan_stubs["database"], "the database stage never ran"

    loaded = api.load_scan(str(reports))
    assert loaded.vulnerabilities == result.vulnerabilities
    assert loaded.project_types == result.project_types == ["bom"]
    assert loaded.types[0].vdr_file == result.types[0].vdr_file
    assert loaded.manifest is not None and result.manifest is not None
    assert loaded.findings == result.findings
    assert len(loaded.findings) == 1
    validate("finding", loaded.findings[0])
    validate("depscan-manifest", loaded.manifest)

    exit_code = report_lib.run_report_command([str(reports)])
    assert exit_code == 0
    output = capsys.readouterr().out
    assert "Vulnerabilities count: 1" in output
    assert "high: 1" in output
    assert "2.32.2" in output, "the fix version of the one advisory is rendered"


def test_findings_are_the_conversion_of_the_vdr_entries(scan_stubs, tmp_path):
    bom = _write_bom(tmp_path / "given.cdx.json")
    result = api.scan(
        api.scan_options(bom=bom, reports_dir=str(tmp_path / "reports"), no_banner=True),
        render=False,
    )
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding["rule"] == "CVE-2024-1111"
    assert finding["components"] == ["pkg:pypi/requests@2.32.1"]
    assert finding["fix"]["fixed_versions"] == ["2.32.2"]
    assert finding["producer"]["name"] == "dep-scan"
    assert finding["coverage"] == {"state": "assessed"}
    assert finding["id"].startswith("dsf1:")
    # The written file carries the same array the result holds.
    written = json.loads((Path(result.reports_dir) / "depscan.findings.json").read_text())
    assert written["schemaVersion"] == "2"
    assert written["findings"] == result.findings


def test_fingerprints_are_stable_across_runs(scan_stubs, tmp_path):
    bom = _write_bom(tmp_path / "given.cdx.json")
    first = api.scan(
        api.scan_options(bom=bom, reports_dir=str(tmp_path / "r1"), no_banner=True), render=False
    )
    second = api.scan(
        api.scan_options(bom=bom, reports_dir=str(tmp_path / "r2"), no_banner=True), render=False
    )
    assert [f["id"] for f in first.findings] == [f["id"] for f in second.findings]
    assert first.findings == second.findings


def test_the_scan_grades_exploitability_and_the_vdr_carries_the_properties(
    scan_stubs, tmp_path
):
    """The grade the scan computed reaches the findings document and the VDR
    file as the same assessment: axes, grade, rule and sources in the
    findings, depscan:exploitability: properties in the VDR."""
    bom = _write_bom(tmp_path / "given.cdx.json")
    result = api.scan(
        api.scan_options(bom=bom, reports_dir=str(tmp_path / "reports"), no_banner=True),
        render=False,
    )
    (finding,) = result.findings
    exploitability = finding["exploitability"]
    assert exploitability["grade"] == "moderate"
    assert exploitability["rule"] == "assessed"
    assert exploitability["axes"] == {
        "presence": "likely",
        "reach": "not_assessed",
        "exposure": "not_assessed",
        "barrier": "not_assessed",
    }
    # The BOM component was read for presence, but no analyzer reached it.
    assert exploitability["sources"] == {"presence": ["vdb", "cdxgen"]}
    vdr = json.loads((Path(result.reports_dir) / "given.vdr.json").read_text())
    properties = {
        prop["name"]: prop["value"] for prop in vdr["vulnerabilities"][0]["properties"]
    }
    assert properties["depscan:exploitability:grade"] == "moderate"
    assert properties["depscan:exploitability:rule"] == "assessed"
    assert properties["depscan:exploitability:axis:presence"] == "likely"
    assert properties["depscan:exploitability:axis:reach"] == "not_assessed"


def test_an_override_rule_table_reaches_the_grading(scan_stubs, tmp_path):
    """A valid --exploitability-rules file replaces the bundled table for the
    whole pipeline: its row's grade and id are what the findings carry."""
    bom = _write_bom(tmp_path / "given.cdx.json")
    rules = tmp_path / "rules.yaml"
    rules.write_text(
        'rules:\n  - id: org-standard\n    match:\n      presence: [likely]\n    grade: low\n',
        encoding="utf-8",
    )
    result = api.scan(
        api.scan_options(
            bom=bom,
            reports_dir=str(tmp_path / "reports"),
            exploitability_rules=str(rules),
            no_banner=True,
        ),
        render=False,
    )
    (finding,) = result.findings
    assert finding["exploitability"]["grade"] == "low"
    assert finding["exploitability"]["rule"] == "org-standard"


# ---------------------------------------------------------------------------
# the checked-in fixture: a scan directory this code wrote
# ---------------------------------------------------------------------------


def test_fixture_is_a_valid_scan_directory():
    """Every field of the checked-in manifest, hand-checked.

    The fixture was written by api.scan (see the module docstring); these
    assertions pin every field so a change to the writer shows up here.
    """
    manifest = _manifest_of(FIXTURE_DIR)
    validate("depscan-manifest", manifest)
    assert manifest["layoutVersion"] == "1.0"
    assert manifest["depscanVersion"] == "7.0.0.dev0"
    assert manifest["startUtc"].endswith("Z") and "T" in manifest["startUtc"]
    assert manifest["endUtc"].endswith("Z") and "T" in manifest["endUtc"]
    assert manifest["inputs"] == [
        {
            "type": "file",
            "path": "scan-directory/django-app.cdx.json",
            "sha256": "4a1835aeaa14efbb6166958018aba5fd35495858a97a32a1e8ab5185777da13d",
        }
    ]
    assert manifest["tools"] == [
        {
            "name": "cdxgen",
            "path": "~/.local/bin/cdxgen",
            "version": "13.8.0",
            "source": "path",
            "reason": None,
        },
        {
            "name": "rusi",
            "path": None,
            "version": None,
            "source": None,
            "reason": "rusi was not found; set RUSI_CMD or install it on PATH",
        },
        {
            "name": "golem",
            "path": None,
            "version": None,
            "source": None,
            "reason": "golem was not found; set GOLEM_CMD or install it on PATH",
        },
        {
            "name": "go",
            "path": None,
            "version": None,
            "source": None,
            "reason": "the Go toolchain golem needs was not found on PATH",
        },
        {
            "name": "dosai",
            "path": None,
            "version": None,
            "source": None,
            "reason": "dosai was not found; set DOSAI_CMD or install it on PATH",
        },
        {
            "name": "dotnet",
            "path": None,
            "version": None,
            "source": None,
            "reason": "the .NET runtime dosai needs was not found on PATH; a "
            "self-contained dosai binary (name containing '-full') would not need it",
        },
    ]
    assert manifest["platform"] == {"os": "linux", "arch": "x86_64", "libc": "glibc"}
    names = {capability["name"]: capability for capability in manifest["capabilities"]}
    assert names["vulnerabilities"]["status"] == "available"
    assert names["reachability"]["status"] == "available"
    assert names["reachability:go"]["status"] == "unavailable"
    assert names["memory-safety"]["status"] == "not-implemented"
    assert manifest["database"]["flavorUsed"] == "app-only"
    assert manifest["database"]["shardsUsed"] == []
    assert manifest["database"]["vulnerabilityDatabase"]["present"] is True
    assert manifest["database"]["vulnerabilityDatabase"]["cveIndexCount"] == 1000
    assert manifest["database"]["vulnerabilityDatabase"]["directory"] == "~/.cache/vdb"
    assert manifest["options"]["no_banner"] is True
    assert manifest["options"]["spec_version"] == "1.6"
    assert manifest["options"]["vdb_image"] is None
    assert manifest["options"]["cdxgen_args"] is None, "unset secrets are recorded as unset"
    assert "bom" not in manifest["options"], "path-valued options are recorded in inputs"
    assert "reports_dir" not in manifest["options"]
    assert "config" not in manifest["options"]

    stage_names = [stage["name"] for stage in manifest["stages"]]
    assert stage_names == [
        "setup",
        "database",
        "inventory",
        "licenses",
        "risk",
        "enrichment",
        "matching",
        "vdr",
    ]
    inventory = manifest["stages"][2]
    assert inventory["projectType"] == "bom"
    assert inventory["status"] == "completed"
    assert inventory["outputs"] == [{"file": "django-app.cdx.json", "status": "completed"}]
    enrichment = manifest["stages"][5]
    assert enrichment["status"] == "completed"
    assert enrichment["capabilities"] == ["reachability"]
    analyzers = {entry["name"]: entry for entry in enrichment["analyzers"]}
    # A BOM-only scan reads no slices, so no analyzer contributed.
    assert analyzers["atom"] == {
        "name": "atom",
        "capability": "reachability",
        "status": "not-assessed",
        "reason": "no reachables slices from atom were produced or given for this scan",
    }
    assert analyzers["rusi"]["status"] == "not-assessed"
    assert analyzers["rusi"]["capability"] == "reachability:rust"
    assert "rusi was not found" in analyzers["rusi"]["reason"]
    assert analyzers["golem"]["status"] == "not-assessed"
    assert "tool:go (go: the Go toolchain" in analyzers["golem"]["reason"]
    assert analyzers["dosai"]["status"] == "not-assessed"
    assert "tool:dotnet (dotnet: the .NET runtime" in analyzers["dosai"]["reason"]
    for entry in analyzers.values():
        assert "not a tool this version knows" not in entry.get("reason", "")
    assert enrichment["outputs"] == [
        {
            "file": "evidence.jsonl",
            "status": "not-assessed",
            "reason": scan_directory.EVIDENCE_NOT_PRODUCED_REASON,
        }
    ]
    matching = manifest["stages"][6]
    assert matching["status"] == "completed"
    assert matching["capabilities"] == ["vulnerabilities"]
    vdr_stage = manifest["stages"][7]
    assert vdr_stage["outputs"] == [{"file": "django-app.vdr.json", "status": "completed"}]
    assert [stage["name"] for stage in manifest["stages"]].count("matching") == 1

    digests = {entry["path"]: entry for entry in manifest["files"]}
    assert set(digests) == {
        "depscan.findings.json",
        "django-app.cdx.json",
        "django-app.vdr.json",
    }
    assert digests["django-app.cdx.json"]["role"] == "bom"
    assert digests["django-app.cdx.json"]["producer"] == "user"
    assert digests["django-app.vdr.json"]["role"] == "vdr"
    assert digests["django-app.vdr.json"]["producer"] == "dep-scan"
    assert digests["depscan.findings.json"]["role"] == "findings"
    for path, entry in digests.items():
        actual = hashlib.sha256((FIXTURE_DIR / path).read_bytes()).hexdigest()
        assert entry["sha256"] == actual, f"the digest of {path}"

    findings = json.loads((FIXTURE_DIR / "depscan.findings.json").read_text())
    assert findings["schemaVersion"] == scan_directory.FINDINGS_SCHEMA_VERSION
    assert len(findings["findings"]) == 1
    validate("finding", findings["findings"][0])
    vdr = json.loads((FIXTURE_DIR / "django-app.vdr.json").read_text())
    assert vdr["bomFormat"] == "CycloneDX"
    assert len(vdr["vulnerabilities"]) == 1


def test_fixture_loads_and_renders(capsys):
    loaded = api.load_scan(str(FIXTURE_DIR))
    assert loaded.project_types == ["bom"]
    assert loaded.types[0].bom_file == str(FIXTURE_DIR / "django-app.cdx.json")
    assert loaded.types[0].vdr_file == str(FIXTURE_DIR / "django-app.vdr.json")
    assert len(loaded.vulnerabilities) == 1
    assert loaded.vulnerabilities[0]["id"] == "CVE-2024-1111"
    assert len(loaded.findings) == 1
    assert loaded.manifest is not None
    assert loaded.manifest["layoutVersion"] == "1.0"

    assert report_lib.run_report_command([str(FIXTURE_DIR)]) == 0
    output = capsys.readouterr().out
    assert "layout" in output and "1.0" in output
    assert "Vulnerabilities count: 1" in output
    assert "high: 1" in output


def _copy_variant(tmp_path, layout_version):
    destination = tmp_path / f"variant-{layout_version.replace('.', '-')}"
    shutil.copytree(FIXTURE_DIR, destination)
    manifest = json.loads((destination / "depscan.manifest.json").read_text())
    manifest["layoutVersion"] = layout_version
    (destination / "depscan.manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return destination


def test_load_accepts_a_higher_minor_layout_version(tmp_path):
    variant = _copy_variant(tmp_path, "1.9")
    loaded = api.load_scan(str(variant))
    assert loaded.vulnerabilities[0]["id"] == "CVE-2024-1111"


def test_load_refuses_a_different_major_layout_version(tmp_path):
    variant = _copy_variant(tmp_path, "2.0")
    with pytest.raises(api.ScanError) as excinfo:
        api.load_scan(str(variant))
    message = str(excinfo.value)
    assert "2.0" in message and "1.0" in message, "the error names both versions"


# ---------------------------------------------------------------------------
# missing analyzers name the capability and the doctor's reason
# ---------------------------------------------------------------------------


def _enrichment_analyzers(manifest):
    for stage in manifest["stages"]:
        if stage["name"] == "enrichment":
            return {entry["name"]: entry for entry in stage["analyzers"]}
    return {}


# The reachables slices each analyzer leaves for the enrichment stage.
ANALYZER_SLICES = {
    "atom": "python-reachables.slices.json",
    "rusi": "rust-reachables.slices.json",
    "golem": "go-reachables.slices.json",
    "dosai": "dotnet-reachables.slices.json",
    "kosi": "kosi-reachables.slices.json",
}


def _bom_dir_scan(tmp_path, analyzers_with_slices):
    """A BOM directory scan whose directory holds the given analyzers' slices."""
    bom_dir = tmp_path / "boms"
    bom_dir.mkdir()
    _write_bom(bom_dir / "sbom-python.cdx.json")
    for name in analyzers_with_slices:
        (bom_dir / ANALYZER_SLICES[name]).write_text("[]")
    return api.scan(
        api.scan_options(
            bom_dir=str(bom_dir),
            reports_dir=str(tmp_path / "reports"),
            no_banner=True,
            reachability_analyzer="SemanticReachability",
        ),
        render=False,
    )


@pytest.mark.parametrize(
    "analyzer,tool_removed,capability,reason_fragment",
    [
        ("atom", "cdxgen", "reachability", "cdxgen"),
        ("rusi", "rusi", "reachability:rust", "rusi was not found"),
        ("golem", "golem", "reachability:go", "golem was not found"),
        ("dosai", "dosai", "reachability:dotnet", "dosai was not found"),
        ("kosi", "kosi", "reachability:kotlin", "kosi was not found"),
    ],
)
def test_a_missing_analyzer_is_not_assessed_with_the_doctor_reason(
    scan_stubs, fake_tools, tmp_path, analyzer, tool_removed, capability, reason_fragment
):
    """The analyzer whose tool is gone left no slices and is named with the
    capability and the doctor's reason; every analyzer whose slices the
    enrichment stage read stays completed."""
    fake_tools["remove"](tool_removed)
    others = [name for name in ANALYZER_SLICES if name != analyzer]
    analyzers = _enrichment_analyzers(_bom_dir_scan(tmp_path, others).manifest)
    assert set(analyzers) == set(ANALYZER_SLICES)
    assert analyzers[analyzer]["status"] == "not-assessed"
    assert analyzers[analyzer]["capability"] == capability
    assert reason_fragment in analyzers[analyzer]["reason"]
    assert capability in analyzers[analyzer]["reason"], "the entry names the capability too"
    for name in others:
        assert analyzers[name]["status"] == "completed", f"{name}: {analyzers[name]}"


def test_an_installed_analyzer_without_slices_is_not_reported_as_completed(
    scan_stubs, fake_tools, tmp_path
):
    """Every tool is present, but the scan was given only Python slices:
    the language analyzers produced nothing and say so."""
    analyzers = _enrichment_analyzers(_bom_dir_scan(tmp_path, ["atom"]).manifest)
    assert analyzers["atom"]["status"] == "completed"
    for name in ("rusi", "golem", "dosai", "kosi"):
        assert analyzers[name]["status"] == "not-assessed"
        assert analyzers[name]["reason"] == (
            f"no {ANALYZER_SLICES[name]} was produced or given for this scan"
        )


def test_analyzers_are_not_listed_when_reachability_is_off(scan_stubs, fake_tools, tmp_path):
    bom = _write_bom(tmp_path / "given.cdx.json")
    result = api.scan(
        api.scan_options(
            bom=bom,
            reports_dir=str(tmp_path / "reports"),
            no_banner=True,
            reachability_analyzer="off",
        ),
        render=False,
    )
    assert result.manifest is not None
    enrichment = next(s for s in result.manifest["stages"] if s["name"] == "enrichment")
    assert enrichment["status"] == "skipped"
    assert enrichment["analyzers"] == []


# ---------------------------------------------------------------------------
# an interrupted scan still writes a truthful manifest
# ---------------------------------------------------------------------------


def test_interrupted_scan_writes_a_manifest_naming_the_failed_stage(
    scan_stubs, monkeypatch, tmp_path
):
    def stop_the_scan(vdr_options):
        raise pipeline.ScanStageError("the matching stage could not read the database")

    monkeypatch.setattr(pipeline, "VDRAnalyzer", stop_the_scan)
    bom = _write_bom(tmp_path / "given.cdx.json")
    reports = tmp_path / "reports"
    with pytest.raises(api.ScanError) as excinfo:
        api.scan(api.scan_options(bom=bom, reports_dir=str(reports), no_banner=True), render=False)
    assert "matching stage" in str(excinfo.value)

    manifest = _manifest_of(reports)
    validate("depscan-manifest", manifest)
    failed = [stage for stage in manifest["stages"] if stage["status"] == "failed"]
    assert len(failed) == 1
    assert failed[0]["name"] == "matching"
    assert failed[0]["reason"] == "the matching stage could not read the database"
    assert (
        "matching"
        not in [stage["name"] for stage in manifest["stages"]][
            [stage["name"] for stage in manifest["stages"]].index("matching") + 1 :
        ]
    ), "no stage after the failed one is recorded"
    # The manifest lists only files that exist, and nothing after the VDR
    # stage ran, so there is no VDR to load.
    for entry in manifest["files"]:
        assert (Path(reports) / entry["path"]).is_file()
    with pytest.raises(api.ScanError) as excinfo:
        api.load_scan(str(reports))
    assert "matching stage did not complete" in str(excinfo.value)


@pytest.mark.parametrize(
    "purl,expected",
    [
        ("pkg:maven/com.google/guava@1.0", "not-assessed"),
        ("pkg:pypi/requests@2.32.1", "completed"),
    ],
)
def test_a_requested_risk_audit_records_what_it_could_audit(
    scan_stubs, monkeypatch, tmp_path, purl, expected
):
    """A BOM with only Maven packages cannot be audited; one with PyPI can.

    The requested audit that had nothing to read is recorded as not
    assessed with its reason, never as "not requested".
    """
    monkeypatch.setattr(
        pipeline, "get_pkg_list", lambda f: ([{"purl": purl, "name": "pkg"}], [])
    )
    monkeypatch.setattr(pipeline, "risk_audit", lambda *a: {})
    bom = _write_bom(tmp_path / "given.cdx.json")
    reports = tmp_path / "reports"
    api.scan(
        api.scan_options(bom=bom, reports_dir=str(reports), no_banner=True, risk_audit=True),
        render=False,
    )
    manifest = _manifest_of(reports)
    validate("depscan-manifest", manifest)
    risk = next(stage for stage in manifest["stages"] if stage["name"] == "risk")
    assert risk["status"] == expected
    if expected == "not-assessed":
        assert "no npm, PyPI or Cargo packages" in risk["reason"]


def test_interrupted_manifest_write_keeps_the_previous_content(tmp_path, monkeypatch):
    """The manifest goes through a temporary file and a rename, so a crash
    mid-write leaves the previous manifest intact and no debris behind."""
    path = tmp_path / "depscan.manifest.json"
    atomic_write_json(str(path), {"layoutVersion": "1.0"})
    original = json.loads(path.read_text())

    def explode(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(scan_directory.json, "dump", explode)
    with pytest.raises(OSError):
        atomic_write_json(str(path), {"layoutVersion": "9.9"})
    assert json.loads(path.read_text()) == original
    assert list(tmp_path.iterdir()) == [path], "no temporary file is left behind"


# ---------------------------------------------------------------------------
# secrets and paths
# ---------------------------------------------------------------------------


def test_every_parser_dest_is_accounted_for_by_the_secret_rule():
    """The redaction rule and the explicit extras cover every option name.

    A new option holding a secret under a name the rule does not match would
    be recorded verbatim; this sweep keeps that visible.
    """
    from depscan.cli_options import build_parser

    dests = {action.dest for action in build_parser()._actions if action.dest != "help"}
    extras = set(scan_directory._SECRET_OPTIONS)
    named = {dest for dest in dests if option_holds_secret(dest)}
    assert named == extras, (
        f"the rule's name match and the explicit extras disagree: "
        f"rule matched {sorted(named - extras)}, extras unmatched {sorted(extras - named)}"
    )


def test_redaction_records_that_a_secret_was_set_without_recording_it():
    options = {
        "vdb_image": "ghcr.io/user:password-here/vdb7:main",
        "cdxgen_args": "--tocs token-value-here",
        "cdxgen_server": None,
        "profile": "generic",
    }
    redacted = redact_options(options)
    # Positive control: the secret was set before the redaction.
    assert options["vdb_image"]
    assert options["cdxgen_args"]
    assert redacted["vdb_image"] == REDACTED
    assert redacted["cdxgen_args"] == REDACTED
    assert redacted["cdxgen_server"] is None, "an unset secret is recorded as unset"
    assert redacted["profile"] == "generic"
    assert "password" not in json.dumps(redacted)
    assert "token-value" not in json.dumps(redacted)


def test_home_path_stays_out_of_the_manifest_outside_inputs(scan_stubs, tmp_path, monkeypatch):
    """A scan written under a temporary home records the home path only in
    the inputs, and no username anywhere."""
    home = tmp_path / "ahome"
    (home / "project").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    # expanduser reads USERPROFILE on Windows
    monkeypatch.setenv("USERPROFILE", str(home))
    bom = _write_bom(home / "project" / "given.cdx.json")
    reports = home / "project" / "reports"
    result = api.scan(
        api.scan_options(bom=bom, reports_dir=str(reports), no_banner=True), render=False
    )
    document = json.loads((reports / "depscan.manifest.json").read_text())
    assert any(str(home) in entry["path"] for entry in document["inputs"]), (
        "the inputs record paths as given"
    )

    def strings_outside_inputs(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "inputs":
                    continue
                yield from strings_outside_inputs(value)
        elif isinstance(node, list):
            for item in node:
                yield from strings_outside_inputs(item)
        elif isinstance(node, str):
            yield node

    for text in strings_outside_inputs(document):
        assert str(home) not in text, f"the home path leaked outside inputs: {text}"
        assert os.path.basename(home) not in re.split(r"[/\\]", text), (
            f"a path segment named the home: {text}"
        )
    assert "depscan.html" not in {entry["path"] for entry in document["files"]}, (
        "render=False wrote no rendering output"
    )


def test_scan_directory_paths_are_relative_and_forward_slashed(scan_stubs, tmp_path):
    bom = _write_bom(tmp_path / "given.cdx.json")
    result = api.scan(
        api.scan_options(bom=bom, reports_dir=str(tmp_path / "reports"), no_banner=True),
        render=False,
    )
    manifest = result.manifest
    assert manifest is not None
    for entry in manifest["files"]:
        relative = entry["path"]
        assert not relative.startswith("/")
        assert "\\" not in relative
        assert (Path(result.reports_dir) / relative).is_file()


# ---------------------------------------------------------------------------
# a skipped or failed matching stage never loads as clean
# ---------------------------------------------------------------------------


def test_a_manifest_without_a_completed_matching_stage_is_refused(tmp_path):
    manifest = json.loads((FIXTURE_DIR / "depscan.manifest.json").read_text())
    for stage in manifest["stages"]:
        if stage["name"] == "matching":
            stage["status"] = "skipped"
            stage["reason"] = "no packages were found"
    destination = tmp_path / "skipped-matching"
    destination.mkdir()
    for name in ("django-app.cdx.json", "django-app.vdr.json", "depscan.findings.json"):
        (destination / name).write_text((FIXTURE_DIR / name).read_text())
    (destination / "depscan.manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    with pytest.raises(api.ScanError) as excinfo:
        api.load_scan(str(destination))
    assert "matching stage did not complete" in str(excinfo.value)


def test_a_type_whose_matching_did_not_complete_gets_no_result(tmp_path):
    """One type matched and one was skipped: only the first loads, and the
    skipped type never reads as a clean one."""
    manifest = json.loads((FIXTURE_DIR / "depscan.manifest.json").read_text())
    go_stages = [
        {"name": "inventory", "status": "completed", "capabilities": [], "projectType": "go"},
        {
            "name": "matching",
            "status": "skipped",
            "capabilities": ["vulnerabilities"],
            "projectType": "go",
            "reason": "the stage had nothing to do",
        },
    ]
    manifest["stages"].extend(go_stages)
    destination = tmp_path / "two-types"
    destination.mkdir()
    for name in ("django-app.cdx.json", "django-app.vdr.json", "depscan.findings.json"):
        (destination / name).write_text((FIXTURE_DIR / name).read_text())
    (destination / "depscan.manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    loaded = api.load_scan(str(destination))
    assert loaded.project_types == ["bom", "go"]
    assert [tscan.project_type for tscan in loaded.types] == ["bom"]
    assert len(loaded.vulnerabilities) == 1


def test_an_unexpected_error_still_leaves_a_manifest(scan_stubs, monkeypatch, tmp_path):
    """A bug in a stage, not a ScanStageError, propagates unchanged and the
    manifest still names the failed stage."""

    def broken(vdr_options):
        raise KeyError("purl")

    monkeypatch.setattr(pipeline, "VDRAnalyzer", broken)
    bom = _write_bom(tmp_path / "given.cdx.json")
    reports = tmp_path / "reports"
    with pytest.raises(KeyError):
        api.scan(api.scan_options(bom=bom, reports_dir=str(reports), no_banner=True), render=False)
    manifest = _manifest_of(reports)
    validate("depscan-manifest", manifest)
    failed = [stage for stage in manifest["stages"] if stage["status"] == "failed"]
    assert [stage["name"] for stage in failed] == ["matching"]
    assert "purl" in failed[0]["reason"]


def test_a_failed_risk_audit_is_recorded_while_the_scan_goes_on(scan_stubs, monkeypatch, tmp_path):
    def audit_fails(*args, **kwargs):
        raise RuntimeError("the registry did not answer")

    monkeypatch.setattr(pipeline, "risk_audit", audit_fails)
    monkeypatch.setattr(
        pipeline,
        "get_pkg_list",
        lambda f: ([{"purl": "pkg:npm/left-pad@1.3.0", "name": "left-pad"}], []),
    )
    bom = _write_bom(tmp_path / "given.cdx.json")
    result = api.scan(
        api.scan_options(
            bom=bom, reports_dir=str(tmp_path / "reports"), no_banner=True, risk_audit=True
        ),
        render=False,
    )
    assert result.manifest is not None
    risk = next(stage for stage in result.manifest["stages"] if stage["name"] == "risk")
    assert risk["status"] == "failed"
    assert "the registry did not answer" in risk["reason"]
    matching = next(stage for stage in result.manifest["stages"] if stage["name"] == "matching")
    assert matching["status"] == "completed", "a degraded audit does not stop the scan"


def test_a_bom_that_was_not_created_is_a_failed_inventory(scan_stubs, monkeypatch, tmp_path):
    """cdxgen failing for a type is recorded as failed, not as nothing to scan."""
    monkeypatch.setattr(
        pipeline,
        "_generate_boms",
        lambda ctx, scan: SimpleNamespace(
            success=False, bom_files=[], primary=None, not_assessed=[]
        ),
    )
    src = tmp_path / "app"
    src.mkdir()
    result = api.scan(
        api.scan_options(
            src_dir_image=str(src),
            project_type=["python"],
            reports_dir=str(tmp_path / "reports"),
            no_banner=True,
        ),
        render=False,
    )
    assert result.manifest is not None
    inventory = next(stage for stage in result.manifest["stages"] if stage["name"] == "inventory")
    assert inventory["status"] == "failed"
    assert "the BOM for the python type was not created" in inventory["reason"]


def test_a_clean_scan_loads_as_empty_because_matching_completed(scan_stubs, tmp_path, monkeypatch):
    class NothingFound:
        def __init__(self, vdr_options):
            pass

        def process(self):
            return _StubVdrResult(None, success=False)

    monkeypatch.setattr(pipeline, "VDRAnalyzer", NothingFound)
    bom = _write_bom(tmp_path / "given.cdx.json")
    reports = tmp_path / "reports"
    result = api.scan(
        api.scan_options(bom=bom, reports_dir=str(reports), no_banner=True), render=False
    )
    assert result.vulnerabilities == []
    assert result.findings == []
    loaded = api.load_scan(str(reports))
    assert loaded.vulnerabilities == []
    assert loaded.findings == []
    assert loaded.project_types == ["bom"], "the manifest shows matching completed"


def test_a_directory_without_a_manifest_loads_the_older_layout(tmp_path):
    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "depscan-universal.vdr.json").write_text(
        json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "vulnerabilities": []})
    )
    loaded = api.load_scan(str(reports))
    assert loaded.manifest is None
    assert loaded.findings == []
    assert loaded.project_types == ["bom"]


def test_a_directory_without_a_manifest_or_a_vdr_is_refused(tmp_path):
    reports = tmp_path / "reports"
    reports.mkdir()
    with pytest.raises(api.ScanError) as excinfo:
        api.load_scan(str(reports))
    assert "no VDR file" in str(excinfo.value)


# ---------------------------------------------------------------------------
# the manifest itself
# ---------------------------------------------------------------------------


def test_git_state_reads_the_commit_and_the_dirty_flag(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    env = dict(
        os.environ,
        GIT_AUTHOR_NAME="t",
        GIT_AUTHOR_EMAIL="t@example",
        GIT_COMMITTER_NAME="t",
        GIT_COMMITTER_EMAIL="t@example",
    )

    def git(*args):
        return subprocess.run(["git", *args], cwd=repo, env=env, check=True, capture_output=True)

    git("init", "-q")
    (repo / "file.txt").write_text("one")
    git("add", ".")
    git("commit", "-qm", "one")
    clean = scan_directory.git_state(str(repo))
    assert clean is not None
    assert clean == {"commit": git("rev-parse", "HEAD").stdout.decode().strip(), "dirty": False}
    (repo / "file.txt").write_text("two")
    dirty = scan_directory.git_state(str(repo))
    assert dirty is not None
    assert dirty["commit"] == clean["commit"]
    assert dirty["dirty"] is True
    assert scan_directory.git_state(str(tmp_path)) is None


def test_home_relative_keeps_only_the_home_prefix():
    assert home_relative("/opt/tools/atom") == "/opt/tools/atom"
    home = os.path.expanduser("~")
    assert home_relative(os.path.join(home, "bin", "cdxgen")) == "~/bin/cdxgen"
    assert home_relative(home) == "~"
    assert home_relative(None) is None
    assert home_relative("") == ""


def test_classify_file_roles():
    entries = {
        "depscan.manifest.json": None,  # never classified; callers leave it out
        "depscan.findings.json": {"role": "findings", "producer": "dep-scan"},
        "analysis/rusi/rusi.json": {"role": "raw-report", "producer": "rusi"},
        "analysis/dosai/dotnet-methods.json": {"role": "raw-report", "producer": "dosai"},
        "depscan-universal.vdr.json": {"role": "vdr", "producer": "dep-scan"},
        "sbom-python.vdr.json": {"role": "vdr", "projectType": "python"},
        "sbom-python.cdx.json": {"role": "bom", "producer": "cdxgen", "projectType": "python"},
        "sbom-postbuild-python.cdx.json": {"role": "bom", "producer": "blint"},
        "bom.json": {"role": "bom", "producer": "user"},
        "python-reachables.slices.json": {"role": "slices", "producer": "cdxgen"},
        "go-reachables.slices.json": {"role": "slices", "producer": "dep-scan"},
        "python-openapi.json": {"projectType": "python"},
        "report.csaf.json": {"role": "csaf"},
        "license-npm.json": {"role": "report"},
        "depscan-risk-npm.json": {"role": "report"},
        "depscan.toml.sample": {"role": "report"},
        "depscan.html": {"role": "report"},
        "unknown.json": {"role": "other"},
    }
    cyclonedx = {"bomFormat": "CycloneDX"}
    for path, expected in entries.items():
        if expected is None:
            continue
        entry = classify_file(path, is_cyclonedx=cyclonedx if path == "bom.json" else None)
        for key, value in expected.items():
            assert entry.get(key) == value, f"{path}: {key}"
    assert classify_file("bom.json").get("role") == "other", (
        "without the parsed document, a user BOM is other, never guessed"
    )


def test_walk_files_hashes_the_scan_files_but_not_the_manifest(tmp_path):
    (tmp_path / "depscan.findings.json").write_text("{}")
    (tmp_path / "analysis" / "rusi").mkdir(parents=True)
    (tmp_path / "analysis" / "rusi" / "rusi.json").write_text("{}")
    (tmp_path / "depscan.manifest.json").write_text("{}")
    # A reports directory inside the scanned project, or a user's BOM
    # directory, can hold trees no scan wrote; they are not walked.
    (tmp_path / "node_modules" / "left-pad").mkdir(parents=True)
    (tmp_path / "node_modules" / "left-pad" / "index.js").write_text("")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    entries = scan_directory.walk_files(str(tmp_path))
    assert [entry["path"] for entry in entries] == [
        "analysis/rusi/rusi.json",
        "depscan.findings.json",
    ]
    for entry in entries:
        expected = hashlib.sha256((tmp_path / entry["path"]).read_bytes()).hexdigest()
        assert entry["sha256"] == expected
    assert entries[0]["role"] == "raw-report" and entries[0]["producer"] == "rusi"


def test_analyzer_entries_follow_the_slices_read_and_the_doctor(fake_tools, tmp_path):
    fake_tools["remove"]("golem")
    fake_tools["remove"]("rusi")
    report = doctor_mod.doctor()
    read = [
        str(tmp_path / "python-reachables.slices.json"),
        # Slices the user gave count even when the tool is missing here.
        str(tmp_path / "rust-reachables.slices_1.json"),
        str(tmp_path / "python-usages.slices.json"),
    ]
    by_name = {
        entry["name"]: entry for entry in scan_directory.analyzer_entries(report, ["bom"], read)
    }
    assert by_name["atom"]["status"] == "completed"
    assert by_name["rusi"]["status"] == "completed"
    assert by_name["golem"]["status"] == "not-assessed"
    assert by_name["golem"]["capability"] == "reachability:go"
    assert "golem was not found" in by_name["golem"]["reason"]
    assert by_name["dosai"] == {
        "name": "dosai",
        "capability": "reachability:dotnet",
        "status": "not-assessed",
        "reason": "no dotnet-reachables.slices.json was produced or given for this scan",
    }
    python_only = scan_directory.analyzer_entries(report, ["python"], read)
    assert [entry["name"] for entry in python_only] == ["atom"]


def test_capability_reason_reads_the_doctor_table_not_a_copy():
    tools = {
        "cdxgen": doctor_mod.ToolStatus(name="cdxgen", path="/bin/cdxgen", source="path"),
        "golem": doctor_mod.ToolStatus(name="golem", reason="golem was not found"),
        "go": doctor_mod.ToolStatus(name="go", path="/bin/go", source="path"),
    }
    data = {"vulnerabilityDatabase": dict(_FULL_VDB_DATA)}
    reason = doctor_mod.capability_unavailable_reason("reachability:go", tools, data)
    assert reason == (
        "capability reachability:go is unavailable: tool:golem (golem: golem was not found)"
    )
    assert doctor_mod.capability_unavailable_reason("reachability", tools, data) is None
    assert doctor_mod.capability_unavailable_reason("no-such-capability", tools, data)
    assert doctor_mod.capability_unavailable_reason("memory-safety", tools, data)


# ---------------------------------------------------------------------------
# the capability lookup explains a missing report, it never gates a run
# ---------------------------------------------------------------------------


class _FakeConverter:
    @staticmethod
    def is_report_ok(data):
        return isinstance(data, dict) and "flows" in data

    @staticmethod
    def build_index(components, extra_components=None):
        return {}

    @staticmethod
    def convert(report, bom_index):
        return list(report["flows"])

    @staticmethod
    def write_slices(path, flows):
        Path(path).write_text(json.dumps(flows))


def _fake_tool(run_fallback):
    from depscan.lib.bom import ReachabilityTool

    return ReachabilityTool(
        name="golem",
        project_types=("go",),
        default_prefix="go",
        slice_file="go-reachables.slices.json",
        import_converter=lambda: _FakeConverter,
        run_fallback=run_fallback,
        no_report_error="No golem report was available.",
    )


def test_an_unavailable_capability_does_not_stop_a_tool_that_can_run(fake_tools, tmp_path):
    """The doctor says reachability:go is unavailable (no Go toolchain on
    PATH), but the tool still produced a report: the slice is written, as it
    was before the doctor table was consulted."""
    from depscan.lib.bom import _run_reachability_tool

    fake_tools["remove"]("go")
    report = doctor_mod.doctor()
    assert scan_directory.analyzer_entries(report, ["go"], [])[1]["status"] == "not-assessed"
    bom = _write_bom(tmp_path / "sbom-go.cdx.json")
    ran = []

    def fallback(src_dir, bom_dir, options, is_report_ok, json_load):
        ran.append(src_dir)
        return {"flows": [{"purls": ["pkg:golang/example.com/a@v1.0.0"]}]}

    options = {"project_type": ["go"], "doctor_report": report}
    assert _run_reachability_tool(bom, str(tmp_path), options, _fake_tool(fallback))
    assert ran == [str(tmp_path)]
    assert (tmp_path / "go-reachables.slices.json").is_file()


def test_fail_on_error_still_fails_when_the_capability_is_unavailable(fake_tools, tmp_path):
    from depscan.lib.bom import ScanFailureError, _run_reachability_tool

    fake_tools["remove"]("golem")
    options = {
        "project_type": ["go"],
        "doctor_report": doctor_mod.doctor(),
        "fail_on_error": True,
    }
    bom = _write_bom(tmp_path / "sbom-go.cdx.json")
    with pytest.raises(ScanFailureError, match="No golem report"):
        _run_reachability_tool(bom, str(tmp_path), options, _fake_tool(lambda *a: None))
    options["fail_on_error"] = False
    assert not _run_reachability_tool(bom, str(tmp_path), options, _fake_tool(lambda *a: None))


def test_a_tool_run_without_a_report_removes_split_slices_and_its_facts(fake_tools, tmp_path):
    """Split parts of an earlier run's slice and dosai's facts sidecar would
    otherwise read as this run's reachability and exposure evidence."""
    from depscan.lib.bom import DOSAI_FACTS_FILE, DOSAI_TOOL, _run_reachability_tool

    fake_tools["remove"]("dosai")
    bom = _write_bom(tmp_path / "sbom-dotnet.cdx.json")
    for name in (
        "dotnet-reachables.slices.json",
        "dotnet-reachables.slices-2.json",
        "dotnet-reachables.slices-notapart.json",
    ):
        (tmp_path / name).write_text("[]")
    facts = tmp_path / "analysis" / "dosai" / DOSAI_FACTS_FILE
    facts.parent.mkdir(parents=True)
    facts.write_text("{}")
    tool = dataclasses.replace(DOSAI_TOOL, run_fallback=lambda *a: None)
    options = {"project_type": ["dotnet"], "doctor_report": doctor_mod.doctor()}
    assert not _run_reachability_tool(bom, str(tmp_path), options, tool)
    assert not (tmp_path / "dotnet-reachables.slices.json").exists()
    assert not (tmp_path / "dotnet-reachables.slices-2.json").exists()
    assert not facts.exists()
    # Only numbered parts are the tool's; anything else is left alone.
    assert (tmp_path / "dotnet-reachables.slices-notapart.json").exists()


def test_a_source_scan_clears_tool_outputs_an_earlier_run_left(tmp_path):
    """A universal rerun into the same reports directory never runs dosai,
    so the earlier .NET run's slices and facts must not survive into it."""
    from depscan.lib.bom import DOSAI_FACTS_FILE, clear_tool_outputs

    for name in (
        "dotnet-reachables.slices.json",
        "dotnet-reachables.slices-3.json",
        "go-reachables.slices.json",
        "rust-reachables.slices.json",
        "java-reachables.slices.json",
    ):
        (tmp_path / name).write_text("[]")
    facts = tmp_path / "analysis" / "dosai" / DOSAI_FACTS_FILE
    facts.parent.mkdir(parents=True)
    facts.write_text("{}")
    clear_tool_outputs(str(tmp_path))
    remaining = sorted(p.name for p in tmp_path.glob("*.json"))
    # atom's slices come from cdxgen, which rewrites them; only the language
    # tools' own outputs are cleared.
    assert remaining == ["java-reachables.slices.json"]
    assert not facts.exists()


def test_documented_manifest_fields_match_the_schema():
    """The scan directory page carries the generated tables; regenerate them
    with the command in the page when this fails."""
    page = (
        Path(__file__).parent.parent / "documentation" / "docs" / "output" / "scan-directory.mdx"
    )
    assert scan_directory.manifest_fields_markdown() in page.read_text(encoding="utf-8")


def test_a_vdr_outside_the_scan_directory_is_not_read_as_clean(scan_stubs, tmp_path):
    """A BOM directory scan with its own reports directory writes the VDR
    next to the BOMs; the scan directory must not load as clean."""
    bom_dir = tmp_path / "boms"
    bom_dir.mkdir()
    _write_bom(bom_dir / "a.cdx.json", name="a")
    _write_bom(bom_dir / "b.cdx.json", name="b")
    reports = tmp_path / "elsewhere" / "reports"
    result = api.scan(
        api.scan_options(bom_dir=str(bom_dir), reports_dir=str(reports), no_banner=True),
        render=False,
    )
    assert result.vulnerabilities, "the scan itself found the stubbed vulnerability"
    vdr_stage = next(s for s in (result.manifest or {})["stages"] if s["name"] == "vdr")
    assert vdr_stage["outputs"][0]["status"] == "not-assessed"
    assert not os.path.isabs(vdr_stage["outputs"][0]["file"])
    with pytest.raises(api.ScanError, match="outside the scan directory"):
        api.load_scan(str(reports))


def test_a_corrupted_findings_document_is_refused_not_read_as_clean(scan_stubs, tmp_path):
    """A depscan.findings.json that is not valid JSON must not load as a
    scan with no findings: the directory refuses to load and names the
    file and the parse failure."""
    bom = _write_bom(tmp_path / "given.cdx.json")
    reports = tmp_path / "reports"
    result = api.scan(
        api.scan_options(bom=bom, reports_dir=str(reports), no_banner=True), render=False
    )
    assert result.findings, "the scan itself found the stubbed vulnerability"
    (Path(result.reports_dir) / "depscan.findings.json").write_text(
        "{not json at all", encoding="utf-8"
    )
    with pytest.raises(api.ScanError) as excinfo:
        api.load_scan(str(reports))
    message = str(excinfo.value)
    assert "depscan.findings.json" in message
    assert "not valid JSON" in message


def test_a_rules_override_is_recorded_as_an_input_with_its_digest(tmp_path):
    """A scan graded with a replacement rule table says which table, so two
    scans with different grades can be told apart from their manifests."""
    rules = tmp_path / "rules.yaml"
    rules.write_text("rules:\n  - id: everything\n    grade: low\n", encoding="utf-8")
    entries = scan_directory.input_entries(
        {"bom": None, "src_dir": str(tmp_path), "exploitability_rules": str(rules)}
    )
    recorded = [entry for entry in entries if entry.get("path") == str(rules)]
    assert recorded == [
        {"type": "file", "path": str(rules), "sha256": scan_directory.sha256_file(str(rules))}
    ]
