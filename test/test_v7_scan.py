"""End-to-end tests of the ``depscan scan`` verb through ``depscan.cli.main``.

Every scan is driven the way a user drives it: ``sys.argv`` is set, ``main``
runs, the exit code, the reports directory and the output are asserted. The
database, the matching stage, the risk audit and the cdxgen process are
stubbed with recorded calls (the pattern of the scan directory and internals
tests), and every stub has a positive control proving it ran. The doctor
report stays real, with its database inspection replaced by a known state and
the tools faked or hidden through the ``fake_tools`` fixture.

Target detection is also tested directly through ``detect_kind``: one fixture
per kind, each asserting the kind and the evidence its reason names.
"""

import json
import logging
import os
import sys
from pathlib import Path

import pytest

from depscan import cli
from depscan.commands.targets import detect_kind
from depscan.lib import bom as bom_mod
from depscan.lib import doctor as doctor_mod
from depscan.lib import pipeline, vdb_setup
from depscan.lib.logger import LOG, console
from xbom_lib import cdxgen as cdxgen_mod

VULN_REQUESTS = {
    "id": "CVE-2024-1111",
    "bom-ref": "CVE-2024-1111/pkg:pypi/requests@2.32.1",
    "affects": [{"ref": "pkg:pypi/requests@2.32.1"}],
    "ratings": [{"severity": "high", "score": 8.1, "method": "CVSSv31"}],
    "fixed_location": "2.32.2",
}

# The BOM document the fake cdxgen process writes, so a source-directory
# scan proceeds the way it does after a real generation run.
BOM_DOCUMENT = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "metadata": {"component": {"name": "app", "type": "application"}},
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

# The doctor data state the scans are evaluated against: a present, fresh,
# populated database, as in the scan directory tests.
FULL_VDB_DATA = {
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


def run_main(monkeypatch, argv):
    """Run ``main`` with ``argv`` after the program name; the exit code."""
    monkeypatch.setattr(sys, "argv", ["depscan", *argv])
    with pytest.raises(SystemExit) as excinfo:
        cli.main()
    return excinfo.value.code


def _write_bom(path, name="app"):
    """Write a small CycloneDX JSON document and return its path."""
    bom = dict(BOM_DOCUMENT)
    bom["metadata"] = {"component": {"name": name, "type": "application"}}
    Path(path).write_text(json.dumps(bom))
    return str(path)


def _manifest_of(reports_dir):
    return json.loads((Path(reports_dir) / "depscan.manifest.json").read_text())


class _StubVdrResult:
    success = True
    prioritized_pkg_vuln_trees = {}

    def __init__(self, pkg_vulnerabilities):
        self.pkg_vulnerabilities = pkg_vulnerabilities


@pytest.fixture
def scan_stubs(monkeypatch):
    """Stub a scan's database, matching, risk audit and cdxgen process.

    The doctor report stays real, with the database inspection replaced by a
    known state. The fake cdxgen records the command line it was handed and
    writes the BOM it was asked for, which is what a successful run leaves
    behind.
    """
    calls = {"matching": [], "database": [], "cdxgen": [], "risk": []}
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

    def fake_risk_audit(*args, **kwargs):
        calls["risk"].append(1)
        return {}

    monkeypatch.setattr(pipeline, "risk_audit", fake_risk_audit)

    def fake_exec_tool(args, *a, **k):
        calls["cdxgen"].append(list(args))
        bom_file = args[args.index("-o") + 1]
        Path(bom_file).write_text(json.dumps(BOM_DOCUMENT))
        return cdxgen_mod.BOMResult(success=True, command_output="BOM saved")

    monkeypatch.setattr(cdxgen_mod, "find_cdxgen_cmd", lambda *a, **k: "cdxgen")
    monkeypatch.setattr(cdxgen_mod, "exec_tool", fake_exec_tool)
    monkeypatch.setattr(bom_mod, "_refuse_old_cdxgen", lambda logger=None: True)

    class StubVDRAnalyzer:
        def __init__(self, vdr_options):
            calls["matching"].append(vdr_options)

        def process(self):
            return _StubVdrResult([dict(VULN_REQUESTS)])

    monkeypatch.setattr(pipeline, "VDRAnalyzer", StubVDRAnalyzer)
    monkeypatch.setattr(doctor_mod, "_vdb_status", lambda: dict(FULL_VDB_DATA))
    return calls


# The tools the reachability capabilities name, with their env overrides and
# the version line the fake prints, exactly as the doctor tests fake them.
FAKE_TOOLS = {
    "cdxgen": ("CDXGEN_CMD", "CycloneDX Generator 13.8.0"),
    "golem": ("GOLEM_CMD", "golem 9.9.9"),
    "rusi": ("RUSI_CMD", "rusi 9.9.9"),
    "dosai": ("DOSAI_CMD", "dosai 9.9.9+deadbeef"),
    "go": (None, "go version go9.9.9 test"),
    "dotnet": (None, "9.9.100"),
}


@pytest.fixture
def fake_tools(tmp_path, monkeypatch):
    """Install one fake per tool the capabilities name, then strip the PATH.

    ``remove`` makes one tool unresolvable again, which is how the gate tests
    hide cdxgen.
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
    ):
        monkeypatch.delenv(var, raising=False)

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
    installed = {}

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


@pytest.fixture
def no_license_env(monkeypatch):
    """Keep FETCH_LICENSE unset around a test whose scan may set it."""
    monkeypatch.delenv("FETCH_LICENSE", raising=False)
    yield
    monkeypatch.delenv("FETCH_LICENSE", raising=False)


# ---------------------------------------------------------------------------
# one end-to-end scan per runnable kind
# ---------------------------------------------------------------------------


def test_scan_runs_a_source_directory(scan_stubs, monkeypatch, tmp_path):
    """A source directory scans through cdxgen, with the type the user named."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text("import requests\n")
    reports = tmp_path / "reports"
    code = run_main(
        monkeypatch,
        [
            "scan",
            str(src),
            "-t",
            "python",
            "--bom-engine",
            "CdxgenGenerator",
            "--reports-dir",
            str(reports),
            "--no-banner",
        ],
    )
    assert code == 0
    manifest = _manifest_of(reports)
    assert manifest["options"]["project_type"] == ["python"]
    # Positive controls: the cdxgen process, the matching stage and the
    # database guard all ran, once, for the python type only.
    assert len(scan_stubs["cdxgen"]) == 1, "the cdxgen process never ran"
    assert scan_stubs["cdxgen"][0][scan_stubs["cdxgen"][0].index("-t") + 1] == "python"
    assert len(scan_stubs["matching"]) == 1, "the matching stage never ran"
    assert scan_stubs["database"], "the database guard never ran"


def test_scan_runs_a_bom_file(scan_stubs, monkeypatch, tmp_path):
    """A CycloneDX file scans as the bom kind: no cdxgen, the file's packages."""
    bom = _write_bom(tmp_path / "given.cdx.json")
    reports = tmp_path / "reports"
    code = run_main(monkeypatch, ["scan", bom, "--reports-dir", str(reports), "--no-banner"])
    assert code == 0
    assert (reports / "depscan.manifest.json").is_file(), "the scan directory was not written"
    # Positive controls: the inventory used the given file and matching ran.
    assert scan_stubs["matching"], "the matching stage never ran"
    assert scan_stubs["matching"][0].bom_file == bom
    assert scan_stubs["cdxgen"] == [], "a BOM scan must not generate a BOM"


def test_scan_runs_a_bom_directory(scan_stubs, monkeypatch, tmp_path):
    """A directory of CycloneDX documents scans as the bom-dir kind."""
    bom_dir = tmp_path / "boms"
    bom_dir.mkdir()
    _write_bom(bom_dir / "a.cdx.json", name="a")
    _write_bom(bom_dir / "b.cdx.json", name="b")
    (bom_dir / "notes.txt").write_text("not a BOM, ignored by detection")
    reports = tmp_path / "reports"
    code = run_main(monkeypatch, ["scan", str(bom_dir), "--reports-dir", str(reports), "--no-banner"])
    assert code == 0
    assert (reports / "depscan.manifest.json").is_file()
    # Positive controls: the packages came from the BOM directory and
    # matching ran once for the aggregated bom type.
    assert scan_stubs["matching"], "the matching stage never ran"
    assert scan_stubs["matching"][0].bom_dir == str(bom_dir)
    assert scan_stubs["cdxgen"] == []


def test_scan_runs_a_purl(scan_stubs, monkeypatch, tmp_path):
    """A package URL scans without any BOM generation, with its risk audit."""
    reports = tmp_path / "reports"
    code = run_main(
        monkeypatch,
        [
            "scan",
            "pkg:pypi/requests@2.32.1",
            "--reports-dir",
            str(reports),
            "--no-banner",
        ],
    )
    assert code == 0
    assert (reports / "depscan.manifest.json").is_file()
    # Positive controls: matching saw the purl's own package list and the
    # single-purl risk audit ran.
    assert scan_stubs["matching"], "the matching stage never ran"
    assert [pkg["purl"] for pkg in scan_stubs["matching"][0].pkg_list] == [
        "pkg:pypi/requests@2.32.1"
    ]
    assert scan_stubs["risk"], "the single-purl risk audit never ran"
    assert scan_stubs["cdxgen"] == []


# ---------------------------------------------------------------------------
# detection
# ---------------------------------------------------------------------------


@pytest.fixture
def detection_fixtures(tmp_path):
    """One existing path per kind, plus the reference strings."""
    tar = tmp_path / "image.tar"
    tar.write_text("")
    oci = tmp_path / "oci-layout-dir"
    oci.mkdir()
    (oci / "oci-layout").write_text('{"imageLayoutVersion": "1.0.0"}')
    apk = tmp_path / "app.apk"
    apk.write_text("an apk is more specific than any executable bit")
    apk.chmod(0o755)
    binary = tmp_path / "tool"
    binary.write_text("#!/bin/sh\n")
    binary.chmod(0o755)
    src = tmp_path / "src"
    src.mkdir()
    (src / "main.py").write_text("pass\n")
    return {
        "tar": str(tar),
        "oci": str(oci),
        "apk": str(apk),
        "binary": str(binary),
        "src": str(src),
    }


@pytest.mark.parametrize(
    "target,kind,reason_fragment",
    [
        ("pkg:pypi/requests@2.32.1", "purl", "starts with pkg:"),
        ("https://github.com/owasp/dep-scan", "git", "starts with https://"),
        ("git@github.com:owasp/dep-scan.git", "git", "starts with git@"),
        ("https://example.com/app.tar", "container", "no path"),
        ("alpine:3.19", "container", "name:tag"),
        ("registry.io/team/app:1.2.3", "container", "registry/name"),
        ("app@" + "sha256:" + "a" * 64, "container", "sha256 digest"),
    ],
)
def test_detect_kind_of_reference_strings(target, kind, reason_fragment):
    """Each reference string maps to its kind with the evidence named."""
    detected, reason = detect_kind(target)
    assert detected == kind
    assert reason_fragment in reason


def test_detect_kind_of_existing_paths(detection_fixtures, tmp_path):
    """Existing paths map to their kind, path kinds before heuristics."""
    bom = _write_bom(tmp_path / "given.json")
    bom_dir = tmp_path / "boms"
    bom_dir.mkdir()
    _write_bom(bom_dir / "one.json")
    expected = [
        (detection_fixtures["tar"], "container", "an existing .tar archive file"),
        (detection_fixtures["oci"], "container", "oci-layout"),
        (bom, "bom", "JSON document is CycloneDX"),
        (str(bom_dir), "bom-dir", "JSON files are all CycloneDX documents"),
        (detection_fixtures["apk"], "android", ".apk file"),
        (detection_fixtures["binary"], "binary", "executable file"),
        (detection_fixtures["src"], "source", "existing directory"),
    ]
    for target, kind, fragment in expected:
        detected, reason = detect_kind(target)
        assert detected == kind, f"{target}: {detected}"
        assert fragment in reason, f"{target}: {reason}"


def test_an_image_reference_that_is_an_existing_path_is_the_path(
    scan_stubs, monkeypatch, caplog, tmp_path
):
    """A directory named like an image reference scans as the path it is."""
    weird = tmp_path / "app:latest"
    weird.mkdir()
    (weird / "main.py").write_text("pass\n")
    reports = tmp_path / "reports"
    with caplog.at_level(logging.INFO, logger=LOG.name):
        code = run_main(
            monkeypatch,
            [
                "scan",
                str(weird),
                "--reports-dir",
                str(reports),
                "--no-banner",
                "--bom-engine",
                "CdxgenGenerator",
            ],
        )
    assert code == 0
    # The detection chose the path kind, not the container reference, and
    # said so in its per-target log line; the scan ran as a source scan.
    lines = [record.getMessage() for record in caplog.records]
    assert any("kind source" in line and str(weird) in line for line in lines), lines
    assert not any("kind container" in line for line in lines)
    # Positive control: the scan really ran.
    assert scan_stubs["matching"], "the matching stage never ran"


def test_detection_logs_the_kind_and_reason_for_each_target(
    scan_stubs, monkeypatch, caplog, tmp_path
):
    bom = _write_bom(tmp_path / "given.cdx.json")
    with caplog.at_level(logging.INFO, logger=LOG.name):
        code = run_main(
            monkeypatch, ["scan", bom, "--reports-dir", str(tmp_path / "reports"), "--no-banner"]
        )
    assert code == 0
    lines = [record.getMessage() for record in caplog.records]
    assert any(
        bom in line and "kind bom" in line and "JSON document is CycloneDX" in line
        for line in lines
    ), lines


# ---------------------------------------------------------------------------
# refusals
# ---------------------------------------------------------------------------


def test_an_ipa_file_is_refused_with_the_mobile_reason(scan_stubs, monkeypatch, caplog, tmp_path):
    ipa = tmp_path / "app.ipa"
    ipa.write_text("an ios archive")
    with caplog.at_level(logging.ERROR, logger=LOG.name):
        code = run_main(
            monkeypatch,
            ["scan", str(ipa), "--reports-dir", str(tmp_path / "reports"), "--no-banner"],
        )
    assert code == 4
    message = " ".join(record.getMessage() for record in caplog.records)
    assert "iOS app" in message
    assert "mobile" in message
    assert "not implemented" in message


def test_target_kind_ios_is_refused(scan_stubs, monkeypatch, caplog, tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    with caplog.at_level(logging.ERROR, logger=LOG.name):
        code = run_main(
            monkeypatch,
            ["scan", str(src), "--target-kind", "ios", "--reports-dir", str(tmp_path / "reports")],
        )
    assert code == 4
    assert "mobile" in " ".join(record.getMessage() for record in caplog.records)


def test_target_kind_firmware_is_refused(scan_stubs, monkeypatch, caplog, tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    with caplog.at_level(logging.ERROR, logger=LOG.name):
        code = run_main(
            monkeypatch,
            [
                "scan",
                str(src),
                "--target-kind",
                "firmware",
                "--reports-dir",
                str(tmp_path / "reports"),
            ],
        )
    assert code == 4
    message = " ".join(record.getMessage() for record in caplog.records).lower()
    assert "firmware" in message
    assert "no inventory path" in message


@pytest.mark.parametrize("kind,fragment", [("firmware", "no inventory path"), ("ios", "mobile")])
def test_a_forced_kind_without_an_inventory_path_is_refused_without_targets(
    scan_stubs, monkeypatch, caplog, tmp_path, kind, fragment
):
    """--target-kind naming a kind this version cannot scan refuses the run
    before any target handling, also when no target was given: without this
    the current directory would be scanned instead."""
    monkeypatch.chdir(tmp_path)
    with caplog.at_level(logging.ERROR, logger=LOG.name):
        code = run_main(monkeypatch, ["scan", "--target-kind", kind])
    assert code == 4
    message = " ".join(record.getMessage() for record in caplog.records).lower()
    assert kind in message
    assert fragment in message
    # Nothing was scanned: no reports directory, no matching, no detection.
    assert not (tmp_path / "reports").exists(), "the refusal must not scan anything"
    assert scan_stubs["matching"] == []
    assert not any("kind" in record.getMessage() for record in caplog.records)


def test_a_missing_source_target_exits_one(scan_stubs, monkeypatch, caplog, tmp_path):
    """A target that is not an existing path and no reference is a source
    target; a nonexistent one is refused with exit 1."""
    monkeypatch.chdir(tmp_path)
    reports = tmp_path / "reports"
    with caplog.at_level(logging.ERROR, logger=LOG.name):
        code = run_main(
            monkeypatch,
            ["scan", "no-such-project", "--reports-dir", str(reports)],
        )
    assert code == 1
    assert "no-such-project" in " ".join(record.getMessage() for record in caplog.records)
    assert not reports.exists(), "no reports directory is written for a refused target"


def test_target_kind_bom_on_a_directory_is_refused_like_the_internal_validation(
    scan_stubs, monkeypatch, caplog, tmp_path
):
    """--target-kind bom on a directory reaches the internal --bom validation,
    which refuses a directory with exit 1."""
    not_a_bom_dir = tmp_path / "plain"
    not_a_bom_dir.mkdir()
    (not_a_bom_dir / "readme.txt").write_text("no json here")
    with caplog.at_level(logging.ERROR, logger=LOG.name):
        code = run_main(
            monkeypatch,
            [
                "scan",
                str(not_a_bom_dir),
                "--target-kind",
                "bom",
                "--reports-dir",
                str(tmp_path / "reports"),
                "--no-banner",
            ],
        )
    assert code == 1
    message = " ".join(record.getMessage() for record in caplog.records)
    assert "is not a file" in message
    assert "--bom-dir" in message


# ---------------------------------------------------------------------------
# the capability gate
# ---------------------------------------------------------------------------


def test_an_explicit_reachability_check_with_cdxgen_hidden_exits_four(
    scan_stubs, fake_tools, monkeypatch, caplog, tmp_path
):
    """--checks naming reachability stops before any work: exit 4, the
    doctor's reason logged, and no reports directory."""
    fake_tools["remove"]("cdxgen")
    bom = _write_bom(tmp_path / "given.cdx.json")
    reports = tmp_path / "reports"
    with caplog.at_level(logging.ERROR, logger=LOG.name):
        code = run_main(
            monkeypatch,
            [
                "scan",
                bom,
                "--checks",
                "vulnerabilities,reachability",
                "--reports-dir",
                str(reports),
                "--no-banner",
            ],
        )
    assert code == 4
    message = " ".join(record.getMessage() for record in caplog.records)
    assert "reachability" in message
    assert "capability reachability is unavailable" in message
    assert "cdxgen" in message
    assert not reports.exists(), "the gate must not create the reports directory"
    # Positive control of the hidden-tool stub: the scan never ran.
    assert scan_stubs["matching"] == []


def test_the_default_checks_are_never_gated(
    scan_stubs, fake_tools, monkeypatch, tmp_path
):
    """Without --checks the same scan runs to exit 0, and reachability is
    recorded not assessed with the doctor's reason, as before."""
    fake_tools["remove"]("cdxgen")
    bom = _write_bom(tmp_path / "given.cdx.json")
    reports = tmp_path / "reports"
    code = run_main(monkeypatch, ["scan", bom, "--reports-dir", str(reports), "--no-banner"])
    assert code == 0
    assert (reports / "depscan.manifest.json").is_file()
    # Positive control: the scan really ran.
    assert scan_stubs["matching"], "the matching stage never ran"
    manifest = _manifest_of(reports)
    enrichment = next(stage for stage in manifest["stages"] if stage["name"] == "enrichment")
    analyzers = {entry["name"]: entry for entry in enrichment["analyzers"]}
    assert analyzers["atom"]["status"] == "not-assessed"
    assert "cdxgen" in analyzers["atom"]["reason"]


def test_checks_all_with_cdxgen_hidden_records_the_unavailable_checks(
    scan_stubs, fake_tools, monkeypatch, tmp_path, no_license_env
):
    """--checks all enables what can run, records the rest not assessed with
    the doctor's reason, and turns reachability off when it cannot run."""
    fake_tools["remove"]("cdxgen")
    bom = _write_bom(tmp_path / "given.cdx.json")
    reports = tmp_path / "reports"
    code = run_main(
        monkeypatch,
        ["scan", bom, "--checks", "all", "--reports-dir", str(reports), "--no-banner"],
    )
    assert code == 0
    assert (reports / "depscan.manifest.json").is_file()
    # Positive control: the scan ran to matching.
    assert scan_stubs["matching"], "the matching stage never ran"
    manifest = _manifest_of(reports)
    stages = {stage["name"]: stage for stage in manifest["stages"]}
    assert stages["check-reachability"]["status"] == "not-assessed"
    assert "cdxgen" in stages["check-reachability"]["reason"]
    assert stages["check-reachability"]["capabilities"] == ["reachability"]
    # Reachability is off: the enrichment stage never ran.
    assert manifest["options"]["reachability_analyzer"] == "off"
    assert stages["enrichment"]["status"] == "skipped"
    assert stages["enrichment"]["reason"] == "reachability analysis is off"
    # The not-implemented checks are named too, never silently absent.
    assert "check-memory-safety" in stages


# ---------------------------------------------------------------------------
# the license check on targets whose types never carry it
# ---------------------------------------------------------------------------


def _licensed_packages(monkeypatch):
    """Point the package loader at one package with a conditional license."""
    monkeypatch.setattr(
        pipeline,
        "get_pkg_list",
        lambda f: (
            [
                {
                    "purl": "pkg:pypi/requests@2.32.1",
                    "name": "requests",
                    "version": "2.32.1",
                    "licenses": ["CC-BY-NC-4.0"],
                }
            ],
            [],
        ),
    )


def test_the_license_check_runs_the_license_analysis_for_a_bom_target(
    scan_stubs, monkeypatch, tmp_path, no_license_env
):
    """--checks license turns the license analysis on for a BOM target too,
    where the detected type is always ``bom`` and never carries the license
    pseudo type."""
    _licensed_packages(monkeypatch)
    bom = _write_bom(tmp_path / "given.cdx.json")
    reports = tmp_path / "reports"
    code = run_main(
        monkeypatch,
        ["scan", bom, "--checks", "license", "--reports-dir", str(reports), "--no-banner"],
    )
    assert code == 0
    manifest = _manifest_of(reports)
    stages = {stage["name"]: stage for stage in manifest["stages"]}
    assert stages["licenses"]["status"] == "completed", (
        f"the licenses stage was {stages['licenses']['status']}"
    )
    # Positive control: the analysis looked the package's license up and
    # wrote the license report.
    assert (reports / "license-bom.json").is_file()
    assert os.environ.get("FETCH_LICENSE") == "true"


def test_profile_deep_runs_the_license_analysis_for_a_bom_target(
    scan_stubs, fake_tools, monkeypatch, tmp_path, no_license_env
):
    """The deep profile names the license check, so a BOM target gets the
    license analysis the same way."""
    _licensed_packages(monkeypatch)
    bom = _write_bom(tmp_path / "given.cdx.json")
    reports = tmp_path / "reports"
    code = run_main(
        monkeypatch,
        ["scan", bom, "--profile", "deep", "--reports-dir", str(reports), "--no-banner"],
    )
    assert code == 0
    manifest = _manifest_of(reports)
    stages = {stage["name"]: stage for stage in manifest["stages"]}
    assert stages["licenses"]["status"] == "completed", (
        f"the licenses stage was {stages['licenses']['status']}"
    )
    assert (reports / "license-bom.json").is_file()


# ---------------------------------------------------------------------------
# checks named alongside the all expansion
# ---------------------------------------------------------------------------


def test_checks_named_alongside_all_are_gated(
    scan_stubs, fake_tools, monkeypatch, caplog, tmp_path
):
    """A check named next to all is gated like a directly named check: with
    cdxgen unusable, all,reachability refuses the run before any work."""
    fake_tools["remove"]("cdxgen")
    bom = _write_bom(tmp_path / "given.cdx.json")
    reports = tmp_path / "reports"
    with caplog.at_level(logging.ERROR, logger=LOG.name):
        code = run_main(
            monkeypatch,
            [
                "scan",
                bom,
                "--checks",
                "all,reachability",
                "--reports-dir",
                str(reports),
                "--no-banner",
            ],
        )
    assert code == 4
    message = " ".join(record.getMessage() for record in caplog.records)
    assert "capability reachability is unavailable" in message
    assert not reports.exists(), "the gate must not create the reports directory"
    # Positive control of the hidden-tool stub: the scan never ran.
    assert scan_stubs["matching"] == []


def test_checks_all_plus_a_neutral_check_still_runs(
    scan_stubs, fake_tools, monkeypatch, tmp_path, no_license_env
):
    """all,license runs with cdxgen hidden: the expansion records
    reachability not assessed and the named license check needs nothing."""
    fake_tools["remove"]("cdxgen")
    _licensed_packages(monkeypatch)
    bom = _write_bom(tmp_path / "given.cdx.json")
    reports = tmp_path / "reports"
    code = run_main(
        monkeypatch,
        ["scan", bom, "--checks", "all,license", "--reports-dir", str(reports), "--no-banner"],
    )
    assert code == 0
    manifest = _manifest_of(reports)
    stages = {stage["name"]: stage for stage in manifest["stages"]}
    assert stages["check-reachability"]["status"] == "not-assessed"
    assert "cdxgen" in stages["check-reachability"]["reason"]
    assert manifest["options"]["reachability_analyzer"] == "off"
    assert stages["enrichment"]["status"] == "skipped"
    # The named check really ran.
    assert stages["licenses"]["status"] == "completed"
    assert (reports / "license-bom.json").is_file()
    # Positive control: the scan itself ran.
    assert scan_stubs["matching"], "the matching stage never ran"


# ---------------------------------------------------------------------------
# the json format
# ---------------------------------------------------------------------------


def test_json_format_prints_one_document_and_nothing_else(
    scan_stubs, monkeypatch, capfd, tmp_path
):
    """In json mode stdout carries exactly one JSON document with the three
    keys; the banner, tables and logs move to stderr."""
    bom = _write_bom(tmp_path / "given.cdx.json")
    reports = tmp_path / "reports"
    saved_console_file = console.file
    code = run_main(
        monkeypatch,
        ["scan", bom, "--reports-dir", str(reports), "--format", "json"],
    )
    assert code == 0
    # The stdout console was pointed at stderr for the duration and restored.
    assert console.file is saved_console_file
    captured = capfd.readouterr()
    # Parsing the whole of stdout proves nothing else reached it.
    document = json.loads(captured.out)
    assert set(document) == {"scanDir", "manifest", "findings"}
    assert document["scanDir"] == str(reports)
    assert document["manifest"]["layoutVersion"] == "1.0"
    assert len(document["findings"]) == 1
    # Positive control: the scan ran, rendering on the moved console.
    assert scan_stubs["matching"], "the matching stage never ran"


def test_json_format_with_two_targets_prints_an_array(scan_stubs, monkeypatch, capfd, tmp_path):
    first = _write_bom(tmp_path / "first.cdx.json", name="first")
    second = _write_bom(tmp_path / "second.cdx.json", name="second")
    reports = tmp_path / "reports"
    code = run_main(
        monkeypatch,
        [
            "scan",
            first,
            second,
            "--reports-dir",
            str(reports),
            "--format",
            "json",
            "--no-banner",
        ],
    )
    assert code == 0
    documents = json.loads(capfd.readouterr().out)
    assert isinstance(documents, list) and len(documents) == 2
    assert [doc["scanDir"] for doc in documents] == [
        str(reports / "1-first.cdx.json"),
        str(reports / "2-second.cdx.json"),
    ]
    for doc in documents:
        assert set(doc) == {"scanDir", "manifest", "findings"}
        assert Path(doc["scanDir"]).is_dir(), "each target writes its own directory"
    # Positive control: two scans ran, one per target.
    assert len(scan_stubs["matching"]) == 2


def test_text_format_leaves_the_scan_tables_on_stdout(
    scan_stubs, monkeypatch, capfd, tmp_path, no_license_env
):
    """Text mode keeps the rendered tables on stdout, logs on stderr."""
    monkeypatch.setenv("FETCH_LICENSE", "true")
    monkeypatch.setattr(
        pipeline,
        "get_pkg_list",
        lambda f: (
            [
                {
                    "purl": "pkg:npm/demo@1.0.0",
                    "name": "demo",
                    "version": "1.0.0",
                    # A license that is not OSI approved earns the package a
                    # row in the license table printed on stdout.
                    "licenses": ["CC-BY-NC-4.0"],
                }
            ],
            [],
        ),
    )
    bom = _write_bom(tmp_path / "given.cdx.json")
    code = run_main(monkeypatch, ["scan", bom, "--reports-dir", str(tmp_path / "reports"), "--no-banner"])
    assert code == 0
    # Positive control: the matching stage ran, so the scan was real.
    assert scan_stubs["matching"], "the matching stage never ran"
    captured = capfd.readouterr()
    assert "CC-BY-NC-4.0" in captured.out
    assert "CC-BY-NC-4.0" not in captured.err


# ---------------------------------------------------------------------------
# profiles
# ---------------------------------------------------------------------------


def test_profile_quick_turns_reachability_off_and_an_explicit_analyzer_wins(
    scan_stubs, monkeypatch, tmp_path
):
    bom = _write_bom(tmp_path / "given.cdx.json")
    reports = tmp_path / "reports"
    code = run_main(
        monkeypatch, ["scan", bom, "--profile", "quick", "--reports-dir", str(reports), "--no-banner"]
    )
    assert code == 0
    stages = {stage["name"]: stage for stage in _manifest_of(reports)["stages"]}
    assert _manifest_of(reports)["options"]["reachability_analyzer"] == "off"
    assert stages["enrichment"]["status"] == "skipped"

    overridden = tmp_path / "overridden"
    code = run_main(
        monkeypatch,
        [
            "scan",
            bom,
            "--profile",
            "quick",
            "--reachability-analyzer",
            "FrameworkReachability",
            "--reports-dir",
            str(overridden),
            "--no-banner",
        ],
    )
    assert code == 0
    manifest = _manifest_of(overridden)
    assert manifest["options"]["reachability_analyzer"] == "FrameworkReachability"
    # The explicit option kept the check on: the enrichment stage ran.
    stages = {stage["name"]: stage for stage in manifest["stages"]}
    assert stages["enrichment"]["status"] != "skipped"
    # Positive control: both scans ran.
    assert len(scan_stubs["matching"]) == 2


def test_profile_ci_keeps_explain_on_when_passed_explicitly(
    scan_stubs, fake_tools, monkeypatch, tmp_path
):
    bom = _write_bom(tmp_path / "given.cdx.json")
    reports = tmp_path / "reports"
    code = run_main(
        monkeypatch,
        ["scan", bom, "--profile", "ci", "--explain", "--reports-dir", str(reports), "--no-banner"],
    )
    assert code == 0
    manifest = _manifest_of(reports)
    assert manifest["options"]["explain"] is True
    stages = {stage["name"]: stage for stage in manifest["stages"]}
    assert stages["explain"]["status"] == "completed"
    # The ci profile alone keeps explain off.
    alone = tmp_path / "alone"
    code = run_main(
        monkeypatch, ["scan", bom, "--profile", "ci", "--reports-dir", str(alone), "--no-banner"]
    )
    assert code == 0
    assert _manifest_of(alone)["options"]["explain"] is False


def test_profile_deep_enables_risk_license_and_semantic_reachability(
    scan_stubs, fake_tools, monkeypatch, tmp_path, no_license_env
):
    """The deep profile turns the risk audit and the license analysis on and
    selects the semantic reachability analyzer, on the recorded namespace."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.js").write_text("const leftPad = require('left-pad');\n")
    reports = tmp_path / "reports"
    code = run_main(
        monkeypatch,
        [
            "scan",
            str(src),
            "-t",
            "js",
            "--bom-engine",
            "CdxgenGenerator",
            "--profile",
            "deep",
            "--reports-dir",
            str(reports),
            "--no-banner",
        ],
    )
    assert code == 0
    manifest = _manifest_of(reports)
    assert manifest["options"]["risk_audit"] is True
    assert manifest["options"]["reachability_analyzer"] == "SemanticReachability"
    # The semantic analyzer switches the vulnerability analyzer over.
    assert manifest["options"]["vuln_analyzer"] == "LifecycleAnalyzer"
    stages = {stage["name"]: stage for stage in manifest["stages"]}
    assert stages["licenses"]["status"] == "completed"
    assert stages["risk"]["status"] == "completed"
    # Positive controls: the license analysis and the risk audit both ran,
    # and the cdxgen process produced the BOM.
    assert os.environ.get("FETCH_LICENSE") == "true"
    assert scan_stubs["risk"], "the risk audit never ran"
    assert scan_stubs["cdxgen"], "the cdxgen process never ran"
    assert scan_stubs["matching"], "the matching stage never ran"


# ---------------------------------------------------------------------------
# excluded types
# ---------------------------------------------------------------------------


def test_exclude_type_through_the_cli_leaves_no_os_scan(
    scan_stubs, monkeypatch, tmp_path
):
    """--exclude-type os drops the os type before any stage and reaches the
    cdxgen command line."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text("import requests\n")
    reports = tmp_path / "reports"
    code = run_main(
        monkeypatch,
        [
            "scan",
            str(src),
            "-t",
            "os",
            "python",
            "--bom-engine",
            "CdxgenGenerator",
            "--exclude-type",
            "os",
            "--reports-dir",
            str(reports),
            "--no-banner",
        ],
    )
    assert code == 0
    manifest = _manifest_of(reports)
    assert manifest["options"]["project_type"] == ["os", "python"]
    assert manifest["options"]["exclude_types"] == ["os"]
    # Positive controls: cdxgen ran once, for python only, with the excluded
    # type filtered the same way.
    assert len(scan_stubs["cdxgen"]) == 1, "cdxgen must run once, for python"
    args = scan_stubs["cdxgen"][0]
    assert args[args.index("-t") + 1] == "python"
    assert args[args.index("--exclude-type") + 1] == "os"


# ---------------------------------------------------------------------------
# multi-target
# ---------------------------------------------------------------------------


def test_the_multi_target_exit_code_is_the_highest(scan_stubs, monkeypatch, caplog, tmp_path):
    """A refused target among several counts 1 while the others still scan."""
    monkeypatch.chdir(tmp_path)
    bom = _write_bom(tmp_path / "given.cdx.json")
    reports = tmp_path / "reports"
    with caplog.at_level(logging.ERROR, logger=LOG.name):
        code = run_main(
            monkeypatch,
            ["scan", bom, "no-such-project", "--reports-dir", str(reports), "--no-banner"],
        )
    assert code == 1
    assert "no-such-project" in " ".join(record.getMessage() for record in caplog.records)
    # The first target's scan directory was written under its index and name.
    assert (reports / "1-given.cdx.json" / "depscan.manifest.json").is_file()
    assert not (reports / "2-no-such-project").exists()
    # Positive control: exactly one scan ran, for the existing target.
    assert len(scan_stubs["matching"]) == 1


# ---------------------------------------------------------------------------
# the cdxgen BOM profile through the CLI
# ---------------------------------------------------------------------------


def test_bom_profile_license_compliance_runs_the_license_stage(
    scan_stubs, monkeypatch, tmp_path, no_license_env
):
    """--bom-profile license-compliance reaches the internal profile dest and
    the license analysis runs, through the command line as through the API."""
    bom = _write_bom(tmp_path / "given.cdx.json")
    reports = tmp_path / "reports"
    code = run_main(
        monkeypatch,
        [
            "scan",
            bom,
            "--bom-profile",
            "license-compliance",
            "--reports-dir",
            str(reports),
            "--no-banner",
        ],
    )
    assert code == 0
    manifest = _manifest_of(reports)
    assert manifest["options"]["profile"] == "license-compliance"
    stages = {stage["name"]: stage for stage in manifest["stages"]}
    assert stages["licenses"]["status"] == "completed"
    # Positive control: the license analysis really turned on.
    assert os.environ.get("FETCH_LICENSE") == "true"
