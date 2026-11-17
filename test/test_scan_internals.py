"""The internal scan options the v7 command line feeds the pipeline.

Excluded project types, the offline database, the doctor report a caller
hands the scan instead of a second probe, the not-assessed check records in
the manifest, and the split of logs and progress onto stderr while tables
stay on stdout.

The scans stub the database helpers, the vulnerability analyzer and the
cdxgen process the way the scan directory tests stub theirs, so no test
touches the network, a host database or a host cdxgen. Every stub records
its calls and the tests assert the recording.
"""

import json
import os
from pathlib import Path

import pytest

from depscan import api
from depscan.cli_options import build_parser
from depscan.lib import bom as bom_mod
from depscan.lib import doctor as doctor_mod
from depscan.lib import pipeline, vdb_setup
from xbom_lib import cdxgen as cdxgen_mod

VULN_REQUESTS = {
    "id": "CVE-2024-1111",
    "bom-ref": "CVE-2024-1111/pkg:pypi/requests@2.32.1",
    "affects": [{"ref": "pkg:pypi/requests@2.32.1"}],
    "ratings": [{"severity": "high", "score": 8.1, "method": "CVSSv31"}],
    "fixed_location": "2.32.2",
}

# The BOM document the fake cdxgen process writes, so the scan's package
# loading and VDR writing proceed as they do after a real generation run.
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


class _StubVdrResult:
    success = True
    prioritized_pkg_vuln_trees = {}

    def __init__(self, pkg_vulnerabilities):
        self.pkg_vulnerabilities = pkg_vulnerabilities


@pytest.fixture
def scan_stubs(monkeypatch):
    """Stub a source-directory scan's database, matching and cdxgen process.

    The doctor report stays real, with the database inspection replaced by a
    known state, exactly as the scan directory tests fake it. The fake cdxgen
    records the command line it was handed and writes the BOM it was asked
    for, which is what a successful run leaves behind.
    """
    calls = {"matching": [], "database": [], "cdxgen": []}
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


def _source_scan_options(tmp_path, **overrides):
    """The options of a source-directory scan for the given project types."""
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    options = dict(
        src_dir_image=str(src),
        reports_dir=str(tmp_path / "reports"),
        bom_engine="CdxgenGenerator",
        reachability_analyzer="off",
        no_banner=True,
    )
    options.update(overrides)
    return api.scan_options(**options)


def _manifest_of(reports_dir):
    return json.loads((Path(reports_dir) / "depscan.manifest.json").read_text())


# ---------------------------------------------------------------------------
# excluded project types
# ---------------------------------------------------------------------------


def test_an_excluded_os_type_never_reaches_a_stage_or_cdxgen(scan_stubs, tmp_path):
    """Excluding os removes it from the type list before any stage runs, so
    no OS scan is launched and the cdxgen command line filters the BOM the
    same way."""
    result = api.scan(
        _source_scan_options(tmp_path, project_type=["os", "python"], exclude_types=["os"]),
        render=False,
    )

    assert result.project_types == ["python"]
    # Positive controls: the cdxgen process, the matching stage and the
    # database guard all ran, once, for the python type only.
    assert len(scan_stubs["cdxgen"]) == 1, "cdxgen must run once, for python"
    assert len(scan_stubs["matching"]) == 1, "the matching stage never ran"
    assert scan_stubs["database"], "the database guard never ran"
    args = scan_stubs["cdxgen"][0]
    assert args[args.index("-t") + 1] == "python"
    assert args[args.index("--exclude-type") + 1] == "os"


def test_an_excluded_docker_type_leaves_no_docker_scan(scan_stubs, tmp_path):
    """Excluding docker drops the container scan the docker type would have
    launched, and the exclusion still reaches the cdxgen command line."""
    result = api.scan(
        _source_scan_options(
            tmp_path, project_type=["docker", "python"], exclude_types=["docker"]
        ),
        render=False,
    )

    assert result.project_types == ["python"]
    assert len(scan_stubs["cdxgen"]) == 1, "cdxgen must run once, for python"
    args = scan_stubs["cdxgen"][0]
    assert args[args.index("-t") + 1] == "python"
    assert args[args.index("--exclude-type") + 1] == "docker"
    # The docker inventory itself never ran.
    assert all("-t" not in args or args[args.index("-t") + 1] != "docker" for args in scan_stubs["cdxgen"])


def test_the_container_run_command_carries_the_excluded_types(tmp_path):
    """The image-based generator appends one --exclude-type pair per excluded
    type to the docker run command it builds."""
    gen = cdxgen_mod.CdxgenImageBasedGenerator(
        str(tmp_path),
        str(tmp_path / "bom.cdx.json"),
        options={"project_type": ["python"], "exclude_types": ["os", "docker"]},
    )
    _, run_command_args = gen._container_run_cmd()
    excluded = [
        run_command_args[i + 1]
        for i, arg in enumerate(run_command_args)
        if arg == "--exclude-type"
    ]
    assert excluded == ["os", "docker"]


# ---------------------------------------------------------------------------
# the offline database
# ---------------------------------------------------------------------------


def test_vdb_offline_skips_the_download_and_still_guards_the_database(
    scan_stubs, tmp_path, monkeypatch
):
    """Offline mode skips the whole download branch: no freshness check, no
    download, no marker write. The unusable-database guard still runs, so the
    database is verified rather than assumed."""
    needed = []

    def refused_download(url):
        raise AssertionError("the offline scan must not download the database")

    def would_download(url, data_dir):
        needed.append(url)
        return True, "stale"

    monkeypatch.setattr(vdb_setup, "download_vdb_with_retries", refused_download)
    monkeypatch.setattr(vdb_setup, "vdb_download_needed", would_download)

    result = api.scan(
        _source_scan_options(tmp_path, project_type=["python"], vdb_offline=True), render=False
    )

    # Positive control: the database stage still ran to its guard.
    assert scan_stubs["database"], "the unusable-database guard never ran"
    assert needed == [], "the download decision must not even be consulted"
    assert result.project_types == ["python"]


def test_vdb_offline_with_an_unusable_database_stops_the_scan(scan_stubs, tmp_path, monkeypatch):
    """Offline mode never fetches a database, so a missing or empty one stops
    the scan through the existing guard: the error the CLI turns into exit
    code 1, never a clean-looking zero-findings scan."""

    def unusable():
        raise vdb_setup.VdbUnusableError(
            "The vulnerability database at /tmp/vdb is empty; no search can "
            "return results. Fetch one with `depscan-vdb download` or "
            "'vdb db refresh full'."
        )

    monkeypatch.setattr(vdb_setup, "ensure_vdb_usable", unusable)

    with pytest.raises(api.ScanError, match="depscan-vdb download"):
        api.scan(
            _source_scan_options(tmp_path, project_type=["python"], vdb_offline=True), render=False
        )


# ---------------------------------------------------------------------------
# the doctor report a caller hands the scan
# ---------------------------------------------------------------------------


def test_a_passed_doctor_report_is_reused_not_recollected(scan_stubs, tmp_path, monkeypatch):
    """api.scan reuses the doctor report it is handed instead of probing the
    machine a second time, the manifest carries that report's content, and
    the report object never lands in the options namespace."""
    calls = []

    def refused_doctor():
        calls.append(1)
        raise AssertionError("a passed doctor report must not be collected again")

    monkeypatch.setattr(doctor_mod, "doctor", refused_doctor)
    fixed = doctor_mod.DoctorReport(
        schema_version="1",
        depscan_version="7.0.0-test",
        platform={"os": "linux", "arch": "x86_64", "libc": "glibc"},
        tools=[
            doctor_mod.ToolStatus(
                name="cdxgen", path="/opt/fake/cdxgen", version="13.8.0", source="path"
            )
        ],
        data={"vulnerabilityDatabase": dict(FULL_VDB_DATA)},
        capabilities=[],
    )
    options = _source_scan_options(tmp_path, project_type=["python"])

    result = api.scan(options, render=False, doctor_report=fixed)

    # Positive control of the refusal stub: the real collector never ran.
    assert calls == []
    assert result.manifest is not None, "the scan directory was not written"
    assert result.manifest["platform"] == fixed.platform
    assert result.manifest["tools"][0]["name"] == "cdxgen"
    assert result.manifest["tools"][0]["path"] == "/opt/fake/cdxgen"
    assert result.manifest["capabilities"] == []
    # The report travelled only through the keyword argument.
    assert "doctor_report" not in vars(options)
    assert "doctor_report" not in result.manifest["options"]


def test_checks_not_assessed_are_recorded_in_the_manifest(scan_stubs, tmp_path):
    """Each entry becomes a check-<name> stage entry with status
    not-assessed, the reason and the capability named, in the written
    manifest."""
    result = api.scan(
        _source_scan_options(tmp_path, project_type=["python"]),
        render=False,
        checks_not_assessed=[
            {"name": "reachability", "reason": "cdxgen was not found on PATH"},
            {"name": "binary", "reason": "the blint package is not installed"},
        ],
    )

    assert result.manifest is not None, "the scan directory was not written"
    stages = {stage["name"]: stage for stage in result.manifest["stages"]}
    assert stages["check-reachability"]["status"] == "not-assessed"
    assert stages["check-reachability"]["reason"] == "cdxgen was not found on PATH"
    assert stages["check-reachability"]["capabilities"] == ["reachability"]
    assert stages["check-binary"]["status"] == "not-assessed"
    assert stages["check-binary"]["reason"] == "the blint package is not installed"
    assert stages["check-binary"]["capabilities"] == ["binary"]
    # The written file carries the same entries the result holds.
    written = _manifest_of(result.reports_dir)
    assert "check-reachability" in {stage["name"] for stage in written["stages"]}
    assert "check-binary" in {stage["name"] for stage in written["stages"]}


def test_checks_not_assessed_are_skipped_without_a_scan_directory(scan_stubs, tmp_path):
    """A scan that writes no directory (the server path) records nothing and
    does not fail on the entries."""
    result = api._run_stages(
        _source_scan_options(tmp_path, project_type=["python"]),
        render=False,
        database=False,
        write_scan_dir=False,
        checks_not_assessed=[{"name": "reachability", "reason": "not probed"}],
    )
    assert result.manifest is None
    # Positive control: the scan itself still ran.
    assert scan_stubs["matching"], "the matching stage never ran"


# ---------------------------------------------------------------------------
# logs and progress on stderr, tables on stdout
# ---------------------------------------------------------------------------


def _bom_scan_options(tmp_path, **overrides):
    bom = tmp_path / "given.cdx.json"
    bom.write_text(json.dumps(BOM_DOCUMENT))
    options = dict(bom=str(bom), reports_dir=str(tmp_path / "reports"), no_banner=True)
    options.update(overrides)
    return api.scan_options(**options)


def test_the_logging_console_writes_on_stderr(capfd):
    """The second console writes on stderr, so logs and progress that print
    on it leave stdout to the rendered output."""
    pipeline.log_console.print("probe line for the log console")
    captured = capfd.readouterr()
    assert "probe line for the log console" in captured.err
    assert captured.out == ""


def test_the_logging_handler_is_attached_to_the_stderr_console():
    """In a fresh interpreter, where the handler is installed the way the
    command runs (the test session's root logger already has handlers of its
    own), a log line lands on stderr and nothing on stdout."""
    import subprocess
    import sys

    probe = "from depscan.lib.logger import LOG\nLOG.info('probe log line for stderr')\n"
    proc = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, check=False
    )
    assert "probe log line for stderr" in proc.stderr, proc.stderr
    assert proc.stdout == ""


def test_progress_panels_write_on_stderr(tmp_path, capfd, monkeypatch):
    """The pipeline's progress panels, the license audit announcement here,
    print on the log console: stderr, not stdout."""
    monkeypatch.delenv("FETCH_LICENSE", raising=False)
    src = tmp_path / "src"
    src.mkdir()
    args = build_parser().parse_args(
        [
            "-t",
            "license",
            "python",
            "--src",
            str(src),
            "--reports-dir",
            str(tmp_path / "reports"),
            "--no-banner",
        ]
    )
    ctx = pipeline.build_context(args)
    pipeline.stage_setup(ctx)
    pipeline.finalize_setup(ctx)

    captured = capfd.readouterr()
    # Positive control: the license analysis really turned on.
    assert os.environ["FETCH_LICENSE"] == "true"
    assert "License audit is enabled" in captured.err
    assert "License audit is enabled" not in captured.out


def test_tables_stay_on_stdout(scan_stubs, tmp_path, monkeypatch, capfd):
    """The rendered tables, the license table here, print on the stdout
    console and never on stderr."""
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
    api.scan(_bom_scan_options(tmp_path))

    # Positive control: the matching stage ran, so the scan was real.
    assert scan_stubs["matching"], "the matching stage never ran"
    captured = capfd.readouterr()
    assert "demo" in captured.out
    assert "CC-BY-NC-4.0" in captured.out
    assert "CC-BY-NC-4.0" not in captured.err


def test_quiet_mode_mutes_the_log_console_too(scan_stubs, tmp_path, monkeypatch, capfd):
    """Quiet mutes both consoles: no log lines, no progress, no tables."""
    # The quiet handling disables the logger globally; the pre-test state is
    # restored so later tests keep their log output.
    monkeypatch.setattr(pipeline.LOG, "disabled", False)
    api.scan(_bom_scan_options(tmp_path, quiet=True))
    captured = capfd.readouterr()
    assert captured.out == ""
    assert captured.err == ""
