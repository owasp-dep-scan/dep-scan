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
from pathlib import Path

import pytest

from depscan import api
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
