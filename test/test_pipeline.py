"""Unit tests for the pipeline stages, one stage per test.

Each test builds a small scan context and runs a single stage. The expensive
collaborators (the database, the vulnerability search, the registry risk
audit) are stubbed, and every stub records its calls so the test also proves
the stage reached it. The BOM fixtures come from ``test/data``; nothing here
touches the network or a database on this machine.
"""

import json
import os
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

from depscan.cli_options import build_parser
from depscan.lib import pipeline, vdb_setup
from depscan.lib.bom import BomResult

DATA_DIR = Path(__file__).parent / "data"


def _args(argv):
    return build_parser().parse_args(argv)


def _write_bom(path, components=None):
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {"component": {"name": "app", "type": "application"}},
        "components": components
        if components is not None
        else [
            {
                "name": "time",
                "version": "0.1.45",
                "purl": "pkg:cargo/time@0.1.45",
                "bom-ref": "pkg:cargo/time@0.1.45",
                "type": "library",
            }
        ],
    }
    path.write_text(json.dumps(bom))
    return str(path)


def _ctx(tmp_path, argv):
    """Build a context whose setup stage has run, with reports under tmp."""
    reports = tmp_path / "reports"
    reports.mkdir(exist_ok=True)
    args = _args(["--reports-dir", str(reports), "--no-banner", *argv])
    ctx = pipeline.build_context(args)
    pipeline.stage_setup(ctx)
    return ctx


# ---------------------------------------------------------------------------
# setup
# ---------------------------------------------------------------------------


def test_stage_setup_resolves_directories_and_options(tmp_path):
    bom = _write_bom(tmp_path / "sbom.cdx.json")
    # An empty --src makes the setup stage infer the source directory from
    # the BOM's location, the way a config file without a src key leaves it.
    ctx = _ctx(tmp_path, ["--bom", bom, "--src", ""])
    assert ctx.src_dir == os.path.dirname(os.path.realpath(bom))
    assert ctx.reports_dir == str(tmp_path / "reports")
    assert ctx.user_bom_dir is None
    assert ctx.bom_dir_mode is False
    assert ctx.depscan_options["src_dir"] == ctx.src_dir
    assert ctx.depscan_options["reports_dir"] == ctx.reports_dir
    assert ctx.depscan_options["exclude_malware"] is False


def test_stage_setup_stops_the_scan_on_unusable_inputs(tmp_path):
    args = _args(
        [
            "--bom",
            str(tmp_path / "missing.json"),
            "--reports-dir",
            str(tmp_path / "reports"),
            "--no-banner",
        ]
    )
    ctx = pipeline.build_context(args)
    with pytest.raises(pipeline.ScanStageError):
        pipeline.stage_setup(ctx)


def test_stage_setup_switches_to_lifecycle_analyzer_for_semantic(tmp_path):
    args = _args(
        [
            "--bom",
            _write_bom(tmp_path / "sbom.cdx.json"),
            "--reachability-analyzer",
            "SemanticReachability",
            "--reports-dir",
            str(tmp_path / "reports"),
            "--no-banner",
        ]
    )
    ctx = pipeline.build_context(args)
    pipeline.stage_setup(ctx)
    assert ctx.args.vuln_analyzer == "LifecycleAnalyzer"
    assert ctx.depscan_options["vuln_analyzer"] == "LifecycleAnalyzer"


def test_finalize_setup_enables_licenses_from_a_profile_without_the_type(tmp_path, monkeypatch):
    """A profile naming license turns the analysis on even when the license
    pseudo type was not among the project types; stripping it from the type
    list must not fail the scan."""
    monkeypatch.delenv("FETCH_LICENSE", raising=False)
    src = tmp_path / "src"
    src.mkdir()
    ctx = _ctx(tmp_path, ["-t", "python", "--src", str(src), "--profile", "license-compliance"])

    pipeline.finalize_setup(ctx)

    assert os.environ["FETCH_LICENSE"] == "true"
    assert ctx.project_types == ["python"]


def test_finalize_setup_strips_a_detected_license_pseudo_type(tmp_path, monkeypatch):
    """The license pseudo type detected through --type licenses nothing
    itself; the analysis is what runs, and no empty type scan remains."""
    monkeypatch.delenv("FETCH_LICENSE", raising=False)
    src = tmp_path / "src"
    src.mkdir()
    ctx = _ctx(tmp_path, ["-t", "license", "python", "--src", str(src)])

    pipeline.finalize_setup(ctx)

    assert os.environ["FETCH_LICENSE"] == "true"
    assert ctx.project_types == ["python"]


def test_set_project_types_removes_the_excluded_types(tmp_path):
    args = _args(["-t", "os", "python", "docker", "--exclude-types", "os", "docker"])
    pkg_list, project_types = pipeline.set_project_types(args, str(tmp_path))
    assert project_types == ["python"]


def test_set_project_types_keeps_the_list_when_nothing_is_excluded(tmp_path):
    args = _args(["-t", "python"])
    pkg_list, project_types = pipeline.set_project_types(args, str(tmp_path))
    assert project_types == ["python"]


def test_set_project_types_stops_when_every_type_is_excluded(tmp_path):
    """A scan left with no project type must stop, not run zero type scans
    and report a clean result."""
    args = _args(["-t", "os", "python", "--exclude-types", "os", "python"])
    with pytest.raises(pipeline.ScanStageError, match="was excluded"):
        pipeline.set_project_types(args, str(tmp_path))


# ---------------------------------------------------------------------------
# database
# ---------------------------------------------------------------------------


def test_stage_database_resolves_and_guards_the_database(tmp_path, monkeypatch):
    calls = {}

    def fake_resolve(args):
        calls["resolve"] = True
        return "oras://vdb-img", False, "app-only"

    def fake_needed(url, data_dir):
        calls["needed"] = url
        return False, None

    monkeypatch.setattr(vdb_setup, "resolve_scan_vdb_image", fake_resolve)
    monkeypatch.setattr(vdb_setup, "vdb_download_needed", fake_needed)
    monkeypatch.setattr(
        vdb_setup, "configure_vdb_readonly", lambda: calls.setdefault("readonly", True)
    )
    monkeypatch.setattr(vdb_setup, "ensure_vdb_usable", lambda: calls.setdefault("guard", True))
    monkeypatch.setattr(pipeline, "VDB_USE_SHARDS", False)
    ctx = _ctx(tmp_path, ["--bom", _write_bom(tmp_path / "sbom.cdx.json")])

    pipeline.stage_database(ctx)

    assert ctx.scan_vdb_url == "oras://vdb-img"
    assert ctx.vdb_user_pinned is False
    assert ctx.vdb_flavor == "app-only"
    # Positive controls: every stubbed collaborator was reached.
    assert calls["resolve"] is True
    assert calls["needed"] == "oras://vdb-img"
    assert calls["readonly"] is True
    assert calls["guard"] is True


def test_stage_database_stops_cleanly_when_the_download_fails(tmp_path, monkeypatch, caplog):
    calls = {}

    def failing_download(url):
        calls["download"] = url
        raise ConnectionError("connection refused")

    monkeypatch.setattr(
        vdb_setup, "resolve_scan_vdb_image", lambda args: ("oras://vdb-img", False, "app-only")
    )
    monkeypatch.setattr(vdb_setup, "vdb_download_needed", lambda url, data_dir: (True, "stale"))
    monkeypatch.setattr(vdb_setup, "download_vdb_with_retries", failing_download)
    monkeypatch.setattr(pipeline, "VDB_USE_SHARDS", False)
    ctx = _ctx(tmp_path, ["--bom", _write_bom(tmp_path / "sbom.cdx.json")])

    with caplog.at_level("ERROR", logger=pipeline.LOG.name):
        with pytest.raises(pipeline.ScanStageError):
            pipeline.stage_database(ctx)
    assert calls["download"] == "oras://vdb-img"
    messages = [r.getMessage() for r in caplog.records if r.levelname == "ERROR"]
    assert any(
        "Could not download the vulnerability database oras://vdb-img" in m
        and "connection refused" in m
        for m in messages
    )


def test_finalize_setup_loads_custom_data_after_detecting_types(tmp_path, monkeypatch):
    order = []
    real_set_project_types = pipeline.set_project_types

    def recording_set_project_types(args, src_dir):
        order.append("types")
        return real_set_project_types(args, src_dir)

    monkeypatch.setattr(pipeline, "set_project_types", recording_set_project_types)
    monkeypatch.setattr(
        pipeline.search, "load_custom_data", lambda path: order.append(f"custom:{path}")
    )
    custom = tmp_path / "custom.json"
    custom.write_text("{}")
    ctx = _ctx(tmp_path, ["--bom", _write_bom(tmp_path / "sbom.cdx.json")])
    ctx.args.custom_data = str(custom)

    pipeline.finalize_setup(ctx)

    assert order == ["types", f"custom:{custom}"]


def test_stage_database_stops_when_image_selection_fails(tmp_path, monkeypatch):
    def bad_resolve(args):
        raise ValueError("vdb 7 publishes no per-distro complete database.")

    monkeypatch.setattr(vdb_setup, "resolve_scan_vdb_image", bad_resolve)
    ctx = _ctx(tmp_path, ["--bom", _write_bom(tmp_path / "sbom.cdx.json")])
    with pytest.raises(pipeline.ScanStageError):
        pipeline.stage_database(ctx)


# ---------------------------------------------------------------------------
# inventory
# ---------------------------------------------------------------------------


def test_stage_inventory_loads_packages_from_a_bom_fixture(tmp_path):
    bom = str(DATA_DIR / "bom-js.json")
    ctx = _ctx(tmp_path, ["--bom", bom])
    scan = pipeline.TypeScan(project_type="bom")
    assert pipeline.stage_inventory(ctx, scan) is True
    assert scan.nominated_bom_file == bom
    assert scan.bom_file == bom
    assert len(scan.pkg_list) > 100
    assert all("purl" in pkg for pkg in scan.pkg_list[:10])
    assert isinstance(scan.scoped_pkgs, dict)


@pytest.mark.parametrize(
    "content, expected",
    [
        (b'<?xml version="1.0"?><bom xmlns="http://cyclonedx.org/schema/bom/1.6"/>', "is XML"),
        (b"\xef\xbb\xbf  <bom/>", "is XML"),
        (b"name,version\n", "is not a CycloneDX JSON document"),
        (b"", "is not a CycloneDX JSON document"),
    ],
)
def test_validate_scan_inputs_rejects_a_bom_that_is_not_json(tmp_path, content, expected):
    bom = tmp_path / "sbom.cdx.json"
    bom.write_bytes(content)
    errors = pipeline.validate_scan_inputs(_args(["--bom", str(bom)]))
    assert len(errors) == 1
    assert expected in errors[0]


def test_validate_scan_inputs_rejects_the_xml_fixture_and_accepts_json():
    errors = pipeline.validate_scan_inputs(_args(["--bom", str(DATA_DIR / "bom-py.xml")]))
    assert errors and "is XML" in errors[0]
    assert pipeline.validate_scan_inputs(_args(["--bom", str(DATA_DIR / "bom-js.json")])) == []


def test_stage_inventory_reads_the_bom_argument_in_lifecycle_mode(tmp_path):
    """Semantic reachability switches to lifecycle mode, which points the BOM
    directory at the empty reports directory. The --bom packages must still
    be scanned."""
    bom = str(DATA_DIR / "bom-js.json")
    ctx = _ctx(tmp_path, ["--bom", bom, "--reachability-analyzer", "SemanticReachability"])
    scan = pipeline.TypeScan(project_type="bom")
    assert pipeline.stage_inventory(ctx, scan) is True
    assert scan.lifecycle_mode is True
    assert scan.bom_dir == os.path.realpath(ctx.reports_dir)
    assert scan.bom_files[0] == bom
    assert scan.bom_file == bom
    expected, _ = pipeline.get_pkg_list(bom)
    assert len(scan.pkg_list) == len(expected) > 100


def test_stage_inventory_skips_a_bom_dir_with_no_packages(tmp_path, caplog):
    bom_dir = tmp_path / "boms"
    bom_dir.mkdir()
    _write_bom(bom_dir / "sbom.cdx.json", components=[])
    ctx = _ctx(tmp_path, ["--bom-dir", str(bom_dir)])
    scan = pipeline.TypeScan(project_type="bom")
    with caplog.at_level("INFO", logger=pipeline.LOG.name):
        assert pipeline.stage_inventory(ctx, scan) is False
    assert any("No packages were found" in r.getMessage() for r in caplog.records)


def test_stage_inventory_records_the_bom_for_the_report_template(tmp_path):
    """The template receives the BOM of a type even when the type is skipped
    for having no packages, as before the stage split."""
    bom = _write_bom(tmp_path / "sbom.cdx.json", components=[])
    ctx = _ctx(tmp_path, ["--bom", bom])
    scan = pipeline.TypeScan(project_type="bom")
    assert pipeline.stage_inventory(ctx, scan) is False
    assert ctx.bom_file == bom


def test_stage_inventory_skips_a_type_when_no_bom_is_produced(tmp_path, monkeypatch):
    monkeypatch.setattr(pipeline, "create_bom", lambda *a, **k: BomResult(success=False))
    src = tmp_path / "src"
    src.mkdir()
    ctx = _ctx(tmp_path, ["-t", "rust", "--src", str(src)])
    scan = pipeline.TypeScan(project_type="rust")
    assert pipeline.stage_inventory(ctx, scan) is False


def test_stage_inventory_stops_under_fail_on_error_when_no_bom_is_produced(tmp_path, monkeypatch):
    monkeypatch.setattr(pipeline, "create_bom", lambda *a, **k: BomResult(success=False))
    src = tmp_path / "src"
    src.mkdir()
    ctx = _ctx(tmp_path, ["-t", "rust", "--src", str(src), "--fail-on-error"])
    scan = pipeline.TypeScan(project_type="rust")
    with pytest.raises(pipeline.ScanStageError):
        pipeline.stage_inventory(ctx, scan)


def test_stage_inventory_carries_the_purl_package_list(tmp_path):
    ctx = _ctx(tmp_path, ["--purl", "pkg:pypi/requests@2.32.1"])
    ctx.purl_pkg_list = [
        {
            "purl": "pkg:pypi/requests@2.32.1",
            "name": "requests",
            "version": "2.32.1",
            "vendor": None,
            "type": "pypi",
        }
    ]
    scan = pipeline.TypeScan(project_type="pypi")
    assert pipeline.stage_inventory(ctx, scan) is True
    assert [p["purl"] for p in scan.pkg_list] == ["pkg:pypi/requests@2.32.1"]


# ---------------------------------------------------------------------------
# analysis: license and risk audit
# ---------------------------------------------------------------------------


def test_stage_analysis_licenses_writes_the_license_report(tmp_path, monkeypatch):
    monkeypatch.setenv("FETCH_LICENSE", "true")
    ctx = _ctx(tmp_path, ["-t", "npm"])
    scan = pipeline.TypeScan(project_type="npm")
    scan.pkg_list = [
        {
            "name": "demo",
            "version": "1.0.0",
            "purl": "pkg:npm/demo@1.0.0",
            # A license that is not OSI approved carries conditions, which is
            # what earns the package a row in the license report.
            "licenses": ["CC-BY-NC-4.0"],
        }
    ]
    pipeline.stage_analysis_licenses(ctx, scan)
    license_report = Path(ctx.reports_dir) / "license-npm.json"
    assert license_report.is_file()
    rows = [json.loads(line) for line in license_report.read_text().splitlines()]
    assert rows[0]["Package"] == "demo"
    assert rows[0]["Version"] == "1.0.0"
    assert "CC-BY-NC-4.0" in rows[0]["License Id"]


def test_stage_analysis_risk_records_and_reports_the_audit(tmp_path, monkeypatch):
    calls = {}

    def fake_risk_audit(project_type, scoped_pkgs, private_ns, pkg_list):
        calls["audit"] = (project_type, list(pkg_list))
        return {
            "fsevents": {
                "scope": "required",
                "risk_metrics": {
                    "risk_score": 0.7,
                    "pkg_deprecated_risk": True,
                },
            }
        }

    monkeypatch.setattr(pipeline, "risk_audit", fake_risk_audit)
    ctx = _ctx(tmp_path, ["-t", "npm"])
    ctx.perform_risk_audit = True
    scan = pipeline.TypeScan(project_type="npm")
    scan.pkg_list = [{"name": "fsevents", "version": "1.2.0", "purl": "pkg:npm/fsevents@1.2.0"}]
    scan.scoped_pkgs = {"required": ["pkg:npm/fsevents@1.2.0"]}
    scan.risk_report_file = os.path.join(ctx.reports_dir, "depscan-risk-npm.json")

    pipeline.stage_analysis_risk(ctx, scan)

    # Positive control: the audit ran for this project type and packages.
    assert calls["audit"][0] == "npm"
    assert calls["audit"][1] == scan.pkg_list
    risk_report = Path(ctx.reports_dir) / "depscan-risk-npm.json"
    assert risk_report.is_file()
    rows = [json.loads(line) for line in risk_report.read_text().splitlines()]
    assert rows[0]["Package"] == "fsevents"
    assert "Deprecated" in rows[0]["Identified Risks"]


def test_stage_analysis_risk_audits_each_ecosystem_of_a_universal_scan(tmp_path, monkeypatch):
    """A source scan is typed universal; its npm and PyPI packages are audited.

    The maven package is left out because the audit reads no Maven metadata,
    and both ecosystems' rows land in the one risk report.
    """
    calls = []

    def fake_risk_audit(project_type, scoped_pkgs, private_ns, pkg_list):
        calls.append((project_type, [pkg["purl"] for pkg in pkg_list]))
        name = pkg_list[0]["name"]
        return {
            name: {
                "scope": "required",
                "risk_metrics": {"risk_score": 0.9, "pkg_deprecated_risk": True},
            }
        }

    monkeypatch.setattr(pipeline, "risk_audit", fake_risk_audit)
    ctx = _ctx(tmp_path, ["-t", "universal"])
    ctx.perform_risk_audit = True
    scan = pipeline.TypeScan(project_type="universal")
    scan.pkg_list = [
        {"name": "left-pad", "version": "1.0.0", "purl": "pkg:npm/left-pad@1.0.0"},
        {"name": "requests", "version": "2.0.0", "purl": "pkg:pypi/requests@2.0.0"},
        {"name": "guava", "version": "1.0", "purl": "pkg:maven/com.google/guava@1.0"},
    ]
    scan.risk_report_file = os.path.join(ctx.reports_dir, "depscan-risk-universal.json")

    assert pipeline.stage_analysis_risk(ctx, scan) is True

    assert calls == [
        ("npm", ["pkg:npm/left-pad@1.0.0"]),
        ("pypi", ["pkg:pypi/requests@2.0.0"]),
    ]
    assert scan.risk_not_assessed is None
    rows = [json.loads(line) for line in Path(scan.risk_report_file).read_text().splitlines()]
    assert [row["Package"] for row in rows] == ["left-pad", "requests"]


def test_stage_analysis_risk_names_why_a_requested_audit_had_nothing_to_audit(
    tmp_path, monkeypatch
):
    """Only Maven packages: the audit was requested and could not run.

    Positive control: the same scan with the audit off returns False with no
    not-assessed reason, which the manifest records as skipped.
    """
    monkeypatch.setattr(
        pipeline, "risk_audit", lambda *a: pytest.fail("nothing here can be audited")
    )
    ctx = _ctx(tmp_path, ["-t", "universal"])
    scan = pipeline.TypeScan(project_type="universal")
    scan.pkg_list = [{"name": "guava", "version": "1.0", "purl": "pkg:maven/com.google/guava@1.0"}]
    ctx.perform_risk_audit = False
    assert pipeline.stage_analysis_risk(ctx, scan) is False
    assert scan.risk_not_assessed is None
    ctx.perform_risk_audit = True
    assert pipeline.stage_analysis_risk(ctx, scan) is False
    reason = scan.risk_not_assessed or ""
    assert "no npm, PyPI or Cargo packages" in reason
    assert "universal" in reason


# ---------------------------------------------------------------------------
# enrichment
# ---------------------------------------------------------------------------


def test_stage_enrichment_runs_reachability_on_the_evidence_fixtures(tmp_path):
    """SemanticReachability over the evinse BOM and the atom 4 reachables
    slice: the atom adapter turns the slices into records, the enrichment
    stage writes them into the evidence store, and the engine counts the
    reached purls from the store."""
    from analysis_lib.evidence import store as evidence_store

    ctx = _ctx(
        tmp_path,
        ["--reachability-analyzer", "SemanticReachability", "-t", "python"],
    )
    shutil.copy2(DATA_DIR / "bom-evinse-java.json", Path(ctx.reports_dir) / "bom-evinse-java.json")
    shutil.copy2(
        DATA_DIR / "atom4" / "python-reachables.slices.json",
        Path(ctx.reports_dir) / "python-reachables.slices.json",
    )
    scan = pipeline.TypeScan(project_type="python")
    scan.bom_dir = str(ctx.reports_dir)

    pipeline.stage_enrichment(ctx, scan)

    assert scan.reachability_analyzer == "SemanticReachability"
    assert scan.reachability_options is not None
    assert scan.direct_purls, "the BOM's occurrences evidence must produce direct purls"
    assert scan.reached_purls, "the reachables slices must produce reached purls"
    assert set(scan.reached_purls) == {
        "pkg:pypi/custom-json-diff@2.1.6",
        "pkg:pypi/quart@0.22.0",
        "pkg:pypi/quart@0.23.1",
        "pkg:pypi/rich@15.0.0",
    }
    assert scan.adapter_results.get("atom") is not None
    assert scan.adapter_results["atom"].status == "completed"
    store = Path(ctx.reports_dir) / evidence_store.EVIDENCE_FILE
    assert store.is_file()
    assert scan.reachability_options.evidence_file == str(store), (
        "the engine reads the store the enrichment stage wrote"
    )
    records = evidence_store.read(str(store))
    assert {r.producer.name for r in records} == {"atom"}
    assert evidence_store.write(str(store), records) == len(records), (
        "a second write of the same records is the same store"
    )


def _flow(purl, file_name):
    """One atom 4 flow object reaching ``purl`` from ``file_name``."""
    return {
        "flows": [
            {"id": 1, "parentFileName": file_name, "lineNumber": 3, "parentMethodName": "main"},
            {"id": 2, "parentFileName": file_name, "lineNumber": 4, "parentMethodName": "call"},
        ],
        "purls": [purl],
    }


def test_a_timed_out_atom_run_keeps_its_caveat_through_a_later_project_type(tmp_path):
    """A scan of two project types: the java run's atom was stopped by its
    timeout, the python run's was not. The java slices' records carry the
    timeout caveat, and the python type's enrichment, which finds the java
    slices too, must neither rebuild them without the caveat nor replace the
    caveated copies in the store."""
    from analysis_lib.evidence import store as evidence_store
    from depscan.lib.bom import ATOM_TIMEOUT_REASON

    ctx = _ctx(tmp_path, ["--reachability-analyzer", "SemanticReachability", "-t", "java"])
    reports = Path(ctx.reports_dir)
    _write_bom(reports / "sbom-java.cdx.json")
    (reports / "java-reachables.slices.json").write_text(
        json.dumps([_flow("pkg:maven/a/b@1", "src/main/java/A.java")])
    )
    java = pipeline.TypeScan(project_type="java")
    java.bom_dir = str(reports)
    java.not_assessed = [ATOM_TIMEOUT_REASON]
    pipeline.stage_enrichment(ctx, java)
    (reports / "python-reachables.slices.json").write_text(
        json.dumps([_flow("pkg:pypi/c@2", "app/main.py")])
    )
    python = pipeline.TypeScan(project_type="python")
    python.bom_dir = str(reports)
    pipeline.stage_enrichment(ctx, python)

    records = evidence_store.read(str(reports / evidence_store.EVIDENCE_FILE))
    by_source = {}
    for record in records:
        by_source.setdefault(record.source, []).append(record)
    assert set(by_source) == {"java-reachables.slices.json", "python-reachables.slices.json"}
    assert len(records) == 2, "each flow is one record, read once"
    (java_record,) = by_source["java-reachables.slices.json"]
    assert ("timeout", ATOM_TIMEOUT_REASON) in [(c.kind, c.detail) for c in java_record.caveats], (
        "the java slices keep the timeout caveat of the run that wrote them"
    )
    (python_record,) = by_source["python-reachables.slices.json"]
    assert not [c for c in python_record.caveats if c.kind == "timeout"], (
        "the python run was not stopped"
    )
    # Both types grade on every atom file they found, as one completed result.
    assert python.adapter_results["atom"].status == "completed"
    assert {r.source for r in python.adapter_results["atom"].records} == set(by_source)
    assert set(python.reached_purls) == {"pkg:maven/a/b@1", "pkg:pypi/c@2"}


def test_an_analyzer_without_reached_records_observed_nothing(tmp_path):
    """atom completed for this type but none of its records counts as
    reached, while the engine's map (the whole store) holds a purl another
    producer reached. The scope must not hand atom that purl: atom observed
    nothing, so a finding atom covers is not assessed."""
    from analysis_lib.evidence.adapters import AdapterResult
    from analysis_lib.findings.exploitability import load_rules
    from analysis_lib.findings.vdr_convert import reach_axis

    scan = SimpleNamespace(
        project_type="python",
        reachability_succeeded=True,
        reached_purls={"pkg:pypi/requests@2.32.1": 1},
        adapter_results={"atom": AdapterResult(status="completed")},
        pkg_list=[{"purl": "pkg:pypi/requests@2.32.1"}],
        bom_dir=str(tmp_path),
    )
    ctx = SimpleNamespace(doctor_report=None, grading_rules=load_rules())
    inputs = pipeline._exploitability_inputs(ctx, scan)
    assert inputs.scope is not None
    assert inputs.scope.reached_by == {"atom": set()}
    assert reach_axis(inputs.scope, "pkg:pypi/requests@2.32.1") == "not_assessed"


def test_stage_enrichment_is_a_no_op_with_reachability_off(tmp_path):
    from depscan.lib.scan_directory import EVIDENCE_FILE

    ctx = _ctx(tmp_path, ["-t", "npm", "--reachability-analyzer", "off"])
    ctx.depscan_options["reachability_analyzer"] = "off"
    ctx.depscan_options["profile"] = "generic"
    scan = pipeline.TypeScan(project_type="npm")
    scan.bom_dir = str(ctx.reports_dir)
    pipeline.stage_enrichment(ctx, scan)
    assert scan.reachability_options is None
    # Null reachability succeeds with empty maps, so nothing was reached.
    assert not scan.reached_purls
    # The store is still written, empty, so the layout is uniform.
    assert (Path(ctx.reports_dir) / EVIDENCE_FILE).read_text() == ""


# ---------------------------------------------------------------------------
# matching
# ---------------------------------------------------------------------------


def test_stage_matching_hands_the_scan_to_the_vdr_analyzer(tmp_path, monkeypatch):
    recorded = {}

    class FakeVDRAnalyzer:
        def __init__(self, vdr_options):
            recorded["options"] = vdr_options

        def process(self):
            recorded["ran"] = True
            return SimpleNamespace(
                success=True, pkg_vulnerabilities=[], prioritized_pkg_vuln_trees={}
            )

    monkeypatch.setattr(pipeline, "VDRAnalyzer", FakeVDRAnalyzer)
    bom = _write_bom(tmp_path / "sbom.cdx.json")
    ctx = _ctx(tmp_path, ["--bom", bom])
    scan = pipeline.TypeScan(project_type="bom")
    scan.bom_file = bom
    scan.pkg_list = [{"purl": "pkg:cargo/time@0.1.45", "name": "time", "version": "0.1.45"}]
    scan.scoped_pkgs = {"required": ["pkg:cargo/time@0.1.45"]}
    scan.reached_purls = {"pkg:cargo/time@0.1.45": 2}

    pipeline.stage_matching(ctx, scan)

    # Positive control: the analyzer ran, on this type's packages.
    assert recorded["ran"] is True
    options = recorded["options"]
    assert options.project_type == "bom"
    assert options.pkg_list == scan.pkg_list
    assert options.bom_file == bom
    assert options.reached_purls == {"pkg:cargo/time@0.1.45": 2}
    assert options.suggest_mode == ctx.args.suggest


# ---------------------------------------------------------------------------
# analysis: the VDR summary
# ---------------------------------------------------------------------------


def test_stage_analysis_vdr_writes_the_vdr_and_aggregates(tmp_path):
    bom = _write_bom(tmp_path / "sbom.cdx.json")
    ctx = _ctx(tmp_path, ["--bom", bom])
    scan = pipeline.TypeScan(project_type="bom")
    scan.bom_file = bom
    scan.pkg_list = [{"purl": "pkg:cargo/time@0.1.45", "name": "time", "version": "0.1.45"}]
    vuln = {
        "id": "RUSTSEC-2020-0071",
        "ratings": [{"severity": "HIGH"}],
        "affects": [{"ref": "pkg:cargo/time@0.1.45"}],
    }
    scan.vdr_result = SimpleNamespace(
        success=True,
        pkg_vulnerabilities=[vuln],
        prioritized_pkg_vuln_trees={"group": [vuln]},
        exploitability={},
    )

    pipeline.stage_analysis_vdr(ctx, scan)

    vdr_file = Path(ctx.reports_dir) / "sbom.vdr.json"
    assert vdr_file.is_file()
    vdr = json.loads(vdr_file.read_text())
    assert vdr["vulnerabilities"][0]["id"] == "RUSTSEC-2020-0071"
    assert scan.summary.get("HIGH") == 1
    assert ctx.summary == scan.summary
    assert ctx.vdr_file == str(vdr_file)
    assert ctx.all_pkg_vulnerabilities == [vuln]
    assert ctx.all_pkg_group_rows == {"group": [vuln]}


def test_stage_analysis_vdr_reports_no_vulnerabilities(tmp_path, caplog):
    bom = _write_bom(tmp_path / "sbom.cdx.json")
    ctx = _ctx(tmp_path, ["--bom", bom])
    scan = pipeline.TypeScan(project_type="bom")
    scan.bom_file = bom
    scan.pkg_list = [{"purl": "pkg:cargo/time@0.1.45", "name": "time", "version": "0.1.45"}]
    scan.vdr_result = SimpleNamespace(
        success=False, pkg_vulnerabilities=None, prioritized_pkg_vuln_trees=None
    )
    with caplog.at_level("INFO", logger=pipeline.LOG.name):
        pipeline.stage_analysis_vdr(ctx, scan)
    assert any("No vulnerabilities found" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------


def test_stage_render_reports_writes_every_report_file(tmp_path):
    bom = _write_bom(tmp_path / "sbom.cdx.json")
    ctx = _ctx(tmp_path, ["--bom", bom])
    scan = pipeline.TypeScan(project_type="bom")
    scan.bom_file = bom
    scan.pkg_list = [{"purl": "pkg:cargo/time@0.1.45", "name": "time", "version": "0.1.45"}]
    vuln = {
        "id": "RUSTSEC-2020-0071",
        "ratings": [{"severity": "HIGH"}],
        "affects": [{"ref": "pkg:cargo/time@0.1.45"}],
    }
    scan.vdr_result = SimpleNamespace(
        success=True,
        pkg_vulnerabilities=[vuln],
        prioritized_pkg_vuln_trees={},
        exploitability={},
    )
    pipeline.stage_analysis_vdr(ctx, scan)
    pipeline.finalize_setup(ctx)
    template = tmp_path / "template.j2"
    template.write_text("{{ summary }}")
    ctx.args.report_template = str(template)
    ctx.args.annotate = True

    pipeline.stage_render_reports(ctx)

    assert ctx.html_report_file and Path(ctx.html_report_file).is_file()
    assert ctx.txt_report_file and Path(ctx.txt_report_file).is_file()
    rendered = Path(ctx.reports_dir) / ctx.args.report_name
    assert rendered.is_file()
    assert ctx.vdr_file, "the summary stage must have produced a VDR file"
    vdr = json.loads(Path(ctx.vdr_file).read_text())
    assert vdr.get("annotations"), "the text report must be annotated into the VDR"


def test_generate_boms_removes_slices_left_by_a_previous_run(tmp_path, monkeypatch):
    reports = tmp_path / "reports"
    reports.mkdir()
    stale = reports / "python-usages.slices.json"
    stale.write_text("{}")
    other_type = reports / "java-usages.slices.json"
    other_type.write_text("{}")
    seen = {}

    def fake_create_bom(bom_file, src_dir, options):
        # Positive control: the generator ran, and it ran after the cleanup.
        seen["stale_present"] = stale.exists()
        return True

    monkeypatch.setattr(pipeline, "create_bom", fake_create_bom)
    args = _args(["--reports-dir", str(reports), "--no-banner"])
    ctx = pipeline.build_context(args)
    ctx.src_dir = str(tmp_path)
    ctx.depscan_options = {"reports_dir": str(reports)}
    scan = pipeline.TypeScan(project_type="python")
    scan.target_bom_file = str(reports / "sbom-python.cdx.json")
    pipeline._generate_boms(ctx, scan)
    assert seen == {"stale_present": False}
    # Only this type's slices are removed.
    assert other_type.exists()


def test_set_slices_args_and_stale_removal_use_the_same_paths(tmp_path):
    from xbom_lib.cdxgen import remove_stale_slices, set_slices_args

    args = []
    set_slices_args(["python"], args, str(tmp_path))
    paths = args[1::2]
    assert len(paths) == 6
    for path in paths:
        Path(path).write_text("{}")
    removed = remove_stale_slices("python", str(tmp_path))
    assert sorted(removed) == sorted(paths)
    assert not any(os.path.exists(path) for path in paths)


def test_generate_boms_removes_every_old_tool_slice_before_generation(tmp_path, monkeypatch):
    from depscan.lib.bom import reachability_slice_files

    old = [tmp_path / name for name in reachability_slice_files().values()]
    for path in old:
        path.write_text("{}")
    unrelated = tmp_path / "notes.json"
    unrelated.write_text("{}")
    seen = []
    monkeypatch.setattr(
        pipeline, "create_bom", lambda *a, **k: seen.append([p.exists() for p in old]) or "bom"
    )
    ctx = SimpleNamespace(src_dir=str(tmp_path), depscan_options={}, doctor_report=None)
    scan = SimpleNamespace(
        project_type="python",
        target_bom_file=str(tmp_path / "sbom-python.cdx.json"),
        prebuild_bom_file=None,
        build_bom_file=None,
        postbuild_bom_file=None,
        container_bom_file=None,
        operations_bom_file=None,
    )
    assert pipeline._generate_boms(ctx, scan) == "bom"
    assert seen == [[False] * len(old)]
    assert unrelated.exists()


@pytest.mark.parametrize(
    "options, types, expected",
    [
        ({}, ["python"], False),
        ({}, ["python", "binary"], True),
        ({"techniques": ["binary-analysis"]}, ["python"], True),
    ],
)
def test_finish_scan_directory_passes_whether_blint_reviews_were_requested(
    monkeypatch, tmp_path, options, types, expected
):
    captured = {}
    monkeypatch.setattr(
        pipeline.scan_directory,
        "write_findings",
        lambda *a, **k: captured.update(k) or {"findings": []},
    )
    scan_dir = SimpleNamespace(build=lambda **k: {})
    monkeypatch.setattr(pipeline.scan_directory, "write_manifest", lambda *a, **k: None)
    ctx = SimpleNamespace(
        scan_dir=scan_dir,
        reports_dir=str(tmp_path),
        all_pkg_vulnerabilities=[],
        src_dir=str(tmp_path),
        exploitability={},
        depscan_options=options,
        project_types=types,
        vdb_flavor=None,
        shards_connected=False,
        evidence_records=[],
    )
    pipeline.finish_scan_directory(ctx)
    assert captured["blint_reviews"] is expected
    assert captured["evidence_records"] == [], (
        "the findings file receives the scan's evidence records, the blint ones included"
    )


def test_exploitability_inputs_come_from_the_adapter_records(tmp_path, monkeypatch):
    """The exploitability inputs are built from the adapter results the BOM
    step and the enrichment stage collected: the reached sets and the purl
    types come from the records, and the slices are never read again."""
    from analysis_lib import ReachabilityAnalysisKV
    from analysis_lib.evidence.adapters import atom as atom_adapter
    from analysis_lib.findings.exploitability import load_rules
    from analysis_lib.findings.vdr_convert import reach_axis
    from analysis_lib import reachability as reachability_module

    slice_file = tmp_path / "java-reachables.slices.json"
    slice_file.write_text(json.dumps([{"flows": [], "purls": ["pkg:maven/a/b@1"]}]))
    options = ReachabilityAnalysisKV(
        project_types=["java"],
        src_dir=str(tmp_path),
        bom_dir=str(tmp_path),
        slices_files=[str(slice_file)],
    )
    scan = SimpleNamespace(
        project_type="java",
        reachability_options=options,
        reachability_succeeded=True,
        reached_purls={"pkg:maven/a/b@1": 1},
        adapter_results={"atom": atom_adapter.extract([str(slice_file)])},
        pkg_list=[{"purl": "pkg:maven/a/b@1", "scope": "required"}],
        bom_dir=str(tmp_path),
    )
    ctx = SimpleNamespace(doctor_report=None, grading_rules=load_rules())

    def refuse_to_read(*args, **kwargs):
        raise AssertionError("the slices were parsed again")

    monkeypatch.setattr(reachability_module, "_iter_json_list", refuse_to_read)
    inputs = pipeline._exploitability_inputs(ctx, scan)
    assert inputs is not None and inputs.scope is not None
    assert inputs.scope.analyzers == ["atom"]
    assert reach_axis(inputs.scope, "pkg:maven/a/b@1") == "likely"


def test_exploitability_inputs_grade_only_the_ecosystems_the_analyzers_covered(tmp_path):
    from analysis_lib import ReachabilityAnalysisKV
    from analysis_lib.evidence.adapters import atom as atom_adapter
    from analysis_lib.findings.exploitability import load_rules
    from analysis_lib.findings.vdr_convert import reach_axis

    slice_file = tmp_path / "java-reachables.slices.json"
    slice_file.write_text(json.dumps([{"flows": [], "purls": ["pkg:maven/a/b@1"]}]))
    options = ReachabilityAnalysisKV(
        project_types=["java"],
        src_dir=str(tmp_path),
        bom_dir=str(tmp_path),
        slices_files=[str(slice_file)],
    )
    scan = SimpleNamespace(
        project_type="java",
        reachability_options=options,
        reachability_succeeded=True,
        reached_purls={"pkg:maven/a/b@1": 1},
        adapter_results={"atom": atom_adapter.extract([str(slice_file)])},
        pkg_list=[{"purl": "pkg:maven/a/b@1", "scope": "required"}],
        bom_dir=str(tmp_path),
    )
    ctx = SimpleNamespace(doctor_report=None, grading_rules=load_rules())
    inputs = pipeline._exploitability_inputs(ctx, scan)
    assert reach_axis(inputs.scope, "pkg:maven/a/b@1") == "likely"
    assert reach_axis(inputs.scope, "pkg:npm/left-pad@1.0.0") == "not_assessed"
    # dosai did not complete for a java scan, so exposure stays unassessed.
    assert inputs.dosai_ran is False
    npm = inputs.evidence_for("pkg:npm/left-pad@1.0.0")
    assert npm.dosai is None


def test_collect_exploitability_prefers_the_assessment_that_reached():
    from analysis_lib.findings.model import Exploitability, ExploitabilityAxes

    ctx = SimpleNamespace(exploitability={})
    blind = Exploitability(
        axes=ExploitabilityAxes("likely", "not_assessed", "not_assessed", "not_assessed")
    )
    seeing = Exploitability(
        axes=ExploitabilityAxes("likely", "likely", "not_assessed", "not_assessed")
    )
    pipeline._collect_exploitability(
        ctx, SimpleNamespace(exploitability={("CVE-1", "pkg:npm/a@1"): blind})
    )
    pipeline._collect_exploitability(
        ctx, SimpleNamespace(exploitability={("CVE-1", "pkg:npm/a@1"): seeing})
    )
    assert ctx.exploitability[("CVE-1", "pkg:npm/a@1")] is seeing
    # An assessed reach is never replaced by an unassessed one.
    pipeline._collect_exploitability(
        ctx, SimpleNamespace(exploitability={("CVE-1", "pkg:npm/a@1"): blind})
    )
    assert ctx.exploitability[("CVE-1", "pkg:npm/a@1")] is seeing
    # With reach equal, the assessment with more assessed axes wins: the
    # .NET type that ran dosai over a universal type that could not.
    exposed = Exploitability(axes=ExploitabilityAxes("likely", "likely", "likely", "unlikely"))
    pipeline._collect_exploitability(
        ctx, SimpleNamespace(exploitability={("CVE-1", "pkg:npm/a@1"): exposed})
    )
    assert ctx.exploitability[("CVE-1", "pkg:npm/a@1")] is exposed


@pytest.mark.parametrize("bom_dir_scan", [False, True])
def test_setup_clears_tool_outputs_only_for_a_source_scan(tmp_path, bom_dir_scan):
    """A source scan's reports directory holds what dep-scan wrote, and an
    earlier run's tool slices there would read as this run's evidence. A BOM
    directory the user hands in is an input and keeps its files."""
    src = tmp_path / "src"
    src.mkdir()
    reports = tmp_path / "reports"
    reports.mkdir()
    stale = reports / "dotnet-reachables.slices.json"
    stale.write_text("[]")
    if bom_dir_scan:
        argv = ["--bom-dir", str(reports), "--reports-dir", str(reports)]
    else:
        argv = ["--src", str(src), "--reports-dir", str(reports)]
    ctx = pipeline.build_context(_args(argv))
    pipeline.stage_setup(ctx)
    assert stale.exists() is bom_dir_scan


def test_a_source_scan_takes_the_atom_version_from_the_doctor(tmp_path, monkeypatch):
    """A scan that ran cdxgen had the local atom write its slices, so the
    doctor's atom version is the producer; a BOM scan reads the BOM's."""
    monkeypatch.setattr(pipeline, "_doctor_analyzer_version", lambda analyzer, ctx: "4.0.3")
    bom = tmp_path / "sbom-python.cdx.json"
    bom.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "metadata": {"tools": {"components": [{"name": "atom", "version": "4.0.1"}]}},
            }
        )
    )
    options = SimpleNamespace(bom_files=[str(bom)])
    source_scan = SimpleNamespace(args=SimpleNamespace(bom=None, bom_dir=None))
    assert pipeline._atom_producer_version(source_scan, options) == "4.0.3"
    bom_scan = SimpleNamespace(args=SimpleNamespace(bom=None, bom_dir=str(tmp_path)))
    assert pipeline._atom_producer_version(bom_scan, options) == "4.0.1"
    assert pipeline._atom_producer_version(bom_scan, SimpleNamespace(bom_files=[])) == ""


def test_the_source_root_of_a_stored_scan_is_only_an_explicit_src(tmp_path, monkeypatch):
    monkeypatch.delenv("DEPSCAN_SOURCE_DIR_IMAGE", raising=False)
    monkeypatch.chdir(tmp_path)
    source = str(tmp_path / "project")
    assert (
        pipeline._source_root(
            SimpleNamespace(bom=None, bom_dir=None, src_dir_image=source), source
        )
        == source
    )
    stored = SimpleNamespace(bom=None, bom_dir="boms", src_dir_image=str(tmp_path))
    assert pipeline._source_root(stored, str(tmp_path)) is None, "the working directory default"
    stored.src_dir_image = source
    assert pipeline._source_root(stored, source) == source, "an explicit --src"
