"""Unit tests for the pipeline stages, one stage per test.

Each test builds a small scan context and runs a single stage. The expensive
collaborators (the database, the vulnerability search, the cdx-audit supply-chain
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
from depscan.lib import cdx_audit, pipeline, vdb_setup
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


def test_stage_setup_makes_a_relative_reports_dir_absolute(tmp_path, monkeypatch):
    """A relative --reports-dir must not ride into the cdxgen argument list.

    dep-scan resolves it against its own working directory, cdxgen against
    the directory it analyses, so a relative value put the BOM inside the
    scanned tree, and with --fail-on-error the scan aborted because the BOM
    was not where dep-scan looked. The setup stage makes the directory
    absolute, which is also what the JSON contract requires of scanDir.
    """
    monkeypatch.chdir(tmp_path)
    args = _args(["--reports-dir", "reports", "--no-banner"])
    ctx = pipeline.build_context(args)
    pipeline.stage_setup(ctx)
    assert ctx.reports_dir == str(tmp_path / "reports")
    assert os.path.isabs(ctx.reports_dir)


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
# analysis: license and supply-chain audit
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
    rows = json.loads(license_report.read_text())
    assert rows[0]["Package"] == "demo"
    assert rows[0]["Version"] == "1.0.0"
    assert "CC-BY-NC-4.0" in rows[0]["License Id"]


def test_stage_analysis_licenses_writes_the_report_when_nothing_matched(tmp_path, monkeypatch):
    """A license scan that matched nothing still writes its report.

    The report file is the mark of a scan that ran: it is written with no
    rows when every license was clean, and when no package carried license
    data at all. The packages without any license data are counted on the
    scan instead of vanishing, so the manifest's licenses stage can say how
    much of the list was never assessed.
    """
    monkeypatch.setenv("FETCH_LICENSE", "true")
    ctx = _ctx(tmp_path, ["-t", "npm"])
    scan = pipeline.TypeScan(project_type="npm")
    scan.pkg_list = [
        # MIT is a known, condition-free license, so it earns no row.
        {"name": "clean", "version": "1.0.0", "purl": "pkg:npm/clean@1.0.0", "licenses": ["MIT"]},
        {"name": "bare", "version": "2.0.0", "purl": "pkg:npm/bare@2.0.0"},
    ]
    assert pipeline.stage_analysis_licenses(ctx, scan) is True
    license_report = Path(ctx.reports_dir) / "license-npm.json"
    assert license_report.is_file(), "an assessed-clean license scan writes its report"
    assert json.loads(license_report.read_text()) == []
    assert scan.license_not_assessed == (
        "1 of 2 packages carry no license data at all; their licenses were not assessed"
    )
    # No package carrying license data at all is the same honest shape.
    bare = pipeline.TypeScan(project_type="npm")
    bare.pkg_list = [{"name": "bare", "version": "2.0.0", "purl": "pkg:npm/bare@2.0.0"}]
    assert pipeline.stage_analysis_licenses(ctx, bare) is True
    assert (Path(ctx.reports_dir) / "license-npm.json").read_text().strip() == "[]"
    assert bare.license_not_assessed == (
        "1 of 1 packages carry no license data at all; their licenses were not assessed"
    )


#: npm components for a BOM the predictive audit has targets in.
_NPM_COMPONENTS = [
    {
        "name": "left-pad",
        "version": "1.3.0",
        "purl": "pkg:npm/left-pad@1.3.0",
        "bom-ref": "pkg:npm/left-pad@1.3.0",
        "type": "library",
    }
]


def _audit_stub(monkeypatch, reports=None, fail=None):
    """Stub cdx-audit for the risk stage. ``reports`` maps a run kind
    (``direct`` or ``predictive``) to the report it writes, the direct
    fixture by default; ``fail`` maps a run kind to the CdxAuditError text
    that run raises. Returns the list of argument lists the stage ran."""
    runs = []
    direct = json.loads((DATA_DIR / "cdx-audit" / "direct-report.json").read_text())
    predictive = json.loads((DATA_DIR / "cdx-audit" / "predictive-report.json").read_text())
    chosen = {"direct": direct, "predictive": predictive, **(reports or {})}

    def fake_run(cmd, args):
        runs.append(list(args))
        kind = "direct" if "--direct-bom-audit" in args else "predictive"
        if fail and kind in fail:
            raise cdx_audit.CdxAuditError(fail[kind])
        report = chosen[kind]
        Path(args[args.index("--report-file") + 1]).write_text(json.dumps(report))
        return cdx_audit.CdxAuditResult(
            report=report, report_version=report.get("version"), results=report.get("results")
        )

    monkeypatch.setattr(cdx_audit, "find_cdx_audit_cmd", lambda: "cdx-audit-fake")
    monkeypatch.setattr(cdx_audit, "cdx_audit_version", lambda cmd: "13.10.0")
    monkeypatch.setattr(cdx_audit, "run_cdx_audit", fake_run)
    return runs


def test_stage_analysis_risk_runs_cdx_audit_on_the_type_bom(tmp_path, monkeypatch):
    """The direct audit runs on the BOM the type scan nominated, with the
    categories that fit the scan and the namespaces the user passed, and
    the records it produced land in the scan's adapter results for the
    evidence store."""
    captured = {}
    real_report = json.loads((DATA_DIR / "cdx-audit" / "direct-report.json").read_text())

    def fake_run(cmd, args):
        captured["cmd"] = cmd
        captured["args"] = args
        report_file = args[args.index("--report-file") + 1]
        Path(report_file).write_text(json.dumps(real_report))
        return cdx_audit.CdxAuditResult(
            report=real_report,
            report_version=real_report["version"],
            findings_count=real_report["summary"]["totalFindings"],
            results=real_report["results"],
        )

    monkeypatch.setattr(cdx_audit, "find_cdx_audit_cmd", lambda: "cdx-audit-fake")
    monkeypatch.setattr(cdx_audit, "cdx_audit_version", lambda cmd: "13.10.0")
    monkeypatch.setattr(cdx_audit, "run_cdx_audit", fake_run)
    ctx = _ctx(tmp_path, ["-t", "npm"])
    ctx.perform_risk_audit = True
    ctx.args.private_ns = "@mycorp"
    scan = pipeline.TypeScan(project_type="npm")
    bom = Path(ctx.reports_dir) / "sbom-npm.cdx.json"
    bom.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6"}))
    scan.nominated_bom_file = str(bom)

    assert pipeline.stage_analysis_risk(ctx, scan) is True
    assert captured["cmd"] == "cdx-audit-fake"
    args = captured["args"]
    assert "--direct-bom-audit" in args
    assert args[args.index("--categories") + 1] == "package-integrity,dependency-source"
    assert args[args.index("--private-namespace") + 1] == "@mycorp"
    # Online, the direct audit looks the packages up in their registries
    # first, so its registry rules have something to read.
    assert "--fetch-registry-metadata" in args
    assert "--offline" not in args
    assert scan.risk_error is None
    assert scan.risk_not_assessed is None
    # Six cdx-audit findings; left-pad sits in two lockfiles, so dep-scan
    # writes eight findings, and that is the count the stage states.
    assert scan.audit_findings_count == 8
    assert scan.audit_caveats == []
    result = scan.adapter_results["cdx-audit"]
    assert result.status == "completed"
    assert len(result.records) == 8
    assert {record.producer.name for record in result.records} == {"cdx-audit"}


def test_stage_analysis_risk_is_offline_and_predictive_by_profile(tmp_path, monkeypatch):
    """The offline profile runs the direct audit with --offline and never a
    predictive one; the deep profile runs both, with the predictive audit
    bounded to the required scope, a target cap and a time budget."""
    runs = []
    real_report = json.loads((DATA_DIR / "cdx-audit" / "direct-report.json").read_text())

    def fake_run(cmd, args):
        runs.append(args)
        report_file = args[args.index("--report-file") + 1]
        Path(report_file).write_text(json.dumps(real_report))
        return cdx_audit.CdxAuditResult(
            report=real_report,
            report_version=real_report["version"],
            findings_count=real_report["summary"]["totalFindings"],
            results=real_report["results"],
        )

    monkeypatch.setattr(cdx_audit, "find_cdx_audit_cmd", lambda: "cdx-audit-fake")
    monkeypatch.setattr(cdx_audit, "cdx_audit_version", lambda cmd: "13.10.0")
    monkeypatch.setattr(cdx_audit, "run_cdx_audit", fake_run)
    ctx = _ctx(tmp_path, ["-t", "npm"])
    ctx.perform_risk_audit = True
    ctx.depscan_options["scan_profile"] = "offline"
    scan = pipeline.TypeScan(project_type="npm")
    bom = Path(ctx.reports_dir) / "sbom-npm.cdx.json"
    _write_bom(bom, _NPM_COMPONENTS)
    scan.nominated_bom_file = str(bom)

    assert pipeline.stage_analysis_risk(ctx, scan) is True
    assert len(runs) == 1
    assert "--offline" in runs[0]
    assert "--direct-bom-audit" in runs[0]
    assert "--fetch-registry-metadata" not in runs[0], (
        "an offline scan asks cdx-audit for no registry lookup"
    )

    runs.clear()
    ctx = _ctx(tmp_path, ["-t", "npm"])
    ctx.perform_risk_audit = True
    ctx.depscan_options["scan_profile"] = "deep"
    scan = pipeline.TypeScan(project_type="npm")
    scan.nominated_bom_file = str(bom)
    assert pipeline.stage_analysis_risk(ctx, scan) is True
    assert len(runs) == 2
    predictive_args = runs[1]
    assert "--direct-bom-audit" not in predictive_args
    assert predictive_args[predictive_args.index("--scope") + 1] == "required"
    assert "--max-targets" in predictive_args
    assert "--time-budget-minutes" in predictive_args
    assert "--offline" not in predictive_args
    assert "--fetch-registry-metadata" not in predictive_args
    assert "--fetch-registry-metadata" in runs[0]


def test_stage_analysis_risk_names_why_it_could_not_run(tmp_path, monkeypatch):
    """A missing cdx-audit and a scan with no BOM to audit each record why
    the requested audit did not run, and the audit off stays a plain skip.

    Positive control for the run path: the same scan with the audit
    available runs instead of recording a reason.
    """
    monkeypatch.setattr(cdx_audit, "find_cdx_audit_cmd", lambda: None)
    ctx = _ctx(tmp_path, ["-t", "universal"])
    scan = pipeline.TypeScan(project_type="universal")
    scan.pkg_list = [{"name": "guava", "version": "1.0", "purl": "pkg:maven/com.google/guava@1.0"}]
    ctx.perform_risk_audit = False
    assert pipeline.stage_analysis_risk(ctx, scan) is False
    assert scan.risk_not_assessed is None
    ctx.perform_risk_audit = True
    assert pipeline.stage_analysis_risk(ctx, scan) is False
    reason = scan.risk_not_assessed or ""
    assert "cdx-audit was not found" in reason

    monkeypatch.setattr(cdx_audit, "find_cdx_audit_cmd", lambda: "cdx-audit-fake")
    monkeypatch.setattr(cdx_audit, "cdx_audit_version", lambda cmd: "13.10.0")
    assert pipeline.stage_analysis_risk(ctx, scan) is False
    reason = scan.risk_not_assessed or ""
    assert "produced no BOM" in reason
    assert "universal" in reason


def test_stage_analysis_risk_records_the_audits_coverage_gaps_in_order(
    tmp_path, monkeypatch
):
    """What the audit could not assess is kept, once each and in the order
    the reports stated it, for the manifest's risk stage.

    Positive control: a report without a gap leaves the list empty.
    """
    reports = []

    def fake_run(cmd, args):
        report_file = args[args.index("--report-file") + 1]
        report = json.loads((DATA_DIR / "cdx-audit" / "direct-report.json").read_text())
        if len(reports) == 1:
            report["summary"]["targetCapTruncated"] = 6
            report["results"][0]["coverage"] = {
                "registryMetadata": "fetched",
                "components": 44,
                "eligible": 40,
                "answered": 37,
                "withoutMetadata": 3,
            }
        Path(report_file).write_text(json.dumps(report))
        reports.append(report)
        return cdx_audit.CdxAuditResult(
            report=report,
            report_version=report["version"],
            findings_count=2,
            results=report["results"],
        )

    monkeypatch.setattr(cdx_audit, "find_cdx_audit_cmd", lambda: "cdx-audit-fake")
    monkeypatch.setattr(cdx_audit, "cdx_audit_version", lambda cmd: "13.10.0")
    monkeypatch.setattr(cdx_audit, "run_cdx_audit", fake_run)
    ctx = _ctx(tmp_path, ["-t", "npm"])
    ctx.perform_risk_audit = True
    scan = pipeline.TypeScan(project_type="npm")
    bom = Path(ctx.reports_dir) / "sbom-npm.cdx.json"
    bom.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6"}))
    scan.nominated_bom_file = str(bom)

    assert pipeline.stage_analysis_risk(ctx, scan) is True
    assert scan.audit_caveats == []

    assert pipeline.stage_analysis_risk(ctx, scan) is True
    assert len(scan.audit_caveats) == 2, "each gap once"
    assert scan.audit_caveats[0].startswith("the audit's target cap left 6 target(s) unanalyzed")
    assert scan.audit_caveats[1].startswith(
        "3 of 40 npm, PyPI or Cargo component(s) carry no registry metadata"
    ), "in the order the report stated them"


def test_stage_analysis_risk_fails_when_the_report_cannot_be_read(tmp_path, monkeypatch):
    """A report whose shape the adapter cannot read is a failed audit with
    the reason, never a completed audit that happened to find nothing."""

    def fake_run(cmd, args):
        report_file = args[args.index("--report-file") + 1]
        report = json.loads((DATA_DIR / "cdx-audit" / "direct-report.json").read_text())
        report["version"] = "9.0"
        Path(report_file).write_text(json.dumps(report))
        return cdx_audit.CdxAuditResult(report=report, report_version="9.0")

    monkeypatch.setattr(cdx_audit, "find_cdx_audit_cmd", lambda: "cdx-audit-fake")
    monkeypatch.setattr(cdx_audit, "cdx_audit_version", lambda cmd: "13.10.0")
    monkeypatch.setattr(cdx_audit, "run_cdx_audit", fake_run)
    ctx = _ctx(tmp_path, ["-t", "npm"])
    ctx.perform_risk_audit = True
    scan = pipeline.TypeScan(project_type="npm")
    scan.nominated_bom_file = _write_bom(Path(ctx.reports_dir) / "sbom-npm.cdx.json")

    assert pipeline.stage_analysis_risk(ctx, scan) is True
    assert scan.risk_error is not None
    assert "not supported" in scan.risk_error
    assert "cdx-audit" not in scan.adapter_results


def test_a_failed_predictive_run_keeps_the_direct_audit(tmp_path, monkeypatch, caplog):
    """The predictive audit adds upstream findings to a direct audit that
    already completed; when it fails, the direct findings and report stay,
    the stage is not failed, and the failure is a coverage caveat with the
    machine's paths taken out."""
    reports_dir = tmp_path / "reports"
    runs = _audit_stub(
        monkeypatch,
        fail={"predictive": f"cdx-audit exited with 1; its output ends: ENOENT {reports_dir}/x"},
    )
    ctx = _ctx(tmp_path, ["-t", "npm"])
    ctx.perform_risk_audit = True
    ctx.depscan_options["scan_profile"] = "deep"
    scan = pipeline.TypeScan(project_type="npm")
    scan.nominated_bom_file = _write_bom(Path(ctx.reports_dir) / "sbom-npm.cdx.json", _NPM_COMPONENTS)

    with caplog.at_level("INFO", logger=pipeline.LOG.name):
        assert pipeline.stage_analysis_risk(ctx, scan) is True
    assert len(runs) == 2, "the predictive run was attempted"
    assert scan.risk_error is None
    assert len(scan.adapter_results["cdx-audit"].records) == 8
    assert [os.path.basename(path) for path in scan.audit_output_files] == ["cdx-audit-npm.json"]
    gap = [detail for detail in scan.audit_caveats if "predictive audit" in detail]
    assert len(gap) == 1
    assert str(reports_dir) not in gap[0]
    assert not any(record.levelname == "ERROR" for record in caplog.records)
    warnings = [record for record in caplog.records if record.levelname == "WARNING"]
    assert len(warnings) == 1


def test_the_predictive_audit_skips_a_bom_without_npm_pypi_or_cargo(tmp_path, monkeypatch):
    """A BOM whose packages are all of ecosystems the predictive audit does
    not select from gets the direct audit only. Positive control: the same
    profile over an npm BOM runs both."""
    runs = _audit_stub(monkeypatch)
    ctx = _ctx(tmp_path, ["-t", "java"])
    ctx.perform_risk_audit = True
    ctx.depscan_options["scan_profile"] = "deep"
    scan = pipeline.TypeScan(project_type="java")
    maven = [{"name": "guava", "version": "1.0", "purl": "pkg:maven/g/guava@1.0", "type": "library"}]
    scan.nominated_bom_file = _write_bom(Path(ctx.reports_dir) / "sbom-java.cdx.json", maven)
    assert pipeline.stage_analysis_risk(ctx, scan) is True
    assert len(runs) == 1 and "--direct-bom-audit" in runs[0]

    runs.clear()
    scan = pipeline.TypeScan(project_type="npm")
    scan.nominated_bom_file = _write_bom(Path(ctx.reports_dir) / "sbom-npm.cdx.json", _NPM_COMPONENTS)
    assert pipeline.stage_analysis_risk(ctx, scan) is True
    assert len(runs) == 2


def test_every_bom_of_a_bom_directory_is_audited_and_reports_are_not_input(tmp_path, monkeypatch):
    """A BOM directory scan audits each BOM in it, with one report per BOM,
    and a second scan of the same directory never reads those reports (or
    the purl scan's input) back as BOMs: cdx-audit-bom.json matches
    *bom*.json."""
    from analysis_lib import get_all_bom_files

    runs = _audit_stub(monkeypatch)
    bom_dir = tmp_path / "boms"
    bom_dir.mkdir()
    _write_bom(bom_dir / "sbom-java.cdx.json")
    _write_bom(bom_dir / "sbom-js.cdx.json", _NPM_COMPONENTS)
    for attempt in (1, 2):
        runs.clear()
        ctx = _ctx(tmp_path, ["--bom-dir", str(bom_dir), "--reports-dir", str(bom_dir)])
        ctx.perform_risk_audit = True
        scan = pipeline.TypeScan(project_type="bom")
        scan.bom_files = get_all_bom_files(str(bom_dir))
        assert pipeline.stage_analysis_risk(ctx, scan) is True
        audited = sorted(os.path.basename(run[run.index("--bom") + 1]) for run in runs)
        assert audited == ["sbom-java.cdx.json", "sbom-js.cdx.json"], f"run {attempt}"
        written = sorted(os.path.basename(path) for path in scan.audit_output_files)
        assert written == ["cdx-audit-bom-sbom-java.json", "cdx-audit-bom-sbom-js.json"]
    (bom_dir / "cdx-audit-bom.json").write_text("{}")
    (bom_dir / "cdx-audit-input-purl.json").write_text("{}")
    assert sorted(os.path.basename(p) for p in get_all_bom_files(str(bom_dir))) == [
        "sbom-java.cdx.json",
        "sbom-js.cdx.json",
    ]


def test_a_bom_directory_audits_only_cyclonedx_documents(tmp_path, monkeypatch):
    """cdxgen writes sbom-<type>.cdx.json.introspection.json beside each BOM,
    which the *bom*.json glob matches; it is no BOM, so it is skipped
    quietly instead of failing the audit."""
    from analysis_lib import get_all_bom_files

    runs = _audit_stub(monkeypatch)
    bom_dir = tmp_path / "boms"
    bom_dir.mkdir()
    _write_bom(bom_dir / "sbom-js.cdx.json", _NPM_COMPONENTS)
    (bom_dir / "sbom-js.cdx.json.introspection.json").write_text(json.dumps({"tiers": {}}))
    ctx = _ctx(tmp_path, ["--bom-dir", str(bom_dir), "--reports-dir", str(bom_dir)])
    ctx.perform_risk_audit = True
    scan = pipeline.TypeScan(project_type="bom")
    scan.bom_files = get_all_bom_files(str(bom_dir))
    assert len(scan.bom_files) == 2, "the glob matches the introspection report"
    assert pipeline.stage_analysis_risk(ctx, scan) is True
    assert scan.risk_error is None
    assert [os.path.basename(run[run.index("--bom") + 1]) for run in runs] == ["sbom-js.cdx.json"]


def test_reports_of_same_named_boms_never_overwrite_each_other(tmp_path, monkeypatch):
    """Two bom.json in different subdirectories, and bom.json beside
    bom.cdx.json, each get their own report name, the same on a rescan."""
    runs = _audit_stub(monkeypatch)
    bom_dir = tmp_path / "boms"
    (bom_dir / "a").mkdir(parents=True)
    (bom_dir / "b").mkdir()
    paths = [
        _write_bom(bom_dir / "a" / "bom.json"),
        _write_bom(bom_dir / "b" / "bom.json"),
        _write_bom(bom_dir / "a" / "bom.cdx.json"),
        _write_bom(bom_dir / "a_bom.json"),
    ]
    names = []
    for _ in (1, 2):
        ctx = _ctx(tmp_path, ["--bom-dir", str(bom_dir)])
        ctx.perform_risk_audit = True
        scan = pipeline.TypeScan(project_type="bom")
        scan.bom_files = list(paths)
        assert pipeline.stage_analysis_risk(ctx, scan) is True
        names.append(sorted(os.path.basename(path) for path in scan.audit_output_files))
    assert len(set(names[0])) == 4, names[0]
    assert names[0] == names[1], "the names are stable across scans"
    assert "cdx-audit-bom-b_bom.json" in names[0]
    assert not any(name.endswith(".cdx.json") for name in names[0]), (
        "a report named *.cdx.json would be read as a BOM by every *.cdx.json glob"
    )
    assert len(runs) == 8


def test_a_lifecycle_run_audits_only_its_own_type_boms(tmp_path, monkeypatch):
    """Lifecycle mode widens bom_files to every BOM in the reports
    directory, other types' included; the audit reads only the documents
    this type's generator wrote."""
    runs = _audit_stub(monkeypatch)
    ctx = _ctx(tmp_path, ["-t", "npm"])
    ctx.perform_risk_audit = True
    reports = Path(ctx.reports_dir)
    own = [_write_bom(reports / "sbom-npm-prebuild.cdx.json"), _write_bom(reports / "sbom-npm-build.cdx.json")]
    other = _write_bom(reports / "sbom-java-build.cdx.json")
    scan = pipeline.TypeScan(project_type="npm")
    scan.lifecycle_mode = True
    scan.generated_bom_files = list(own)
    scan.bom_files = sorted([*own, other])
    assert pipeline.stage_analysis_risk(ctx, scan) is True
    audited = sorted(run[run.index("--bom") + 1] for run in runs)
    assert audited == sorted(own)


@pytest.mark.parametrize(
    "project_type,root_type,purl,expected",
    [
        ("npm", "application", "pkg:npm/a@1", ("package-integrity", "dependency-source")),
        ("cargo", "application", "pkg:cargo/time@0.1.45", ("package-integrity", "dependency-source", "cargo-security")),
        ("docker", "application", "pkg:npm/a@1", pipeline.CONTAINER_AUDIT_CATEGORIES),
        ("podman", "application", "pkg:npm/a@1", pipeline.CONTAINER_AUDIT_CATEGORIES),
        ("rootfs", "application", "pkg:npm/a@1", pipeline.CONTAINER_AUDIT_CATEGORIES),
        ("oci-dir", "application", "pkg:npm/a@1", pipeline.CONTAINER_AUDIT_CATEGORIES),
        ("image", "application", "pkg:npm/a@1", pipeline.CONTAINER_AUDIT_CATEGORIES),
        ("bom", "container", "pkg:npm/a@1", pipeline.CONTAINER_AUDIT_CATEGORIES),
        ("bom", "container", "pkg:cargo/time@0.1.45", (*pipeline.CONTAINER_AUDIT_CATEGORIES, "cargo-security")),
    ],
)
def test_the_audit_categories_fit_the_bom(tmp_path, monkeypatch, project_type, root_type, purl, expected):
    """Every container alias cdxgen and dep-scan use, and a BOM whose root
    component is a container, add the image packs to the package packs; a
    BOM with Cargo crates adds the crate pack."""
    runs = _audit_stub(monkeypatch)
    ctx = _ctx(tmp_path, ["-t", project_type])
    ctx.perform_risk_audit = True
    scan = pipeline.TypeScan(project_type=project_type)
    bom = Path(ctx.reports_dir) / f"sbom-{project_type}.cdx.json"
    bom.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "metadata": {"component": {"name": "x", "type": root_type}},
                "components": [{"name": "c", "purl": purl, "type": "library"}],
            }
        )
    )
    scan.nominated_bom_file = str(bom)
    assert pipeline.stage_analysis_risk(ctx, scan) is True
    args = runs[0]
    assert tuple(args[args.index("--categories") + 1].split(",")) == tuple(expected)


def test_a_purl_scan_audits_a_document_no_bom_glob_reads(tmp_path, monkeypatch):
    """The purl scan's input document is recorded as an output of the stage
    and named so no BOM directory scan of the reports directory reads it."""
    from analysis_lib import get_all_bom_files

    runs = _audit_stub(monkeypatch)
    ctx = _ctx(tmp_path, ["--purl", "pkg:npm/left-pad@1.3.0"])
    ctx.perform_risk_audit = True
    scan = pipeline.TypeScan(project_type="npm")
    scan.pkg_list = [{"name": "left-pad", "version": "1.3.0", "purl": "pkg:npm/left-pad@1.3.0"}]
    assert pipeline.stage_analysis_risk(ctx, scan) is True
    audited = runs[0][runs[0].index("--bom") + 1]
    assert os.path.basename(audited) == "cdx-audit-input-npm.json"
    assert audited in scan.audit_output_files
    assert audited not in get_all_bom_files(ctx.reports_dir)


def test_the_stage_warns_once_and_keeps_caveats_off_the_console(tmp_path, monkeypatch, caplog):
    """A cdx-audit that cannot run is one warning for the whole scan, not
    one per type; a completed audit's caveats go to the debug log only, and
    a failed one is one error line."""
    monkeypatch.setattr(cdx_audit, "find_cdx_audit_cmd", lambda: None)
    ctx = _ctx(tmp_path, ["-t", "npm"])
    ctx.perform_risk_audit = True
    with caplog.at_level("INFO", logger=pipeline.LOG.name):
        for project_type in ("npm", "python"):
            scan = pipeline.TypeScan(project_type=project_type)
            scan.nominated_bom_file = _write_bom(Path(ctx.reports_dir) / f"sbom-{project_type}.json")
            assert pipeline.stage_analysis_risk(ctx, scan) is False
            assert scan.risk_not_assessed
    assert len([r for r in caplog.records if r.levelname == "WARNING"]) == 1

    caplog.clear()
    report = json.loads((DATA_DIR / "cdx-audit" / "direct-report.json").read_text())
    report["summary"]["targetCapTruncated"] = 3
    _audit_stub(monkeypatch, reports={"direct": report})
    scan = pipeline.TypeScan(project_type="npm")
    scan.nominated_bom_file = _write_bom(Path(ctx.reports_dir) / "sbom-npm.json")
    with caplog.at_level("DEBUG", logger=pipeline.LOG.name):
        assert pipeline.stage_analysis_risk(ctx, scan) is True
    caveat_lines = [r for r in caplog.records if "Audit coverage caveat" in r.getMessage()]
    assert caveat_lines and all(r.levelname == "DEBUG" for r in caveat_lines)

    caplog.clear()
    _audit_stub(monkeypatch, fail={"direct": "cdx-audit exited with 2; its output ends: boom"})
    with caplog.at_level("INFO", logger=pipeline.LOG.name):
        assert pipeline.stage_analysis_risk(ctx, scan) is True
    assert scan.risk_error and "exited with 2" in scan.risk_error
    assert len([r for r in caplog.records if r.levelname == "ERROR"]) == 1


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
    scan.bom_files = [str(Path(ctx.reports_dir) / "bom-evinse-java.json")]

    # The inventory stage runs cdxgen's adapter over the BOM; its occurrence
    # records are what the engine counts as direct purls.
    pipeline._collect_inventory_evidence(ctx, scan, write_store=False)
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
    assert {r.producer.name for r in records} == {"atom", "cdxgen"}
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
        cdxgen_reads={},
    )
    ctx = SimpleNamespace(doctor_report=None, grading_rules=load_rules(), usage_not_assessed={})
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


def test_stage_analysis_vdr_reports_no_vulnerabilities(tmp_path, capfd, caplog):
    """The clean result is a result line: it prints on stdout, where the
    results go, and is not a log record."""
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
    captured = capfd.readouterr()
    assert "No vulnerabilities found." in captured.out
    assert "No vulnerabilities found" not in captured.err
    assert not any("No vulnerabilities found" in r.message for r in caplog.records)


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
    records = [object()]
    usage_not_assessed = {"pkg:pypi/a@1": "the BOM was not assessed"}
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
        evidence_records=records,
        usage_not_assessed=usage_not_assessed,
        perform_risk_audit=False,
        # One produced result, so the findings file is written at all; a scan
        # whose every type failed writes none.
        scans=[object()],
        blint_review_ran=False,
    )
    pipeline.finish_scan_directory(ctx)
    assert captured["blint_reviews"] is expected
    assert captured["evidence_records"] is records, (
        "the findings file receives the scan's evidence records, the blint ones included"
    )
    assert captured["usage_not_assessed"] is usage_not_assessed


@pytest.mark.parametrize(
    "review_ran, written",
    [(False, False), (True, True)],
)
def test_a_scan_with_no_matched_type_writes_a_findings_file_only_for_a_review(
    monkeypatch, tmp_path, review_ran, written
):
    """cdxgen's own evidence records do not make an empty findings array
    mean anything: with no project type matched (an inventory that listed
    no packages) only a completed blint review, whose findings are
    findings, writes the file."""
    calls = []
    monkeypatch.setattr(
        pipeline.scan_directory,
        "write_findings",
        lambda *a, **k: calls.append(k) or {"findings": []},
    )
    monkeypatch.setattr(pipeline.scan_directory, "write_manifest", lambda *a, **k: None)
    ctx = SimpleNamespace(
        scan_dir=SimpleNamespace(build=lambda **k: {}),
        reports_dir=str(tmp_path),
        all_pkg_vulnerabilities=[],
        src_dir=str(tmp_path),
        exploitability={},
        depscan_options={},
        project_types=["universal"],
        vdb_flavor=None,
        shards_connected=False,
        evidence_records=[object()],
        usage_not_assessed={},
        perform_risk_audit=False,
        scans=[],
        blint_review_ran=review_ran,
    )
    pipeline.finish_scan_directory(ctx)
    assert bool(calls) is written


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
        cdxgen_reads={},
    )
    ctx = SimpleNamespace(doctor_report=None, grading_rules=load_rules(), usage_not_assessed={})

    def refuse_to_read(*args, **kwargs):
        raise AssertionError("the slices were parsed again")

    monkeypatch.setattr(reachability_module, "_iter_json_list", refuse_to_read)
    inputs = pipeline._exploitability_inputs(ctx, scan)
    assert inputs is not None and inputs.scope is not None
    assert inputs.scope.analyzers == ["atom"]
    assert reach_axis(inputs.scope, "pkg:maven/a/b@1") == "likely"


def test_findings_grade_reach_from_atom_usages_joined_to_the_declared_packages(tmp_path):
    """atom's usage slices name resolved methods and no purl. A finding on a
    package whose module a usage names, in a file cdxgen recorded the package
    in, grades reach as reached and names the usage as its witness, even when
    cdxgen filed the occurrences under an inferred version of the package; a
    package atom covers and never reached grades not observed."""
    from analysis_lib.evidence.adapters import atom as atom_adapter
    from analysis_lib.evidence.adapters import cdxgen as cdxgen_adapter
    from analysis_lib.findings.exploitability import exploitability_for, load_rules
    from analysis_lib.findings.vdr_convert import assess_reach, reach_axis

    def component(purl, name, identity, occurrences):
        return {
            "type": "library",
            "name": name,
            "purl": purl,
            "bom-ref": purl,
            "evidence": {"identity": identity, "occurrences": occurrences},
        }

    declared = [
        {
            "field": "purl",
            "methods": [{"technique": "manifest-analysis", "confidence": 0.5, "value": "r.txt"}],
        }
    ]
    inferred = [
        {
            "field": "version",
            "methods": [{"technique": "source-code-analysis", "confidence": 0.5, "value": "x"}],
        }
    ]
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            component(
                "pkg:pypi/flask@2.2.0", "Flask", declared, [{"location": "requirements.txt"}]
            ),
            component(
                "pkg:pypi/flask@3.1.3", "Flask", inferred, [{"location": "app.py", "line": 1}]
            ),
            component(
                "pkg:pypi/requests@2.31.0",
                "requests",
                declared,
                [{"location": "app.py", "line": 6}],
            ),
            component("pkg:pypi/idna@3.0", "idna", declared, [{"location": "requirements.txt"}]),
        ],
    }
    bom_file = tmp_path / "sbom-prebuild-universal.cdx.json"
    bom_file.write_text(json.dumps(bom))
    cdxgen_read = cdxgen_adapter.extract(
        bom_file.read_text(), source="sbom-prebuild-universal.cdx.json"
    )
    usages = tmp_path / "universal-usages.slices.json"

    def usage(line, method):
        target = {"name": "x", "resolvedMethod": method, "lineNumber": line, "label": "CALL"}
        return {
            "fullName": "app",
            "fileName": "app.py",
            "lineNumber": line,
            "usages": [{"targetObj": target, "definedBy": target}],
        }

    usages.write_text(
        json.dumps({"objectSlices": [usage(1, "flask.Flask.route"), usage(6, "requests.get")]})
    )
    atom = atom_adapter.extract([], usages_files=[str(usages)])
    assert atom.status == "completed"
    scan = SimpleNamespace(
        project_type="universal",
        reachability_succeeded=True,
        reached_purls={},
        adapter_results={"atom": atom, "cdxgen": cdxgen_read},
        pkg_list=[
            {"purl": "pkg:pypi/flask@2.2.0"},
            {"purl": "pkg:pypi/flask@3.1.3"},
            {"purl": "pkg:pypi/requests@2.31.0"},
            {"purl": "pkg:pypi/idna@3.0"},
        ],
        bom_dir=str(tmp_path),
        bom_files=[str(bom_file)],
        cdxgen_reads={"sbom-prebuild-universal.cdx.json": cdxgen_read},
    )
    ctx = SimpleNamespace(doctor_report=None, grading_rules=load_rules(), usage_not_assessed={})
    scan.adapter_results["atom"] = pipeline._attribute_atom_result(scan, atom)
    attributed = [r for r in scan.adapter_results["atom"].records if r not in atom.records]
    assert sorted(r.subject.purls[0] for r in attributed) == [
        "pkg:pypi/flask@2.2.0",
        "pkg:pypi/requests@2.31.0",
    ]
    assert all(r.producer.name == "atom" and r.path for r in attributed)
    assert all(r.caveats[-1].kind == "attributed" for r in attributed)
    assert not {r.id for r in attributed} & {r.id for r in atom.records}
    # The ids are the same on every scan of the same input.
    again = pipeline._attribute_atom_result(scan, atom)
    assert sorted(r.id for r in again.records) == sorted(
        r.id for r in scan.adapter_results["atom"].records
    )
    inputs = pipeline._exploitability_inputs(ctx, scan)
    assert inputs is not None and inputs.scope is not None
    assert inputs.scope.analyzers == ["atom"]
    assert reach_axis(inputs.scope, "pkg:pypi/flask@2.2.0") == "likely"
    assert reach_axis(inputs.scope, "pkg:pypi/requests@2.31.0") == "likely"
    assert assess_reach(inputs.scope, "pkg:pypi/idna@3.0") == ("unknown", ["atom"])
    for ref in ("pkg:pypi/flask@2.2.0", "pkg:pypi/requests@2.31.0"):
        graded = exploitability_for(inputs.evidence_for(ref), load_rules())
        assert graded.axes.reach == "likely"
        assert graded.witness in {r.id for r in attributed}, f"{ref} names no stored witness"


def test_every_witness_and_index_entry_of_a_research_scan_is_in_the_store():
    """The scan directory contract: each record id a finding or the index
    names exists in ``evidence.jsonl``. The directory is a real research scan
    whose findings cite atom usage records dep-scan attributed to packages."""
    data = Path(__file__).parent / "data" / "research-scan-store"
    stored = {
        json.loads(line)["id"]
        for line in (data / "evidence.jsonl").read_text().splitlines()
        if line.strip()
    }
    cited = set()

    def collect(node):
        if isinstance(node, dict):
            for value in node.values():
                collect(value)
        elif isinstance(node, list):
            for value in node:
                collect(value)
        elif isinstance(node, str) and node.startswith("ev-"):
            cited.add(node)

    collect(json.loads((data / "evidence.index.json").read_text()))
    findings = json.loads((data / "depscan.findings.json").read_text())["findings"]
    witnesses = {
        f["exploitability"]["witness"]
        for f in findings
        if (f.get("exploitability") or {}).get("witness")
    }
    # Positive controls: the scan cited witnesses and index entries, and some
    # stored record is one dep-scan attributed.
    assert witnesses and cited
    assert any(
        '"kind":"attributed"' in line
        for line in (data / "evidence.jsonl").read_text().splitlines()
    )
    assert witnesses <= stored
    assert cited <= stored


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
        cdxgen_reads={},
    )
    ctx = SimpleNamespace(doctor_report=None, grading_rules=load_rules(), usage_not_assessed={})
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
    type_scan = pipeline.TypeScan(project_type="python")
    assert pipeline._atom_producer_version(source_scan, type_scan, options) == "4.0.3"
    bom_scan = SimpleNamespace(args=SimpleNamespace(bom=None, bom_dir=str(tmp_path)))
    assert pipeline._atom_producer_version(bom_scan, type_scan, options) == "4.0.1"
    assert (
        pipeline._atom_producer_version(bom_scan, type_scan, SimpleNamespace(bom_files=[])) == ""
    )


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


def test_matching_not_assessed_counts_rows_that_named_no_component():
    from depscan import api

    tscan = SimpleNamespace(
        ungraded_usage_records=0, vdr_result=SimpleNamespace(rows_without_component=3)
    )
    assert api._matching_not_assessed(tscan) == [
        "3 vulnerability rows named no component and are not in the VDR or the findings"
    ]
    clean = SimpleNamespace(
        ungraded_usage_records=0, vdr_result=SimpleNamespace(rows_without_component=0)
    )
    assert api._matching_not_assessed(clean) == []
    assert (
        api._matching_not_assessed(SimpleNamespace(ungraded_usage_records=0, vdr_result=None))
        == []
    )


# ---------------------------------------------------------------------------
# console noise: one line for each gap the user can act on
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "argv,warns",
    [
        # The default profile on a purl or a source target never promised
        # atom's slices, so their absence is a debug line.
        (["--purl", "pkg:pypi/requests@2.31.0"], False),
        (["--src", "{src}"], False),
        # The research BOM profile asks for them on a source target only.
        (["--src", "{src}", "--profile", "research"], True),
        (["--purl", "pkg:pypi/requests@2.31.0", "--profile", "research"], False),
        # Semantic reachability asks for them on any target.
        (["--src", "{src}", "--reachability-analyzer", "SemanticReachability"], True),
        (
            [
                "--purl",
                "pkg:pypi/requests@2.31.0",
                "--reachability-analyzer",
                "SemanticReachability",
            ],
            True,
        ),
    ],
)
def test_missing_atom_slices_warn_only_when_the_scan_asked_for_them(tmp_path, caplog, argv, warns):
    src = tmp_path / "src"
    src.mkdir()
    args = _args([a.replace("{src}", str(src)) for a in argv])
    ctx = SimpleNamespace(args=args, atom_results={}, doctor_report=None, source_root=str(src))
    scan = pipeline.TypeScan(project_type="python")
    options = SimpleNamespace(slices_files=[], openapi_spec_files=[], bom_dir=str(tmp_path))
    with caplog.at_level("DEBUG", logger=pipeline.LOG.name):
        result = pipeline._atom_adapter_result(ctx, scan, options)
    # Positive control: atom was not assessed in every case, and the
    # manifest's status comes from this result either way.
    assert result.status == "not-assessed"
    lines = [r for r in caplog.records if "atom reachability was not assessed" in r.getMessage()]
    assert len(lines) == 1
    assert lines[0].levelname == ("WARNING" if warns else "DEBUG")
    assert "adapter" not in lines[0].getMessage()


@pytest.mark.parametrize(
    "failure_reason,expected",
    [
        (
            "cdxgen exited with status 3 while generating the project BOM, so no "
            "document was written. Rerun with --debug to see cdxgen's output.",
            "cdxgen exited with status 3",
        ),
        (None, "the BOM for the python type was not created"),
    ],
)
def test_a_failed_bom_gives_one_error_line(
    tmp_path, monkeypatch, caplog, failure_reason, expected
):
    """A failed BOM generation is one error line: the generator's reason and
    where to look next, with no second warning about the same BOM."""
    src = tmp_path / "src"
    src.mkdir()
    ctx = _ctx(tmp_path, ["--src", str(src)])
    monkeypatch.setattr(
        pipeline,
        "_generate_boms",
        lambda ctx, scan: BomResult(success=False, failure_reason=failure_reason),
    )
    scan = pipeline.TypeScan(project_type="python")
    with caplog.at_level("DEBUG", logger=pipeline.LOG.name):
        assert pipeline._produce_boms(ctx, scan) is False
    # Positive control: the reason reached the manifest's inventory error.
    assert expected in (scan.inventory_error or "")
    errors = [r.getMessage() for r in caplog.records if r.levelname == "ERROR"]
    assert len(errors) == 1, errors
    assert expected in errors[0]
    assert errors[0].count("--debug") == 1
    assert not [r for r in caplog.records if r.levelname == "WARNING"]
    assert "SCAN_DEBUG_MODE" not in caplog.text


def test_unreadable_cdxgen_documents_give_one_line(tmp_path, caplog):
    """Several BOM documents the cdxgen adapter refuses for the same reason
    are named in one warning, not one warning each."""
    names = ["a.cdx.json", "b.cdx.json", "c.cdx.json"]
    for name in names:
        (tmp_path / name).write_text("[1, 2]")
    good = _write_bom(tmp_path / "good.cdx.json")
    scan = pipeline.TypeScan(project_type="python")
    scan.bom_files = [str(tmp_path / name) for name in names] + [good]
    ctx = SimpleNamespace(reports_dir=str(tmp_path), source_root=str(tmp_path))
    with caplog.at_level("WARNING", logger=pipeline.LOG.name):
        result = pipeline._cdxgen_adapter_result(ctx, scan)
    # Positive control: every refused document was read and refused.
    refused = [r for r in scan.cdxgen_reads.values() if r.status != "completed"]
    assert len(refused) == 3
    assert result is not None
    lines = [r.getMessage() for r in caplog.records if "cdxgen evidence" in r.getMessage()]
    assert len(lines) == 1, lines
    assert "a.cdx.json, b.cdx.json, c.cdx.json" in lines[0]
    assert "good.cdx.json" not in lines[0]


@pytest.mark.parametrize("checks_requested,audits", [(False, True), (True, False)])
def test_a_purl_search_audits_only_when_no_checks_were_named(
    tmp_path, checks_requested, audits
):
    """A bare purl search turns the supply-chain audit on; a scan that named
    its checks or a profile runs exactly those."""
    ctx = _ctx(tmp_path, ["--purl", "pkg:npm/left-pad@1.3.0"])
    ctx.args.checks_requested = checks_requested
    ctx.perform_risk_audit = False
    pipeline.finalize_setup(ctx)
    assert ctx.perform_risk_audit is audits


def test_the_sample_config_leaves_the_resolved_profile_and_checks_out(tmp_path):
    """scan_profile and checks_requested ride on the internal namespace for
    the stages; a depscan.toml.sample read back must not turn them into
    settings, so they are never written."""
    path = tmp_path / "depscan.toml.sample"
    options = {"scan_profile": "deep", "checks_requested": True, "no_banner": True, "risk_audit": True}
    assert pipeline.write_config_file(options, str(path))
    text = path.read_text()
    assert "risk_audit" in text
    for internal in ("scan_profile", "checks_requested", "no_banner"):
        assert internal not in text


def test_a_bare_purl_search_does_not_warn_when_cdx_audit_is_missing(tmp_path, monkeypatch, caplog):
    """The audit a bare purl search turns on by itself is not something the
    user asked for: a missing cdx-audit records the reason and logs it at
    info. Positive control: the same scan that asked for the check warns."""
    monkeypatch.setattr(cdx_audit, "find_cdx_audit_cmd", lambda: None)
    for checks_requested, level in ((False, "INFO"), (True, "WARNING")):
        caplog.clear()
        ctx = _ctx(tmp_path, ["--purl", "pkg:npm/left-pad@1.3.0"])
        ctx.args.checks_requested = checks_requested
        ctx.perform_risk_audit = checks_requested
        pipeline.finalize_setup(ctx)
        scan = pipeline.TypeScan(project_type="npm")
        scan.pkg_list = [{"name": "left-pad", "version": "1.3.0", "purl": "pkg:npm/left-pad@1.3.0"}]
        with caplog.at_level("INFO", logger=pipeline.LOG.name):
            assert pipeline.stage_analysis_risk(ctx, scan) is False
        assert "cdx-audit was not found" in (scan.risk_not_assessed or "")
        lines = [r for r in caplog.records if "supply-chain audit cannot run" in r.getMessage()]
        assert [r.levelname for r in lines] == [level]


def test_a_failed_direct_run_does_not_stop_the_other_boms(tmp_path, monkeypatch):
    """A BOM whose direct audit fails marks the stage failed with that
    BOM's name, and the BOMs after it are still audited and keep their
    findings."""
    report = json.loads((DATA_DIR / "cdx-audit" / "direct-report.json").read_text())
    runs = []

    def fake_run(cmd, args):
        bom = args[args.index("--bom") + 1]
        runs.append(os.path.basename(bom))
        if os.path.basename(bom).startswith("a-"):
            raise cdx_audit.CdxAuditError("cdx-audit exited with 1; its output ends: boom")
        Path(args[args.index("--report-file") + 1]).write_text(json.dumps(report))
        return cdx_audit.CdxAuditResult(report=report, report_version=1, results=report["results"])

    monkeypatch.setattr(cdx_audit, "find_cdx_audit_cmd", lambda: "cdx-audit-fake")
    monkeypatch.setattr(cdx_audit, "cdx_audit_version", lambda cmd: "13.10.0")
    monkeypatch.setattr(cdx_audit, "run_cdx_audit", fake_run)
    bom_dir = tmp_path / "boms"
    bom_dir.mkdir()
    ctx = _ctx(tmp_path, ["--bom-dir", str(bom_dir)])
    ctx.perform_risk_audit = True
    scan = pipeline.TypeScan(project_type="bom")
    scan.bom_files = [_write_bom(bom_dir / "a-bad.cdx.json"), _write_bom(bom_dir / "b-good.cdx.json")]
    assert pipeline.stage_analysis_risk(ctx, scan) is True
    assert runs == ["a-bad.cdx.json", "b-good.cdx.json"]
    assert scan.risk_error and "a-bad.cdx.json" in scan.risk_error
    assert len(scan.adapter_results["cdx-audit"].records) == 8


def test_the_predictive_audit_runs_once_per_type_over_all_its_boms(tmp_path, monkeypatch):
    """A lifecycle scan's per-stage BOMs name the same dependencies, so the
    predictive audit runs once for the type over all of them through
    --bom-dir, with the whole cap and budget, and each upstream target is
    cloned once; the direct audit still runs once per BOM. Positive
    control: a type with one BOM passes it with --bom."""
    seen = {}

    def fake_run(cmd, args):
        report = direct if "--direct-bom-audit" in args else predictive
        if "--bom-dir" in args:
            directory = args[args.index("--bom-dir") + 1]
            seen["inputs"] = sorted(os.listdir(directory))
        runs.append(list(args))
        Path(args[args.index("--report-file") + 1]).write_text(json.dumps(report))
        return cdx_audit.CdxAuditResult(report=report, report_version=1, results=report["results"])

    direct = json.loads((DATA_DIR / "cdx-audit" / "direct-report.json").read_text())
    predictive = json.loads((DATA_DIR / "cdx-audit" / "predictive-report.json").read_text())
    runs = []
    monkeypatch.setattr(cdx_audit, "find_cdx_audit_cmd", lambda: "cdx-audit-fake")
    monkeypatch.setattr(cdx_audit, "cdx_audit_version", lambda cmd: "13.10.0")
    monkeypatch.setattr(cdx_audit, "run_cdx_audit", fake_run)
    ctx = _ctx(tmp_path, ["-t", "npm"])
    ctx.perform_risk_audit = True
    ctx.depscan_options["scan_profile"] = "deep"
    reports = Path(ctx.reports_dir)
    scan = pipeline.TypeScan(project_type="npm")
    scan.lifecycle_mode = True
    scan.generated_bom_files = [
        _write_bom(reports / f"sbom-{stage}-npm.cdx.json", _NPM_COMPONENTS)
        for stage in ("prebuild", "build", "postbuild")
    ]
    scan.bom_files = list(scan.generated_bom_files)
    assert pipeline.stage_analysis_risk(ctx, scan) is True
    predictive_runs = [run for run in runs if "--direct-bom-audit" not in run]
    assert len(predictive_runs) == 1
    run = predictive_runs[0]
    assert "--bom" not in run
    assert seen["inputs"] == ["bom-0.json", "bom-1.json", "bom-2.json"]
    assert run[run.index("--max-targets") + 1] == str(pipeline.PREDICTIVE_MAX_TARGETS)
    assert run[run.index("--time-budget-minutes") + 1] == str(
        pipeline.PREDICTIVE_TIME_BUDGET_MINUTES
    )
    assert len([run for run in runs if "--direct-bom-audit" in run]) == 3
    predictive_reports = [
        name
        for name in (os.path.basename(path) for path in scan.audit_output_files)
        if name.startswith("cdx-audit-predictive-")
    ]
    assert predictive_reports == ["cdx-audit-predictive-npm.json"]
    assert not any(name.startswith("depscan-predictive-") for name in os.listdir(reports))

    runs.clear()
    single = pipeline.TypeScan(project_type="npm")
    single.nominated_bom_file = scan.generated_bom_files[0]
    assert pipeline.stage_analysis_risk(ctx, single) is True
    predictive_runs = [run for run in runs if "--direct-bom-audit" not in run]
    assert len(predictive_runs) == 1 and "--bom" in predictive_runs[0]
