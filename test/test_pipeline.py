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


# ---------------------------------------------------------------------------
# enrichment
# ---------------------------------------------------------------------------


def test_stage_enrichment_runs_reachability_on_the_evidence_fixtures(tmp_path):
    """SemanticReachability over the evinse BOM and the reachables slices:
    the direct purls come from the BOM's occurrences evidence and the reached
    purls from the slices file."""
    ctx = _ctx(
        tmp_path,
        ["--reachability-analyzer", "SemanticReachability", "-t", "java"],
    )
    for name in ("bom-evinse-java.json", "reachables.slices.json"):
        shutil.copy2(DATA_DIR / name, Path(ctx.reports_dir) / name)
    scan = pipeline.TypeScan(project_type="java")
    scan.bom_dir = str(ctx.reports_dir)

    pipeline.stage_enrichment(ctx, scan)

    assert scan.reachability_analyzer == "SemanticReachability"
    assert scan.reachability_options is not None
    assert scan.direct_purls, "the BOM's occurrences evidence must produce direct purls"
    assert scan.reached_purls, "the reachables slices must produce reached purls"
    assert all(purl.startswith("pkg:") for purl in scan.reached_purls)


def test_stage_enrichment_is_a_no_op_with_reachability_off(tmp_path):
    ctx = _ctx(tmp_path, ["-t", "npm", "--reachability-analyzer", "off"])
    ctx.depscan_options["reachability_analyzer"] = "off"
    ctx.depscan_options["profile"] = "generic"
    scan = pipeline.TypeScan(project_type="npm")
    scan.bom_dir = str(ctx.reports_dir)
    pipeline.stage_enrichment(ctx, scan)
    assert scan.reachability_options is None
    # Null reachability succeeds with empty maps, so nothing was reached.
    assert not scan.reached_purls


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


def _redirect_ctx(tmp_path, reports_inside):
    """A context whose src is a project and whose reports dir is set up.

    ``reports_inside`` puts the reports directory under the project, which is
    what the CLI default ``<cwd>/reports`` produces when depscan runs from the
    project it scans.
    """
    src = tmp_path / "proj"
    src.mkdir()
    reports = src / "reports" if reports_inside else tmp_path / "elsewhere"
    reports.mkdir(parents=True)
    args = _args(["--reports-dir", str(reports), "--no-banner"])
    ctx = pipeline.build_context(args)
    ctx.src_dir = str(src)
    ctx.reports_dir = str(reports)
    ctx.depscan_options = {"reports_dir": str(reports)}
    ctx.html_report_file = os.path.join(str(reports), "depscan.html")
    ctx.txt_report_file = os.path.join(str(reports), "depscan.txt")
    ctx.llm_prompt_file = os.path.join(str(reports), "depscan-prompts.md")
    sample = reports / "depscan.toml.sample"
    sample.write_text("profile = 'generic'\n")
    return ctx, src, reports


def test_prepare_lifecycle_paths_moves_reports_out_of_the_scanned_tree(tmp_path):
    ctx, src, reports = _redirect_ctx(tmp_path, reports_inside=True)
    scan = pipeline.TypeScan(project_type="python")
    pipeline._prepare_lifecycle_paths(ctx, scan)
    new_dir = ctx.reports_dir
    assert not new_dir.startswith(str(src) + os.sep)
    assert os.path.basename(new_dir) == "proj-reports"
    assert os.path.isdir(new_dir)
    assert ctx.depscan_options["reports_dir"] == new_dir
    assert ctx.html_report_file == os.path.join(new_dir, "depscan.html")
    assert ctx.txt_report_file == os.path.join(new_dir, "depscan.txt")
    assert ctx.llm_prompt_file == os.path.join(new_dir, "depscan-prompts.md")
    # The sample config written into the old directory follows the move.
    assert os.path.exists(os.path.join(new_dir, "depscan.toml.sample"))
    # The second project type sees the moved directory and leaves it alone.
    pipeline._prepare_lifecycle_paths(ctx, pipeline.TypeScan(project_type="java"))
    assert ctx.reports_dir == new_dir


def test_prepare_lifecycle_paths_keeps_an_outside_reports_dir(tmp_path):
    ctx, src, reports = _redirect_ctx(tmp_path, reports_inside=False)
    pipeline._prepare_lifecycle_paths(ctx, pipeline.TypeScan(project_type="python"))
    assert ctx.reports_dir == str(reports)
    assert ctx.html_report_file == os.path.join(str(reports), "depscan.html")


def test_prepare_lifecycle_paths_falls_back_to_a_temp_dir(tmp_path, monkeypatch, caplog):
    ctx, src, reports = _redirect_ctx(tmp_path, reports_inside=True)
    real_makedirs = os.makedirs

    def refuse_makedirs(name, *a, **k):
        if str(name).endswith("-reports") and str(name) != str(reports):
            raise OSError("read-only parent")
        return real_makedirs(name, *a, **k)

    monkeypatch.setattr(pipeline.os, "makedirs", refuse_makedirs)
    with caplog.at_level("WARNING"):
        pipeline._prepare_lifecycle_paths(ctx, pipeline.TypeScan(project_type="python"))
    assert not ctx.reports_dir.startswith(str(src))
    assert "temporary directory" in " ".join(r.message for r in caplog.records)
