"""Tests for the CLI scan-input resolution logic.

These cover the family of bugs where depscan's behaviour silently depended on
whether a BOM file / BOM directory happened to exist on disk:

* https://github.com/owasp-dep-scan/dep-scan/issues/517 -- ``--csaf`` produced
  nothing because the stale ``sbom-<type>.cdx.json`` path won over the VDR.
* ``--bom missing.json`` / ``--bom-dir missing/`` were ignored silently.
* per-project-type state leaking between loop iterations.
"""

import json
import os

import pytest

from depscan import cli
from depscan.cli_options import build_parser
from depscan.lib.bom import BomResult


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
    with open(path, "w") as fh:
        json.dump(bom, fh)
    return path


# ---------------------------------------------------------------------------
# validate_scan_inputs
# ---------------------------------------------------------------------------


def test_validate_scan_inputs_accepts_no_input_args():
    assert cli.validate_scan_inputs(_args([])) == []


def test_validate_scan_inputs_accepts_existing_bom(tmp_path):
    bom = _write_bom(str(tmp_path / "sbom.cdx.json"))
    assert cli.validate_scan_inputs(_args(["--bom", bom])) == []


def test_validate_scan_inputs_accepts_existing_bom_dir(tmp_path):
    assert cli.validate_scan_inputs(_args(["--bom-dir", str(tmp_path)])) == []


def test_validate_scan_inputs_rejects_missing_bom(tmp_path):
    missing = str(tmp_path / "nope.cdx.json")
    errors = cli.validate_scan_inputs(_args(["--bom", missing]))
    assert len(errors) == 1
    assert missing in errors[0]
    assert "does not exist" in errors[0]


def test_validate_scan_inputs_rejects_bom_that_is_a_directory(tmp_path):
    errors = cli.validate_scan_inputs(_args(["--bom", str(tmp_path)]))
    assert len(errors) == 1
    assert "is not a file" in errors[0]


def test_validate_scan_inputs_rejects_missing_bom_dir(tmp_path):
    missing = str(tmp_path / "nope")
    errors = cli.validate_scan_inputs(_args(["--bom-dir", missing]))
    assert len(errors) == 1
    assert "does not exist" in errors[0]


def test_validate_scan_inputs_rejects_bom_dir_that_is_a_file(tmp_path):
    bom = _write_bom(str(tmp_path / "sbom.cdx.json"))
    errors = cli.validate_scan_inputs(_args(["--bom-dir", bom]))
    assert len(errors) == 1
    assert "is not a directory" in errors[0]


def test_validate_scan_inputs_rejects_conflicting_inputs(tmp_path):
    """argparse makes these mutually exclusive, but TOML config values bypass
    the group, so the runtime check must catch it too."""
    bom = _write_bom(str(tmp_path / "sbom.cdx.json"))
    args = _args(["--bom", bom])
    args.bom_dir = str(tmp_path)
    errors = cli.validate_scan_inputs(args)
    assert any("mutually exclusive" in e for e in errors)
    assert any("--bom-dir" in e and "--bom" in e for e in errors)


def test_validate_scan_inputs_rejects_purl_with_bom(tmp_path):
    bom = _write_bom(str(tmp_path / "sbom.cdx.json"))
    args = _args(["--bom", bom])
    args.search_purl = "pkg:cargo/time@0.1.45"
    errors = cli.validate_scan_inputs(args)
    assert any("mutually exclusive" in e for e in errors)


# ---------------------------------------------------------------------------
# run_depscan integration
# ---------------------------------------------------------------------------


class _FakeVdrResult:
    pkg_vulnerabilities = []
    prioritized_pkg_vuln_trees = {}
    reached_purls = {}


@pytest.fixture
def harness(monkeypatch, tmp_path):
    """Stub every expensive/external call in run_depscan and record what the
    BOM-resolution logic decided."""
    calls = {
        "create_bom": [],
        "vdr": [],
        "csaf": [],
        "get_all_pkg_list": [],
        "template": [],
    }

    monkeypatch.setattr(cli, "resolve_scan_vdb_image", lambda args: ("oras://vdb", False))
    monkeypatch.setattr(cli, "_warn_large_appos_for_source_scan", lambda url, args: None)
    monkeypatch.setattr(cli, "vdb_download_needed", lambda url, d: (False, ""))
    monkeypatch.setattr(cli, "configure_vdb_readonly", lambda: None)
    monkeypatch.setattr(cli.search, "load_custom_data", lambda d: None)
    monkeypatch.setattr(cli, "get_pkgs_by_scope", lambda pkg_list: {})
    monkeypatch.setattr(cli, "annotate_vdr", lambda v, t: None)
    monkeypatch.setattr(
        cli.ReportGenerator, "parse_and_generate_report", lambda self: None, raising=False
    )
    monkeypatch.setattr(cli.console, "save_html", lambda *a, **k: None)
    monkeypatch.setattr(cli.console, "save_text", lambda *a, **k: None)

    def fake_get_all_pkg_list(from_dir):
        calls["get_all_pkg_list"].append(from_dir)
        return [{"purl": "pkg:cargo/time@0.1.45", "name": "time", "version": "0.1.45"}]

    monkeypatch.setattr(cli, "get_all_pkg_list", fake_get_all_pkg_list)
    monkeypatch.setattr(
        cli,
        "get_pkg_list",
        lambda f: ([{"purl": "pkg:cargo/time@0.1.45", "name": "time", "version": "0.1.45"}], []),
    )

    # The default create_bom stub mimics lifecycle analysis: it reports success
    # but writes per-stage documents rather than the requested path.
    def fake_create_bom(bom_file, src_dir, options):
        calls["create_bom"].append((bom_file, options))
        written = []
        for key in ("build_bom_file", "prebuild_bom_file"):
            if options.get(key):
                written.append(_write_bom(options[key]))
        return BomResult(success=True, bom_files=written, primary=None)

    monkeypatch.setattr(cli, "create_bom", fake_create_bom)

    vdr_holder = {"file": None}

    def fake_vdr_analyze_summarize(project_type, results, **kwargs):
        calls["vdr"].append({"project_type": project_type, **kwargs})
        return {}, vdr_holder["file"], _FakeVdrResult()

    monkeypatch.setattr(cli, "vdr_analyze_summarize", fake_vdr_analyze_summarize)

    def fake_export_csaf(vdr_result, src_dir, reports_dir, bom_file, csaf_version="2.1"):
        calls["csaf"].append(bom_file)
        return os.path.join(reports_dir, "out.csaf.json"), []

    monkeypatch.setattr(cli, "export_csaf", fake_export_csaf)

    def fake_render(**kwargs):
        calls["template"].append(kwargs)

    monkeypatch.setattr(cli.utils, "render_template_report", fake_render)

    calls["_vdr_holder"] = vdr_holder
    return calls


def _base_argv(tmp_path, extra=None):
    reports = tmp_path / "reports"
    reports.mkdir(exist_ok=True)
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    argv = [
        "--src",
        str(src),
        "--reports-dir",
        str(reports),
        "--no-banner",
        "-t",
        "rust",
    ]
    argv.extend(extra or [])
    return argv


def test_csaf_falls_back_to_vdr_when_lifecycle_wrote_no_bom(harness, tmp_path):
    """Issue #517: SemanticReachability without --bom-dir switches to lifecycle
    analysis, which never writes `sbom-<type>.cdx.json`. The stale path used to
    win over the VDR and CSAF export silently produced nothing."""
    reports = tmp_path / "reports"
    reports.mkdir(exist_ok=True)
    vdr_file = str(reports / "depscan-universal.vdr.json")
    _write_bom(vdr_file)
    harness["_vdr_holder"]["file"] = vdr_file

    args = _args(
        _base_argv(tmp_path, ["--csaf", "--reachability-analyzer", "SemanticReachability"])
    )
    cli.run_depscan(args)

    assert harness["csaf"] == [vdr_file]


def test_csaf_prefers_the_reported_bom_file(harness, tmp_path, monkeypatch):
    """When the generator reports a single BOM, CSAF is named after it rather
    than the VDR."""
    reports = tmp_path / "reports"
    reports.mkdir(exist_ok=True)
    vdr_file = _write_bom(str(reports / "depscan-universal.vdr.json"))
    harness["_vdr_holder"]["file"] = vdr_file

    def create_and_report(bom_file, src_dir, options):
        _write_bom(bom_file)
        return BomResult(success=True, bom_files=[bom_file], primary=bom_file)

    monkeypatch.setattr(cli, "create_bom", create_and_report)

    args = _args(_base_argv(tmp_path, ["--csaf"]))
    cli.run_depscan(args)

    assert harness["csaf"] == [str(reports / "sbom-rust.cdx.json")]


def test_unreported_bom_on_disk_is_not_used(harness, tmp_path):
    """The #517 failure mode. A lifecycle run writes no `sbom-<type>.cdx.json`
    and nominates no project BOM, so the requested path must not be treated as
    one just because a stale file from an earlier scan happens to sit there
    alongside the stage documents."""
    reports = tmp_path / "reports"
    reports.mkdir(exist_ok=True)
    stale = _write_bom(str(reports / "sbom-rust.cdx.json"))
    vdr_file = _write_bom(str(reports / "depscan-universal.vdr.json"))
    harness["_vdr_holder"]["file"] = vdr_file

    args = _args(
        _base_argv(tmp_path, ["--csaf", "--reachability-analyzer", "SemanticReachability"])
    )
    cli.run_depscan(args)

    assert stale not in harness["csaf"]
    assert harness["csaf"] == [vdr_file]


def test_csaf_skipped_when_neither_bom_nor_vdr_exists(harness, tmp_path, caplog):
    harness["_vdr_holder"]["file"] = str(tmp_path / "reports" / "missing.vdr.json")

    args = _args(
        _base_argv(tmp_path, ["--csaf", "--reachability-analyzer", "SemanticReachability"])
    )
    cli.run_depscan(args)

    assert harness["csaf"] == []


def test_csaf_failure_is_reported(harness, tmp_path, monkeypatch, caplog):
    reports = tmp_path / "reports"
    reports.mkdir(exist_ok=True)
    vdr_file = _write_bom(str(reports / "depscan-universal.vdr.json"))
    harness["_vdr_holder"]["file"] = vdr_file
    monkeypatch.setattr(cli, "export_csaf", lambda *a, **k: (None, ["boom"]))

    args = _args(
        _base_argv(tmp_path, ["--csaf", "--reachability-analyzer", "SemanticReachability"])
    )
    with caplog.at_level("WARNING", logger=cli.LOG.name):
        cli.run_depscan(args)

    assert any("CSAF export failed" in r.message for r in caplog.records)


def test_bom_file_is_dropped_when_not_written(harness, tmp_path):
    """A generator that reports success without producing the file must not
    leave a phantom path behind for the VDR analyzer."""
    args = _args(_base_argv(tmp_path, ["--reachability-analyzer", "SemanticReachability"]))
    cli.run_depscan(args)

    assert harness["vdr"], "vdr_analyze_summarize was never reached"
    assert harness["vdr"][0]["bom_file"] is None


def test_bom_file_is_used_when_written(harness, tmp_path, monkeypatch):
    reports = tmp_path / "reports"
    reports.mkdir(exist_ok=True)

    def create_and_write(bom_file, src_dir, options):
        _write_bom(bom_file)
        return BomResult(success=True, bom_files=[bom_file], primary=bom_file)

    monkeypatch.setattr(cli, "create_bom", create_and_write)

    args = _args(_base_argv(tmp_path))
    cli.run_depscan(args)

    assert harness["vdr"][0]["bom_file"] == str(reports / "sbom-rust.cdx.json")


def test_template_report_not_given_a_phantom_bom_path(harness, tmp_path):
    template = tmp_path / "tmpl.j2"
    template.write_text("{{ summary }}")

    args = _args(
        _base_argv(
            tmp_path,
            [
                "--report-template",
                str(template),
                "--reachability-analyzer",
                "SemanticReachability",
            ],
        )
    )
    cli.run_depscan(args)

    assert harness["template"], "render_template_report was never called"
    assert harness["template"][0]["bom_file"] is None


def test_missing_bom_argument_exits(tmp_path, harness):
    args = _args(_base_argv(tmp_path, ["--bom", str(tmp_path / "nope.json")]))
    with pytest.raises(SystemExit) as excinfo:
        cli.run_depscan(args)
    assert excinfo.value.code == 1
    assert harness["vdr"] == [], "the scan must not proceed with an unusable input"


def test_missing_bom_dir_argument_exits(tmp_path, harness):
    args = _args(_base_argv(tmp_path, ["--bom-dir", str(tmp_path / "nope")]))
    with pytest.raises(SystemExit) as excinfo:
        cli.run_depscan(args)
    assert excinfo.value.code == 1
    assert harness["vdr"] == []


def test_lifecycle_bom_dir_does_not_leak_across_project_types(harness, tmp_path, monkeypatch):
    """The lifecycle branch used to mutate ``args.bom_dir``. The second project
    type then re-derived its state from the first type's output directory."""
    args = _args(_base_argv(tmp_path, ["--reachability-analyzer", "SemanticReachability"]))
    args.project_type = ["rust", "python"]
    cli.run_depscan(args)

    assert args.bom_dir is None, "args must not be mutated by lifecycle analysis"
    assert [c["project_type"] for c in harness["vdr"]] == ["rust", "python"]
    # Both iterations aggregate from the reports dir, never from a stale value.
    reports = os.path.realpath(str(tmp_path / "reports"))
    assert [c["bom_dir"] for c in harness["vdr"]] == [reports, reports]


def test_bom_dir_mode_is_honoured(harness, tmp_path):
    bom_dir = tmp_path / "boms"
    bom_dir.mkdir()
    _write_bom(str(bom_dir / "sbom-rust.cdx.json"))

    args = _args(["--bom-dir", str(bom_dir), "--no-banner"])
    cli.run_depscan(args)

    assert harness["create_bom"] == [], "BOM generation must be skipped in bom-dir mode"
    assert harness["get_all_pkg_list"] == [str(bom_dir)]
    assert harness["vdr"][0]["bom_dir"] == str(bom_dir)


def test_purl_mode_does_not_touch_bom_paths(harness, tmp_path):
    args = _args(
        [
            "--purl",
            "pkg:cargo/time@0.1.45",
            "--reports-dir",
            str(tmp_path / "reports"),
            "--no-banner",
        ]
    )
    cli.run_depscan(args)

    assert harness["create_bom"] == []
    assert harness["get_all_pkg_list"] == []
    assert harness["vdr"][0]["bom_file"] is None
    assert harness["vdr"][0]["bom_dir"] is None


def test_lone_file_in_bom_dir_is_the_project_bom(harness, tmp_path):
    """A bom dir holding exactly one document: that document is the project's
    BOM, so it is both what the VDR analyzer reads and what names the CSAF."""
    bom_dir = tmp_path / "boms"
    bom_dir.mkdir()
    only_bom = _write_bom(str(bom_dir / "sbom-rust.cdx.json"))
    vdr_file = _write_bom(str(bom_dir / "depscan-universal.vdr.json"))
    harness["_vdr_holder"]["file"] = vdr_file

    args = _args(["--bom-dir", str(bom_dir), "--csaf", "--no-banner"])
    cli.run_depscan(args)

    assert harness["vdr"][0]["bom_file"] == only_bom
    assert harness["csaf"] == [only_bom]


def test_lone_lifecycle_document_is_the_project_bom(harness, tmp_path, monkeypatch):
    """Same rule when only one lifecycle stage succeeded: there is exactly one
    document, so it is the project's BOM even though the lifecycle run itself
    nominates nothing."""
    reports = tmp_path / "reports"
    reports.mkdir(exist_ok=True)

    def only_build_stage_succeeds(bom_file, src_dir, options):
        return BomResult(
            success=True, bom_files=[_write_bom(options["build_bom_file"])], primary=None
        )

    monkeypatch.setattr(cli, "create_bom", only_build_stage_succeeds)
    harness["_vdr_holder"]["file"] = _write_bom(str(reports / "depscan-universal.vdr.json"))

    args = _args(
        _base_argv(tmp_path, ["--csaf", "--reachability-analyzer", "SemanticReachability"])
    )
    cli.run_depscan(args)

    build_bom = str(reports / "sbom-build-rust.cdx.json")
    assert harness["vdr"][0]["bom_file"] == build_bom
    assert harness["csaf"] == [build_bom]


def test_explicit_bom_is_the_project_bom(harness, tmp_path):
    bom = _write_bom(str(tmp_path / "given.cdx.json"))
    harness["_vdr_holder"]["file"] = None

    args = _args(
        ["--bom", bom, "--reports-dir", str(tmp_path / "reports"), "--no-banner", "--csaf"]
    )
    cli.run_depscan(args)

    assert harness["vdr"][0]["bom_file"] == bom
    assert harness["csaf"] == [bom]


# ---------------------------------------------------------------------------
# --fail-on-error: silent degradations must abort the scan instead
# ---------------------------------------------------------------------------


def test_fail_on_error_exits_when_bom_creation_fails(harness, tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "create_bom", lambda *a, **k: BomResult(success=False))
    args = _args(_base_argv(tmp_path, ["--fail-on-error"]))
    with pytest.raises(SystemExit) as excinfo:
        cli.run_depscan(args)
    assert excinfo.value.code == 1
    assert harness["vdr"] == [], "the scan must not proceed without a BOM"


def test_bom_creation_failure_continues_without_flag(harness, tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "create_bom", lambda *a, **k: BomResult(success=False))
    args = _args(_base_argv(tmp_path))
    cli.run_depscan(args)
    assert harness["vdr"] == [], "no BOM means nothing to analyze, but no exit either"


def test_fail_on_error_exits_on_scan_failure_error(harness, tmp_path, monkeypatch):
    from depscan.lib.bom import ScanFailureError

    def raising_create_bom(*a, **k):
        raise ScanFailureError("dosai produced no usable slices")

    monkeypatch.setattr(cli, "create_bom", raising_create_bom)
    args = _args(_base_argv(tmp_path, ["--fail-on-error"]))
    with pytest.raises(SystemExit) as excinfo:
        cli.run_depscan(args)
    assert excinfo.value.code == 1
    assert harness["vdr"] == []


def test_fail_on_error_exits_when_no_packages_found(harness, tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "get_pkg_list", lambda f: ([], []))
    bom = _write_bom(str(tmp_path / "given.cdx.json"))
    args = _args(
        [
            "--bom",
            bom,
            "--reports-dir",
            str(tmp_path / "reports"),
            "--no-banner",
            "--fail-on-error",
        ]
    )
    with pytest.raises(SystemExit) as excinfo:
        cli.run_depscan(args)
    assert excinfo.value.code == 1
    assert harness["vdr"] == [], "an empty package list is a failed scan under the flag"


def test_empty_package_list_continues_without_flag(harness, tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "get_pkg_list", lambda f: ([], []))
    bom = _write_bom(str(tmp_path / "given.cdx.json"))
    args = _args(["--bom", bom, "--reports-dir", str(tmp_path / "reports"), "--no-banner"])
    cli.run_depscan(args)
    assert harness["vdr"] == []
