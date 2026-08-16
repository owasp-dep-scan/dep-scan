"""Tests for ``--fail-on-error`` (issue #523).

The flag mirrors cdxgen's ``--fail-on-error`` and is passed through to the
cdxgen invocation. For every other tool (blint, rusi, golem, dosai) and the
exception paths that normally degrade silently (unreadable reachability
reports, empty slices, swallowed errors), setting the flag must abort the scan
instead of producing a quietly downgraded result.
"""

import json
from types import SimpleNamespace

import pytest

from depscan.cli_options import build_parser
from depscan.lib import bom as bom_mod
from depscan.lib.bom import ScanFailureError, run_dosai_reachability
from xbom_lib import cdxgen as cdxgen_mod
from xbom_lib import dosai as dosai_mod
from xbom_lib import golem as golem_mod
from xbom_lib import rusi as rusi_mod

VALID_METHODS = {
    "Metadata": {"Tool": "Dosai"},
    "CallGraph": {"Nodes": [], "Edges": []},
    "ApiEndpoints": [],
    "PackageReachability": [],
}


def _write_bom(bom_file, purl="pkg:nuget/System.Text.Json@10.0.0"):
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {"component": {"type": "application", "name": "app", "purl": purl}},
        "components": [{"type": "library", "name": "lib", "purl": purl}],
    }
    bom_file.write_text(json.dumps(bom), encoding="utf-8")
    return str(bom_file)


# ---------------------------------------------------------------------------
# CLI parsing
# ---------------------------------------------------------------------------


def test_fail_on_error_defaults_off():
    assert build_parser().parse_args([]).fail_on_error is False


def test_fail_on_error_flag_parses():
    assert build_parser().parse_args(["--fail-on-error"]).fail_on_error is True


# ---------------------------------------------------------------------------
# cdxgen pass-through
# ---------------------------------------------------------------------------


def _capture_cdxgen_args(monkeypatch, tmp_path, options):
    captured = {}

    def fake_exec_tool(args, *a, **k):
        captured["args"] = args
        return cdxgen_mod.BOMResult(success=True)

    monkeypatch.setattr(cdxgen_mod, "find_cdxgen_cmd", lambda *a, **k: "cdxgen")
    monkeypatch.setattr(cdxgen_mod, "exec_tool", fake_exec_tool)
    gen = cdxgen_mod.CdxgenGenerator(
        str(tmp_path), str(tmp_path / "bom.cdx.json"), options=options
    )
    gen.generate()
    return captured["args"]


def test_cdxgen_generator_passes_fail_on_error(monkeypatch, tmp_path):
    args = _capture_cdxgen_args(
        monkeypatch, tmp_path, {"project_type": ["rust"], "fail_on_error": True}
    )
    assert "--fail-on-error" in args


def test_cdxgen_generator_omits_flag_by_default(monkeypatch, tmp_path):
    args = _capture_cdxgen_args(monkeypatch, tmp_path, {"project_type": ["rust"]})
    assert "--fail-on-error" not in args


def test_image_generator_passes_fail_on_error(monkeypatch, tmp_path):
    monkeypatch.setenv("CDXGEN_TEMP_DIR", str(tmp_path))
    gen = cdxgen_mod.CdxgenImageBasedGenerator(
        str(tmp_path),
        str(tmp_path / "bom.cdx.json"),
        options={"project_type": ["rust"], "fail_on_error": True},
    )
    _, run_command_args = gen._container_run_cmd()
    assert "--fail-on-error" in run_command_args


def test_image_generator_omits_flag_by_default(monkeypatch, tmp_path):
    monkeypatch.setenv("CDXGEN_TEMP_DIR", str(tmp_path))
    gen = cdxgen_mod.CdxgenImageBasedGenerator(
        str(tmp_path),
        str(tmp_path / "bom.cdx.json"),
        options={"project_type": ["rust"]},
    )
    _, run_command_args = gen._container_run_cmd()
    assert "--fail-on-error" not in run_command_args


# ---------------------------------------------------------------------------
# Report loaders -- swallowed read failures
# ---------------------------------------------------------------------------


def _raising_load(path, log=None):
    raise PermissionError("denied")


def test_load_dosai_report_raises_on_read_failure_under_flag(tmp_path):
    report = tmp_path / "dotnet-semantics.slices.json"
    report.write_text("{}", encoding="utf-8")
    with pytest.raises(ScanFailureError):
        bom_mod._load_dosai_report(str(report), lambda d: True, _raising_load, fail_on_error=True)


def test_load_dosai_report_read_failure_degrades_by_default(tmp_path):
    report = tmp_path / "dotnet-semantics.slices.json"
    report.write_text("{}", encoding="utf-8")
    assert bom_mod._load_dosai_report(str(report), lambda d: True, _raising_load) is None


def test_load_rusi_report_raises_on_read_failure_under_flag(tmp_path):
    report = tmp_path / "rust-semantics.slices.json"
    report.write_text("{}", encoding="utf-8")
    with pytest.raises(ScanFailureError):
        bom_mod._load_rusi_report(str(report), lambda d: True, _raising_load, fail_on_error=True)


def test_load_golem_report_raises_on_read_failure_under_flag(tmp_path):
    report = tmp_path / "go-semantics.slices.json"
    report.write_text("{}", encoding="utf-8")
    with pytest.raises(ScanFailureError):
        bom_mod._load_golem_report(str(report), lambda d: True, _raising_load, fail_on_error=True)


# ---------------------------------------------------------------------------
# dosai fallback -- corrupt reports and empty slices (issue #523 core)
# ---------------------------------------------------------------------------


def _fake_dosai_run_writing(tmp_path, methods_content, dataflows_content):
    def fake_run_dosai(src_dir, out_dir, **kwargs):
        methods_path = tmp_path / "dotnet-methods.json"
        dataflows_path = tmp_path / "dotnet-dataflows.json"
        methods_path.write_text(methods_content, encoding="utf-8")
        dataflows_path.write_text(dataflows_content, encoding="utf-8")
        return dosai_mod.DosaiResult(
            success=True,
            methods_path=str(methods_path),
            dataflows_path=str(dataflows_path),
        )

    return fake_run_dosai


def _write_json(path, data):
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _corrupt_report_case(tmp_path, monkeypatch):
    """A corrupt methods report plus a readable dataflows report. json_load
    swallows the JSONDecodeError and returns {}, so without the flag the run
    silently degrades to whatever dataflows carries (issue #523)."""
    monkeypatch.setattr(
        dosai_mod,
        "run_dosai",
        _fake_dosai_run_writing(tmp_path, "{ truncated", json.dumps(VALID_METHODS)),
    )
    bom = _write_bom(tmp_path / "bom.cdx.json")
    options = {"project_type": ["dotnet"], "reachability_analyzer": "FrameworkReachability"}
    return bom, options


def test_dosai_corrupt_report_raises_under_flag(tmp_path, monkeypatch):
    bom, options = _corrupt_report_case(tmp_path, monkeypatch)
    with pytest.raises(ScanFailureError, match="unreadable or empty"):
        run_dosai_reachability(bom, str(tmp_path), options={**options, "fail_on_error": True})


def test_dosai_corrupt_report_degrades_by_default(tmp_path, monkeypatch, caplog):
    """Without the flag the corrupt methods artifact is treated as absent and
    the run continues from the dataflows half -- the pre-existing behaviour,
    but the user is warned that reachability is incomplete (issue #523)."""
    bom, options = _corrupt_report_case(tmp_path, monkeypatch)
    with caplog.at_level("WARNING"):
        ok = run_dosai_reachability(bom, str(tmp_path), options=options)
    assert ok is True
    assert (tmp_path / "dotnet-reachables.slices.json").exists()
    assert any(
        "methods" in r.getMessage() and "incomplete" in r.getMessage() for r in caplog.records
    )


def test_dosai_missing_dataflows_warns(tmp_path, monkeypatch, caplog):
    """A methods-only run is legitimate, so it must not fail -- but a missing
    dataflows report means data-flow reachability is unavailable and has to be
    reported rather than swallowed."""
    monkeypatch.setattr(
        dosai_mod,
        "run_dosai",
        lambda *a, **k: dosai_mod.DosaiResult(
            success=True,
            methods_path=str(_write_json(tmp_path / "methods.json", VALID_METHODS)),
            dataflows_path=None,
        ),
    )
    bom = _write_bom(tmp_path / "bom.cdx.json")
    options = {
        "project_type": ["dotnet"],
        "reachability_analyzer": "FrameworkReachability",
        "fail_on_error": True,
    }
    with caplog.at_level("WARNING"):
        assert run_dosai_reachability(bom, str(tmp_path), options=options) is True
    assert any(
        "dataflows" in r.getMessage() and "incomplete" in r.getMessage() for r in caplog.records
    )


def test_dosai_empty_slices_raise_under_flag(tmp_path, monkeypatch):
    """Both artifacts present but empty: no usable slices at all."""
    monkeypatch.setattr(
        dosai_mod,
        "run_dosai",
        _fake_dosai_run_writing(tmp_path, "{}", "{}"),
    )
    bom = _write_bom(tmp_path / "bom.cdx.json")
    with pytest.raises(ScanFailureError, match="unreadable or empty"):
        run_dosai_reachability(
            bom,
            str(tmp_path),
            options={
                "project_type": ["dotnet"],
                "reachability_analyzer": "FrameworkReachability",
                "fail_on_error": True,
            },
        )


def test_dosai_unavailable_raises_under_flag(tmp_path, monkeypatch):
    monkeypatch.setattr(
        dosai_mod,
        "run_dosai",
        lambda *a, **k: dosai_mod.DosaiResult(success=False, skipped=True),
    )
    bom = _write_bom(tmp_path / "bom.cdx.json")
    with pytest.raises(ScanFailureError):
        run_dosai_reachability(
            bom,
            str(tmp_path),
            options={
                "project_type": ["dotnet"],
                "reachability_analyzer": "FrameworkReachability",
                "fail_on_error": True,
            },
        )


# ---------------------------------------------------------------------------
# rusi / golem fallbacks -- skipped or failed tools
# ---------------------------------------------------------------------------


def test_rusi_fallback_skipped_raises_under_flag(tmp_path, monkeypatch):
    monkeypatch.setattr(
        rusi_mod,
        "run_rusi",
        lambda *a, **k: rusi_mod.RusiResult(success=False, skipped=True),
    )
    with pytest.raises(ScanFailureError):
        bom_mod._run_rusi_fallback(
            str(tmp_path), str(tmp_path), {"fail_on_error": True}, lambda d: True, dict
        )


def test_rusi_fallback_skipped_degrades_by_default(tmp_path, monkeypatch):
    monkeypatch.setattr(
        rusi_mod,
        "run_rusi",
        lambda *a, **k: rusi_mod.RusiResult(success=False, skipped=True),
    )
    assert (
        bom_mod._run_rusi_fallback(str(tmp_path), str(tmp_path), {}, lambda d: True, dict) is None
    )


def test_golem_fallback_skipped_raises_under_flag(tmp_path, monkeypatch):
    monkeypatch.setattr(
        golem_mod,
        "run_golem",
        lambda *a, **k: golem_mod.GolemResult(success=False, skipped=True),
    )
    with pytest.raises(ScanFailureError):
        bom_mod._run_golem_fallback(
            str(tmp_path), str(tmp_path), {"fail_on_error": True}, lambda d: True, dict
        )


def test_golem_fallback_skipped_degrades_by_default(tmp_path, monkeypatch):
    monkeypatch.setattr(
        golem_mod,
        "run_golem",
        lambda *a, **k: golem_mod.GolemResult(success=False, skipped=True),
    )
    assert (
        bom_mod._run_golem_fallback(str(tmp_path), str(tmp_path), {}, lambda d: True, dict) is None
    )


def test_run_rusi_reachability_raises_under_flag(tmp_path, monkeypatch):
    """End to end: no cdxgen report + skipped fallback must abort the scan
    rather than silently skipping Rust reachability."""
    bom = _write_bom(tmp_path / "bom.cdx.json", purl="pkg:cargo/time@0.1.45")
    monkeypatch.setattr(
        rusi_mod,
        "run_rusi",
        lambda *a, **k: rusi_mod.RusiResult(success=False, skipped=True),
    )
    with pytest.raises(ScanFailureError):
        bom_mod.run_rusi_reachability(
            bom,
            str(tmp_path),
            options={
                "project_type": ["rust"],
                "reachability_analyzer": "FrameworkReachability",
                "fail_on_error": True,
            },
        )


# ---------------------------------------------------------------------------
# lifecycle analysis -- swallowed cdxgen build-stage failure
# ---------------------------------------------------------------------------


def _lifecycle_options(tmp_path, fail_on_error):
    return {
        "prebuild_bom_file": str(tmp_path / "sbom-prebuild.cdx.json"),
        "build_bom_file": str(tmp_path / "sbom-build.cdx.json"),
        "postbuild_bom_file": str(tmp_path / "sbom-postbuild.cdx.json"),
        "container_bom_file": str(tmp_path / "sbom-container.cdx.json"),
        "reachability_analyzer": "off",
        "fail_on_error": fail_on_error,
    }


def _failing_generator():
    class _FailGen:
        def __init__(self, src_dir, bom_file, logger=None, options=None):
            pass

        def generate(self):
            return SimpleNamespace(success=False, command_output="boom")

    return _FailGen


def test_lifecycle_build_failure_raises_under_flag(tmp_path, monkeypatch):
    """Falling back to the pre-build stage is itself a silent downgrade, so the
    flag must abort rather than let a degraded lifecycle BOM through."""
    monkeypatch.setattr(bom_mod, "create_blint_bom", lambda *a, **k: False)
    with pytest.raises(ScanFailureError):
        bom_mod.create_lifecycle_boms(
            _failing_generator(), str(tmp_path), _lifecycle_options(tmp_path, True)
        )


def test_lifecycle_build_failure_degrades_by_default(tmp_path, monkeypatch):
    monkeypatch.setattr(bom_mod, "create_blint_bom", lambda *a, **k: False)
    result = bom_mod.create_lifecycle_boms(
        _failing_generator(), str(tmp_path), _lifecycle_options(tmp_path, False)
    )
    assert result.success is False
