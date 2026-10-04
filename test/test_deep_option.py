"""Tests for the ``deep`` option plumbing (issue #536).

The lifecycle stages pass ``deep`` as the strings "true"/"false", while
depscan's blint fallback and the depscan server pass real booleans. A bare
truthiness test treats the string "false" as enabled, so the pre-build stage
of lifecycle analysis used to hand cdxgen a spurious ``--deep``. Every
generator must normalize the value instead.
"""

import pytest

from depscan.lib import bom as bom_mod
from xbom_lib import cdxgen as cdxgen_mod
from xbom_lib.cdxgen import deep_enabled

# ---------------------------------------------------------------------------
# normalization helper
# ---------------------------------------------------------------------------

ENABLED = (True, "true", "True", "1", " 1 ")
DISABLED = (False, "false", "False", "0", "", None, "no")


@pytest.mark.parametrize("value", ENABLED)
def test_deep_enabled_accepts(value):
    assert deep_enabled({"deep": value}) is True


@pytest.mark.parametrize("value", DISABLED)
def test_deep_enabled_rejects(value):
    assert deep_enabled({"deep": value}) is False


def test_deep_enabled_defaults_off():
    assert deep_enabled({}) is False


# ---------------------------------------------------------------------------
# CdxgenGenerator -- local CLI arguments
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


def test_cli_generator_omits_deep_for_false_string(monkeypatch, tmp_path):
    """The issue #536 regression: lifecycle pre-build passes deep="false"."""
    args = _capture_cdxgen_args(
        monkeypatch, tmp_path, {"project_type": ["dotnet"], "deep": "false"}
    )
    assert "--deep" not in args


def test_cli_generator_passes_deep_for_true_string(monkeypatch, tmp_path):
    args = _capture_cdxgen_args(
        monkeypatch, tmp_path, {"project_type": ["dotnet"], "deep": "true"}
    )
    assert "--deep" in args


def test_cli_generator_passes_deep_for_boolean_true(monkeypatch, tmp_path):
    """The depscan server and the blint fallback set deep to a real boolean."""
    args = _capture_cdxgen_args(
        monkeypatch, tmp_path, {"project_type": ["dotnet"], "deep": True}
    )
    assert "--deep" in args


def test_cli_generator_omits_deep_for_boolean_false(monkeypatch, tmp_path):
    args = _capture_cdxgen_args(
        monkeypatch, tmp_path, {"project_type": ["dotnet"], "deep": False}
    )
    assert "--deep" not in args


def test_cli_generator_omits_deep_by_default(monkeypatch, tmp_path):
    args = _capture_cdxgen_args(monkeypatch, tmp_path, {"project_type": ["dotnet"]})
    assert "--deep" not in args


# ---------------------------------------------------------------------------
# CdxgenImageBasedGenerator -- container arguments
# ---------------------------------------------------------------------------


def _container_args(tmp_path, options):
    gen = cdxgen_mod.CdxgenImageBasedGenerator(
        str(tmp_path), str(tmp_path / "bom.cdx.json"), options=options
    )
    _, run_command_args = gen._container_run_cmd()
    return run_command_args


def test_image_generator_omits_deep_for_false_string(tmp_path):
    args = _container_args(tmp_path, {"project_type": ["dotnet"], "deep": "false"})
    assert "--deep" not in args


def test_image_generator_passes_deep_for_true_string(tmp_path):
    args = _container_args(tmp_path, {"project_type": ["dotnet"], "deep": "true"})
    assert "--deep" in args


def test_image_generator_passes_deep_for_boolean_true(tmp_path):
    """The old membership test silently dropped boolean True here."""
    args = _container_args(tmp_path, {"project_type": ["dotnet"], "deep": True})
    assert "--deep" in args


def test_image_generator_omits_deep_for_boolean_false(tmp_path):
    args = _container_args(tmp_path, {"project_type": ["dotnet"], "deep": False})
    assert "--deep" not in args


# ---------------------------------------------------------------------------
# lifecycle analysis -- end to end argument construction
# ---------------------------------------------------------------------------


def test_lifecycle_prebuild_omits_deep_build_keeps_it(tmp_path, monkeypatch):
    """Replay the issue #536 scenario through create_lifecycle_boms with the
    real CdxgenGenerator: the build invocation must carry --deep and the
    pre-build invocation must not."""
    invocations = []

    def fake_exec_tool(args, *a, **k):
        invocations.append(list(args))
        return cdxgen_mod.BOMResult(success=True)

    monkeypatch.setattr(cdxgen_mod, "find_cdxgen_cmd", lambda *a, **k: "cdxgen")
    monkeypatch.setattr(cdxgen_mod, "exec_tool", fake_exec_tool)
    monkeypatch.setattr(bom_mod, "create_blint_bom", lambda *a, **k: False)
    options = {
        "prebuild_bom_file": str(tmp_path / "sbom-prebuild.cdx.json"),
        "build_bom_file": str(tmp_path / "sbom-build.cdx.json"),
        "postbuild_bom_file": str(tmp_path / "sbom-postbuild.cdx.json"),
        "container_bom_file": str(tmp_path / "sbom-container.cdx.json"),
        "project_type": ["java"],
        "reachability_analyzer": "SemanticReachability",
        "profile": "research",
    }
    bom_mod.create_lifecycle_boms(cdxgen_mod.CdxgenGenerator, str(tmp_path), options)
    build_invocations = [a for a in invocations if "build" in a]
    prebuild_invocations = [a for a in invocations if "pre-build" in a]
    assert build_invocations, "expected a build lifecycle invocation"
    assert prebuild_invocations, "expected a pre-build lifecycle invocation"
    assert all("--deep" in a for a in build_invocations)
    assert all("--deep" not in a for a in prebuild_invocations)
