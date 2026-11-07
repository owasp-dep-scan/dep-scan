"""Unit tests for the golem runner (``xbom_lib.golem``).

These exercise the binary-discovery + invocation logic WITHOUT the real golem
binary (everything is monkeypatched), so they run unconditionally in CI. The
integration tests in ``test/test_golem_integration.py`` cover the real binary.
"""

import pytest

from xbom_lib import golem as golem_mod
from xbom_lib.golem import (
    DEFAULT_CALLGRAPH_MODE,
    DEFAULT_DATAFLOW_MODE,
    _build_golem_args,
    _build_hardened_go_env,
    bundled_golem_path,
    find_golem_binary,
    go_toolchain_available,
    run_golem,
)


@pytest.fixture
def stub_binary(monkeypatch, tmp_path):
    """Resolve the binary + version without needing golem installed."""
    fake_bin = str(tmp_path / "golem")
    monkeypatch.setattr(golem_mod, "find_golem_binary", lambda logger=None: fake_bin)
    monkeypatch.setattr(golem_mod, "get_golem_version", lambda binary, logger=None: "2.5.2")
    monkeypatch.setattr(golem_mod, "go_toolchain_available", lambda logger=None: True)
    monkeypatch.setattr(golem_mod, "_peek_report", lambda out_path: (True, "ok"))
    monkeypatch.setattr(golem_mod, "_check_truncation", lambda out_path, logger=None: None)
    return fake_bin


# ---------------------------------------------------------------------------
# Binary discovery -- cdxgen-matching resolution (no real binary required)
# ---------------------------------------------------------------------------


def _clear_binary_env(monkeypatch):
    monkeypatch.delenv(golem_mod.GOLEM_CMD_ENV, raising=False)
    monkeypatch.delenv(golem_mod.GOLEM_BINARY_ENV, raising=False)
    monkeypatch.delenv("CDXGEN_PLUGINS_DIR", raising=False)


def test_bundled_golem_path_matches_cdxgen_layout(tmp_path):
    """Layout MUST be <pluginsDir>/golem/golem-<platform>-<arch><extn>,
    matching cdxgen's resolveBundledPluginBinary for the golem tool across all
    platform/arch tokens."""
    plugins_dir = tmp_path / "plugins"

    def _expect(target, expected_name):
        bin_path = plugins_dir / "golem" / expected_name
        bin_path.parent.mkdir(parents=True, exist_ok=True)
        bin_path.write_text("")
        assert bundled_golem_path(str(plugins_dir), target) == str(bin_path), (
            f"expected layout for {target}"
        )

    _expect({"platform": "darwin", "arch": "arm64", "extn": ""}, "golem-darwin-arm64")
    _expect({"platform": "linux", "arch": "amd64", "extn": ""}, "golem-linux-amd64")
    _expect(
        {"platform": "linuxmusl", "arch": "amd64", "extn": ""},
        "golem-linuxmusl-amd64",
    )
    _expect(
        {"platform": "windows", "arch": "amd64", "extn": ".exe"},
        "golem-windows-amd64.exe",
    )
    _expect({"platform": "linux", "arch": "ppc64le", "extn": ""}, "golem-linux-ppc64le")

    assert (
        bundled_golem_path(str(plugins_dir), {"platform": "linux", "arch": "arm64", "extn": ""})
        is None
    )
    assert bundled_golem_path(None, {"platform": "linux", "arch": "amd64", "extn": ""}) is None
    assert bundled_golem_path("", {"platform": "linux", "arch": "amd64", "extn": ""}) is None


def test_find_golem_binary_prefers_golem_cmd(monkeypatch, tmp_path):
    """GOLEM_CMD (cdxgen's env) wins over DEPSCAN_GOLEM_BINARY and the bundled
    layout, so depscan's fallback resolves the SAME binary cdxgen uses."""
    golem_cmd = tmp_path / "golem-via-golem-cmd"
    golem_cmd.write_text("")
    depscan_bin = tmp_path / "golem-via-depscan"
    depscan_bin.write_text("")
    monkeypatch.setenv(golem_mod.GOLEM_CMD_ENV, str(golem_cmd))
    monkeypatch.setenv(golem_mod.GOLEM_BINARY_ENV, str(depscan_bin))
    monkeypatch.setattr("xbom_lib.golem.find_executable", lambda name: None)
    assert find_golem_binary() == str(golem_cmd)


def test_find_golem_binary_falls_back_to_depscan_env(monkeypatch, tmp_path):
    """Without GOLEM_CMD, the depscan-specific override is honored."""
    depscan_bin = tmp_path / "golem-via-depscan"
    depscan_bin.write_text("")
    _clear_binary_env(monkeypatch)
    monkeypatch.setenv(golem_mod.GOLEM_BINARY_ENV, str(depscan_bin))
    monkeypatch.setattr("xbom_lib.golem.find_executable", lambda name: None)
    assert find_golem_binary() == str(depscan_bin)


def test_find_golem_binary_uses_path_lookup(monkeypatch, tmp_path):
    """PATH lookup (find_executable) is consulted after the env overrides."""
    path_bin = tmp_path / "golem-on-path"
    path_bin.write_text("")
    _clear_binary_env(monkeypatch)
    monkeypatch.setattr("xbom_lib.golem.find_executable", lambda name: str(path_bin))
    assert find_golem_binary() == str(path_bin)


def test_find_golem_binary_resolves_bundled_layout(monkeypatch, tmp_path):
    """Without env overrides or PATH, the cdxgen-plugins-bin bundled layout is
    resolved from CDXGEN_PLUGINS_DIR using the host's platform/arch tokens."""
    from xbom_lib.plugins import get_plugins_bin_target

    plugins_dir = tmp_path / "plugins"
    target = get_plugins_bin_target()
    bin_path = (
        plugins_dir / "golem" / f"golem-{target['platform']}-{target['arch']}{target['extn']}"
    )
    bin_path.parent.mkdir(parents=True)
    bin_path.write_text("")
    _clear_binary_env(monkeypatch)
    monkeypatch.setattr("xbom_lib.golem.find_executable", lambda name: None)
    monkeypatch.setenv("CDXGEN_PLUGINS_DIR", str(plugins_dir))
    assert find_golem_binary() == str(bin_path)


def test_find_golem_binary_missing_env_falls_through(monkeypatch, tmp_path):
    """An env var pointing at a non-existent file does NOT short-circuit;
    resolution continues to PATH so a stale override is not fatal."""
    real_on_path = tmp_path / "golem-real"
    real_on_path.write_text("")
    monkeypatch.setenv(golem_mod.GOLEM_CMD_ENV, str(tmp_path / "no-such-binary"))
    monkeypatch.delenv(golem_mod.GOLEM_BINARY_ENV, raising=False)
    monkeypatch.delenv("CDXGEN_PLUGINS_DIR", raising=False)
    monkeypatch.setattr("xbom_lib.golem.find_executable", lambda name: str(real_on_path))
    assert find_golem_binary() == str(real_on_path)


def test_find_golem_binary_returns_none_when_unresolvable(monkeypatch, tmp_path):
    _clear_binary_env(monkeypatch)
    monkeypatch.setattr("xbom_lib.golem.find_executable", lambda name: None)
    monkeypatch.setenv("CDXGEN_PLUGINS_DIR", str(tmp_path))
    assert find_golem_binary() is None


# ---------------------------------------------------------------------------
# Go toolchain check
# ---------------------------------------------------------------------------


def test_go_toolchain_available_returns_bool():
    """go_toolchain_available returns a bool (True if go is on PATH)."""
    result = go_toolchain_available()
    assert isinstance(result, bool)


def test_go_toolchain_available_false_when_missing(monkeypatch):
    """When 'go' is not on PATH, returns False (not an exception)."""

    def fake_run(*args, **kwargs):
        raise FileNotFoundError("go not found")

    monkeypatch.setattr("subprocess.run", fake_run)
    assert go_toolchain_available() is False


# ---------------------------------------------------------------------------
# Skipped when binary / toolchain missing
# ---------------------------------------------------------------------------


def test_skipped_when_binary_missing(monkeypatch, tmp_path):
    """Missing binary -> skipped=True (soft fallback), never an exception."""
    monkeypatch.setattr(golem_mod, "find_golem_binary", lambda logger=None: None)
    out = tmp_path / "golem.json"
    result = run_golem(str(tmp_path), str(out))
    assert result.skipped
    assert not result.success


def test_skipped_when_go_toolchain_missing(monkeypatch, tmp_path):
    """Binary present but Go toolchain absent -> skipped=True."""
    fake_bin = str(tmp_path / "golem")
    monkeypatch.setattr(golem_mod, "find_golem_binary", lambda logger=None: fake_bin)
    monkeypatch.setattr(golem_mod, "go_toolchain_available", lambda logger=None: False)
    out = tmp_path / "golem.json"
    result = run_golem(str(tmp_path), str(out))
    assert result.skipped
    assert not result.success


# ---------------------------------------------------------------------------
# Invocation args -- --include-all-flows is REQUIRED
# ---------------------------------------------------------------------------


def test_build_args_always_includes_all_flows():
    """``--include-all-flows`` MUST always be in the invocation args. Without
    it, golem drops flows rooted entirely in the module cache (dependency-internal
    call stacks) -- exactly the CVE-reachability flows we need."""
    args = _build_golem_args(
        "/tmp/src",
        "/tmp/out.json",
        callgraph_mode=DEFAULT_CALLGRAPH_MODE,
        dataflow_mode=DEFAULT_DATAFLOW_MODE,
        deep=False,
    )
    assert "--include-all-flows" in args, (
        "--include-all-flows is REQUIRED for dependency-CVE reachability"
    )
    assert "analyze" in args
    assert "--format" in args
    assert "json" in args
    assert "--callgraph" in args
    assert "static" in args
    assert "--dataflow" in args
    assert "all" in args
    assert "--dataflow-skip-generated" in args
    assert "--dataflow-skip-tests" in args


def test_build_args_deep_reduces_max_slices():
    """Deep mode uses a smaller max-slices (cdxgen's deep default trades breadth
    for per-slice depth)."""
    normal = _build_golem_args(
        "/tmp/src",
        "/tmp/out.json",
        callgraph_mode="static",
        dataflow_mode="all",
        deep=False,
    )
    deep = _build_golem_args(
        "/tmp/src",
        "/tmp/out.json",
        callgraph_mode="static",
        dataflow_mode="all",
        deep=True,
    )
    normal_idx = normal.index("--dataflow-max-slices")
    deep_idx = deep.index("--dataflow-max-slices")
    assert int(normal[normal_idx + 1]) == 1000
    assert int(deep[deep_idx + 1]) == 250


# ---------------------------------------------------------------------------
# Hardened Go env
# ---------------------------------------------------------------------------


def test_hardened_env_default_sets_mod_readonly(monkeypatch):
    """Default env includes GOFLAGS=-mod=readonly to prevent go.mod rewrites."""
    monkeypatch.delenv("GOFLAGS", raising=False)
    monkeypatch.delenv("GOPROXY", raising=False)
    env = _build_hardened_go_env("auto")
    assert env["GOFLAGS"] == "-mod=readonly"
    assert env.get("GOPROXY") != "off"


def test_hardened_env_offline_sets_goproxy_off(monkeypatch):
    """Offline mode sets GOPROXY=off to forbid all module downloads."""
    monkeypatch.delenv("GOFLAGS", raising=False)
    monkeypatch.delenv("GOPROXY", raising=False)
    env = _build_hardened_go_env("offline")
    assert env["GOPROXY"] == "off"
    assert env["GOFLAGS"] == "-mod=readonly"


def test_hardened_env_respects_user_goflags(monkeypatch):
    """User's explicit GOFLAGS is not overridden."""
    monkeypatch.setenv("GOFLAGS", "-mod=mod")
    env = _build_hardened_go_env("auto")
    assert env["GOFLAGS"] == "-mod=mod"


# ---------------------------------------------------------------------------
# run_golem success path
# ---------------------------------------------------------------------------


def test_run_golem_success(stub_binary, monkeypatch, tmp_path):
    """A successful run writes the report and returns success=True."""
    out_path = str(tmp_path / "golem.json")

    captured = {}

    def fake_run(full_cmd, **kwargs):
        captured["args"] = full_cmd
        captured["env"] = kwargs.get("env", {})
        # write a minimal valid report
        import json

        with open(out_path, "w") as f:
            json.dump({"tool": {"name": "golem"}, "callGraph": {"nodes": []}}, f)
        from subprocess import CompletedProcess

        return CompletedProcess(args=full_cmd, returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr("subprocess.run", fake_run)
    result = run_golem(str(tmp_path), out_path)
    assert result.success
    assert result.report_path == out_path
    # the binary is at the front
    assert captured["args"][0] == stub_binary
    assert captured["args"][1] == "analyze"
    # env has hardened GOFLAGS
    assert captured["env"]["GOFLAGS"] == "-mod=readonly"


def test_run_golem_offline_sets_goproxy(stub_binary, monkeypatch, tmp_path):
    """Offline mode propagates GOPROXY=off to the subprocess env."""
    out_path = str(tmp_path / "golem.json")

    captured = {}

    def fake_run(full_cmd, **kwargs):
        captured["env"] = kwargs.get("env", {})
        import json

        with open(out_path, "w") as f:
            json.dump({"tool": {"name": "golem"}, "callGraph": {"nodes": []}}, f)
        from subprocess import CompletedProcess

        return CompletedProcess(args=full_cmd, returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr("subprocess.run", fake_run)
    run_golem(str(tmp_path), out_path, network_mode="offline")
    assert captured["env"]["GOPROXY"] == "off"


def test_run_golem_failure_returns_not_success(stub_binary, monkeypatch, tmp_path):
    """A non-zero exit code with no report -> success=False."""

    def fake_run(full_cmd, **kwargs):
        from subprocess import CompletedProcess

        return CompletedProcess(args=full_cmd, returncode=1, stdout="err", stderr="")

    monkeypatch.setattr("subprocess.run", fake_run)
    out_path = str(tmp_path / "golem.json")
    result = run_golem(str(tmp_path), out_path)
    assert not result.success
    assert not result.skipped
