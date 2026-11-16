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
    CGO_ALLOW_ENV_VARS,
    _build_golem_args,
    _build_hardened_go_env,
    bundled_golem_path,
    find_golem_binary,
    go_toolchain_available,
    go_toolchain_has_cgo_fixes,
    go_toolchain_version,
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
# cgo is forced off unless the operator opted in
# ---------------------------------------------------------------------------


def _clear_cgo_env(monkeypatch):
    monkeypatch.delenv("CGO_ENABLED", raising=False)
    for var in CGO_ALLOW_ENV_VARS:
        monkeypatch.delenv(var, raising=False)


def test_hardened_env_forces_cgo_off_over_caller_env(monkeypatch):
    """CGO_ENABLED=0 and no CGO_*_ALLOW, even when the caller's environment
    sets them. CI images export CGO_ENABLED=1 for their own builds; that must
    not turn cgo on for a scan."""
    _clear_cgo_env(monkeypatch)
    monkeypatch.setenv("CGO_ENABLED", "1")
    monkeypatch.setenv("CGO_CFLAGS_ALLOW", ".*")
    monkeypatch.setenv("CGO_LDFLAGS_ALLOW", "-Wl,.*")
    monkeypatch.setenv("CGO_CPPFLAGS_ALLOW", "-I.*")
    env = _build_hardened_go_env("auto")
    assert env["CGO_ENABLED"] == "0"
    for var in CGO_ALLOW_ENV_VARS:
        assert var not in env


def test_hardened_env_cgo_opt_in_keeps_caller_values(monkeypatch):
    """The opt-in keeps the caller's CGO_ENABLED and CGO_*_ALLOW values."""
    _clear_cgo_env(monkeypatch)
    monkeypatch.setenv("CGO_ENABLED", "1")
    monkeypatch.setenv("CGO_CFLAGS_ALLOW", ".*")
    monkeypatch.setenv("CGO_LDFLAGS_ALLOW", "-Wl,.*")
    env = _build_hardened_go_env("auto", allow_cgo=True)
    assert env["CGO_ENABLED"] == "1"
    assert env["CGO_CFLAGS_ALLOW"] == ".*"
    assert env["CGO_LDFLAGS_ALLOW"] == "-Wl,.*"


def test_hardened_env_cgo_opt_in_defaults_cgo_enabled_to_1(monkeypatch):
    """Without a caller value, the opt-in enables cgo explicitly."""
    _clear_cgo_env(monkeypatch)
    env = _build_hardened_go_env("auto", allow_cgo=True)
    assert env["CGO_ENABLED"] == "1"


def test_run_golem_env_forces_cgo_off(stub_binary, monkeypatch, tmp_path):
    """The subprocess env run_golem hands over has cgo off by default, even
    when the caller's environment sets CGO_ENABLED and CGO_*_ALLOW."""
    _clear_cgo_env(monkeypatch)
    monkeypatch.setenv("CGO_ENABLED", "1")
    monkeypatch.setenv("CGO_CFLAGS_ALLOW", ".*")
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
    result = run_golem(str(tmp_path), out_path)
    assert result.success
    assert captured["env"]["CGO_ENABLED"] == "0"
    assert "CGO_CFLAGS_ALLOW" not in captured["env"]


# ---------------------------------------------------------------------------
# Go release check behind the cgo opt-in
# ---------------------------------------------------------------------------


def _fake_go_version(monkeypatch, output, rc=0):
    """Point ``go version`` at fixed output and let the golem run succeed.

    The fake answers every subprocess call: a command carrying ``go version``
    gets ``output``, and a golem invocation (it carries ``--out``) writes a
    minimal valid report so the caller sees a successful run.
    """

    import json
    from subprocess import CompletedProcess

    def fake_run(full_cmd, **kwargs):
        parts = [str(part) for part in full_cmd]
        if "--out" in parts:
            out_path = parts[parts.index("--out") + 1]
            with open(out_path, "w") as f:
                json.dump({"tool": {"name": "golem"}, "callGraph": {"nodes": []}}, f)
            return CompletedProcess(args=full_cmd, returncode=0, stdout="ok", stderr="")
        return CompletedProcess(args=full_cmd, returncode=rc, stdout=output, stderr="")

    monkeypatch.setattr("subprocess.run", fake_run)


@pytest.mark.parametrize(
    "output,expected",
    [
        ("go version go1.26.10 X:boringcrypto linux/amd64", "go1.26.10"),
        ("go version go1.27.4 darwin/arm64", "go1.27.4"),
        ("go version go1.26.11 linux/amd64", "go1.26.11"),
        ("go version go1.28rc1 linux/amd64", "go1.28rc1"),
        ("go version go1.29beta1 linux/amd64", "go1.29beta1"),
        ("go version devel +2a4b6c8 Darwin/arm64", "devel"),
    ],
)
def test_go_toolchain_version_parses_release_forms(monkeypatch, output, expected):
    """go_toolchain_version reads the release token out of ``go version``
    output, including the boringcrypto annotation, release candidates, beta
    builds and source builds."""
    _fake_go_version(monkeypatch, output)
    assert go_toolchain_version() == expected


def test_go_toolchain_version_none_when_missing(monkeypatch):
    _fake_go_version(monkeypatch, "", rc=1)
    assert go_toolchain_version() is None


@pytest.mark.parametrize(
    "release,patched",
    [
        ("go1.26.10", False),
        ("go1.26.11", True),
        ("go1.26.12", True),
        ("go1.27.3", False),
        ("go1.27.4", True),
        ("go1.27rc2", False),
        ("go1.28rc1", True),
        ("go1.29beta1", True),
        ("go1.25.5", False),
        ("go1.24.0", False),
        ("devel", True),
        (None, True),
    ],
)
def test_go_toolchain_has_cgo_fixes(release, patched):
    """The 1.26 line needs 1.26.11, the 1.27 line needs 1.27.4, older lines
    are unpatched, and release candidates of later lines count as fixed."""
    assert go_toolchain_has_cgo_fixes(release) is patched


def test_run_golem_cgo_opt_in_warns(stub_binary, monkeypatch, tmp_path, caplog):
    """The opt-in logs one warning about the C compiler and a second one when
    the toolchain predates the fixed releases."""
    import logging

    _clear_cgo_env(monkeypatch)
    _fake_go_version(monkeypatch, "go version go1.26.10 X:boringcrypto linux/amd64")
    out_path = str(tmp_path / "golem.json")
    result = run_golem(
        str(tmp_path), out_path, allow_cgo=True, logger=logging.getLogger("golem-test")
    )
    assert result.success
    messages = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
    assert any("C compiler will run with flags taken from the scanned code" in m for m in messages)
    assert any("go1.26.11" in m and "go1.27.4" in m for m in messages)


def test_run_golem_cgo_opt_in_warns_once_when_patched(stub_binary, monkeypatch, tmp_path, caplog):
    """A patched toolchain gets the cgo warning but not the release warning."""
    import logging

    _clear_cgo_env(monkeypatch)
    _fake_go_version(monkeypatch, "go version go1.27.4 darwin/arm64")
    out_path = str(tmp_path / "golem.json")
    result = run_golem(
        str(tmp_path), out_path, allow_cgo=True, logger=logging.getLogger("golem-test")
    )
    assert result.success
    messages = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
    assert any("C compiler will run with flags taken from the scanned code" in m for m in messages)
    assert not any("predates the releases" in m for m in messages)


def test_run_golem_no_cgo_warning_by_default(monkeypatch, tmp_path, caplog):
    """Without the opt-in, no cgo warnings are logged and the release probe
    does not run a second time."""
    import logging

    fake_bin = str(tmp_path / "golem")
    monkeypatch.setattr(golem_mod, "find_golem_binary", lambda logger=None: fake_bin)
    monkeypatch.setattr(golem_mod, "get_golem_version", lambda binary, logger=None: "2.5.2")
    monkeypatch.setattr(golem_mod, "_peek_report", lambda out_path: (True, "ok"))
    monkeypatch.setattr(golem_mod, "_check_truncation", lambda out_path, logger=None: None)
    _clear_cgo_env(monkeypatch)
    calls = []
    import json
    from subprocess import CompletedProcess

    def fake_run(full_cmd, **kwargs):
        calls.append([str(part) for part in full_cmd])
        parts = [str(part) for part in full_cmd]
        if "--out" in parts:
            out_path = parts[parts.index("--out") + 1]
            with open(out_path, "w") as f:
                json.dump({"tool": {"name": "golem"}, "callGraph": {"nodes": []}}, f)
            return CompletedProcess(args=full_cmd, returncode=0, stdout="ok", stderr="")
        return CompletedProcess(
            args=full_cmd,
            returncode=0,
            stdout="go version go1.26.10 linux/amd64",
            stderr="",
        )

    monkeypatch.setattr("subprocess.run", fake_run)
    result = run_golem(
        str(tmp_path), str(tmp_path / "golem.json"), logger=logging.getLogger("golem-test")
    )
    assert result.success
    messages = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
    assert not any("C compiler" in m for m in messages)
    # One `go version` probe (availability), no second probe for the release.
    assert sum(1 for cmd in calls if cmd[1:2] == ["version"]) == 1


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
