"""Unit tests for the dosai runner (``xbom_lib.dosai``).

These exercise the binary-discovery + invocation logic WITHOUT the real dosai
binary (everything is monkeypatched), so they run unconditionally in CI. The
integration tests in ``test/test_dosai_integration.py`` cover the real binary.
"""

import json

import pytest

from xbom_lib import dosai as dosai_mod
from xbom_lib.dosai import (
    DEFAULT_PATTERN_PACKS,
    DOSAI_BINARY_ENV,
    DOSAI_CMD_ENV,
    DOSAI_DATAFLOWS_COMMAND,
    DOSAI_METHODS_COMMAND,
    DosaiResult,
    _build_dosai_args,
    _dosai_sdk_missing,
    _is_self_contained_binary,
    bundled_dosai_path,
    dotnet_runtime_available,
    find_dosai_binary,
    run_dosai,
)


@pytest.fixture
def stub_binary(monkeypatch, tmp_path):
    """Resolve the binary + runtime without needing dosai or dotnet installed."""
    fake_bin = str(tmp_path / "dosai")
    monkeypatch.setattr(dosai_mod, "find_dosai_binary", lambda logger=None: fake_bin)
    monkeypatch.setattr(dosai_mod, "get_dosai_version", lambda binary, logger=None: "3.0.5")
    monkeypatch.setattr(
        dosai_mod, "dotnet_runtime_available", lambda binary=None, logger=None: True
    )
    return fake_bin


# ---------------------------------------------------------------------------
# Binary discovery -- cdxgen-matching resolution (no real binary required)
# ---------------------------------------------------------------------------


def _clear_binary_env(monkeypatch):
    monkeypatch.delenv(dosai_mod.DOSAI_CMD_ENV, raising=False)
    monkeypatch.delenv(dosai_mod.DOSAI_BINARY_ENV, raising=False)
    monkeypatch.delenv("CDXGEN_PLUGINS_DIR", raising=False)


def test_bundled_dosai_path_matches_cdxgen_layout(tmp_path):
    """Layout MUST be <pluginsDir>/dosai/dosai-<platform>-<arch><extn>,
    matching cdxgen's resolveBundledPluginBinary for the dosai tool across all
    platform/arch tokens. (Upstream Dosai-<platform> assets are RENAMED to this
    lowercase layout by cdxgen-plugins-bin's install step.)"""
    plugins_dir = tmp_path / "plugins"

    def _expect(target, expected_name):
        bin_path = plugins_dir / "dosai" / expected_name
        bin_path.parent.mkdir(parents=True, exist_ok=True)
        bin_path.write_text("")
        assert bundled_dosai_path(str(plugins_dir), target) == str(bin_path), (
            f"expected layout for {target}"
        )

    _expect({"platform": "darwin", "arch": "arm64", "extn": ""}, "dosai-darwin-arm64")
    _expect({"platform": "darwin", "arch": "amd64", "extn": ""}, "dosai-darwin-amd64")
    _expect({"platform": "linux", "arch": "amd64", "extn": ""}, "dosai-linux-amd64")
    _expect({"platform": "linux", "arch": "arm", "extn": ""}, "dosai-linux-arm")
    _expect({"platform": "linux", "arch": "arm64", "extn": ""}, "dosai-linux-arm64")
    _expect(
        {"platform": "linuxmusl", "arch": "amd64", "extn": ""},
        "dosai-linuxmusl-amd64",
    )
    _expect(
        {"platform": "linuxmusl", "arch": "arm64", "extn": ""},
        "dosai-linuxmusl-arm64",
    )
    _expect(
        {"platform": "windows", "arch": "amd64", "extn": ".exe"},
        "dosai-windows-amd64.exe",
    )
    _expect(
        {"platform": "windows", "arch": "arm64", "extn": ".exe"},
        "dosai-windows-arm64.exe",
    )

    # absent on disk -> None (ppc64le was NOT created above)
    assert (
        bundled_dosai_path(str(plugins_dir), {"platform": "linux", "arch": "ppc64le", "extn": ""})
        is None
    )
    assert bundled_dosai_path(None, {"platform": "linux", "arch": "amd64", "extn": ""}) is None
    assert bundled_dosai_path("", {"platform": "linux", "arch": "amd64", "extn": ""}) is None


def test_find_dosai_binary_prefers_dosai_cmd(monkeypatch, tmp_path):
    """DOSAI_CMD (cdxgen's env) wins over DEPSCAN_DOSAI_BINARY and the bundled
    layout, so depscan's fallback resolves the SAME binary cdxgen uses."""
    dosai_cmd = tmp_path / "dosai-via-dosai-cmd"
    dosai_cmd.write_text("")
    depscan_bin = tmp_path / "dosai-via-depscan"
    depscan_bin.write_text("")
    monkeypatch.setenv(dosai_mod.DOSAI_CMD_ENV, str(dosai_cmd))
    monkeypatch.setenv(dosai_mod.DOSAI_BINARY_ENV, str(depscan_bin))
    monkeypatch.setattr("xbom_lib.dosai.find_executable", lambda name: None)
    assert find_dosai_binary() == str(dosai_cmd)


def test_find_dosai_binary_falls_back_to_depscan_env(monkeypatch, tmp_path):
    """Without DOSAI_CMD, the depscan-specific override is honored."""
    depscan_bin = tmp_path / "dosai-via-depscan"
    depscan_bin.write_text("")
    _clear_binary_env(monkeypatch)
    monkeypatch.setenv(dosai_mod.DOSAI_BINARY_ENV, str(depscan_bin))
    monkeypatch.setattr("xbom_lib.dosai.find_executable", lambda name: None)
    assert find_dosai_binary() == str(depscan_bin)


def test_find_dosai_binary_uses_path_lookup_lowercase(monkeypatch, tmp_path):
    """PATH lookup is consulted after the env overrides (lowercase 'dosai')."""
    path_bin = tmp_path / "dosai-on-path"
    path_bin.write_text("")
    _clear_binary_env(monkeypatch)
    # only 'dosai' resolves on PATH
    monkeypatch.setattr("xbom_lib.dosai.find_executable", lambda name: str(path_bin) if name == "dosai" else None)
    assert find_dosai_binary() == str(path_bin)


def test_find_dosai_binary_uses_path_lookup_pascalcase(monkeypatch, tmp_path):
    """The upstream binary is ``Dosai`` -- PATH lookup falls back to the
    PascalCase name when lowercase is absent."""
    path_bin = tmp_path / "Dosai-on-path"
    path_bin.write_text("")
    _clear_binary_env(monkeypatch)
    monkeypatch.setattr("xbom_lib.dosai.find_executable", lambda name: str(path_bin) if name == "Dosai" else None)
    assert find_dosai_binary() == str(path_bin)


def test_find_dosai_binary_resolves_bundled_layout(monkeypatch, tmp_path):
    """Without env overrides or PATH, the cdxgen-plugins-bin bundled layout is
    resolved from CDXGEN_PLUGINS_DIR using the host's platform/arch tokens."""
    from xbom_lib.plugins import get_plugins_bin_target

    plugins_dir = tmp_path / "plugins"
    target = get_plugins_bin_target()
    bin_path = (
        plugins_dir / "dosai" / f"dosai-{target['platform']}-{target['arch']}{target['extn']}"
    )
    bin_path.parent.mkdir(parents=True)
    bin_path.write_text("")
    _clear_binary_env(monkeypatch)
    monkeypatch.setattr("xbom_lib.dosai.find_executable", lambda name: None)
    monkeypatch.setenv("CDXGEN_PLUGINS_DIR", str(plugins_dir))
    assert find_dosai_binary() == str(bin_path)


def test_find_dosai_binary_missing_env_falls_through(monkeypatch, tmp_path):
    """An env var pointing at a non-existent file does NOT short-circuit;
    resolution continues to PATH so a stale override is not fatal."""
    real_on_path = tmp_path / "dosai-real"
    real_on_path.write_text("")
    monkeypatch.setenv(dosai_mod.DOSAI_CMD_ENV, str(tmp_path / "no-such-binary"))
    monkeypatch.delenv(dosai_mod.DOSAI_BINARY_ENV, raising=False)
    monkeypatch.delenv("CDXGEN_PLUGINS_DIR", raising=False)
    monkeypatch.setattr("xbom_lib.dosai.find_executable", lambda name: str(real_on_path))
    assert find_dosai_binary() == str(real_on_path)


def test_find_dosai_binary_returns_none_when_unresolvable(monkeypatch, tmp_path):
    _clear_binary_env(monkeypatch)
    monkeypatch.setattr("xbom_lib.dosai.find_executable", lambda name: None)
    monkeypatch.setenv("CDXGEN_PLUGINS_DIR", str(tmp_path))
    assert find_dosai_binary() is None


# ---------------------------------------------------------------------------
# .NET runtime check
# ---------------------------------------------------------------------------


def test_dotnet_runtime_available_returns_bool():
    """dotnet_runtime_available returns a bool."""
    result = dotnet_runtime_available()
    assert isinstance(result, bool)


def test_dotnet_runtime_available_false_when_missing(monkeypatch):
    """When 'dotnet' is not on PATH (and no self-contained binary), returns
    False (not an exception)."""

    def fake_run(*args, **kwargs):
        raise FileNotFoundError("dotnet not found")

    monkeypatch.setattr("subprocess.run", fake_run)
    assert dotnet_runtime_available() is False


def test_dotnet_runtime_available_self_contained_binary_skips_probe(monkeypatch):
    """A '-full' self-contained binary satisfies the gate WITHOUT probing
    dotnet (the runtime is bundled). The probe must not even run."""

    def fail_if_called(*args, **kwargs):
        raise AssertionError("dotnet --version must not run for a -full binary")

    monkeypatch.setattr("subprocess.run", fail_if_called)
    assert dotnet_runtime_available(binary="/opt/dosai/dosai-linux-amd64-full") is True


def test_is_self_contained_binary_detects_full_suffix():
    assert _is_self_contained_binary("/opt/dosai/dosai-linux-amd64-full") is True
    assert _is_self_contained_binary("/opt/dosai/Dosai-osx-arm64-full") is True
    assert _is_self_contained_binary("/opt/dosai/dosai-linux-amd64") is False
    assert _is_self_contained_binary(None) is False


# ---------------------------------------------------------------------------
# Invocation args -- --pattern-packs ONLY for dataflows
# ---------------------------------------------------------------------------


def test_build_args_dataflows_includes_pattern_packs():
    """dataflows command MUST include --pattern-packs all (maximizes the
    reachability signal, mirror cdxgen's research-profile default)."""
    args = _build_dosai_args("/tmp/src", "/tmp/out.json", DOSAI_DATAFLOWS_COMMAND)
    assert args[0] == DOSAI_DATAFLOWS_COMMAND
    assert "--path" in args
    assert "--o" in args
    assert "--pattern-packs" in args
    assert DEFAULT_PATTERN_PACKS in args


def test_build_args_methods_omits_pattern_packs():
    """The methods command does NOT accept --pattern-packs (System.CommandLine
    rejects it -- verified in Dosai/CommandLine.cs). Passing it would break the
    run, so it MUST be omitted (mirror cdxgen's runDosaiCommand)."""
    args = _build_dosai_args("/tmp/src", "/tmp/out.json", DOSAI_METHODS_COMMAND)
    assert args[0] == DOSAI_METHODS_COMMAND
    assert "--path" in args
    assert "--o" in args
    assert "--pattern-packs" not in args


# ---------------------------------------------------------------------------
# SDK-missing detection
# ---------------------------------------------------------------------------


def test_dosai_sdk_missing_detects_known_markers():
    """dosai prints one of these when no .NET runtime is present; detection
    triggers a graceful skip (not a hard failure)."""
    assert _dosai_sdk_missing("Dotnet SDK is not installed. Aborting.")
    assert _dosai_sdk_missing("You must install or update .NET to run this application.")
    assert not _dosai_sdk_missing("Analysis complete.")
    assert not _dosai_sdk_missing("")


# ---------------------------------------------------------------------------
# Skipped when binary / runtime missing
# ---------------------------------------------------------------------------


def test_skipped_when_binary_missing(monkeypatch, tmp_path):
    """Missing binary -> skipped=True (soft fallback), never an exception."""
    monkeypatch.setattr(dosai_mod, "find_dosai_binary", lambda logger=None: None)
    result = run_dosai(str(tmp_path), str(tmp_path))
    assert result.skipped
    assert not result.success


def test_skipped_when_dotnet_runtime_missing(monkeypatch, tmp_path):
    """Binary present but .NET runtime absent (and not a -full binary) ->
    skipped=True."""
    fake_bin = str(tmp_path / "dosai")
    monkeypatch.setattr(dosai_mod, "find_dosai_binary", lambda logger=None: fake_bin)
    monkeypatch.setattr(
        dosai_mod, "dotnet_runtime_available", lambda binary=None, logger=None: False
    )
    result = run_dosai(str(tmp_path), str(tmp_path))
    assert result.skipped
    assert not result.success


def test_skipped_when_dosai_reports_missing_sdk(stub_binary, monkeypatch, tmp_path):
    """If dosai itself prints the SDK-missing marker mid-run, the run is
    skipped (not failed) with a diagnostic."""
    from subprocess import CompletedProcess

    def fake_run(full_cmd, **kwargs):
        return CompletedProcess(
            args=full_cmd,
            returncode=1,
            stdout="Dotnet SDK is not installed. Aborting.",
            stderr="",
        )

    monkeypatch.setattr("subprocess.run", fake_run)
    result = run_dosai(str(tmp_path), str(tmp_path))
    assert result.skipped
    assert not result.success
    assert "Dotnet SDK" in result.command_output


# ---------------------------------------------------------------------------
# run_dosai success path (persists BOTH native artifacts)
# ---------------------------------------------------------------------------


def test_run_dosai_success_writes_both_artifacts(stub_binary, monkeypatch, tmp_path):
    """A successful run persists dotnet-dataflows.json + dotnet-methods.json
    (source of truth) and returns success=True with both paths set."""
    out_dir = tmp_path / "bom"
    out_dir.mkdir()
    captured = {}

    def fake_run(full_cmd, **kwargs):
        captured.setdefault("invocations", []).append((list(full_cmd), kwargs))
        # dosai args: [binary, command, "--path", src, "--o", out, ...]
        out_idx = full_cmd.index("--o") + 1
        out_path = full_cmd[out_idx]
        with open(out_path, "w") as f:
            json.dump(
                {"Metadata": {"Tool": "Dosai"}, "PackageReachability": []},
                f,
            )
        from subprocess import CompletedProcess

        return CompletedProcess(args=full_cmd, returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr("subprocess.run", fake_run)
    result = run_dosai(str(tmp_path), str(out_dir))
    assert result.success
    assert result.methods_path == str(out_dir / "dotnet-methods.json")
    assert result.dataflows_path == str(out_dir / "dotnet-dataflows.json")
    assert result.version == "3.0.5"
    # BOTH commands were invoked (dataflows + methods)
    invoked_cmds = [inv[0][1] for inv in captured["invocations"]]
    assert DOSAI_DATAFLOWS_COMMAND in invoked_cmds
    assert DOSAI_METHODS_COMMAND in invoked_cmds
    # the binary is at the front, shell disabled, cwd passed through
    for full_cmd, kwargs in captured["invocations"]:
        assert full_cmd[0] == stub_binary
        assert kwargs.get("shell") is False
        assert "cwd" in kwargs


def test_run_dosai_dataflows_only_is_still_success(stub_binary, monkeypatch, tmp_path):
    """If only dataflows succeeds (methods fails), success is still True --
    dataflows carries its own PackageReachability so reachability is usable."""
    out_dir = tmp_path / "bom"
    out_dir.mkdir()

    def fake_run(full_cmd, **kwargs):
        from subprocess import CompletedProcess

        cmd = full_cmd[1]
        if cmd == DOSAI_DATAFLOWS_COMMAND:
            out_path = full_cmd[full_cmd.index("--o") + 1]
            with open(out_path, "w") as f:
                json.dump({"Metadata": {"Tool": "Dosai"}}, f)
            return CompletedProcess(args=full_cmd, returncode=0, stdout="ok", stderr="")
        return CompletedProcess(args=full_cmd, returncode=2, stdout="methods err", stderr="")

    monkeypatch.setattr("subprocess.run", fake_run)
    result = run_dosai(str(tmp_path), str(out_dir))
    assert result.success
    assert result.dataflows_path is not None
    assert result.methods_path is None


def test_run_dosai_failure_when_no_artifact(stub_binary, monkeypatch, tmp_path):
    """Both commands fail with no artifact -> success=False (and not skipped:
    this is a real failure, not a missing-runtime skip)."""
    from subprocess import CompletedProcess

    def fake_run(full_cmd, **kwargs):
        return CompletedProcess(args=full_cmd, returncode=1, stdout="err", stderr="")

    monkeypatch.setattr("subprocess.run", fake_run)
    result = run_dosai(str(tmp_path), str(tmp_path))
    assert not result.success
    assert not result.skipped


def test_run_dosai_creats_out_dir(stub_binary, monkeypatch, tmp_path):
    """The output directory is created if it does not yet exist."""
    nested = tmp_path / "nested" / "bom"

    def fake_run(full_cmd, **kwargs):
        out_path = full_cmd[full_cmd.index("--o") + 1]
        with open(out_path, "w") as f:
            json.dump({"Metadata": {"Tool": "Dosai"}}, f)
        from subprocess import CompletedProcess

        return CompletedProcess(args=full_cmd, returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr("subprocess.run", fake_run)
    result = run_dosai(str(tmp_path), str(nested))
    assert result.success
    assert nested.is_dir()


def test_dosai_result_dataclass_defaults():
    """DosaiResult defaults are all falsy/None (safe soft-fallback shape)."""
    r = DosaiResult()
    assert r.success is False
    assert r.methods_path is None
    assert r.dataflows_path is None
    assert r.skipped is False
    assert r.command_output == ""
    assert r.version is None
    assert r.timed_out is False


def test_constants_align_with_cdxgen():
    """The env-var names match cdxgen's PLUGIN_ENV_COMMAND_NAMES so depscan's
    fallback resolves the SAME binary cdxgen uses."""
    assert DOSAI_CMD_ENV == "DOSAI_CMD"
    assert DOSAI_BINARY_ENV == "DEPSCAN_DOSAI_BINARY"
