"""Unit tests for the cgo rule on every local cdxgen invocation.

cdxgen may run golem for a Go project, and a cdxgen release before the
matching golem fix passes its whole environment to golem, so every cdxgen
environment dep-scan builds must carry cgo off unless the operator opted in
with --go-analyzer-cgo. The rule itself lives in xbom_lib.golem.apply_cgo_env;
these tests cover the wiring at each invocation site.
"""

from xbom_lib import cdxgen as cdxgen_mod
from xbom_lib.golem import CGO_ALLOW_ENV_VARS


def _clear_cgo_env(monkeypatch):
    monkeypatch.delenv("CGO_ENABLED", raising=False)
    for var in CGO_ALLOW_ENV_VARS:
        monkeypatch.delenv(var, raising=False)


def _generate_with_captured_env(monkeypatch, tmp_path, options):
    """Run CdxgenGenerator.generate with a stubbed cdxgen command and return
    the environment exec_tool received."""
    captured = {}

    def fake_exec_tool(args, cwd=None, env=None, stdout=None, logger=None):
        captured["env"] = env
        return cdxgen_mod.BOMResult(success=True, command_output="")

    monkeypatch.setattr(cdxgen_mod, "find_cdxgen_cmd", lambda *a, **k: "cdxgen")
    monkeypatch.setattr(cdxgen_mod, "exec_tool", fake_exec_tool)
    gen = cdxgen_mod.CdxgenGenerator(
        str(tmp_path), str(tmp_path / "bom.cdx.json"), options=options
    )
    gen.generate()
    env = captured.get("env")
    assert env is not None, "cdxgen was not started"
    return env


def _container_env_values(run_command_args):
    """The environment arguments handed to ``docker run -e``.

    Each value is either ``NAME`` (forwarded from the host) or
    ``NAME=VALUE`` (explicit).
    """
    values = []
    for i, arg in enumerate(run_command_args):
        if arg == "-e" and i + 1 < len(run_command_args):
            values.append(run_command_args[i + 1])
    return values


def test_cdxgen_env_forces_cgo_off_over_host_env(monkeypatch, tmp_path):
    """The local cdxgen run gets CGO_ENABLED=0 and no CGO_*_ALLOW, even when
    the host environment sets them."""
    _clear_cgo_env(monkeypatch)
    monkeypatch.setenv("CGO_ENABLED", "1")
    monkeypatch.setenv("CGO_CFLAGS_ALLOW", ".*")
    env = _generate_with_captured_env(monkeypatch, tmp_path, {"project_type": ["go"]})
    assert env["CGO_ENABLED"] == "0"
    for var in CGO_ALLOW_ENV_VARS:
        assert var not in env


def test_cdxgen_env_cgo_opt_in_keeps_host_values(monkeypatch, tmp_path):
    """With --go-analyzer-cgo the run keeps the host's CGO_ENABLED and
    CGO_*_ALLOW values."""
    _clear_cgo_env(monkeypatch)
    monkeypatch.setenv("CGO_ENABLED", "1")
    monkeypatch.setenv("CGO_LDFLAGS_ALLOW", "-Wl,.*")
    env = _generate_with_captured_env(
        monkeypatch, tmp_path, {"project_type": ["go"], "go_analyzer_cgo": True}
    )
    assert env["CGO_ENABLED"] == "1"
    assert env["CGO_LDFLAGS_ALLOW"] == "-Wl,.*"


# ---------------------------------------------------------------------------
# The cdxgen container image gets the rule through -e arguments
# ---------------------------------------------------------------------------


def _container_args(monkeypatch, tmp_path, options):
    monkeypatch.setenv("CDXGEN_TEMP_DIR", str(tmp_path))
    gen = cdxgen_mod.CdxgenImageBasedGenerator(
        str(tmp_path), str(tmp_path / "bom.cdx.json"), options=options
    )
    _, run_command_args = gen._container_run_cmd()
    return run_command_args


def test_container_gets_cgo_disabled_by_default(monkeypatch, tmp_path):
    """The default run passes -e CGO_ENABLED=0 into the container exactly
    once and never forwards the host's CGO_*_ALLOW values."""
    _clear_cgo_env(monkeypatch)
    monkeypatch.setenv("CGO_ENABLED", "1")
    monkeypatch.setenv("CGO_CFLAGS_ALLOW", ".*")
    args = _container_args(monkeypatch, tmp_path, {"project_type": ["go"]})
    values = _container_env_values(args)
    assert "CGO_ENABLED=0" in values
    assert sum(1 for v in values if v.split("=")[0] == "CGO_ENABLED") == 1
    for var in CGO_ALLOW_ENV_VARS:
        assert not any(v.split("=")[0] == var for v in values), values


def test_container_cgo_opt_in_forwards_host_values(monkeypatch, tmp_path):
    """With --go-analyzer-cgo the container receives the host's CGO_ENABLED
    and its CGO_*_ALLOW variables, forwarded by name."""
    _clear_cgo_env(monkeypatch)
    monkeypatch.setenv("CGO_ENABLED", "1")
    monkeypatch.setenv("CGO_CFLAGS_ALLOW", ".*")
    args = _container_args(
        monkeypatch, tmp_path, {"project_type": ["go"], "go_analyzer_cgo": True}
    )
    values = _container_env_values(args)
    # Forwarded by name, so docker reads the value from the environment and
    # the value never appears on the command line.
    assert "CGO_ENABLED" in values
    assert "CGO_CFLAGS_ALLOW" in values
    assert not any(".*" in v for v in values), values


def test_container_cgo_opt_in_defaults_cgo_enabled(monkeypatch, tmp_path):
    """Without a host value the opt-in enables cgo inside the container."""
    _clear_cgo_env(monkeypatch)
    args = _container_args(
        monkeypatch, tmp_path, {"project_type": ["go"], "go_analyzer_cgo": True}
    )
    assert "CGO_ENABLED=1" in _container_env_values(args)
