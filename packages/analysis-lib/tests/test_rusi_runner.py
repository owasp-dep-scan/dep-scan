"""Unit tests for the rusi runner (``xbom_lib.rusi``).

These exercise the binary-discovery + invocation logic WITHOUT the real rusi
binary (everything is monkeypatched), so they run unconditionally in CI. The
integration tests in ``test/test_rusi_integration.py`` cover the real binary.
"""

from types import SimpleNamespace
from typing import List

import pytest

from xbom_lib import rusi as rusi_mod
from xbom_lib.rusi import DEFAULT_BACKEND, RusiResult, run_rusi


def _ok_result(backend: str) -> RusiResult:
    return RusiResult(
        success=True,
        report_path=f"/tmp/fake-rusi-{backend}.json",
        command_output="ok",
        version="2.5.2",
    )


def _fail_result() -> RusiResult:
    return RusiResult(success=False, command_output="compiler build failed", version="2.5.2")


@pytest.fixture
def stub_binary(monkeypatch, tmp_path):
    """Resolve the binary + version without needing rusi installed."""
    fake_bin = str(tmp_path / "rusi")
    monkeypatch.setattr(rusi_mod, "find_rusi_binary", lambda logger=None: fake_bin)
    monkeypatch.setattr(rusi_mod, "get_rusi_version", lambda binary, logger=None: "2.5.2")
    monkeypatch.setattr(rusi_mod, "_peek_report", lambda out_path: (True, "ok"))
    return fake_bin


def test_compiler_backend_falls_back_to_stable_on_failure(stub_binary, monkeypatch, tmp_path):
    """When a ``compiler`` run produces no report, ``run_rusi`` MUST retry once
    on the ``stable`` backend and succeed, so reachability degrades instead of
    being lost."""
    calls: List[SimpleNamespace] = []

    def fake_once(binary, abs_src_dir, out_path, **kwargs):
        calls.append(SimpleNamespace(backend=kwargs["backend"]))
        if kwargs["backend"] == "compiler":
            return _fail_result()
        return _ok_result(kwargs["backend"])

    monkeypatch.setattr(rusi_mod, "_run_rusi_once", fake_once)

    out = tmp_path / "rusi.json"
    result = run_rusi(str(tmp_path), str(out), backend="compiler")

    assert result.success, "compiler failure must fall back to stable and succeed"
    assert [c.backend for c in calls] == ["compiler", DEFAULT_BACKEND], (
        "run_rusi must retry exactly once on the stable backend after a compiler failure"
    )


def test_stable_backend_does_not_retry(stub_binary, monkeypatch, tmp_path):
    """A failed ``stable`` run MUST NOT retry (it would just repeat)."""
    calls: List[SimpleNamespace] = []

    def fake_once(binary, abs_src_dir, out_path, **kwargs):
        calls.append(SimpleNamespace(backend=kwargs["backend"]))
        return _fail_result()

    monkeypatch.setattr(rusi_mod, "_run_rusi_once", fake_once)

    out = tmp_path / "rusi.json"
    result = run_rusi(str(tmp_path), str(out), backend=DEFAULT_BACKEND)

    assert not result.success
    assert len(calls) == 1, "a stable failure must not trigger a retry"


def test_compiler_timeout_does_not_fall_back(stub_binary, monkeypatch, tmp_path):
    """A compiler run that TIMED OUT must NOT retry on stable -- a stable run
    would likely time out too, doubling the wall-clock. Only non-timeout
    failures fall back."""
    calls: List[SimpleNamespace] = []

    def fake_once(binary, abs_src_dir, out_path, **kwargs):
        calls.append(SimpleNamespace(backend=kwargs["backend"]))
        return RusiResult(
            success=False, command_output="timed out", version="2.5.2", timed_out=True
        )

    monkeypatch.setattr(rusi_mod, "_run_rusi_once", fake_once)

    out = tmp_path / "rusi.json"
    result = run_rusi(str(tmp_path), str(out), backend="compiler")

    assert not result.success
    assert len(calls) == 1, "a timed-out compiler run must not trigger a stable retry"


def test_skipped_when_binary_missing(monkeypatch, tmp_path):
    """Missing binary -> skipped=True (soft fallback), never an exception."""
    monkeypatch.setattr(rusi_mod, "find_rusi_binary", lambda logger=None: None)
    out = tmp_path / "rusi.json"
    result = run_rusi(str(tmp_path), str(out))
    assert result.skipped
    assert not result.success


# ---------------------------------------------------------------------------
# Binary discovery -- cdxgen-matching resolution (no real binary required)
# ---------------------------------------------------------------------------


def _clear_binary_env(monkeypatch):
    monkeypatch.delenv(rusi_mod.RUSI_CMD_ENV, raising=False)
    monkeypatch.delenv(rusi_mod.RUSI_BINARY_ENV, raising=False)
    monkeypatch.delenv("CDXGEN_PLUGINS_DIR", raising=False)


def test_get_plugins_bin_target_has_cdxgen_shape():
    """The target tuple mirrors cdxgen's getPluginsBinTarget keys/tokens."""
    import sys

    t = rusi_mod.get_plugins_bin_target()
    assert set(t) == {"platform", "arch", "extn"}
    # .exe only on windows
    assert (t["extn"] == ".exe") == (sys.platform == "win32")
    # cdxgen's normalized platform vocabulary
    assert t["platform"] in {"darwin", "linux", "linuxmusl", "windows"}
    # arch is always a non-empty token
    assert t["arch"]


def test_bundled_rusi_path_matches_cdxgen_layout(tmp_path):
    """Layout MUST be <pluginsDir>/rusi/rusi-<platform>-<arch><extn>, matching
    cdxgen's resolveBundledPluginBinary for the rusi tool across all platform
    tokens (darwin/linux/linuxmusl/windows) and arch tokens."""
    plugins_dir = tmp_path / "plugins"

    def _expect(target, expected_name):
        bin_path = plugins_dir / "rusi" / expected_name
        bin_path.parent.mkdir(parents=True, exist_ok=True)
        bin_path.write_text("")
        assert rusi_mod.bundled_rusi_path(str(plugins_dir), target) == str(bin_path), (
            f"expected layout for {target}"
        )

    _expect({"platform": "darwin", "arch": "arm64", "extn": ""}, "rusi-darwin-arm64")
    _expect({"platform": "linux", "arch": "amd64", "extn": ""}, "rusi-linux-amd64")
    _expect(
        {"platform": "linuxmusl", "arch": "amd64", "extn": ""},
        "rusi-linuxmusl-amd64",
    )
    _expect(
        {"platform": "windows", "arch": "amd64", "extn": ".exe"},
        "rusi-windows-amd64.exe",
    )
    _expect({"platform": "linux", "arch": "ppc64le", "extn": ""}, "rusi-linux-ppc64le")

    # a missing platform/arch combination resolves to None (not a crash)
    assert (
        rusi_mod.bundled_rusi_path(
            str(plugins_dir), {"platform": "linux", "arch": "arm64", "extn": ""}
        )
        is None
    )
    # empty/None plugins dir -> None (chainable)
    assert (
        rusi_mod.bundled_rusi_path(None, {"platform": "linux", "arch": "amd64", "extn": ""})
        is None
    )
    assert (
        rusi_mod.bundled_rusi_path("", {"platform": "linux", "arch": "amd64", "extn": ""}) is None
    )


def test_find_rusi_binary_prefers_rusi_cmd(monkeypatch, tmp_path):
    """RUSI_CMD (cdxgen's env) wins over DEPSCAN_RUSI_BINARY and the bundled
    layout, so depscan's fallback resolves the SAME binary cdxgen uses."""
    rusi_cmd = tmp_path / "rusi-via-rusi-cmd"
    rusi_cmd.write_text("")
    depscan_bin = tmp_path / "rusi-via-depscan"
    depscan_bin.write_text("")
    monkeypatch.setenv(rusi_mod.RUSI_CMD_ENV, str(rusi_cmd))
    monkeypatch.setenv(rusi_mod.RUSI_BINARY_ENV, str(depscan_bin))
    monkeypatch.setattr("xbom_lib.rusi.find_executable", lambda name: None)
    assert rusi_mod.find_rusi_binary() == str(rusi_cmd)


def test_find_rusi_binary_falls_back_to_depscan_env(monkeypatch, tmp_path):
    """Without RUSI_CMD, the depscan-specific override is honored."""
    depscan_bin = tmp_path / "rusi-via-depscan"
    depscan_bin.write_text("")
    _clear_binary_env(monkeypatch)
    monkeypatch.setenv(rusi_mod.RUSI_BINARY_ENV, str(depscan_bin))
    monkeypatch.setattr("xbom_lib.rusi.find_executable", lambda name: None)
    assert rusi_mod.find_rusi_binary() == str(depscan_bin)


def test_find_rusi_binary_uses_path_lookup(monkeypatch, tmp_path):
    """PATH lookup (find_executable) is consulted after the env overrides."""
    path_bin = tmp_path / "rusi-on-path"
    path_bin.write_text("")
    _clear_binary_env(monkeypatch)
    monkeypatch.setattr("xbom_lib.rusi.find_executable", lambda name: str(path_bin))
    assert rusi_mod.find_rusi_binary() == str(path_bin)


def test_find_rusi_binary_resolves_bundled_layout(monkeypatch, tmp_path):
    """Without env overrides or PATH, the cdxgen-plugins-bin bundled layout is
    resolved from CDXGEN_PLUGINS_DIR using the host's platform/arch tokens."""
    plugins_dir = tmp_path / "plugins"
    target = rusi_mod.get_plugins_bin_target()
    bin_path = plugins_dir / "rusi" / f"rusi-{target['platform']}-{target['arch']}{target['extn']}"
    bin_path.parent.mkdir(parents=True)
    bin_path.write_text("")
    _clear_binary_env(monkeypatch)
    monkeypatch.setattr("xbom_lib.rusi.find_executable", lambda name: None)
    monkeypatch.setenv("CDXGEN_PLUGINS_DIR", str(plugins_dir))
    assert rusi_mod.find_rusi_binary() == str(bin_path)


def test_find_rusi_binary_missing_env_falls_through(monkeypatch, tmp_path):
    """An env var pointing at a non-existent file does NOT short-circuit;
    resolution continues to PATH so a stale override is not fatal."""
    real_on_path = tmp_path / "rusi-real"
    real_on_path.write_text("")
    monkeypatch.setenv(rusi_mod.RUSI_CMD_ENV, str(tmp_path / "no-such-binary"))
    monkeypatch.delenv(rusi_mod.RUSI_BINARY_ENV, raising=False)
    monkeypatch.delenv("CDXGEN_PLUGINS_DIR", raising=False)
    monkeypatch.setattr("xbom_lib.rusi.find_executable", lambda name: str(real_on_path))
    assert rusi_mod.find_rusi_binary() == str(real_on_path)


def test_find_rusi_binary_returns_none_when_unresolvable(monkeypatch, tmp_path):
    _clear_binary_env(monkeypatch)
    monkeypatch.setattr("xbom_lib.rusi.find_executable", lambda name: None)
    # CDXGEN_PLUGINS_DIR points at a dir without the rusi binary
    monkeypatch.setenv("CDXGEN_PLUGINS_DIR", str(tmp_path))
    assert rusi_mod.find_rusi_binary() is None
