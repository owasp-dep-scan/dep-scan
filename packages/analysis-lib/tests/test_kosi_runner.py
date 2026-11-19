"""Unit tests for the kosi runner (``xbom_lib.kosi``); no kosi binary needed."""

import json
from subprocess import CompletedProcess

import pytest

from xbom_lib import kosi as kosi_mod
from xbom_lib.kosi import (
    _build_kosi_args,
    bundled_kosi_path,
    find_kosi_binary,
    get_kosi_version,
    run_kosi,
)


def _clear_env(monkeypatch):
    for name in (kosi_mod.KOSI_CMD_ENV, kosi_mod.KOSI_BINARY_ENV, "CDXGEN_PLUGINS_DIR"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(kosi_mod, "find_executable", lambda name: None)


def test_bundled_kosi_path_layout(tmp_path):
    target = {"platform": "darwin", "arch": "arm64", "extn": ""}
    binary = tmp_path / "kosi" / "kosi-darwin-arm64"
    binary.parent.mkdir()
    binary.write_text("")
    assert bundled_kosi_path(str(tmp_path), target) == str(binary)
    assert bundled_kosi_path(str(tmp_path), {**target, "arch": "amd64"}) is None
    assert bundled_kosi_path(None, target) is None


def test_find_kosi_binary_prefers_kosi_cmd_then_depscan_env(monkeypatch, tmp_path):
    _clear_env(monkeypatch)
    cmd, own = tmp_path / "cmd", tmp_path / "own"
    cmd.write_text("")
    own.write_text("")
    monkeypatch.setenv(kosi_mod.KOSI_BINARY_ENV, str(own))
    assert find_kosi_binary() == str(own)
    monkeypatch.setenv(kosi_mod.KOSI_CMD_ENV, str(cmd))
    assert find_kosi_binary() == str(cmd)


def test_find_kosi_binary_uses_plugins_dir_and_returns_none_otherwise(monkeypatch, tmp_path):
    _clear_env(monkeypatch)
    assert find_kosi_binary() is None
    target = {"platform": "linux", "arch": "amd64", "extn": ""}
    monkeypatch.setattr(kosi_mod, "get_plugins_bin_target", lambda: target)
    binary = tmp_path / "kosi" / "kosi-linux-amd64"
    binary.parent.mkdir()
    binary.write_text("")
    monkeypatch.setenv("CDXGEN_PLUGINS_DIR", str(tmp_path))
    assert find_kosi_binary() == str(binary)


def test_syntax_args_pass_no_dataflow_or_callgraph_flags():
    args = _build_kosi_args("/src", "/out.json", backend="syntax")
    assert args[args.index("--backend") + 1] == "syntax"
    assert "--dataflow" not in args
    assert "--callgraph" not in args


def test_resolved_args_add_callgraph_and_dataflow():
    args = _build_kosi_args("/src", "/out.json", backend="resolved")
    assert args[args.index("--callgraph") + 1] == "static"
    assert args[args.index("--dataflow") + 1] == "security"


def test_version_is_read_from_json_stdout(monkeypatch):
    out = json.dumps({"version": "4.3.1", "schemaVersion": "kosi/1"})
    monkeypatch.setattr(
        "subprocess.run", lambda cmd, **kw: CompletedProcess(cmd, 0, stdout=out, stderr="")
    )
    assert get_kosi_version("/x/kosi") == "4.3.1"
    monkeypatch.setattr(
        "subprocess.run", lambda cmd, **kw: CompletedProcess(cmd, 0, stdout="not json", stderr="")
    )
    assert get_kosi_version("/x/kosi") is None


def test_run_kosi_skips_when_binary_missing(monkeypatch, tmp_path):
    _clear_env(monkeypatch)
    res = run_kosi(str(tmp_path), str(tmp_path / "kosi.json"))
    assert res.skipped and not res.success


def test_run_kosi_defaults_to_the_syntax_backend(monkeypatch, tmp_path):
    out_path = str(tmp_path / "kosi.json")
    monkeypatch.setattr(kosi_mod, "find_kosi_binary", lambda logger=None: "/x/kosi")
    monkeypatch.setattr(kosi_mod, "get_kosi_version", lambda binary, logger=None: "4.3.1")
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        with open(out_path, "w") as fp:
            json.dump({"schemaVersion": "kosi/1", "tool": {"name": "kosi"}}, fp)
        return CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("subprocess.run", fake_run)
    res = run_kosi(str(tmp_path), out_path)
    assert res.success and res.report_path == out_path
    assert res.backend == "syntax"
    assert "syntax" in captured["cmd"]


def test_run_kosi_failure_has_no_report(monkeypatch, tmp_path):
    monkeypatch.setattr(kosi_mod, "find_kosi_binary", lambda logger=None: "/x/kosi")
    monkeypatch.setattr(kosi_mod, "get_kosi_version", lambda binary, logger=None: None)
    monkeypatch.setattr(
        "subprocess.run", lambda cmd, **kw: CompletedProcess(cmd, 2, stdout="usage", stderr="")
    )
    res = run_kosi(str(tmp_path), str(tmp_path / "kosi.json"))
    assert not res.success and not res.skipped


@pytest.mark.parametrize(
    ("data", "ok"),
    [
        ({"schemaVersion": "kosi/1"}, True),
        ({"schemaVersion": "golem/1"}, False),
        ([], False),
    ],
)
def test_peek_report(tmp_path, data, ok):
    path = tmp_path / "r.json"
    path.write_text(json.dumps(data))
    assert kosi_mod._peek_report(str(path))[0] is ok
