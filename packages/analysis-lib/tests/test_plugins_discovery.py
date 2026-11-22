"""The plugins directory found beside the cdxgen install.

cdxgen ships golem, rusi, dosai and kosi in ``@cdxgen/cdxgen-plugins-bin``,
installed next to it. The finders must use that directory when neither an
override nor ``CDXGEN_PLUGINS_DIR`` names a binary, as cdxgen does.
"""

import json
import os

import pytest
from xbom_lib import dosai as dosai_mod
from xbom_lib import golem as golem_mod
from xbom_lib import kosi as kosi_mod
from xbom_lib import plugins as plugins_mod
from xbom_lib import rusi as rusi_mod
from xbom_lib.plugins import discover_plugins_dir, get_plugins_bin_target

_REAL_RESOLVE_CDXGEN_PATH = plugins_mod.resolve_cdxgen_path

TOOLS = {
    "golem": golem_mod.find_golem_binary,
    "rusi": rusi_mod.find_rusi_binary,
    "dosai": dosai_mod.find_dosai_binary,
    "kosi": kosi_mod.find_kosi_binary,
}


def _make_plugins(plugins_dir, tools=tuple(TOOLS)):
    target = get_plugins_bin_target()
    paths = {}
    for tool in tools:
        path = plugins_dir / tool / f"{tool}-{target['platform']}-{target['arch']}{target['extn']}"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#!/bin/sh\n", encoding="utf-8")
        path.chmod(0o755)
        paths[tool] = path
    return paths


@pytest.fixture
def install(tmp_path, monkeypatch):
    """A cdxgen install with its plugins package; cdxgen is only on PATH."""
    monkeypatch.setattr(plugins_mod, "resolve_cdxgen_path", _REAL_RESOLVE_CDXGEN_PATH)
    for var in (
        "CDXGEN_PLUGINS_DIR",
        "CDXGEN_CMD",
        *[f"{t.upper()}_CMD" for t in TOOLS],
        *[f"DEPSCAN_{t.upper()}_BINARY" for t in TOOLS],
    ):
        monkeypatch.delenv(var, raising=False)
    target = get_plugins_bin_target()
    root = tmp_path / "depscan-tools" / "cdxgen"
    plugins = (
        root
        / "node_modules"
        / "@cdxgen"
        / f"cdxgen-plugins-bin-{target['platform']}-{target['arch']}"
        / "plugins"
    )
    binaries = _make_plugins(plugins)
    (plugins.parent / "package.json").write_text("{}", encoding="utf-8")
    (root / "bin").mkdir(parents=True)
    (root / "package.json").write_text("{}", encoding="utf-8")
    entry = root / "bin" / "cdxgen"
    entry.write_text("#!/bin/sh\n", encoding="utf-8")
    entry.chmod(0o755)
    path_dir = tmp_path / "path"
    path_dir.mkdir()
    try:
        (path_dir / "cdxgen").symlink_to(entry)
    except OSError:
        pytest.skip("symlinks are not available")
    monkeypatch.setenv("PATH", str(path_dir))
    return type("Install", (), {"plugins": plugins, "binaries": binaries, "path_dir": path_dir})


@pytest.mark.parametrize("tool", TOOLS)
def test_finders_use_the_plugins_dir_beside_cdxgen(install, tool):
    assert TOOLS[tool]() == str(install.binaries[tool])


def test_discovery_reports_the_source(install):
    found = discover_plugins_dir()
    assert found is not None
    assert os.path.samefile(found.path, install.plugins)
    assert found.source == "cdxgen-install"


def test_cdxgen_cmd_selects_the_install(install, tmp_path, monkeypatch):
    """CDXGEN_CMD is honoured when it names the cdxgen to start from."""
    link = tmp_path / "elsewhere" / "my-cdxgen"
    link.parent.mkdir()
    link.symlink_to((install.path_dir / "cdxgen").resolve())
    (install.path_dir / "cdxgen").unlink()
    assert TOOLS["golem"]() is None
    monkeypatch.setenv("CDXGEN_CMD", str(link))
    assert TOOLS["golem"]() == str(install.binaries["golem"])


@pytest.mark.parametrize("tool", TOOLS)
def test_env_override_wins_over_the_install(install, tool, tmp_path, monkeypatch):
    own = tmp_path / f"own-{tool}"
    own.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setenv(f"{tool.upper()}_CMD", str(own))
    assert TOOLS[tool]() == str(own)


@pytest.mark.parametrize("tool", TOOLS)
def test_plugins_dir_env_wins_over_the_install(install, tool, tmp_path, monkeypatch):
    other = tmp_path / "other-plugins"
    paths = _make_plugins(other)
    monkeypatch.setenv("CDXGEN_PLUGINS_DIR", str(other))
    assert TOOLS[tool]() == str(paths[tool])


@pytest.mark.parametrize("tool", TOOLS)
def test_plugins_dir_env_without_the_tool_falls_back_to_the_install(
    install, tool, tmp_path, monkeypatch
):
    empty = tmp_path / "empty-plugins"
    empty.mkdir()
    monkeypatch.setenv("CDXGEN_PLUGINS_DIR", str(empty))
    assert TOOLS[tool]() == str(install.binaries[tool])


@pytest.mark.parametrize("tool", TOOLS)
def test_nothing_found_without_cdxgen(install, tool, tmp_path, monkeypatch):
    empty = tmp_path / "no-cdxgen"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    assert TOOLS[tool]() is None
    assert discover_plugins_dir() is None


def test_manifest_binary_path_is_preferred(install):
    """A manifest binaryPath that exists beats the conventional name."""
    custom = install.plugins / "golem" / "golem-custom"
    custom.write_text("#!/bin/sh\n", encoding="utf-8")
    (install.plugins / "plugins-manifest.json").write_text(
        json.dumps({"plugins": [{"name": "golem", "binaryPath": "plugins/golem/golem-custom"}]}),
        encoding="utf-8",
    )
    assert golem_mod.find_golem_binary() == str(custom)
    # A tool the manifest does not name keeps the conventional layout.
    assert rusi_mod.find_rusi_binary() == str(install.binaries["rusi"])


def test_a_manifest_naming_a_missing_file_falls_back_to_the_layout(install):
    (install.plugins / "plugins-manifest.json").write_text(
        json.dumps({"plugins": [{"name": "golem", "binaryPath": "plugins/golem/gone"}]}),
        encoding="utf-8",
    )
    assert golem_mod.find_golem_binary() == str(install.binaries["golem"])
