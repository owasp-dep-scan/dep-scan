"""The plugins directory found beside the cdxgen install.

cdxgen ships golem, rusi, dosai and kosi in ``@cdxgen/cdxgen-plugins-bin``,
installed next to it. The finders must use that directory when neither an
override nor ``CDXGEN_PLUGINS_DIR`` names a binary, as cdxgen does.
"""

import json
import os
import sys

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


IS_WINDOWS = sys.platform == "win32"

#: ``link``: cdxgen on PATH is a symlink into the install, as for a pnpm or
#: npm install reached through ``~/.local/bin``. The ``shim-*`` layouts are
#: what a global npm or pnpm install writes on Windows: ``cdxgen.cmd`` (with
#: ``.ps1`` and shell variants) beside a package directory, no link at all.
#: The shell shim is also what npm writes on POSIX hosts that cannot link.
LAYOUTS = ("link", "shim-nested", "shim-hoisted", "shim-cyclonedx", "shim-pnpm")

_CMD_SHIM = '@ECHO off\r\nSETLOCAL\r\nSET dp0=%~dp0\r\n"%_prog%"  "%dp0%\\{target}" %*\r\n'
_SH_SHIM = '#!/bin/sh\nbasedir=$(dirname "$0")\nexec node "$basedir/{target}" "$@"\n'
_PS1_SHIM = '$basedir=Split-Path $MyInvocation.MyCommand.Definition -Parent\n& node "$basedir/{target}" $args\n'


def _write_shims(directory, target):
    """The files npm writes for a global ``cdxgen``, named for this platform."""
    directory.mkdir(parents=True, exist_ok=True)
    files = {"cdxgen": _SH_SHIM}
    if IS_WINDOWS:
        files["cdxgen.cmd"] = _CMD_SHIM
        files["cdxgen.ps1"] = _PS1_SHIM
    for name, template in files.items():
        shim = directory / name
        shim.write_text(template.format(target=target), encoding="utf-8", newline="")
        shim.chmod(0o755)


def _build_install(tmp_path, layout):
    """Create the install for ``layout``; returns (directory on PATH, cdxgen
    entry, plugins directory)."""
    target = get_plugins_bin_target()
    plugins_pkg = f"cdxgen-plugins-bin-{target['platform']}-{target['arch']}"
    if layout == "link":
        root = tmp_path / "depscan-tools" / "cdxgen"
        plugins = root / "node_modules" / "@cdxgen" / plugins_pkg / "plugins"
        (root / "bin").mkdir(parents=True)
        (root / "package.json").write_text("{}", encoding="utf-8")
        name = "cdxgen.exe" if IS_WINDOWS else "cdxgen"
        entry = root / "bin" / name
        entry.write_text("#!/bin/sh\n", encoding="utf-8")
        entry.chmod(0o755)
        path_dir = tmp_path / "path"
        path_dir.mkdir()
        try:
            (path_dir / name).symlink_to(entry)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks are not available")
        shim = path_dir / name
        package = None
    elif layout == "shim-pnpm":
        path_dir = tmp_path / "pnpm"
        package = (
            path_dir / "global" / "5" / "node_modules" / ".pnpm" / "@cdxgen+cdxgen@1"
            / "node_modules" / "@cdxgen" / "cdxgen"
        )  # fmt: skip
        plugins = package.parent / plugins_pkg / "plugins"
        _write_shims(
            path_dir,
            "global/5/node_modules/.pnpm/@cdxgen+cdxgen@1/node_modules/@cdxgen/cdxgen/bin/cdxgen.js",
        )
        shim = path_dir / ("cdxgen.cmd" if IS_WINDOWS else "cdxgen")
    else:
        path_dir = tmp_path / "AppData" / "npm"
        scope = "@cyclonedx" if layout == "shim-cyclonedx" else "@cdxgen"
        package = path_dir / "node_modules" / scope / "cdxgen"
        if layout == "shim-hoisted":
            plugins = path_dir / "node_modules" / "@cdxgen" / plugins_pkg / "plugins"
        else:
            plugins = package / "node_modules" / "@cdxgen" / plugins_pkg / "plugins"
        _write_shims(path_dir, f"node_modules/{scope}/cdxgen/bin/cdxgen.js")
        shim = path_dir / ("cdxgen.cmd" if IS_WINDOWS else "cdxgen")
    if package is not None:
        (package / "bin").mkdir(parents=True)
        (package / "bin" / "cdxgen.js").write_text("// cdxgen\n", encoding="utf-8")
        (package / "package.json").write_text("{}", encoding="utf-8")
    return path_dir, shim, plugins


@pytest.fixture(params=LAYOUTS)
def install(request, tmp_path, monkeypatch):
    """A cdxgen install with its plugins package; cdxgen is only on PATH."""
    monkeypatch.setattr(plugins_mod, "resolve_cdxgen_path", _REAL_RESOLVE_CDXGEN_PATH)
    for var in (
        "CDXGEN_PLUGINS_DIR",
        "CDXGEN_CMD",
        *[f"{t.upper()}_CMD" for t in TOOLS],
        *[f"DEPSCAN_{t.upper()}_BINARY" for t in TOOLS],
    ):
        monkeypatch.delenv(var, raising=False)
    path_dir, shim, plugins = _build_install(tmp_path, request.param)
    binaries = _make_plugins(plugins)
    (plugins.parent / "package.json").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("PATH", str(path_dir))
    monkeypatch.setenv("PATHEXT", ".COM;.EXE;.BAT;.CMD")
    return type(
        "Install",
        (),
        {"plugins": plugins, "binaries": binaries, "path_dir": path_dir, "cdxgen": shim},
    )


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
    empty = tmp_path / "elsewhere"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    assert TOOLS["golem"]() is None
    monkeypatch.setenv("CDXGEN_CMD", str(install.cdxgen))
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
