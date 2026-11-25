"""The doctor report, exercised through fakes on every platform.

The fake tools are Python scripts. The ``fakes`` fixture replaces the
probe's ``_version_command`` so a fake runs through ``sys.executable``,
which also works on Windows where a script cannot be started directly; the
product code itself runs every tool as the scan does. Every fake appends to
a record file, which gives each test its positive control that the probe
really called it.

Three groups of tests:

- one per tool for missing, unreadable version and present. Library-sourced
  tools (blint, blintdb) and the always-present python runtime have no
  version probe, so they take only the cases that apply to them.
- the plugin matrix: a fake plugins directory holding every plugin binary,
  where removing one binary at a time must change exactly the capabilities
  whose requirements name it and no others.
- the command: the report validates against the published schema, and the
  run never opens a socket, never calls a download or refresh and leaves the
  database files untouched.
"""

import inspect
import json
import os
import re
import subprocess
import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest

from depscan.commands import output as commands_output
from depscan.lib import doctor as doctor_mod

# The fake tool records every call, prints the version line the test chose
# and exits with the code the test chose. The shebang marks it as a fake for
# the patched version command. Each fake records into its own file, named
# after the tool, because the doctor probes run concurrently and a shared
# file loses entries: appending is not atomic across processes on Windows.
FAKE_TOOL_SOURCE = """#!/usr/bin/env python3
import json
import sys

RECORD = {record!r}
NAME = {name!r}
OUTPUT = {output!r}
EXIT_CODE = {exit_code!r}


def note():
    if not RECORD:
        return
    line = json.dumps({{"tool": NAME, "argv": sys.argv[1:]}})
    with open(RECORD, "a", encoding="utf-8") as fp:
        fp.write(line + "\\n")


note()
print(OUTPUT)
sys.exit(EXIT_CODE)
"""

# The tools resolved through an environment variable naming the binary.
ENV_TOOLS = {
    "cdxgen": ("CDXGEN_CMD", "CycloneDX Generator 13.8.0", "13.8.0"),
    "golem": ("GOLEM_CMD", "golem 9.9.9", "9.9.9"),
    "rusi": ("RUSI_CMD", "rusi 9.9.9", "9.9.9"),
    "dosai": ("DOSAI_CMD", "dosai 9.9.9+deadbeef", "9.9.9"),
    # The real shape: a nested compiler version comes before the top-level one.
    "kosi": (
        "KOSI_CMD",
        '{"compiler":{"name":"kotlin","version":"2.4.20"},"name":"kosi","version":"9.9.9"}',
        "9.9.9",
    ),
}

# The tools resolved through find_executable, with the output of their own
# version option and the version the report must parse out of it.
FIND_TOOLS = {
    "atom": ("atom 4.0.2", "4.0.2", ["--version"]),
    "atom-tools": ("Atom Tools (version 9.9.9)", "9.9.9", ["--version"]),
    "edga": ("edga 0.2.0", "0.2.0", ["--version"]),
    "node": ("v24.9.9", "24.9.9", ["--version"]),
    "go": ("go version go9.9.9 darwin/arm64", "9.9.9", ["version"]),
    "dotnet": ("9.9.100", "9.9.100", ["--version"]),
}

# golem, rusi and dosai also live in a plugins directory; the matrix test
# needs their file name pattern next to the plugins-only ones.
PLUGIN_FILENAMES = dict(doctor_mod._PLUGIN_BINARY_NAMES)
for _tool in ("golem", "rusi", "dosai", "kosi"):
    PLUGIN_FILENAMES[_tool] = _tool + "-{platform}-{arch}{extn}"

#: Every plugin binary a full plugins directory carries.
ALL_PLUGIN_TOOLS = tuple(sorted(PLUGIN_FILENAMES))

# A database entry that satisfies the data:vdb requirement.
FULL_VDB_DATA = {
    "present": True,
    "directory": "/tmp/vdb",
    "image": "ghcr.io/appthreat/vdb7-app-only:v7.0.x-xz",
    "flavor": "app-only",
    "shards": {"enabled": False, "present": []},
    "createdUtc": "2026-11-01T00:00:00+00:00",
    "ageHours": 10.0,
    "stale": False,
    "maxAgeHours": 48,
    "cveDataCount": 100,
    "cveIndexCount": 100,
    "extendedMetadataPresent": False,
    "cveMetadataRows": 0,
}


@pytest.fixture
def clean_env(tmp_path, monkeypatch):
    """Strip every tool override and the real PATH so only the fakes resolve.

    PATH points at an empty directory, so the PATH lookup of a tool that no
    fake serves finds nothing on any platform. APPDATA points there too,
    because on Windows cdxgen is also looked up under ``%APPDATA%\\npm``.
    """
    empty_path = tmp_path / "stripped-path"
    empty_path.mkdir()
    monkeypatch.setenv("PATH", str(empty_path))
    monkeypatch.setenv("APPDATA", str(empty_path))
    for var in (
        "CDXGEN_PLUGINS_DIR",
        "CDXGEN_CMD",
        "GOLEM_CMD",
        "DEPSCAN_GOLEM_BINARY",
        "RUSI_CMD",
        "DEPSCAN_RUSI_BINARY",
        "DOSAI_CMD",
        "DEPSCAN_DOSAI_BINARY",
    ):
        monkeypatch.delenv(var, raising=False)
    # The test environment's own bin directory carries a real atom-tools;
    # only the fakes may answer here.
    monkeypatch.setattr(doctor_mod, "find_in_interpreter_scripts", lambda name: None)
    return tmp_path


@pytest.fixture
def fakes(tmp_path, monkeypatch, clean_env):
    """Install fake tools and the find_executable registry doctor consults.

    ``script(name, output)`` writes a fake tool and returns its path;
    ``found`` maps a tool name to the path the PATH lookup answers with, and
    a lookup nothing serves falls through to the real PATH (which the
    stripped PATH keeps empty); every fake invocation appends one line to
    ``record-<tool>.jsonl`` next to ``record``, which the positive controls
    read back.
    """
    record = tmp_path / "record"

    def record_path(tool):
        return record.with_name(f"record-{tool}.jsonl")

    def script(name, output, exit_code=0):
        path = tmp_path / f"fake-{name}.py"
        path.write_text(
            FAKE_TOOL_SOURCE.format(
                record=str(record_path(name)),
                name=name,
                output=output,
                exit_code=exit_code,
            ),
            encoding="utf-8",
        )
        path.chmod(0o755)
        return path

    real_version_command = doctor_mod._version_command

    def version_command(path, args):
        try:
            with open(path, encoding="utf-8", errors="replace") as fp:
                is_fake = fp.readline().startswith("#!/usr/bin/env python3")
        except OSError:
            is_fake = False
        if is_fake:
            return [sys.executable, str(path), *args]
        return real_version_command(path, args)

    monkeypatch.setattr(doctor_mod, "_version_command", version_command)

    found = {}
    real_find = doctor_mod.find_executable

    def find(name):
        return found.get(name) or real_find(name)

    monkeypatch.setattr(doctor_mod, "find_executable", find)
    return SimpleNamespace(script=script, record=record, record_path=record_path, found=found)


def _tool_entries(report):
    return {tool.name: tool for tool in report.tools}


def _capability_signature(report):
    return {
        capability.name: (capability.status, tuple(capability.missing))
        for capability in report.capabilities
    }


def _assert_probed(record, tool, argv):
    """Positive control: the fake tool ran with exactly ``argv``.

    Each fake appends to its own ``record-<tool>.jsonl``, so a missing file
    means the fake never ran at all."""
    record_file = record.with_name(f"record-{tool}.jsonl")
    entries = [
        json.loads(line)
        for line in record_file.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert any(entry["tool"] == tool and entry["argv"] == argv for entry in entries), (
        f"the {tool} fake was never called with {argv}: {entries}"
    )


# --- one tool at a time -------------------------------------------------------


def _install_tool(fakes, monkeypatch, name):
    """Install the present-case fake for ``name``; returns the expected version."""
    if name in ENV_TOOLS:
        env_name, output, version = ENV_TOOLS[name]
        monkeypatch.setenv(env_name, str(fakes.script(name, output)))
        return version
    if name in FIND_TOOLS:
        output, version, _argv = FIND_TOOLS[name]
        fakes.found[name] = fakes.script(name, output)
        return version
    if name == "blint":
        monkeypatch.setattr(doctor_mod, "_python_package_version", lambda package: "4.0.1")
        fake_init = fakes.record.parent / "fake-blint" / "blint" / "__init__.py"
        fake_init.parent.mkdir(parents=True, exist_ok=True)
        fake_init.write_text("", encoding="utf-8")
        real_find_spec = doctor_mod.util.find_spec
        monkeypatch.setattr(
            doctor_mod.util,
            "find_spec",
            lambda module, *a, **k: (
                types.SimpleNamespace(origin=str(fake_init))
                if module == "blint"
                else real_find_spec(module, *a, **k)
            ),
        )
        return "4.0.1"
    if name == "blintdb":
        location = fakes.record.parent / "blint.db"
        location.write_bytes(b"database")
        monkeypatch.setitem(sys.modules, "blint", types.ModuleType("blint"))
        monkeypatch.setitem(
            sys.modules,
            "blint.config",
            types.SimpleNamespace(BLINTDB_LOC=str(location)),
        )
        return None
    raise AssertionError(f"unknown tool {name}")


def _uninstall_tool(fakes, monkeypatch, name):
    """Make a library-sourced tool report missing deterministically."""
    from importlib import metadata

    if name == "blint":

        def raise_missing(package):
            raise metadata.PackageNotFoundError(package)

        monkeypatch.setattr(doctor_mod, "_python_package_version", raise_missing)
    elif name == "blintdb":
        monkeypatch.setitem(sys.modules, "blint", types.ModuleType("blint"))
        monkeypatch.setitem(
            sys.modules,
            "blint.config",
            types.SimpleNamespace(BLINTDB_LOC=str(fakes.record.parent / "absent-blint.db")),
        )


def _install_unreadable(fakes, monkeypatch, name):
    """Install a fake whose version output no parser accepts."""
    if name in ENV_TOOLS:
        env_name = ENV_TOOLS[name][0]
        monkeypatch.setenv(env_name, str(fakes.script(name, "garbage output")))
        return
    if name in FIND_TOOLS:
        fakes.found[name] = fakes.script(name, "garbage output")
    else:
        pytest.skip("a library-sourced tool has no version probe to fail")


def _probe_argv(name):
    if name in FIND_TOOLS:
        return FIND_TOOLS[name][2]
    return ["--version"]


@pytest.mark.parametrize("case", ["missing", "unreadable", "present"], ids=lambda case: case)
@pytest.mark.parametrize(
    "name",
    [
        "cdxgen",
        "atom",
        "atom-tools",
        "edga",
        "node",
        "go",
        "dotnet",
        "golem",
        "rusi",
        "dosai",
        "blint",
        "blintdb",
    ],
    ids=lambda name: name,
)
def test_tool_states(case, name, fakes, monkeypatch):
    """Each tool reports missing, present, and an unreadable version.

    A version that cannot be parsed leaves the tool usable, except cdxgen,
    which is refused without a readable version the same way a scan refuses
    it. Every probed fake leaves a record entry, proving the probe ran.
    """
    monkeypatch.setattr(doctor_mod, "_vdb_status", lambda: dict(FULL_VDB_DATA))
    expected_version = None
    if case == "present":
        expected_version = _install_tool(fakes, monkeypatch, name)
    elif case == "unreadable":
        _install_unreadable(fakes, monkeypatch, name)
    else:
        _uninstall_tool(fakes, monkeypatch, name)
    entry = _tool_entries(doctor_mod.doctor())[name]
    if case == "missing":
        assert entry.path is None
        assert entry.reason, f"{name} must say why it is missing"
        assert entry.source is None
        return
    assert entry.path is not None
    assert entry.version == expected_version, f"{name} version"
    if name in ENV_TOOLS or name in FIND_TOOLS:
        _assert_probed(fakes.record, name, _probe_argv(name))
    if name == "cdxgen" and case == "unreadable":
        # cdxgen without a readable version is unusable and says so.
        assert "minimum" in entry.reason
    else:
        assert entry.reason is None, f"{name} stays usable: {entry.reason}"


def test_atom_tools_next_to_the_interpreter_is_found_without_path(fakes, monkeypatch):
    """depscan started by its full path still finds atom-tools in its own venv.

    PATH is stripped by the fixture; the only copy of atom-tools sits in the
    running interpreter's scripts directory.
    """
    from xbom_lib import process as process_mod

    monkeypatch.setattr(doctor_mod, "_vdb_status", lambda: dict(FULL_VDB_DATA))
    scripts = fakes.record.parent / "venv-bin"
    scripts.mkdir()
    source = fakes.script("atom-tools", "Atom Tools (version 9.9.9)")
    name = "atom-tools.exe" if sys.platform == "win32" else "atom-tools"
    target = scripts / name
    target.write_bytes(source.read_bytes())
    target.chmod(0o755)
    monkeypatch.setattr(process_mod, "interpreter_scripts_dirs", lambda: [str(scripts)])
    monkeypatch.setattr(
        doctor_mod, "find_in_interpreter_scripts", process_mod.find_in_interpreter_scripts
    )
    entry = _tool_entries(doctor_mod.doctor())["atom-tools"]
    # Windows lookups append the PATHEXT extension as PATHEXT spells it
    # (.EXE); the file system there is case-insensitive.
    assert os.path.normcase(entry.path) == os.path.normcase(str(target))
    assert entry.version == "9.9.9"


def test_python_runtime_is_always_reported(clean_env):
    entry = _tool_entries(doctor_mod.doctor())["python"]
    assert entry.path == sys.executable
    assert entry.version
    assert entry.reason is None


def test_cdxgen_below_the_minimum_is_unusable(fakes, monkeypatch):
    """A cdxgen older than the minimum is reported with the reason named."""
    monkeypatch.setattr(doctor_mod, "_vdb_status", lambda: dict(FULL_VDB_DATA))
    monkeypatch.setenv("CDXGEN_CMD", str(fakes.script("cdxgen", "CycloneDX Generator 13.3.0")))
    entry = _tool_entries(doctor_mod.doctor())["cdxgen"]
    assert entry.version == "13.3.0"
    assert "13.8.0" in entry.reason
    assert not entry.usable


def test_dotnet_satisfied_by_self_contained_dosai(fakes, monkeypatch):
    """A dosai binary whose name carries -full bundles the .NET runtime."""
    monkeypatch.setattr(doctor_mod, "_vdb_status", lambda: dict(FULL_VDB_DATA))
    binary = fakes.script("dosai-full", "dosai 9.9.9")
    monkeypatch.setenv("DOSAI_CMD", str(binary))
    entries = _tool_entries(doctor_mod.doctor())
    assert entries["dotnet"].source == "bundled-runtime"
    assert entries["dotnet"].usable


@pytest.mark.parametrize(
    "name, capability",
    [("go", "reachability:go"), ("dotnet", "reachability:dotnet")],
)
def test_runtime_whose_version_command_fails_is_unusable(name, capability, fakes, monkeypatch):
    """go and dotnet must answer their version command, as a scan requires.

    ``go_toolchain_available`` and ``dotnet_runtime_available`` refuse a
    runtime whose version command exits non-zero, so the report marks it
    unusable and the capability that needs it unavailable.
    """
    monkeypatch.setattr(doctor_mod, "_vdb_status", lambda: dict(FULL_VDB_DATA))
    output, _version, argv = FIND_TOOLS[name]
    fakes.found[name] = fakes.script(name, output, exit_code=1)
    report = doctor_mod.doctor()
    entry = _tool_entries(report)[name]
    _assert_probed(fakes.record, name, argv)
    assert entry.path is not None
    assert not entry.usable
    assert "failed" in entry.reason
    assert f"tool:{name}" in _capability_signature(report)[capability][1]


def test_cdxgen_version_is_read_whatever_its_exit_code(fakes, monkeypatch):
    """The scan reads cdxgen's version from its output and ignores the exit
    code, so the report does the same."""
    monkeypatch.setattr(doctor_mod, "_vdb_status", lambda: dict(FULL_VDB_DATA))
    monkeypatch.setenv(
        "CDXGEN_CMD",
        str(fakes.script("cdxgen", "CycloneDX Generator 13.8.0", exit_code=1)),
    )
    entry = _tool_entries(doctor_mod.doctor())["cdxgen"]
    _assert_probed(fakes.record, "cdxgen", ["--version"])
    assert entry.version == "13.8.0"
    assert entry.usable


def test_rusi_below_its_soft_minimum_stays_usable(fakes, monkeypatch):
    """rusi has a soft minimum: the scan warns and still runs an older one."""
    monkeypatch.setattr(doctor_mod, "_vdb_status", lambda: dict(FULL_VDB_DATA))
    monkeypatch.setenv("RUSI_CMD", str(fakes.script("rusi", "rusi 2.5.1")))
    report = doctor_mod.doctor()
    entry = _tool_entries(report)["rusi"]
    assert entry.version == "2.5.1"
    assert entry.to_dict()["minVersion"] == doctor_mod.rusi_mod.RUSI_MIN_VERSION
    assert entry.usable
    assert f"older than {doctor_mod.rusi_mod.RUSI_MIN_VERSION}" in report.to_text()


# --- the plugin matrix ---------------------------------------------------------


@pytest.fixture
def plugins_env(fakes, monkeypatch):
    """A fake plugins directory with every binary, plus a full toolchain.

    The PATH is stripped and every override cleared, so golem, rusi and
    dosai resolve from the plugins directory exactly as a scan would find
    them there, and the go, dotnet, node and atom lookups answer from fakes.
    """
    monkeypatch.setattr(doctor_mod, "_vdb_status", lambda: dict(FULL_VDB_DATA))
    target = doctor_mod.get_plugins_bin_target()
    base = fakes.record.parent / "plugins-root"
    plugins_dir = base / "plugins"
    plugins_dir.mkdir(parents=True)
    binaries = {}
    manifest_plugins = []
    for tool in ALL_PLUGIN_TOOLS:
        filename = PLUGIN_FILENAMES[tool].format(**target)
        path = plugins_dir / tool / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        if filename.endswith(".app"):
            path.mkdir()
        elif tool in ("golem", "rusi", "dosai"):
            path.write_text(
                FAKE_TOOL_SOURCE.format(
                    record=str(fakes.record_path(tool)),
                    name=tool,
                    output=f"{tool} 9.9.9",
                    exit_code=0,
                ),
                encoding="utf-8",
            )
            path.chmod(0o755)
        else:
            path.write_text("plugin binary placeholder", encoding="utf-8")
        binaries[tool] = path
        manifest_plugins.append(
            {
                "name": tool,
                "version": "1.2.3",
                "binaryPath": f"plugins/{tool}/{filename}",
            }
        )
    (plugins_dir / "plugins-manifest.json").write_text(
        json.dumps(
            {
                "package": {
                    "name": "@cdxgen/cdxgen-plugins-bin",
                    "version": "9.9.9",
                },
                "plugins": manifest_plugins,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("CDXGEN_PLUGINS_DIR", str(plugins_dir))
    monkeypatch.setenv(
        "CDXGEN_CMD",
        str(fakes.script("cdxgen", "CycloneDX Generator 13.8.0")),
    )
    for name in ("go", "dotnet", "node", "atom"):
        output = FIND_TOOLS[name][0] if name in FIND_TOOLS else f"{name} 9.9.9"
        fakes.found[name] = fakes.script(name, output)
    return SimpleNamespace(plugins_dir=plugins_dir, binaries=binaries)


def _remove(path):
    """Move a plugin binary (or bundle directory) out of the way."""
    away = path.with_name(path.name + ".removed")
    path.rename(away)
    return away


def test_plugin_matrix_baseline(plugins_env, fakes):
    """Every capability whose requirements the fakes satisfy is available."""
    report = doctor_mod.doctor()
    entries = _tool_entries(report)
    for tool in ALL_PLUGIN_TOOLS:
        assert entries[tool].path is not None, tool
        assert entries[tool].usable, tool
    for tool in ("golem", "rusi", "dosai"):
        assert entries[tool].source == "plugins-dir"
        assert entries[tool].version == "9.9.9"
        _assert_probed(fakes.record, tool, ["--version"])
    assert entries["cdxgen-plugins"].version == "9.9.9"
    signature = _capability_signature(report)
    for name in (
        "vulnerabilities",
        "reachability",
        "reachability:rust",
        "reachability:go",
        "reachability:dotnet",
        "license",
    ):
        assert signature[name] == ("available", ()), name


@pytest.mark.parametrize("plugin", ALL_PLUGIN_TOOLS)
def test_removing_one_plugin_changes_only_its_dependents(plugin, plugins_env):
    """Removing one binary flips exactly the capabilities that need it.

    The expected set comes from the capability table itself, so this checks
    that the discovery wiring agrees with the table: whatever the table says
    depends on the tool is what flips, and nothing else.
    """
    baseline = _capability_signature(doctor_mod.doctor())
    binary = plugins_env.binaries[plugin]
    away = _remove(binary)
    try:
        after_report = doctor_mod.doctor()
    finally:
        away.rename(binary)
    changed = {
        name for name in baseline if baseline[name] != _capability_signature(after_report)[name]
    }
    expected = {
        spec.name
        for spec in doctor_mod.CAPABILITIES
        if spec.implemented and f"tool:{plugin}" in spec.requirements
    }
    assert changed == expected
    entry = _tool_entries(after_report)[plugin]
    assert entry.path is None
    assert plugin in (entry.reason or "")


# --- the supply-chain and binary rows -----------------------------------------


def test_supply_chain_needs_nothing_and_binary_follows_blint(fakes, monkeypatch):
    """supply-chain is the package risk audit and the malware advisory
    reporting a scan already does, so it needs no tool or data and is
    available on a machine with nothing installed. binary runs on blint, so
    it is unavailable while the package is missing."""
    monkeypatch.setattr(doctor_mod, "_vdb_status", lambda: dict(FULL_VDB_DATA))
    _uninstall_tool(fakes, monkeypatch, "blint")
    report = doctor_mod.doctor()
    signature = _capability_signature(report)
    assert signature["supply-chain"] == ("available", ())
    assert signature["binary"] == ("unavailable", ("tool:blint",))
    by_name = {capability.name: capability for capability in report.capabilities}
    assert by_name["supply-chain"].description == (
        "Package risk audit and malware advisory reporting."
    )
    assert by_name["binary"].description == "Binary analysis with blint."


def test_binary_is_available_with_blint_installed(fakes, monkeypatch):
    monkeypatch.setattr(doctor_mod, "_vdb_status", lambda: dict(FULL_VDB_DATA))
    _install_tool(fakes, monkeypatch, "blint")
    assert _capability_signature(doctor_mod.doctor())["binary"] == ("available", ())


# --- the command and the guarantees -------------------------------------------


@pytest.fixture
def no_network(monkeypatch):
    """Any socket the report tries to open fails the test."""
    import socket

    def refuse(*args, **kwargs):
        raise AssertionError("depscan doctor must not open a network socket")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


def test_json_report_validates_against_the_schema(no_network, capsys):
    """The command's JSON output satisfies the published schema."""
    from analysis_lib.findings.schemas import validate

    exit_code = doctor_mod.run_doctor_command(["--format", "json"])
    assert exit_code == 0
    document = json.loads(capsys.readouterr().out)
    validate("depscan-doctor", document)
    assert document["schemaVersion"] == "1"
    names = {tool["name"] for tool in document["tools"]}
    assert {
        "cdxgen",
        "atom",
        "edga",
        "atom-tools",
        "blint",
        "golem",
        "rusi",
        "dosai",
        "dotnet",
        "go",
        "node",
        "python",
        "cdxgen-plugins",
    } <= names


def test_text_report_names_every_capability(no_network, capsys):
    exit_code = doctor_mod.run_doctor_command([])
    assert exit_code == 0
    text = capsys.readouterr().out
    assert text.startswith("dep-scan doctor")
    for spec in doctor_mod.CAPABILITIES:
        assert spec.name in text


def test_doctor_never_touches_the_network_or_the_database(no_network, monkeypatch, tmp_path):
    """No download or refresh runs and the database files are left alone.

    The database is a garbage pair of files in a temporary home, so the
    report must also cope with a present but unreadable one: it reports the
    counts as unknown instead of answering from nothing.
    """
    from depscan.lib import vdb_setup
    from vdb.lib import config as vdb_config
    from vdb.lib import db_cmd

    def fail(*args, **kwargs):
        raise AssertionError("depscan doctor must not download or refresh")

    monkeypatch.setattr(vdb_setup, "download_vdb_with_retries", fail)
    monkeypatch.setattr(vdb_setup, "refresh_shards_with_retries", fail)
    monkeypatch.setattr(db_cmd, "refresh_full_image", fail)
    monkeypatch.setattr(db_cmd, "refresh_shards", fail)
    home = tmp_path / "vdb-home"
    home.mkdir()
    (home / "data.vdb7").write_bytes(b"not a database")
    (home / "data.index.vdb7").write_bytes(b"not a database")
    (home / ".depscan-vdb-image").write_text(
        "ghcr.io/appthreat/vdb7-app-only:v7.0.x-xz", encoding="utf-8"
    )
    monkeypatch.setattr(vdb_config, "DATA_DIR", str(home))
    monkeypatch.setattr(vdb_config, "VDB_BIN_FILE", str(home / "data.vdb7"))
    monkeypatch.setattr(vdb_config, "VDB_BIN_INDEX", str(home / "data.index.vdb7"))
    monkeypatch.setattr(vdb_config, "VDB_SHARDS_DIR", str(home / "shards"))
    monkeypatch.setattr(vdb_config, "VDB_METADATA_FILE", str(home / "data.vdb7-meta.json"))
    before = {
        entry.name: (entry.stat().st_mtime_ns, entry.stat().st_size)
        for entry in sorted(home.iterdir())
    }
    report = doctor_mod.doctor()
    after = {
        entry.name: (entry.stat().st_mtime_ns, entry.stat().st_size)
        for entry in sorted(home.iterdir())
    }
    assert after == before
    vdb = report.data["vulnerabilityDatabase"]
    assert vdb["present"] is True
    assert vdb["flavor"] == "app-only"
    assert vdb["cveDataCount"] is None
    assert vdb["cveMetadataRows"] is None
    vulnerabilities = {capability.name: capability for capability in report.capabilities}[
        "vulnerabilities"
    ]
    assert vulnerabilities.status == "unavailable"
    assert vulnerabilities.missing == ["data:vdb"]


def test_missing_database_is_a_reported_state(no_network, monkeypatch, tmp_path):
    """An absent database is reported, and never fetched, by the command."""
    from vdb.lib import config as vdb_config

    home = tmp_path / "empty-home"
    home.mkdir()
    monkeypatch.setattr(vdb_config, "DATA_DIR", str(home))
    monkeypatch.setattr(vdb_config, "VDB_BIN_FILE", str(home / "data.vdb7"))
    monkeypatch.setattr(vdb_config, "VDB_BIN_INDEX", str(home / "data.index.vdb7"))
    monkeypatch.setattr(vdb_config, "VDB_SHARDS_DIR", str(home / "shards"))
    monkeypatch.setattr(vdb_config, "VDB_METADATA_FILE", str(home / "data.vdb7-meta.json"))
    report = doctor_mod.doctor()
    vdb = report.data["vulnerabilityDatabase"]
    assert vdb["present"] is False
    assert vdb["flavor"] is None
    assert list(home.iterdir()) == []


def test_metadata_rows_are_counted_without_touching_vdb_connections(monkeypatch, tmp_path):
    """The cve_metadata count uses a private read-only connection.

    A scan in the same process keeps its own vdb connections; the report must
    leave them bound as they were and must not write to the index file.
    """
    import sqlite3

    from vdb.lib import config as vdb_config
    from vdb.lib import db as vdb_db

    index_file = tmp_path / "data.index.vdb7"
    conn = sqlite3.connect(index_file)
    conn.execute("CREATE TABLE cve_metadata (cve_id TEXT)")
    conn.executemany("INSERT INTO cve_metadata VALUES (?)", [("CVE-1",), ("CVE-2",)])
    conn.commit()
    conn.close()
    before = (index_file.stat().st_mtime_ns, index_file.stat().st_size)
    monkeypatch.setattr(vdb_config, "VDB_BIN_INDEX", str(index_file))
    sentinel = object()
    monkeypatch.setattr(vdb_db, "index_conn", sentinel)
    assert doctor_mod._cve_metadata_rows() == 2
    assert vdb_db.index_conn is sentinel
    assert (index_file.stat().st_mtime_ns, index_file.stat().st_size) == before


@pytest.fixture
def fixed_report(monkeypatch):
    """The report with every implemented capability available but rusi missing."""
    tools = {
        name: doctor_mod.ToolStatus(name=name, path=f"/bin/{name}", source="path")
        for name in ("cdxgen", "golem", "go", "dosai", "dotnet")
    }
    tools["rusi"] = doctor_mod.ToolStatus(name="rusi", reason="not found")
    report = doctor_mod.DoctorReport(
        schema_version="1",
        depscan_version="7.0.0",
        platform={"os": "linux", "arch": "x86_64", "libc": "glibc"},
        tools=list(tools.values()),
        data={"vulnerabilityDatabase": dict(FULL_VDB_DATA)},
        capabilities=doctor_mod._evaluate_capabilities(
            tools, {"vulnerabilityDatabase": dict(FULL_VDB_DATA)}
        ),
    )
    monkeypatch.setattr(doctor_mod, "doctor", lambda: report)
    return report


def test_require_available_capabilities_exits_zero(fixed_report, capsys):
    code = doctor_mod.run_doctor_command(
        ["--require", "vulnerabilities,reachability:go", "--require", "license"]
    )
    assert code == 0
    assert capsys.readouterr().err == ""


def _one_document(capsys):
    """stdout as the single document the json contract asks for.

    Parsing the whole stream only works when the command wrote exactly one
    document; a second one or any stray line breaks the parse.
    """
    captured = capsys.readouterr()
    return json.loads(captured.out), captured


@pytest.mark.parametrize("required", ["reachability:rust", "memory-safety:c"])
def test_require_unavailable_capability_exits_four_in_text(fixed_report, capsys, required):
    """Unavailable and not-implemented capabilities both fail ``--require``,
    and the text report is still printed next to the message."""
    code = doctor_mod.run_doctor_command(
        ["--format", "text", "--require", f"vulnerabilities,{required}"]
    )
    captured = capsys.readouterr()
    assert code == doctor_mod.EXIT_REQUIREMENT_NOT_MET == 4
    assert captured.out.startswith("dep-scan doctor")
    assert required in captured.err
    assert "vulnerabilities" not in captured.err


@pytest.mark.parametrize("required", ["reachability:rust", "memory-safety:c"])
def test_require_unavailable_capability_exits_four_with_the_error_document(
    fixed_report, capsys, required
):
    """In json format the error document is the one stdout document, with the
    unmet names in its details; the report yields to it."""
    code = doctor_mod.run_doctor_command(
        ["--format", "json", "--require", f"vulnerabilities,{required}"]
    )
    assert code == doctor_mod.EXIT_REQUIREMENT_NOT_MET == 4
    document, captured = _one_document(capsys)
    assert document["error"] == {
        "exitCode": 4,
        "verb": "doctor",
        "message": document["error"]["message"],
        "details": {"unmet": [required]},
    }
    assert required in document["error"]["message"]
    assert "vulnerabilities" not in document["error"]["message"]
    # The same message also goes to stderr as text.
    assert captured.err == document["error"]["message"] + "\n"


def test_require_unknown_capability_is_a_usage_error(fixed_report, capsys):
    code = doctor_mod.run_doctor_command(["--require", "reachability:cobol"])
    captured = capsys.readouterr()
    assert code == doctor_mod.EXIT_USAGE == 2
    assert captured.out == ""
    assert "reachability:cobol" in captured.err


def test_require_unknown_capability_writes_the_error_document(fixed_report, capsys):
    """In json format the usage error writes the error document, with the
    unknown names in its details, next to the message on stderr."""
    code = doctor_mod.run_doctor_command(["--format", "json", "--require", "reachability:cobol"])
    assert code == doctor_mod.EXIT_USAGE == 2
    document, captured = _one_document(capsys)
    assert document["error"] == {
        "exitCode": 2,
        "verb": "doctor",
        "message": document["error"]["message"],
        "details": {"unknownCapabilities": ["reachability:cobol"]},
    }
    assert "reachability:cobol" in document["error"]["message"]
    assert captured.err == document["error"]["message"] + "\n"


def test_the_doctor_exit_codes_come_from_the_output_core():
    """The exit constants are the shared table's, not a doctor-local copy."""
    source = inspect.getsource(doctor_mod)
    assert "from depscan.commands import output" in source
    assert not re.search(r"^EXIT_\w+\s*=", source, flags=re.MULTILINE)
    assert doctor_mod.EXIT_USAGE is commands_output.EXIT_USAGE
    assert doctor_mod.EXIT_REQUIREMENT_NOT_MET is commands_output.EXIT_REQUIREMENT_NOT_MET
    table_codes = [code for code, _meaning in commands_output.EXIT_CODES]
    assert doctor_mod.EXIT_USAGE in table_codes
    assert doctor_mod.EXIT_REQUIREMENT_NOT_MET in table_codes


def test_the_doctor_module_imports_in_any_order():
    """Importing the doctor module before the verb registry must work.

    The registry imports this module back through depscan.api, so an import
    from depscan.commands while the module is still defining itself would
    leave DoctorReport undefined for api and crash the import. The exit
    codes are therefore resolved from the shared table on first use, not at
    module level.
    """
    probe = "import depscan.lib.doctor, depscan.lib.scan_directory, depscan.api\nprint('imported')"
    result = subprocess.run(
        [sys.executable, "-c", probe],
        capture_output=True,
        text=True,
        check=False,
        cwd=Path(__file__).parent.parent,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "imported"


def test_the_json_report_matches_the_doctor_output_schema(no_network, capsys):
    """The command's success document carries its own output schema's name."""
    from analysis_lib.findings.schemas import load_schema, validate

    try:
        load_schema("depscan-doctor-output")
    except ValueError:
        pytest.skip("the depscan-doctor-output schema lands with the schemas piece")
    assert doctor_mod.run_doctor_command(["--format", "json"]) == 0
    document = json.loads(capsys.readouterr().out)
    validate("depscan-doctor-output", document)


# --- the command line ----------------------------------------------------------


def test_doctor_format_defaults_to_text():
    assert doctor_mod.parse_doctor_args([]).format == "text"
    assert doctor_mod.parse_doctor_args(["--format", "json"]).format == "json"
    assert doctor_mod.parse_doctor_args(["--require", " a, b,", "--require", "c"]).require == [
        "a",
        "b",
        "c",
    ]


def test_doctor_rejects_an_unknown_format(capsys):
    with pytest.raises(SystemExit) as excinfo:
        doctor_mod.parse_doctor_args(["--format", "yaml"])
    assert excinfo.value.code == 2


def test_main_routes_doctor_and_rejects_v6_invocations(monkeypatch, capsys):
    """``doctor`` reaches the doctor command through the verb registry; a
    v6 options-first invocation is rejected with its translation."""
    from depscan import cli

    monkeypatch.setattr(sys, "argv", ["depscan", "doctor", "--format", "json"])
    with pytest.raises(SystemExit) as excinfo:
        cli.main()
    assert excinfo.value.code == 0
    document = json.loads(capsys.readouterr().out)
    assert document["schemaVersion"] == "1"

    monkeypatch.setattr(sys, "argv", ["depscan", "--purl", "pkg:pypi/requests@2.32.1"])
    with pytest.raises(SystemExit) as excinfo:
        cli.main()
    assert excinfo.value.code == 2
    err = capsys.readouterr().err
    assert "The equivalent v7 command is: depscan scan pkg:pypi/requests@2.32.1" in err


def test_documented_capability_table_matches_the_code():
    """The doctor page carries the generated table; regenerate it when this fails."""
    page = os.path.join(
        os.path.dirname(__file__), os.pardir, "documentation", "docs", "reference", "doctor.mdx"
    )
    with open(page, encoding="utf-8") as fp:
        text = fp.read()
    assert doctor_mod.capability_table_markdown() in text


@pytest.mark.parametrize(
    "output, expected",
    [
        ('{"compiler":{"version":"2.4.20"},"version":"4.3.1"}', "4.3.1"),
        (
            'WARNING: jvm noise\n{\n  "compiler": {"version": "2.4.20"},\n  "version": "4.3.1"\n}\n',
            "4.3.1",
        ),
        ('{"compiler":{"version":"2.4.20"}}', None),
        ("kosi", None),
    ],
)
def test_kosi_version_is_the_top_level_key_not_the_compilers(output, expected):
    assert doctor_mod._parse_kosi(output) == expected


def test_kosi_report_entry_carries_the_top_level_version(fakes, monkeypatch):
    monkeypatch.setattr(doctor_mod, "_vdb_status", lambda: dict(FULL_VDB_DATA))
    binary = fakes.script(
        "kosi", '{"compiler":{"name":"kotlin","version":"2.4.20"},"version":"4.3.1"}'
    )
    monkeypatch.setenv("KOSI_CMD", str(binary))
    assert _tool_entries(doctor_mod.doctor())["kosi"].version == "4.3.1"


# --- plugins found beside the cdxgen install -----------------------------------


@pytest.fixture(params=["link", "shim"])
def install_env(request, plugins_env, fakes, monkeypatch):
    """The plugins tree under a cdxgen install, with no CDXGEN_PLUGINS_DIR.

    ``link``: ``<root>/bin/cdxgen`` and ``<root>/package.json``, with the
    plugins package under ``<root>/node_modules/@cdxgen``; cdxgen is on PATH
    through a symlink, the way ``~/.local/bin/cdxgen`` points into a package
    manager's install.

    ``shim``: what a global npm install writes on Windows, a ``cdxgen.cmd``
    shim (a shell shim elsewhere) in ``<prefix>`` beside
    ``<prefix>/node_modules/@cdxgen/cdxgen``, which carries the plugins.
    """
    target = doctor_mod.get_plugins_bin_target()
    plugins_pkg = f"cdxgen-plugins-bin-{target['platform']}-{target['arch']}"
    windows = sys.platform == "win32"
    base = fakes.record.parent
    path_dir = base / "on-path"
    path_dir.mkdir()
    if request.param == "link":
        root = base / "cdxgen-install"
        package = root / "node_modules" / "@cdxgen" / plugins_pkg
        (root / "bin").mkdir(parents=True)
        (root / "package.json").write_text("{}", encoding="utf-8")
        name = "cdxgen.exe" if windows else "cdxgen"
        real_cdxgen = root / "bin" / name
        real_cdxgen.write_text(
            Path(os.environ["CDXGEN_CMD"]).read_text(encoding="utf-8"), encoding="utf-8"
        )
        real_cdxgen.chmod(0o755)
        try:
            (path_dir / name).symlink_to(real_cdxgen)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks are not available")
    else:
        # A shim is not runnable here (no node), so its version probe runs the
        # fake cdxgen the plugins_env fixture installed.
        fake_cdxgen = os.environ["CDXGEN_CMD"]
        probe = doctor_mod._version_command
        shim_dir = os.path.normcase(str(path_dir))

        def shim_aware_command(path, args):
            if os.path.normcase(os.path.dirname(str(path))) == shim_dir:
                return [sys.executable, fake_cdxgen, *args]
            return probe(path, args)

        monkeypatch.setattr(doctor_mod, "_version_command", shim_aware_command)
        cdxgen_pkg = path_dir / "node_modules" / "@cdxgen" / "cdxgen"
        package = cdxgen_pkg / "node_modules" / "@cdxgen" / plugins_pkg
        (cdxgen_pkg / "bin").mkdir(parents=True)
        (cdxgen_pkg / "package.json").write_text("{}", encoding="utf-8")
        (cdxgen_pkg / "bin" / "cdxgen.js").write_text("// cdxgen\n", encoding="utf-8")
        target_js = "node_modules/@cdxgen/cdxgen/bin/cdxgen.js"
        shims = {"cdxgen": f'#!/bin/sh\nexec node "$basedir/{target_js}" "$@"\n'}
        if windows:
            shims["cdxgen.cmd"] = f'@ECHO off\r\n"%_prog%"  "%dp0%\\{target_js}" %*\r\n'
        for shim_name, text in shims.items():
            (path_dir / shim_name).write_text(text, encoding="utf-8", newline="")
            (path_dir / shim_name).chmod(0o755)
    package.mkdir(parents=True, exist_ok=True)
    installed = package / "plugins"
    plugins_env.plugins_dir.rename(installed)
    (package / "package.json").write_text("{}", encoding="utf-8")
    monkeypatch.delenv("CDXGEN_PLUGINS_DIR")
    monkeypatch.delenv("CDXGEN_CMD")
    monkeypatch.setenv("PATH", str(path_dir))
    monkeypatch.setenv("PATHEXT", ".COM;.EXE;.BAT;.CMD")
    return SimpleNamespace(plugins_dir=installed, path_dir=path_dir)


def test_plugins_beside_the_cdxgen_install_are_used(install_env, fakes):
    """golem, rusi, dosai and kosi come from the install, and the reachability
    capabilities that need them become available."""
    report = doctor_mod.doctor()
    entries = _tool_entries(report)
    assert entries["cdxgen-plugins"].path == str(install_env.plugins_dir)
    assert entries["cdxgen-plugins"].source == "cdxgen-install"
    for tool in ("golem", "rusi", "dosai", "kosi"):
        assert entries[tool].path is not None, tool
        assert Path(entries[tool].path).is_relative_to(install_env.plugins_dir), tool
        assert entries[tool].source == "plugins-dir", tool
    for tool in ("golem", "rusi", "dosai"):
        _assert_probed(fakes.record, tool, ["--version"])
    signature = _capability_signature(report)
    for name in ("reachability:go", "reachability:rust", "reachability:dotnet"):
        assert signature[name] == ("available", ()), name


def test_plugins_dir_env_wins_over_the_install(install_env, plugins_env, tmp_path, monkeypatch):
    """CDXGEN_PLUGINS_DIR keeps priority over the directory beside cdxgen."""
    target = doctor_mod.get_plugins_bin_target()
    other = tmp_path / "other-plugins"
    (other / "golem").mkdir(parents=True)
    golem = other / "golem" / f"golem-{target['platform']}-{target['arch']}{target['extn']}"
    golem.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setenv("CDXGEN_PLUGINS_DIR", str(other))
    entries = _tool_entries(doctor_mod.doctor())
    assert entries["cdxgen-plugins"].path == str(other)
    assert entries["golem"].path == str(golem)
    assert entries["golem"].source == "plugins-dir"


def test_no_discovery_without_cdxgen(install_env, monkeypatch, tmp_path):
    """Without cdxgen on PATH nothing leads to the install's plugins."""
    empty = tmp_path / "no-cdxgen"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    entries = _tool_entries(doctor_mod.doctor())
    assert entries["cdxgen-plugins"].path is None
    for tool in ("golem", "rusi", "kosi"):
        assert entries[tool].path is None, tool


# --- dosai that cannot start ---------------------------------------------------

# What the .NET apphost prints, with the exit status 150, when the runtime
# dosai was built for is not installed. The home path is neutral.
APPHOST_FAILURE = """You must install or update .NET to run this application.

App: /home/user/.local/bin/dosai
Architecture: arm64
Framework: 'Microsoft.NETCore.App', version '11.0.0' (arm64)
.NET location: /usr/local/share/dotnet

The following frameworks were found:
  9.0.6 at [/usr/local/share/dotnet/shared/Microsoft.NETCore.App]
  10.0.0 at [/usr/local/share/dotnet/shared/Microsoft.NETCore.App]

Learn more:
https://aka.ms/dotnet/app-launch-failed

To install missing framework, download:
https://aka.ms/dotnet-core-applaunch?framework=Microsoft.NETCore.App&framework_version=11.0.0&arch=arm64&rid=osx-arm64&os=osx.27
"""


def test_dosai_apphost_failure_is_not_a_version(plugins_env, fakes, monkeypatch):
    """The framework numbers in the apphost message are not dosai's version:
    dosai is unusable, names the framework it needs and reachability:dotnet
    is unavailable."""
    monkeypatch.setenv("DOSAI_CMD", str(fakes.script("dosai", APPHOST_FAILURE, exit_code=150)))
    report = doctor_mod.doctor()
    dosai = _tool_entries(report)["dosai"]
    assert dosai.version is None
    assert not dosai.usable
    assert "Microsoft.NETCore.App 11.0.0" in dosai.reason
    assert "DOTNET_ROOT" in dosai.reason
    _assert_probed(fakes.record, "dosai", ["--version"])
    assert _capability_signature(report)["reachability:dotnet"][0] == "unavailable"


def test_dosai_apphost_text_with_a_zero_exit_is_still_a_failure(fakes, monkeypatch, plugins_env):
    monkeypatch.setenv("DOSAI_CMD", str(fakes.script("dosai", APPHOST_FAILURE, exit_code=0)))
    dosai = _tool_entries(doctor_mod.doctor())["dosai"]
    assert dosai.version is None and not dosai.usable


def test_dosai_nonzero_exit_without_a_message_is_unusable(fakes, monkeypatch, plugins_env):
    monkeypatch.setenv("DOSAI_CMD", str(fakes.script("dosai", "5.0.0", exit_code=3)))
    dosai = _tool_entries(doctor_mod.doctor())["dosai"]
    assert dosai.version is None and not dosai.usable
    assert "status 3" in dosai.reason


def test_dosai_that_starts_keeps_its_version(fakes, monkeypatch, plugins_env):
    monkeypatch.setenv("DOSAI_CMD", str(fakes.script("dosai", "5.0.0+0c35f37", exit_code=0)))
    dosai = _tool_entries(doctor_mod.doctor())["dosai"]
    assert dosai.version == "5.0.0" and dosai.usable
