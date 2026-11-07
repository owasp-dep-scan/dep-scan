"""Tests for xbom_lib.process, which starts external tools without a shell.

The unit tests run everywhere. The tests marked ``windows_only`` start real
batch files and check two things: that every argument reaches the tool
unchanged, and that cmd.exe syntax inside an argument, such as the payloads
from GHSA-xpgh-m7fj-jqq9, is never executed.
"""

import json
import os
import shutil
import subprocess
import sys

import pytest

from xbom_lib.cdxgen import CdxgenGenerator
from xbom_lib.process import (
    UnsafeCommandError,
    batch_command_line,
    build_command,
    npm_shim_command,
    parse_npm_shim,
    quote_batch_arg,
    windows_which,
)

windows_only = pytest.mark.skipif(sys.platform != "win32", reason="Windows batch file behaviour")

# The shim that `npm install -g @cyclonedx/cdxgen` writes on Windows, with the
# package path swapped for the test script.
NPM_SHIM_TEMPLATE = r"""@ECHO off
GOTO start
:find_dp0
SET dp0=%~dp0
EXIT /b
:start
SETLOCAL
CALL :find_dp0

IF EXIST "%dp0%\node.exe" (
  SET "_prog=%dp0%\node.exe"
) ELSE (
  SET "_prog=node"
  SET PATHEXT=%PATHEXT:;.JS;=;%
)

endLocal & goto #_undefined_# 2>NUL || title %COMSPEC% & "%_prog%"  "%dp0%\{script}" %*
"""

# Arguments that are legal in Windows paths or tool options and that cmd.exe
# would treat as syntax if they were not quoted.
ARGS_SAFE_FOR_ANY_BATCH = [
    "plain",
    "with space",
    "C:\\dir with space\\",
    "trailing\\",
    "",
    "a&b",
    "a|b",
    "a<b>c",
    "a^b",
    "Program Files (x86)",
    "unicode-\u00fc\u00f1\u00ef",
    "pwn&cd>marker.txt",
]
# Arguments that only the npm shim path can deliver, because cmd.exe cannot
# quote them.
ARGS_NEEDING_DIRECT_NODE = ['say "hi"', "100%", "%PATH%", "bang!"]


# ---------------------------------------------------------------- unit tests


def test_windows_which_skips_current_and_relative_path_entries():
    files = {r"C:\tools\cdxgen.CMD", r".\cdxgen.CMD", r"rel\cdxgen.CMD"}
    found = windows_which(
        "cdxgen",
        path_env=r".;;rel;C:\tools",
        pathext=".COM;.EXE;.BAT;.CMD",
        isfile=lambda p: p in files,
    )
    assert found == r"C:\tools\cdxgen.CMD"


def test_windows_which_prefers_pathext_order_and_strips_quotes():
    files = {r"C:\b\tool.EXE", r"C:\b\tool.CMD"}
    found = windows_which(
        "tool", path_env=r'"C:\b"', pathext=".EXE;.CMD", isfile=lambda p: p in files
    )
    assert found == r"C:\b\tool.EXE"


def test_windows_which_keeps_a_name_that_already_has_an_extension():
    files = {r"C:\b\cdxgen.cmd", r"C:\b\cdxgen.cmd.EXE"}
    found = windows_which(
        "cdxgen.cmd", path_env=r"C:\b", pathext=".EXE;.CMD", isfile=lambda p: p in files
    )
    assert found == r"C:\b\cdxgen.cmd"


def test_windows_which_honours_an_explicit_path():
    files = {r"C:\plugins\rusi-windows-amd64.exe"}
    assert (
        windows_which(
            r"C:\plugins\rusi-windows-amd64",
            path_env="",
            pathext=".exe",
            isfile=lambda p: p in files,
        )
        == r"C:\plugins\rusi-windows-amd64.exe"
    )
    assert windows_which(r"C:\plugins\missing", path_env="", isfile=lambda p: False) is None


def test_windows_which_returns_none_when_missing():
    assert windows_which("cdxgen", path_env=r"C:\b", isfile=lambda p: False) is None


def test_parse_npm_shim_reads_the_script_path():
    text = NPM_SHIM_TEMPLATE.replace("{script}", r"node_modules\@cyclonedx\cdxgen\bin\cdxgen.js")
    assert parse_npm_shim(text) == r"node_modules\@cyclonedx\cdxgen\bin\cdxgen.js"


@pytest.mark.parametrize(
    "text",
    [
        '@"%~dp0\\node.exe" "%~dp0\\..\\cdxgen\\bin\\cdxgen.js" %*\n',
        "@echo off\r\ncdxgen.exe %*\r\n",
        '"%_prog%"  "%dp0%\\node_modules\\x\\bin\\run.sh" %*\n',
        "",
    ],
)
def test_parse_npm_shim_ignores_other_batch_files(text):
    assert parse_npm_shim(text) is None


def test_npm_shim_command_prefers_node_next_to_the_shim(tmp_path):
    shim = tmp_path / "cdxgen.cmd"
    shim.write_text(NPM_SHIM_TEMPLATE.replace("{script}", r"node_modules\c\bin\cdxgen.js"))
    shim_dir = str(tmp_path)
    script = shim_dir + r"\node_modules\c\bin\cdxgen.js"
    local_node = shim_dir + r"\node.exe"
    present = {script, local_node}
    assert npm_shim_command(
        str(shim), which=lambda n: r"C:\nodejs\node.exe", isfile=lambda p: p in present
    ) == [local_node, script]
    present = {script}
    assert npm_shim_command(
        str(shim), which=lambda n: r"C:\nodejs\node.exe", isfile=lambda p: p in present
    ) == [r"C:\nodejs\node.exe", script]


def test_npm_shim_command_gives_up_without_a_usable_node(tmp_path):
    shim = tmp_path / "cdxgen.cmd"
    shim.write_text(NPM_SHIM_TEMPLATE.replace("{script}", r"node_modules\c\bin\cdxgen.js"))
    script = str(tmp_path) + r"\node_modules\c\bin\cdxgen.js"
    assert npm_shim_command(str(shim), which=lambda n: None, isfile=lambda p: p == script) is None
    assert (
        npm_shim_command(
            str(shim), which=lambda n: r"C:\volta\node.cmd", isfile=lambda p: p == script
        )
        is None
    )
    # The script the shim names has to exist.
    assert npm_shim_command(str(shim), which=lambda n: "node.exe", isfile=lambda p: False) is None


@pytest.mark.parametrize(
    "arg,quoted",
    [
        ("plain", '"plain"'),
        ("", '""'),
        ("with space", '"with space"'),
        ("a&b|c<d>e^f(g)", '"a&b|c<d>e^f(g)"'),
        ("C:\\dir\\", '"C:\\dir\\\\"'),
        ("C:\\a\\b", '"C:\\a\\b"'),
        ("x\\\\", '"x\\\\\\\\"'),
    ],
)
def test_quote_batch_arg(arg, quoted):
    assert quote_batch_arg(arg) == quoted


@pytest.mark.parametrize(
    "arg", ['x" & calc & "', "100%", "%PATH%", "bang!", "a\nb", "a\rb", "a\x00b"]
)
def test_quote_batch_arg_refuses_characters_cmd_interprets_inside_quotes(arg):
    with pytest.raises(UnsafeCommandError):
        quote_batch_arg(arg)


def test_unsafe_command_error_is_caught_like_other_launch_failures():
    # Every call site catches (OSError, subprocess.SubprocessError).
    assert issubclass(UnsafeCommandError, subprocess.SubprocessError)


def test_batch_command_line_quotes_every_argument():
    line = batch_command_line(
        r"C:\Program Files (x86)\tools\run.bat",
        ["-o", "C:\\out dir\\", "pwn&cd>x"],
        r"C:\Windows\System32\cmd.exe",
    )
    assert line == (
        r'"C:\Windows\System32\cmd.exe" /d /v:off /s /c '
        r'""C:\Program Files (x86)\tools\run.bat" "-o" "C:\out dir\\" "pwn&cd>x""'
    )


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX passthrough")
def test_build_command_is_a_passthrough_off_windows():
    args = ["cdxgen", "-t", "python", "pwn&cd>x", 'q"uote', "100%"]
    assert build_command(args) == args


def test_windows_command_passes_a_missing_explicit_path_through():
    # CreateProcess does not search for a path, so it can report the error.
    from xbom_lib.process import _build_windows_command

    argv = [r"C:\no-such-dir\golem", "--version"]
    assert _build_windows_command(argv) == argv


def test_windows_command_refuses_a_bare_name_missing_from_path(monkeypatch):
    # A bare name would make CreateProcess search the current directory.
    from xbom_lib.process import _build_windows_command

    monkeypatch.setenv("PATH", "")
    with pytest.raises(FileNotFoundError):
        _build_windows_command(["no-such-tool-xyz", "--version"])


# ------------------------------------------------------ Windows integration


@pytest.fixture
def fake_tools(tmp_path, monkeypatch):
    """A directory with an npm shim and a plain batch wrapper that record argv."""
    bin_dir = tmp_path / "bin dir (x86)"
    script_dir = bin_dir / "node_modules" / "fake" / "bin"
    script_dir.mkdir(parents=True)
    (script_dir / "argv.js").write_text(
        "require('fs').writeFileSync(process.env.ARGV_OUT, "
        "JSON.stringify(process.argv.slice(2)));\n",
        encoding="utf-8",
    )
    (bin_dir / "fakecdx.cmd").write_text(
        NPM_SHIM_TEMPLATE.replace("{script}", r"node_modules\fake\bin\argv.js"),
        encoding="utf-8",
    )
    (bin_dir / "argv.py").write_text(
        "import json, os, sys\n"
        "with open(os.environ['ARGV_OUT'], 'w', encoding='utf-8') as f:\n"
        "    json.dump(sys.argv[1:], f)\n",
        encoding="utf-8",
    )
    (bin_dir / "wrapper.bat").write_text(
        f'@"{sys.executable}" -I "%~dp0argv.py" %*\r\n', encoding="utf-8"
    )
    argv_out = tmp_path / "argv.json"
    monkeypatch.setenv("ARGV_OUT", str(argv_out))
    monkeypatch.setenv("PATH", str(bin_dir) + os.pathsep + os.environ.get("PATH", ""))
    return bin_dir, argv_out


def _read_argv(argv_out):
    with open(argv_out, encoding="utf-8") as fp:
        return json.load(fp)


def _require_node():
    if not shutil.which("node"):
        pytest.skip("node is required for the npm shim test")


@windows_only
def test_npm_shim_runs_node_directly_and_keeps_every_argument(fake_tools):
    _require_node()
    bin_dir, argv_out = fake_tools
    args = ARGS_SAFE_FOR_ANY_BATCH + ARGS_NEEDING_DIRECT_NODE
    command = build_command(["fakecdx", *args])
    assert isinstance(command, list)
    assert command[1].endswith("argv.js")
    subprocess.run(command, shell=False, check=True)
    assert _read_argv(argv_out) == args


@windows_only
def test_plain_batch_file_gets_quoted_arguments(fake_tools):
    bin_dir, argv_out = fake_tools
    command = build_command([str(bin_dir / "wrapper.bat"), *ARGS_SAFE_FOR_ANY_BATCH])
    assert isinstance(command, str)
    subprocess.run(command, shell=False, check=True)
    assert _read_argv(argv_out) == ARGS_SAFE_FOR_ANY_BATCH


@windows_only
@pytest.mark.parametrize("arg", ARGS_NEEDING_DIRECT_NODE)
def test_plain_batch_file_refuses_arguments_it_cannot_quote(fake_tools, arg):
    bin_dir, _ = fake_tools
    with pytest.raises(UnsafeCommandError):
        build_command([str(bin_dir / "wrapper.bat"), arg])


def _payloads(work_dir):
    """The source values from GHSA-xpgh-m7fj-jqq9 and the marker each would create."""
    no_space_marker = work_dir / "marker-no-space.txt"
    quote_marker = work_dir / "marker-quote.txt"
    amp_dir = work_dir / "proj&mkdir,PWNED"
    amp_dir.mkdir()
    return [
        (f"pwn&cd>{no_space_marker}", no_space_marker),
        (f'x" & echo injected > {quote_marker} & rem "', quote_marker),
        (str(amp_dir), amp_dir / "PWNED"),
    ]


@windows_only
@pytest.mark.parametrize("tool", ["fakecdx.cmd", "wrapper.bat"])
def test_cdxgen_generator_does_not_execute_advisory_payloads(
    fake_tools, tmp_path, monkeypatch, tool
):
    if tool == "fakecdx.cmd":
        _require_node()
    bin_dir, argv_out = fake_tools
    monkeypatch.setenv("CDXGEN_CMD", str(bin_dir / tool))
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    for source, marker in _payloads(work_dir):
        if argv_out.exists():
            argv_out.unlink()
        result = CdxgenGenerator(
            source, str(work_dir / "bom.json"), options={"project_type": ["python"]}
        ).generate()
        assert not marker.exists(), f"payload executed: {source!r}"
        if tool == "wrapper.bat" and '"' in source:
            # cmd.exe cannot quote this argument, so the launch is refused.
            assert not result.success
            assert not argv_out.exists()
        else:
            assert result.success, result.command_output
            # The whole value reached the tool as its last argument.
            expected = os.path.abspath(source) if os.path.isdir(source) else source
            assert _read_argv(argv_out)[-1] == expected


@windows_only
def test_cdxgen_in_the_scanned_project_is_not_picked_up(fake_tools, tmp_path, monkeypatch):
    _require_node()
    bin_dir, argv_out = fake_tools
    (bin_dir / "cdxgen.cmd").write_text(
        NPM_SHIM_TEMPLATE.replace("{script}", r"node_modules\fake\bin\argv.js"),
        encoding="utf-8",
    )
    project = tmp_path / "untrusted project"
    project.mkdir()
    hijack_marker = project / "hijacked.txt"
    (project / "cdxgen.cmd").write_text(
        '@echo hijacked> "%~dp0hijacked.txt"\r\n', encoding="utf-8"
    )
    monkeypatch.delenv("CDXGEN_CMD", raising=False)
    # The CLI is often started from inside the project it scans.
    monkeypatch.chdir(project)
    result = CdxgenGenerator(
        str(project), str(tmp_path / "bom.json"), options={"project_type": ["python"]}
    ).generate()
    assert not hijack_marker.exists()
    assert result.success, result.command_output
    assert _read_argv(argv_out)[-1] == str(project)
