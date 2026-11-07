"""Tests for xbom_lib.process, which starts external tools without a shell.

The unit tests run everywhere. The tests marked ``windows_only`` start real
batch files and check two things: that every argument reaches the tool
unchanged, and that cmd.exe syntax inside an argument, such as the payloads
from GHSA-xpgh-m7fj-jqq9, is never executed.
"""

import ast
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from xbom_lib.cdxgen import CdxgenGenerator
from xbom_lib.process import (
    UNSAFE_BATCH_ARG_CHARS,
    UnsafeCommandError,
    _build_windows_command,
    batch_command_line,
    build_command,
    find_executable,
    npm_shim_command,
    parse_npm_shim,
    quote_batch_arg,
    tool_env,
    windows_suffix,
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

# Arguments that any batch file receives intact once quoted.
ARGS_SAFE_FOR_ANY_BATCH = [
    "plain",
    "with space",
    "C:\\dir with space\\",
    "trailing\\",
    "",
    "Program Files (x86)",
    "unicode-\u00fc\u00f1\u00ef",
]
# Arguments that only the npm shim path delivers. cmd.exe cannot quote the
# first group at all, and a batch wrapper that uses %~1 or copies %* into a
# variable would run the second group, so plain batch files refuse both.
ARGS_NEEDING_DIRECT_NODE = [
    'say "hi"',
    "100%",
    "%PATH%",
    "bang!",
    "a&b",
    "a|b",
    "a<b>c",
    "a^b",
    "pwn&cd>marker.txt",
]


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
        ("proj (1) [x]", '"proj (1) [x]"'),
        ("C:\\dir\\", '"C:\\dir\\\\"'),
        ("C:\\a\\b", '"C:\\a\\b"'),
        ("x\\\\", '"x\\\\\\\\"'),
    ],
)
def test_quote_batch_arg(arg, quoted):
    assert quote_batch_arg(arg) == quoted


@pytest.mark.parametrize(
    "arg",
    ['x" & calc & "', "100%", "%PATH%", "bang!", "a\nb", "a\rb", "a\x00b"]
    + ["a&b", "a|b", "a<b", "a>b", "a^b"],
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
        ["-o", "C:\\out dir\\", "proj (1)"],
        r"C:\Windows\System32\cmd.exe",
    )
    assert line == (
        r'"C:\Windows\System32\cmd.exe" /d /v:off /s /c '
        r'""C:\Program Files (x86)\tools\run.bat" "-o" "C:\out dir\\" "proj (1)""'
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


@pytest.mark.parametrize(
    "name,suffix",
    [
        ("run.bat", ".bat"),
        ("RUN.CMD", ".cmd"),
        ("run.bat.", ".bat"),
        ("run.bat ", ".bat"),
        ("run.bat. .", ".bat"),
        (r"C:\a.b\tool", ""),
        ("tool.exe", ".exe"),
    ],
)
def test_windows_suffix_ignores_trailing_dots_and_spaces(name, suffix):
    assert windows_suffix(name) == suffix


def test_windows_which_prefers_pathext_names_for_an_explicit_path():
    # npm writes an extensionless shell script next to cdxgen.cmd.
    files = {r"C:\npm\cdxgen", r"C:\npm\cdxgen.CMD"}
    assert (
        windows_which(r"C:\npm\cdxgen", pathext=".EXE;.CMD", isfile=lambda p: p in files)
        == r"C:\npm\cdxgen.CMD"
    )
    # A name with another extension is still tried as given.
    assert (
        windows_which(r"C:\x\tool.v2", pathext=".EXE", isfile=lambda p: p == r"C:\x\tool.v2")
        == r"C:\x\tool.v2"
    )


def test_windows_which_strips_whitespace_in_pathext():
    files = {r"C:\b\run.BAT"}
    assert (
        windows_which("run", path_env=r"C:\b", pathext=".EXE; .BAT ", isfile=lambda p: p in files)
        == r"C:\b\run.BAT"
    )


@pytest.mark.parametrize("name", ["run.bat.", "run.cmd "])
def test_batch_file_with_trailing_dot_or_space_goes_through_quoting(tmp_path, name):
    batch = tmp_path / name
    batch.write_text("@echo off\r\n")
    command = _build_windows_command([str(batch), "a b"])
    assert isinstance(command, str)
    assert " /d /v:off /s /c " in command
    with pytest.raises(UnsafeCommandError):
        _build_windows_command([str(batch), "a&mkdir,PWN"])


def test_programs_that_are_not_executables_or_batch_files_are_refused(tmp_path):
    script = tmp_path / "tool.ps1"
    script.write_text("calc\n")
    with pytest.raises(UnsafeCommandError):
        _build_windows_command([str(script), "--version"])


def test_tool_env_blocks_current_directory_lookups_on_windows(monkeypatch):
    base = {"PATH": "x"}
    monkeypatch.setattr(sys, "platform", "win32")
    env = tool_env(base)
    assert env["NoDefaultCurrentDirectoryInExePath"] == "1"
    assert base == {"PATH": "x"}
    monkeypatch.setattr(sys, "platform", "linux")
    assert "NoDefaultCurrentDirectoryInExePath" not in tool_env(base)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX lookup")
def test_find_executable_uses_shutil_which_off_windows(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
    assert find_executable("golem") == "/usr/bin/golem"


XBOM_LIB_DIR = (
    Path(__file__).resolve().parent.parent / "packages" / "xbom-lib" / "src" / "xbom_lib"
)
LAUNCH_FUNCTIONS = {"run", "Popen", "call", "check_call", "check_output"}


def _launch_calls():
    for module in sorted(XBOM_LIB_DIR.glob("*.py")):
        source = module.read_text(encoding="utf-8")
        if module.name != "process.py":
            assert "shutil.which(" not in source, module.name
        for node in ast.walk(ast.parse(source, filename=str(module))):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "subprocess"
                and node.func.attr in LAUNCH_FUNCTIONS
            ):
                yield module.name, node


def test_every_tool_launch_in_xbom_lib_goes_through_build_command():
    calls = list(_launch_calls())
    assert len(calls) >= 9
    for module, call in calls:
        where = f"{module}:{call.lineno}"
        if module == "plugins.py":
            # ldd --version, Linux only, fixed arguments.
            continue
        first = call.args[0] if call.args else None
        assert (
            isinstance(first, ast.Call)
            and isinstance(first.func, ast.Name)
            and first.func.id == "build_command"
        ), where
        keywords = {kw.arg: kw.value for kw in call.keywords}
        assert isinstance(keywords.get("shell"), ast.Constant), where
        assert keywords["shell"].value is False, where
        env = keywords.get("env")
        assert (
            isinstance(env, ast.Call)
            and isinstance(env.func, ast.Name)
            and env.func.id == "tool_env"
        ), where


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
        if tool == "wrapper.bat" and set(source) & UNSAFE_BATCH_ARG_CHARS:
            # A plain batch file never receives these characters.
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


def _clear_tool_env(monkeypatch):
    for tool in ("RUSI", "GOLEM", "DOSAI"):
        monkeypatch.delenv(f"{tool}_CMD", raising=False)
        monkeypatch.delenv(f"DEPSCAN_{tool}_BINARY", raising=False)
    monkeypatch.delenv("CDXGEN_PLUGINS_DIR", raising=False)


@windows_only
def test_plugins_in_the_current_directory_are_not_picked_up(tmp_path, monkeypatch):
    from xbom_lib import dosai, golem, rusi

    project = tmp_path / "untrusted go project"
    project.mkdir()
    for name in ("rusi.cmd", "golem.bat", "dosai.cmd", "Dosai.bat"):
        (project / name).write_text(
            f'@echo planted> "%~dp0PLANTED_{name}.txt"\r\n', encoding="utf-8"
        )
    _clear_tool_env(monkeypatch)
    monkeypatch.setenv("PATH", os.environ.get("SystemRoot", r"C:\Windows") + r"\System32")
    monkeypatch.chdir(project)
    for find, version in (
        (rusi.find_rusi_binary, rusi.get_rusi_version),
        (golem.find_golem_binary, golem.get_golem_version),
        (dosai.find_dosai_binary, dosai.get_dosai_version),
    ):
        binary = find()
        assert binary is None or not os.path.abspath(binary).startswith(str(project)), binary
        if binary:
            version(binary)
    assert not list(project.glob("PLANTED_*"))


@windows_only
def test_batch_wrapper_does_not_run_node_from_the_scanned_project(
    fake_tools, tmp_path, monkeypatch
):
    _require_node()
    bin_dir, argv_out = fake_tools
    # A wrapper that runs a bare "node", as pnpm and older npm shims do.
    wrapper = bin_dir / "barenode.cmd"
    wrapper.write_text('@node "%~dp0node_modules\\fake\\bin\\argv.js" %*\r\n', encoding="utf-8")
    project = tmp_path / "untrusted js project"
    project.mkdir()
    (project / "node.bat").write_text(
        '@echo planted> "%~dp0PLANTED_node.txt"\r\n', encoding="utf-8"
    )
    monkeypatch.setenv("CDXGEN_CMD", str(wrapper))
    result = CdxgenGenerator(
        str(project), str(tmp_path / "bom.json"), options={"project_type": ["js"]}
    ).generate()
    assert not (project / "PLANTED_node.txt").exists()
    assert result.success, result.command_output
    assert _read_argv(argv_out)[-1] == str(project)
