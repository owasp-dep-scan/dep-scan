"""The sibling tools' published commands match the tools' real command lines.

The plugin's skills run golem, kosi, rusi, dosai, atom, atom-tools, blint,
trustinspector, trivy-cdxgen, the v7 vdb CLI and cdx-audit directly. A
renamed flag or subcommand in one of those tools would teach a broken
command silently, so this test extracts every sibling-tool command the
plugin publishes from fenced code blocks (continuation lines joined),
resolves the tool, and asserts that the command's subcommand exists and
that each flag is one the tool's own help lists, compared as whole tokens.
golem commands are also checked for positional arguments, which golem
ignores (it reads the project from ``-dir``).

A tool that is not installed on this machine is recorded as a skip with
that reason: the published commands stay checked wherever the tool
exists, and the skip is the machine's fact, not a pass. The plugin tools
are found through the variables cdxgen and dep-scan read (``GOLEM_CMD``,
``KOSI_CMD`` and so on), ``DEPSCAN_PLUGINS_DIR`` (a
``cdxgen-plugins-bin`` ``plugins`` directory), ``PATH``, and the global npm
install of ``@cdxgen/cdxgen-plugins-bin-<platform>``.
"""

import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from functools import lru_cache
from pathlib import Path

import pytest

from test.test_agent_plugin_commands import _join_continuations

PLUGIN_ROOT = Path(__file__).resolve().parent.parent / "agent-plugin"

#: tool -> (published command name pattern, plugins sub-directory and
#: binary prefix, or None, environment variables that name the command)
TOOLS = {
    "golem": (r"golem", ("golem", "golem-"), ("GOLEM_CMD", "DEPSCAN_GOLEM_BINARY")),
    "kosi": (r"kosi", ("kosi", "kosi-"), ("KOSI_CMD",)),
    "rusi": (r"rusi", ("rusi", "rusi-"), ("RUSI_CMD", "DEPSCAN_RUSI_BINARY")),
    "dosai": (r"dosai", ("dosai", "dosai-"), ("DOSAI_CMD",)),
    "atom": (r"atom", None, ("ATOM_CMD",)),
    "atom-tools": (r"atom-tools", None, ()),
    "blint": (r"blint", None, ()),
    "vdb": (r"vdb", None, ()),
    "cdx-audit": (r"cdx-audit", None, ()),
    "trustinspector": (
        r"trustinspector-cdxgen-\S+",
        ("trustinspector", "trustinspector-cdxgen-"),
        ("TRUSTINSPECTOR_CMD",),
    ),
    "trivy-cdxgen": (r"trivy-cdxgen-\S+", ("trivy", "trivy-cdxgen-"), ("TRIVY_CMD",)),
}

#: The plugin tools' published commands were verified with
#: cdxgen-plugins-bin 4.3.1; older releases lack -roots,
#: -reachable-symbols and rusi's -o/--out, so they are skipped by name.
MIN_PLUGIN_VERSION = {"golem": (4, 3, 1), "rusi": (4, 3, 1), "kosi": (4, 3, 1)}

#: Global options a tool accepts before its subcommand.
LEADING_GLOBAL_FLAGS = {"blint": {"--no-banner"}}

_FENCE = re.compile(r"^\s*```")
_ENV_ASSIGNMENT = re.compile(r"^[A-Z_][A-Z0-9_]*=\S*$")
_SUBCOMMAND = re.compile(r"^[a-z][a-z-]*$")
_FLAG_IN_HELP = re.compile(r"(?<![\w-])(--?[A-Za-z][\w-]*)")
_HELP_FAILURE = re.compile(
    r"flag provided but not defined|unknown (?:command|argument|subcommand)|"
    r"unrecognized (?:arguments|subcommand)|invalid choice|Could not parse command line",
    re.IGNORECASE,
)


def published_commands(tool: str) -> list[tuple[Path, int, list[str]]]:
    """Every fenced-block command the plugin publishes for a tool."""
    pattern = TOOLS[tool][0]
    needle = re.compile(rf"^(?:[A-Z_][A-Z0-9_]*=\S*\s+)*{pattern}(?:\s|$)")
    found = []
    for path in sorted(PLUGIN_ROOT.rglob("*.md")):
        in_fence = False
        for lineno, line in _join_continuations(path.read_text(encoding="utf-8")):
            if _FENCE.match(line):
                in_fence = not in_fence
                continue
            if not in_fence or not needle.match(line.strip()):
                continue
            tokens = []
            for token in line.split():
                if token in (">", ">>", "|", "&&", ";", "2>&1"):
                    break
                tokens.append(token)
            while tokens and _ENV_ASSIGNMENT.match(tokens[0]):
                tokens.pop(0)
            found.append((path, lineno, tokens))
    return found


@lru_cache(maxsize=None)
def _npm_plugins_dirs() -> tuple[Path, ...]:
    npm = shutil.which("npm")
    if not npm:
        return ()
    try:
        root = subprocess.run(
            [npm, "root", "-g"], capture_output=True, text=True, timeout=30, check=False
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ()
    if not root:
        return ()
    return tuple(sorted(Path(root).glob("@cdxgen/cdxgen-plugins-bin-*/plugins")))


def _from_plugins_dir(base: Path, layout) -> str | None:
    directory, prefix = layout
    for candidate in sorted((base / directory).glob(f"{prefix}*")):
        if candidate.is_file() and candidate.suffix != ".sha256" and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def resolve_command(tool: str) -> list[str] | None:
    """The tool's command on this machine, or None.

    The command variables win, then the environment that runs the tests
    (it carries the blint, atom-tools and vdb versions dep-scan pins), then
    DEPSCAN_PLUGINS_DIR, PATH and the global plugins package.
    """
    _, layout, env_names = TOOLS[tool]
    for name in env_names:
        value = os.environ.get(name)
        if value:
            return shlex.split(value)
    scripts = Path(sys.executable).parent
    for suffix in ("", ".exe"):
        local = scripts / f"{tool}{suffix}"
        if local.is_file():
            return [str(local)]
    plugins_dir = os.environ.get("DEPSCAN_PLUGINS_DIR")
    if layout and plugins_dir:
        found = _from_plugins_dir(Path(plugins_dir), layout)
        if found:
            return [found]
    direct = shutil.which(tool)
    if direct:
        return [direct]
    if layout:
        for base in _npm_plugins_dirs():
            found = _from_plugins_dir(base, layout)
            if found:
                return [found]
    return None


@lru_cache(maxsize=None)
def help_text(command: tuple[str, ...], subcommand: tuple[str, ...], tool: str) -> tuple[str, str]:
    """(root help, subcommand help) as printed by the tool."""
    env = dict(os.environ)
    if tool == "dosai":
        # The released dosai targets a .NET runtime older than some
        # machines carry; the roll-forward is the documented way to run it.
        env.setdefault("DOTNET_ROLL_FORWARD", "LatestMajor")

    def run(argv):
        proc = subprocess.run(
            [*command, *argv], capture_output=True, text=True, timeout=120, env=env, check=False
        )
        return proc.stdout + proc.stderr

    root = run(["--help"])
    sub = run([*subcommand, "--help"]) if subcommand else ""
    return root, sub


def split_command(tool: str, tokens: list[str]) -> tuple[tuple[str, ...], list[str]]:
    """(subcommand words, the remaining tokens) of one published command."""
    rest = tokens[1:]
    leading = []
    while rest and rest[0] in LEADING_GLOBAL_FLAGS.get(tool, set()):
        leading.append(rest.pop(0))
    words = []
    while rest and _SUBCOMMAND.match(rest[0]) and len(words) < 2:
        words.append(rest.pop(0))
        # Only `vdb db status` nests two levels deep.
        if not (tool == "vdb" and words == ["db"]):
            break
    return tuple(words), leading + rest


def golem_boolean_flags(sub_help: str) -> set[str]:
    """golem's flags that take no value: Go prints them without a type."""
    return {match.group(1) for match in re.finditer(r"^\s+(-[\w-]+)\s*$", sub_help, re.MULTILINE)}


def tool_version(command: tuple[str, ...]) -> tuple[int, ...] | None:
    """The first dotted version a tool prints for --version, or None."""
    try:
        proc = subprocess.run(
            [*command, "--version"], capture_output=True, text=True, timeout=60, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    output = proc.stdout + proc.stderr
    try:
        # kosi prints one JSON line whose top-level "version" is its own.
        output = str(json.loads(proc.stdout).get("version", ""))
    except (ValueError, AttributeError):
        pass
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", output)
    return tuple(int(part) for part in match.groups()) if match else None


def golem_positionals(rest: list[str], booleans: set[str]) -> list[str]:
    """The tokens of a golem command that are neither flags nor flag values."""
    positional = []
    expecting_value = False
    for token in rest:
        if expecting_value:
            expecting_value = False
            continue
        if token.startswith("-"):
            expecting_value = "=" not in token and token not in booleans
            continue
        positional.append(token)
    return positional


@pytest.mark.parametrize("tool", sorted(TOOLS))
def test_published_tool_commands_match_the_tool_help(tool):
    """Every published command names a real subcommand and real flags."""
    commands = published_commands(tool)
    assert commands, f"no {tool} commands found in the plugin; the extractor broke"
    command = resolve_command(tool)
    if not command:
        pytest.skip(
            f"{tool} is not installed on this machine; its published commands stay unchecked here"
        )
    minimum = MIN_PLUGIN_VERSION.get(tool)
    if minimum:
        version = tool_version(tuple(command))
        if version is None or version < minimum:
            pytest.skip(
                f"{tool} {'.'.join(map(str, version or ())) or '(unknown version)'} is older than the "
                f"{'.'.join(map(str, minimum))} the published commands target; they stay unchecked here"
            )
    problems = []
    for path, lineno, tokens in commands:
        where = f"{path.relative_to(PLUGIN_ROOT.parent)}:{lineno}"
        subcommand, rest = split_command(tool, tokens)
        root_help, sub_help = help_text(tuple(command), subcommand, tool)
        if (
            tool == "atom"
            and subcommand
            and f"|{subcommand[0]}" not in root_help
            and f"[{subcommand[0]}" not in root_help
        ):
            pytest.skip(
                f"the installed atom has no {subcommand[0]} command (it needs atom 4.0.2 "
                "or newer); its published commands stay unchecked here"
            )
        if (
            tool == "blint"
            and subcommand
            and subcommand[0] in ("diff", "capabilities")
            and subcommand[0] not in root_help
        ):
            # Published for blint 4 and marked so; dep-scan's extra pins 3.2.x.
            continue
        if subcommand:
            if not re.search(
                rf"(?<![\w-]){re.escape(subcommand[-1])}(?![\w-])", root_help + sub_help
            ):
                problems.append(f"{where}: {tool} has no subcommand {' '.join(subcommand)}")
                continue
            if _HELP_FAILURE.search(sub_help):
                problems.append(f"{where}: `{tool} {' '.join(subcommand)} --help` was refused")
                continue
        known = set(_FLAG_IN_HELP.findall(root_help + "\n" + sub_help))
        for token in rest:
            if not token.startswith("-") or token == "--":
                continue
            flag = token.split("=", 1)[0]
            if flag not in known:
                problems.append(f"{where}: {tool} help does not list {flag}")
        if tool == "golem":
            for token in golem_positionals(rest, golem_boolean_flags(sub_help)):
                problems.append(
                    f"{where}: golem ignores the positional argument {token}; pass the project as -dir"
                )
    assert not problems, "\n".join(problems)


def test_the_flag_match_is_whole_token():
    """A positive control: `-o` is not accepted because `--out` exists."""
    known = set(_FLAG_IN_HELP.findall("  -out string\n  --output <file>\n  -dir string"))
    assert "-out" in known
    assert "-o" not in known


def test_continuation_lines_are_checked():
    """A flag on a continuation line reaches the check."""
    commands = published_commands("golem")
    assert any("-reachable-symbols" in tokens for _, _, tokens in commands)
    assert all("\\" not in tokens for _, _, tokens in commands)


def test_golem_positional_paths_are_caught():
    """A positive control for the golem rule on a command written the old way."""
    _, rest = split_command(
        "golem", ["golem", "analyze", "-callgraph", "rta", "-out", "/tmp/x.json", "/abs/project"]
    )
    sub_help = "  -callgraph string\n  -out string\n  -include-stdlib\n"
    booleans = golem_boolean_flags(sub_help)
    assert booleans == {"-include-stdlib"}
    assert golem_positionals(rest, booleans) == ["/abs/project"]
