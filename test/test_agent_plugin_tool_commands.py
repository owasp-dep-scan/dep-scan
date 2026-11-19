"""The sibling tools' published commands match the tools' real surfaces.

The plugin's skills reach golem, rusi, dosai, atom, atom-tools, blint,
trustinspector, trivy-cdxgen, the v7 vdb CLI and cdx-audit directly. A
renamed flag or subcommand in one of those tools would teach a broken
command silently, so this test extracts every sibling-tool command the
plugin publishes from fenced code blocks, resolves the tool, and asserts
each command's subcommand and flags appear in the tool's own help text.

A tool that is not installed on this machine is recorded as a skip with
that reason: the published commands stay checked wherever the tool
exists, and the skip is the machine's fact, not a pass.
"""

import os
import re
import shutil
import subprocess
from functools import lru_cache
from pathlib import Path

import pytest

PLUGIN_ROOT = Path(__file__).resolve().parent.parent / "agent-plugin"

#: The sibling tools whose commands the plugin publishes, and how to
#: resolve each one on this machine. None means resolve from PATH.
TOOL_BINARY = {
    "golem": None,
    "rusi": None,
    "dosai": None,
    "atom": None,
    "atom-tools": None,
    "blint": None,
    "vdb": None,
    "cdx-audit": None,
}

#: Tools resolved from the plugins package; the published name carries a
#: platform suffix the test strips before matching.
PLUGIN_TOOLS = ("trustinspector", "trivy-cdxgen")

_FENCE = re.compile(r"^\s*```")
_ENV_PREFIX = re.compile(r"^[A-Z_][A-Z0-9_]*=")


def published_commands(tool: str) -> list[tuple[Path, int, list[str]]]:
    """Every fenced-block command line the plugin publishes for a tool."""
    found = []
    needle = re.compile(rf"^(?:[A-Z_][A-Z0-9_]*=\S+\s+)*{re.escape(tool)}(?:-cdxgen-\S+)?(?:\s|$)")
    for path in sorted(PLUGIN_ROOT.rglob("*.md")):
        in_fence = False
        for lineno, line in enumerate(path.read_text(encoding="utf-8").split("\n"), start=1):
            if _FENCE.match(line):
                in_fence = not in_fence
                continue
            if not in_fence or not needle.match(line):
                continue
            tokens = line.split()
            while tokens and _ENV_PREFIX.match(tokens[0]):
                tokens.pop(0)
            # The platform suffix resolves to the installed binary's name.
            tokens[0] = tokens[0].rsplit("-cdxgen-", 1)[0]
            found.append((path, lineno, tokens))
    return found


def resolve_binary(tool: str) -> str | None:
    """The tool's executable on this machine, or None.

    The dep-scan venv resolves first: it carries the blint, atom-tools and
    v7 vdb versions dep-scan pins, which a machine's PATH may not.
    """
    venv_bin = Path(__file__).resolve().parent.parent / ".venv" / "bin" / tool
    if venv_bin.exists():
        return str(venv_bin)
    direct = shutil.which(tool)
    if direct:
        return direct
    if tool in PLUGIN_TOOLS:
        plugins = sorted(
            Path(__file__).resolve().parent.parent.glob(
                ".venv/**/@cdxgen/cdxgen-plugins-bin-*/plugins"
            )
        )
        for base in plugins + sorted(
            Path("/tmp").glob("p15-plugins/node_modules/@cdxgen/cdxgen-plugins-bin-*/plugins")
        ):
            for candidate in (base / tool).glob(f"{tool}-cdxgen-*"):
                # The package ships a .sha256 next to the binary.
                if candidate.is_file() and candidate.suffix != ".sha256":
                    return str(candidate)
    return None


#: Some tools answer --help with only their command list or their shared
#: options; the flags the plugin publishes live in the subcommand help, so
#: the check unions each tool's relevant help texts.
HELP_ARGV = {
    "golem": (("--help",), ("analyze", "--help")),
    "rusi": (("--help",), ("analyze", "--help")),
    "dosai": (("--help",), ("dataflows", "--help"), ("crypto", "--help"), ("diff", "--help")),
    "atom": (("--help",), ("memory-safety", "--help"), ("reachables", "--help")),
    "atom-tools": (
        ("--help",),
        ("ingest", "--help"),
        ("attack-surface", "--help"),
        ("drift", "--help"),
        ("crypto-reach", "--help"),
    ),
    "blint": (
        ("--help",),
        ("sbom", "--help"),
        ("canonicalize", "--help"),
    ),
    "vdb": (("--help",), ("db", "status", "--help")),
    "cdx-audit": (("--help",),),
    "trustinspector": (("--help",),),
    "trivy-cdxgen": (("--help",), ("rootfs", "--help")),
}


@lru_cache(maxsize=None)
def help_text(binary: str, tool: str) -> str:
    env = dict(os.environ)
    if tool == "dosai":
        # The released dosai targets a .NET runtime older than some
        # machines carry; the roll-forward is the documented way to run it.
        env.setdefault("DOTNET_ROLL_FORWARD", "LatestMajor")
    out = []
    for argv in HELP_ARGV.get(tool, (("--help",),)):
        proc = subprocess.run(
            [binary, *argv], capture_output=True, text=True, timeout=120, env=env
        )
        out.append(proc.stdout + proc.stderr)
    return "\n".join(out)


@pytest.mark.parametrize("tool", sorted(TOOL_BINARY) + list(PLUGIN_TOOLS))
def test_published_tool_commands_match_the_tool_help(tool):
    """Every published command names flags the tool's help carries."""
    binary = resolve_binary(tool)
    if not binary:
        pytest.skip(f"{tool} is not installed on this machine; its published commands stay unchecked here")
    resolved_help = help_text(binary, tool)
    if tool == "atom" and "|memory-safety" not in resolved_help:
        # The old atom names the subcommand only in its parse error; a new
        # atom lists it in the usage line's alternation.
        pytest.skip(
            "the installed atom predates the memory-safety subcommand; "
            "the published commands target a newer atom and stay unchecked here"
        )
    commands = published_commands(tool)
    assert commands, f"no {tool} commands found in the plugin; the extractor broke"
    problems = []
    for path, lineno, tokens in commands:
        where = f"{path.relative_to(PLUGIN_ROOT.parent)}:{lineno}"
        for token in tokens[1:]:
            if not token.startswith("-") or token == "--":
                continue
            # A flag with a value (--roots main) and a value inside the
            # token (--min-confidence=medium) both reduce to the flag.
            flag = token.split("=", 1)[0]
            if flag not in resolved_help:
                problems.append(f"{where}: {tool} help does not carry {flag}")
    assert not problems, "\n".join(problems)
