"""Every depscan command the agent plugin shows parses with the real parser.

The skills, the agent and the reference files carry the command lines an
agent will run. A skill whose command drifted from the v7 verb surface
would teach the wrong thing silently, so this test extracts every
``depscan`` command the plugin publishes and parses each one through the
same argument parser the repository's own docs are checked with.

The extractor is the one from ``test_repo_invocations.py``, narrowed to the
plugin's Markdown files: a command starts a line, follows ``run`` or
follows a shell separator, and prose that merely mentions depscan never
counts.
"""

import re
from pathlib import Path

import pytest

from depscan.commands import VERBS, build_parser

PLUGIN_ROOT = Path(__file__).resolve().parent.parent / "agent-plugin"

#: The verbs plus the help flags argparse answers before any verb is needed.
ACCEPTED_FIRST_TOKENS = frozenset(VERBS) | {"-h", "--help"}

_DEPSCAN_WORD = re.compile(r"(?<![\w/.=@$-])(depscan)(?=$|\s)")
_COMMAND_PREFIXES = frozenset({"run", "&&", "||", ";", "|"})
_TRAILING_PROSE = "\"'.,):;"
_SEPARATORS = "|&;>`"


def _walk_plugin_files():
    for path in sorted(PLUGIN_ROOT.rglob("*.md")):
        yield path


def _join_continuations(text):
    joined = []
    buffer = ""
    start = 0
    for lineno, line in enumerate(text.splitlines(), start=1):
        buffer = f"{buffer} {line.strip()}" if buffer else line
        start = start or lineno
        if buffer.rstrip().endswith("\\"):
            buffer = buffer.rstrip()[:-1].rstrip()
            continue
        joined.append((start, buffer))
        buffer = ""
        start = 0
    if buffer:
        joined.append((start, buffer))
    return joined


def _tokenize(tail):
    tokens = []
    current = ""
    quote = None
    for char in tail:
        if quote:
            if char == quote:
                quote = None
            else:
                current += char
        elif char in "\"'":
            quote = char
        elif char in _SEPARATORS:
            break
        elif char.isspace():
            if current:
                tokens.append(current)
                current = ""
        else:
            current += char
    if current:
        tokens.append(current)
    while tokens and not tokens[-1].rstrip(_TRAILING_PROSE):
        tokens.pop()
    if tokens:
        tokens[-1] = tokens[-1].rstrip(_TRAILING_PROSE)
        if not tokens[-1]:
            tokens.pop()
    return tokens


def _in_command_position(line, match, in_fence=False):
    """A command position: line start, after run or a shell separator, or
    any full line inside a fenced code block, which is where the skills
    write the commands an agent runs."""
    if in_fence and line.lstrip().startswith("depscan "):
        return True
    prefix = line[: match.start()].rstrip()
    if not prefix:
        return True
    last = prefix.split()[-1]
    return last in _COMMAND_PREFIXES


def extract_invocations() -> list[tuple[Path, int, list[str]]]:
    """Every ``(path, lineno, argv)`` depscan command in the plugin files."""
    found = []
    for path in _walk_plugin_files():
        text = path.read_text(encoding="utf-8")
        in_fence = False
        for lineno, line in _join_continuations(text):
            stripped = line.lstrip()
            if stripped.startswith("```"):
                in_fence = not in_fence
                continue
            for match in _DEPSCAN_WORD.finditer(line):
                if not _in_command_position(line, match, in_fence):
                    continue
                tokens = _tokenize(line[match.end() :])
                if not tokens:
                    continue
                found.append((path, lineno, ["depscan", *tokens]))
    return found


def test_the_extractor_finds_the_published_commands():
    """A positive control: the plugin publishes command lines to check.

    Without this an extractor bug would turn the parse test below into an
    empty pass.
    """
    invocations = extract_invocations()
    verbs = {argv[1] for _, _, argv in invocations}
    assert len(invocations) >= 10, f"only {len(invocations)} commands found"
    assert {"scan", "report", "vdb"} <= verbs, f"expected verbs missing: {verbs}"


@pytest.mark.parametrize(
    "path,lineno,argv",
    extract_invocations(),
    ids=lambda argv: " ".join(argv)[:60] if isinstance(argv, list) else "",
)
def test_every_published_command_parses(path, lineno, argv):
    """The command parses with the real argument parser."""
    where = f"{path.relative_to(PLUGIN_ROOT.parent)}:{lineno}"
    try:
        build_parser().parse_args(argv[1:])
    except SystemExit:
        pytest.fail(f"{where}: the parser rejects the command: {' '.join(argv)}")


def test_no_published_command_is_a_v6_shape():
    """A command whose first token is an option is the v6 options-first shape."""
    offenders = [
        f"{path.relative_to(PLUGIN_ROOT.parent)}:{lineno}: {' '.join(argv)}"
        for path, lineno, argv in extract_invocations()
        if argv[1].startswith("-") and argv[1] not in ("-h", "--help")
    ]
    assert not offenders, "v6 invocations remain in the plugin: " + "\n".join(offenders)
