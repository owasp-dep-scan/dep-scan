"""Tests that keep the documentation's command line pages true to the code.

The usage page embeds the top-level help and the scan help exactly as the
built parsers print them, and the migration guide embeds the generated v6 to
v7 option table between markers, so neither page can drift from the code. The
remaining tests sweep every page under ``documentation/``: no fenced command
block may show a v6 (options-first) ``depscan`` invocation, and the removed
``depscan-vdb`` and ``depscan-validate`` console scripts may be named only in
the migration entry that documents their removal (the ``.depscan-vdb-image``
marker file keeps its name). Published schema names such as
``depscan-vdb-info-output`` name schema files, not the removed commands, so
the sweep strips them from a line before checking it. When one of these
fails, fix the page or regenerate the embedded block, not the test.
"""

import argparse
import re
from pathlib import Path

from analysis_lib.findings.schemas import schema_names
from depscan.commands import VERBS, build_parser
from depscan.commands.translate import option_table_markdown

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS_DIR = REPO_ROOT / "documentation"
USAGE_PAGE = DOCS_DIR / "docs" / "cli-usage.mdx"
MIGRATION_PAGE = DOCS_DIR / "docs" / "migrate-v6-to-v7.mdx"

#: Fenced block languages that hold shell commands.
COMMAND_LANGUAGES = frozenset({"bash", "sh", "shell", "zsh"})

TABLE_START = "<!-- v6-to-v7 option table start -->"
TABLE_END = "<!-- v6-to-v7 option table end -->"

#: The migration entry that names the removed console scripts; it is the one
#: place the old names may appear, because saying what was removed is its job.
CONSOLE_SCRIPT_ENTRY = "- **The `depscan-vdb` and `depscan-validate` console scripts are gone.**"

#: The marker file the code writes; its name contains a console-script name
#: but names a file, not a command (``VDB_IMAGE_MARKER_FILE`` in the config).
MARKER_FILE = ".depscan-vdb-image"

#: The published schema names, which may carry a console-script substring
#: (``depscan-vdb-download-output`` names a schema file, not a command); the
#: sweep strips them from a line before checking the line.
SCHEMA_NAMES = tuple(schema_names())

#: The text files under ``documentation/`` the console-script sweep reads;
#: images and other binaries are skipped.
TEXT_SUFFIXES = frozenset({".mdx", ".md", ".ts", ".js", ".json", ".yaml", ".yml", ".txt", ".css"})


def _read(path: Path) -> str:
    """The page text with line endings normalised, as text mode reads."""
    return path.read_text(encoding="utf-8")


def scan_help_text() -> str:
    """The scan subparser's help, found through the built registry."""
    parser = build_parser()
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction) and "scan" in action.choices:
            return action.choices["scan"].format_help()
    raise AssertionError("the verb registry registered no scan subparser")


def fenced_blocks(text: str, languages):
    """``(start_line, body_lines)`` of every fenced block in ``languages``.

    ``start_line`` is the 1-based line of the first body line.
    """
    lines = text.split("\n")
    blocks = []
    index = 0
    while index < len(lines):
        match = re.match(r"^\s*```(\w+)\s*$", lines[index])
        if match and match.group(1) in languages:
            start = index + 2
            body = []
            index += 1
            while index < len(lines) and not lines[index].lstrip().startswith("```"):
                body.append(lines[index])
                index += 1
            blocks.append((start, body))
        index += 1
    return blocks


def logical_commands(body_lines, start_line):
    """``(line_number, tokens)`` per command, continuations joined.

    A line ending in a backslash continues on the next line; the command
    carries the line it started on. Comment and empty lines between commands
    are skipped.
    """
    commands = []
    line_number = None
    tokens: list = []
    for offset, raw in enumerate(body_lines):
        stripped = raw.strip()
        if not tokens and (not stripped or stripped.startswith("#")):
            continue
        if not tokens:
            line_number = start_line + offset
        tokens.extend(stripped.removesuffix("\\").split())
        if not raw.rstrip().endswith("\\"):
            commands.append((line_number, tokens))
            tokens = []
    if tokens:
        commands.append((line_number, tokens))
    return commands


def _normalized_help(text: str) -> str:
    """Help text comparable across the supported Python versions.

    Two renderings differ between 3.11 and 3.13: the width argparse wraps at
    comes from the terminal, and 3.13 stopped repeating a short option's
    value placeholder in the option list (``-o, --reports-dir REPORTS_DIR``
    where 3.11 prints ``-o REPORTS_DIR, --reports-dir REPORTS_DIR``). The
    page is generated at a fixed wide ``COLUMNS`` with the modern rendering;
    the comparison normalizes both sides to it.
    """
    return re.sub(
        r"-([a-zA-Z]) ([A-Z_]+)((?: \[[A-Z_ ]+\.\.\.\])?)(, --[a-z][a-z0-9-]*) \2\3",
        r"-\1\4 \2\3",
        text,
    )


def test_usage_page_embeds_the_built_help(monkeypatch):
    """The two usage blocks are the parsers' own output at a fixed width."""
    monkeypatch.setenv("COLUMNS", "200")
    blocks = [
        body
        for _, body in fenced_blocks(_read(USAGE_PAGE), {"text"})
        if body and body[0].startswith("usage: depscan")
    ]
    assert len(blocks) == 2, "the usage page must carry exactly the top-level and the scan help"
    tops = [block for block in blocks if block[0].startswith("usage: depscan scan")]
    assert len(tops) == 1, "one of the two blocks must be the scan help"
    whole = [block for block in blocks if block not in tops]
    assert _normalized_help("\n".join(whole[0]) + "\n") == _normalized_help(
        build_parser().format_help()
    )
    assert _normalized_help("\n".join(tops[0]) + "\n") == _normalized_help(scan_help_text())


def test_migration_page_embeds_the_generated_option_table():
    """The region between the markers is option_table_markdown() exactly."""
    text = _read(MIGRATION_PAGE)
    start = text.find(TABLE_START + "\n")
    end = text.find(TABLE_END)
    assert start != -1 and end != -1, "the migration page must carry both table markers"
    region = text[start + len(TABLE_START) + 1 : end]
    assert region == option_table_markdown()


def test_no_v6_invocations_remain_in_the_docs():
    """Every depscan command in a fenced block starts with a verb.

    The first token after ``depscan`` must be a registered verb or a help
    flag; prefixes such as ``uv run``, ``docker run ...`` or environment
    assignments in front of ``depscan`` change nothing.
    """
    allowed_heads = set(VERBS) | {"-h", "--help", "version"}
    problems = []
    pages = sorted((DOCS_DIR / "docs").rglob("*.mdx"))
    assert pages, "the documentation pages were not found"
    for page in pages:
        for start_line, body in fenced_blocks(_read(page), COMMAND_LANGUAGES):
            for line_number, tokens in logical_commands(body, start_line):
                if "depscan" not in tokens:
                    continue
                rest = tokens[tokens.index("depscan") + 1 :]
                if not rest:
                    continue
                if rest[0] not in allowed_heads:
                    relative = page.relative_to(REPO_ROOT)
                    problems.append(f"{relative}:{line_number}: {' '.join(tokens)}")
    assert not problems, "v6-shaped depscan invocations left in the docs:\n" + "\n".join(problems)


def test_no_console_script_names_remain_in_the_docs():
    """The removed console scripts are named only where their removal is
    documented, and the marker file keeps its own name."""
    problems = []
    for path in sorted(DOCS_DIR.rglob("*")):
        if not path.is_file() or path.suffix not in TEXT_SUFFIXES:
            continue
        for line_number, line in enumerate(_read(path).split("\n"), start=1):
            if "depscan-vdb" not in line and "depscan-validate" not in line:
                continue
            if MARKER_FILE in line:
                continue
            without_schema_names = line
            for name in SCHEMA_NAMES:
                without_schema_names = without_schema_names.replace(name, "")
            if (
                "depscan-vdb" not in without_schema_names
                and "depscan-validate" not in without_schema_names
            ):
                continue
            if path == MIGRATION_PAGE and line.strip().startswith(CONSOLE_SCRIPT_ENTRY):
                continue
            problems.append(f"{path.relative_to(REPO_ROOT)}:{line_number}: {line.strip()}")
    assert not problems, "stale console script references in the docs:\n" + "\n".join(problems)
