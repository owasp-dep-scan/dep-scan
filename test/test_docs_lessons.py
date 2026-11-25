"""Tests that keep the lesson pages, their scripts and their expectations
one document.

Every lesson lives in a directory under ``documentation/lessons/<name>/``
with the script ``run.sh`` and an ``expect.txt`` of output lines the
workflow greps for. The lesson page under ``documentation/docs/lessons/``
embeds the script verbatim in one fenced bash block and quotes the
expectation lines in its output block, so a reader, the page and the CI job
that re-runs the lesson cannot drift apart. When one of these fails, fix the
page or the script, never the test: the failure means the three copies of a
command or a quoted line disagree.
"""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LESSONS_DIR = REPO_ROOT / "documentation" / "lessons"
PAGES_DIR = REPO_ROOT / "documentation" / "docs" / "lessons"


def lesson_dirs():
    """Every lesson directory with a script, in name order."""
    return sorted(path for path in LESSONS_DIR.iterdir() if path.is_dir())


def fenced_bash_blocks(text: str):
    """The bodies of every fenced ```bash block in the page text."""
    blocks = []
    lines = text.split("\n")
    index = 0
    while index < len(lines):
        if re.match(r"^```bash\s*$", lines[index]):
            body = []
            index += 1
            while index < len(lines) and not lines[index].lstrip().startswith("```"):
                body.append(lines[index])
                index += 1
            blocks.append("\n".join(body))
        index += 1
    return blocks


def test_every_lesson_has_script_and_expectations():
    """Each lesson directory carries a runnable script and expectations."""
    assert lesson_dirs(), "the lessons directory was not found"
    for directory in lesson_dirs():
        script = directory / "run.sh"
        expect = directory / "expect.txt"
        assert script.is_file(), f"{directory.name} has no run.sh"
        assert expect.is_file(), f"{directory.name} has no expect.txt"
        assert expect.read_text().strip(), f"{directory.name} has empty expect.txt"


def test_every_script_is_bash_with_pinned_inputs():
    """A script states its needs in a comment and stops on its own errors."""
    for directory in lesson_dirs():
        text = (directory / "run.sh").read_text()
        assert text.startswith("#!/usr/bin/env bash\n"), (
            f"{directory.name}/run.sh must start with the bash shebang"
        )
        assert "set -euo pipefail" in text, (
            f"{directory.name}/run.sh must stop on its own errors"
        )


def test_page_embeds_the_script_verbatim():
    """The page's bash block is the script, byte for byte (a fenced block
    never carries the file's final newline, so both sides are compared
    without one)."""
    pages = sorted(PAGES_DIR.glob("*.mdx"))
    assert pages, "the lesson pages were not found"
    by_name = {}
    for directory in lesson_dirs():
        by_name[directory.name] = directory
    for page in pages:
        assert page.stem in by_name, (
            f"{page.name} has no lesson directory named {page.stem}"
        )
        script = (by_name[page.stem] / "run.sh").read_text().rstrip("\n")
        blocks = [block.rstrip("\n") for block in fenced_bash_blocks(page.read_text())]
        assert script in blocks, (
            f"{page.name} must embed {page.stem}/run.sh verbatim in one bash block"
        )


def test_page_quotes_the_expectations():
    """Every line the workflow greps for is quoted on the page."""
    for directory in lesson_dirs():
        page = PAGES_DIR / f"{directory.name}.mdx"
        assert page.is_file(), f"{directory.name} has no lesson page"
        text = page.read_text()
        missing = [
            line
            for line in (directory / "expect.txt").read_text().splitlines()
            if line.strip() and line not in text
        ]
        assert not missing, (
            f"{page.name} does not quote the expectation lines: {missing}"
        )
