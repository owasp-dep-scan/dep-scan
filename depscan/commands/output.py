"""The shared output contract core: exit codes, JSON documents and paths.

In json format a verb writes exactly one JSON document to stdout, followed
by a newline, and nothing else, whatever the exit code. When a verb in json
format exits 1, 2 or 4, the document on stdout is the error document built
by :func:`error_document`, and the same message also goes to stderr as
text. :func:`json_path` gives every path a json document carries outside
the manifest and findings their absolute, normalised, slash-separated form.

This module imports nothing from dep-scan: :mod:`depscan.lib.doctor` and
the verb modules import it, so it must be importable in any order and holds
only standard library code.
"""

import contextlib
import json
import os
import re
import sys
from typing import Any, Dict, Optional

#: Exit code: the verb ran.
EXIT_SUCCESS = 0

#: Exit code: a scan or command that could not run.
EXIT_FAILURE = 1

#: Exit code: a usage error.
EXIT_USAGE = 2

#: Exit code: a requested capability that cannot run here.
EXIT_REQUIREMENT_NOT_MET = 4

#: The exit codes and their meanings, as ``cli-usage.mdx`` and the agents
#: page embed them through :func:`exit_code_table_markdown`. Findings never
#: change the exit code in this version.
EXIT_CODES = (
    (EXIT_SUCCESS, "Success."),
    (
        EXIT_FAILURE,
        "A scan or command that could not run, for example an unusable "
        "vulnerability database or a source target that does not exist.",
    ),
    (EXIT_USAGE, "A usage error, including any dep-scan 6 command line."),
    (
        EXIT_REQUIREMENT_NOT_MET,
        "A requested capability that cannot run, for example a named check "
        "whose analyzer is missing, or an iOS or firmware target.",
    ),
)


def exit_code_table_markdown() -> str:
    """The exit codes as the markdown table the documentation embeds."""
    lines = ["| Code | Meaning |", "| --- | --- |"]
    for code, meaning in EXIT_CODES:
        lines.append(f"| {code} | {meaning} |")
    return "\n".join(lines) + "\n"


_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def plain_text(text: str) -> str:
    """``text`` without ANSI escape sequences.

    argparse colours its help on Python 3.14 and later when the stream is a
    terminal or FORCE_COLOR is set; a JSON document carries the plain text.
    """
    return _ANSI_ESCAPE.sub("", text)


def json_path(path) -> Optional[str]:
    """The absolute, normalised form of ``path`` with ``/`` separators.

    This is the form every path in a json document carries outside the
    manifest and the findings; inside those, paths keep the
    scan-directory-relative form their schemas define, with ``scanDir`` as
    the root. The drive letter is kept on Windows.
    """
    if path is None:
        return None
    absolute = os.path.abspath(os.fspath(path))
    if os.sep != "/":
        absolute = absolute.replace(os.sep, "/")
    if os.altsep and os.altsep != "/":
        absolute = absolute.replace(os.altsep, "/")
    return absolute


def error_document(
    exit_code: int, verb: str, message: str, details: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """The error document a json-format verb writes when it exits 1, 2 or 4.

    ``details`` is optional and verb specific, for example the unknown check
    names of a usage error or the capability that cannot run.
    """
    error: Dict[str, Any] = {"exitCode": exit_code, "verb": verb, "message": message}
    if details is not None:
        error["details"] = details
    return {"error": error}


def print_json_document(document: Dict[str, Any], stream=None) -> None:
    """Write one JSON document followed by a newline."""
    print(json.dumps(document, indent=2), file=stream)


def print_error_document(
    exit_code: int,
    verb: str,
    message: str,
    details: Optional[Dict[str, Any]] = None,
    stream=None,
) -> None:
    """Write the error document on stdout and the message on stderr as text."""
    print_json_document(error_document(exit_code, verb, message, details), stream)
    print(message, file=sys.stderr)


@contextlib.contextmanager
def stdout_on_stderr(active: bool = True):
    """Send everything written to stdout to stderr for the duration.

    Yields the real stdout, which the caller keeps for its one JSON
    document. The tables, the banner, the logs and any stray print from a
    library the verb calls land on stderr instead. dep-scan's stdout console
    pins no stream and follows ``sys.stdout`` at write time, so it moves
    with the redirect. With ``active`` false nothing moves, so a text-format
    run keeps its output where it was.
    """
    saved_stdout = sys.stdout
    if not active:
        yield saved_stdout
        return
    sys.stdout = sys.stderr
    try:
        yield saved_stdout
    finally:
        sys.stdout = saved_stdout


def argv_requests_json(argv) -> bool:
    """Whether ``argv`` asks for json anywhere: ``--format json`` as two
    tokens or ``--format=json`` as one.

    Usage errors that argparse finds before a verb runs write the error
    document only when this holds; a command line without ``--format``,
    as every dep-scan 6 invocation is, stays text only.
    """
    for index, token in enumerate(argv):
        if token == "--format":
            if index + 1 < len(argv) and argv[index + 1] == "json":
                return True
        elif token.startswith("--format=") and token[len("--format=") :] == "json":
            return True
    return False


def argv_verb(argv) -> str:
    """The verb token ``argv`` names: its first token that is neither an
    option nor the value of a ``--format`` option.

    The empty string while no verb appears, as on a command line that is
    all options.
    """
    value_expected = False
    for token in argv:
        if value_expected:
            value_expected = False
            continue
        if token == "--format":
            value_expected = True
            continue
        if not token.startswith("-"):
            return token
    return ""
