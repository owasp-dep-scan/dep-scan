"""Tests of the shared output contract core and its parser wiring.

:mod:`depscan.commands.output` owns the exit-code table, the error document
builder, the one-document JSON printer and the ``json_path`` normaliser;
this module checks each of them directly, then drives the usage-error
behaviour through ``depscan.cli.main`` the way a user does: the error
document on stdout when the command line asked for json anywhere, argparse's
usage and message on stderr, exit 2, and text only without ``--format``.
"""

import argparse
import json
import os
import sys
from pathlib import Path

import pytest

from depscan import cli
from depscan.commands import ErrorDocumentParser, build_parser
from depscan.commands.output import (
    EXIT_CODES,
    argv_requests_json,
    argv_verb,
    error_document,
    exit_code_table_markdown,
    json_path,
    print_error_document,
    print_json_document,
)


def run_main(monkeypatch, argv):
    """Run ``main`` with ``argv`` after the program name; the exit code."""
    monkeypatch.setattr(sys, "argv", ["depscan", *argv])
    with pytest.raises(SystemExit) as excinfo:
        cli.main()
    return excinfo.value.code


# --- the exit codes ----------------------------------------------------------------


def test_the_exit_code_table_lists_the_four_codes_with_their_meanings():
    """0, 1, 2 and 4, with the meanings the exit-code section documents."""
    assert [code for code, _ in EXIT_CODES] == [0, 1, 2, 4]
    assert exit_code_table_markdown() == (
        "| Code | Meaning |\n"
        "| --- | --- |\n"
        "| 0 | Success. |\n"
        "| 1 | A scan or command that could not run, for example an unusable "
        "vulnerability database or a source target that does not exist. |\n"
        "| 2 | A usage error, including any dep-scan 6 command line. |\n"
        "| 4 | A requested capability that cannot run, for example a named "
        "check whose analyzer is missing, or an iOS or firmware target. |\n"
    )


def test_the_documented_exit_code_table_is_the_generated_one():
    """The cli-usage page embeds exit_code_table_markdown() between markers."""
    page = Path(__file__).parent.parent / "documentation" / "docs" / "cli-usage.mdx"
    text = page.read_text(encoding="utf-8")
    start = text.find("<!-- exit code table start -->\n")
    end = text.find("<!-- exit code table end -->")
    assert start != -1 and end != -1, "the exit code table markers are missing"
    region = text[start + len("<!-- exit code table start -->\n") : end]
    assert region == exit_code_table_markdown()


# --- json_path ---------------------------------------------------------------------


def test_json_path_makes_a_relative_path_absolute_under_the_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = json_path("sub/reports")
    assert result is not None
    assert os.path.isabs(result)
    assert result.endswith("/sub/reports")
    assert "/../" not in result and not result.endswith("/.")
    # The same form config init prints for a path beside the cwd.
    assert result == os.path.join(os.getcwd(), "sub", "reports").replace(os.sep, "/")


def test_json_path_normalises_dot_segments_and_keeps_the_cwd_form(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert json_path(".") == os.getcwd().replace(os.sep, "/")
    assert json_path("a/../b") == os.getcwd().replace(os.sep, "/") + "/b"


def test_json_path_keeps_an_absolute_path_unchanged(tmp_path):
    result = json_path(tmp_path / "reports")
    assert result is not None
    assert os.path.isabs(result)
    assert result == str(tmp_path / "reports").replace(os.sep, "/")


@pytest.mark.skipif(sys.platform != "win32", reason="drive letters exist on Windows")
def test_json_path_keeps_the_drive_letter_on_windows(tmp_path):
    drive = os.path.splitdrive(str(tmp_path))[0]
    result = json_path(tmp_path / "reports")
    assert result is not None
    assert result.startswith(drive + "/")


@pytest.mark.skipif(sys.platform == "win32", reason="a backslash is a plain character on posix")
def test_json_path_keeps_a_backslash_in_a_posix_name():
    assert json_path("odd\\name") == os.path.abspath("odd\\name")


def test_json_path_passes_none_through():
    assert json_path(None) is None


# --- the error document --------------------------------------------------------------


def test_error_document_carries_the_contract_shape():
    document = error_document(2, "scan", "it broke", {"unknownChecks": ["bogus"]})
    assert document == {
        "error": {
            "exitCode": 2,
            "verb": "scan",
            "message": "it broke",
            "details": {"unknownChecks": ["bogus"]},
        }
    }


def test_error_document_details_are_optional():
    assert error_document(4, "vdb", "it broke") == {
        "error": {"exitCode": 4, "verb": "vdb", "message": "it broke"}
    }


def test_print_json_document_writes_one_document_and_one_newline(capsys):
    print_json_document({"ok": True})
    captured = capsys.readouterr()
    assert captured.out == '{\n  "ok": true\n}\n'
    json.loads(captured.out)  # the whole stream parses as one document


def test_print_error_document_writes_the_document_and_the_message(capsys):
    print_error_document(2, "scan", "it broke", {"unknownChecks": ["bogus"]})
    captured = capsys.readouterr()
    document = json.loads(captured.out)
    assert document["error"]["message"] == "it broke"
    assert captured.err == "it broke\n"


# --- the argv token scan ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (["scan", "--format", "json"], True),
        (["scan", "--format=json"], True),
        (["--format=json", "scan"], True),
        (["scan", "--checks", "--format", "json"], True),
        (["scan", "--format", "json", "--format", "text"], True),
        (["scan", "--format", "text"], False),
        (["scan", "--format=text"], False),
        (["scan", "--format"], False),
        (["scan", "--format=jsonx"], False),
        (["scan", "--checks", "json"], False),
        (["scan"], False),
        ([], False),
    ],
)
def test_argv_requests_json_is_the_token_rule(argv, expected):
    assert argv_requests_json(argv) == expected


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (["scan", "--format", "json"], "scan"),
        (["frobnicate", "--format", "json"], "frobnicate"),
        (["--format", "json"], ""),
        (["--format", "json", "scan"], "scan"),
        ([], ""),
    ],
)
def test_argv_verb_is_the_first_token_that_names_a_verb(argv, expected):
    assert argv_verb(argv) == expected


# --- the parser wiring ----------------------------------------------------------------


def test_the_top_level_parser_and_every_subparser_carry_the_error_document_parser():
    parser = build_parser()
    assert isinstance(parser, ErrorDocumentParser)
    subparser_actions = [
        action for action in parser._actions if isinstance(action, argparse._SubParsersAction)
    ]
    assert len(subparser_actions) == 1
    for sub in subparser_actions[0].choices.values():
        assert isinstance(sub, ErrorDocumentParser)


@pytest.mark.parametrize("format_argv", [["--format", "json"], ["--format=json"]])
def test_a_usage_error_with_json_anywhere_writes_the_document(monkeypatch, capsys, format_argv):
    code = run_main(monkeypatch, ["scan", "--profile", "bogus", *format_argv])
    assert code == 2
    captured = capsys.readouterr()
    document = json.loads(captured.out)
    assert document["error"]["exitCode"] == 2
    assert document["error"]["verb"] == "scan"
    assert "invalid choice: 'bogus'" in document["error"]["message"]
    # argparse's own usage and message stay on stderr.
    assert "usage: depscan scan" in captured.err
    assert "error: argument --profile: invalid choice: 'bogus'" in captured.err


def test_a_usage_error_without_json_is_text_only(monkeypatch, capsys):
    code = run_main(monkeypatch, ["scan", "--profile", "bogus"])
    assert code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "usage: depscan scan" in captured.err
    assert "invalid choice: 'bogus'" in captured.err


def test_a_usage_error_with_text_format_is_text_only(monkeypatch, capsys):
    code = run_main(monkeypatch, ["scan", "--profile", "bogus", "--format", "text"])
    assert code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "usage: depscan scan" in captured.err


def test_an_unknown_verb_with_json_names_it_in_the_document(monkeypatch, capsys):
    code = run_main(monkeypatch, ["frobnicate", "--format", "json"])
    assert code == 2
    captured = capsys.readouterr()
    document = json.loads(captured.out)
    assert document["error"]["verb"] == "frobnicate"
    assert "invalid choice: 'frobnicate'" in document["error"]["message"]
    assert "usage: depscan" in captured.err


def test_a_missing_verb_stays_text_only(monkeypatch, capsys):
    code = run_main(monkeypatch, [])
    assert code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "usage: depscan" in captured.err


def test_a_v6_invocation_stays_text_only(monkeypatch, capsys):
    code = run_main(monkeypatch, ["--bom-dir", "x", "-o", "y"])
    assert code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "this is a dep-scan 6 command line" in captured.err
