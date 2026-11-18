"""End-to-end tests of the ``depscan report`` verb through ``depscan.cli.main``.

The verb is driven the way a user drives it: ``sys.argv`` is set, ``main``
runs, the exit code and the output are asserted. The output contract holds:
``--format`` selects ``text`` or ``json``, and in json format stdout carries
exactly one JSON document and nothing else, whatever the exit code. A scan
directory that cannot be loaded is the error document; a loaded one keeps
its document, with ``scanDir`` normalised.
"""

import json
import os
import shutil
import sys
from pathlib import Path

import pytest

from analysis_lib.findings.schemas import validate as validate_schema
from depscan import api, cli
from depscan.commands.output import json_path

DATA_DIR = Path(__file__).parent / "data"
FIXTURE_DIR = DATA_DIR / "scan-directory"


def run_main(monkeypatch, argv):
    """Run ``main`` with ``argv`` after the program name; the exit code."""
    monkeypatch.setattr(sys, "argv", ["depscan", *argv])
    with pytest.raises(SystemExit) as excinfo:
        cli.main()
    return excinfo.value.code


# --- the json document and the error document ---------------------------------------


def test_a_missing_directory_prints_the_error_document(monkeypatch, capfd, tmp_path):
    """A scan directory that cannot be loaded is the error document on
    stdout, exit 1, with the same message on stderr as text."""
    missing = tmp_path / "no-such-scan"
    code = run_main(monkeypatch, ["report", str(missing), "--format", "json"])
    assert code == 1
    captured = capfd.readouterr()
    document = json.loads(captured.out)
    assert document["error"]["exitCode"] == 1
    assert document["error"]["verb"] == "report"
    assert "does not exist" in document["error"]["message"]
    assert "does not exist" in captured.err


def test_a_loaded_scan_directory_prints_its_document_with_a_normalised_scan_dir(
    monkeypatch, capfd, tmp_path
):
    """``scanDir`` is absolute, normalised and slash-separated, whatever form
    the path was given in; the manifest and the findings keep the
    scan-directory-relative paths their schemas define."""
    scan_dir = tmp_path / "scan-directory"
    shutil.copytree(FIXTURE_DIR, scan_dir)
    monkeypatch.chdir(tmp_path)
    code = run_main(monkeypatch, ["report", "scan-directory", "--format", "json"])
    assert code == 0
    captured = capfd.readouterr()
    document = json.loads(captured.out)
    assert set(document) == {"scanDir", "manifest", "findings"}
    assert document["scanDir"] == json_path("scan-directory")
    assert os.path.isabs(document["scanDir"])
    assert document["scanDir"] == f"{json_path(os.getcwd())}/scan-directory"
    assert document["manifest"]["layoutVersion"] == "1.0"
    assert len(document["findings"]) == 1
    validate_schema("finding", document["findings"][0])
    assert captured.err == ""


def test_an_absolute_scan_dir_stays_the_normalised_absolute_form(monkeypatch, capfd):
    code = run_main(monkeypatch, ["report", str(FIXTURE_DIR), "--format", "json"])
    assert code == 0
    document = json.loads(capfd.readouterr().out)
    assert document["scanDir"] == json_path(FIXTURE_DIR)


def test_a_missing_directory_in_text_mode_stays_text(monkeypatch, capfd, tmp_path):
    code = run_main(monkeypatch, ["report", str(tmp_path / "no-such-scan")])
    assert code == 1
    captured = capfd.readouterr()
    assert captured.out == ""
    assert "depscan report:" in captured.err
    assert "does not exist" in captured.err


def test_text_mode_still_renders_the_tables(monkeypatch, capfd):
    code = run_main(monkeypatch, ["report", str(FIXTURE_DIR)])
    assert code == 0
    out = capfd.readouterr().out
    assert "Vulnerabilities count: 1" in out
    assert "high: 1" in out


def test_an_unexpected_error_prints_the_error_document(monkeypatch, capfd, tmp_path):
    """An error nothing above translates stops the verb with the error
    document on stdout in json format, exit 1, the message on stderr."""
    calls = []

    def raising_load_scan(reports_dir):
        calls.append(reports_dir)
        raise RuntimeError("boom")

    monkeypatch.setattr(api, "load_scan", raising_load_scan)
    scan_dir = tmp_path / "any-dir"
    code = run_main(monkeypatch, ["report", str(scan_dir), "--format", "json"])
    assert code == 1
    captured = capfd.readouterr()
    document = json.loads(captured.out)
    assert document["error"]["exitCode"] == 1
    assert document["error"]["verb"] == "report"
    assert "boom" in document["error"]["message"]
    assert "boom" in captured.err
    # Positive control: the stub really replaced the loader.
    assert calls == [str(scan_dir)]
