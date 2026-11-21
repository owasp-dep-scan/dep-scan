"""End-to-end tests of the ``depscan validate`` and ``depscan report`` verbs.

Both verbs are driven the way a user drives them: ``sys.argv`` is set,
``main`` runs, the exit code and the output are asserted. The output
contract holds for both: ``--format`` selects ``text`` or ``json``, and in
json format stdout carries exactly one JSON document and nothing else,
whatever the exit code. An invalid input document is a ``validate`` result,
not an error, while a scan directory that cannot be loaded is the report's
error document. Anything expensive or external is stubbed with recorded
calls, and each stub has a positive control proving it ran.
"""

import json
import os
import shutil
import sys
from pathlib import Path

import pytest

from analysis_lib.findings.schemas import validate as validate_schema
from analysis_lib.vex.csaf import build_csaf
from depscan import api, cli
from depscan.commands.output import json_path
from depscan.lib import scan_directory
from depscan.validate_cli import _build_parser

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(__file__).parent / "data"
FIXTURE_DIR = DATA_DIR / "scan-directory"
# The demo BOM the analysis-lib CSAF builder tests use; build_csaf turns it
# into a CSAF document that passes the bundled schema and semantic tests.
CSAF_DEMO_BOM = REPO_ROOT / "packages" / "analysis-lib" / "tests" / "data" / "vex" / "demo_bom.json"


def run_main(monkeypatch, argv):
    """Run ``main`` with ``argv`` after the program name; the exit code."""
    monkeypatch.setattr(sys, "argv", ["depscan", *argv])
    with pytest.raises(SystemExit) as excinfo:
        cli.main()
    return excinfo.value.code


def _write_cyclonedx(path):
    """Write a minimal valid CycloneDX document and return its path."""
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {"timestamp": "2026-07-24T00:00:00Z"},
        "components": [
            {
                "type": "library",
                "name": "express",
                "version": "4.22.2",
                "purl": "pkg:npm/express@4.22.2",
            }
        ],
    }
    Path(path).write_text(json.dumps(document))
    return str(path)


def _write_valid_csaf(path):
    """Write a CSAF VEX document the bundled schema accepts, and return it."""
    bom = json.loads(CSAF_DEMO_BOM.read_text(encoding="utf-8"))
    document = build_csaf(bom, bom["vulnerabilities"], csaf_version="2.1")
    Path(path).write_text(json.dumps(document))
    return str(path)


def _write_broken_cyclonedx(path):
    """Write a CycloneDX document the schema rejects, and return its path."""
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "9.9",
        "version": 1,
    }
    Path(path).write_text(json.dumps(document))
    return str(path)


# --- validate: the results document ------------------------------------------------


def test_a_valid_document_prints_one_results_document(monkeypatch, capfd, tmp_path):
    path = _write_cyclonedx(tmp_path / "given.cdx.json")
    code = run_main(monkeypatch, ["validate", path, "--format", "json"])
    assert code == 0
    captured = capfd.readouterr()
    document = json.loads(captured.out)
    assert set(document) == {"results"}
    assert len(document["results"]) == 1
    entry = document["results"][0]
    assert set(entry) == {"file", "format", "valid", "errors"}
    assert entry["format"] == "cyclonedx"
    assert entry["valid"] is True
    assert entry["errors"] == []
    assert captured.err == ""


def test_the_results_file_is_absolute_and_slash_separated(monkeypatch, capfd, tmp_path):
    _write_cyclonedx(tmp_path / "given.cdx.json")
    monkeypatch.chdir(tmp_path)
    code = run_main(monkeypatch, ["validate", "given.cdx.json", "--format", "json"])
    assert code == 0
    entry = json.loads(capfd.readouterr().out)["results"][0]
    assert entry["file"] == json_path("given.cdx.json")
    assert os.path.isabs(entry["file"])
    assert "\\" not in entry["file"]
    assert entry["file"] == f"{json_path(os.getcwd())}/given.cdx.json"


def test_an_invalid_document_is_a_result_not_an_error(monkeypatch, capfd, tmp_path):
    """A document that fails its schema is a result entry and exit 1: the
    error document is reserved for a failure that stops the verb."""
    path = _write_broken_cyclonedx(tmp_path / "broken.cdx.json")
    code = run_main(monkeypatch, ["validate", path, "--format", "json"])
    assert code == 1
    captured = capfd.readouterr()
    document = json.loads(captured.out)
    assert set(document) == {"results"}, "an invalid document is not a verb error"
    entry = document["results"][0]
    assert entry["valid"] is False
    assert entry["format"] == "cyclonedx"
    assert any("specVersion" in error for error in entry["errors"])


def test_an_unreadable_file_is_a_result(monkeypatch, capfd, tmp_path):
    """A missing file and a directory both land in the results with their
    reason, keeping the fields of every other entry."""
    missing = str(tmp_path / "no-such.json")
    directory = str(tmp_path)
    code = run_main(monkeypatch, ["validate", missing, directory, "--format", "json"])
    assert code == 1
    entries = json.loads(capfd.readouterr().out)["results"]
    assert len(entries) == 2
    assert entries[0]["file"] == json_path(missing)
    assert entries[0]["valid"] is False
    assert entries[0]["format"] is None
    assert "could not read JSON" in entries[0]["errors"][0]
    assert entries[1]["file"] == json_path(directory)
    assert "is a directory" in entries[1]["errors"][0]


def test_auto_detection_keeps_picking_the_format_per_file(monkeypatch, capfd, tmp_path):
    cyclonedx = _write_cyclonedx(tmp_path / "given.cdx.json")
    csaf = _write_valid_csaf(tmp_path / "csaf.json")
    code = run_main(monkeypatch, ["validate", cyclonedx, csaf, "--format", "json"])
    assert code == 0
    entries = json.loads(capfd.readouterr().out)["results"]
    assert [entry["format"] for entry in entries] == ["cyclonedx", "csaf"]
    assert all(entry["valid"] for entry in entries)


def test_an_undetectable_document_advises_input_format(monkeypatch, capfd, tmp_path):
    """The hint for a document no format matches names the option that forces
    one, ``--input-format``; ``--format`` selects the output and its old
    document values are gone, so advising them would point at a usage error.
    The positive control follows the hint and is accepted."""
    path = tmp_path / "unknown.json"
    Path(path).write_text(json.dumps({"nothing": "useful"}))
    code = run_main(monkeypatch, ["validate", str(path)])
    assert code == 1
    out = capfd.readouterr().out
    assert "could not detect" in out
    assert "--input-format" in out
    assert "--format" not in out
    # Positive control: the advised spelling is a real option, not a usage
    # error, and forces the path it names.
    code = run_main(
        monkeypatch, ["validate", str(path), "--input-format", "cyclonedx", "--format", "json"]
    )
    assert code == 1
    entry = json.loads(capfd.readouterr().out)["results"][0]
    assert entry["format"] == "cyclonedx"
    code = run_main(
        monkeypatch, ["validate", str(path), "--input-format", "csaf", "--format", "json"]
    )
    assert code == 1
    # Forcing skips detection, so the entry names the forced format and its
    # own schema errors instead of the hint.
    entry = json.loads(capfd.readouterr().out)["results"][0]
    assert entry["format"] == "csaf"


# --- validate: --input-format ------------------------------------------------------


def test_input_format_csaf_forces_the_csaf_path(monkeypatch, capfd, tmp_path):
    """``--input-format csaf`` runs every file through the CSAF path, also a
    document that auto-detection would have called CycloneDX."""
    csaf = _write_valid_csaf(tmp_path / "csaf.json")
    cyclonedx = _write_cyclonedx(tmp_path / "given.cdx.json")
    code = run_main(
        monkeypatch,
        ["validate", csaf, "--input-format", "csaf", "--format", "json"],
    )
    assert code == 0
    entry = json.loads(capfd.readouterr().out)["results"][0]
    assert entry["format"] == "csaf"
    assert entry["valid"] is True
    code = run_main(
        monkeypatch,
        ["validate", cyclonedx, "--input-format", "csaf", "--format", "json"],
    )
    assert code == 1
    entry = json.loads(capfd.readouterr().out)["results"][0]
    assert entry["format"] == "csaf"
    assert entry["valid"] is False


def test_input_format_cyclonedx_forces_the_cyclonedx_path(monkeypatch, capfd, tmp_path):
    csaf = _write_valid_csaf(tmp_path / "csaf.json")
    cyclonedx = _write_cyclonedx(tmp_path / "given.cdx.json")
    code = run_main(
        monkeypatch,
        ["validate", cyclonedx, "--input-format", "cyclonedx", "--format", "json"],
    )
    assert code == 0
    entry = json.loads(capfd.readouterr().out)["results"][0]
    assert entry["format"] == "cyclonedx"
    code = run_main(
        monkeypatch,
        ["validate", csaf, "--input-format", "cyclonedx", "--format", "json"],
    )
    assert code == 1
    entry = json.loads(capfd.readouterr().out)["results"][0]
    assert entry["format"] == "cyclonedx"
    assert entry["valid"] is False


@pytest.mark.parametrize("value", ["auto", "csaf", "cyclonedx"])
def test_the_old_document_format_values_of_format_are_usage_errors_now(
    monkeypatch, capfd, tmp_path, value
):
    """``--format`` selects the output now: the document formats it used to
    name are no longer its choices."""
    path = _write_cyclonedx(tmp_path / "given.cdx.json")
    code = run_main(monkeypatch, ["validate", path, "--format", value])
    assert code == 2
    captured = capfd.readouterr()
    assert captured.out == ""
    assert f"invalid choice: '{value}'" in captured.err


# --- validate: text mode and unexpected errors --------------------------------------


def test_text_mode_prints_the_text_lines_and_no_json(monkeypatch, capfd, tmp_path):
    valid = _write_cyclonedx(tmp_path / "given.cdx.json")
    broken = _write_broken_cyclonedx(tmp_path / "broken.cdx.json")
    code = run_main(monkeypatch, ["validate", valid, broken])
    assert code == 1
    captured = capfd.readouterr()
    assert "[VALID]   " in captured.out
    assert "[INVALID]" in captured.out
    assert "specVersion" in captured.out
    with pytest.raises(json.JSONDecodeError):
        json.loads(captured.out)


def test_an_unexpected_error_prints_the_error_document(monkeypatch, capfd, tmp_path):
    """An error nothing above translates is the error document on stdout in
    json format, with its message on stderr; the verb still exits 1."""
    path = _write_cyclonedx(tmp_path / "given.cdx.json")
    calls = []

    def raising_validate_document(doc, doc_format, csaf_version):
        calls.append(path)
        raise RuntimeError("boom")

    monkeypatch.setattr(
        "depscan.validate_cli.validate_document", raising_validate_document
    )
    code = run_main(monkeypatch, ["validate", path, "--format", "json"])
    assert code == 1
    captured = capfd.readouterr()
    document = json.loads(captured.out)
    assert document["error"]["exitCode"] == 1
    assert document["error"]["verb"] == "validate"
    assert "boom" in document["error"]["message"]
    assert "boom" in captured.err
    # Positive control: the stub really replaced the validation.
    assert calls == [path]


def test_an_unexpected_error_in_text_mode_keeps_stdout_empty(
    monkeypatch, capfd, caplog, tmp_path
):
    """The message and its traceback go to the logs, which the command line
    writes on stderr; pytest owns the logging handlers, so the record is
    asserted through caplog instead of the stream."""
    path = _write_cyclonedx(tmp_path / "given.cdx.json")
    monkeypatch.setattr(
        "depscan.validate_cli.validate_document",
        lambda doc, doc_format, csaf_version: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    with caplog.at_level("ERROR", logger="depscan.validate_cli"):
        code = run_main(monkeypatch, ["validate", path])
    assert code == 1
    captured = capfd.readouterr()
    assert captured.out == ""
    assert any("boom" in record.getMessage() for record in caplog.records)


def test_the_verb_parser_registers_the_new_options():
    """The parser the verb registry shares offers the two option names."""
    parser = _build_parser()
    defaults = vars(parser.parse_args(["x.json"]))
    assert defaults["format"] == "text"
    assert defaults["input_format"] == "auto"


# --- report: the json document and the error document -------------------------------


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
    assert document["manifest"]["layoutVersion"] == scan_directory.LAYOUT_VERSION
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


def test_an_unexpected_load_error_prints_the_error_document(monkeypatch, capfd, tmp_path):
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
