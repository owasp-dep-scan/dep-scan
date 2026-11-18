"""Tests of the version, help and config verbs' json output contract.

In json format each verb writes exactly one document to stdout, followed by
a newline, and nothing else: ``{"version", "tools"}`` for version,
``{"help"}`` for help, ``{"options": ...}`` and ``{"written": ...}`` for
config show and config init. ``config show`` prints option values verbatim,
as the scan receives them, and ``config init`` reports the written path in
the absolute, normalised, slash-separated form. The error paths write the
shared error document instead, with the unknown check names or the failed
path in ``details``, and carry the same message on stderr as text.
"""

import json
import os
import sys
from types import SimpleNamespace

import pytest

from depscan import cli
from depscan.commands.output import json_path
from depscan.lib import doctor as doctor_mod
from depscan.lib import pipeline


def run_main(monkeypatch, argv):
    """Run ``main`` with ``argv`` after the program name; the exit code."""
    monkeypatch.setattr(sys, "argv", ["depscan", *argv])
    with pytest.raises(SystemExit) as excinfo:
        cli.main()
    return excinfo.value.code


def read_one_document(capsys):
    """stdout as the single document the json contract asks for.

    Parsing the whole stream only works when the verb wrote exactly one
    document; a second one or any stray line breaks the parse.
    """
    captured = capsys.readouterr()
    return json.loads(captured.out), captured


def validate_against_published_schema(document, name):
    """Validate against the named schema when it is published.

    The output schemas land with the schemas piece; until then there is
    nothing to load and this check skips.
    """
    from analysis_lib.findings.schemas import load_schema, validate

    try:
        load_schema(name)
    except ValueError:
        pytest.skip(f"the {name} schema lands with the schemas piece")
    validate(name, document)


@pytest.fixture
def clean_option_env(monkeypatch):
    """Remove every environment variable that feeds an internal option default."""
    from depscan.commands.config import DEST_TO_ENV

    for env_var in set(DEST_TO_ENV.values()):
        monkeypatch.delenv(env_var, raising=False)


# --- version ---------------------------------------------------------------------


def test_version_json_is_one_document_with_version_and_tools(monkeypatch, capsys):
    calls = []

    def fake_doctor():
        calls.append(1)
        return SimpleNamespace(
            tools=[
                doctor_mod.ToolStatus(name="cdxgen", version="11.1.0"),
                doctor_mod.ToolStatus(name="rusi"),
            ]
        )

    monkeypatch.setattr(doctor_mod, "doctor", fake_doctor)
    assert run_main(monkeypatch, ["version", "--format", "json"]) == 0
    document, captured = read_one_document(capsys)
    assert set(document) == {"version", "tools"}
    assert document["version"]
    assert document["tools"] == {"cdxgen": "11.1.0", "rusi": None}
    # The one document the shared printer writes: indent=2 and one newline.
    assert captured.out == json.dumps(document, indent=2) + "\n"
    assert captured.err == ""
    # Positive control: the tool versions were collected for this run.
    assert calls == [1]
    validate_against_published_schema(document, "depscan-version-output")


# --- help ------------------------------------------------------------------------


def test_help_json_is_one_document_named_help(monkeypatch, capsys):
    assert run_main(monkeypatch, ["help", "--format", "json"]) == 0
    document, captured = read_one_document(capsys)
    assert set(document) == {"help"}
    assert "usage: depscan" in document["help"]
    assert captured.out == json.dumps(document, indent=2) + "\n"
    assert captured.err == ""
    validate_against_published_schema(document, "depscan-help-output")


def test_help_json_of_one_verb_describes_that_verb(monkeypatch, capsys):
    assert run_main(monkeypatch, ["help", "config", "--format", "json"]) == 0
    document, captured = read_one_document(capsys)
    assert set(document) == {"help"}
    assert "usage: depscan config" in document["help"]
    assert captured.out == json.dumps(document, indent=2) + "\n"
    assert captured.err == ""


# --- config show -----------------------------------------------------------------


def test_config_show_json_prints_values_verbatim(monkeypatch, capsys, clean_option_env):
    assert (
        run_main(
            monkeypatch,
            ["config", "show", "--reports-dir", "./sub/../reports", "--format", "json"],
        )
        == 0
    )
    document, captured = read_one_document(capsys)
    assert set(document) == {"options"}
    # The value mirrors what the scan receives; config show does not rewrite
    # the paths it is given.
    assert document["options"]["reports_dir"] == {
        "value": "./sub/../reports",
        "source": "command line",
    }
    assert captured.out == json.dumps(document, indent=2) + "\n"
    validate_against_published_schema(document, "depscan-config-show-output")


def test_config_show_unknown_check_writes_the_error_document(monkeypatch, capsys):
    code = run_main(
        monkeypatch, ["config", "show", "--checks", "bogus", "--format", "json"]
    )
    assert code == 2
    document, captured = read_one_document(capsys)
    assert document["error"]["exitCode"] == 2
    assert document["error"]["verb"] == "config"
    assert "unknown check bogus" in document["error"]["message"]
    assert document["error"]["details"] == {"unknownChecks": ["bogus"]}
    # The same message also goes to stderr as text.
    assert captured.err == document["error"]["message"] + "\n"
    validate_against_published_schema(document, "depscan-error")


def test_config_show_unknown_check_stays_text_without_json(monkeypatch, capsys):
    code = run_main(monkeypatch, ["config", "show", "--checks", "bogus"])
    assert code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "unknown check bogus" in captured.err


# --- config init -----------------------------------------------------------------


def test_config_init_json_reports_the_written_path_normalised(
    monkeypatch, capsys, tmp_path
):
    monkeypatch.chdir(tmp_path)
    assert run_main(monkeypatch, ["config", "init", "--format", "json"]) == 0
    document, captured = read_one_document(capsys)
    written = document["written"]
    # The absolute, normalised, slash-separated form the path rule asks for:
    # naming the file again changes nothing, so the value is already normal.
    assert os.path.isabs(written)
    assert written.endswith("/depscan.toml")
    assert "\\" not in written
    assert json_path(written) == written
    assert os.path.realpath(written) == os.path.realpath(tmp_path / "depscan.toml")
    assert captured.err == ""
    # Positive control: the file exists and carries the effective options.
    assert 'profile = "generic"' in (tmp_path / "depscan.toml").read_text()
    validate_against_published_schema(document, "depscan-config-init-output")


def test_config_init_text_names_the_file(monkeypatch, capsys, tmp_path):
    monkeypatch.chdir(tmp_path)
    assert run_main(monkeypatch, ["config", "init"]) == 0
    captured = capsys.readouterr()
    assert captured.out.startswith("Wrote the effective scan options to ")
    assert (tmp_path / "depscan.toml").is_file()


def test_config_init_refuses_an_existing_file_with_the_error_document(
    monkeypatch, capsys, tmp_path
):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "depscan.toml").write_text('severity = "high"\n')
    assert run_main(monkeypatch, ["config", "init", "--format", "json"]) == 1
    document, captured = read_one_document(capsys)
    assert document["error"]["exitCode"] == 1
    assert document["error"]["verb"] == "config"
    assert "already exists" in document["error"]["message"]
    assert "not overwriting" in document["error"]["message"]
    details_path = document["error"]["details"]["path"]
    assert os.path.isabs(details_path)
    assert os.path.realpath(details_path) == os.path.realpath(tmp_path / "depscan.toml")
    assert captured.err == document["error"]["message"] + "\n"


def test_config_init_refusal_stays_text_without_json(monkeypatch, capsys, tmp_path):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "depscan.toml").write_text('severity = "high"\n')
    assert run_main(monkeypatch, ["config", "init"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "already exists" in captured.err


def test_config_init_write_failure_writes_the_error_document(
    monkeypatch, capsys, tmp_path
):
    calls = []

    def refusing(options, path):
        calls.append(path)
        return False

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(pipeline, "write_config_file", refusing)
    assert run_main(monkeypatch, ["config", "init", "--format", "json"]) == 1
    document, captured = read_one_document(capsys)
    assert document["error"]["exitCode"] == 1
    assert document["error"]["verb"] == "config"
    assert "could not be written" in document["error"]["message"]
    details_path = document["error"]["details"]["path"]
    assert os.path.realpath(details_path) == os.path.realpath(tmp_path / "depscan.toml")
    assert captured.err == document["error"]["message"] + "\n"
    # Positive control: the write was attempted once, at the current
    # directory's depscan.toml.
    assert calls == [os.path.join(os.getcwd(), "depscan.toml")]


def test_config_init_write_failure_stays_text_without_json(monkeypatch, capsys, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(pipeline, "write_config_file", lambda options, path: False)
    assert run_main(monkeypatch, ["config", "init"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "could not be written" in captured.err
