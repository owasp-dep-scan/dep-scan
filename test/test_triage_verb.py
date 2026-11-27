"""End-to-end tests of the ``depscan triage`` verb through the CLI.

The verb is driven the way a user drives it: ``sys.argv`` is set, ``main``
runs, and the exit code, the file on disk and the json document are
asserted. The comment-and-order preservation is checked on a file with
comments between and inside the entries, and the listing runs against the
committed scan directory fixture, whose one finding is CVE-2024-1111.
"""

import json
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from analysis_lib.findings.schemas import load_schema
from depscan import api, cli
from depscan.lib import decisions_edit

SCAN_DIR = str(Path(__file__).parent / "data" / "scan-directory")


def run_main(monkeypatch, argv):
    """Run ``main`` with ``argv`` after the program name; the exit code."""
    monkeypatch.setattr(sys, "argv", ["depscan", *argv])
    with pytest.raises(SystemExit) as excinfo:
        cli.main()
    return excinfo.value.code


COMMENTED_FILE = """\
# Our decisions, reviewed in pull requests.

[[triage]]
# lodash before the 4.17.21 upgrade lands
finding = "dsf1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
state = "in_triage"
author = "alice"

[[expect]]
id = "no-high"
severity = "high"
action = "fail"
"""

PROPOSAL_FILE = """\
[[triage]]
advisory = "CVE-2024-1111"
purl = "pkg:pypi/requests"
state = "not_affected"
justification = "code_not_reachable"
proposed_by = "triage-agent session 8123"
"""


def _write(path, text):
    path.write_text(text, encoding="utf-8")
    return str(path)


def _tables(file):
    """The triage tables of the file as the editor reads them."""
    return decisions_edit.load(str(file)).tables


def _handle(file, position=0):
    """The handle depscan triage list prints for the entry at ``position``."""
    return api.triage_entries(file=str(file))["entries"][position]["handle"]


def _set_argv(file, *extra):
    return [
        "triage",
        "set",
        "--advisory",
        "CVE-2024-1111",
        "--purl",
        "pkg:pypi/requests",
        "--state",
        "in_triage",
        "--author",
        "bob",
        "--decisions",
        file,
        *extra,
    ]


# --- set ------------------------------------------------------------------------------


def test_set_appends_and_keeps_comments_and_order(tmp_path, monkeypatch):
    file = _write(tmp_path / "decisions.toml", COMMENTED_FILE)
    assert run_main(monkeypatch, _set_argv(file)) == 0
    text = Path(file).read_text(encoding="utf-8")
    # The comment above the first entry, and the entry's order, survive.
    assert "# lodash before the 4.17.21 upgrade lands" in text
    assert text.index("dsf1:aaa") < text.index("CVE-2024-1111")
    assert text.endswith('action = "fail"\n') or 'action = "fail"' in text
    entries = _tables(file)
    assert len(entries) == 2
    assert str(entries[1]["advisory"]) == "CVE-2024-1111"


def test_set_updates_the_same_selector_in_place(tmp_path, monkeypatch):
    file = _write(tmp_path / "decisions.toml", COMMENTED_FILE)
    assert run_main(monkeypatch, _set_argv(file)) == 0
    assert run_main(monkeypatch, _set_argv(file, "--detail", "second look")) == 0
    text = Path(file).read_text(encoding="utf-8")
    entries = _tables(file)
    assert len(entries) == 2, "the same selector updates, not appends"
    assert str(entries[1]["detail"]) == "second look"
    assert "# lodash before the 4.17.21 upgrade lands" in text


def test_set_creates_the_file_when_missing(tmp_path, monkeypatch):
    file = tmp_path / "new" / "decisions.toml"
    assert run_main(monkeypatch, _set_argv(str(file))) == 0
    assert len(_tables(file)) == 1


def test_set_requires_the_author(tmp_path, monkeypatch):
    file = _write(tmp_path / "decisions.toml", COMMENTED_FILE)
    argv = [
        "triage",
        "set",
        "--advisory",
        "CVE-2024-1111",
        "--purl",
        "pkg:pypi/requests",
        "--state",
        "in_triage",
        "--decisions",
        file,
    ]
    assert run_main(monkeypatch, argv) == 2


def test_set_requires_a_justification_for_not_affected(tmp_path, monkeypatch):
    file = _write(tmp_path / "decisions.toml", COMMENTED_FILE)
    argv = [
        "triage",
        "set",
        "--advisory",
        "CVE-2024-1111",
        "--purl",
        "pkg:pypi/requests",
        "--state",
        "not_affected",
        "--author",
        "bob",
        "--decisions",
        file,
    ]
    assert run_main(monkeypatch, argv) == 2


def test_set_needs_a_selector(tmp_path, monkeypatch):
    file = _write(tmp_path / "decisions.toml", COMMENTED_FILE)
    argv = ["triage", "set", "--state", "in_triage", "--author", "bob", "--decisions", file]
    assert run_main(monkeypatch, argv) == 2


def test_set_json_validates_against_the_output_schema(tmp_path, monkeypatch, capsys):
    file = _write(tmp_path / "decisions.toml", COMMENTED_FILE)
    argv = _set_argv(file) + ["--format", "json"]
    assert run_main(monkeypatch, argv) == 0
    document = json.loads(capsys.readouterr().out)
    validator = Draft202012Validator(load_schema("depscan-triage-output"))
    validator.validate(document)
    assert document["subcommand"] == "set"
    assert document["result"] == "added"


# --- list -----------------------------------------------------------------------------


def test_list_matches_the_scan_directory(tmp_path, monkeypatch):
    file = _write(tmp_path / "decisions.toml", COMMENTED_FILE)
    assert run_main(monkeypatch, ["triage", "list", SCAN_DIR, "--decisions", file]) == 0


def test_list_flags_a_stale_entry_in_json(tmp_path, monkeypatch, capsys):
    file = _write(
        tmp_path / "decisions.toml",
        "\n".join(
            [
                "[[triage]]",
                'advisory = "CVE-9999-0001"',
                'purl = "pkg:npm/gone"',
                'state = "in_triage"',
                'author = "alice"',
            ]
        ),
    )
    assert (
        run_main(
            monkeypatch, ["triage", "list", SCAN_DIR, "--decisions", file, "--format", "json"]
        )
        == 0
    )
    document = json.loads(capsys.readouterr().out)
    validator = Draft202012Validator(load_schema("depscan-triage-output"))
    validator.validate(document)
    assert document["entries"][0]["status"] == "stale"
    assert document["stale"] == [1]


def test_list_names_what_the_advisory_matches(tmp_path, monkeypatch, capsys):
    file = _write(
        tmp_path / "decisions.toml",
        "\n".join(
            [
                "[[triage]]",
                'advisory = "CVE-2024-1111"',
                'purl = "pkg:pypi/requests"',
                'state = "in_triage"',
                'author = "alice"',
            ]
        ),
    )
    assert (
        run_main(
            monkeypatch, ["triage", "list", SCAN_DIR, "--decisions", file, "--format", "json"]
        )
        == 0
    )
    document = json.loads(capsys.readouterr().out)
    assert document["entries"][0]["status"] == "live"
    assert len(document["entries"][0]["matches"]) == 1
    assert document["entries"][0]["matches"][0].startswith("dsf1:")


# --- review ---------------------------------------------------------------------------


def test_review_approves_a_proposal(tmp_path, monkeypatch):
    file = _write(tmp_path / "decisions.toml", PROPOSAL_FILE)
    handle = _handle(file)
    assert (
        run_main(
            monkeypatch,
            ["triage", "review", "--approve", handle, "--approver", "alice", "--decisions", file],
        )
        == 0
    )
    text = Path(file).read_text(encoding="utf-8")
    assert 'approver = "alice"' in text
    # The approver becomes the author of a proposal that named none.
    assert 'author = "alice"' in text
    assert 'proposed_by = "triage-agent session 8123"' in text


def test_review_rejects_a_proposal_and_records_nothing(tmp_path, monkeypatch):
    file = _write(
        tmp_path / "decisions.toml",
        PROPOSAL_FILE + '\n[[expect]]\nid = "keep"\nseverity = "high"\naction = "warn"\n',
    )
    handle = _handle(file)
    assert (
        run_main(
            monkeypatch,
            ["triage", "review", "--reject", handle, "--approver", "alice", "--decisions", file],
        )
        == 0
    )
    text = Path(file).read_text(encoding="utf-8")
    assert "CVE-2024-1111" not in text
    assert 'id = "keep"' in text


def test_review_refuses_an_entry_that_is_not_a_proposal(tmp_path, monkeypatch):
    file = _write(
        tmp_path / "decisions.toml",
        "\n".join(
            [
                "[[triage]]",
                'advisory = "CVE-2024-1111"',
                'purl = "pkg:pypi/requests"',
                'state = "in_triage"',
                'author = "alice"',
            ]
        ),
    )
    assert (
        run_main(
            monkeypatch,
            [
                "triage",
                "review",
                "--approve",
                _handle(file),
                "--approver",
                "carol",
                "--decisions",
                file,
            ],
        )
        == 2
    )


def test_review_requires_the_approver(tmp_path, monkeypatch):
    file = _write(tmp_path / "decisions.toml", PROPOSAL_FILE)
    assert (
        run_main(
            monkeypatch, ["triage", "review", "--approve", _handle(file), "--decisions", file]
        )
        == 2
    )


def test_review_refuses_an_unknown_entry(tmp_path, monkeypatch):
    file = _write(tmp_path / "decisions.toml", PROPOSAL_FILE)
    assert (
        run_main(
            monkeypatch,
            [
                "triage",
                "review",
                "--approve",
                "tr-0000000000",
                "--approver",
                "alice",
                "--decisions",
                file,
            ],
        )
        == 2
    )


# --- remove ---------------------------------------------------------------------------


def test_remove_takes_the_entry_out(tmp_path, monkeypatch):
    file = _write(tmp_path / "decisions.toml", COMMENTED_FILE)
    assert run_main(monkeypatch, ["triage", "remove", _handle(file), "--decisions", file]) == 0
    text = Path(file).read_text(encoding="utf-8")
    assert "dsf1:aaa" not in text
    assert 'id = "no-high"' in text


# --- check ----------------------------------------------------------------------------


def test_check_passes_a_valid_file(tmp_path, monkeypatch):
    file = _write(tmp_path / "decisions.toml", COMMENTED_FILE)
    assert run_main(monkeypatch, ["triage", "check", "--decisions", file]) == 0


def test_check_exits_3_on_a_broken_file_and_names_the_line(tmp_path, monkeypatch, capsys):
    file = _write(
        tmp_path / "decisions.toml",
        '[[triage]]\nfinding = "dsf1:' + "a" * 64 + '"\nstate = 3\nauthor = "alice"\n',
    )
    assert run_main(monkeypatch, ["triage", "check", "--decisions", file]) == 3
    captured = capsys.readouterr()
    # The message names the key and the line, the way a scan refuses it.
    assert "line 3" in captured.err + captured.out


def test_check_json_carries_the_errors(tmp_path, monkeypatch, capsys):
    file = _write(
        tmp_path / "decisions.toml",
        '[[triage]]\nfinding = "dsf1:' + "a" * 64 + '"\nstate = 3\nauthor = "alice"\n',
    )
    assert run_main(monkeypatch, ["triage", "check", "--decisions", file, "--format", "json"]) == 3
    document = json.loads(capsys.readouterr().out)
    validator = Draft202012Validator(load_schema("depscan-triage-output"))
    validator.validate(document)
    assert document["valid"] is False
    assert any("triage/0/state" in error for error in document["errors"])


def test_check_reports_stale_and_expired_against_a_scan(tmp_path, monkeypatch, capsys):
    file = _write(
        tmp_path / "decisions.toml",
        "\n".join(
            [
                "[[triage]]",
                'advisory = "CVE-2024-1111"',
                'purl = "pkg:pypi/requests"',
                'state = "in_triage"',
                'author = "alice"',
                "",
                "[[triage]]",
                'advisory = "CVE-9999-0001"',
                'purl = "pkg:npm/gone"',
                'state = "in_triage"',
                'author = "alice"',
                "",
                "[[triage]]",
                'advisory = "CVE-2024-1111"',
                'purl = "pkg:pypi/requests"',
                'state = "not_affected"',
                'justification = "code_not_reachable"',
                'author = "bob"',
                'expires = "2020-01-01T00:00:00Z"',
            ]
        ),
    )
    assert run_main(monkeypatch, ["triage", "check", SCAN_DIR, "--decisions", file]) == 0
    out = capsys.readouterr().out
    assert "2 entries" in out or "3 entries" in out


# --- the api the server shares ---------------------------------------------------------


def test_the_api_sets_and_the_scan_applies(tmp_path):
    file = str(tmp_path / "decisions.toml")
    document = api.triage_set(
        file=file,
        state="not_affected",
        author="alice",
        advisory="CVE-2024-1111",
        purl="pkg:pypi/requests",
        justification="code_not_reachable",
    )
    assert document["result"] == "added"
    listing = api.triage_entries(file=file, scan_dir=SCAN_DIR)
    assert listing["entries"][0]["status"] == "live"
    assert len(listing["entries"][0]["matches"]) == 1


# --- proposals, replacement and handles --------------------------------------------------

FID = "dsf1:" + "a" * 64

AUTHORED_FILE = "\n".join(
    [
        "[[triage]]",
        f'finding = "{FID}"',
        'state = "exploitable"',
        'detail = "confirmed exploitable"',
        'author = "alice"',
        "",
    ]
)


def test_reject_refuses_a_person_decision(tmp_path, monkeypatch):
    file = _write(tmp_path / "decisions.toml", AUTHORED_FILE)
    argv = ["triage", "review", "--reject", _handle(file), "--approver", "mallory"]
    assert run_main(monkeypatch, argv + ["--decisions", file]) == 2
    assert Path(file).read_text(encoding="utf-8") == AUTHORED_FILE


def test_set_replaces_a_live_entry_as_a_whole(tmp_path, monkeypatch):
    file = _write(
        tmp_path / "decisions.toml",
        "\n".join(
            [
                "[[triage]]",
                f'finding = "{FID}"',
                'state = "not_affected"',
                'justification = "code_not_reachable"',
                'expires = "2099-01-01T00:00:00Z"',
                'proposed_by = "agent"',
                'approver = "alice"',
                'author = "alice"',
                "",
            ]
        ),
    )
    argv = ["triage", "set", FID, "--state", "exploitable", "--author", "bob"]
    assert run_main(monkeypatch, argv + ["--decisions", file]) == 0
    tables = _tables(file)
    assert len(tables) == 1
    # Nothing of the earlier decision survives: alice never approved bob's
    # exploitable decision, and the state carries no justification.
    assert set(tables[0]) == {"finding", "state", "author", "created"}
    assert str(tables[0]["author"]) == "bob"


def test_set_reports_the_entry_it_wrote(tmp_path, monkeypatch, capsys):
    file = _write(
        tmp_path / "decisions.toml",
        "\n".join(
            [
                "[[triage]]",
                'advisory = "CVE-2021-23337"',
                'purl = "pkg:npm/lodash"',
                'version_range = "vers:npm/<4.17.21"',
                'state = "not_affected"',
                'justification = "code_not_reachable"',
                'author = "carol"',
                "",
            ]
        ),
    )
    argv = [
        "triage", "set", "--advisory", "CVE-2021-23337", "--purl", "pkg:npm/lodash",
        "--state", "exploitable", "--author", "dan", "--decisions", file, "--format", "json",
    ]  # fmt: skip
    assert run_main(monkeypatch, argv) == 0
    document = json.loads(capsys.readouterr().out)
    assert document["result"] == "added"
    assert document["entry"]["index"] == 2
    assert document["entry"]["state"] == "exploitable"
    assert "version_range" not in document["entry"]


def test_set_with_proposed_by_writes_a_proposal_beside_a_decision(tmp_path, monkeypatch, capsys):
    file = _write(tmp_path / "decisions.toml", AUTHORED_FILE)
    argv = [
        "triage", "set", FID, "--state", "not_affected", "--justification",
        "code_not_reachable", "--proposed-by", "agent session 1", "--decisions", file,
        "--format", "json",
    ]  # fmt: skip
    assert run_main(monkeypatch, argv) == 0
    document = json.loads(capsys.readouterr().out)
    assert document["entry"]["status"] == "proposal"
    assert "author" not in document["entry"]
    # alice's decision is untouched; the proposal sits beside it.
    assert Path(file).read_text(encoding="utf-8").startswith(AUTHORED_FILE)
    listing = api.triage_entries(file=file)
    assert [entry["status"] for entry in listing["entries"]] == ["live", "proposal"]


def test_review_without_an_option_lists_the_proposals(tmp_path, monkeypatch, capsys):
    file = _write(tmp_path / "decisions.toml", AUTHORED_FILE + "\n" + PROPOSAL_FILE)
    argv = ["triage", "review", "--decisions", file, "--format", "json"]
    assert run_main(monkeypatch, argv) == 0
    document = json.loads(capsys.readouterr().out)
    Draft202012Validator(load_schema("depscan-triage-output")).validate(document)
    assert [entry["status"] for entry in document["entries"]] == ["proposal"]
    assert document["entries"][0]["proposedBy"] == "triage-agent session 8123"


def test_every_editing_subcommand_exits_2_on_a_file_that_does_not_parse(tmp_path, monkeypatch):
    file = _write(tmp_path / "decisions.toml", "[[triage]\nstate=")
    assert run_main(monkeypatch, ["triage", "remove", "tr-0000000000", "--decisions", file]) == 2
    argv = ["triage", "review", "--approve", "tr-0000000000", "--approver", "a"]
    assert run_main(monkeypatch, argv + ["--decisions", file]) == 2
    argv = ["triage", "set", FID, "--state", "in_triage", "--author", "a"]
    assert run_main(monkeypatch, argv + ["--decisions", file]) == 2
    assert run_main(monkeypatch, ["triage", "list", "--decisions", file]) == 2


def test_triage_edits_the_file_the_environment_names(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    configured = tmp_path / "policy" / "decisions.toml"
    monkeypatch.setenv("DEPSCAN_DECISIONS", str(configured))
    argv = ["triage", "set", FID, "--state", "in_triage", "--author", "alice"]
    assert run_main(monkeypatch, argv) == 0
    assert configured.is_file()
    assert not (tmp_path / ".depscan" / "decisions.toml").exists()


def test_triage_edits_the_file_the_config_names(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("DEPSCAN_DECISIONS", raising=False)
    _write(tmp_path / "my.toml", '[scan]\ndecisions = "policy/decisions.toml"\n')
    argv = ["triage", "set", FID, "--state", "in_triage", "--author", "alice"]
    assert run_main(monkeypatch, argv + ["--config", str(tmp_path / "my.toml")]) == 0
    assert (tmp_path / "policy" / "decisions.toml").is_file()
    assert not (tmp_path / ".depscan" / "decisions.toml").exists()


def test_an_edit_refuses_a_file_that_changed_since_it_was_read(tmp_path):
    file = _write(tmp_path / "decisions.toml", AUTHORED_FILE)
    loaded = decisions_edit.load(file)
    # Another writer adds an entry between the read and the write.
    _write(tmp_path / "decisions.toml", AUTHORED_FILE + "\n" + PROPOSAL_FILE)
    with pytest.raises(decisions_edit.TriageEditError, match="changed since it was read"):
        decisions_edit.write_entry(
            loaded,
            selector={"finding": FID},
            fields={"state": "in_triage", "author": "bob"},
        )
    assert "CVE-2024-1111" in Path(file).read_text(encoding="utf-8")


def test_a_handle_that_names_two_entries_is_refused(tmp_path, monkeypatch):
    file = _write(tmp_path / "decisions.toml", AUTHORED_FILE + "\n" + AUTHORED_FILE)
    handle = _handle(file)
    assert handle == _handle(file, 1)
    assert run_main(monkeypatch, ["triage", "remove", handle, "--decisions", file]) == 2
    assert len(_tables(file)) == 2
