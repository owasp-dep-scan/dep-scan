"""Tests for the decisions file loader, selectors, triage application and gate."""

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict

import pytest

from analysis_lib.findings.decisions import (
    BaselineError,
    BaselineSpec,
    DecisionsError,
    FINDINGS_FILE,
    apply_baseline,
    apply_triage,
    decisions_from_document,
    entry_matches_finding,
    evaluate_gate,
    finding_matches_selectors,
    load_decisions,
    parse_decisions_document,
    parse_fail_on,
    read_baseline,
    vers_range_is_valid,
)

NOW = datetime(2026, 11, 27, 12, 0, 0, tzinfo=timezone.utc)


def _finding(**overrides) -> Dict[str, Any]:
    finding = {
        "id": "dsf1:" + "a" * 64,
        "category": "vulnerability",
        "rule": "CVE-2021-23337",
        "title": "Command injection in the lodash template function",
        "severity": "high",
        "coverage": {"state": "assessed"},
        "producer": {"name": "dep-scan", "version": "7.0.0"},
        "components": ["pkg:npm/lodash@4.17.20"],
    }
    finding.update(overrides)
    return finding


def _graded_finding(**overrides):
    finding = _finding(**overrides)
    finding["exploitability"] = {
        "axes": {
            "presence": "proven",
            "reach": "likely",
            "exposure": "likely",
            "barrier": "unknown",
        },
        "grade": "high",
        "rule": "reached",
    }
    return finding


def _write(path, text):
    path.write_text(text, encoding="utf-8")
    return str(path)


# --- loading and refusing -----------------------------------------------------------


VALID_FILE = """
# The team's decisions.
[[triage]]
finding = "dsf1:%s"
state = "not_affected"
justification = "code_not_present"
detail = "The template option is not reachable"
author = "alice"
created = "2026-11-01T09:00:00Z"

[[triage]]
advisory = "CVE-2021-23337"
purl = "pkg:npm/lodash"
version_range = "vers:npm/>=4.17.0|<4.17.21"
state = "false_positive"
author = "bob"
approver = "carol"

[[triage]]
advisory = "GHSA-p6mc-m468-83gw"
purl = "pkg:npm/lodash@4.17.20"
state = "in_triage"
proposed_by = "triage-agent session 8123"

[[expect]]
id = "no-reached-high"
description = "No reached finding of grade high or above"
grade = "high"
reach = "reached"
action = "fail"

[[expect]]
id = "warn-supply-chain"
category = "supply-chain"
action = "warn"

[[require]]
capability = "reachability"
project_type = "npm"

[baseline]
scan = "../baseline/first-scan"
digest = "%s"
"""


def test_load_valid_file(tmp_path):
    digest = "b" * 64
    _write(tmp_path / "decisions.toml", VALID_FILE % ("a" * 64, digest))
    decisions = load_decisions(str(tmp_path / "decisions.toml"))
    assert [entry.state for entry in decisions.triage] == [
        "not_affected",
        "false_positive",
        "in_triage",
    ]
    assert decisions.triage[0].author == "alice"
    assert decisions.triage[0].suppresses
    assert decisions.triage[1].approver == "carol"
    assert decisions.triage[2].is_proposal
    assert decisions.triage[1].version_range == "vers:npm/>=4.17.0|<4.17.21"
    assert [entry.id for entry in decisions.expects] == ["no-reached-high", "warn-supply-chain"]
    assert decisions.expects[0].selectors == {
        "grade": "high",
        "reach": "reached",
    }
    assert decisions.requires[0].id == "require-reachability-npm"
    assert decisions.baseline is not None
    assert decisions.baseline.scan == "../baseline/first-scan"
    assert decisions.baseline.digest == digest
    # The digest is of the file's bytes as written, which carry the host's
    # line endings, so the expectation hashes the bytes on disk.
    assert (
        decisions.digest == hashlib.sha256((tmp_path / "decisions.toml").read_bytes()).hexdigest()
    )
    assert decisions.selected_by == "default"


def test_a_number_for_a_state_is_refused_with_its_line(tmp_path):
    text = (
        '# a comment\n[[triage]]\nfinding = "dsf1:' + "a" * 64 + '"\nstate = 3\nauthor = "alice"\n'
    )
    _write(tmp_path / "decisions.toml", text)
    with pytest.raises(DecisionsError) as excinfo:
        load_decisions(str(tmp_path / "decisions.toml"))
    message = str(excinfo.value)
    assert "line 4" in message
    assert "triage/0/state" in message
    assert "valid values" in message and "not_affected" in message


def test_a_missing_key_reports_the_entry_header_line(tmp_path):
    text = (
        "[[triage]]\n"
        'finding = "dsf1:' + "a" * 64 + '"\n'
        'author = "alice"\n'
        "\n"
        "[[triage]]\n"
        'advisory = "CVE-2021-23337"\n'
    )
    _write(tmp_path / "decisions.toml", text)
    with pytest.raises(DecisionsError) as excinfo:
        load_decisions(str(tmp_path / "decisions.toml"))
    message = str(excinfo.value)
    # The first entry misses state at line 2's table; the second misses both
    # the state and the purl its advisory selector needs.
    assert "line 1" in message or "line 5" in message
    assert "state" in message


def test_an_unknown_key_is_refused_with_its_line(tmp_path):
    text = '[[triage]]\nfinding = "dsf1:' + "a" * 64 + '"\nstate = "in_triage"\nwho = "alice"\n'
    _write(tmp_path / "decisions.toml", text)
    with pytest.raises(DecisionsError) as excinfo:
        load_decisions(str(tmp_path / "decisions.toml"))
    assert "line 4" in str(excinfo.value)
    assert "who" in str(excinfo.value)


def test_not_affected_without_a_justification_is_refused(tmp_path):
    text = (
        '[[triage]]\nfinding = "dsf1:' + "a" * 64 + '"\nstate = "not_affected"\nauthor = "alice"\n'
    )
    _write(tmp_path / "decisions.toml", text)
    with pytest.raises(DecisionsError) as excinfo:
        load_decisions(str(tmp_path / "decisions.toml"))
    message = str(excinfo.value)
    assert "justification" in message
    assert "code_not_present" in message


def test_a_broken_vers_range_is_refused_with_its_line(tmp_path):
    text = (
        "[[triage]]\n"
        'advisory = "CVE-2021-23337"\n'
        'purl = "pkg:npm/lodash"\n'
        'version_range = "not a range"\n'
        'state = "in_triage"\n'
        'author = "alice"\n'
    )
    _write(tmp_path / "decisions.toml", text)
    with pytest.raises(DecisionsError) as excinfo:
        load_decisions(str(tmp_path / "decisions.toml"))
    assert "line 4" in str(excinfo.value)
    assert "vers" in str(excinfo.value)


def test_invalid_toml_names_the_line(tmp_path):
    _write(tmp_path / "decisions.toml", "[[triage]\nstate = 1\n")
    with pytest.raises(DecisionsError) as excinfo:
        load_decisions(str(tmp_path / "decisions.toml"))
    assert "TOML" in str(excinfo.value)


def test_a_missing_file_is_refused(tmp_path):
    with pytest.raises(DecisionsError) as excinfo:
        load_decisions(str(tmp_path / "absent.toml"))
    assert "cannot be read" in str(excinfo.value)


def test_both_selectors_at_once_are_refused(tmp_path):
    text = (
        "[[triage]]\n"
        'finding = "dsf1:' + "a" * 64 + '"\n'
        'advisory = "CVE-2021-23337"\n'
        'purl = "pkg:npm/lodash"\n'
        'state = "in_triage"\n'
        'author = "alice"\n'
    )
    _write(tmp_path / "decisions.toml", text)
    with pytest.raises(DecisionsError) as excinfo:
        load_decisions(str(tmp_path / "decisions.toml"))
    assert "triage/0: takes finding, or advisory with purl, not both" in str(excinfo.value)


# --- selectors ------------------------------------------------------------------------


def test_selectors_match_one_at_a_time():
    graded = _graded_finding()
    assert finding_matches_selectors(graded, {"category": "vulnerability"})
    assert not finding_matches_selectors(graded, {"category": "malware"})
    # A floor matches the floor and everything more severe.
    assert finding_matches_selectors(graded, {"severity": "high"})
    assert finding_matches_selectors(graded, {"severity": "medium"})
    assert not finding_matches_selectors(graded, {"severity": "critical"})
    assert finding_matches_selectors(graded, {"grade": "high"})
    assert finding_matches_selectors(graded, {"grade": "moderate"})
    assert not finding_matches_selectors(graded, {"grade": "critical"})
    assert finding_matches_selectors(graded, {"reach": "reached"})
    assert not finding_matches_selectors(graded, {"reach": "not_reached"})
    # A finding without confidence matches no floor.
    assert not finding_matches_selectors(graded, {"confidence": "low"})
    assert finding_matches_selectors(_finding(category="malware"), {"malware": True})
    assert not finding_matches_selectors(graded, {"malware": True})
    assert finding_matches_selectors(graded, {"rule": ["CVE-2021-23337"]})
    assert finding_matches_selectors(graded, {"rule": ["cve-2021-23337"]})
    assert not finding_matches_selectors(graded, {"rule": ["CVE-2020-8203"]})
    assert finding_matches_selectors(graded, {"purl": "pkg:npm/lodash"})
    assert not finding_matches_selectors(graded, {"purl": "pkg:pypi/lodash"})


def test_selectors_combine_with_and():
    graded = _graded_finding(severity="low")
    assert not finding_matches_selectors(graded, {"grade": "high", "severity": "medium"})
    assert finding_matches_selectors(graded, {"grade": "high", "severity": "low"})
    assert not finding_matches_selectors(
        graded, {"grade": "high", "severity": "low", "reach": "not_assessed"}
    )


def test_the_reach_assessed_unknown_matches_none_of_the_three():
    finding = _graded_finding()
    exploitability = finding["exploitability"]
    assert isinstance(exploitability, dict)
    axes = exploitability["axes"]
    assert isinstance(axes, dict)
    axes["reach"] = "unknown"
    for value in ("reached", "not_reached", "not_assessed"):
        assert not finding_matches_selectors(finding, {"reach": value})


def test_a_finding_without_exploitability_is_only_not_assessed():
    finding = _finding()
    assert finding_matches_selectors(finding, {"reach": "not_assessed"})
    assert not finding_matches_selectors(finding, {"reach": "reached"})
    grade_floor = {"grade": "moderate"}
    assert not finding_matches_selectors(finding, grade_floor)


def test_an_unknown_severity_matches_only_the_unknown_floor():
    finding = _finding(severity="unknown")
    assert finding_matches_selectors(finding, {"severity": "unknown"})
    assert not finding_matches_selectors(finding, {"severity": "low"})


def test_purl_selectors_fold_case_and_qualifiers():
    graded = _graded_finding(components=["pkg:NPM/Lodash@4.17.20?arch=x64"])
    assert finding_matches_selectors(graded, {"purl": "pkg:npm/lodash"})
    assert finding_matches_selectors(graded, {"purl": "pkg:npm/lodash@4.17.20"})
    assert not finding_matches_selectors(graded, {"purl": "pkg:npm/lodash@4.17.21"})
    assert not finding_matches_selectors(
        graded, {"purl": "pkg:npm/lodash", "version_range": "vers:npm/<4.17.0"}
    )
    assert finding_matches_selectors(
        graded, {"purl": "pkg:npm/lodash", "version_range": "vers:npm/>=4.0.0|<5.0.0"}
    )


def test_nuget_purl_case_is_folded():
    graded = _graded_finding(components=["pkg:nuget/Newtonsoft.Json@13.0.3"])
    assert finding_matches_selectors(graded, {"purl": "pkg:nuget/newtonsoft.json"})
    assert finding_matches_selectors(graded, {"purl": "pkg:nuget/newtonsoft.json@13.0.3"})


def test_the_new_selector_needs_a_baseline():
    new_finding = _finding(baseline="new")
    existing = _finding(baseline="existing")
    assert finding_matches_selectors(new_finding, {"new": True}, has_baseline=True)
    assert not finding_matches_selectors(new_finding, {"new": False}, has_baseline=True)
    assert finding_matches_selectors(existing, {"new": False}, has_baseline=True)
    assert not finding_matches_selectors(new_finding, {"new": True}, has_baseline=False)


def test_the_rule_selector_matches_an_alias():
    graded = _graded_finding()
    assert finding_matches_selectors(
        graded,
        {"rule": ["GHSA-p6mc-m468-83gw"]},
        alias_map={"cve-2021-23337": {"cve-2021-23337", "ghsa-p6mc-m468-83gw"}},
    )


def test_an_invalid_vers_range_is_refused():
    assert vers_range_is_valid("vers:npm/>=4.17.0|<4.17.21")
    # The file grammar requires the vers scheme, so a range is unambiguous
    # about which ecosystem's version rules compare it.
    assert not vers_range_is_valid(">=4.17.0|<4.17.21")
    assert not vers_range_is_valid("not a range")
    assert not vers_range_is_valid("vers:npm/>=")


# --- matching triage entries ----------------------------------------------------------


def test_a_finding_selector_matches_the_fingerprint():
    entry = decisions_from_document(
        {"triage": [{"finding": "dsf1:" + "a" * 64, "state": "in_triage"}]}
    ).triage[0]
    assert entry_matches_finding(entry, _finding())
    assert not entry_matches_finding(entry, _finding(id="dsf1:" + "b" * 64))


def test_an_advisory_alias_selector_matches_through_the_alias_map():
    entry = decisions_from_document(
        {
            "triage": [
                {
                    "advisory": "GHSA-p6mc-m468-83gw",
                    "purl": "pkg:npm/lodash",
                    "state": "in_triage",
                }
            ]
        }
    ).triage[0]
    alias_map = {"cve-2021-23337": {"cve-2021-23337", "ghsa-p6mc-m468-83gw"}}
    assert entry_matches_finding(entry, _finding(), alias_map=alias_map)
    assert not entry_matches_finding(entry, _finding())
    assert not entry_matches_finding(entry, _finding(category="supply-chain"))


def test_an_advisory_selector_with_a_pinned_version_and_range():
    entry = decisions_from_document(
        {
            "triage": [
                {
                    "advisory": "CVE-2021-23337",
                    "purl": "pkg:npm/lodash@4.17.20",
                    "version_range": "vers:npm/>=4.17.0|<4.17.21",
                    "state": "in_triage",
                }
            ]
        }
    ).triage[0]
    assert entry_matches_finding(entry, _finding())
    assert not entry_matches_finding(entry, _finding(components=["pkg:npm/lodash@4.17.21"]))


# --- applying triage ------------------------------------------------------------------


def _document(entries):
    return decisions_from_document({"triage": entries})


def test_each_state_suppresses_or_not():
    findings = [_finding(id="dsf1:" + "a" * 64)]
    for state, expected in [
        ("not_affected", True),
        ("false_positive", True),
        ("resolved", True),
        ("in_triage", False),
        ("exploitable", False),
        ("resolved_with_pedigree", False),
    ]:
        entry = {"finding": "dsf1:" + "a" * 64, "state": state, "author": "alice"}
        if state == "not_affected":
            entry["justification"] = "code_not_present"
        applied = [dict(f) for f in findings]
        application = apply_triage(applied, _document([entry]).triage)
        assert (application.suppressed == 1) is expected, state
        # Nothing is deleted either way, and the gate skips a suppressed one.
        assert len(applied) == 1 and applied[0]["triage"]["state"] == state
        gate = _decisions_with(expect=[{"id": "any", "severity": "high", "action": "fail"}])
        assert evaluate_gate(applied, [], gate).exit_code == (0 if expected else 3), state


def test_an_expired_entry_warns_and_does_not_suppress():
    finding = _finding(id="dsf1:" + "a" * 64)
    entry = {
        "finding": "dsf1:" + "a" * 64,
        "state": "not_affected",
        "justification": "code_not_present",
        "author": "alice",
        "expires": "2026-01-01T00:00:00Z",
    }
    application = apply_triage([finding], _document([entry]).triage, now=NOW)
    assert application.suppressed == 0
    assert application.applied == 0
    assert len(application.expired) == 1
    report = application.expired[0].to_document()
    assert report["expires"] == "2026-01-01T00:00:00Z"
    assert report["findings"] == ["dsf1:" + "a" * 64]
    assert "triage" not in finding


def test_an_unexpired_entry_applies():
    finding = _finding(id="dsf1:" + "a" * 64)
    entry = {
        "finding": "dsf1:" + "a" * 64,
        "state": "not_affected",
        "justification": "code_not_present",
        "author": "alice",
        "expires": "2027-01-01T00:00:00Z",
    }
    application = apply_triage([finding], _document([entry]).triage, now=NOW)
    assert application.suppressed == 1
    triage = finding["triage"]
    assert isinstance(triage, dict)
    assert triage["state"] == "not_affected"
    assert triage["author"] == "alice"


def test_a_stale_entry_is_reported_with_its_selector():
    entry = {
        "finding": "dsf1:" + "c" * 64,
        "state": "in_triage",
        "author": "alice",
    }
    application = apply_triage([_finding()], _document([entry]).triage, now=NOW)
    assert application.applied == 0
    assert len(application.stale) == 1
    assert application.stale[0].to_document()["selector"] == {"finding": "dsf1:" + "c" * 64}


def test_a_proposal_changes_nothing_until_approved():
    finding = _finding(id="dsf1:" + "a" * 64)
    proposal = {
        "finding": "dsf1:" + "a" * 64,
        "state": "not_affected",
        "justification": "code_not_present",
        "proposed_by": "triage-agent session 8123",
    }
    application = apply_triage([finding], _document([proposal]).triage, now=NOW)
    assert application.suppressed == 0
    assert application.applied == 0
    assert len(application.proposals) == 1
    assert "triage" not in finding
    approved = dict(proposal, approver="alice")
    application = apply_triage([finding], _document([approved]).triage, now=NOW)
    assert application.suppressed == 1
    triage = finding["triage"]
    assert isinstance(triage, dict)
    assert triage["approver"] == "alice"


def test_an_entry_entered_by_a_person_applies_without_an_approver():
    finding = _finding(id="dsf1:" + "a" * 64)
    entry = {
        "finding": "dsf1:" + "a" * 64,
        "state": "in_triage",
        "author": "alice",
    }
    application = apply_triage([finding], _document([entry]).triage, now=NOW)
    assert application.applied == 1
    assert application.suppressed == 0


# --- the baseline ---------------------------------------------------------------------


def test_read_baseline_reads_a_findings_file(tmp_path):
    document = {"schemaVersion": "2", "findings": [_finding(), _finding(id="dsf1:" + "b" * 64)]}
    path = tmp_path / FINDINGS_FILE
    path.write_text(json.dumps(document), encoding="utf-8")
    ids = read_baseline(BaselineSpec(scan=str(path)))
    assert ids == {"dsf1:" + "a" * 64, "dsf1:" + "b" * 64}


def test_read_baseline_resolves_against_the_decisions_dir(tmp_path):
    baseline_dir = tmp_path / "baseline" / "first"
    baseline_dir.mkdir(parents=True)
    (baseline_dir / FINDINGS_FILE).write_text(
        json.dumps({"schemaVersion": "2", "findings": [_finding()]}), encoding="utf-8"
    )
    decisions_dir = tmp_path / "project" / ".depscan"
    decisions_dir.mkdir(parents=True)
    ids = read_baseline(BaselineSpec(scan="../../baseline/first"), base_dir=str(decisions_dir))
    assert ids == {"dsf1:" + "a" * 64}


def test_read_baseline_checks_the_digest(tmp_path):
    path = tmp_path / FINDINGS_FILE
    raw = json.dumps({"schemaVersion": "2", "findings": [_finding()]})
    # Write in binary mode so the digest is of exactly these bytes on every
    # platform; a text-mode write would translate the newlines on Windows.
    path.write_bytes(raw.encode("utf-8"))
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    assert read_baseline(BaselineSpec(scan=str(path), digest=digest))
    with pytest.raises(BaselineError) as excinfo:
        read_baseline(BaselineSpec(scan=str(path), digest="0" * 64))
    assert "digest" in str(excinfo.value)


def test_an_unreadable_baseline_is_a_baseline_error(tmp_path):
    with pytest.raises(BaselineError) as excinfo:
        read_baseline(BaselineSpec(scan=str(tmp_path / "absent")))
    assert "cannot be read" in str(excinfo.value)


def test_a_document_that_is_not_findings_is_refused(tmp_path):
    path = tmp_path / "not-findings.json"
    path.write_text(json.dumps({"something": "else"}), encoding="utf-8")
    with pytest.raises(BaselineError) as excinfo:
        read_baseline(BaselineSpec(scan=str(path)))
    assert "not a findings document" in str(excinfo.value)


def test_a_windows_style_path_is_read(tmp_path):
    document = {"schemaVersion": "2", "findings": [_finding()]}
    nested = tmp_path / "win" / "baseline"
    nested.mkdir(parents=True)
    (nested / FINDINGS_FILE).write_text(json.dumps(document), encoding="utf-8")
    # A Windows-style relative path with backslashes resolves the same way.
    ids = read_baseline(BaselineSpec(scan="win\\baseline"), base_dir=str(tmp_path))
    assert ids == {"dsf1:" + "a" * 64}


def test_apply_baseline_marks_new_and_existing():
    findings = [_finding(id="dsf1:" + "a" * 64), _finding(id="dsf1:" + "e" * 64)]
    new, existing = apply_baseline(findings, {"dsf1:" + "a" * 64})
    assert (new, existing) == (1, 1)
    assert findings[0]["baseline"] == "existing"
    assert findings[1]["baseline"] == "new"


# --- the gate -------------------------------------------------------------------------


def _decisions_with(**sections):
    return decisions_from_document(sections)


def test_an_expect_entry_fails_warns_and_passes():
    graded = _graded_finding()
    decisions = _decisions_with(
        expect=[
            {"id": "fail-high", "grade": "high", "action": "fail"},
            {"id": "warn-scan", "category": "supply-chain", "action": "warn"},
        ]
    )
    evaluation = evaluate_gate([graded], [], decisions)
    assert [result.status for result in evaluation.results] == ["fail", "pass"]
    assert evaluation.exit_code == 3
    assert evaluation.results[0].findings == [graded["id"]]
    assert evaluation.results[0].evidence == ["depscan.findings.json"]


def test_a_warn_action_never_changes_the_exit():
    decisions = _decisions_with(expect=[{"id": "w", "category": "malware", "action": "warn"}])
    evaluation = evaluate_gate([_finding(category="malware")], [], decisions)
    assert evaluation.results[0].status == "warn"
    assert evaluation.exit_code == 0
    assert evaluation.summary_document()["warn"] == 1


def test_a_new_selector_without_a_baseline_is_not_evaluated():
    decisions = _decisions_with(expect=[{"id": "only-new", "new": True, "action": "fail"}])
    evaluation = evaluate_gate([_finding()], [], decisions)
    assert evaluation.results[0].status == "not_evaluated"
    reason = evaluation.results[0].reason
    assert reason is not None and "baseline" in reason
    assert evaluation.exit_code == 0


def test_a_new_selector_evaluates_against_the_baseline_flags():
    decisions = _decisions_with(expect=[{"id": "only-new", "new": True, "action": "fail"}])
    findings = [_finding(id="dsf1:" + "a" * 64, baseline="new")]
    evaluation = evaluate_gate(findings, [], decisions, has_baseline=True)
    assert evaluation.results[0].status == "fail"
    findings = [_finding(id="dsf1:" + "a" * 64, baseline="existing")]
    evaluation = evaluate_gate(findings, [], decisions, has_baseline=True)
    assert evaluation.results[0].status == "pass"


def test_a_require_entry_passes_fails_and_is_not_evaluated():
    stages = [
        {
            "name": "enrichment",
            "status": "completed",
            "capabilities": ["reachability"],
            "projectType": "npm",
        },
        {
            "name": "risk",
            "status": "not-assessed",
            "capabilities": ["supply-chain"],
            "projectType": "npm",
        },
        {
            "name": "enrichment",
            "status": "completed",
            "capabilities": ["reachability"],
            "projectType": "pypi",
        },
    ]
    decisions = _decisions_with(
        require=[
            {"capability": "reachability"},
            {"capability": "supply-chain"},
            {"capability": "reachability", "project_type": "golang"},
        ]
    )
    evaluation = evaluate_gate([], stages, decisions)
    statuses = [result.status for result in evaluation.results]
    assert statuses == ["pass", "fail", "not_evaluated"]
    assert evaluation.exit_code == 4
    stages_reported = evaluation.results[1].stages[0]
    assert isinstance(stages_reported, dict)
    assert stages_reported["name"] == "risk"
    reason = evaluation.results[1].reason
    assert reason is not None and "not assessed" in reason
    other = evaluation.results[2].reason
    assert other is not None and "golang" in other


def test_a_require_without_any_stage_fails():
    decisions = _decisions_with(require=[{"capability": "reachability"}])
    evaluation = evaluate_gate([], [], decisions)
    assert evaluation.exit_code == 4
    reason = evaluation.results[0].reason
    assert reason is not None and "no manifest stage recorded it" in reason


def test_four_wins_over_three():
    decisions = _decisions_with(
        expect=[{"id": "fail-high", "grade": "high", "action": "fail"}],
        require=[{"capability": "reachability"}],
    )
    evaluation = evaluate_gate([_graded_finding()], [], decisions)
    assert evaluation.exit_code == 4


def test_the_summary_counts_suppressed_new_and_existing():
    decisions = _decisions_with(
        expect=[{"id": "fail-high", "grade": "high", "action": "fail"}],
    )
    findings = [
        _graded_finding(id="dsf1:" + "a" * 64, baseline="new"),
        _graded_finding(
            id="dsf1:" + "b" * 64, baseline="existing", triage={"state": "not_affected"}
        ),
    ]
    evaluation = evaluate_gate(
        findings, [], decisions, has_baseline=True, suppressed=1, new=1, existing=1
    )
    summary = evaluation.summary_document()
    assert summary["fail"] == 1
    assert summary["new"] == 1 and summary["existing"] == 1 and summary["suppressed"] == 1


def test_the_document_carries_the_schema_version_and_the_triage_report(tmp_path):
    decisions = _decisions_with(
        expect=[{"id": "fail-high", "grade": "high", "action": "fail"}],
    )
    expired_entry = {
        "finding": "dsf1:" + "d" * 64,
        "state": "not_affected",
        "justification": "code_not_present",
        "author": "alice",
        "expires": "2026-01-01T00:00:00Z",
    }
    document = decisions_from_document({"triage": [expired_entry]})
    findings = [_graded_finding(id="dsf1:" + "d" * 64)]
    application = apply_triage(findings, document.triage, now=NOW)
    evaluation = evaluate_gate(
        findings, [], decisions, application=application, suppressed=application.suppressed
    )
    published = evaluation.to_document(evaluated_utc="2026-11-27T12:00:00+00:00", source="scan")
    from analysis_lib.findings.schemas import validate

    validate("depscan-expectations", published)
    assert published["schemaVersion"] == "1"
    assert published["triage"]["expired"][0]["findings"] == ["dsf1:" + "d" * 64]
    assert published["results"][0]["id"] == "fail-high"


# --- the --fail-on expression ---------------------------------------------------------


def test_parse_fail_on_builds_the_same_grammar_as_the_file():
    entry = parse_fail_on("category=vulnerability,grade=high,reach=reached")
    assert entry.action == "fail"
    assert entry.selectors == {
        "category": "vulnerability",
        "grade": "high",
        "reach": "reached",
    }
    assert entry.id == "fail-on:1"


def test_parse_fail_on_takes_lists_and_booleans():
    entry = parse_fail_on("rule=CVE-2020-8203|GHSA-p6mc-m468-83gw,new=true")
    assert entry.selectors["rule"] == ["CVE-2020-8203", "GHSA-p6mc-m468-83gw"]
    assert entry.selectors["new"] is True


def test_parse_fail_on_refuses_unknown_keys_and_values():
    with pytest.raises(DecisionsError) as excinfo:
        parse_fail_on("colour=red")
    assert "not a selector" in str(excinfo.value)
    with pytest.raises(DecisionsError) as excinfo:
        parse_fail_on("grade=extreme")
    assert "grade 'extreme' is not a valid value; valid values: critical" in str(excinfo.value)
    with pytest.raises(DecisionsError):
        parse_fail_on("grade")
    with pytest.raises(DecisionsError):
        parse_fail_on("new=maybe")


def test_the_fail_on_entry_and_the_file_agree():
    graded = _graded_finding()
    from_file = _decisions_with(expect=[{"id": "same", "grade": "high", "action": "fail"}])
    from_cli = parse_fail_on("grade=high")
    assert finding_matches_selectors(graded, from_file.expects[0].selectors)
    assert finding_matches_selectors(graded, from_cli.selectors)


def test_a_suppressed_finding_is_out_of_the_gate():
    decisions = _decisions_with(expect=[{"id": "no-high", "severity": "high", "action": "fail"}])
    findings = [
        _graded_finding(id="dsf1:" + "a" * 64, triage={"state": "not_affected"}),
        _graded_finding(id="dsf1:" + "b" * 64),
    ]
    evaluation = evaluate_gate(findings, [], decisions)
    assert evaluation.results[0].status == "fail"
    assert evaluation.results[0].findings == ["dsf1:" + "b" * 64]
    findings = [_graded_finding(id="dsf1:" + "a" * 64, triage={"state": "not_affected"})]
    evaluation = evaluate_gate(findings, [], decisions)
    assert evaluation.results[0].status == "pass"
    assert evaluation.exit_code == 0


# --- proposals and live entries -----------------------------------------------------


DSF_A = "dsf1:" + "a" * 64


def test_an_author_never_turns_a_proposal_into_a_live_decision():
    # The shape propose_triage wrote over a person's entry: the author was
    # kept and proposed_by added. Without an approver it is a proposal.
    entry = _document(
        [
            {
                "finding": DSF_A,
                "state": "not_affected",
                "justification": "code_not_reachable",
                "author": "alice",
                "proposed_by": "agent session 1",
            }
        ]
    ).triage[0]
    assert entry.is_proposal
    finding = _finding()
    application = apply_triage([finding], [entry], now=NOW)
    assert application.suppressed == 0
    assert [report.entry for report in application.proposals] == [entry]
    assert "triage" not in finding


def test_a_proposal_may_omit_the_author_and_a_live_entry_may_not(tmp_path):
    proposal = (
        f'[[triage]]\nfinding = "{DSF_A}"\nstate = "in_triage"\nproposed_by = "agent session 1"\n'
    )
    _write(tmp_path / "proposal.toml", proposal)
    assert load_decisions(str(tmp_path / "proposal.toml")).triage[0].is_proposal
    _write(
        tmp_path / "live.toml", f'# team\n[[triage]]\nfinding = "{DSF_A}"\nstate = "in_triage"\n'
    )
    with pytest.raises(DecisionsError) as excinfo:
        load_decisions(str(tmp_path / "live.toml"))
    assert "line 2: triage/0: needs author" in str(excinfo.value)
    approved = proposal + 'approver = "carol"\n'
    _write(tmp_path / "approved.toml", approved)
    entry = load_decisions(str(tmp_path / "approved.toml")).triage[0]
    assert not entry.is_proposal


# --- applying again -------------------------------------------------------------------


def test_applying_again_reflects_the_file_as_it_is_now():
    finding = _graded_finding()
    entry = {
        "advisory": "CVE-2021-23337",
        "purl": "pkg:npm/lodash",
        "state": "not_affected",
        "justification": "code_not_present",
        "author": "alice",
        "expires": "2026-12-01T00:00:00Z",
    }
    entries = _document([entry]).triage
    gate = _decisions_with(expect=[{"id": "no-high", "severity": "high", "action": "fail"}])
    scan_time = apply_triage([finding], entries, now=NOW)
    assert scan_time.suppressed == 1
    assert evaluate_gate([finding], [], gate).exit_code == 0
    # The saved finding keeps the scan's triage object; a report run after
    # the expiry, or with the entry removed, must not inherit it.
    report_time = apply_triage([finding], entries, now=datetime(2026, 12, 5, tzinfo=timezone.utc))
    assert len(report_time.expired) == 1 and report_time.suppressed == 0
    assert "triage" not in finding
    assert evaluate_gate([finding], [], gate, application=report_time).exit_code == 3
    apply_triage([finding], entries, now=NOW)
    removed = apply_triage([finding], [], now=NOW)
    assert removed.suppressed == 0 and "triage" not in finding


def test_applying_no_baseline_clears_the_saved_marks():
    findings = [_finding(baseline="new"), _finding(id="dsf1:" + "b" * 64, baseline="existing")]
    assert apply_baseline(findings, None) == (0, 0)
    assert all("baseline" not in finding for finding in findings)
    assert apply_baseline(findings, {"dsf1:" + "b" * 64}) == (1, 1)


# --- one winner per finding -----------------------------------------------------------


def _two_entries(advisory_state: str, finding_state: str, finding_first: bool):
    advisory = {
        "advisory": "CVE-2021-23337",
        "purl": "pkg:npm/lodash",
        "state": advisory_state,
        "author": "a",
    }
    by_finding = {"finding": "", "state": finding_state, "author": "b"}
    for entry in (advisory, by_finding):
        if entry["state"] == "not_affected":
            entry["justification"] = "code_not_reachable"
    return (
        advisory,
        by_finding,
        [by_finding, advisory] if finding_first else [advisory, by_finding],
    )


def _vdr_pair():
    from analysis_lib.findings.vdr_convert import findings_from_vdr

    vuln: Dict[str, Any] = {"id": "CVE-2021-23337", "affects": [{"ref": "pkg:npm/lodash@4.17.20"}]}
    finding = findings_from_vdr([vuln], producer_version="7.0.0")[0].to_dict()
    return vuln, finding


@pytest.mark.parametrize("finding_first", [True, False])
def test_a_finding_selector_beats_an_advisory_selector(finding_first):
    from analysis_lib.findings.decisions import annotate_vdr_analysis

    vuln, finding = _vdr_pair()
    _, by_finding, entries = _two_entries("not_affected", "exploitable", finding_first)
    by_finding["finding"] = finding["id"]
    triage = _document(entries).triage
    application = apply_triage([finding], triage, now=NOW)
    assert finding["triage"]["state"] == "exploitable"
    assert application.suppressed == 0 and application.applied == 1
    shadowed = [report.to_document() for report in application.shadowed]
    assert [report["selector"].get("advisory") for report in shadowed] == ["CVE-2021-23337"]
    assert shadowed[0]["findings"] == [finding["id"]]
    gate = _decisions_with(expect=[{"id": "no-high", "severity": "unknown", "action": "fail"}])
    evaluation = evaluate_gate([finding], [], gate, application=application)
    assert evaluation.exit_code == 3
    assert evaluation.summary_document()["suppressed"] == 0
    # The VDR takes the same winner, from the application or the entries.
    assert annotate_vdr_analysis([vuln], application) == 1
    assert vuln["analysis"] == {"state": "exploitable"}
    fresh, _ = _vdr_pair()
    annotate_vdr_analysis([fresh], triage, now=NOW)
    assert fresh["analysis"] == {"state": "exploitable"}


def test_the_first_entry_of_one_kind_wins():
    finding = _finding()
    first = {"finding": DSF_A, "state": "false_positive", "author": "a"}
    second = {"finding": DSF_A, "state": "exploitable", "author": "b"}
    application = apply_triage([finding], _document([first, second]).triage, now=NOW)
    assert finding["triage"]["state"] == "false_positive"
    assert application.suppressed == 1
    assert [report.entry.index for report in application.shadowed] == [2]


def test_a_finding_keyed_decision_reaches_the_vdr():
    from analysis_lib.findings.decisions import annotate_vdr_analysis

    vuln, finding = _vdr_pair()
    entries = _document(
        [{"finding": finding["id"], "state": "false_positive", "author": "alice"}]
    ).triage
    assert annotate_vdr_analysis([vuln], entries, now=NOW) == 1
    assert vuln["analysis"] == {"state": "false_positive"}
    assert {"name": "depscan:triage:author", "value": "alice"} in vuln["properties"]


def test_suppressed_counts_findings_not_fingerprints():
    # Two versions of one package share a fingerprint and stay two findings.
    findings = [_finding(), _finding(components=["pkg:npm/lodash@4.17.19"])]
    entry = {"finding": DSF_A, "state": "false_positive", "author": "alice"}
    application = apply_triage(findings, _document([entry]).triage, now=NOW)
    assert application.suppressed == 2
    assert application.applied == 1


# --- the selectors the file and --fail-on share ---------------------------------------


FAIL_ON_SAMPLES = {
    "category": ("vulnerability", "vulnerability"),
    "severity": ("high", "high"),
    "grade": ("high", "high"),
    "reach": ("reached", "reached"),
    "malware": ("false", False),
    "rule": ("CVE-2021-23337|CVE-1", ["CVE-2021-23337", "CVE-1"]),
    "purl": ("pkg:npm/lodash", "pkg:npm/lodash"),
    "confidence": ("high", "high"),
    "new": ("true", True),
}


def test_every_fail_on_selector_is_honoured_in_the_file(tmp_path):
    from analysis_lib.findings.decisions import SELECTOR_KEYS

    samples = dict(FAIL_ON_SAMPLES)
    samples["version_range"] = ("vers:npm/<4.17.21", "vers:npm/<4.17.21")
    assert set(samples) == set(SELECTOR_KEYS)
    for key, (cli_value, toml_value) in samples.items():
        expression = f"{key}={cli_value}"
        if key == "version_range":
            expression = f"purl=pkg:npm/lodash,{expression}"
        from_cli = parse_fail_on(expression)
        toml = (
            json.dumps(toml_value) if not isinstance(toml_value, bool) else str(toml_value).lower()
        )
        text = f'[[expect]]\nid = "x"\naction = "fail"\n{key} = {toml}\n'
        if key == "version_range":
            text += 'purl = "pkg:npm/lodash"\n'
        _write(tmp_path / "decisions.toml", text)
        from_file = load_decisions(str(tmp_path / "decisions.toml")).expects[0]
        assert from_file.selectors == from_cli.selectors, key


def test_a_version_range_in_the_file_narrows_the_purl():
    findings = [_finding(components=["pkg:npm/lodash@4.17.21"])]
    decisions = decisions_from_document(
        parse_decisions_document(
            '[[expect]]\nid = "old-lodash"\naction = "fail"\n'
            'purl = "pkg:npm/lodash"\nversion_range = "vers:npm/<4.17.21"\n'
        )
    )
    from_file = evaluate_gate(findings, [], decisions)
    from_cli = evaluate_gate(
        findings,
        [],
        decisions_from_document({}),
        cli_expects=[parse_fail_on("purl=pkg:npm/lodash,version_range=vers:npm/<4.17.21")],
    )
    assert from_file.exit_code == from_cli.exit_code == 0
    findings[0]["components"] = ["pkg:npm/lodash@4.17.20"]
    assert evaluate_gate(findings, [], decisions).exit_code == 3


def test_a_version_range_needs_a_purl_and_its_scheme():
    for text in (
        '[[expect]]\nid = "x"\naction = "fail"\nseverity = "high"\nversion_range = "vers:npm/<1"\n',
        '[[triage]]\nfinding = "%s"\nstate = "in_triage"\nauthor = "a"\n'
        'version_range = "vers:npm/<1"\n' % DSF_A,
    ):
        with pytest.raises(DecisionsError) as excinfo:
            parse_decisions_document(text)
        assert "version_range narrows purl and needs purl" in str(excinfo.value)
    with pytest.raises(DecisionsError) as excinfo:
        parse_fail_on("severity=high,version_range=vers:npm/<1")
    assert "needs purl" in str(excinfo.value)
    with pytest.raises(DecisionsError) as excinfo:
        parse_fail_on("purl=pkg:npm/lodash,version_range=vers:pypi/<5")
    assert "uses the pypi scheme" in str(excinfo.value)
    assert parse_fail_on("purl=pkg:golang/github.com/x/y,version_range=vers:golang/<v1.3.0")


@pytest.mark.parametrize(
    "version_range", ["vers:npm/garbage!!", "vers:npm/>=abc", "vers:npm/<1|>x"]
)
def test_a_range_naming_no_version_is_refused(version_range):
    assert not vers_range_is_valid(version_range)
    with pytest.raises(DecisionsError) as excinfo:
        parse_fail_on(f"purl=pkg:npm/lodash,version_range={version_range}")
    assert "which is not a version" in str(excinfo.value)
    assert vers_range_is_valid("vers:npm/*")


# --- malware ----------------------------------------------------------------------------


def test_a_malware_finding_matches_the_malware_selector_and_its_advisory():
    from analysis_lib.findings.vdr_convert import findings_from_vdr

    vuln = {"id": "MAL-2025-1234", "affects": [{"ref": "pkg:npm/evil-pkg@1.0.0"}]}
    finding = findings_from_vdr([vuln], producer_version="7.0.0")[0].to_dict()
    assert finding["category"] == "malware"
    gate = _decisions_with(expect=[{"id": "no-malware", "malware": True, "action": "fail"}])
    assert evaluate_gate([finding], [], gate).exit_code == 3
    gate = _decisions_with(expect=[{"id": "no-malware", "category": "malware", "action": "fail"}])
    assert evaluate_gate([finding], [], gate).exit_code == 3
    entry = {
        "advisory": "MAL-2025-1234",
        "purl": "pkg:npm/evil-pkg",
        "state": "false_positive",
        "author": "alice",
    }
    assert apply_triage([finding], _document([entry]).triage, now=NOW).suppressed == 1


# --- requirements and ids --------------------------------------------------------------


def test_the_require_capabilities_are_the_ones_a_stage_records():
    from analysis_lib.findings.decisions import REQUIRE_CAPABILITIES
    from analysis_lib.findings.schemas import load_schema

    schema = load_schema("depscan-decisions")
    capability = schema["properties"]["require"]["items"]["properties"]["capability"]
    assert tuple(capability["enum"]) == REQUIRE_CAPABILITIES
    assert "supply-chain" in REQUIRE_CAPABILITIES and "binary" in REQUIRE_CAPABILITIES


@pytest.mark.parametrize("capability", ["memory-safety", "mobile", "code", "crypto"])
def test_a_requirement_no_stage_can_meet_is_refused(capability):
    with pytest.raises(DecisionsError) as excinfo:
        parse_decisions_document(f'[[require]]\ncapability = "{capability}"\n')
    message = str(excinfo.value)
    assert f"line 2: require/0/capability: dep-scan does not assess {capability} yet" in message
    assert message.count("require/0/capability") == 1


def test_a_require_result_without_a_project_type_validates():
    from analysis_lib.findings.schemas import validate

    stages = [{"name": "database", "status": "completed", "capabilities": ["vulnerabilities"]}]
    decisions = _decisions_with(require=[{"capability": "vulnerabilities"}])
    evaluation = evaluate_gate([], stages, decisions)
    assert evaluation.results[0].stages == [{"name": "database", "status": "completed"}]
    validate(
        "depscan-expectations",
        evaluation.to_document(evaluated_utc="2026-11-27T12:00:00Z", source="scan"),
    )


def test_ids_are_unique_across_the_file():
    text = (
        '[[expect]]\nid = "same"\naction = "fail"\nseverity = "high"\n\n'
        '[[expect]]\nid = "same"\naction = "warn"\nseverity = "low"\n\n'
        '[[require]]\ncapability = "license"\n\n'
        '[[require]]\ncapability = "license"\n'
    )
    with pytest.raises(DecisionsError) as excinfo:
        parse_decisions_document(text)
    message = str(excinfo.value)
    assert "line 7: expect/1/id: the id 'same' is already used by expect/0" in message
    assert (
        "line 14: require/1/id: the id 'require-license' is already used by require/0" in message
    )
    with pytest.raises(DecisionsError):
        parse_decisions_document(
            '[[expect]]\nid = "fail-on:1"\naction = "fail"\nseverity = "high"\n'
        )


# --- handles ----------------------------------------------------------------------------


def test_the_handle_follows_the_selector_and_not_the_position():
    from analysis_lib.findings.decisions import entry_handle

    live = {"advisory": "CVE-2021-23337", "purl": "pkg:npm/lodash", "state": "in_triage"}
    first = _document([dict(live, author="a")]).triage[0]
    moved = _document(
        [{"finding": DSF_A, "state": "in_triage", "author": "b"}, dict(live, author="c")]
    )
    assert first.handle == moved.triage[1].handle == entry_handle(first)
    assert re.fullmatch(r"tr-[0-9a-f]{10}", first.handle)
    folded = _document([dict(live, advisory="cve-2021-23337", purl="pkg:NPM/lodash", author="d")])
    assert folded.triage[0].handle == first.handle
    proposals = _document(
        [dict(live, proposed_by="agent 1"), dict(live, proposed_by="agent 2")]
    ).triage
    assert len({first.handle, proposals[0].handle, proposals[1].handle}) == 3
    report = apply_triage([_finding()], [first], now=NOW)
    assert report.to_document()["stale"] == [] and report.applied == 1


# --- refusals -----------------------------------------------------------------------------


def test_baseline_keys_report_their_own_line():
    text = '# c\n[baseline]\nscan = "x"\ndigest = "nothex"\ndigst = "y"\n'
    with pytest.raises(DecisionsError) as excinfo:
        parse_decisions_document(text)
    message = str(excinfo.value)
    assert "line 4: baseline/digest:" in message
    assert "line 5: baseline: Additional properties are not allowed ('digst'" in message
    assert "valid values: scan, digest" in message


def test_headers_inside_multi_line_strings_and_spaced_headers_are_placed():
    text = (
        f'[[triage]]\nfinding = "{DSF_A}"\nstate = "in_triage"\nauthor = "a"\n'
        'detail = """\nsee\n[[triage]]\n"""\n\n'
        f'[[ triage ]]\nfinding = "{DSF_A}"\nauthor = "a"\nstate = 5\n'
    )
    with pytest.raises(DecisionsError) as excinfo:
        parse_decisions_document(text)
    message = str(excinfo.value)
    assert "line 13: triage/1/state: 5 is not of type 'string'; valid values: resolved" in message
    # A type error on a key with an enum is reported once.
    assert message.count("triage/1/state") == 1
    with pytest.raises(DecisionsError) as excinfo:
        parse_decisions_document(
            f'# top\ntriage = [{{finding = "{DSF_A}", state = 7, author = "a"}}]\n'
        )
    assert "line 2: triage/0/state" in str(excinfo.value)


def test_composite_rules_name_what_is_missing():
    with pytest.raises(DecisionsError) as excinfo:
        parse_decisions_document(
            '[[triage]]\nadvisory = "CVE-1"\nstate = "in_triage"\nauthor = "a"\n'
        )
    assert "line 1: triage/0: an advisory selector needs purl" in str(excinfo.value)
    with pytest.raises(DecisionsError) as excinfo:
        parse_decisions_document('[[expect]]\nid = "x"\naction = "fail"\n')
    assert "expect/0: needs at least one selector; valid values: category, severity" in str(
        excinfo.value
    )


def test_problems_are_reported_in_line_order():
    text = (
        f'[[triage]]\nfinding = "{DSF_A}"\nstate = "bogus"\nauthor = "a"\n\n'
        '[[expect]]\nid = "x"\naction = "maybe"\nseverity = "high"\n'
    )
    with pytest.raises(DecisionsError) as excinfo:
        parse_decisions_document(text)
    lines = str(excinfo.value).splitlines()[1:]
    assert [line.split(":")[0] for line in lines] == ["line 3", "line 8"]


def test_a_file_that_is_not_utf8_is_refused_and_a_bom_is_accepted(tmp_path):
    path = tmp_path / "decisions.toml"
    path.write_bytes(b'[[require]]\ncapability = "\xff"\n')
    with pytest.raises(DecisionsError) as excinfo:
        load_decisions(str(path))
    assert "is not UTF-8 text: the byte at offset 26" in str(excinfo.value)
    raw = '\ufeff[[require]]\ncapability = "reachability"\n'.encode("utf-8")
    path.write_bytes(raw)
    decisions = load_decisions(str(path))
    assert decisions.requires[0].capability == "reachability"
    assert decisions.digest == hashlib.sha256(raw).hexdigest()


def test_toml_date_times_are_read_and_local_dates_refused():
    text = f'[[triage]]\nfinding = "{DSF_A}"\nstate = "in_triage"\nauthor = "a"\n'
    document = parse_decisions_document(text + "expires = 2026-12-31T00:00:00Z\n")
    entry = decisions_from_document(document).triage[0]
    assert entry.expires == "2026-12-31T00:00:00Z"
    with pytest.raises(DecisionsError) as excinfo:
        parse_decisions_document(text + "expires = 2026-12-31\n")
    message = str(excinfo.value)
    assert "line 5: triage/0/expires: 2026-12-31 is a TOML date without an offset" in message
    assert '"2026-12-31T00:00:00Z"' in message and message.count("triage/0/expires") == 1


def test_a_windows_drive_baseline_is_absolute_everywhere(tmp_path):
    with pytest.raises(BaselineError) as excinfo:
        read_baseline(BaselineSpec(scan="C:/scans/main"), base_dir=str(tmp_path))
    assert str(tmp_path) not in str(excinfo.value.__cause__)


# --- the enums the code keeps -------------------------------------------------------------


def test_the_floors_compare_most_severe_first():
    from analysis_lib.findings.decisions import (
        CONFIDENCE_ORDER,
        GRADE_ORDER,
        REACH_SELECTOR_VALUES,
        SEVERITY_ORDER,
    )
    from analysis_lib.findings.fingerprint import CATEGORIES
    from analysis_lib.findings.schemas import load_schema

    assert SEVERITY_ORDER == ("critical", "high", "medium", "low", "info", "unknown")
    assert GRADE_ORDER == ("critical", "high", "moderate", "low", "shielded", "unassessed")
    assert CONFIDENCE_ORDER == ("high", "medium", "low")
    expect = load_schema("depscan-decisions")["properties"]["expect"]["items"]["properties"]
    assert tuple(expect["reach"]["enum"]) == tuple(REACH_SELECTOR_VALUES)
    assert tuple(expect["category"]["enum"]) == CATEGORIES
