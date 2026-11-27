"""Tests for the decisions file loader, selectors, triage application and gate."""

import hashlib
import json
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
        "axes": {"presence": "proven", "reach": "likely", "exposure": "likely", "barrier": "unknown"},
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
    assert decisions.digest == hashlib.sha256(
        (VALID_FILE % ("a" * 64, digest)).encode("utf-8")
    ).hexdigest()
    assert decisions.selected_by == "default"


def test_a_number_for_a_state_is_refused_with_its_line(tmp_path):
    text = (
        "# a comment\n"
        "[[triage]]\n"
        "finding = \"dsf1:" + "a" * 64 + "\"\n"
        "state = 3\n"
        "author = \"alice\"\n"
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
        "finding = \"dsf1:" + "a" * 64 + "\"\n"
        "author = \"alice\"\n"
        "\n"
        "[[triage]]\n"
        "advisory = \"CVE-2021-23337\"\n"
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
    text = (
        "[[triage]]\n"
        "finding = \"dsf1:" + "a" * 64 + "\"\n"
        "state = \"in_triage\"\n"
        "who = \"alice\"\n"
    )
    _write(tmp_path / "decisions.toml", text)
    with pytest.raises(DecisionsError) as excinfo:
        load_decisions(str(tmp_path / "decisions.toml"))
    assert "line 4" in str(excinfo.value)
    assert "who" in str(excinfo.value)


def test_not_affected_without_a_justification_is_refused(tmp_path):
    text = (
        "[[triage]]\n"
        "finding = \"dsf1:" + "a" * 64 + "\"\n"
        "state = \"not_affected\"\n"
        "author = \"alice\"\n"
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
        "advisory = \"CVE-2021-23337\"\n"
        "purl = \"pkg:npm/lodash\"\n"
        "version_range = \"not a range\"\n"
        "state = \"in_triage\"\n"
        "author = \"alice\"\n"
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
        "finding = \"dsf1:" + "a" * 64 + "\"\n"
        "advisory = \"CVE-2021-23337\"\n"
        "purl = \"pkg:npm/lodash\"\n"
        "state = \"in_triage\"\n"
        "author = \"alice\"\n"
    )
    _write(tmp_path / "decisions.toml", text)
    with pytest.raises(DecisionsError) as excinfo:
        load_decisions(str(tmp_path / "decisions.toml"))
    assert "oneOf" in str(excinfo.value) or "valid" in str(excinfo.value)


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
        alias_ids={"cve-2021-23337", "ghsa-p6mc-m468-83gw"},
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
    assert not entry_matches_finding(entry, _finding(category="malware", rule="MAL-1"))


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
    assert not entry_matches_finding(
        entry, _finding(components=["pkg:npm/lodash@4.17.21"])
    )


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
        application = apply_triage([dict(f) for f in findings], _document([entry]).triage)
        assert (application.suppressed == 1) is expected, state
        # Nothing is deleted either way.
        assert len(application.proposals) == 0


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
    ids = read_baseline(
        BaselineSpec(scan="../../baseline/first"), base_dir=str(decisions_dir)
    )
    assert ids == {"dsf1:" + "a" * 64}


def test_read_baseline_checks_the_digest(tmp_path):
    path = tmp_path / FINDINGS_FILE
    raw = json.dumps({"schemaVersion": "2", "findings": [_finding()]})
    path.write_text(raw, encoding="utf-8")
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
        {"name": "enrichment", "status": "completed", "capabilities": ["reachability"], "projectType": "npm"},
        {"name": "risk", "status": "not-assessed", "capabilities": ["supply-chain"], "projectType": "npm"},
        {"name": "enrichment", "status": "completed", "capabilities": ["reachability"], "projectType": "pypi"},
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
        _graded_finding(id="dsf1:" + "b" * 64, baseline="existing", triage={"state": "not_affected"}),
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
    published = evaluation.to_document(
        evaluated_utc="2026-11-27T12:00:00+00:00", source="scan"
    )
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
    assert entry.id.startswith("cli-")


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
    assert "takes one of" in str(excinfo.value)
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
