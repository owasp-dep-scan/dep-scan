"""End-to-end tests of the decisions pipeline stages through ``depscan.api``.

Every scan runs the real pipeline with the database and matching stages
stubbed (the pattern of the scan directory tests), so the decisions stage,
the VDR annotation and the gate evaluation run against the output a real
scan writes. Each stub has a positive control: the assertions read the files
the scan wrote.
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from analysis_lib.findings.decisions import (
    BaselineSpec,
    Decisions,
    EXPECTATIONS_FILE,
)
from analysis_lib.findings.schemas import validate
from depscan import api
from depscan.lib import doctor as doctor_mod
from depscan.lib import pipeline, scan_directory, vdb_setup

VULN_REQUESTS = {
    "id": "CVE-2024-1111",
    "bom-ref": "CVE-2024-1111/pkg:pypi/requests@2.32.1",
    "affects": [{"ref": "pkg:pypi/requests@2.32.1"}],
    "ratings": [{"severity": "high", "score": 8.1, "method": "CVSSv31"}],
    "fixed_location": "2.32.2",
}


def _write_bom(path, name="app"):
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {"component": {"name": name, "type": "application"}},
        "components": [
            {
                "name": "requests",
                "version": "2.32.1",
                "purl": "pkg:pypi/requests@2.32.1",
                "bom-ref": "pkg:pypi/requests@2.32.1",
                "type": "library",
            }
        ],
    }
    path.write_text(json.dumps(bom))
    return str(path)


class _StubVdrResult:
    success = True
    prioritized_pkg_vuln_trees = {}
    exploitability = None

    def __init__(self, pkg_vulnerabilities):
        self.pkg_vulnerabilities = pkg_vulnerabilities


@pytest.fixture
def scan_stubs(monkeypatch):
    """Stub the database and matching stages of a scan.

    The stub returns one vulnerability, CVE-2024-1111 on requests 2.32.1,
    and runs the real exploitability grading step, so the findings the
    decisions stage builds carry grades a gate can select on.
    """
    calls = {"matching": [], "database": []}
    monkeypatch.setattr(
        vdb_setup, "resolve_scan_vdb_image", lambda args: ("oras://vdb", False, "app-only")
    )
    monkeypatch.setattr(vdb_setup, "vdb_download_needed", lambda url, d: (False, ""))
    monkeypatch.setattr(vdb_setup, "configure_vdb_readonly", lambda: None)
    monkeypatch.setattr(vdb_setup, "ensure_vdb_usable", lambda: calls["database"].append(1))
    monkeypatch.setattr(pipeline, "get_pkgs_by_scope", lambda pkg_list: {})
    monkeypatch.setattr(
        pipeline,
        "get_pkg_list",
        lambda f: ([{"purl": "pkg:pypi/requests@2.32.1", "name": "requests"}], []),
    )
    monkeypatch.setattr(pipeline.ReportGenerator, "parse_and_generate_report", lambda self: None)
    monkeypatch.setattr(pipeline.console, "save_html", lambda *a, **k: None)
    monkeypatch.setattr(pipeline.console, "save_text", lambda *a, **k: None)

    class StubVDRAnalyzer:
        def __init__(self, vdr_options):
            calls["matching"].append(vdr_options)
            self.vdr_options = vdr_options

        def process(self):
            from analysis_lib.findings.exploitability import annotate_exploitability

            vulns = [dict(VULN_REQUESTS)]
            result = _StubVdrResult(vulns)
            result.exploitability = annotate_exploitability(
                vulns, self.vdr_options.exploitability_inputs
            )
            return result

    monkeypatch.setattr(pipeline, "VDRAnalyzer", StubVDRAnalyzer)
    monkeypatch.setattr(doctor_mod, "_vdb_status", lambda: dict(_FULL_VDB_DATA))
    return calls


_FULL_VDB_DATA = {
    "present": True,
    "directory": "/tmp/vdb",
    "image": "ghcr.io/appthreat/vdb7-app-only:v7.0.x-xz",
    "flavor": "app-only",
    "shards": {"enabled": False, "present": []},
    "createdUtc": "2026-11-01T00:00:00+00:00",
    "ageHours": 10.0,
    "stale": False,
    "maxAgeHours": 48,
    "cveDataCount": 100,
    "cveIndexCount": 100,
    "extendedMetadataPresent": False,
    "cveMetadataRows": 0,
}


def _scan(tmp_path, *, decisions=None, cli_expects=None, baseline=None):
    bom = _write_bom(tmp_path / "app.cdx.json")
    reports = tmp_path / "reports"
    options = api.scan_options(bom=bom, reports_dir=str(reports), no_banner=True)
    return api.scan(
        options,
        render=False,
        decisions=decisions,
        cli_expects=cli_expects,
        baseline_override=baseline,
        decisions_base_dir=str(tmp_path),
    )


def _read(reports, name):
    return json.loads((Path(reports) / name).read_text(encoding="utf-8"))


def _read_vdr(result):
    """The VDR document the scan wrote; a --bom scan names it after the BOM."""
    vdr_file = next(t.vdr_file for t in result.types if t.vdr_file)
    return json.loads(Path(vdr_file).read_text(encoding="utf-8"))


def _decisions(tmp_path, document, name="decisions.toml"):
    import tomllib

    from analysis_lib.findings.decisions import decisions_from_document, load_decisions

    path = tmp_path / name
    path.write_text(document, encoding="utf-8")
    return load_decisions(str(path))


# --- triage application ---------------------------------------------------------------


def test_a_live_decision_triages_the_finding_and_the_vdr(scan_stubs, tmp_path):
    decisions = _decisions(
        tmp_path,
        "\n".join(
            [
                "[[triage]]",
                'advisory = "CVE-2024-1111"',
                'purl = "pkg:pypi/requests"',
                'state = "not_affected"',
                'justification = "code_not_reachable"',
                'detail = "The client never calls the affected route"',
                'author = "alice"',
                'expires = "2099-01-01T00:00:00Z"',
            ]
        ),
    )
    result = _scan(tmp_path, decisions=decisions)
    manifest = result.manifest
    assert manifest is not None
    triaged = [f for f in result.findings if f.get("triage")]
    assert len(triaged) == 1
    triage = triaged[0]["triage"]
    assert triage["state"] == "not_affected"
    assert triage["justification"] == "code_not_reachable"
    assert triage["author"] == "alice"
    # The VDR carries the decision in its analysis object.
    vdr = _read_vdr(result)
    analysis = vdr["vulnerabilities"][0]["analysis"]
    assert analysis["state"] == "not_affected"
    assert analysis["justification"] == "code_not_reachable"
    properties = {prop["name"]: prop["value"] for prop in vdr["vulnerabilities"][0]["properties"]}
    assert properties["depscan:triage:author"] == "alice"
    # The manifest records the decisions file with its digest.
    assert manifest["decisions"]["sha256"] == decisions.digest
    assert manifest["decisions"]["selectedBy"] == "default"
    stage = next(s for s in manifest["stages"] if s["name"] == "decisions")
    assert stage["status"] == "completed"


def test_a_suppressed_finding_stays_in_the_findings_file(scan_stubs, tmp_path):
    decisions = _decisions(
        tmp_path,
        "\n".join(
            [
                "[[triage]]",
                'finding = "%s"' % _fingerprint_of_vuln(),
                'state = "false_positive"',
                'author = "alice"',
            ]
        ),
    )
    result = _scan(tmp_path, decisions=decisions)
    assert len(result.findings) == 1
    assert result.findings[0]["triage"]["state"] == "false_positive"


def _fingerprint_of_vuln():
    from analysis_lib.findings.fingerprint import finding_fingerprint

    return finding_fingerprint("vulnerability", "CVE-2024-1111", ["pkg:pypi/requests@2.32.1"])


def test_a_proposal_changes_nothing(scan_stubs, tmp_path):
    decisions = _decisions(
        tmp_path,
        "\n".join(
            [
                "[[triage]]",
                'advisory = "CVE-2024-1111"',
                'purl = "pkg:pypi/requests"',
                'state = "not_affected"',
                'justification = "code_not_reachable"',
                'proposed_by = "triage-agent session 8123"',
            ]
        ),
    )
    result = _scan(tmp_path, decisions=decisions)
    assert all(not f.get("triage") for f in result.findings)
    vdr = _read_vdr(result)
    assert not vdr["vulnerabilities"][0].get("analysis")


def test_an_expired_entry_is_reported_in_the_gate(scan_stubs, tmp_path):
    yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    decisions = _decisions(
        tmp_path,
        "\n".join(
            [
                "[[triage]]",
                'advisory = "CVE-2024-1111"',
                'purl = "pkg:pypi/requests"',
                'state = "not_affected"',
                'justification = "code_not_reachable"',
                'author = "alice"',
                f'expires = "{yesterday}"',
            ]
        ),
    )
    result = _scan(tmp_path, decisions=decisions)
    assert all(not f.get("triage") for f in result.findings)


def test_a_stale_entry_is_reported_in_the_gate(scan_stubs, tmp_path):
    decisions = _decisions(
        tmp_path,
        "\n".join(
            [
                "[[triage]]",
                'finding = "dsf1:%s"' % ("c" * 64),
                'state = "in_triage"',
                'author = "alice"',
            ]
        ),
    )
    result = _scan(tmp_path, decisions=decisions)
    assert result.expectations is not None
    assert len(result.expectations["triage"]["stale"]) == 1
    assert result.expectations["triage"]["stale"][0]["selector"]["finding"] == "dsf1:" + "c" * 64


# --- the gate -------------------------------------------------------------------------


def test_the_gate_fails_on_a_matching_expectation(scan_stubs, tmp_path):
    decisions = _decisions(
        tmp_path,
        "\n".join(
            [
                "[[expect]]",
                'id = "no-high"',
                'description = "No finding of severity high or above"',
                'severity = "high"',
                'action = "fail"',
            ]
        ),
    )
    result = _scan(tmp_path, decisions=decisions)
    document = result.expectations
    assert document is not None
    validate("depscan-expectations", document)
    assert document["schemaVersion"] == "1"
    assert document["summary"]["fail"] == 1
    assert document["results"][0]["id"] == "no-high"
    assert document["results"][0]["status"] == "fail"
    assert len(document["results"][0]["findings"]) == 1
    assert document["results"][0]["evidence"] == ["depscan.findings.json"]
    written = _read(result.reports_dir, EXPECTATIONS_FILE)
    assert written == document
    manifest = result.manifest
    assert manifest is not None
    stage = next(s for s in manifest["stages"] if s["name"] == "expectations")
    assert stage["status"] == "completed"
    assert stage["outputs"][0]["file"] == "depscan.expectations.json"


def test_the_gate_reads_the_grades_the_scan_graded(scan_stubs, tmp_path):
    """The grade floor selects on the grade the findings carry, whatever the
    stub's evidence graded it to."""
    first = _scan(tmp_path)
    graded = [f for f in first.findings if f.get("exploitability")]
    assert graded, "the positive control: the stub graded the finding"
    grade = graded[0]["exploitability"]["grade"]
    floor = grade
    gate_dir = tmp_path / "gate"
    gate_dir.mkdir()
    decisions = _decisions(
        gate_dir,
        "\n".join(
            [
                "[[expect]]",
                'id = "grade-floor"',
                f'grade = "{floor}"',
                'action = "fail"',
            ]
        ),
        name="gate.toml",
    )
    result = _scan(gate_dir, decisions=decisions)
    document = result.expectations
    assert document is not None
    assert document["summary"]["fail"] == 1


def test_a_require_that_was_not_assessed_exits_four(scan_stubs, tmp_path):
    decisions = _decisions(
        tmp_path,
        "\n".join(["[[require]]", 'capability = "reachability"']),
    )
    result = _scan(tmp_path, decisions=decisions)
    document = result.expectations
    assert document is not None
    assert document["summary"]["requireNotAssessed"] == 1
    assert document["results"][0]["status"] == "fail"
    assert "not assessed" in document["results"][0]["reason"]


def test_the_gate_runs_from_the_command_line_without_a_file(scan_stubs, tmp_path):
    from analysis_lib.findings.decisions import parse_fail_on

    result = _scan(tmp_path, cli_expects=[parse_fail_on("severity=high")])
    document = result.expectations
    assert document is not None
    validate("depscan-expectations", document)
    assert document["decisions"] is None
    assert document["summary"]["fail"] == 1
    assert document["results"][0]["id"].startswith("cli-")
    assert document["results"][0]["description"].startswith("the --fail-on expression")


def test_a_scan_without_decisions_writes_no_expectations(scan_stubs, tmp_path):
    result = _scan(tmp_path)
    assert result.expectations is None
    assert not (Path(result.reports_dir) / EXPECTATIONS_FILE).exists()
    manifest = result.manifest
    assert manifest is not None
    assert not [s for s in manifest["stages"] if s["name"] in ("decisions", "expectations")]
    assert manifest.get("decisions") is None


# --- the baseline ---------------------------------------------------------------------


def test_the_baseline_marks_new_and_existing(scan_stubs, tmp_path):
    first = _scan(tmp_path)
    # A first scan with no findings of its own would mark nothing; build the
    # baseline from this scan's findings document instead, then rescan into
    # a second directory with an extra finding the baseline cannot hold.
    reports = Path(first.reports_dir)
    findings_document = _read(reports, scan_directory.FINDINGS_FILE)
    assert findings_document["findings"], "the positive control: the stub found one"
    second = tmp_path / "second"
    second.mkdir()
    decisions = _decisions(
        second,
        "[baseline]\nscan = %r\n" % str(first.reports_dir),
        name="decisions.toml",
    )
    result = _scan(second, decisions=decisions)
    states = {f["baseline"] for f in result.findings}
    assert states == {"existing"}
    document = result.expectations
    assert document is not None
    assert document["baseline"]["findings"] == 1
    assert document["summary"]["existing"] == 1
    assert document["summary"]["new"] == 0


def test_a_baseline_with_a_wrong_digest_stops_the_scan(scan_stubs, tmp_path):
    baseline_dir = tmp_path / "base"
    baseline_dir.mkdir()
    (baseline_dir / scan_directory.FINDINGS_FILE).write_text(
        json.dumps({"schemaVersion": "2", "findings": []}), encoding="utf-8"
    )
    decisions = _decisions(
        tmp_path,
        "\n".join(
            [
                "[baseline]",
                'scan = "base"',
                'digest = "%s"' % ("0" * 64),
            ]
        ),
    )
    bom = _write_bom(tmp_path / "app.cdx.json")
    options = api.scan_options(bom=bom, reports_dir=str(tmp_path / "reports"), no_banner=True)
    with pytest.raises(api.ScanError) as excinfo:
        api.scan(options, render=False, decisions=decisions, decisions_base_dir=str(tmp_path))
    assert "digest" in str(excinfo.value)
    manifest = json.loads(
        (tmp_path / "reports" / "depscan.manifest.json").read_text(encoding="utf-8")
    )
    stage = next(s for s in manifest["stages"] if s["name"] == "decisions")
    assert stage["status"] == "failed"
    assert "digest" in stage["reason"]


def test_an_unreadable_baseline_stops_the_scan(scan_stubs, tmp_path):
    decisions = Decisions(baseline=BaselineSpec(scan=str(tmp_path / "absent-scan")))
    bom = _write_bom(tmp_path / "app.cdx.json")
    options = api.scan_options(bom=bom, reports_dir=str(tmp_path / "reports"), no_banner=True)
    with pytest.raises(api.ScanError) as excinfo:
        api.scan(options, render=False, decisions=decisions)
    assert "cannot be read" in str(excinfo.value)


def test_the_baseline_override_replaces_the_file(scan_stubs, tmp_path):
    first = _scan(tmp_path)
    reports = Path(first.reports_dir)
    assert _read(reports, scan_directory.FINDINGS_FILE)["findings"]
    second = tmp_path / "second"
    second.mkdir()
    # A file whose own baseline points elsewhere is overridden for one run.
    decisions = _decisions(
        second,
        "\n".join(["[baseline]", 'scan = "also-absent"']),
    )
    result = _scan(
        second,
        decisions=decisions,
        baseline=BaselineSpec(scan=str(first.reports_dir)),
    )
    assert {f["baseline"] for f in result.findings} == {"existing"}


# --- VEX input and expectations plumbing live with the verbs; these two keep
# --- the pipeline contract for the alias map.


def test_the_alias_map_folds_the_vdr_aliases(scan_stubs, tmp_path):
    decisions = _decisions(
        tmp_path,
        "\n".join(
            [
                "[[triage]]",
                'advisory = "GHSA-test-test-test-test"',
                'purl = "pkg:pypi/requests"',
                'state = "in_triage"',
                'author = "alice"',
            ]
        ),
    )
    # The stub's VDR entry names no GHSA alias, so this entry is stale.
    result = _scan(tmp_path, decisions=decisions)
    document = result.expectations
    assert document is not None
    assert len(document["triage"]["stale"]) == 1
