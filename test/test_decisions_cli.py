"""End-to-end tests of the decisions options through ``depscan.cli.main``.

The exit codes (0, 2, 3, 4 and 4 winning over 3), the report
re-evaluation, the --fail-on grammar and the VEX input are driven the way a
user drives them: ``sys.argv`` is set, ``main`` runs, and the exit code and
the written files are asserted. The database and matching stages are stubbed
with the pattern of the scan directory tests, and every stub has a positive
control: the assertions read the files the run wrote.
"""

import json
import sys
from pathlib import Path

import pytest

from depscan import cli
from depscan.lib import doctor as doctor_mod
from depscan.lib import pipeline, scan_directory, vdb_setup
from xbom_lib import cdxgen as cdxgen_mod

VULN_REQUESTS = {
    "id": "CVE-2024-1111",
    "bom-ref": "CVE-2024-1111/pkg:pypi/requests@2.32.1",
    "affects": [{"ref": "pkg:pypi/requests@2.32.1"}],
    "ratings": [{"severity": "high", "score": 8.1, "method": "CVSSv31"}],
    "fixed_location": "2.32.2",
}

BOM_DOCUMENT = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "metadata": {"component": {"name": "app", "type": "application"}},
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

FULL_VDB_DATA = {
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


def run_main(monkeypatch, argv):
    """Run ``main`` with ``argv`` after the program name; the exit code."""
    monkeypatch.setattr(sys, "argv", ["depscan", *argv])
    with pytest.raises(SystemExit) as excinfo:
        cli.main()
    return excinfo.value.code


class _StubVdrResult:
    success = True
    prioritized_pkg_vuln_trees = {}
    exploitability = None

    def __init__(self, pkg_vulnerabilities):
        self.pkg_vulnerabilities = pkg_vulnerabilities


@pytest.fixture
def scan_stubs(monkeypatch):
    """Stub a bom-target scan's database and matching stages."""
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
    monkeypatch.setattr(cdxgen_mod, "find_cdxgen_cmd", lambda *a, **k: "cdxgen")
    monkeypatch.setattr(bom_mod_ref(), "_refuse_old_cdxgen", lambda logger=None: True)

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
    monkeypatch.setattr(doctor_mod, "_vdb_status", lambda: dict(FULL_VDB_DATA))
    return calls


def bom_mod_ref():
    from depscan.lib import bom

    return bom


def _write_bom(path, name="app"):
    bom = dict(BOM_DOCUMENT)
    bom["metadata"] = {"component": {"name": name, "type": "application"}}
    Path(path).write_text(json.dumps(bom))
    return str(path)


def _write(path, text):
    path.write_text(text, encoding="utf-8")
    return str(path)


FAIL_HIGH = "\n".join(
    [
        "[[expect]]",
        'id = "no-high"',
        'description = "No finding of severity high or above"',
        'severity = "high"',
        'action = "fail"',
    ]
)

REQUIRE_REACH = "\n".join(["[[require]]", 'capability = "reachability"'])


def _scan_argv(bom, reports, *extra):
    return ["scan", bom, "--reports-dir", str(reports), "--no-banner", *extra]


# --- exit codes from scan -------------------------------------------------------------


def test_exit_0_without_decisions(scan_stubs, tmp_path, monkeypatch):
    bom = _write_bom(tmp_path / "app.cdx.json")
    reports = tmp_path / "reports"
    assert run_main(monkeypatch, _scan_argv(bom, reports)) == 0
    assert not (reports / scan_directory.EXPECTATIONS_FILE).exists()


def test_exit_3_when_a_fail_expectation_matches(scan_stubs, tmp_path, monkeypatch):
    bom = _write_bom(tmp_path / "app.cdx.json")
    reports = tmp_path / "reports"
    decisions = _write(tmp_path / "decisions.toml", FAIL_HIGH)
    assert run_main(monkeypatch, _scan_argv(bom, reports, "--decisions", decisions)) == 3
    document = json.loads((reports / scan_directory.EXPECTATIONS_FILE).read_text())
    assert document["summary"]["fail"] == 1
    assert document["results"][0]["status"] == "fail"


def test_exit_4_when_a_requirement_was_not_assessed(scan_stubs, tmp_path, monkeypatch):
    bom = _write_bom(tmp_path / "app.cdx.json")
    reports = tmp_path / "reports"
    decisions = _write(tmp_path / "decisions.toml", REQUIRE_REACH)
    assert run_main(monkeypatch, _scan_argv(bom, reports, "--decisions", decisions)) == 4
    document = json.loads((reports / scan_directory.EXPECTATIONS_FILE).read_text())
    assert document["summary"]["requireNotAssessed"] == 1


def test_exit_4_wins_over_3(scan_stubs, tmp_path, monkeypatch):
    bom = _write_bom(tmp_path / "app.cdx.json")
    reports = tmp_path / "reports"
    decisions = _write(tmp_path / "decisions.toml", FAIL_HIGH + "\n\n" + REQUIRE_REACH)
    assert run_main(monkeypatch, _scan_argv(bom, reports, "--decisions", decisions)) == 4
    document = json.loads((reports / scan_directory.EXPECTATIONS_FILE).read_text())
    assert document["summary"]["fail"] == 1
    assert document["summary"]["requireNotAssessed"] == 1


def test_the_default_file_of_the_scanned_directory_applies(scan_stubs, tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    (project / ".depscan").mkdir()
    _write(project / ".depscan" / "decisions.toml", FAIL_HIGH)
    reports = tmp_path / "reports"
    assert run_main(monkeypatch, _scan_argv(str(project), reports)) == 3
    manifest = json.loads((reports / "depscan.manifest.json").read_text())
    assert manifest["decisions"]["selectedBy"] == "default"


def test_a_broken_decisions_file_is_a_usage_error(scan_stubs, tmp_path, monkeypatch):
    bom = _write_bom(tmp_path / "app.cdx.json")
    reports = tmp_path / "reports"
    decisions = _write(
        tmp_path / "decisions.toml",
        "[[triage]]\nfinding = \"dsf1:" + "a" * 64 + "\"\nstate = 3\n",
    )
    assert run_main(monkeypatch, _scan_argv(bom, reports, "--decisions", decisions)) == 2


def test_a_broken_fail_on_is_a_usage_error(scan_stubs, tmp_path, monkeypatch):
    bom = _write_bom(tmp_path / "app.cdx.json")
    reports = tmp_path / "reports"
    assert run_main(monkeypatch, _scan_argv(bom, reports, "--fail-on", "grade=extreme")) == 2


def test_a_baseline_with_a_wrong_digest_exits_1(scan_stubs, tmp_path, monkeypatch):
    bom = _write_bom(tmp_path / "app.cdx.json")
    reports = tmp_path / "reports"
    baseline_dir = tmp_path / "base"
    baseline_dir.mkdir()
    (baseline_dir / scan_directory.FINDINGS_FILE).write_text(
        json.dumps({"schemaVersion": "2", "findings": []}), encoding="utf-8"
    )
    decisions = _write(
        tmp_path / "decisions.toml",
        "\n".join(["[baseline]", 'scan = "base"', 'digest = "%s"' % ("0" * 64)]),
    )
    assert run_main(monkeypatch, _scan_argv(bom, reports, "--decisions", decisions)) == 1


def test_a_warn_action_keeps_exit_0(scan_stubs, tmp_path, monkeypatch):
    bom = _write_bom(tmp_path / "app.cdx.json")
    reports = tmp_path / "reports"
    decisions = _write(
        tmp_path / "decisions.toml",
        "\n".join(
            [
                "[[expect]]",
                'id = "warn-high"',
                'severity = "high"',
                'action = "warn"',
            ]
        ),
    )
    assert run_main(monkeypatch, _scan_argv(bom, reports, "--decisions", decisions)) == 0
    document = json.loads((reports / scan_directory.EXPECTATIONS_FILE).read_text())
    assert document["summary"]["warn"] == 1


def test_the_json_output_carries_the_expectations(scan_stubs, tmp_path, monkeypatch, capsys):
    bom = _write_bom(tmp_path / "app.cdx.json")
    reports = tmp_path / "reports"
    decisions = _write(tmp_path / "decisions.toml", FAIL_HIGH)
    code = run_main(
        monkeypatch,
        _scan_argv(bom, reports, "--decisions", decisions, "--format", "json"),
    )
    assert code == 3
    document = json.loads(capsys.readouterr().out)
    entry = document["scans"][0]
    assert entry["expectations"]["summary"]["fail"] == 1


# --- the --fail-on grammar -------------------------------------------------------------


def test_fail_on_gates_like_the_file(scan_stubs, tmp_path, monkeypatch):
    bom = _write_bom(tmp_path / "app.cdx.json")
    reports = tmp_path / "reports"
    assert run_main(
        monkeypatch, _scan_argv(bom, reports, "--fail-on", "severity=high,category=vulnerability")
    ) == 3
    document = json.loads((reports / scan_directory.EXPECTATIONS_FILE).read_text())
    assert document["results"][0]["id"].startswith("cli-")
    assert document["summary"]["fail"] == 1


def test_fail_on_and_the_file_agree(scan_stubs, tmp_path, monkeypatch):
    bom = _write_bom(tmp_path / "app.cdx.json")
    one = tmp_path / "one"
    two = tmp_path / "two"
    one.mkdir()
    two.mkdir()
    assert run_main(monkeypatch, _scan_argv(bom, one, "--fail-on", "severity=high")) == 3
    decisions = _write(two / "decisions.toml", FAIL_HIGH)
    assert run_main(monkeypatch, _scan_argv(bom, two, "--decisions", decisions)) == 3
    from_file = json.loads((two / scan_directory.EXPECTATIONS_FILE).read_text())
    assert from_file["summary"]["fail"] == 1


# --- report re-evaluation -------------------------------------------------------------


def test_report_reevaluates_after_a_decision_is_added(scan_stubs, tmp_path, monkeypatch):
    bom = _write_bom(tmp_path / "app.cdx.json")
    reports = tmp_path / "reports"
    assert run_main(monkeypatch, _scan_argv(bom, reports)) == 0
    # A decision is recorded after the scan; the re-evaluation takes effect
    # without rescanning and the gate fails on the saved findings.
    decisions = _write(tmp_path / "decisions.toml", FAIL_HIGH)
    assert run_main(monkeypatch, ["report", str(reports), "--decisions", decisions]) == 3
    # Nothing is written into the scan directory without --out.
    assert not (reports / scan_directory.EXPECTATIONS_FILE).exists()


def test_report_reads_the_recorded_decisions_file(scan_stubs, tmp_path, monkeypatch):
    project = tmp_path / "project"
    (project / ".depscan").mkdir(parents=True)
    _write(project / ".depscan" / "decisions.toml", FAIL_HIGH)
    reports = tmp_path / "reports"
    assert run_main(monkeypatch, _scan_argv(str(project), reports)) == 3
    # The gate passes now, because the decisions file suppresses nothing yet;
    # triage it and the recorded file makes the re-evaluation differ.
    _write(
        project / ".depscan" / "decisions.toml",
        "\n".join(
            [
                "[[triage]]",
                'advisory = "CVE-2024-1111"',
                'purl = "pkg:pypi/requests"',
                'state = "not_affected"',
                'justification = "code_not_reachable"',
                'author = "alice"',
                "",
                FAIL_HIGH,
            ]
        ),
    )
    assert run_main(monkeypatch, ["report", str(reports)]) == 0


def test_report_out_writes_the_evaluation(scan_stubs, tmp_path, monkeypatch):
    bom = _write_bom(tmp_path / "app.cdx.json")
    reports = tmp_path / "reports"
    decisions = _write(tmp_path / "decisions.toml", FAIL_HIGH)
    assert run_main(monkeypatch, _scan_argv(bom, reports, "--decisions", decisions)) == 3
    out = tmp_path / "gate.json"
    assert run_main(
        monkeypatch,
        ["report", str(reports), "--decisions", decisions, "--out", str(out)],
    ) == 3
    document = json.loads(out.read_text())
    assert document["source"] == "report"
    assert document["summary"]["fail"] == 1


def test_report_with_a_broken_decisions_file_is_a_usage_error(
    scan_stubs, tmp_path, monkeypatch
):
    bom = _write_bom(tmp_path / "app.cdx.json")
    reports = tmp_path / "reports"
    assert run_main(monkeypatch, _scan_argv(bom, reports)) == 0
    decisions = _write(
        tmp_path / "broken.toml",
        "[[triage]]\nfinding = \"dsf1:" + "a" * 64 + "\"\nstate = 3\n",
    )
    assert run_main(monkeypatch, ["report", str(reports), "--decisions", decisions]) == 2


# --- VEX input ------------------------------------------------------------------------

CYCLONEDX_VEX = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
    "metadata": {"component": {"name": "app", "type": "application"}},
    "components": [
        {
            "name": "requests",
            "version": "2.32.1",
            "purl": "pkg:pypi/requests@2.32.1",
            "bom-ref": "pkg:pypi/requests@2.32.1",
            "type": "library",
        }
    ],
    "vulnerabilities": [
        {
            "id": "CVE-2024-1111",
            "affects": [{"ref": "pkg:pypi/requests@2.32.1"}],
            "analysis": {
                "state": "not_affected",
                "justification": "code_not_reachable",
                "detail": "The client never calls the affected route",
            },
        }
    ],
}

OPENVEX_DOCUMENT = {
    "@context": "https://openvex.dev/ns/v0.2.0",
    "id": "https://example.com/vex/doc",
    "version": 1,
    "statements": [
        {
            "vulnerability": {"name": "CVE-2024-1111"},
            "products": [{"id": "pkg:pypi/requests@2.32.1"}],
            "status": "not_affected",
            "justification": "vulnerable_code_not_in_execute_path",
            "detail": "Not in the executed path",
        },
        {
            "vulnerability": {"name": "CVE-2024-2222"},
            "products": ["git+https://example.com/repo"],
            "status": "not_affected",
        },
    ],
}


def test_a_cyclonedx_vex_document_applies(scan_stubs, tmp_path, monkeypatch):
    bom = _write_bom(tmp_path / "app.cdx.json")
    reports = tmp_path / "reports"
    vex = _write(tmp_path / "vex.json", json.dumps(CYCLONEDX_VEX))
    assert run_main(monkeypatch, _scan_argv(bom, reports, "--vex", vex)) == 0
    findings = json.loads((reports / scan_directory.FINDINGS_FILE).read_text())["findings"]
    triaged = [f for f in findings if f.get("triage")]
    assert len(triaged) == 1
    assert triaged[0]["triage"]["state"] == "not_affected"
    assert triaged[0]["triage"]["justification"] == "code_not_reachable"
    assert triaged[0]["triage"]["proposed_by"].startswith("VEX document")
    document = json.loads((reports / scan_directory.EXPECTATIONS_FILE).read_text())
    assert document["summary"]["suppressed"] == 1


def test_an_openvex_document_applies_and_names_the_stale(scan_stubs, tmp_path, monkeypatch):
    bom = _write_bom(tmp_path / "app.cdx.json")
    reports = tmp_path / "reports"
    vex = _write(tmp_path / "vex.json", json.dumps(OPENVEX_DOCUMENT))
    assert run_main(monkeypatch, _scan_argv(bom, reports, "--vex", vex)) == 0
    findings = json.loads((reports / scan_directory.FINDINGS_FILE).read_text())["findings"]
    triaged = [f for f in findings if f.get("triage")]
    assert len(triaged) == 1
    assert triaged[0]["triage"]["state"] == "not_affected"
    assert triaged[0]["triage"]["justification"] == "code_not_reachable"
    # The statement that names no package URL is stale, never dropped.
    document = json.loads((reports / scan_directory.EXPECTATIONS_FILE).read_text())
    assert document["summary"]["suppressed"] == 1
    assert len(document["triage"]["stale"]) == 1


def test_a_vex_document_that_is_neither_format_is_a_usage_error(
    scan_stubs, tmp_path, monkeypatch
):
    bom = _write_bom(tmp_path / "app.cdx.json")
    reports = tmp_path / "reports"
    vex = _write(tmp_path / "vex.json", json.dumps({"hello": "world"}))
    assert run_main(monkeypatch, _scan_argv(bom, reports, "--vex", vex)) == 2
