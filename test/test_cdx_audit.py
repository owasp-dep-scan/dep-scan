"""Tests for the cdx-audit runner and its wiring into the scan.

The end-to-end tests that run a real cdx-audit need one installed that
carries the options dep-scan passes (``--private-namespace``, ``--offline``,
``--time-budget-minutes``); they are skipped, with the reason, when
``CDX_AUDIT_CMD`` does not point at one.
"""

import json
import os
import socket
import stat
from pathlib import Path

import pytest

from depscan.lib import cdx_audit

TESTS_DIR = Path(__file__).parent
DATA_DIR = TESTS_DIR / "data"


@pytest.fixture()
def fake_cdx_audit(tmp_path, monkeypatch):
    """A fake cdx-audit executable that records its arguments and writes a
    fixed report to --report-file. Its --version names a version the tests
    choose, so the minimum check is exercised against real parse output."""
    calls = {}

    script = tmp_path / "cdx-audit-fake"
    body = f"""#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "CycloneDX Generator {calls.get('version', '13.10.0')}"
  exit 0
fi
report=""
prev=""
for arg in "$@"; do
  if [ "$prev" = "--report-file" ]; then report="$arg"; fi
  prev="$arg"
done
printf '%s' "$FAKE_REPORT" > "$report"
exit "${{FAKE_EXIT:-0}}"
"""
    script.write_text(body)
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return script, calls


def test_find_prefers_the_env_command(monkeypatch):
    monkeypatch.setenv("CDX_AUDIT_CMD", "/opt/tools/cdx-audit")
    assert cdx_audit.find_cdx_audit_cmd() == "/opt/tools/cdx-audit"


def test_version_check_against_the_minimum(monkeypatch):
    # The documented default, whatever the run's environment overrode it to
    # for the tests that run the real worktree build.
    monkeypatch.setattr(cdx_audit, "CDX_AUDIT_MIN_VERSION", "13.10.0")
    assert cdx_audit.check_cdx_audit_version("13.10.0")
    assert cdx_audit.check_cdx_audit_version("14.0.1")
    assert not cdx_audit.check_cdx_audit_version("13.9.0")
    assert not cdx_audit.check_cdx_audit_version("13.9")
    assert not cdx_audit.check_cdx_audit_version(None)
    assert not cdx_audit.check_cdx_audit_version("")


def test_run_reads_the_report_and_the_markers(tmp_path, fake_cdx_audit):
    script, calls = fake_cdx_audit
    report = {
        "version": 1,
        "auditMode": "direct",
        "results": [{"findings": [{"ruleId": "INT-001"}]}],
        "summary": {
            "totalFindings": 1,
            "skippedTargets": 2,
            "erroredTargets": 1,
            "targetCapTruncated": 4,
            "offline": True,
            "timeBudgetExhausted": True,
        },
        "skipped": [{"reason": "unsupported-ecosystem"}],
    }
    os.environ["FAKE_REPORT"] = json.dumps(report)
    try:
        report_file = tmp_path / "audit.json"
        result = cdx_audit.run_cdx_audit(str(script), ["--bom", "bom.json", "--report-file", str(report_file)])
    finally:
        os.environ.pop("FAKE_REPORT", None)
    assert result.report_version == 1
    assert result.findings_count == 1
    assert result.skipped_count == 2
    assert result.errored_count == 1
    assert result.truncated_count == 4
    assert result.offline is True
    assert result.time_budget_exhausted is True
    assert len(result.results) == 1
    assert len(result.skipped_entries) == 1


def test_run_names_a_run_without_a_report(tmp_path, fake_cdx_audit):
    script, calls = fake_cdx_audit
    script.write_text("#!/bin/sh\nexit 1\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    with pytest.raises(cdx_audit.CdxAuditError, match="wrote no report"):
        cdx_audit.run_cdx_audit(str(script), ["--bom", "bom.json", "--report-file", str(tmp_path / "none.json")])


def test_build_args_direct_audit():
    args = cdx_audit.build_audit_args(
        "sbom.cdx.json",
        "audit.json",
        direct=True,
        categories=["package-integrity"],
        private_ns="@acme,acme-",
        offline=True,
    )
    assert args[:4] == ["--bom", "sbom.cdx.json", "--report", "json"]
    assert "--direct-bom-audit" in args
    assert args[args.index("--categories") + 1] == "package-integrity"
    assert args[args.index("--private-namespace") + 1] == "@acme,acme-"
    assert "--offline" in args
    assert "--scope" not in args


def test_build_args_predictive_bounds():
    args = cdx_audit.build_audit_args(
        "sbom.cdx.json",
        "audit.json",
        direct=False,
        predictive=True,
        scope_required=True,
        max_targets=10,
        time_budget_minutes=15,
    )
    assert "--direct-bom-audit" not in args
    assert args[args.index("--scope") + 1] == "required"
    assert args[args.index("--max-targets") + 1] == "10"
    assert args[args.index("--time-budget-minutes") + 1] == "15"


def test_run_exit_3_is_a_result_not_a_failure(tmp_path, fake_cdx_audit):
    """cdx-audit exits 3 when a finding met the fail severity; the runner
    reports it as an exit code on the result, never an exception."""
    script, calls = fake_cdx_audit
    report = {"version": 1, "auditMode": "direct", "results": [], "summary": {"totalFindings": 1}}
    os.environ["FAKE_REPORT"] = json.dumps(report)
    os.environ["FAKE_EXIT"] = "3"
    try:
        result = cdx_audit.run_cdx_audit(
            str(script), ["--bom", "bom.json", "--report-file", str(tmp_path / "audit.json")]
        )
    finally:
        os.environ.pop("FAKE_REPORT", None)
        os.environ.pop("FAKE_EXIT", None)
    assert result.exit_code == 3
    assert result.report["version"] == 1


def _block_network(monkeypatch):
    """Every socket construction raises, so a registry, git or OCI request
    fails the test instead of quietly succeeding."""
    def no_socket(*args, **kwargs):
        raise AssertionError("a scan in offline mode made a network request")

    monkeypatch.setattr(socket, "socket", no_socket)
    monkeypatch.setattr(socket, "create_connection", no_socket)
    if hasattr(socket, "socketpair"):
        monkeypatch.setattr(socket, "socketpair", no_socket)


@pytest.mark.skipif(
    not os.environ.get("CDX_AUDIT_CMD"),
    reason="needs a cdx-audit that carries --offline and --private-namespace; set CDX_AUDIT_CMD",
)
def test_offline_direct_audit_makes_no_network_request(tmp_path, monkeypatch):
    """The real cdx-audit, offline, over a BOM whose component carries
    registry metadata: no socket is ever built, and the report still lands."""
    _block_network(monkeypatch)
    cmd = cdx_audit.find_cdx_audit_cmd()
    assert cmd, "CDX_AUDIT_CMD is set, so the finder resolves it"
    bom_file = tmp_path / "sbom.cdx.json"
    bom_file.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "version": 1,
                "components": [
                    {
                        "type": "library",
                        "bom-ref": "pkg:npm/express@4.21.2",
                        "name": "express",
                        "version": "4.21.2",
                        "purl": "pkg:npm/express@4.21.2",
                    }
                ],
            }
        )
    )
    report_file = tmp_path / "audit.json"
    args = cdx_audit.build_audit_args(
        str(bom_file), str(report_file), direct=True, offline=True
    )
    result = cdx_audit.run_cdx_audit(cmd, args)
    assert result.report_version == 1
    assert result.offline is True


@pytest.mark.skipif(
    not os.environ.get("CDX_AUDIT_CMD"),
    reason="needs a cdx-audit that carries --offline and --private-namespace; set CDX_AUDIT_CMD",
)
def test_private_namespace_produces_a_dependency_confusion_finding(tmp_path):
    """End to end through the real cdx-audit: a component whose scoped name
    starts with the private prefix becomes a supply-chain finding with the
    INT-017 rule id, and the evidence store holds its record."""
    from analysis_lib.evidence.adapters.cdx_audit import extract as cdx_audit_extract
    from analysis_lib.findings.cdx_audit_convert import findings_from_cdx_audit_records

    cmd = cdx_audit.find_cdx_audit_cmd()
    assert cmd, "CDX_AUDIT_CMD is set, so the finder resolves it"
    bom_file = tmp_path / "sbom.cdx.json"
    bom_file.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "version": 1,
                "components": [
                    {
                        "type": "library",
                        "bom-ref": "pkg:npm/@mycorp/secret@1.0.0",
                        "name": "secret",
                        "group": "@mycorp",
                        "version": "1.0.0",
                        "purl": "pkg:npm/%40mycorp/secret@1.0.0",
                    },
                    {
                        "type": "library",
                        "bom-ref": "pkg:npm/express@4.21.2",
                        "name": "express",
                        "version": "4.21.2",
                        "purl": "pkg:npm/express@4.21.2",
                    },
                ],
            }
        )
    )
    report_file = tmp_path / "audit.json"
    args = cdx_audit.build_audit_args(
        str(bom_file),
        str(report_file),
        direct=True,
        offline=True,
        private_ns="mycorp",
    )
    result = cdx_audit.run_cdx_audit(cmd, args)
    adapter_result = cdx_audit_extract(
        result.report,
        source="audit.json",
        producer_version="13.10.0",
        source_root=str(tmp_path),
        mode="direct",
    )
    findings = findings_from_cdx_audit_records(adapter_result.records)
    confusion = [f for f in findings if f.rule == "INT-017"]
    assert confusion, "the private namespace must produce a dependency-confusion finding"
    assert confusion[0].category == "supply-chain"
    assert "pkg:npm/%40mycorp/secret@1.0.0" in (confusion[0].components or [])
    assert not any(
        "pkg:npm/express@4.21.2" in (f.components or []) for f in confusion
    ), "a public package must stay unflagged"


def test_doctor_reports_the_audit_tool(tmp_path, monkeypatch):
    """The doctor's cdx-audit entry carries the version the fake names, and
    a too-old one is unusable with the reason a scan refuses on."""
    from depscan.lib import doctor as doctor_lib

    script = tmp_path / "cdx-audit-old"
    script.write_text("#!/bin/sh\necho 'CycloneDX Generator 13.0.0'\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("CDX_AUDIT_CMD", str(script))
    monkeypatch.delenv("DEPSCAN_CDX_AUDIT_MIN_VERSION", raising=False)
    status = doctor_lib._cdx_audit_status()
    assert status.version == "13.0.0"
    assert not status.usable
    assert "minimum" in (status.reason or "")
