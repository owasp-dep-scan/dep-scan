"""Tests for the cdx-audit runner and its wiring into the scan.

The end-to-end tests that run a real cdx-audit need one that carries the
options dep-scan passes (``--private-namespace``, ``--offline``,
``--time-budget-minutes``); they are skipped, with the reason, when none is
found or the one found is older than the minimum. The offline tests load a
Node module into cdx-audit that records and refuses any network access.
"""

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from depscan.lib import cdx_audit

TESTS_DIR = Path(__file__).parent
DATA_DIR = TESTS_DIR / "data"


#: The body of a fake cdx-audit: prints the version line, writes the
#: report the environment names to the --report-file argument and exits
#: with the environment's exit code. The same body runs behind a POSIX
#: shebang script and behind a Windows batch shim, so the runner tests
#: exercise the real argv handling on both.
FAKE_AUDIT_BODY = """import os
import sys

args = sys.argv[1:]
if args and args[0] == "--version":
    print("CycloneDX Generator " + os.environ.get("FAKE_VERSION", "13.9.0"))
    sys.exit(0)
report = ""
for index, arg in enumerate(args):
    if arg == "--report-file" and index + 1 < len(args):
        report = args[index + 1]
if report:
    with open(report, "w", encoding="utf-8") as handle:
        handle.write(os.environ.get("FAKE_REPORT", ""))
sys.exit(int(os.environ.get("FAKE_EXIT", "0")))
"""


def _write_fake_audit(directory, name="cdx-audit-fake", version=None):
    """The fake cdx-audit command for this platform, as a path."""
    body = directory / f"{name}-body.py"
    text = FAKE_AUDIT_BODY
    if version:
        # A fixed version line, for the tests that probe --version.
        text = text.replace(
            'os.environ.get("FAKE_VERSION", "13.9.0")', repr(version)
        )
    body.write_text(text, encoding="utf-8")
    if sys.platform == "win32":
        script = directory / f"{name}.cmd"
        script.write_text(
            "@echo off\n" + f'python "{body}" %*\n' + "exit /b %ERRORLEVEL%\n",
            encoding="utf-8",
        )
    else:
        script = directory / name
        script.write_text("#!/usr/bin/env python3\n" + text, encoding="utf-8")
        script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return script


@pytest.fixture()
def fake_cdx_audit(tmp_path, monkeypatch):
    """A fake cdx-audit executable that records its arguments and writes a
    fixed report to --report-file. Its --version names a version the tests
    choose, so the minimum check is exercised against real parse output."""
    calls = {}

    script = _write_fake_audit(tmp_path, version="13.9.0")
    return script, calls


def test_find_prefers_the_env_command(tmp_path, monkeypatch):
    script = _write_fake_audit(tmp_path)
    monkeypatch.setenv("CDX_AUDIT_CMD", str(script))
    assert cdx_audit.find_cdx_audit_cmd() == str(script)
    location = cdx_audit.locate_cdx_audit()
    assert location.source == "env"


def test_a_missing_env_command_is_not_found_by_the_scan_and_the_doctor(tmp_path, monkeypatch):
    """CDX_AUDIT_CMD naming nothing is reported as not found, with the value
    it named, by the scan's finder and the doctor alike; neither falls
    through to another install the user did not ask for."""
    from depscan.lib import doctor as doctor_lib

    missing = tmp_path / "no-such-cdx-audit"
    monkeypatch.setenv("CDX_AUDIT_CMD", str(missing))
    assert cdx_audit.find_cdx_audit_cmd() is None
    reason = cdx_audit.locate_cdx_audit().reason or ""
    assert "cdx-audit was not found" in reason
    assert str(missing) in reason
    status = doctor_lib._cdx_audit_status()
    assert status.path is None
    assert status.reason == reason


def test_discovery_uses_the_platform_safe_lookup(monkeypatch):
    """PATH is searched with xbom_lib's find_executable, which never looks in
    the current directory on Windows, not with shutil.which."""
    monkeypatch.delenv("CDX_AUDIT_CMD", raising=False)
    asked = []

    def fake_find(name):
        asked.append(name)
        return "/usr/local/bin/cdx-audit" if name == "cdx-audit" else None

    monkeypatch.setattr(cdx_audit, "find_executable", fake_find)
    assert cdx_audit.find_cdx_audit_cmd() == "/usr/local/bin/cdx-audit"
    assert asked == ["cdx-audit"]


def test_both_runs_get_the_tool_environment(tmp_path, monkeypatch):
    """The version probe and the run pass tool_env(), which on Windows keeps
    cmd.exe from running a command planted in the scanned project."""
    seen = []
    real_run = cdx_audit.subprocess.run

    def spy(*args, **kwargs):
        seen.append(kwargs.get("env"))
        return real_run(*args, **kwargs)

    monkeypatch.setattr(cdx_audit, "tool_env", lambda: {**os.environ, "DEPSCAN_TOOL_ENV": "1"})
    monkeypatch.setattr(cdx_audit.subprocess, "run", spy)
    script = _write_fake_audit(tmp_path)
    cdx_audit.cdx_audit_version(str(script))
    monkeypatch.setenv("FAKE_REPORT", json.dumps({"version": 1, "results": []}))
    cdx_audit.run_cdx_audit(str(script), ["--bom", "b.json", "--report-file", str(tmp_path / "r.json")])
    assert len(seen) == 2
    assert all(env and env.get("DEPSCAN_TOOL_ENV") == "1" for env in seen)


def test_an_unsafe_command_is_a_failed_probe_not_a_crash(monkeypatch):
    """build_command refuses a Windows batch file it cannot pass arguments to
    safely with UnsafeCommandError, a SubprocessError; the version probe
    reads that as an unreadable version."""
    from xbom_lib.process import UnsafeCommandError

    def refuse(argv):
        raise UnsafeCommandError("Refusing to pass an argument containing '&' to a batch file")

    monkeypatch.setattr(cdx_audit, "build_command", refuse)
    assert cdx_audit.cdx_audit_version("C:/tools/cdx-audit.cmd") is None


def test_version_check_against_the_minimum(monkeypatch):
    # The documented default, whatever the run's environment overrode it to
    # for the tests that run the real worktree build.
    monkeypatch.setattr(cdx_audit, "CDX_AUDIT_MIN_VERSION", "13.9.0")
    assert cdx_audit.check_cdx_audit_version("13.9.0")
    assert cdx_audit.check_cdx_audit_version("14.0.1")
    assert not cdx_audit.check_cdx_audit_version("13.8.0")
    assert not cdx_audit.check_cdx_audit_version("13.8")
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


def test_run_names_a_run_without_a_report(tmp_path, fake_cdx_audit, monkeypatch):
    script, calls = fake_cdx_audit
    # A run that exits 0 and writes nothing.
    monkeypatch.setattr(cdx_audit, "build_command", lambda argv: [sys.executable, "-c", "pass"])
    with pytest.raises(cdx_audit.CdxAuditError, match="wrote no report"):
        cdx_audit.run_cdx_audit(
            str(script), ["--bom", "bom.json", "--report-file", str(tmp_path / "none.json")]
        )


def test_a_stale_report_is_never_read_as_this_runs(tmp_path, fake_cdx_audit, monkeypatch):
    """A crashed run next to the report an earlier scan left is a failure
    with the run's output, never the earlier findings."""
    script, calls = fake_cdx_audit
    report_file = tmp_path / "cdx-audit-npm.json"
    report_file.write_text((DATA_DIR / "cdx-audit" / "direct-report.json").read_text())
    crash = tmp_path / "crash.py"
    crash.write_text("import sys\nprint('boom: the audit crashed', file=sys.stderr)\nsys.exit(0)\n")
    monkeypatch.setattr(
        cdx_audit, "build_command", lambda argv: [sys.executable, str(crash), *argv[1:]]
    )
    with pytest.raises(cdx_audit.CdxAuditError, match="wrote no report"):
        cdx_audit.run_cdx_audit(str(script), ["--bom", "b.json", "--report-file", str(report_file)])
    assert not report_file.exists(), "the earlier report was removed before the run"


@pytest.mark.parametrize("exit_code", ["1", "2", "4"])
def test_any_exit_other_than_0_and_3_is_a_failure(tmp_path, fake_cdx_audit, monkeypatch, exit_code):
    """Only 0 and 3 (a finding met the fail severity) are completed runs; any
    other exit is a failure whose message carries the end of the output,
    even when a report was written."""
    script, calls = fake_cdx_audit
    monkeypatch.setenv("FAKE_REPORT", json.dumps({"version": 1, "results": []}))
    monkeypatch.setenv("FAKE_EXIT", exit_code)
    with pytest.raises(cdx_audit.CdxAuditError, match=f"exited with {exit_code}"):
        cdx_audit.run_cdx_audit(
            str(script), ["--bom", "b.json", "--report-file", str(tmp_path / "r.json")]
        )


@pytest.mark.parametrize(
    "report,why",
    [
        ('{"version":1,"results":[', "a truncated report"),
        ("[1, 2]", "a report that is no object"),
        (json.dumps({"version": 1, "summary": {"skippedTargets": "many"}}), "a text count"),
        (json.dumps({"version": 1, "summary": {"targetCapTruncated": 1.5}}), "a fractional count"),
    ],
)
def test_an_unreadable_report_is_a_cdx_audit_error(tmp_path, fake_cdx_audit, monkeypatch, report, why):
    script, calls = fake_cdx_audit
    monkeypatch.setenv("FAKE_REPORT", report)
    with pytest.raises(cdx_audit.CdxAuditError):
        cdx_audit.run_cdx_audit(
            str(script), ["--bom", "b.json", "--report-file", str(tmp_path / "r.json")]
        )


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


def test_build_args_ask_for_the_registry_lookup_unless_offline():
    """Online, the direct audit looks the packages up; offline, it is not
    asked, and cdx-audit is told why with --offline instead."""
    online = cdx_audit.build_audit_args(
        "sbom.cdx.json",
        "audit.json",
        direct=True,
        fetch_registry_metadata=True,
    )
    assert "--fetch-registry-metadata" in online
    assert "--offline" not in online
    offline = cdx_audit.build_audit_args(
        "sbom.cdx.json",
        "audit.json",
        direct=True,
        fetch_registry_metadata=True,
        offline=True,
    )
    assert "--offline" in offline
    assert "--fetch-registry-metadata" not in offline
    unasked = cdx_audit.build_audit_args("sbom.cdx.json", "audit.json", direct=True)
    assert "--fetch-registry-metadata" not in unasked


#: A Node module loaded into cdx-audit with ``--import`` that records and
#: refuses every socket connection, DNS lookup or resolve, fetch, child
#: process and worker thread the process attempts. cdx-audit is a Node
#: program, so patching Python's socket module observes nothing it does,
#: and its registry lookups run in a helper binary it spawns (cdxrs), so a
#: spawn is refused as well. ``syncBuiltinESMExports`` makes the patches
#: reach named ESM imports.
NETGUARD_SOURCE = """import fs from "node:fs";
import net from "node:net";
import tls from "node:tls";
import dns from "node:dns";
import childProcess from "node:child_process";
import workerThreads from "node:worker_threads";
import { syncBuiltinESMExports } from "node:module";
const logFile = process.env.DEPSCAN_NETGUARD_LOG;
const refuse = (kind, target) => {
  fs.appendFileSync(logFile, `${kind} ${String(target).slice(0, 200)}\\n`);
  throw new Error(`network access refused by the test: ${kind}`);
};
const guard = (module, name, kind) => {
  module[name] = (...args) => refuse(kind, JSON.stringify(args.slice(0, 2)));
};
guard(net, "connect", "net.connect");
guard(net, "createConnection", "net.createConnection");
guard(tls, "connect", "tls.connect");
net.Socket.prototype.connect = function (...args) {
  refuse("socket.connect", JSON.stringify(args[0]));
};
for (const name of Object.keys(dns)) {
  if (name === "lookup" || name === "lookupService" || name.startsWith("resolve")) {
    guard(dns, name, `dns.${name}`);
  }
}
for (const name of Object.keys(dns.promises)) {
  if (name === "lookup" || name === "lookupService" || name.startsWith("resolve")) {
    dns.promises[name] = async (...args) => refuse(`dns.promises.${name}`, args[0]);
  }
}
// cdxgen reads `ldd --version` on Linux to pick its plugin binaries; that
// local probe runs, and any other child process is refused.
const localProbes = new Set(["ldd"]);
for (const name of ["spawn", "spawnSync", "execFile", "execFileSync", "exec", "execSync", "fork"]) {
  const original = childProcess[name];
  childProcess[name] = (...args) => {
    const command = String(args[0] ?? "").trim().split(/\\s+/)[0];
    if (name !== "fork" && localProbes.has(command)) {
      return original(...args);
    }
    return refuse(`child_process.${name}`, JSON.stringify(args.slice(0, 2)));
  };
}
workerThreads.Worker = class {
  constructor(file) {
    refuse("worker_threads.Worker", file);
  }
};
globalThis.fetch = async (url) => refuse("fetch", url);
syncBuiltinESMExports();
"""


@pytest.mark.parametrize(
    "probe,kind",
    [
        ("require('node:dns').resolve4('example.org', () => {})", "dns.resolve4"),
        ("require('node:dns').promises.resolveTxt('example.org').catch(() => {})", "dns.promises.resolveTxt"),
        ("require('node:dns').lookup('example.org', () => {})", "dns.lookup"),
        ("require('node:net').connect(9, '127.0.0.1')", "net.connect"),
        ("new (require('node:worker_threads').Worker)('x.js')", "worker_threads.Worker"),
        ("require('node:child_process').spawnSync('true')", "child_process.spawnSync"),
        ("fetch('http://example.org').catch(() => {})", "fetch"),
    ],
)
def test_the_network_guard_sees_each_route(tmp_path, monkeypatch, probe, kind):
    """The guard the offline tests rely on records every route a Node
    process could reach the network by, so its empty log means something."""
    import shutil
    import subprocess

    node = shutil.which("node")
    if not node:
        pytest.skip("node is not on PATH")
    log = _netguard(tmp_path, monkeypatch)
    subprocess.run([node, "-e", f"try {{ {probe} }} catch (e) {{}}"], check=False, timeout=60)
    assert log.read_text().startswith(kind), log.read_text()


def _real_cdx_audit():
    """The cdx-audit command to run, or skip: the real-tool tests need one
    that carries the options dep-scan passes, so a missing or older one is
    a skip with the reason, never a failure."""
    cmd = cdx_audit.find_cdx_audit_cmd()
    if not cmd:
        pytest.skip("no cdx-audit found; set CDX_AUDIT_CMD to run the real-tool tests")
    version = cdx_audit.cdx_audit_version(cmd)
    if not cdx_audit.check_cdx_audit_version(version):
        pytest.skip(
            f"cdx-audit {version or 'of an unknown version'} is older than "
            f"{cdx_audit.CDX_AUDIT_MIN_VERSION}, which carries the options dep-scan passes"
        )
    # A development build can report the minimum's version before it carries
    # the options, so its help text decides.
    from xbom_lib.process import build_command, tool_env

    help_text = subprocess.run(
        build_command([cmd, "--help"]),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        env=tool_env(),
    ).stdout
    if "--time-budget-minutes" not in (help_text or ""):
        pytest.skip(f"cdx-audit {version} does not carry the options dep-scan passes")
    return cmd


def _netguard(tmp_path, monkeypatch):
    """Load the network guard into every Node process the test starts; the
    log file it writes to, empty while nothing touched the network."""
    guard = tmp_path / "netguard.mjs"
    guard.write_text(NETGUARD_SOURCE, encoding="utf-8")
    log = tmp_path / "network-attempts.log"
    log.write_text("", encoding="utf-8")
    monkeypatch.setenv("DEPSCAN_NETGUARD_LOG", str(log))
    monkeypatch.setenv("NODE_OPTIONS", f"--import={guard.as_uri()}")
    return log


def _npm_bom(path, names=("depscan-netguard-probe-7f3a",)):
    path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "version": 1,
                "components": [
                    {
                        "type": "library",
                        "bom-ref": f"pkg:npm/{name}@4.21.2",
                        "name": name,
                        "version": "4.21.2",
                        "purl": f"pkg:npm/{name}@4.21.2",
                    }
                    for name in names
                ],
            }
        )
    )
    return path


def test_an_offline_scan_runs_cdx_audit_without_touching_the_network(tmp_path, monkeypatch):
    """The real cdx-audit under a Node guard that records any socket, DNS
    lookup or fetch. The scan's own offline detection (--vdb-offline) is
    what makes the stage pass --offline; the guard log stays empty and the
    report says the registry lookups did not run.

    Positive control: the same stage online asks for the registry lookup of
    a package no local cache holds, and the guard records the attempt, so
    an empty log means something.
    """
    from depscan.lib import pipeline
    from test.test_pipeline import _ctx

    cmd = _real_cdx_audit()
    monkeypatch.setattr(cdx_audit, "find_cdx_audit_cmd", lambda: cmd)
    log = _netguard(tmp_path, monkeypatch)
    bom = _npm_bom(tmp_path / "sbom-npm.cdx.json")

    (tmp_path / "offline").mkdir()
    (tmp_path / "online").mkdir()
    ctx = _ctx(tmp_path / "offline", ["-t", "npm", "--vdb-offline"])
    ctx.perform_risk_audit = True
    scan = pipeline.TypeScan(project_type="npm")
    scan.nominated_bom_file = str(bom)
    assert pipeline.stage_analysis_risk(ctx, scan) is True
    assert scan.risk_error is None, scan.risk_error
    assert scan.audit_output_files, "the audit ran and wrote its report"
    report = json.loads(Path(scan.audit_output_files[0]).read_text())
    assert report["results"][0]["coverage"]["registryMetadata"] == "offline"
    assert log.read_text() == "", "the offline audit attempted network access"

    online = _ctx(tmp_path / "online", ["-t", "npm"])
    online.perform_risk_audit = True
    scan = pipeline.TypeScan(project_type="npm")
    scan.nominated_bom_file = str(bom)
    pipeline.stage_analysis_risk(online, scan)
    assert log.read_text() != "", "the guard saw the online audit's registry lookup"


def test_private_namespace_produces_a_dependency_confusion_finding(tmp_path):
    """End to end through the real cdx-audit and the real public registry.

    A private namespace is whatever the caller says it is, so the test names
    a package the public npm registry holds (``lodash``) and one it does not
    (a name made up for the test). Only the name the public registry holds is
    a dependency-confusion finding: a private package that is not published
    publicly is the intended state.
    """
    from analysis_lib.evidence.adapters.cdx_audit import extract as cdx_audit_extract
    from analysis_lib.findings.cdx_audit_convert import findings_from_cdx_audit_records

    cmd = _real_cdx_audit()
    unpublished = "depscan-p21-unpublished-private-package"
    components = [
        {
            "type": "library",
            "bom-ref": f"pkg:npm/{name}@1.0.0",
            "name": name,
            "version": "1.0.0",
            "purl": f"pkg:npm/{name}@1.0.0",
        }
        for name in ("lodash", unpublished)
    ]
    bom_file = tmp_path / "sbom.cdx.json"
    bom_file.write_text(
        json.dumps(
            {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": components}
        )
    )
    report_file = tmp_path / "audit.json"
    args = cdx_audit.build_audit_args(
        str(bom_file),
        str(report_file),
        direct=True,
        categories=["package-integrity"],
        private_ns=f"lodash,{unpublished}",
    )
    result = cdx_audit.run_cdx_audit(cmd, args)
    block = result.report["results"][0]["coverage"]["privateNamespace"]
    assert block == {
        "matched": 2,
        "onPublicRegistry": 1,
        "notOnPublicRegistry": 1,
        "unknown": 0,
        "publicRegistry": "checked",
    }, "the public registry answered about both names"
    adapter_result = cdx_audit_extract(
        result.report,
        source="audit.json",
        producer_version="13.9.0",
        source_root=str(tmp_path),
        mode="direct",
    )
    findings = findings_from_cdx_audit_records(adapter_result.records)
    confusion = [f for f in findings if f.rule == "INT-017"]
    assert len(confusion) == 1, "the name the public registry holds is the finding"
    assert confusion[0].category == "supply-chain"
    assert confusion[0].components == ["pkg:npm/lodash@1.0.0"]
    assert not any(
        unpublished in (f.components or [""])[0] for f in confusion
    ), "a private name the public registry does not hold is no finding"
    assert not any(
        "dependency-confusion check did not assess" in (reason.detail or "")
        for f in confusion
        for reason in (f.coverage.reasons or [])
    ), "both names were answered about, so there is no gap to state"


def test_an_offline_private_namespace_check_asks_nothing_and_says_so(tmp_path, monkeypatch):
    """Offline, the public registry is not asked whether it holds a private
    name. No socket is built, and the report counts the name as unanswered,
    which the adapter states as a coverage gap instead of a clean check."""
    from analysis_lib.evidence.adapters.cdx_audit import extract as cdx_audit_extract

    cmd = _real_cdx_audit()
    log = _netguard(tmp_path, monkeypatch)
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
                        "bom-ref": "pkg:npm/lodash@4.17.21",
                        "name": "lodash",
                        "version": "4.17.21",
                        "purl": "pkg:npm/lodash@4.17.21",
                    }
                ],
            }
        )
    )
    report_file = tmp_path / "audit.json"
    args = cdx_audit.build_audit_args(
        str(bom_file), str(report_file), direct=True, offline=True, private_ns="lodash"
    )
    result = cdx_audit.run_cdx_audit(cmd, args)
    assert log.read_text() == "", "the offline audit attempted network access"
    assert result.report["results"][0]["coverage"]["privateNamespace"] == {
        "matched": 1,
        "onPublicRegistry": 0,
        "notOnPublicRegistry": 0,
        "unknown": 1,
        "publicRegistry": "offline",
    }
    adapter_result = cdx_audit_extract(
        result.report, source="audit.json", producer_version="13.9.0", mode="direct"
    )
    assert adapter_result.records == [], "nothing is reported as taken"
    assert any(
        caveat.kind == "coverage-gap"
        and "the dependency-confusion check did not assess 1 component(s) matching a private namespace"
        in caveat.detail
        and "the audit ran offline" in caveat.detail
        for caveat in adapter_result.caveats
    ), [caveat.detail for caveat in adapter_result.caveats]


def test_doctor_reports_the_audit_tool(tmp_path, monkeypatch):
    """The doctor's cdx-audit entry carries the version the fake names, and
    a too-old one is unusable with the reason a scan refuses on."""
    from depscan.lib import doctor as doctor_lib

    script = _write_fake_audit(tmp_path, name="cdx-audit-old", version="13.8.0")
    monkeypatch.setenv("CDX_AUDIT_CMD", str(script))
    # The minimum is read from DEPSCAN_CDX_AUDIT_MIN_VERSION at import, so
    # removing the variable here would change nothing: the constant is set
    # to the documented default instead, which 13.8.0 does not meet.
    monkeypatch.setattr(cdx_audit, "CDX_AUDIT_MIN_VERSION", "13.9.0")
    status = doctor_lib._cdx_audit_status()
    assert status.version == "13.8.0"
    assert not status.usable
    assert "minimum" in (status.reason or "")
