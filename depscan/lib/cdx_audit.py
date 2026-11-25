"""Find and run cdxgen's ``cdx-audit``, dep-scan's supply-chain audit engine.

dep-scan owns orchestration and presentation; every supply-chain rule, score
and severity comes from cdx-audit (decision 0004, delegate to the toolchain).
This module locates the command the way dep-scan locates cdxgen itself, checks
the version against the options dep-scan passes, runs one audit per project
type's BOM with an argument list built in code, and returns the parsed JSON
report. A report whose shape predates the fields dep-scan reads is refused the
same way an old version is.
"""

import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from depscan.lib.logger import LOG

#: The cdxgen release this dep-scan needs. The audit passes
#: ``--private-namespace``, ``--offline`` and ``--time-budget-minutes`` and
#: reads the report's ``version`` field, the ``summary.targetCapTruncated``
#: marker and the per-target skip reasons; all of that shipped after
#: 13.9.0, so the minimum is the release that carries them.
#: ``DEPSCAN_CDX_AUDIT_MIN_VERSION`` overrides the minimum for a scan run
#: against a development cdxgen that already carries the options; the
#: doctor reports the overridden minimum as its own.
CDX_AUDIT_MIN_VERSION = os.getenv("DEPSCAN_CDX_AUDIT_MIN_VERSION", "") or "13.10.0"

_CDXYGEN_NPM_PACKAGE = "@cdxgen/cdxgen"

_VERSION_RE = re.compile(r"(\d+\.\d+\.\d+)")

#: Seconds one cdx-audit run may take. A direct audit reads the BOM and its
#: properties; a predictive run is bounded by its own target cap and time
#: budget, so this ceiling only catches a hung process.
RUN_TIMEOUT_SECONDS = 3600


def find_cdx_audit_cmd() -> Optional[str]:
    """Locate the cdx-audit command.

    The ``CDX_AUDIT_CMD`` environment variable wins, then ``cdx-audit`` on
    PATH, then the binary beside the cdxgen install dep-scan already found:
    the cdxgen npm package ships ``cdx-audit`` in the same ``bin`` directory.
    Returns None when none of the three holds a runnable command.
    """
    env_cmd = os.environ.get("CDX_AUDIT_CMD", "").strip()
    if env_cmd:
        return env_cmd
    from shutil import which

    on_path = which("cdx-audit")
    if on_path:
        return on_path
    # Fall through to the cdxgen install: packages/xBOM-lib resolves the
    # command the scan already validated, and cdx-audit sits beside it.
    try:
        from xbom_lib.cdxgen import find_cdxgen_cmd

        cdxgen_cmd = find_cdxgen_cmd() or find_cdxgen_cmd(False)
    except ImportError:
        return None
    if not cdxgen_cmd:
        return None
    resolved = which(str(cdxgen_cmd)) or str(cdxgen_cmd)
    candidate = os.path.join(os.path.dirname(os.path.abspath(resolved)), "cdx-audit")
    if os.path.isfile(candidate) or which(candidate):
        return candidate
    return None


def cdx_audit_version(cmd: str) -> Optional[str]:
    """The cdx-audit version string, or None when it cannot be read.

    cdx-audit prints the cdxgen version it belongs to, the same string
    ``cdxgen --version`` prints.
    """
    try:
        proc = subprocess.run(
            [cmd, "--version"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        LOG.debug("cdx-audit version probe failed: %s", e)
        return None
    found = _VERSION_RE.search(proc.stdout or "")
    if found:
        return found.group(1)
    return None


def _version_tuple(version: str) -> tuple:
    parts = []
    for part in version.split("."):
        digits = re.match(r"\d+", part)
        parts.append(int(digits.group()) if digits else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)


def check_cdx_audit_version(version: Optional[str]) -> bool:
    """Whether a probed version satisfies dep-scan's minimum."""
    if not version:
        return False
    return _version_tuple(version) >= _version_tuple(CDX_AUDIT_MIN_VERSION)


@dataclass
class CdxAuditResult:
    """One cdx-audit run: the report, and what the run itself reported."""

    report: Dict[str, Any]
    #: Combined stdout and stderr, for the log when the run went wrong.
    output: str = ""
    #: The report's own version field; None when the report names none.
    report_version: Optional[Any] = None
    skipped_count: int = 0
    errored_count: int = 0
    truncated_count: Optional[int] = None
    offline: bool = False
    time_budget_exhausted: bool = False
    #: Non-zero exit codes that mean results (3) rather than trouble.
    exit_code: int = 0
    #: Findings count the report's summary states, for the manifest stage.
    findings_count: int = 0
    #: Direct mode's per-BOM results and predictive mode's per-target results,
    #: already pulled out of the report for the caller.
    results: List[Dict[str, Any]] = field(default_factory=list)
    skipped_entries: List[Dict[str, Any]] = field(default_factory=list)


def build_audit_args(
    bom_file: str,
    report_file: str,
    *,
    direct: bool = True,
    categories: Optional[List[str]] = None,
    private_ns: Optional[str] = None,
    offline: bool = False,
    predictive: bool = False,
    scope_required: bool = False,
    max_targets: Optional[int] = None,
    time_budget_minutes: Optional[int] = None,
) -> List[str]:
    """The cdx-audit argument list for one audit run.

    Every path leaves the process as the caller spelled it; the argument list
    is passed to ``subprocess.run`` without a shell.
    """
    args = ["--bom", bom_file, "--report", "json", "--report-file", report_file]
    if direct:
        args.append("--direct-bom-audit")
    if categories:
        args.extend(["--categories", ",".join(categories)])
    if private_ns:
        args.extend(["--private-namespace", private_ns])
    if offline:
        args.append("--offline")
    if predictive:
        if scope_required:
            args.append("--scope")
            args.append("required")
        if max_targets:
            args.extend(["--max-targets", str(max_targets)])
        if time_budget_minutes:
            args.extend(["--time-budget-minutes", str(time_budget_minutes)])
    return args


def run_cdx_audit(cmd: str, args: List[str]) -> CdxAuditResult:
    """Run cdx-audit once and read its JSON report back.

    Exit code 3 is a result (a finding met the fail severity), never a run
    failure; exit code 1 or a missing report is. The report's own markers
    name what the run cut short, so the caller can turn them into caveats.
    """
    argv = [cmd, *args]
    LOG.debug("Running cdx-audit: %s", " ".join(argv))
    proc = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=RUN_TIMEOUT_SECONDS,
        check=False,
        shell=False,
    )
    output = (proc.stdout or "") + (proc.stderr or "")
    report_file = args[args.index("--report-file") + 1]
    if not os.path.isfile(report_file):
        raise CdxAuditError(
            f"cdx-audit wrote no report at {report_file} (exit {proc.returncode}); "
            f"its output follows: {output.strip()[:2000]}"
        )
    with open(report_file, encoding="utf-8") as handle:
        report = json.load(handle)
    result = CdxAuditResult(
        report=report,
        output=output,
        report_version=report.get("version"),
        exit_code=proc.returncode,
    )
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    result.findings_count = int(summary.get("totalFindings", 0) or 0)
    result.skipped_count = int(summary.get("skippedTargets", 0) or 0)
    result.errored_count = int(summary.get("erroredTargets", 0) or 0)
    truncated = summary.get("targetCapTruncated")
    result.truncated_count = int(truncated) if truncated is not None else None
    result.offline = bool(summary.get("offline"))
    result.time_budget_exhausted = bool(summary.get("timeBudgetExhausted"))
    result.results = report.get("results") if isinstance(report.get("results"), list) else []
    result.skipped_entries = (
        report.get("skipped") if isinstance(report.get("skipped"), list) else []
    )
    return result


class CdxAuditError(RuntimeError):
    """cdx-audit could not run or produced no readable report."""
