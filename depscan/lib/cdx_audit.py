"""Find and run cdxgen's ``cdx-audit``, dep-scan's supply-chain audit engine.

dep-scan owns orchestration and presentation; every supply-chain rule, score
and severity comes from cdx-audit. This module locates the command the way dep-scan locates cdxgen itself, checks
the version against the options dep-scan passes, runs one audit per project
type's BOM with an argument list built in code, and returns the parsed JSON
report. A report whose shape predates the fields dep-scan reads is refused the
same way an old version is.
"""

import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from depscan.lib.logger import LOG
from xbom_lib.process import build_command, find_executable, tool_env

#: The cdxgen release this dep-scan needs. The audit passes
#: ``--private-namespace``, ``--fetch-registry-metadata``, ``--offline`` and
#: ``--time-budget-minutes``, and reads the report's ``version`` field, the
#: summary's ``targetCapTruncated`` and ``offline`` markers, each direct
#: result's ``coverage`` block and the per-target skip reasons; all of that
#: shipped after 13.9.0, so the minimum is the release that carries them.
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


@dataclass
class CdxAuditLocation:
    """Where cdx-audit was found, or why it was not.

    ``source`` is ``"env"`` when ``CDX_AUDIT_CMD`` named the command,
    ``"path"`` when it came from PATH and ``"cdxgen"`` when it sits beside
    the cdxgen install. ``reason`` says why ``path`` is None.
    """

    path: Optional[str] = None
    source: Optional[str] = None
    reason: Optional[str] = None


#: The reason a scan and the doctor give when no cdx-audit is found.
NOT_FOUND_REASON = (
    "cdx-audit was not found; install the cdxgen npm package (which ships it) "
    "with `npm install -g @cdxgen/cdxgen` or set CDX_AUDIT_CMD"
)


def _beside_cdxgen() -> Optional[str]:
    """The cdx-audit command in the ``bin`` directory of the cdxgen install
    dep-scan uses, where the cdxgen npm package ships it."""
    try:
        from xbom_lib.cdxgen import find_cdxgen_cmd
    except ImportError:
        return None
    cdxgen_cmd = find_cdxgen_cmd() or find_cdxgen_cmd(False)
    if not cdxgen_cmd:
        return None
    resolved = find_executable(str(cdxgen_cmd)) or str(cdxgen_cmd)
    directory = os.path.dirname(os.path.abspath(resolved))
    names = ("cdx-audit.cmd", "cdx-audit.exe", "cdx-audit") if sys.platform == "win32" else (
        "cdx-audit",
    )
    for name in names:
        candidate = os.path.join(directory, name)
        if os.path.isfile(candidate):
            return candidate
    return None


def locate_cdx_audit() -> CdxAuditLocation:
    """Locate the cdx-audit command; the doctor and the scan share this.

    The ``CDX_AUDIT_CMD`` environment variable wins, then ``cdx-audit`` on
    PATH, then the binary beside the cdxgen install dep-scan already found.
    A ``CDX_AUDIT_CMD`` that names neither an existing file nor a command on
    PATH is reported as not found with the value it named, rather than
    falling through to another install the user did not ask for. PATH is
    searched with :func:`xbom_lib.process.find_executable`, which never
    looks in the current directory on Windows.
    """
    env_cmd = os.environ.get("CDX_AUDIT_CMD", "").strip()
    if env_cmd:
        found = env_cmd if os.path.isfile(env_cmd) else find_executable(env_cmd)
        if found:
            return CdxAuditLocation(path=found, source="env")
        return CdxAuditLocation(
            reason=f"cdx-audit was not found: CDX_AUDIT_CMD names {env_cmd}, which does not exist"
        )
    on_path = find_executable("cdx-audit")
    if on_path:
        return CdxAuditLocation(path=on_path, source="path")
    beside = _beside_cdxgen()
    if beside:
        return CdxAuditLocation(path=beside, source="cdxgen")
    return CdxAuditLocation(reason=NOT_FOUND_REASON)


def find_cdx_audit_cmd() -> Optional[str]:
    """The cdx-audit command the scan runs, or None when none is found.

    :func:`locate_cdx_audit` says why when this returns None.
    """
    return locate_cdx_audit().path


def cdx_audit_version(cmd: str) -> Optional[str]:
    """The cdx-audit version string, or None when it cannot be read.

    cdx-audit prints the cdxgen version it belongs to, the same string
    ``cdxgen --version`` prints.
    """
    try:
        proc = subprocess.run(
            build_command([cmd, "--version"]),
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
            shell=False,
            env=tool_env(),
        )
    except (OSError, subprocess.SubprocessError) as e:
        # SubprocessError covers a timeout and the UnsafeCommandError
        # build_command raises for a Windows batch file it will not run.
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
    #: The registry coverage block of each direct result, as the report
    #: states it: whether the registry lookups ran, and how many
    #: registry-eligible components a registry answered for.
    coverage: List[Dict[str, Any]] = field(default_factory=list)


def build_audit_args(
    bom_file: str,
    report_file: str,
    *,
    direct: bool = True,
    categories: Optional[List[str]] = None,
    private_ns: Optional[str] = None,
    fetch_registry_metadata: bool = False,
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
    if fetch_registry_metadata and not offline:
        # The rules that read registry metadata can only evaluate what the
        # BOM carries. Offline mode makes no request, so the flag is left
        # out and the report's coverage block says the lookups did not run.
        args.append("--fetch-registry-metadata")
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


#: How much of a failed run's output an error message carries.
OUTPUT_TAIL_CHARS = 2000

#: The exit codes of a run that completed: 0, and 3 when a finding met the
#: fail severity.
COMPLETED_EXIT_CODES = (0, 3)


def _output_tail(output: str) -> str:
    """The end of a run's output, where the error usually is."""
    text = output.strip()
    if len(text) > OUTPUT_TAIL_CHARS:
        text = "..." + text[-OUTPUT_TAIL_CHARS:]
    return text or "(no output)"


def _summary_count(summary: Dict[str, Any], key: str, optional: bool = False) -> Optional[int]:
    """A count from the report's summary; a value that is not a whole
    number is a malformed report."""
    value = summary.get(key)
    if value is None:
        return None if optional else 0
    if isinstance(value, bool) or not isinstance(value, (int, float)) or int(value) != value:
        raise CdxAuditError(
            f"the cdx-audit report is malformed: summary.{key} is {value!r}, not a count"
        )
    return int(value)


def run_cdx_audit(cmd: str, args: List[str]) -> CdxAuditResult:
    """Run cdx-audit once and read its JSON report back.

    The report file is removed before the run, so a report left by an
    earlier scan is never read as this run's. Exit code 3 is a result (a
    finding met the fail severity); any other non-zero exit, a missing
    report, a report that is not JSON and a summary count that is not a
    number are failures, raised as :class:`CdxAuditError` with the end of
    the run's output. The report's own markers name what the run cut
    short, so the caller can turn them into caveats.
    """
    report_file = args[args.index("--report-file") + 1]
    try:
        os.unlink(report_file)
    except FileNotFoundError:
        pass
    except OSError as e:
        raise CdxAuditError(f"the stale cdx-audit report {report_file} could not be removed: {e}")
    # build_command spells a Windows npm shim (a .cmd batch file) as the
    # command line cmd.exe needs, and leaves a plain argv list everywhere
    # else.
    argv = build_command([cmd, *args])
    LOG.debug("Running cdx-audit: %s", " ".join(str(part) for part in argv))
    proc = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=RUN_TIMEOUT_SECONDS,
        check=False,
        shell=False,
        env=tool_env(),
    )
    output = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode not in COMPLETED_EXIT_CODES:
        raise CdxAuditError(
            f"cdx-audit exited with {proc.returncode}; its output ends: {_output_tail(output)}"
        )
    if not os.path.isfile(report_file):
        raise CdxAuditError(
            f"cdx-audit wrote no report at {report_file} (exit {proc.returncode}); "
            f"its output ends: {_output_tail(output)}"
        )
    try:
        with open(report_file, encoding="utf-8") as handle:
            report = json.load(handle)
    except (OSError, ValueError, RecursionError) as e:
        raise CdxAuditError(
            f"the cdx-audit report {report_file} could not be read: {e}; "
            f"its output ends: {_output_tail(output)}"
        ) from e
    if not isinstance(report, dict):
        raise CdxAuditError(
            f"the cdx-audit report {report_file} is a {type(report).__name__}, not an object"
        )
    result = CdxAuditResult(
        report=report,
        output=output,
        report_version=report.get("version"),
        exit_code=proc.returncode,
    )
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    result.skipped_count = _summary_count(summary, "skippedTargets") or 0
    result.errored_count = _summary_count(summary, "erroredTargets") or 0
    result.truncated_count = _summary_count(summary, "targetCapTruncated", optional=True)
    result.offline = bool(summary.get("offline"))
    result.time_budget_exhausted = bool(summary.get("timeBudgetExhausted"))
    result.results = report.get("results") if isinstance(report.get("results"), list) else []
    # Counted from the results in both modes: the direct summary states a
    # total and the predictive summary does not.
    result.findings_count = sum(
        len(entry.get("findings"))
        for entry in result.results
        if isinstance(entry, dict) and isinstance(entry.get("findings"), list)
    )
    result.skipped_entries = (
        report.get("skipped") if isinstance(report.get("skipped"), list) else []
    )
    result.coverage = [
        entry.get("coverage")
        for entry in result.results
        if isinstance(entry, dict) and isinstance(entry.get("coverage"), dict)
    ]
    return result


class CdxAuditError(RuntimeError):
    """cdx-audit could not run or produced no readable report."""
