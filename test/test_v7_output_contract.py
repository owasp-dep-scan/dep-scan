"""The output contract for agents and scripts, driven through subprocesses.

Every verb and subcommand runs the way an agent starts it: a fresh
interpreter whose stdin is closed and whose stdout and stderr are pipes,
with ``--format json``, for a success case and at least one failure case per
verb. A generated runner script installs the recorded fakes the verb tests
use (the scan pipeline stages, the vdb store state, the download, the
server start) before ``depscan.cli.main()`` runs, records the calls those
fakes saw into a JSON file the test reads as positive controls, and exits
with ``main()``'s code.

Each run must leave stdout carrying exactly one JSON document that
validates against the verb's published schema, or against the error schema
when the verb stops as a whole with exit 1, 2 or 4. A scan whose individual
targets fail and a validate run with invalid documents keep their own
documents and still exit 1, which is why every case names the schema its
stdout carries. stderr must carry no line that parses as JSON and no ANSI
escape.

Beyond the per-verb runs this module checks that the colour variables
change what a run's stderr carries, that ``depscan schema`` lists every
schema file in the schemas directory and every one of them is a valid draft
2020-12 schema, and that every worked example on the agents page runs and
prints what its row in the verbs table promises.
"""

import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from analysis_lib.findings.schemas import (
    load_schema,
    published_files,
    schema_names,
    validate as validate_schema,
)
from depscan.lib import scan_directory

REPO_ROOT = Path(__file__).resolve().parent.parent
AGENTS_PAGE = REPO_ROOT / "documentation" / "docs" / "integrate" / "agents.mdx"
SCAN_DIRECTORY_FIXTURE = REPO_ROOT / "test" / "data" / "scan-directory"
VALID_VDR_FIXTURE = REPO_ROOT / "test" / "data" / "jinja-report.vdr.json"

#: Timeout for one verb run; a verb under the fakes finishes in seconds and
#: the rest of the time is the child interpreter's own import.
RUN_TIMEOUT = 300

#: The variables the child must never inherit: the colour switches under
#: test, the CI flags that change console behaviour, the vdb selection pins
#: the CI job may set, and every variable an internal scan option reads.
#: ``VDB_HOME`` is added back per run, pointing into the run's scratch.
DROP_ENV_VARS = (
    "NO_COLOR",
    "FORCE_COLOR",
    "CONSOLE_COLOR_SCHEME",
    "DISABLE_CONSOLE_EMOJI",
    "COLORTERM",
    "TERM",
    "CI",
    "CONTINUOUS_INTEGRATION",
    "GITHUB_REPOSITORY",
    "INPUT_THANK_YOU",
    "VDB_DATABASE_URL",
    "VDB_APP_ONLY_DATABASE_URL",
    "USE_VDB_10Y",
    "VDB_USE_SHARDS",
    "VDB_INCLUDE_METADATA",
    "VDB_SQLITE_IMMUTABLE",
    "VDB_SQLITE_JOURNAL_MODE",
    "FETCH_LICENSE",
    "SCAN_DEBUG_MODE",
    "CDXGEN_DEBUG_MODE",
    "CDXGEN_ARGS",
    "CDX_SPEC_VERSION",
    "CDXGEN_SERVER_URL",
    "CDXGEN_CMD",
    "CDXGEN_PLUGINS_DIR",
    "PKG_PRIVATE_NAMESPACE",
    "ENABLE_OSS_RISK",
    "DEPSCAN_RUSI_BACKEND",
    "DEPSCAN_GO_ANALYZER_NETWORK",
    "DEPSCAN_GO_ANALYZER_CGO",
    "DEPSCAN_FAIL_ON_ERROR",
    "DEPSCAN_HOST",
    "DEPSCAN_PORT",
    "DEPSCAN_SPINNER",
    "DEPSCAN_THINK_MODE",
    "DEPSCAN_SERVER_MAX_CONTENT_LENGTH",
    "DEPSCAN_REPORTS_DIR",
    "DEPSCAN_CONFIG",
    "OSV_EXCLUDE_MALWARE",
    "GOLEM_CMD",
    "DEPSCAN_GOLEM_BINARY",
    "RUSI_CMD",
    "DEPSCAN_RUSI_BINARY",
    "DOSAI_CMD",
    "DEPSCAN_DOSAI_BINARY",
)

#: The image reference the flavor resolver lands on with the pins dropped,
#: as the vdb download tests assert too.
APP_ONLY_URL = "ghcr.io/appthreat/vdb7-app-only:v7.0.x-xz"


# --- the runner script --------------------------------------------------------


RUNNER_SCRIPT = r'''
"""Run one dep-scan verb with the recorded fakes installed.

The contract test generates this file and starts it as

    python runner.py <calls-file> <profile> <depscan argv...>

``profile`` names the fake set to install, ``argv`` is the dep-scan command
line after the program name. The fakes record their calls into the JSON
file in every case, also when ``main()`` exits with an error, and the
process exits with ``depscan.cli.main()``'s code.
"""

import json
import os
import sys

CALLS_FILE = sys.argv[1]
PROFILE = sys.argv[2]
ARGV = sys.argv[3:]

calls = {}

# The BOM document the fake cdxgen process writes and the vulnerability the
# fake matching stage reports, as the scan tests' fixtures carry them.
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
    "directory": os.path.join(os.environ["VDB_HOME"], "data"),
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

VULN_REQUESTS = {
    "id": "CVE-2024-1111",
    "bom-ref": "CVE-2024-1111/pkg:pypi/requests@2.32.1",
    "affects": [{"ref": "pkg:pypi/requests@2.32.1"}],
    "ratings": [{"severity": "high", "score": 8.1, "method": "CVSSv31"}],
    "fixed_location": "2.32.2",
}


def install_scan_fakes():
    """Stub a scan's database, matching, supply-chain audit and cdxgen process."""
    from depscan.lib import bom as bom_mod
    from depscan.lib import doctor as doctor_mod
    from depscan.lib import pipeline, vdb_setup
    from xbom_lib import cdxgen as cdxgen_mod

    calls["matching"] = []
    calls["database"] = []
    calls["cdxgen"] = []
    calls["risk"] = []

    vdb_setup.resolve_scan_vdb_image = lambda args: ("oras://vdb", False, "app-only")
    vdb_setup.vdb_download_needed = lambda url, d: (False, "")
    vdb_setup.configure_vdb_readonly = lambda: None
    vdb_setup.ensure_vdb_usable = lambda: calls["database"].append(1)
    pipeline.get_pkgs_by_scope = lambda pkg_list: {}
    pipeline.get_pkg_list = lambda f: (
        [{"purl": "pkg:pypi/requests@2.32.1", "name": "requests"}],
        [],
    )
    pipeline.ReportGenerator.parse_and_generate_report = lambda self: None
    pipeline.console.save_html = lambda *a, **k: None
    pipeline.console.save_text = lambda *a, **k: None

    # install_scan_fakes patches the modules directly, without a fixture,
    # exactly as the assignments above do. This file's runner is a spawned
    # subprocess that cannot import the conftest, so the smallest report is
    # spelled here.
    from depscan.lib import cdx_audit as cdx_audit_module
    from pathlib import Path

    empty_audit_report = {
        "version": 1,
        "auditMode": "direct",
        "results": [],
        "summary": {"totalFindings": 0, "skippedTargets": 0, "erroredTargets": 0},
    }

    def fake_run(cmd, args):
        calls["risk"].append(list(args))
        path = args[args.index("--report-file") + 1]
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(empty_audit_report))
        return cdx_audit_module.CdxAuditResult(
            report=empty_audit_report,
            report_version=empty_audit_report.get("version"),
            findings_count=0,
            results=[],
        )

    cdx_audit_module.find_cdx_audit_cmd = lambda: "cdx-audit-fake"
    cdx_audit_module.cdx_audit_version = lambda cmd: "13.9.0"
    cdx_audit_module.run_cdx_audit = fake_run

    def fake_exec_tool(args, *a, **k):
        calls["cdxgen"].append([str(item) for item in args])
        bom_file = args[args.index("-o") + 1]
        with open(bom_file, "w", encoding="utf-8") as fp:
            json.dump(BOM_DOCUMENT, fp)
        return cdxgen_mod.BOMResult(success=True, command_output="BOM saved")

    cdxgen_mod.find_cdxgen_cmd = lambda *a, **k: "cdxgen"
    cdxgen_mod.exec_tool = fake_exec_tool
    bom_mod._refuse_old_cdxgen = lambda logger=None: True

    class StubVdrResult:
        success = True
        prioritized_pkg_vuln_trees = {}
        exploitability = None

        def __init__(self, pkg_vulnerabilities):
            self.pkg_vulnerabilities = pkg_vulnerabilities

    class StubVDRAnalyzer:
        def __init__(self, vdr_options):
            calls["matching"].append(
                [pkg.get("purl") for pkg in getattr(vdr_options, "pkg_list", [])]
            )
            self.vdr_options = vdr_options

        def process(self):
            # The stub replaces only the vulnerability search, so it runs the
            # same exploitability grading step the real analyzer runs.
            from analysis_lib.findings.exploitability import annotate_exploitability

            vulns = [dict(VULN_REQUESTS)]
            result = StubVdrResult(vulns)
            result.exploitability = annotate_exploitability(
                vulns, self.vdr_options.exploitability_inputs
            )
            return result

    pipeline.VDRAnalyzer = StubVDRAnalyzer
    doctor_mod._vdb_status = lambda: dict(FULL_VDB_DATA)


def install_vdb_fakes():
    """Stub the vdb store state and the download; record what they saw."""
    from vdb.lib import db as db_lib
    from vdb.lib import db_cmd

    from depscan.lib import vdb_setup

    calls["metadata"] = []
    calls["store_status"] = []
    calls["downloads"] = []

    shard_store_dir = os.path.join(os.environ["VDB_HOME"], "shards")

    db_lib.get_db_file_metadata = lambda: None

    def fake_store_status(store_dir=None):
        calls["store_status"].append(store_dir)
        return {
            "store_dir": store_dir or shard_store_dir,
            "shards": [],
            "coverage": "full",
            "mixed_builds": False,
            "missing_group_shards": [],
        }

    db_cmd.store_status = fake_store_status

    def fake_download(url):
        calls["downloads"].append(url)
        return {"image": url}

    vdb_setup.download_vdb_with_retries = fake_download


def install_vdb_download_failure():
    """A download that records the attempt and then fails."""
    install_vdb_fakes()

    from depscan.lib import vdb_setup

    def failing_download(url):
        calls["downloads"].append(url)
        raise ConnectionError("the registry refused the pull")

    vdb_setup.download_vdb_with_retries = failing_download


def install_serve_fakes():
    """A server start that records the context and runs the hook."""
    from depscan.lib import pipeline

    calls["server"] = []
    calls["database"] = []

    def fake_start(ctx, started_hook=None):
        calls["server"].append(
            {
                "host": ctx.args.server_host,
                "port": int(ctx.args.server_port),
                "mode": ctx.args.server_mode,
                "hook": started_hook is not None,
            }
        )
        if started_hook is not None:
            started_hook()
        return 0

    def fake_database(ctx):
        calls["database"].append(1)

    pipeline.start_server_mode = fake_start
    pipeline.stage_database = fake_database


def install_serve_database_failure():
    """A server start whose database stage cannot be prepared."""
    from depscan.lib import pipeline

    calls["server"] = []

    def failing_start(ctx, started_hook=None):
        raise pipeline.ScanStageError("the database could not be prepared")

    pipeline.start_server_mode = failing_start


def install_serve_requirement_failure():
    """A server whose packages are missing."""
    from depscan.lib import pipeline

    calls["server"] = []

    def missing_start(ctx, started_hook=None):
        raise pipeline.ServerRequirementError("the server packages are missing")

    pipeline.start_server_mode = missing_start


def install_report_spy():
    """Record the scan directory the report verb loads."""
    import depscan.api

    calls["load_scan"] = []
    real_load_scan = depscan.api.load_scan

    def spy_load_scan(reports_dir, *a, **k):
        calls["load_scan"].append(str(reports_dir))
        return real_load_scan(reports_dir, *a, **k)

    depscan.api.load_scan = spy_load_scan


INSTALLERS = {
    "scan": install_scan_fakes,
    "vdb": install_vdb_fakes,
    "vdb-download-error": install_vdb_download_failure,
    "serve": install_serve_fakes,
    "serve-db-error": install_serve_database_failure,
    "serve-req-error": install_serve_requirement_failure,
    "report": install_report_spy,
}

# The verb entry point is imported before any fake: an installer's module
# (xbom_lib's cdxgen, vdb) imports blint's logger, whose forced-colour
# handler would claim root logging ahead of dep-scan's own, and the scan's
# log lines would render coloured onto stdout instead of stderr.
import depscan.cli

installer = INSTALLERS.get(PROFILE)
if installer is not None:
    installer()

sys.argv = ["depscan", *ARGV]
code = 0
try:
    depscan.cli.main()
except SystemExit as exc:
    code = exc.code if isinstance(exc.code, int) else 0
finally:
    with open(CALLS_FILE, "w", encoding="utf-8") as fp:
        json.dump(calls, fp)
sys.exit(code)
'''


@pytest.fixture(scope="session")
def runner_script(tmp_path_factory):
    """The generated runner script, one file for the whole module."""
    path = tmp_path_factory.mktemp("contract-runner") / "runner.py"
    path.write_text(RUNNER_SCRIPT, encoding="utf-8")
    return path


def _child_env(extra):
    """The child's environment: the parent's import path, nothing inherited.

    ``PYTHONPATH`` carries the directories the parent resolved its imports
    from, so the child sees the same workspace packages, and
    ``PYTHONIOENCODING`` pins the streams' encoding.
    """
    env = {name: value for name, value in os.environ.items() if name not in DROP_ENV_VARS}
    seen = []
    for entry in [str(REPO_ROOT), *(p for p in sys.path if p)]:
        if entry and os.path.isdir(entry) and entry not in seen:
            seen.append(entry)
    env["PYTHONPATH"] = os.pathsep.join(seen)
    env["PYTHONIOENCODING"] = "utf-8"
    env.update(extra)
    return env


def _read_calls(path, out, err):
    if not path.is_file():
        pytest.fail(
            f"the runner never wrote its calls file to {path}:\n"
            f"stdout: {out[:2000]!r}\nstderr: {err[:2000]!r}"
        )
    return json.loads(path.read_text(encoding="utf-8"))


def run_verb(argv, profile, runner, scratch, cwd=None, env_extra=None):
    """Run one verb in the child; ``(exit_code, stdout, stderr, calls)``.

    The child's stdin is closed, both output streams are pipes, so neither
    stream is a terminal, and the run is capped at ``RUN_TIMEOUT`` seconds.
    """
    calls_file = scratch / "calls.json"
    (scratch / "vdb-home").mkdir(exist_ok=True)
    env = _child_env({"VDB_HOME": str(scratch / "vdb-home"), **(env_extra or {})})
    result = subprocess.run(
        [sys.executable, str(runner), calls_file, profile, *argv],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        cwd=str(cwd) if cwd else str(scratch),
        timeout=RUN_TIMEOUT,
    )
    out = result.stdout.decode("utf-8", "replace")
    err = result.stderr.decode("utf-8", "replace")
    return result.returncode, out, err, _read_calls(calls_file, out, err)


# --- the contract assertions --------------------------------------------------


def assert_one_document(out, err, exit_code, schema_name, label):
    """stdout carries one JSON document that the named schema accepts."""
    try:
        document = json.loads(out)
    except ValueError as exc:
        pytest.fail(
            f"{label}: exit {exit_code}, stdout is not one JSON document ({exc}):\n"
            f"stdout: {out[:2000]!r}\nstderr: {err[:2000]!r}"
        )
    assert out.endswith("\n"), f"{label}: the document does not end with a newline"
    validate_schema(schema_name, document)
    return document


def assert_stderr_rules(err, label):
    """stderr carries no JSON document and no ANSI escape.

    A document can leak one line at a time or pretty-printed over many, so
    every line that opens an object or an array is decoded from there to
    the end of stderr; a non-empty object or array found that way fails.
    """
    assert "\x1b" not in err, f"{label}: stderr carries ANSI escapes:\n{err[:2000]!r}"
    decoder = json.JSONDecoder()
    offset = 0
    for line in err.splitlines(keepends=True):
        stripped = line.lstrip()
        if stripped[:1] in ("{", "["):
            start = offset + len(line) - len(stripped)
            try:
                value, _end = decoder.raw_decode(err, start)
            except ValueError:
                value = None
            if isinstance(value, (dict, list)) and value:
                pytest.fail(f"{label}: stderr carries a JSON document: {stripped[:200]!r}")
        offset += len(line)


#: Sentinel for a case whose error document carries no details.
NO_DETAILS = object()

#: Sentinel for details a case asserts itself, when the value carries a
#: path only the run's scratch knows.
CASE_SPECIFIC_DETAILS = object()


def assert_error_document(document, expected, err, label):
    """The document is the expected error document, message on stderr."""
    error = document["error"]
    assert error["exitCode"] == expected["exitCode"], (
        f"{label}: exitCode {error['exitCode']} != {expected['exitCode']}"
    )
    assert error["verb"] == expected["verb"], f"{label}: verb {error['verb']!r}"
    message = expected["message"]
    assert message in error["message"], f"{label}: message {error['message']!r}"
    if expected["details"] is NO_DETAILS:
        assert "details" not in error, f"{label}: unexpected details {error.get('details')!r}"
    elif expected["details"] is not CASE_SPECIFIC_DETAILS:
        assert error["details"] == expected["details"], (
            f"{label}: details {error.get('details')!r}"
        )
    assert message in err, f"{label}: the message never reached stderr:\n{err[:2000]!r}"


# --- the per-verb cases --------------------------------------------------------


@dataclass(frozen=True)
class ContractCase:
    """One verb run: its argv, its fakes and the contract it must keep.

    ``argv`` and ``prepare`` receive the case's scratch directory; every
    case runs with that scratch as the working directory, a scratch reports
    directory at hand and ``VDB_HOME`` inside the scratch. ``checks`` are
    the positive controls, ``(calls, scratch)`` callables that prove a fake
    ran. ``details`` is the expected ``error.details`` value, or
    ``NO_DETAILS`` to require the key's absence.
    """

    case_id: str
    profile: str
    argv: object
    exit_code: int
    schema: str
    message: object = None
    verb: object = None
    details: object = NO_DETAILS
    prepare: object = None
    checks: tuple = ()

    @property
    def is_error_document(self):
        """Whether stdout must carry the error document."""
        return self.schema == "depscan-error"


def reports_dir_of(scratch):
    """The reports directory a case's scan writes into."""
    return scratch / "reports"


def _prepare_valid_file(scratch):
    """A JSON file that validates as CycloneDX, for a passing validate run."""
    (scratch / "given.vdr.json").write_text(
        VALID_VDR_FIXTURE.read_text(encoding="utf-8"), encoding="utf-8"
    )


def _prepare_invalid_file(scratch):
    """A file that is no JSON at all, for a failing validate run."""
    (scratch / "broken.vdr.json").write_text("{not json", encoding="utf-8")


def _prepare_source_file(scratch):
    """A source file in the scratch, so the zero-target scan scans a source."""
    (scratch / "app.py").write_text("import requests\n", encoding="utf-8")


def _prepare_config_file(scratch):
    """A configuration file the next config init must refuse to overwrite."""
    (scratch / ".config").mkdir(exist_ok=True)
    (scratch / ".config" / "depscan.toml").write_text('severity = "high"\n', encoding="utf-8")


def _check_matching_ran(calls, scratch):
    assert calls["matching"], "the matching stage never ran"


def _check_risk_ran(calls, scratch):
    assert calls["risk"], "the single-purl supply-chain audit never ran"


def _check_database_guard_ran(calls, scratch):
    assert calls["database"], "the database guard never ran"


def _check_cdxgen_ran(calls, scratch):
    assert calls["cdxgen"], "the cdxgen process never ran"


def _check_no_cdxgen(calls, scratch):
    assert calls["cdxgen"] == [], "a purl scan must not generate a BOM"


def _check_download_ran_once(calls, scratch):
    assert calls["downloads"] == [APP_ONLY_URL], (
        f"the download ran {calls['downloads']!r}, not once with the flavor's URL"
    )


def _check_download_marker_written(calls, scratch):
    marker = scratch / "vdb-home" / ".depscan-vdb-image"
    assert marker.is_file(), "the download never wrote the variant marker"
    assert marker.read_text(encoding="utf-8") == APP_ONLY_URL


def _check_server_started_with_hook(calls, scratch):
    assert len(calls["server"]) == 1, "the server did not start exactly once"
    started = calls["server"][0]
    assert started["mode"] is True, "the server did not start in server mode"
    assert started["hook"] is True, "the verb handed the server no startup hook"


def _check_report_loaded_fixture(calls, scratch):
    assert calls["load_scan"], "the report verb never loaded a scan directory"
    assert calls["load_scan"][0].endswith("scan-directory"), (
        f"the report loaded {calls['load_scan'][0]!r}"
    )


def _check_store_status_ran(calls, scratch):
    assert calls["store_status"], "the shard store status was never read"


CASES = (
    ContractCase(
        case_id="scan-purl-success",
        profile="scan",
        argv=lambda s: [
            "scan",
            "pkg:pypi/requests@2.32.1",
            "--reports-dir",
            str(reports_dir_of(s)),
            "--format",
            "json",
        ],
        exit_code=0,
        schema="depscan-scan-output",
        checks=(
            _check_matching_ran,
            _check_risk_ran,
            _check_database_guard_ran,
            _check_no_cdxgen,
        ),
    ),
    ContractCase(
        case_id="scan-two-targets-one-missing",
        profile="scan",
        argv=lambda s: [
            "scan",
            "pkg:pypi/requests@2.32.1",
            str(s / "missing-target"),
            "--reports-dir",
            str(reports_dir_of(s)),
            "--format",
            "json",
        ],
        exit_code=1,
        schema="depscan-scan-output",
        checks=(_check_matching_ran,),
    ),
    ContractCase(
        case_id="scan-unknown-check",
        profile="scan",
        argv=lambda s: ["scan", ".", "--checks", "bogus", "--format", "json"],
        exit_code=2,
        schema="depscan-error",
        verb="scan",
        message="unknown check bogus",
        details={"unknownChecks": ["bogus"]},
    ),
    ContractCase(
        case_id="scan-firmware-refused",
        profile="scan",
        argv=lambda s: [
            "scan",
            "pkg:pypi/requests@2.32.1",
            "--target-kind",
            "firmware",
            "--format",
            "json",
        ],
        exit_code=4,
        schema="depscan-error",
        verb="scan",
        message="Firmware targets have no inventory path",
        details={
            "capability": None,
            "reason": "Firmware targets have no inventory path in this version.",
        },
    ),
    ContractCase(
        case_id="scan-zero-targets",
        profile="scan",
        argv=lambda s: [
            "scan",
            "--reports-dir",
            str(reports_dir_of(s)),
            "--bom-engine",
            "CdxgenGenerator",
            "--format",
            "json",
        ],
        exit_code=0,
        schema="depscan-scan-output",
        prepare=_prepare_source_file,
        checks=(_check_matching_ran, _check_cdxgen_ran),
    ),
    ContractCase(
        case_id="report-saved-scan",
        profile="report",
        argv=lambda s: ["report", str(SCAN_DIRECTORY_FIXTURE), "--format", "json"],
        exit_code=0,
        schema="depscan-report-output",
        checks=(_check_report_loaded_fixture,),
    ),
    ContractCase(
        case_id="report-missing-directory",
        profile="report",
        argv=lambda s: ["report", str(s / "missing-scan"), "--format", "json"],
        exit_code=1,
        schema="depscan-error",
        verb="report",
        message="does not exist",
        details=NO_DETAILS,
    ),
    ContractCase(
        case_id="vdb-info",
        profile="vdb",
        argv=lambda s: ["vdb", "info", "--format", "json"],
        exit_code=0,
        schema="depscan-vdb-info-output",
        checks=(_check_store_status_ran,),
    ),
    ContractCase(
        case_id="vdb-info-format-before-subcommand",
        profile="vdb",
        argv=lambda s: ["vdb", "--format", "json", "info"],
        exit_code=0,
        schema="depscan-vdb-info-output",
        checks=(_check_store_status_ran,),
    ),
    ContractCase(
        case_id="vdb-path",
        profile="vdb",
        argv=lambda s: ["vdb", "path", "--format", "json"],
        exit_code=0,
        schema="depscan-vdb-path-output",
    ),
    ContractCase(
        case_id="vdb-download-success",
        profile="vdb",
        argv=lambda s: ["vdb", "download", "--flavor", "app-only", "--format", "json"],
        exit_code=0,
        schema="depscan-vdb-download-output",
        checks=(_check_download_ran_once, _check_download_marker_written),
    ),
    ContractCase(
        case_id="vdb-download-failure",
        profile="vdb-download-error",
        argv=lambda s: ["vdb", "download", "--flavor", "app-only", "--format", "json"],
        exit_code=1,
        schema="depscan-error",
        verb="vdb",
        message=f"Downloading the vdb image {APP_ONLY_URL} failed",
        details=NO_DETAILS,
        checks=(_check_download_ran_once,),
    ),
    ContractCase(
        case_id="vdb-unknown-subcommand",
        profile="vdb",
        argv=lambda s: ["vdb", "frobnicate", "--format", "json"],
        exit_code=2,
        schema="depscan-error",
        verb="vdb",
        message="invalid choice: 'frobnicate'",
    ),
    ContractCase(
        case_id="doctor-success",
        profile="none",
        argv=lambda s: ["doctor", "--format", "json"],
        exit_code=0,
        schema="depscan-doctor-output",
    ),
    ContractCase(
        case_id="doctor-unknown-capability",
        profile="none",
        argv=lambda s: ["doctor", "--require", "bogus", "--format", "json"],
        exit_code=2,
        schema="depscan-error",
        verb="doctor",
        message="unknown capability bogus",
        details={"unknownCapabilities": ["bogus"]},
    ),
    ContractCase(
        case_id="doctor-unmet-requirement",
        profile="none",
        argv=lambda s: ["doctor", "--require", "mobile", "--format", "json"],
        exit_code=4,
        schema="depscan-error",
        verb="doctor",
        message="required capabilities not available: mobile",
        details={"unmet": ["mobile"]},
    ),
    ContractCase(
        case_id="schema-listing",
        profile="none",
        argv=lambda s: ["schema", "--format", "json"],
        exit_code=0,
        schema="depscan-schema-output",
    ),
    ContractCase(
        case_id="schema-unknown-name",
        profile="none",
        argv=lambda s: ["schema", "nope", "--format", "json"],
        exit_code=2,
        schema="depscan-error",
        verb="schema",
        message="unknown schema 'nope'",
    ),
    ContractCase(
        case_id="config-show",
        profile="none",
        argv=lambda s: ["config", "show", "--format", "json"],
        exit_code=0,
        schema="depscan-config-show-output",
    ),
    ContractCase(
        case_id="config-init",
        profile="none",
        argv=lambda s: ["config", "init", "--format", "json"],
        exit_code=0,
        schema="depscan-config-init-output",
    ),
    ContractCase(
        case_id="config-init-refuses-existing",
        profile="none",
        argv=lambda s: ["config", "init", "--format", "json"],
        exit_code=1,
        schema="depscan-error",
        verb="config",
        message="already exists; not overwriting",
        details=CASE_SPECIFIC_DETAILS,
        prepare=_prepare_config_file,
    ),
    ContractCase(
        case_id="config-show-unknown-check",
        profile="none",
        argv=lambda s: ["config", "show", "--checks", "bogus", "--format", "json"],
        exit_code=2,
        schema="depscan-error",
        verb="config",
        message="unknown check bogus",
        details={"unknownChecks": ["bogus"]},
    ),
    ContractCase(
        case_id="serve-success",
        profile="serve",
        argv=lambda s: [
            "serve",
            "--server-host",
            "0.0.0.0",
            "--server-port",
            "9999",
            "--format",
            "json",
        ],
        exit_code=0,
        schema="depscan-serve-output",
        checks=(_check_server_started_with_hook,),
    ),
    ContractCase(
        case_id="serve-database-failure",
        profile="serve-db-error",
        argv=lambda s: ["serve", "--format", "json"],
        exit_code=1,
        schema="depscan-error",
        verb="serve",
        message="the database could not be prepared",
        details=NO_DETAILS,
    ),
    ContractCase(
        case_id="serve-requirement-failure",
        profile="serve-req-error",
        argv=lambda s: ["serve", "--format", "json"],
        exit_code=4,
        schema="depscan-error",
        verb="serve",
        message="the server packages are missing",
        details={"capability": "server", "reason": "the server packages are missing"},
    ),
    ContractCase(
        case_id="validate-valid-document",
        profile="none",
        argv=lambda s: ["validate", str(s / "given.vdr.json"), "--format", "json"],
        exit_code=0,
        schema="depscan-validate-output",
        prepare=_prepare_valid_file,
    ),
    ContractCase(
        case_id="validate-invalid-document",
        profile="none",
        argv=lambda s: ["validate", str(s / "broken.vdr.json"), "--format", "json"],
        exit_code=1,
        schema="depscan-validate-output",
        prepare=_prepare_invalid_file,
    ),
    ContractCase(
        case_id="validate-usage-no-files",
        profile="none",
        argv=lambda s: ["validate", "--format", "json"],
        exit_code=2,
        schema="depscan-error",
        verb="validate",
        message="the following arguments are required: files",
    ),
    ContractCase(
        case_id="version-success",
        profile="none",
        argv=lambda s: ["version", "--format", "json"],
        exit_code=0,
        schema="depscan-version-output",
    ),
    ContractCase(
        case_id="help-top-level",
        profile="none",
        argv=lambda s: ["help", "--format", "json"],
        exit_code=0,
        schema="depscan-help-output",
    ),
    ContractCase(
        case_id="help-one-verb",
        profile="none",
        argv=lambda s: ["help", "scan", "--format", "json"],
        exit_code=0,
        schema="depscan-help-output",
    ),
    ContractCase(
        case_id="usage-error-unknown-verb-with-json",
        profile="none",
        argv=lambda s: ["frobnicate", "--format", "json"],
        exit_code=2,
        schema="depscan-error",
        verb="frobnicate",
        message="invalid choice: 'frobnicate'",
    ),
    ContractCase(
        case_id="help-unknown-topic",
        profile="none",
        argv=lambda s: ["help", "frobnicate", "--format", "json"],
        exit_code=2,
        schema="depscan-error",
        verb="help",
        message="invalid choice: 'frobnicate'",
    ),
    ContractCase(
        case_id="help-flag-with-json",
        profile="none",
        argv=lambda s: ["scan", "--help", "--format", "json"],
        exit_code=0,
        schema="depscan-help-output",
    ),
    ContractCase(
        case_id="vdb-subcommand-format-wins",
        profile="vdb",
        argv=lambda s: ["vdb", "--format", "text", "info", "--format", "json"],
        exit_code=0,
        schema="depscan-vdb-info-output",
    ),
    ContractCase(
        case_id="vdb-download-conflicting-options",
        profile="none",
        argv=lambda s: [
            "vdb",
            "download",
            "--shards",
            "npm",
            "--flavor",
            "full",
            "--format",
            "json",
        ],
        exit_code=2,
        schema="depscan-error",
        verb="vdb",
        message="--shards cannot be combined",
    ),
    ContractCase(
        case_id="config-show-malformed-config-file",
        profile="none",
        prepare=lambda s: (s / "bad.toml").write_text("severity = [\n", encoding="utf-8"),
        argv=lambda s: ["config", "show", "--config", str(s / "bad.toml"), "--format", "json"],
        exit_code=1,
        schema="depscan-error",
        verb="config",
        message="TOMLDecodeError",
    ),
    ContractCase(
        case_id="doctor-require-value-with-a-dash",
        profile="none",
        argv=lambda s: ["doctor", "--require=-x", "--format", "json"],
        exit_code=2,
        schema="depscan-error",
        verb="doctor",
        message="unknown capability -x",
        details={"unknownCapabilities": ["-x"]},
    ),
    ContractCase(
        case_id="validate-deeply-nested-file",
        profile="none",
        prepare=lambda s: (s / "deep.json").write_text("[" * 100000 + "]" * 100000),
        argv=lambda s: ["validate", str(s / "deep.json"), "--format", "json"],
        exit_code=1,
        schema="depscan-validate-output",
    ),
    ContractCase(
        case_id="serve-port-not-a-number",
        profile="none",
        argv=lambda s: ["serve", "--server-port", "abc", "--format", "json"],
        exit_code=2,
        schema="depscan-error",
        verb="serve",
        message="is not a number from 1 to 65535",
    ),
    ContractCase(
        case_id="usage-error-single-token-format-json",
        profile="none",
        argv=lambda s: ["scan", "--format=json", "--no-such-option"],
        exit_code=2,
        schema="depscan-error",
        verb="scan",
        message="--no-such-option",
    ),
)


def _assert_case_document(case, document, scratch):
    """The case-specific shape assertions next to the schema validation."""
    if case.case_id == "scan-purl-success":
        assert list(document) == ["scans"]
        assert len(document["scans"]) == 1
        entry = document["scans"][0]
        assert set(entry) == {
            "target",
            "kind",
            "scanDir",
            "manifest",
            "findings",
            "expectations",
        }
        assert entry["target"] == "pkg:pypi/requests@2.32.1"
        assert entry["kind"] == "purl"
        assert entry["scanDir"] == str(reports_dir_of(scratch)).replace(os.sep, "/")
        assert entry["manifest"]["layoutVersion"] == scan_directory.LAYOUT_VERSION
        assert len(entry["findings"]) == 1
    elif case.case_id == "validate-deeply-nested-file":
        (result,) = document["results"]
        assert result["valid"] is False
        assert result["file"].endswith("/deep.json")
    elif case.case_id == "scan-zero-targets":
        assert len(document["scans"]) == 1
        entry = document["scans"][0]
        assert entry["kind"] == "source"
        assert entry["target"] == str(scratch).replace(os.sep, "/")
    elif case.case_id == "scan-two-targets-one-missing":
        entries = document["scans"]
        assert [entry["kind"] for entry in entries] == ["purl", None], (
            "the scanned and the refused target swapped places"
        )
        assert entries[0]["findings"], "the scanned target carried no findings"
        assert "does not exist" in entries[1]["error"]
        assert set(entries[1]) == {"target", "kind", "error"}
    elif case.case_id == "vdb-path":
        assert document["path"] == str(scratch / "vdb-home").replace(os.sep, "/")
    elif case.case_id == "vdb-download-success":
        assert document["image"] == APP_ONLY_URL
        assert document["marker"] == str(scratch / "vdb-home" / ".depscan-vdb-image").replace(
            os.sep, "/"
        )
    elif case.case_id == "config-init":
        written = scratch / ".config" / "depscan.toml"
        assert document["written"] == str(written).replace(os.sep, "/")
        assert written.is_file()
    elif case.case_id == "config-init-refuses-existing":
        assert document["error"]["details"] == {
            "path": str(scratch / ".config" / "depscan.toml").replace(os.sep, "/")
        }
    elif case.case_id == "serve-success":
        assert document["serving"] == {
            "host": "0.0.0.0",
            "port": 9999,
            "url": "http://127.0.0.1:9999",
        }
    elif case.case_id == "validate-invalid-document":
        results = document["results"]
        assert len(results) == 1
        assert results[0]["valid"] is False
        assert results[0]["errors"]
        assert results[0]["file"] == str(scratch / "broken.vdr.json").replace(os.sep, "/")
    elif case.case_id == "validate-valid-document":
        results = document["results"]
        assert len(results) == 1
        assert results[0]["valid"] is True
        assert results[0]["errors"] == []


@pytest.mark.parametrize("case", [pytest.param(case, id=case.case_id) for case in CASES])
def test_verb_contract(case, runner_script, tmp_path):
    """One verb run keeps the whole output contract.

    The run's exit code matches, stdout is one JSON document valid against
    the case's schema, the error cases carry their exit code, verb, message
    and details, stderr is free of JSON lines and ANSI escapes, and the
    positive controls prove the fakes ran.
    """
    scratch = tmp_path
    if case.prepare is not None:
        case.prepare(scratch)
    argv = case.argv(scratch)
    exit_code, out, err, calls = run_verb(argv, case.profile, runner_script, scratch)
    assert exit_code == case.exit_code, (
        f"{case.case_id}: exit {exit_code} != {case.exit_code}\nstderr: {err[:2000]!r}"
    )
    document = assert_one_document(out, err, exit_code, case.schema, case.case_id)
    if case.is_error_document:
        assert_error_document(
            document,
            {
                "exitCode": case.exit_code,
                "verb": case.verb,
                "message": case.message,
                "details": case.details,
            },
            err,
            case.case_id,
        )
    assert_stderr_rules(err, case.case_id)
    _assert_case_document(case, document, scratch)
    for check in case.checks:
        check(calls, scratch)


# --- text-only command lines ---------------------------------------------------


def test_v6_invocation_stays_text_only(runner_script, tmp_path):
    """A command line that starts with an option never writes a document.

    This is the dep-scan 6 shape: the translation and the migration guide
    go to stderr, stdout stays empty, and the exit code is 2.
    """
    exit_code, out, err, _calls = run_verb(
        ["--bom-dir", "x", "-o", "y"], "none", runner_script, tmp_path
    )
    assert exit_code == 2
    assert out == ""
    assert "this is a dep-scan 6 command line" in err
    assert_stderr_rules(err, "v6 invocation")


def test_v6_invocation_with_json_writes_the_error_document(runner_script, tmp_path):
    """A dep-scan 6 line that asks for json gets the error document as well."""
    exit_code, out, err, _calls = run_verb(
        ["--format", "json", "--bom-dir", "x"], "none", runner_script, tmp_path
    )
    assert exit_code == 2
    document = assert_one_document(out, err, exit_code, "depscan-error", "v6 with json")
    assert document["error"]["exitCode"] == 2
    assert "dep-scan 6 command line" in document["error"]["message"]
    assert document["error"]["details"]["translated"].startswith("depscan scan x")
    assert "this is a dep-scan 6 command line" in err


def test_a_path_target_is_absolute_in_the_scan_entry(runner_script, tmp_path):
    """A relative path target is reported in the absolute, slash form."""
    exit_code, out, err, _calls = run_verb(
        ["scan", "no-such-dir", "--format", "json"], "scan", runner_script, tmp_path
    )
    document = assert_one_document(out, err, exit_code, "depscan-scan-output", "relative")
    target = document["scans"][0]["target"]
    assert target.endswith("/no-such-dir") and "\\" not in target
    assert os.path.isabs(target.replace("/", os.sep))


@pytest.mark.skipif(
    sys.platform == "win32" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="mode 000 does not stop a directory listing on Windows or for root",
)
def test_an_unreadable_target_is_an_entry_not_a_crash(runner_script, tmp_path):
    """A directory the scan cannot list is refused in its entry."""
    unreadable = tmp_path / "noread"
    unreadable.mkdir()
    unreadable.chmod(0)
    try:
        exit_code, out, err, _calls = run_verb(
            ["scan", "pkg:pypi/requests@2.32.1", str(unreadable), "--format", "json"],
            "scan",
            runner_script,
            tmp_path,
        )
    finally:
        unreadable.chmod(0o755)
    assert exit_code == 1
    document = assert_one_document(out, err, exit_code, "depscan-scan-output", "unreadable")
    entries = document["scans"]
    assert entries[0]["kind"] == "purl"
    assert entries[1]["kind"] is None
    assert "cannot be read" in entries[1]["error"]
    assert "Traceback" not in err


def test_schema_with_a_name_prints_a_valid_schema(runner_script, tmp_path):
    """`depscan schema <name> --format json` prints that schema document."""
    exit_code, out, err, _calls = run_verb(
        ["schema", "depscan-scan-output", "--format", "json"], "none", runner_script, tmp_path
    )
    assert exit_code == 0
    assert out.endswith("\n")
    document = json.loads(out)
    Draft202012Validator.check_schema(document)
    assert document == load_schema("depscan-scan-output")
    assert_stderr_rules(err, "schema by name")


def test_help_json_carries_no_ansi_escapes(runner_script, tmp_path):
    """FORCE_COLOR colours consoles, never the help text inside a document."""
    exit_code, out, err, _calls = run_verb(
        ["help", "scan", "--format", "json"],
        "none",
        runner_script,
        tmp_path,
        env_extra={"FORCE_COLOR": "1"},
    )
    assert exit_code == 0
    document = json.loads(out)
    assert "\x1b" not in document["help"]
    assert "usage: depscan scan" in document["help"]


def test_usage_error_without_json_is_text_only(runner_script, tmp_path):
    """Without --format json anywhere, a usage error's text usage is all."""
    exit_code, out, err, _calls = run_verb(["frobnicate"], "none", runner_script, tmp_path)
    assert exit_code == 2
    assert out == ""
    assert "invalid choice: 'frobnicate'" in err
    assert "usage: depscan" in err
    assert_stderr_rules(err, "text usage error")


# --- colour and terminals -------------------------------------------------------


def _run_missing_target_scan(runner, scratch, env_extra):
    """The refusal run whose LOG error lands on stderr through rich."""
    return run_verb(
        [
            "scan",
            "does-not-exist-src",
            "--reports-dir",
            str(scratch / "reports"),
            "--format",
            "json",
        ],
        "none",
        runner,
        scratch,
        env_extra=env_extra,
    )


def test_stderr_is_plain_by_default(runner_script, tmp_path):
    """With no colour variable set, a piped stderr carries no ANSI escape."""
    exit_code, out, err, _calls = _run_missing_target_scan(runner_script, tmp_path, {})
    assert exit_code == 1
    assert "does not exist" in err
    assert "\x1b" not in err
    assert_stderr_rules(err, "default stderr")


def test_force_color_puts_ansi_on_stderr(runner_script, tmp_path):
    """FORCE_COLOR turns colour on for a piped stderr that was plain."""
    exit_code, _out, err, _calls = _run_missing_target_scan(
        runner_script, tmp_path, {"FORCE_COLOR": "1"}
    )
    assert exit_code == 1
    assert "\x1b[" in err, "FORCE_COLOR=1 left the piped stderr plain"


def test_no_color_beats_the_colour_variables(runner_script, tmp_path):
    """NO_COLOR removes the ANSI escapes an explicit scheme would force."""
    scheme_only = _run_missing_target_scan(
        runner_script, tmp_path, {"CONSOLE_COLOR_SCHEME": "256"}
    )
    assert scheme_only[0] == 1
    assert "\x1b[" in scheme_only[2], "an explicit scheme left the piped stderr plain"
    both = _run_missing_target_scan(
        runner_script, tmp_path, {"CONSOLE_COLOR_SCHEME": "256", "NO_COLOR": "1"}
    )
    assert both[0] == 1
    assert "\x1b" not in both[2], "NO_COLOR did not remove the ANSI escapes"


# --- the schema inventory -------------------------------------------------------


def test_schema_verb_lists_every_file_and_validates(runner_script, tmp_path):
    """`depscan schema --format json` lists every published schema file."""
    exit_code, out, err, _calls = run_verb(
        ["schema", "--format", "json"], "none", runner_script, tmp_path
    )
    assert exit_code == 0, err[:2000]
    document = assert_one_document(out, err, exit_code, "depscan-schema-output", "schema listing")
    entries = document["schemas"]
    assert [entry["name"] for entry in entries] == schema_names()
    on_disk = published_files()
    stems = {name[: -len(".schema.json")] for name in on_disk}
    assert {entry["name"] for entry in entries} == stems, (
        "the listing and the schemas directory disagree"
    )
    for entry in entries:
        assert entry["$id"] == load_schema(entry["name"])["$id"]
        assert entry["title"] == load_schema(entry["name"])["title"]
    assert_stderr_rules(err, "schema listing")


def test_every_published_schema_is_valid_draft_2020_12():
    """Every schema in the directory passes draft 2020-12 meta-validation."""
    for name in schema_names():
        Draft202012Validator.check_schema(load_schema(name))
    stems = {name[: -len(".schema.json")] for name in published_files()}
    assert stems == set(schema_names()), "a schema file is missing from the published list"


# --- the agents page examples ----------------------------------------------------


def _agents_table_rows():
    """The verbs table as ``{verb: schema}``, in the page's order.

    The verbs table comes first on the page; the MCP tools' table after it
    names its tools in the same three-column shape, and where a verb and a
    tool share a name (``doctor``) the verbs table's row is the one kept,
    because the worked examples below name the verbs. Schema names carry an
    underscore where the tool they belong to does
    (``depscan-mcp-vdb_status-output``), so both tables parse with the same
    pattern.
    """
    rows = {}
    for line in AGENTS_PAGE.read_text(encoding="utf-8").split("\n"):
        match = re.match(r"^\| `([^`]+)` \| .* \| `([a-z0-9_-]+)` \|$", line)
        if match:
            rows.setdefault(match.group(1), match.group(2))
    return rows


def _agents_row_schemas():
    """Every schema name any document table row on the page names, the
    verbs' and the MCP tools' together."""
    return set(
        re.findall(
            r"^\| `[^`]+` \| .* \| `([a-z0-9_-]+)` \|$",
            AGENTS_PAGE.read_text(encoding="utf-8"),
            flags=re.MULTILINE,
        )
    )


def _agents_examples():
    """``(heading, tokens)`` per worked example, one command block each.

    A tree without the page contributes no examples, so the module keeps
    collecting wherever the page does not exist yet; the table test below
    still fails there, naming the missing page.
    """
    if not AGENTS_PAGE.is_file():
        return []
    examples = []
    heading = None
    body = None
    for line in AGENTS_PAGE.read_text(encoding="utf-8").split("\n"):
        if line.startswith("### "):
            heading = line[4:].strip()
            body = None
        elif line.strip() == "```bash" and heading:
            body = []
        elif body is not None and line.strip() == "```":
            commands = [item for item in body if item.strip() and not item.strip().startswith("#")]
            assert len(commands) == 1, f"the {heading} example is one command: {body!r}"
            assert commands[0].rstrip().endswith("--format json"), (
                f"the {heading} example never asks for json: {commands[0]!r}"
            )
            tokens = commands[0].split()
            assert tokens[0] == "depscan", f"the {heading} example starts with {tokens[:1]!r}"
            assert heading is not None
            head = heading.split()
            assert tokens[1 : 1 + len(head)] == head, (
                f"the {heading} example runs {tokens[1:]} instead"
            )
            examples.append((heading, tokens[1:]))
            body = None
        elif body is not None:
            body.append(line)
    return examples


EXAMPLE_PROFILES = {
    "scan": "scan",
    "vdb download": "vdb",
    "vdb info": "vdb",
    "vdb path": "vdb",
    "serve": "serve",
}


def test_agents_page_table_covers_the_published_schemas():
    """Every output schema is named in one of the page's document tables,
    and only those.

    The verbs table covers the documents the verbs write in json format and
    the MCP tools' table the documents its ten tools return over the
    protocol. The error schema is the one output document outside the
    tables; it has its own section.
    """
    rows = _agents_row_schemas()
    expected = {name for name in schema_names() if name.endswith("-output")}
    assert rows == expected, (
        f"the page's document tables and the published output schemas disagree: {sorted(rows)}"
    )


@pytest.mark.parametrize(
    ("heading", "argv"),
    _agents_examples(),
    ids=[heading for heading, _ in _agents_examples()],
)
def test_agents_page_example_runs_and_matches_its_schema(heading, argv, runner_script, tmp_path):
    """The page's command runs and prints the document its row promises.

    The examples run from the repository root, as the page says, with the
    fakes standing in for the database download and the server, so no run
    touches the network. The serve example's fake start runs the startup
    hook directly; test_v7_serve.py covers the hook firing only once the
    real listener answers.
    """
    scratch = tmp_path
    profile = EXAMPLE_PROFILES.get(heading, "none")
    schema = _agents_table_rows()[heading]
    exit_code, out, err, calls = run_verb(
        argv,
        profile,
        runner_script,
        scratch,
        cwd=REPO_ROOT,
        env_extra={"DEPSCAN_REPORTS_DIR": str(scratch / "reports")},
    )
    label = f"agents example {heading}"
    assert exit_code == 0, f"{label}: exit {exit_code}\nstderr: {err[:2000]!r}"
    document = assert_one_document(out, err, exit_code, schema, label)
    assert_stderr_rules(err, label)
    if heading == "scan":
        assert calls["matching"], "the scan example's matching stage never ran"
        assert list(document) == ["scans"]
    elif heading == "vdb download":
        assert calls["downloads"] == [APP_ONLY_URL], calls["downloads"]
    elif heading == "serve":
        assert calls["server"] and calls["server"][0]["hook"], calls["server"]
        assert list(document) == ["serving"]
