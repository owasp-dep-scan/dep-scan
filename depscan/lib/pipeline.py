"""The scan pipeline: one stage function per phase of a depscan run.

``depscan.api.scan`` builds a :class:`ScanContext` and calls the stages in
order. Each stage is a plain function over the context (plus the
per-project-type :class:`TypeScan` for the loop stages); the context is plain
data with no stage methods on it, so a later task can persist and re-run
single stages.

Stage order, which reproduces the order the previous single function used:

1. ``configure_output`` - console, quiet and debug handling
2. ``start_server_mode`` - server mode returns before any scan stage runs
3. ``stage_setup`` - banner, input validation, search order, directories,
   the option dictionary
4. ``stage_database`` - image resolution, shards, download, the empty
   database guard, custom data
5. ``finalize_setup`` - project types detection, report file paths, the
   license pseudo type, the sample config
6. per project type: ``stage_inventory`` (BOM generation or loading),
   ``stage_analysis_licenses`` and ``stage_analysis_risk`` (the analysis
   steps that run before the search), ``announce_scan_targets``,
   ``stage_enrichment`` (reachability), ``stage_matching`` (the vulnerability
   lookup), ``stage_analysis_vdr`` (the VDR file and summary),
   ``stage_render_explain`` (explanation and CSAF export)
7. ``stage_render_reports`` - console export, HTML, text, template reports
   and VDR annotations

A stage that must stop the scan logs the message the scan always printed and
raises :class:`ScanStageError` with the same message; the caller turns that
into the same exit code. Stages never call ``sys.exit`` themselves.
"""

import contextlib
import json
import os
import secrets
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set

from analysis_lib import ReachabilityAnalysisKV, VdrAnalysisKV, get_all_bom_files
from analysis_lib.output import (
    exploitability_grade_stats,
    licenses_risk_table,
    pkg_risks_table,
    summary_stats,
)
from analysis_lib.packages import get_all_pkg_list, get_pkg_list
from analysis_lib.reachability import get_reachability_impl, reached_by_analyzer
from analysis_lib.search import get_pkgs_by_scope
from analysis_lib.vdr import VDRAnalyzer
from analysis_lib.vex.emit import export_csaf
from custom_json_diff.lib.utils import file_write, json_load
from reporting_lib.htmlgen import ReportGenerator
from rich.panel import Panel
from rich.terminal_theme import DEFAULT_TERMINAL_THEME, MONOKAI
from vdb.lib import config, search
from vdb.lib.utils import parse_purl
from xbom_lib.cdxgen import remove_stale_slices

from depscan import get_version
from depscan.lib import explainer, utils
from depscan.lib import doctor as doctor_lib
from depscan.lib import logger as logger_lib
from depscan.lib import scan_directory, vdb_setup
from depscan.lib.audit import risk_audit, risk_audit_map
from depscan.lib.bom import (
    ScanFailureError,
    annotate_vdr,
    blint_reviews_requested,
    create_bom,
    create_empty_vdr,
    determine_spec_version,
    export_bom,
    get_pkg_by_type,
    reachability_slice_files,
)
from depscan.lib.config import (
    DEPSCAN_DEFAULT_VDR_FILE,
    UNIVERSAL_SCAN_TYPE,
    VDB_USE_SHARDS,
    license_data_dir,
    pkg_max_risk_score,
    spdx_license_list,
    write_vdb_image_marker,
)
from depscan.lib.license import build_license_data, bulk_lookup
from depscan.lib.logger import DEBUG, IS_CI, LOG, SPINNER, console, log_console

LOGO = """
  _|  _  ._   _  _  _. ._
 (_| (/_ |_) _> (_ (_| | |
         |
"""

SERVER_LIB = None
try:
    from server_lib import ServerOptions, simple

    SERVER_LIB = simple
except ImportError:
    pass


class ScanStageError(RuntimeError):
    """A stage decided the scan must stop.

    The stage has already logged every message the scan prints for this
    condition and passes the same message to this error, so the caller can
    report why the scan stopped; the CLI verb dispatch catches this error and
    exits with code 1.
    """


class ServerRequirementError(RuntimeError):
    """The server cannot start: a package or a requirement is missing.

    :func:`start_server_mode` raises it instead of returning False, so the
    caller always holds the reason to report.
    """


@dataclass
class TypeScan:
    """The per-project-type state the loop stages pass to each other.

    One instance is created per project type. The fields reset per type
    (BOM paths, package list, results) deliberately live here rather than on
    the context so a second type cannot inherit the first type's values.
    """

    project_type: str
    vuln_analyzer: Optional[str] = None
    bom_dir: Optional[str] = None
    lifecycle_mode: bool = False
    prebuild_bom_file: Optional[str] = None
    build_bom_file: Optional[str] = None
    postbuild_bom_file: Optional[str] = None
    container_bom_file: Optional[str] = None
    operations_bom_file: Optional[str] = None
    target_bom_file: Optional[str] = None
    risk_report_file: Optional[str] = None
    # Why the risk audit failed when it ran and degraded; the scan goes on.
    risk_error: Optional[str] = None
    # Why a requested risk audit had nothing it could audit for this type.
    risk_not_assessed: Optional[str] = None
    # Why BOM generation failed for this type; the scan goes on to the next.
    inventory_error: Optional[str] = None
    bom_files: List[str] = field(default_factory=list)
    nominated_bom_file: Optional[str] = None
    bom_file: Optional[str] = None
    pkg_list: List[Dict] = field(default_factory=list)
    scoped_pkgs: Dict = field(default_factory=dict)
    reachability_analyzer: Optional[str] = None
    reachability_options: Optional[ReachabilityAnalysisKV] = None
    direct_purls: Dict = field(default_factory=dict)
    reached_purls: Dict = field(default_factory=dict)
    reached_services: Dict = field(default_factory=dict)
    endpoint_reached_purls: Dict = field(default_factory=dict)
    #: True once the reachability engine ran and returned a result for this
    #: type; slices on disk alone do not make the analysis succeeded.
    reachability_succeeded: bool = False
    results: List = field(default_factory=list)
    vdr_result: Optional[object] = None
    vdr_file: Optional[str] = None
    summary: Dict = field(default_factory=dict)
    #: Reasons parts of this type's analysis did not run, such as an atom run
    #: that ATOM_TIMEOUT stopped. Kept on the scan so a later stage can write
    #: them out instead of counting the affected parts as clean.
    not_assessed: List[str] = field(default_factory=list)


@dataclass
class ScanContext:
    """Plain data shared by the stages of one scan.

    ``scans`` holds one :class:`TypeScan` per project type that produced
    results. ``summary`` and ``vdr_file`` carry the last matched type's
    values for the report rendering, ``bom_file`` the BOM of the last type
    whose BOMs were produced, and the vulnerability lists aggregate every
    type.
    """

    args: Any
    src_dir: str = ""
    reports_dir: str = ""
    depscan_options: Dict = field(default_factory=dict)
    perform_risk_audit: bool = False
    user_bom_dir: Optional[str] = None
    bom_dir_mode: bool = False
    config_file_mode: bool = False
    # Whether this run writes a scan directory. The server's per-request
    # scans leave it off: their output is the response, not a directory.
    write_scan_dir: bool = False
    # The doctor report collected once per scan, and the scan directory
    # builder the stages record their manifest entries into.
    doctor_report: Optional[doctor_lib.DoctorReport] = None
    scan_dir: Optional[scan_directory.ScanDirectory] = None
    # Database selection for this scan.
    scan_vdb_url: Optional[str] = None
    vdb_user_pinned: bool = False
    vdb_flavor: Optional[str] = None
    shards_connected: List[str] = field(default_factory=list)
    project_types: List[str] = field(default_factory=list)
    # The package list a --purl scan searches; empty for every other mode.
    purl_pkg_list: List[Dict] = field(default_factory=list)
    scans: List[TypeScan] = field(default_factory=list)
    # Report file paths and the rendering aggregates.
    html_report_file: Optional[str] = None
    txt_report_file: Optional[str] = None
    llm_prompt_file: Optional[str] = None
    all_pkg_vulnerabilities: List = field(default_factory=list)
    #: The (advisory id, affects ref) -> Exploitability map the project type
    #: scans graded, for the findings document; a pair whose reach was
    #: assessed keeps the assessment over a later unassessed one.
    exploitability: Dict = field(default_factory=dict)
    #: The rule table this scan grades with, loaded once before matching.
    grading_rules: Optional[Any] = None
    all_pkg_group_rows: Dict = field(default_factory=dict)
    summary: Optional[Dict] = None
    vdr_file: Optional[str] = None
    bom_file: Optional[str] = None


def build_context(args) -> ScanContext:
    """Create the scan context from the parsed CLI options."""
    ctx = ScanContext(args=args)
    ctx.perform_risk_audit = args.risk_audit
    return ctx


def configure_output(ctx):
    """Apply quiet/debug console settings and print the CI donation panel."""
    args = ctx.args
    if (
        os.getenv("CI")
        and not os.getenv("GITHUB_REPOSITORY", "").lower().startswith("owasp")
        and not args.no_banner
        and not os.getenv("INPUT_THANK_YOU", "") == "I have sponsored OWASP-dep-scan."
    ):
        log_console.print(
            Panel(
                "OWASP foundation relies on donations to fund our projects.\nPlease donate at: https://owasp.org/donate/?reponame=www-project-dep-scan&title=OWASP+depscan",
                title="Donate to the OWASP Foundation",
                expand=False,
            )
        )
    # Should we be quiet
    if args.quiet:
        args.explain = False
        LOG.disabled = True
        args.enable_debug = False
        os.environ["SCAN_DEBUG_MODE"] = "off"
        os.environ["CDXGEN_DEBUG_MODE"] = "off"
        console.quiet = True
        log_console.quiet = True
        args.no_vuln_table = True
    # Should we enable debug
    if args.enable_debug:
        os.environ["SCAN_DEBUG_MODE"] = "debug"
        os.environ["CDXGEN_DEBUG_MODE"] = "debug"
        LOG.setLevel(DEBUG)


def build_server_bom_scanner():
    """Build the BOM scanner the depscan server injects into its requests.

    The server package cannot import depscan (depscan depends on it), so it
    receives this callable through ``ServerOptions`` the same way it receives
    ``create_bom``. It scans one BOM file through the API with the
    rendering off and returns the VDR vulnerabilities for the response; a
    scan that stops early raises, so a failed request can never come back
    looking like a scan with no vulnerabilities.

    Requests skip the database stage. :func:`start_server_mode` runs it once,
    with the options the server was started with, before the server accepts
    requests. Running it per request would download or replace the database
    inside a request whenever it aged past ``VDB_AGE_HOURS``, or whenever the
    server's database options differed from the defaults the request uses.

    ``depscan.api`` imports this module, so the import is done here at call
    time rather than at module level to keep the import graph acyclic.
    """

    from depscan import api

    def scan_bom(bom_file, reports_dir, project_type, *, suggest_mode=False, fuzzy_search=False):
        options = api.scan_options(
            bom=bom_file,
            reports_dir=reports_dir,
            project_type=[project_type],
            no_banner=True,
            no_vuln_table=True,
            reachability_analyzer="off",
            risk_audit=False,
            fail_on_error=False,
            # The server always searched without an explicit order, which is
            # the batched search path; the CLI default would switch it.
            search_order=None,
            suggest=suggest_mode,
            fuzzy_search=fuzzy_search,
        )
        recording = console.record
        try:
            result = api._run_stages(options, render=False, database=False)
        finally:
            # The enrichment stage turns on console recording for the text
            # report, which a request never writes. Drop what was recorded so
            # a long-running server does not keep every request's output.
            if not recording and console.record:
                console.export_text(clear=True)
                console.record = False
        return result.vulnerabilities

    return scan_bom


#: How long the startup announcement waits for the server's listening socket
#: to accept a connection, in seconds. The bind happens moments after the
#: server package's startup hooks run; the deadline only bounds a start that
#: never comes up, where nothing is announced at all.
ANNOUNCE_TIMEOUT_SECONDS = 30.0

#: The response header that marks every answer this process's server gives.
#: The announcement probe reads it to tell the server it started from
#: whatever else may already hold the port.
_SERVING_MARKER_HEADER = "X-Depscan-Instance"


def _listener_candidates(host):
    """The addresses the startup announcement may probe.

    The configured host comes first; the loopback forms follow, for a
    wildcard or IPv6-any host whose socket also accepts loopback
    connections. Duplicates and empty names are dropped, order kept.
    """
    seen = set()
    ordered = []
    for candidate in (host, "127.0.0.1", "::1", "localhost"):
        if candidate and candidate not in seen:
            seen.add(candidate)
            ordered.append(candidate)
    return ordered


def _carries_marker(response: bytes, marker: str) -> bool:
    """Whether an HTTP response head carries this process's marker header."""
    head = response.split(b"\r\n\r\n", 1)[0]
    for line in head.split(b"\r\n"):
        name, _, value = line.partition(b":")
        if name.strip().lower() == _SERVING_MARKER_HEADER.lower().encode():
            return value.strip().decode("latin-1") == marker
    return False


def _answers_with_marker(host, port, marker: str) -> bool:
    """Whether the server answering this port carries this process's marker.

    A successful connection proves only that something listens; when the
    port was already held by another process, the bind that follows fails.
    This process's server stamps every response, whatever its status, with
    the marker header, so the probe can tell the server it started from a
    squatter or from another dep-scan server.
    """
    try:
        port_number = int(port)
    except (TypeError, ValueError):
        return False
    try:
        with socket.create_connection((host, port_number), timeout=0.25) as probe:
            probe.settimeout(1.0)
            probe.sendall(f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
            response = b""
            while len(response) < 4096:
                chunk = probe.recv(1024)
                if not chunk:
                    break
                response += chunk
                if b"\r\n\r\n" in response:
                    break
    except OSError:
        return False
    return _carries_marker(response, marker)


def _wait_until_listening(
    host, port, marker: str, announce: Callable[[], None], cancelled
) -> None:
    """Announce once the server answering the port carries this process's marker.

    The thread returns without announcing when the cancellation event is set
    or the deadline passes, so a server that never binds, or whose port is
    held by something else, announces nothing.
    """
    deadline = time.monotonic() + ANNOUNCE_TIMEOUT_SECONDS
    while time.monotonic() < deadline and not cancelled.is_set():
        for candidate in _listener_candidates(host):
            if _answers_with_marker(candidate, port, marker):
                if not cancelled.is_set():
                    announce()
                return
        time.sleep(0.05)


def _announce_once_listening(app, host, port, announce: Callable[[], None]):
    """Run ``announce`` through a hook the server calls once it serves.

    The server package's startup hooks run before it binds its socket, so
    announcing from the hook alone would print before the server is
    listening, and announcing on the first successful connection alone
    would announce for whatever already holds the port when the bind later
    fails. The hook therefore stamps the app's responses with a
    per-process marker header and starts a daemon thread that polls the
    port for a server answering with that marker: only the server this
    process started can carry it, so the announcement names a server that
    is listening and is ours. The returned event cancels the thread.
    """
    cancelled = threading.Event()
    marker = f"dep-scan-{secrets.token_hex(8)}"

    def mark_response(response):
        response.headers[_SERVING_MARKER_HEADER] = marker
        return response

    def start_hook():
        threading.Thread(
            target=_wait_until_listening,
            args=(host, port, marker, announce, cancelled),
            daemon=True,
        ).start()

    app.after_request(mark_response)
    app.before_serving(start_hook)
    return cancelled


def start_server_mode(ctx, started_hook: Optional[Callable[[], None]] = None):
    """Prepare the database once, then start the depscan server.

    No other scan stage runs here. A database that cannot be prepared raises
    :class:`ScanStageError`, so the server never starts without one. A server
    whose packages are missing, or that refuses its requirements, raises
    :class:`ServerRequirementError` with the reason.

    ``started_hook``, when given, runs once the server's listening socket
    accepts connections; the announce reason is described in
    :func:`_announce_once_listening`.
    """
    args = ctx.args
    if SERVER_LIB:
        stage_database(ctx)
        # Flask compares the request content length against this value,
        # so it must be an int (bytes); the raw env str would raise
        # TypeError on every upload instead of returning 413.
        max_content_length = None
        if raw_max_length := os.getenv("DEPSCAN_SERVER_MAX_CONTENT_LENGTH", ""):
            try:
                max_content_length = int(raw_max_length)
            except ValueError:
                LOG.warning(
                    "Ignoring non-numeric DEPSCAN_SERVER_MAX_CONTENT_LENGTH %r",
                    raw_max_length,
                )
        server_options = ServerOptions(
            server_host=args.server_host,
            server_port=args.server_port,
            cdxgen_server=args.cdxgen_server,
            allowed_hosts=args.server_allowed_hosts,
            allowed_paths=args.server_allowed_paths,
            console=console,
            logger=LOG,
            debug=args.enable_debug or os.environ.get("SCAN_DEBUG_MODE") == "debug",
            create_bom=create_bom,
            scan_bom=build_server_bom_scanner(),
            max_content_length=max_content_length,
            custom_data_directory=args.custom_data,
        )
        cancelled = None
        if started_hook is not None:
            cancelled = _announce_once_listening(
                simple.app, args.server_host, args.server_port, started_hook
            )
        try:
            started = simple.run_server(server_options)
        finally:
            if cancelled is not None:
                cancelled.set()
        if started is False:
            # run_server returns False only when it refuses a non-local bind
            # without an API key; the same refusal is logged by the server.
            raise ServerRequirementError(
                "The server cannot bind to a non-local host without "
                "DEPSCAN_SERVER_API_KEY or DEPSCAN_SERVER_ALLOW_UNAUTHENTICATED_BIND=true."
            )
        return started
    raise ServerRequirementError(
        "The required packages for server mode are unavailable. Reinstall depscan "
        "using `pip install owasp-depscan[all]`."
    )


def validate_scan_inputs(args):
    """Validate the scan input arguments before any expensive work begins.

    ``--bom``, ``--bom-dir`` and ``--purl`` are mutually exclusive at the
    argparse level, but values supplied via a TOML config file bypass that
    group. Worse, a path that simply did not exist used to be ignored
    silently: ``--bom missing.json`` fell through to generating a brand new
    BOM and ``--bom-dir missing/`` aggregated zero packages, both of which are
    indistinguishable from a clean scan in the output.

    :param args: Parsed CLI arguments.
    :returns: A list of human readable error messages. Empty when the inputs
        are usable.
    """
    errors = []
    provided = [
        (name, value)
        for name, value in (
            ("--bom", args.bom),
            ("--bom-dir", args.bom_dir),
            ("--purl", args.search_purl),
        )
        if value
    ]
    if len(provided) > 1:
        errors.append(
            "The arguments {} are mutually exclusive. Pass only one of them.".format(
                ", ".join(f"`{name}`" for name, _ in provided)
            )
        )
    if args.bom:
        if not os.path.exists(args.bom):
            errors.append(
                f"The BOM file `{args.bom}` passed via `--bom` does not exist. "
                "Generate one with cdxgen, or drop the argument to let depscan create it."
            )
        elif not os.path.isfile(args.bom):
            errors.append(
                f"The path `{args.bom}` passed via `--bom` is not a file. "
                "Use `--bom-dir` to scan a directory of BOM files."
            )
        elif bom_error := _bom_format_error(args.bom):
            errors.append(bom_error)
    if args.bom_dir:
        if not os.path.exists(args.bom_dir):
            errors.append(
                f"The BOM directory `{args.bom_dir}` passed via `--bom-dir` does not exist."
            )
        elif not os.path.isdir(args.bom_dir):
            errors.append(
                f"The path `{args.bom_dir}` passed via `--bom-dir` is not a directory. "
                "Use `--bom` to scan a single BOM file."
            )
    return errors


def _bom_format_error(bom_path):
    """Describe why ``bom_path`` cannot be read as a CycloneDX JSON BOM.

    Only the start of the file is read. The package reader parses JSON only,
    so an XML or other document would otherwise yield zero packages and a
    scan that looks clean.

    :returns: An error message, or None when the file starts like JSON.
    """
    try:
        with open(bom_path, "rb") as fp:
            head = fp.read(4096)
    except OSError as e:
        return f"The BOM file `{bom_path}` passed via `--bom` cannot be read: {e}"
    head = head.removeprefix(b"\xef\xbb\xbf").lstrip()
    if head.startswith(b"{"):
        return None
    if head.startswith(b"<"):
        return (
            f"The BOM file `{bom_path}` passed via `--bom` is XML. depscan reads "
            "CycloneDX JSON only; generate a JSON BOM with cdxgen."
        )
    return f"The BOM file `{bom_path}` passed via `--bom` is not a CycloneDX JSON document."


def _check_search_order(args):
    """Reject search orders that cannot work for this scan's inputs."""
    search_order = args.search_order
    if not search_order:
        return
    if search_order.startswith("c") and not args.bom and not args.bom_dir:
        LOG.warning(
            "To perform CPE-based searches, the SBOM must include a CPE identifier for each component. Generate the SBOM using a compatible tool such as Syft or Trivy, and invoke depscan with the --bom or --bom-dir argument."
        )
        LOG.info(
            "Alternatively, run depscan without the `--search-order` argument to perform PURL-based searches. This method is more accurate and recommended."
        )
        raise ScanStageError(
            "CPE-based searches need a BOM with CPE identifiers; pass --bom or "
            "--bom-dir or drop the --search-order argument."
        )
    if search_order.startswith("u") and not os.getenv("FETCH_LICENSE"):
        LOG.warning(
            "To perform URL-based searches, the SBOM must include externalReferences with a URL. Set the environment variable `FETCH_LICENSE=true` to force cdxgen to populate this attribute."
        )
        LOG.info(
            "Alternatively, include the project type `-t license` to ensure this attribute is populated."
        )


def stage_setup(ctx):
    """Validate the inputs and resolve the scan's directories and options."""
    args = ctx.args
    if not args.no_banner:
        with contextlib.suppress(UnicodeEncodeError):
            print(LOGO)
    # Fail fast on unusable scan inputs. Silently ignoring them produces an
    # empty-looking but successful scan, which is worse than no scan at all.
    input_errors = validate_scan_inputs(args)
    if input_errors:
        for input_error in input_errors:
            LOG.error(input_error)
        raise ScanStageError("\n".join(input_errors))
    _check_search_order(args)
    src_dir = args.src_dir_image
    if not src_dir or src_dir == ".":
        if src_dir == "." or args.search_purl:
            src_dir = os.getcwd()
        # Try to infer from the bom file
        elif args.bom and os.path.exists(args.bom):
            src_dir = os.path.dirname(os.path.realpath(args.bom))
        elif args.bom_dir and os.path.exists(args.bom_dir):
            src_dir = os.path.realpath(args.bom_dir)
        else:
            src_dir = os.getcwd()
    ctx.src_dir = src_dir
    reports_dir = args.reports_dir
    # User has not provided an explicit reports_dir. Reuse the bom_dir
    if not reports_dir and args.bom_dir:
        reports_dir = os.path.realpath(args.bom_dir)
    ctx.reports_dir = reports_dir
    # Are we running for a BOM directory the *user* supplied? This must be
    # captured before the lifecycle branch in stage_inventory repurposes the
    # bom dir as an output directory, otherwise the two modes become
    # indistinguishable.
    ctx.user_bom_dir = args.bom_dir
    ctx.bom_dir_mode = bool(ctx.user_bom_dir and os.path.isdir(ctx.user_bom_dir))
    # Are we running with a config file
    ctx.config_file_mode = args.config and os.path.exists(args.config)
    ctx.depscan_options = {**vars(args), "src_dir": src_dir, "reports_dir": reports_dir}
    # depscan owns the malware-exclusion filter (vdb also reads this env var,
    # but we translate it here so build_search_filters receives an explicit
    # option).
    ctx.depscan_options["exclude_malware"] = os.getenv("OSV_EXCLUDE_MALWARE", "") in (
        "true",
        "1",
    )
    # Is the user looking for semantic analysis?
    # We can default to this when run against a BOM directory
    if (
        args.reachability_analyzer == "SemanticReachability"
    ) and args.vuln_analyzer != "LifecycleAnalyzer":
        LOG.debug("Automatically switching to the `LifecycleAnalyzer` for vulnerability analysis.")
        ctx.depscan_options["vuln_analyzer"] = "LifecycleAnalyzer"
        args.vuln_analyzer = "LifecycleAnalyzer"
    # The exploitability rule table is loaded once, before any matching: an
    # override file that fails its schema stops the scan here, carrying the
    # schema error, instead of grading on a table nobody validated. The scan
    # verb reports the same failure as a usage error before the scan starts;
    # this path covers the server and the API.
    from analysis_lib.findings.exploitability import load_rules

    try:
        ctx.grading_rules = load_rules(ctx.depscan_options.get("exploitability_rules"))
    except ValueError as e:
        raise ScanStageError(str(e)) from e
    _start_scan_directory(ctx)


def _start_scan_directory(ctx):
    """Collect the doctor report once and open the scan directory's manifest.

    Every stage records its entry into the builder from here on; the manifest
    itself is written when the scan finishes, after every other file. Server
    requests write no scan directory, so they collect no doctor report either.
    A scan handed a report through :func:`depscan.api.scan` reuses it: the
    report never travels through the options namespace, whose every value the
    manifest and the sample config copy.
    """
    if not ctx.write_scan_dir:
        return
    if ctx.doctor_report is None:
        ctx.doctor_report = doctor_lib.doctor()
    ctx.scan_dir = scan_directory.ScanDirectory(
        ctx.reports_dir,
        depscan_version=get_version(),
        doctor_report=ctx.doctor_report,
    )
    ctx.scan_dir.record_stage("setup", "completed")


def finish_scan_directory(ctx) -> Optional[Dict[str, Any]]:
    """Write the findings file and then the manifest, in that order.

    The manifest is written last, through a temporary file and a rename, so
    it lists only files that exist. A scan that stopped partway still gets
    one, carrying the failed stage and its reason. Returns the manifest and
    the findings array, or None when this run writes no scan directory.
    """
    scan_dir = ctx.scan_dir
    if scan_dir is None:
        return None
    findings_document = scan_directory.write_findings(
        ctx.reports_dir,
        ctx.all_pkg_vulnerabilities,
        get_version(),
        scan_root=ctx.src_dir,
        exploitability=ctx.exploitability,
        blint_reviews=any(
            blint_reviews_requested({**ctx.depscan_options, "project_type": [project_type]})
            for project_type in (ctx.project_types or [None])
        ),
    )
    manifest = scan_dir.build(
        options=ctx.depscan_options,
        database_flavor=ctx.vdb_flavor,
        shards_used=ctx.shards_connected,
    )
    scan_directory.write_manifest(scan_dir, manifest)
    return {"manifest": manifest, "findings": findings_document["findings"]}


def stage_database(ctx):
    """Resolve, download and verify the vulnerability database."""
    args = ctx.args
    # Resolve the vdb image for this scan.
    try:
        scan_vdb_url, user_pinned, flavor = vdb_setup.resolve_scan_vdb_image(args)
    except ValueError as e:
        LOG.error("%s", e)
        raise ScanStageError(str(e)) from e
    ctx.scan_vdb_url, ctx.vdb_user_pinned, ctx.vdb_flavor = (
        scan_vdb_url,
        user_pinned,
        flavor,
    )
    # Opt-in shard mode replaces the complete database with the type shards
    # serving the scan's purl types, but only when those types are known
    # before matching. Offline mode never sets shards up: the setup does a
    # freshness check, a refresh over the network and a marker write, none of
    # which the offline promise allows, so the local complete database is
    # used as it is.
    ctx.shards_connected = []
    if VDB_USE_SHARDS and args.vdb_offline:
        LOG.warning(
            "VDB_USE_SHARDS is set but the offline mode was requested; using "
            "the local complete database as it is, without refreshing shards."
        )
    elif VDB_USE_SHARDS:
        shard_types = vdb_setup.collect_purl_types(args, ctx.src_dir)
        if shard_types:
            try:
                ctx.shards_connected = vdb_setup.setup_shards_for_scan(shard_types)
            except vdb_setup.VdbUnusableError as e:
                raise ScanStageError(str(e)) from e
        else:
            LOG.warning(
                "VDB_USE_SHARDS is set but this scan's purl types are not known "
                "before matching; using a complete database instead."
            )
    if not ctx.shards_connected and not args.vdb_offline:
        # Should we download the latest vdb. Offline mode uses the database
        # as it is: no freshness check, no download, no marker write. The
        # unusable-database guard below still runs, so a missing or empty
        # database stops the scan instead of looking like a clean one.
        should_download, dl_reason = vdb_setup.vdb_download_needed(scan_vdb_url, config.DATA_DIR)
        if should_download:
            with logger_lib.console_status(
                f"Downloading the latest vulnerability database to {config.DATA_DIR}. Please wait ...",
                spinner=SPINNER,
            ) as vdb_download_status:
                if not IS_CI:
                    vdb_download_status.stop()
                # The download raises once every retry has failed. The layer
                # that fails varies (vdb's own errors, urllib3 IncompleteRead,
                # requests ChunkedEncodingError), so any exception stops the
                # scan with a message instead of a traceback.
                try:
                    vdb_setup.download_vdb_with_retries(scan_vdb_url)
                except Exception as e:  # noqa: BLE001
                    LOG.error(
                        "Could not download the vulnerability database %s into %s: %s. "
                        "Check the network or proxy settings, or download it first "
                        "with `depscan vdb download` and run the scan again.",
                        scan_vdb_url,
                        config.DATA_DIR,
                        e,
                    )
                    raise ScanStageError(
                        f"Could not download the vulnerability database "
                        f"{scan_vdb_url} into {config.DATA_DIR}: {e}."
                    ) from e
                # Record the variant so a future switch forces a re-download
                # even when the DB is still within the age window.
                write_vdb_image_marker(scan_vdb_url, config.DATA_DIR)
    # Apply read-only SQLite tuning for the scan. Done after the download
    # so the vdb update path is never opened immutable.
    vdb_setup.configure_vdb_readonly()
    # A database with no rows answers nothing; a scan must not report zero
    # findings from zero data.
    try:
        vdb_setup.ensure_vdb_usable()
    except vdb_setup.VdbUnusableError as e:
        raise ScanStageError(str(e)) from e


def _excluded_types(args) -> Set[str]:
    """The excluded project types, whatever form the option carries.

    A single comma-separated string is accepted next to the list so a caller
    reusing the environment-variable spellings works unchanged.
    """
    raw = getattr(args, "exclude_types", None) or []
    if isinstance(raw, str):
        raw = raw.split(",")
    return {item.strip() for item in raw if isinstance(item, str) and item.strip()}


def set_project_types(args, src_dir):
    """Detect the project types and perform the right type of scan.

    Types named in the ``exclude_types`` option are removed before the list
    is returned, so no stage ever sees an excluded type: the per-type loop
    scans nothing for it and cdxgen is never asked for its inventory.

    :param args: cli arguments
    :param src_dir: source directory

    :return: A tuple containing the package list, the parsed package URL object,
        and the list of project types.
    """
    pkg_list, purl_obj = [], {}
    project_types_list: List[str] = []
    if args.search_purl:
        purl_obj = parse_purl(args.search_purl)
        purl_obj["purl"] = args.search_purl
        purl_obj["vendor"] = purl_obj.get("namespace")
        if purl_obj.get("type"):
            project_types_list = [purl_obj.get("type", "")]
        pkg_list = [purl_obj]
    elif args.bom or args.bom_dir:
        project_types_list = ["bom"]
    elif args.project_type:
        project_types_list = (
            args.project_type
            if isinstance(args.project_type, list)
            else args.project_type.split(",")
        )
        if len(project_types_list) == 1 and "," in project_types_list[0]:
            project_types_list = project_types_list[0].split(",")
    elif not args.non_universal_scan:
        project_types_list = [UNIVERSAL_SCAN_TYPE]
    else:
        project_types_list = utils.detect_project_type(src_dir)
    excluded = _excluded_types(args)
    if excluded:
        project_types_list = [ptype for ptype in project_types_list if ptype not in excluded]
        if not project_types_list:
            # A scan with no project type left runs zero type scans and its
            # manifest shows no matching, which reads exactly like a clean
            # result. Stop with the reason instead.
            raise ScanStageError(
                "Every project type of this scan was excluded, so there is "
                "nothing to scan. Pass at least one project type that is not "
                f"excluded; the excluded types are {', '.join(sorted(excluded))}."
            )
    return pkg_list, project_types_list


def finalize_setup(ctx):
    """Finish setup once the database is ready: types, paths, sample config."""
    args = ctx.args
    pkg_list, project_types_list = set_project_types(args, ctx.src_dir)
    if args.custom_data:
        LOG.info(f"Loading custom vulnerability data from {args.custom_data}")
        search.load_custom_data(args.custom_data)
    ctx.purl_pkg_list = pkg_list
    if args.search_purl:
        # Automatically enable risk audit for single purl searches
        ctx.perform_risk_audit = True
    ctx.project_types = project_types_list
    # Construct the various report files
    ctx.html_report_file = ctx.depscan_options.get(
        "html_report_file", os.path.join(ctx.reports_dir, "depscan.html")
    )
    ctx.txt_report_file = ctx.depscan_options.get(
        "txt_report_file", os.path.join(ctx.reports_dir, "depscan.txt")
    )
    ctx.llm_prompt_file = ctx.depscan_options.get(
        "llm_prompt_file", os.path.join(ctx.reports_dir, "depscan-prompts.md")
    )
    run_config_file = os.path.join(ctx.reports_dir, "depscan.toml.sample")
    ctx.depscan_options["html_report_file"] = ctx.html_report_file
    ctx.depscan_options["txt_report_file"] = ctx.txt_report_file
    ctx.depscan_options["llm_prompt_file"] = ctx.llm_prompt_file
    # Create reports directory
    if ctx.reports_dir and not os.path.exists(ctx.reports_dir):
        os.makedirs(ctx.reports_dir, exist_ok=True)
    if len(ctx.project_types) > 1:
        LOG.debug("Multiple project types found: %s", ctx.project_types)
    # Enable license scanning
    if "license" in ctx.project_types or "license" in args.profile:
        os.environ["FETCH_LICENSE"] = "true"
        # The license pseudo type names no scan of its own; it only turns the
        # license analysis on. A profile can name license without the type
        # having been detected, so remove it only when it is there.
        if "license" in ctx.project_types:
            ctx.project_types.remove("license")
        log_console.print(
            Panel(
                "License audit is enabled for this scan. This would increase "
                "the time by up to 10 minutes.",
                title="License Audit",
                expand=False,
            )
        )
    _write_sample_config(ctx, run_config_file)


def write_config_file(options: Dict[str, Any], run_config_file: str) -> bool:
    """Write an options dict as a TOML config file, without ``no_banner``.

    The sample config a scan writes and the file ``depscan config init``
    writes are the same document: the effective options minus the banner
    flag. Options whose value is None are dropped by the TOML encoder.
    Returns False when the file could not be written.
    """
    run_config = {**options}
    run_config.pop("no_banner", None)
    try:
        import toml as _toml

        with open(run_config_file, "w") as _fh:
            _fh.write(_toml.dumps(run_config))
    except OSError as exc:
        LOG.debug("Could not write config to %s: %s", run_config_file, exc)
        return False
    LOG.debug(f"Created a depscan config file at '{run_config_file}'.")
    return True


def _write_sample_config(ctx, run_config_file):
    """Write a sample configuration file based on the options in use."""
    if ctx.config_file_mode:
        return
    write_config_file(ctx.depscan_options, run_config_file)


def _prepare_lifecycle_paths(ctx, scan):
    """Decide whether this type runs lifecycle analysis and where its BOMs go.

    Lifecycle analysis writes up to five per-stage documents into the reports
    directory and repurposes an empty ``bom_dir`` as that directory.
    """
    args = ctx.args
    scan.vuln_analyzer = args.vuln_analyzer
    # Reset every per-iteration path. These used to leak from one project
    # type to the next, so a second type could be handed the first type's
    # lifecycle BOM paths.
    scan.bom_dir = ctx.user_bom_dir
    scan.lifecycle_mode = False
    scan.prebuild_bom_file = scan.build_bom_file = scan.postbuild_bom_file = None
    scan.container_bom_file = scan.operations_bom_file = None
    # Are we performing a lifecycle analysis
    if not args.search_purl and (
        scan.vuln_analyzer == "LifecycleAnalyzer"
        or (scan.vuln_analyzer == "auto" and ctx.bom_dir_mode)
    ):
        scan.lifecycle_mode = True
        if args.reachability_analyzer == "SemanticReachability":
            if not scan.bom_dir:
                LOG.info(
                    "Semantic Reachability analysis requested for project type '%s'. This might take a while ...",
                    scan.project_type,
                )
            else:
                LOG.info(
                    "Attempting semantic analysis using existing data at '%s'",
                    scan.bom_dir,
                )
        else:
            LOG.info(
                "Lifecycle-based vulnerability analysis requested for project type '%s'. This might take a while ...",
                scan.project_type,
            )
        reports_dir = ctx.reports_dir
        scan.prebuild_bom_file = os.path.join(
            reports_dir, f"sbom-prebuild-{scan.project_type}.cdx.json"
        )
        scan.build_bom_file = os.path.join(reports_dir, f"sbom-build-{scan.project_type}.cdx.json")
        scan.postbuild_bom_file = os.path.join(
            reports_dir, f"sbom-postbuild-{scan.project_type}.cdx.json"
        )
        # We support only one container SBOM per project.
        # Projects that rely on docker compose and multiple services require some thinking
        scan.container_bom_file = os.path.join(
            reports_dir, f"sbom-container-{scan.project_type}.cdx.json"
        )
        scan.operations_bom_file = os.path.join(
            reports_dir, f"sbom-operations-{scan.project_type}.cdx.json"
        )
        if scan.vuln_analyzer == "auto":
            scan.vuln_analyzer = "LifecycleAnalyzer"
            ctx.depscan_options["vuln_analyzer"] = "LifecycleAnalyzer"
        # We need to set the following two values to make the rest of the code correctly use
        # the generated BOM files after lifecycle analysis
        ctx.depscan_options["lifecycle_analysis_mode"] = True
        if not scan.bom_dir:
            scan.bom_dir = os.path.realpath(reports_dir)


def _generate_boms(ctx, scan):
    """Ask the BOM generator for this type's documents and report what ran.

    ``--fail-on-error`` turns a generator failure into a stopped scan; every
    other path keeps its degrade-and-continue behaviour.
    """
    for bom_dir in {
        os.path.dirname(path)
        for path in (
            scan.target_bom_file,
            scan.prebuild_bom_file,
            scan.build_bom_file,
            scan.postbuild_bom_file,
            scan.container_bom_file,
            scan.operations_bom_file,
        )
        if path
    }:
        remove_stale_slices(scan.project_type, bom_dir, logger=LOG)
        # Tool slices carry the tool's name rather than a project type, so a
        # scan of another type would otherwise read an old one.
        for tool_slice in reachability_slice_files().values():
            tool_slice_path = os.path.join(bom_dir, tool_slice)
            if os.path.isfile(tool_slice_path):
                os.remove(tool_slice_path)
                LOG.debug("Removed the tool slice %s left by a previous run.", tool_slice_path)
    try:
        return create_bom(
            scan.target_bom_file,
            ctx.src_dir,
            {
                **ctx.depscan_options,
                "project_type": [scan.project_type],
                "bom_file": scan.target_bom_file,
                "prebuild_bom_file": scan.prebuild_bom_file,
                "build_bom_file": scan.build_bom_file,
                "postbuild_bom_file": scan.postbuild_bom_file,
                "container_bom_file": scan.container_bom_file,
                "operations_bom_file": scan.operations_bom_file,
                # The reachability runners consult the doctor's capability
                # table through this report instead of probing the tools
                # a second time.
                "doctor_report": ctx.doctor_report,
            },
        )
    except ScanFailureError as e:
        # Only raised when --fail-on-error is set; every other path keeps
        # its degrade-and-continue behaviour.
        LOG.error("%s --fail-on-error is set; aborting the scan.", e)
        raise ScanStageError(f"{e} --fail-on-error is set; aborting the scan.") from e


def _produce_boms(ctx, scan):
    """Generate or collect the BOM documents for this project type.

    :return: True when the type has documents or packages to scan; False when
        the loop should move on to the next type.
    """
    args = ctx.args
    # If the user opts out of lifecycle analysis, we need to maintain multiple SBOMs based on the project type.
    # This is where we *ask* for a BOM to be written. It is an input to the
    # generator, never evidence that a document exists, so nothing below
    # reads it - `bom_files` holds what was actually produced.
    scan.target_bom_file = os.path.join(ctx.reports_dir, f"sbom-{scan.project_type}.cdx.json")
    scan.risk_report_file = os.path.join(ctx.reports_dir, f"depscan-risk-{scan.project_type}.json")
    # Every BOM document available for this project type. An empty list is
    # a normal state (purl scans), not a failure.
    scan.bom_files = []
    # The document a producer explicitly nominates as the project's BOM.
    # Lifecycle runs nominate nothing: no one of their per-stage documents
    # represents the project.
    scan.nominated_bom_file = None
    # Are we scanning a single purl
    if args.search_purl:
        creation_status = True
    # Are we scanning a bom file
    ###################
    # Note to students and researchers benchmarking depscan:
    #   we’ve seen attempts to run depscan using SBOMs generated by tools like Syft, Trivy, etc.
    # It’s important to understand that not all SBOMs contain the same level of detail.
    # Component PURLs can differ slightly, especially in qualifiers.
    #
    # For container SBOMs, qualifiers like distro_name and distro_version are critical for accurate results.
    # Tools like Syft and Trivy often include internal metadata—such as vendor IDs or fabricated CPE strings—to brute-force vulnerability matches.
    # Because of these inconsistencies, it’s not possible to achieve identical results with depscan when using a non-cdxgen or non-blint SBOM.
    # If in doubt, speak to us before benchmarking depscan. Don’t run depscan with default settings and expect magic.
    # SCA and xBOM are complex domains that require understanding, configuration, and continuous learning.
    ###################
    elif args.bom:
        # Existence was validated up front by validate_scan_inputs.
        scan.bom_files = [args.bom]
        scan.nominated_bom_file = args.bom
        creation_status = True
    # Are we scanning a bom directory
    elif ctx.bom_dir_mode:
        creation_status = True
    else:
        # Create a bom for each project type. The generator reports back the
        # documents it wrote, which is not necessarily the path we asked for:
        # lifecycle analysis writes per-stage documents instead.
        bom_result = _generate_boms(ctx, scan)
        creation_status = bom_result.success
        scan.bom_files = list(bom_result.bom_files)
        scan.nominated_bom_file = bom_result.primary
        scan.not_assessed = list(getattr(bom_result, "not_assessed", None) or [])
    if not creation_status:
        LOG.warning(
            "The BOM file `%s` was not created successfully. Set the `SCAN_DEBUG_MODE=debug` environment variable to troubleshoot.",
            scan.target_bom_file,
        )
        scan.inventory_error = (
            f"the BOM for the {scan.project_type} type was not created; the type's "
            "packages were not scanned"
        )
        if ctx.args.fail_on_error:
            LOG.error("--fail-on-error is set; aborting the scan because BOM generation failed.")
            raise ScanStageError(
                "The BOM file was not created successfully and --fail-on-error is set."
            )
        return False
    # A BOM directory supersedes whatever a single run produced: it is the
    # aggregate view, and in lifecycle mode it is where the per-stage
    # documents were written.
    if scan.bom_dir:
        scan.bom_files = get_all_bom_files(scan.bom_dir)
        # Lifecycle mode points bom_dir at the reports directory, which need
        # not hold the BOM the user passed with --bom.
        if args.bom and os.path.realpath(args.bom) not in scan.bom_files:
            scan.bom_files.insert(0, args.bom)
    # The BOM document for this scan: whichever a producer nominated, or -
    # when only one document is available at all - that one, since a lone
    # document is the project's BOM however it got here. None only when
    # several documents exist and none of them is nominated, as with a
    # lifecycle run's per-stage documents.
    scan.bom_file = scan.nominated_bom_file or (
        scan.bom_files[0] if len(scan.bom_files) == 1 else None
    )
    # The report template receives the BOM of the last type that got this
    # far, even when that type is skipped later for having no packages.
    ctx.bom_file = scan.bom_file
    return True


def _load_packages(ctx, scan):
    """Load the package list for this type from its BOM documents.

    :return: True when the type has packages to scan; False when the loop
        should move on to the next type.
    """
    scan.pkg_list = list(ctx.purl_pkg_list)
    # We have a BOM directory. Let’s aggregate all packages from every file within it.
    if scan.bom_dir:
        LOG.debug(
            "Collecting components from all the BOM files at %s",
            scan.bom_dir,
        )
        scan.pkg_list = get_all_pkg_list(scan.bom_dir)
        if ctx.args.bom and os.path.realpath(ctx.args.bom) not in get_all_bom_files(scan.bom_dir):
            seen = {pkg.get("bom-ref") or pkg.get("purl") for pkg in scan.pkg_list}
            user_pkgs, _ = get_pkg_list(ctx.args.bom)
            scan.pkg_list += [
                pkg for pkg in user_pkgs if (pkg.get("bom-ref") or pkg.get("purl")) not in seen
            ]
    # We are working with a single BOM file and will collect all packages from it accordingly.
    elif scan.bom_file:
        LOG.debug("Scanning using the bom file %s", scan.bom_file)
        if not ctx.args.bom:
            LOG.info(
                "To improve performance, cache the bom file and invoke "
                "depscan with --bom %s instead of -i",
                scan.bom_file,
            )
        scan.pkg_list, _ = get_pkg_list(scan.bom_file)
    # An empty package list is reported whatever its source. Matching zero
    # packages would print "No vulnerabilities found", which reads as clean.
    if not scan.pkg_list:
        if ctx.args.fail_on_error:
            LOG.error(
                "No packages were found in the project and --fail-on-error is set; "
                "aborting the scan instead of skipping project type '%s'.",
                scan.project_type,
            )
            raise ScanStageError(
                f"No packages were found for project type '{scan.project_type}' "
                "and --fail-on-error is set."
            )
        LOG.info(
            "No packages were found in the project. Try generating the BOM manually or use the `CdxgenImageBasedGenerator` engine."
        )
        return False
    # Depending on the SBOM tool used, there may be details about component usage and scopes. Let’s analyze and interpret that information.
    scan.scoped_pkgs = get_pkgs_by_scope(scan.pkg_list)
    return True


def stage_inventory(ctx, scan):
    """Produce the BOM documents and package list for one project type.

    :return: True when the type has something to scan; False when the loop
        should move on to the next type.
    """
    _prepare_lifecycle_paths(ctx, scan)
    if not _produce_boms(ctx, scan):
        return False
    return _load_packages(ctx, scan)


def stage_analysis_licenses(ctx, scan) -> bool:
    """Look up license risks, before any security-related analysis.

    Returns False when license analysis was not requested, so the scan's
    manifest can record the stage as skipped rather than silent.
    """
    args = ctx.args
    # Is the user interested in seeing license risks? Handle that first before any security-related analysis.
    if os.getenv("FETCH_LICENSE", "") not in (True, "1", "true") and "license" not in args.profile:
        return False
    licenses_results = bulk_lookup(
        build_license_data(license_data_dir, spdx_license_list),
        pkg_list=scan.pkg_list,
    )
    license_report_file = os.path.join(ctx.reports_dir, f"license-{scan.project_type}.json")
    ltable = licenses_risk_table(scan.project_type, licenses_results, license_report_file)
    if ltable and not args.no_vuln_table:
        console.print(ltable)
    return True


#: The purl types the risk audit reads package-manager metadata for, with
#: the risk_audit_map key that audits them.
RISK_AUDIT_PURL_TYPES = (("npm", "npm"), ("pypi", "pypi"), ("cargo", "cargo"))


def _risk_audit_groups(scan):
    """The (audit type, packages) pairs the risk audit can run on.

    A type the audit knows (npm, python, cargo and their aliases) audits its
    whole package list. Any other type, such as ``universal`` for a source
    scan or ``bom``, audits the packages whose purl type the audit reads.
    """
    if scan.project_type in risk_audit_map:
        return [(scan.project_type, scan.pkg_list)] if scan.pkg_list else []
    groups = []
    for purl_type, audit_type in RISK_AUDIT_PURL_TYPES:
        packages = get_pkg_by_type(scan.pkg_list, purl_type)
        if packages:
            groups.append((audit_type, packages))
    return groups


def stage_analysis_risk(ctx, scan) -> bool:
    """Run the OSS risk audit for the package managers that support it.

    Returns False when the audit did not run. When it was requested but the
    scan holds no npm, PyPI or Cargo packages, ``scan.risk_not_assessed``
    says so, and the stage is recorded as not assessed rather than skipped.
    """
    args = ctx.args
    if not ctx.perform_risk_audit:
        return False
    groups = _risk_audit_groups(scan)
    if not groups:
        scan.risk_not_assessed = (
            f"the risk audit was requested, but the {scan.project_type} scan "
            "has no npm, PyPI or Cargo packages, the only ecosystems it audits"
        )
        return False
    total = sum(len(packages) for _, packages in groups)
    if total > 1:
        log_console.print(
            Panel(
                f"Performing OSS Risk Audit for packages from "
                f"{ctx.src_dir}\nNo of packages [bold]{total}"
                f"[/bold]. This will take a while ...",
                title="OSS Risk Audit",
                expand=False,
            )
        )
    report_rows = []
    try:
        for audit_type, packages in groups:
            risk_results = risk_audit(audit_type, scan.scoped_pkgs, args.private_ns, packages)
            rtable, report_data = pkg_risks_table(
                audit_type,
                scan.scoped_pkgs,
                risk_results,
                pkg_max_risk_score=pkg_max_risk_score,
            )
            if report_data:
                report_rows.extend(report_data)
            if not args.no_vuln_table and report_data and rtable:
                console.print(rtable)
        if report_rows and scan.risk_report_file:
            # The risk audit findings are stored in jsonl format.
            file_write(scan.risk_report_file, "\n".join(json.dumps(row) for row in report_rows))
    except Exception as e:  # noqa: BLE001 - the audit degrades, the scan continues
        LOG.error(e)
        LOG.error("Risk audit was not successful")
        scan.risk_error = f"the risk audit was not successful: {e}"
    return True


def announce_scan_targets(ctx, scan):
    """Log what is about to be searched for this project type."""
    args = ctx.args
    # Remote npm advisory audit was removed: the npmjs security endpoints
    # (/-/npm/v1/security/audits and /-/npm/v1/security/advisories) were
    # permanently retired upstream, so vdb's NpmSource.bulk_search now
    # returns nothing. Those advisories are served from the local VDB via
    # the purl search path instead.
    if len(scan.pkg_list) > 1:
        if scan.project_type == "bom":
            LOG.info("Scanning CycloneDX xBOMs and atom slices")
        elif args.bom:
            LOG.info(
                "Scanning %s with type %s",
                args.bom,
                scan.project_type,
            )
        else:
            LOG.info(
                "Scanning %s with type %s",
                ctx.src_dir,
                scan.project_type,
            )
    # `bom_files` was resolved once, above, from what actually exists.
    if not scan.pkg_list and not scan.bom_files:
        LOG.debug("Empty package search attempted!")
    elif scan.bom_files:
        LOG.debug("Scanning %d bom files for issues", len(scan.bom_files))
    else:
        LOG.debug("Scanning %d oss dependencies for issues", len(scan.pkg_list))


def stage_enrichment(ctx, scan):
    """Run the reachability analyzer and keep its reachable purl maps.

    There are many ways to perform reachability analysis.
    Most tools—including commercial ones—rely on a vulnerability database with affected modules (sinks) to detect reachable flows.
    This has several downsides:
    1. These databases are often incomplete and manually maintained.
    2. If a CVE or ADP enhancement isn’t available yet, reachability won’t be detected.

    In contrast, depscan computes reachable flows (via atom) without relying on vulnerability data upfront.
    It then identifies a smaller subset of those flows that are actually vulnerable.
    From there, we can further narrow it down to flows that are Endpoint-Reachable, Exploitable, Container-Escapable, etc.
    """
    reachability_analyzer = ctx.depscan_options.get("reachability_analyzer")
    reachability_options = None
    if (reachability_analyzer and reachability_analyzer != "off") or ctx.depscan_options.get(
        "profile"
    ) != "generic":
        reachability_options = ReachabilityAnalysisKV(
            project_types=[scan.project_type],
            src_dir=ctx.src_dir,
            bom_dir=scan.bom_dir or ctx.reports_dir,
            require_multi_usage=ctx.depscan_options.get("require_multi_usage", False),
            source_tags=ctx.depscan_options.get("source_tags"),
            sink_tags=ctx.depscan_options.get("sink_tags"),
        )
    scan.reachability_analyzer = reachability_analyzer
    scan.reachability_options = reachability_options
    # We now have reachability results, OpenAPI endpoints, BOMs, and component scope information.
    reach_result = get_reachability_impl(reachability_analyzer, reachability_options).process()
    if reach_result and reach_result.success:
        scan.reachability_succeeded = True
        scan.direct_purls = reach_result.direct_purls
        scan.reached_purls = reach_result.reached_purls
        scan.reached_services = reach_result.reached_services
        scan.endpoint_reached_purls = reach_result.endpoint_reached_purls
    console.record = True


def stage_matching(ctx, scan):
    """Search the vulnerability database for this type's packages."""
    args = ctx.args
    options = VdrAnalysisKV(
        scan.project_type,
        scan.results,
        pkg_aliases={},
        purl_aliases={},
        suggest_mode=args.suggest,
        scoped_pkgs=scan.scoped_pkgs,
        no_vuln_table=args.no_vuln_table,
        bom_file=scan.bom_file,
        bom_dir=scan.bom_dir,
        pkg_list=scan.pkg_list,
        direct_purls=scan.direct_purls,
        reached_purls=scan.reached_purls,
        reached_services=scan.reached_services,
        endpoint_reached_purls=scan.endpoint_reached_purls,
        console=console,
        logger=LOG,
        fuzzy_search=ctx.depscan_options.get("fuzzy_search", False),
        search_order=ctx.depscan_options.get("search_order"),
        severity=ctx.depscan_options.get("severity"),
        malware_only=ctx.depscan_options.get("malware_only", False),
        exclude_malware=ctx.depscan_options.get("exclude_malware", False),
        exploitability_inputs=(
            _exploitability_inputs(ctx, scan) if ctx.grading_rules is not None else None
        ),
    )
    scan.vdr_result = VDRAnalyzer(vdr_options=options).process()


def _exploitability_inputs(ctx, scan):
    """What this scan produced for the exploitability of the findings the
    matching stage is about to grade, for one project type's scan.

    The analyzers named are those the enrichment stage read slices from
    (the manifest's ``completed`` entries); when reachability was off, failed
    or produced no purls, the scope says so and every finding of the type
    records ``reach`` as not assessed. The dosai facts and reachables slices
    are read only when dosai completed for this scan, so a report left by an
    earlier run is never graded on.
    """
    from analysis_lib.findings.exploitability import ExploitabilityInputs
    from analysis_lib.findings.vdr_convert import ReachScope

    options = scan.reachability_options
    analyzers: List[str] = []
    tool_stems = {
        name: file_name.split(".slices", 1)[0]
        for name, file_name in reachability_slice_files().items()
    }
    if options is not None:
        analyzers = [
            entry["name"]
            for entry in scan_directory.analyzer_entries(
                ctx.doctor_report, [scan.project_type], options.slices_files
            )
            if entry.get("status") == "completed"
        ]
    by_analyzer = (
        reached_by_analyzer(options.slices_files, tool_stems) if options is not None else {}
    )
    scope = ReachScope(
        analyzers=analyzers,
        reached=set((scan.reached_purls or {}).keys()),
        succeeded=scan.reachability_succeeded,
        analyzer_types={"atom": by_analyzer.get("atom", {}).get("types", set())},
        reached_by={name: entry["purls"] for name, entry in by_analyzer.items()},
    )
    dosai_facts = None
    dosai_flows: List[Dict] = []
    if "dosai" in analyzers:
        facts_path = os.path.join(
            scan.bom_dir or ctx.reports_dir, "analysis", "dosai", "dotnet-reachability.facts.json"
        )
        if os.path.isfile(facts_path):
            dosai_facts = json_load(facts_path, log=LOG)
        for slice_file in (options.slices_files if options is not None else []) or []:
            if os.path.basename(slice_file).startswith("dotnet-reachables"):
                try:
                    with open(slice_file, encoding="utf-8") as fp:
                        dosai_flows.extend(json.load(fp))
                except (OSError, ValueError) as e:
                    LOG.warning(
                        "The dosai reachables slices %s could not be read: %s", slice_file, e
                    )
    return ExploitabilityInputs(
        rules=ctx.grading_rules,
        scope=scope,
        bom_components=scan.pkg_list,
        dosai_ran="dosai" in analyzers,
        dosai_facts=dosai_facts,
        dosai_flows=dosai_flows,
    )


def _collect_exploitability(ctx, vdr_result):
    """Fold one project type's graded assessments into the scan's mapping.

    A pair several types graded keeps the assessment that assessed more
    axes (reach first, then the count of assessed axes), so a universal
    scan that could not run dosai never overwrites the .NET scan that did;
    on a tie the first type's assessment stays.
    """

    def assessed(exploitability):
        axes = exploitability.axes.to_dict()
        return (
            axes.get("reach") != "not_assessed",
            sum(value != "not_assessed" for value in axes.values()),
        )

    for key, exploitability in (vdr_result.exploitability or {}).items():
        existing = ctx.exploitability.get(key)
        if existing is None or assessed(exploitability) > assessed(existing):
            ctx.exploitability[key] = exploitability


def stage_analysis_vdr(ctx, scan):
    """Write the VDR file and summarize this type's findings.

    Also aggregates the results the report rendering needs across types.
    """
    vdr_result = scan.vdr_result
    pkg_vulnerabilities = []
    summary = {}
    ds_version = get_version()
    # Set vdr_file in report folder
    vdr_file = (
        os.path.join(ctx.reports_dir, os.path.basename(scan.bom_file)) if scan.bom_file else None
    )
    vdr_file = vdr_file.replace(".cdx.json", ".vdr.json") if vdr_file else None
    if not vdr_file and scan.bom_dir:
        vdr_file = os.path.join(scan.bom_dir, DEPSCAN_DEFAULT_VDR_FILE)
    scan.vdr_file = vdr_file
    if vdr_result.success:
        pkg_vulnerabilities = vdr_result.pkg_vulnerabilities
        cdx_vdr_data = None
        # Always create VDR files even when empty
        if pkg_vulnerabilities is not None:
            # Case 1: Single BOM file resulting in a single VDR file
            if scan.bom_file:
                cdx_vdr_data = json_load(scan.bom_file, log=LOG)
            # Case 2: Multiple BOM files in a bom directory (e.g. lifecycle
            # analysis). Use the max specVersion across those SBOMs, falling
            # back to the user's --spec-version and then the default.
            elif scan.bom_dir:
                lifecycle_spec_version = determine_spec_version(
                    get_all_bom_files(scan.bom_dir),
                    fallback=ctx.depscan_options.get("spec_version"),
                )
                cdx_vdr_data = create_empty_vdr(
                    scan.pkg_list, ds_version, spec_version=lifecycle_spec_version
                )
        if cdx_vdr_data:
            export_bom(cdx_vdr_data, ds_version, pkg_vulnerabilities, vdr_file)
            LOG.debug(f"The VDR file '{vdr_file}' was created successfully.")
        else:
            LOG.debug(f"VDR file '{vdr_file}' was not created for the type {scan.project_type}.")
        summary = summary_stats(pkg_vulnerabilities)
    elif scan.bom_dir or scan.bom_file or scan.pkg_list:
        if scan.project_type != "bom":
            LOG.info("No vulnerabilities found for project type '%s'!", scan.project_type)
        else:
            LOG.info("No vulnerabilities found!")
    scan.summary = summary
    if vdr_result.pkg_vulnerabilities:
        ctx.all_pkg_vulnerabilities += vdr_result.pkg_vulnerabilities
        _collect_exploitability(ctx, vdr_result)
        grade_stats = exploitability_grade_stats(vdr_result.exploitability)
        if grade_stats:
            console.print(
                "Exploitability grades for project type '{}': {}".format(
                    scan.project_type,
                    ", ".join(f"{name}: {count}" for name, count in grade_stats.items()),
                )
            )
    if vdr_result.prioritized_pkg_vuln_trees:
        ctx.all_pkg_group_rows.update(vdr_result.prioritized_pkg_vuln_trees)
    ctx.summary = summary
    ctx.vdr_file = vdr_file


def stage_render_explain(ctx, scan):
    """Explain the results and export CSAF VEX for this project type."""
    args = ctx.args
    # Explain the results
    if args.explain:
        explainer.explain(
            scan.project_type,
            ctx.src_dir,
            scan.bom_dir or ctx.reports_dir,
            scan.vdr_file,
            scan.vdr_result,
            args.explanation_mode,
            ctx.depscan_options["llm_prompt_file"],
        )
    else:
        LOG.debug("Pass the `--explain` argument to get a detailed explanation of the analysis.")
    # CSAF VEX export
    if not args.csaf:
        return
    # Prefer the project BOM so the output is named after the project
    # (<base>.csaf.json) and the product tree is built from it. Fall
    # back to the VDR (also a CycloneDX document), which the analysis
    # may not have written either. The emit layer guarantees the VDR is
    # never overwritten.
    csaf_bom_file = scan.bom_file or (
        scan.vdr_file if scan.vdr_file and os.path.exists(scan.vdr_file) else None
    )
    if not csaf_bom_file:
        LOG.warning(
            "CSAF export skipped for project type '%s': no readable BOM or "
            "VDR file is available to name the output and build the product tree.",
            scan.project_type,
        )
        return
    csaf_file, _csaf_errors = export_csaf(
        scan.vdr_result,
        src_dir=ctx.src_dir,
        reports_dir=ctx.reports_dir,
        bom_file=csaf_bom_file,
        csaf_version=getattr(args, "csaf_version", "2.1"),
    )
    # A failed export must never look like a successful one.
    if not csaf_file:
        LOG.warning(
            "CSAF export failed for project type '%s' using `%s`.",
            scan.project_type,
            csaf_bom_file,
        )


def stage_render_reports(ctx):
    """Export the console output and render every report file."""
    args = ctx.args
    console.record = True
    # Export the console output
    console.save_html(
        ctx.html_report_file,
        clear=False,
        theme=(MONOKAI if os.getenv("USE_DARK_THEME") else DEFAULT_TERMINAL_THEME),
    )
    console.save_text(ctx.txt_report_file, clear=False)
    # Prettify the rich html report
    html_report_generator = ReportGenerator(
        input_rich_html_path=ctx.html_report_file,
        report_output_path=ctx.html_report_file,
        raw_content=False,
    )
    html_report_generator.parse_and_generate_report()
    # This logic needs refactoring
    # render report into template if wished
    if args.report_template and os.path.isfile(args.report_template):
        utils.render_template_report(
            vdr_file=ctx.vdr_file,
            bom_file=ctx.bom_file,
            pkg_vulnerabilities=ctx.all_pkg_vulnerabilities,
            pkg_group_rows=ctx.all_pkg_group_rows,
            summary=ctx.summary,
            template_file=args.report_template,
            result_file=os.path.join(ctx.reports_dir, args.report_name),
            depscan_options=ctx.depscan_options,
        )
    elif args.report_template:
        LOG.warning(
            "Template file %s doesn't exist, custom report not created.",
            args.report_template,
        )
    # Should we include the generated text report as an annotation in the VDR file?
    if args.explain or args.annotate:
        annotate_vdr(ctx.vdr_file, ctx.txt_report_file)
