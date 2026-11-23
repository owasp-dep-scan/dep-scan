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
import glob
import json
import os
import secrets
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Set, Tuple

if TYPE_CHECKING:
    from analysis_lib.evidence.adapters import AdapterResult

from analysis_lib import ReachabilityAnalysisKV, VdrAnalysisKV, get_all_bom_files
from analysis_lib.output import (
    exploitability_grade_stats,
    licenses_risk_table,
    pkg_risks_table,
    summary_stats,
)
from analysis_lib.packages import get_all_pkg_list, get_pkg_list
from analysis_lib.evidence import store as evidence_store
from analysis_lib.evidence.adapters import bom_tool_version
from analysis_lib.reachability import get_reachability_impl
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
from depscan.lib import binary_review, explainer, utils
from depscan.lib import doctor as doctor_lib
from depscan.lib import logger as logger_lib
from depscan.lib import scan_directory, vdb_setup
from depscan.lib.audit import risk_audit, risk_audit_map
from depscan.lib.bom import (
    ScanFailureError,
    annotate_vdr,
    blint_reviews_requested,
    clear_tool_outputs,
    create_bom,
    create_empty_vdr,
    determine_spec_version,
    discover_reachability_reports,
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

#: The producers whose adapters the reachability engine grades on. Their
#: results drive the reach scope, the manifest's analyzer entries and the
#: store's reachability records; the order fixes the analyzers list.
REACHABILITY_PRODUCERS = ("atom", "rusi", "golem", "kosi", "dosai")

#: The producers whose adapters collect evidence without grading
#: reachability: the BOM's own usage evidence and annotations (cdxgen), the
#: binary review (blint) and the runtime trace (tracebom). Their records
#: reach the evidence store and the exploitability inputs, and nothing else:
#: they are not reachability analyzers, so the manifest's analyzer entries
#: never list them and their records never count as reached.
EVIDENCE_PRODUCERS = ("blint", "cdxgen", "tracebom")

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
    #: The evidence adapter result of every producer that produced records or
    #: read a report for this type, keyed by producer name: the reachability
    #: analyzers from the BOM step and this stage, and the evidence producers
    #: (blint, cdxgen, tracebom) from this stage. The analyzer entries read
    #: only the reachability names; the store write and the exploitability
    #: inputs read them all.
    adapter_results: Dict[str, "AdapterResult"] = field(default_factory=dict)
    #: cdxgen's adapter result of each BOM document, keyed by the path the
    #: inventory stage listed it under.
    cdxgen_reads: Dict[str, "AdapterResult"] = field(default_factory=dict)
    #: For each BOM document in ``cdxgen_reads``, the keys (``bom-ref``, else
    #: purl) and the comparable purls of the components of that document the
    #: loaders keep, assessed or refused alike. A document whose result was
    #: not completed owes every loaded package these name a reason in
    #: ``ScanContext.usage_not_assessed``.
    cdxgen_document_keys: Dict[str, Tuple[Set[str], Set[str]]] = field(default_factory=dict)
    #: How many cdxgen usage records of this type matched no loaded component
    #: and therefore graded nothing; the matching stage's manifest entry
    #: carries the count as a not-assessed line.
    ungraded_usage_records: int = 0
    #: The BOM documents cdxgen wrote with an introspection score below its
    #: gate (exit status 4); their fidelity tier is logged from the
    #: introspection records.
    introspection_gate_missed: List[str] = field(default_factory=list)
    #: Each BOM document of this type parsed once, keyed by path: the parsed
    #: value, or the text when it is not JSON, or None when it is unreadable.
    #: Emptied once the type's evidence producers have read them.
    bom_documents: Dict[str, Any] = field(default_factory=dict, repr=False)
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
    #: The directory the reachability reports' file paths are relative to,
    #: or None when the scan does not know it. A scan that ran the tools
    #: knows: it is the source directory they scanned. A scan of stored BOMs
    #: and slices knows only when the user named the source directory.
    source_root: Optional[str] = None
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
    #: The evidence records this scan's adapters built, in arrival order, so
    #: a scan of several project types rewrites the store once per type
    #: holding every type's records without reading the previous file back.
    #: A record that arrives again is kept again; the store's write rules
    #: fold the copies (and merge their caveats) at write time.
    evidence_records: List = field(default_factory=list)
    #: The Python object ids of the records already in ``evidence_records``,
    #: so a result shared by several types is added once.
    evidence_record_objects: Set[int] = field(default_factory=set)
    #: Why a package's usage evidence was not assessed, keyed by comparable
    #: purl: the reason cdxgen's adapter gave for not assessing a BOM
    #: document that names the package. Every graded finding of such a
    #: package carries the reason in its coverage, proven presence included,
    #: so a finding that graded on another BOM's records still names the BOM
    #: that was not read.
    usage_not_assessed: Dict[str, str] = field(default_factory=dict)
    #: atom's adapter results, one per group of atom output files read
    #: together, keyed by the group's sorted resolved paths. A file is read
    #: once per scan, by the first project type whose enrichment finds it,
    #: with that type's run markers (an atom timeout) as caveats; later types
    #: reuse the group's records instead of reading the file again.
    atom_results: Dict[Tuple[str, ...], "AdapterResult"] = field(default_factory=dict)
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
    ctx.source_root = _source_root(args, src_dir)
    if not (args.bom_dir or getattr(args, "bom", None) or args.search_purl):
        # A source scan generates its BOM and the language tools' slices in
        # the reports directory; files an earlier run left there would read
        # as this scan's reachability and exposure evidence.
        clear_tool_outputs(reports_dir)
    _clear_evidence_store(reports_dir)
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


def _reads_stored_analysis(args) -> bool:
    """Whether the scan reads BOMs and slices an earlier run wrote (a BOM
    directory or a BOM file) instead of running cdxgen and the tools."""
    return bool(getattr(args, "bom_dir", None) or getattr(args, "bom", None))


def _source_root(args, src_dir) -> Optional[str]:
    """The source directory the reports' file paths are relative to.

    A scan that runs cdxgen scans ``src_dir``, so that is the root. A scan
    of stored BOMs and slices was not run here: the source directory option
    defaults to the working directory, which says nothing about where the
    data was generated, so the root is known only when the user named it,
    on the command line or through ``DEPSCAN_SOURCE_DIR_IMAGE``. Without a
    root the adapters keep each path in their outside-root form, and dosai
    uses the input path its report states. A ``--src`` that names the
    working directory itself reads the same as no ``--src``. The root is
    absolute: a relative ``--src`` resolves against the working directory,
    the directory the tools resolved it against. A target that is a single
    file (a binary) is reported by the directory that holds it, so the root
    is that directory and the file is spelled by its base name.
    """
    if not _reads_stored_analysis(args):
        return _root_directory(src_dir)
    given = args.src_dir_image
    if os.getenv("DEPSCAN_SOURCE_DIR_IMAGE") or given == ".":
        return _root_directory(src_dir)
    if given and os.path.abspath(given) != os.getcwd():
        return _root_directory(src_dir)
    return None


def _root_directory(src_dir) -> Optional[str]:
    """``src_dir`` as an absolute directory: the directory that holds it
    when it names a file."""
    if not src_dir:
        return None
    root = os.path.abspath(src_dir)
    return os.path.dirname(root) if os.path.isfile(root) else root


def _clear_evidence_store(reports_dir) -> None:
    """Remove the evidence store and its index an earlier scan left in the
    reports directory.

    The store is written from this scan's adapter results alone, by the
    enrichment stage of each project type. A scan where no type reaches that
    stage (every type skipped inventory, say) writes no store, and the
    files of an earlier scan must not then be indexed and listed in the
    manifest as this scan's evidence. Every scan mode clears them, the BOM
    directory modes included, because the reports directory of those is
    often the BOM directory an earlier scan wrote into.
    """
    if not reports_dir:
        return
    for name in (scan_directory.EVIDENCE_FILE, scan_directory.EVIDENCE_INDEX_FILE):
        path = os.path.join(str(reports_dir), name)
        try:
            os.remove(path)
        except FileNotFoundError:
            continue
        except OSError as e:
            raise ScanStageError(
                f"The evidence file {path} an earlier scan left could not be removed: {e}"
            ) from e


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
    """Write the findings file, the evidence index, and then the manifest, in
    that order.

    The index is built from the store the enrichment stage wrote and the
    findings just written, so it lands after both exist. The manifest is
    written last, through a temporary file and a rename, so it lists only
    files that exist, the evidence files included. A scan that stopped
    partway still gets one, carrying the failed stage and its reason.
    Returns the manifest and the findings array, or None when this run
    writes no scan directory.
    """
    scan_dir = ctx.scan_dir
    if scan_dir is None:
        return None
    findings_document = scan_directory.write_findings(
        ctx.reports_dir,
        ctx.all_pkg_vulnerabilities,
        get_version(),
        exploitability=ctx.exploitability,
        blint_reviews=any(
            blint_reviews_requested({**ctx.depscan_options, "project_type": [project_type]})
            for project_type in (ctx.project_types or [None])
        ),
        evidence_records=ctx.evidence_records,
        usage_not_assessed=ctx.usage_not_assessed,
    )
    evidence_path = os.path.join(str(ctx.reports_dir), scan_directory.EVIDENCE_FILE)
    if os.path.isfile(evidence_path):
        index = evidence_store.build_index(
            evidence_store.read(evidence_path), findings_document["findings"]
        )
        evidence_store.write_index(
            os.path.join(str(ctx.reports_dir), scan_directory.EVIDENCE_INDEX_FILE), index
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
        # No tool runs for a BOM directory: every adapter looks for its known
        # raw report names in the directory before giving up as not assessed.
        scan.adapter_results = discover_reachability_reports(
            scan.bom_dir or ctx.reports_dir,
            [scan.project_type],
            {**ctx.depscan_options, "doctor_report": ctx.doctor_report},
            bom_files=get_all_bom_files(scan.bom_dir) if scan.bom_dir else [],
            source_root=ctx.source_root,
        )
    else:
        # Create a bom for each project type. The generator reports back the
        # documents it wrote, which is not necessarily the path we asked for:
        # lifecycle analysis writes per-stage documents instead.
        bom_result = _generate_boms(ctx, scan)
        creation_status = bom_result.success
        scan.bom_files = list(bom_result.bom_files)
        scan.nominated_bom_file = bom_result.primary
        scan.not_assessed = list(getattr(bom_result, "not_assessed", None) or [])
        scan.introspection_gate_missed = list(
            getattr(bom_result, "introspection_gate_missed", None) or []
        )
        scan.adapter_results = dict(getattr(bom_result, "adapter_results", None) or {})
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


def _component_key(component) -> Optional[str]:
    """The key the package loader tells components apart by: the
    ``bom-ref``, else the purl."""
    key = component.get("bom-ref") or component.get("purl")
    return key if isinstance(key, str) and key else None


def _document_component_keys(document) -> Tuple[Set[str], Set[str]]:
    """The keys and the comparable purls of the components of one BOM
    document the loaders keep.

    A document the cdxgen adapter did not assess still names the packages
    it would have contributed, and the loaded packages it names are the
    ones its refusal owes a reason to; the walk is the loader's own filter,
    so the named set is exactly what a load of the document would keep. A
    document that is not a JSON object names nothing."""
    from analysis_lib.findings.vdr_convert import comparable_purl
    from analysis_lib.packages import bom_components

    keys = set()
    purls = set()
    for component in bom_components(document):
        key = _component_key(component)
        if key:
            keys.add(key)
        purl = component.get("purl")
        if isinstance(purl, str) and purl:
            purls.add(comparable_purl(purl))
    return keys, purls


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
            seen = {_component_key(pkg) for pkg in scan.pkg_list}
            user_pkgs, _ = get_pkg_list(ctx.args.bom)
            appended = [pkg for pkg in user_pkgs if _component_key(pkg) not in seen]
            scan.pkg_list += appended
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
    loaded = False
    try:
        if not _produce_boms(ctx, scan):
            return False
        loaded = _load_packages(ctx, scan)
        return loaded
    finally:
        _collect_inventory_evidence(ctx, scan, write_store=not loaded)


def _collect_inventory_evidence(ctx, scan, write_store: bool) -> None:
    """Run the evidence producers' adapters over what the inventory stage
    produced, right after it ran.

    cdxgen's BOMs, blint's review reports and the trace BOMs are read here
    rather than in the enrichment stage, so a type that never reaches
    enrichment (a blint-written BOM listing no components, a failed BOM
    generation) still has its review findings and records. ``write_store``
    writes the evidence store at once for such a type; otherwise the
    enrichment stage writes it with the reachability records and releases
    the parsed BOM documents once atom's adapter has read its version from
    them. A failure here is logged and never replaces the error that
    stopped the stage.
    """
    try:
        _collect_evidence_records(ctx, scan)
        if write_store and any(
            scan.adapter_results.get(name) is not None and scan.adapter_results[name].records
            for name in EVIDENCE_PRODUCERS
        ):
            _write_evidence_store(
                ctx,
                os.path.join(ctx.reports_dir, scan_directory.EVIDENCE_FILE),
                scan.adapter_results,
            )
    except Exception as e:  # noqa: BLE001 - the stage's own outcome wins
        LOG.warning(
            "The evidence of project type '%s' could not be collected: %s", scan.project_type, e
        )
    if write_store:
        # No enrichment stage follows to read the parsed documents.
        scan.bom_documents = {}


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
            # The risk audit findings are stored as one JSON array of rows.
            file_write(scan.risk_report_file, json.dumps(report_rows, indent=2))
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
    """Run the reachability adapters, write their records into the evidence
    store, and let the engine count the reached purl maps from it.

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
    evidence_file = os.path.join(ctx.reports_dir, scan_directory.EVIDENCE_FILE)
    adapters_run = bool(reachability_analyzer) and reachability_analyzer != "off"
    if (reachability_analyzer and reachability_analyzer != "off") or ctx.depscan_options.get(
        "profile"
    ) != "generic":
        # The store lives at the top of the scan directory, so the manifest
        # lists it and a later read finds it where the scan wrote it.
        reachability_options = ReachabilityAnalysisKV(
            project_types=[scan.project_type],
            src_dir=ctx.src_dir,
            bom_dir=scan.bom_dir or ctx.reports_dir,
            require_multi_usage=ctx.depscan_options.get("require_multi_usage", False),
            source_tags=ctx.depscan_options.get("source_tags"),
            sink_tags=ctx.depscan_options.get("sink_tags"),
            evidence_file=evidence_file,
            source_root=ctx.source_root,
        )
    if adapters_run and reachability_options is not None:
        # atom's slices are its own native output; its adapter runs here, over
        # the slices and OpenAPI files the scan holds. The language tools'
        # results are already on the type scan from the BOM step.
        scan.adapter_results["atom"] = _atom_adapter_result(ctx, scan, reachability_options)
    # The evidence producers ran in the inventory stage whatever the
    # reachability setting: the BOM's own usage evidence drives the presence
    # axis even when nothing grades reach, so a scan with reachability off
    # still writes a store holding the inventory records, and never one
    # holding a reachability producer's.
    _write_evidence_store(ctx, evidence_file, scan.adapter_results)
    scan.bom_documents = {}
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


def _atom_adapter_result(ctx, scan, options):
    """atom's adapter result for this project type.

    atom's slices are its native output: every reachables slices file the
    language tools do not claim is atom's, as are the usages and callsites
    slices and the OpenAPI documents. The producer version comes from the
    atom that wrote the slices (:func:`_atom_producer_version`). Each
    record's ``source`` is the file's path
    relative to the directory the slices were found in, the BOM directory
    the other adapters' sources are relative to too, and the file names atom
    wrote are made relative to the scan's source root
    (:func:`_source_root`); without one, and for a path outside it, the
    adapter keeps its outside-root form, never an absolute path.
    When the scan holds no atom output at all the
    result is not assessed, with the doctor's reason when the capability is
    unavailable on this machine and the adapter's otherwise.

    Each file is read once per scan. The files no earlier project type read
    are read together, with this type's run markers (an atom run a timeout
    stopped) as timeout caveats, so the caveats stay on the records of the
    files the timed-out run wrote. The result for this type combines every
    group of files it covers: completed when every group completed, else the
    first group's not-assessed reason.
    """
    from analysis_lib.evidence.adapters import AdapterResult, not_assessed
    from analysis_lib.evidence.adapters import atom as atom_adapter

    stems = tuple(
        file_name.split(".slices", 1)[0] for file_name in reachability_slice_files().values()
    )
    roles: Dict[str, str] = {}
    for path in options.slices_files or []:
        name = os.path.basename(path)
        if "reachables.slices" in name and not name.startswith(stems):
            roles[os.path.realpath(path)] = "reachables"
        elif "usages.slices" in name:
            roles[os.path.realpath(path)] = "usages"
        elif "callsites.slices" in name:
            roles[os.path.realpath(path)] = "callsites"
    for path in options.openapi_spec_files or []:
        roles.setdefault(os.path.realpath(path), "openapi")
    read_before = {path for group in ctx.atom_results for path in group}
    fresh = tuple(sorted(path for path in roles if path not in read_before))
    if fresh:

        def of_role(role):
            return [path for path in fresh if roles[path] == role]

        ctx.atom_results[fresh] = atom_adapter.extract(
            of_role("reachables"),
            producer_version=_atom_producer_version(ctx, scan, options),
            usages_files=of_role("usages"),
            callsites_files=of_role("callsites"),
            openapi_files=of_role("openapi"),
            timeout_reasons=[reason for reason in scan.not_assessed if reason],
            scan_dir=options.bom_dir,
            source_root=ctx.source_root,
        )
    groups = [result for group, result in ctx.atom_results.items() if roles.keys() & set(group)]
    if not groups:
        # No atom output at all: the doctor's reason, when it explains why
        # (cdxgen missing on this machine), says more than the adapter's.
        reason = None
        if ctx.doctor_report is not None:
            reason = doctor_lib.capability_unavailable_reason(
                doctor_lib.ANALYZER_CAPABILITIES["atom"],
                ctx.doctor_report.tools_by_name(),
                ctx.doctor_report.data,
            )
        result = not_assessed(reason) if reason else atom_adapter.extract([])
    else:
        refused = next((result for result in groups if result.status != "completed"), None)
        if refused is not None:
            result = refused
        else:
            caveats = []
            for group in groups:
                caveats.extend(c for c in group.caveats if c not in caveats)
            result = AdapterResult(
                status=groups[0].status,
                records=[record for group in groups for record in group.records],
                caveats=caveats,
            )
    if result.status != "completed":
        LOG.warning("atom reachability was not assessed: %s", result.reason)
    return result


def _atom_producer_version(ctx, scan, options) -> str:
    """The version of the atom that wrote this scan's slices.

    A scan that ran cdxgen had the atom the doctor found write them. Slices
    stored by an earlier run were written by whatever atom that run had: the
    BOM names it in ``metadata.tools`` when cdxgen recorded its version, and
    otherwise nothing names it, so no version is given and the records carry
    a ``schema-unknown`` caveat rather than being gated on the local atom.
    """
    if not _reads_stored_analysis(ctx.args):
        return _doctor_analyzer_version("atom", ctx)
    for bom_file in options.bom_files or []:
        version = bom_tool_version(_bom_document(scan, bom_file), "atom")
        if version:
            return version
    return ""


def _bom_document(scan, path: str) -> Any:
    """One BOM document of this type, parsed once per type.

    The value is the parsed JSON, or the file's text when it is not JSON
    or nests deeper than the parser reaches (so cdxgen's adapter reports
    the failure as not assessed), or None when the file cannot be read. The inventory stage's evidence producers all
    read through here, so a large BOM is parsed once however many of them
    need it."""
    key = str(path)
    if key not in scan.bom_documents:
        text = _read_report_text(key)
        value: Any = text
        if text is not None:
            try:
                value = json.loads(text)
            except (ValueError, RecursionError):
                value = text
        scan.bom_documents[key] = value
    return scan.bom_documents[key]


def _doctor_analyzer_version(analyzer: str, ctx) -> str:
    """The version the doctor report read for an analyzer, or the empty
    string when there is no report or no status."""
    if ctx.doctor_report is None:
        return ""
    status = (ctx.doctor_report.tools_by_name() or {}).get(analyzer)
    return str(status.version or "") if status is not None else ""


def _collect_evidence_records(ctx, scan) -> None:
    """Run every evidence producer's adapter for this project type and keep
    the results beside the reachability adapters'."""
    for name, collect in (
        ("cdxgen", _cdxgen_adapter_result),
        ("blint", _blint_adapter_result),
        ("tracebom", _tracebom_adapter_result),
    ):
        result = collect(ctx, scan)
        if result is not None:
            scan.adapter_results[name] = result


def _record_source(path: str, base: str) -> str:
    """A report file's record source: its path relative to ``base``, the
    directory the other adapters' sources are relative to, and its base name
    when it sits outside it, so no source is ever absolute or climbs out.
    The reachability engine finds a BOM's occurrence records by the same
    spelling."""
    from analysis_lib.reachability import report_source

    return report_source(path, base)


def _read_report_text(path: str) -> Optional[str]:
    """A report file's text, or None when there is no readable file.

    A file that exists but cannot be read, or is not UTF-8 text (a binary or
    mislabelled file a discovery walk may open before any adapter guards
    it), is logged and read as absent: the adapter that would have read it
    then reports nothing rather than failing the scan, and the warning names
    what was lost."""
    try:
        with open(path, encoding="utf-8") as fp:
            return fp.read()
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as e:
        LOG.warning("The report %s could not be read and was not assessed: %s", path, e)
        return None


def _merge_adapter_results(reads: List[Tuple[str, Any]]):
    """One adapter result for a producer that read several documents, from
    the ``(source, result)`` pair of each read.

    A document the adapter refused costs its own records and no others: the
    healthy documents' records survive, each carrying a ``record-skipped``
    caveat naming the refused file and the reason, so one damaged BOM in a
    directory of healthy ones never silently zeroes the rest. Only when
    every read refused does the producer read as not assessed, with the
    first refusal's reason. The surviving records concatenate and the
    caveats keep first-seen order."""
    from analysis_lib.evidence import EvidenceCaveat
    from analysis_lib.evidence.adapters import AdapterResult, add_caveat

    if len(reads) == 1:
        return reads[0][1]
    refused = [(source, result) for source, result in reads if result.status != "completed"]
    if len(refused) == len(reads):
        return refused[0][1]
    records = []
    caveats = []
    for result in (result for _, result in reads if result.status == "completed"):
        caveats.extend(caveat for caveat in result.caveats if caveat not in caveats)
        records.extend(result.records)
    for source, result in refused:
        detail = (
            f"the report {source} was not assessed and its records were skipped: {result.reason}"
        )
        caveats.append(EvidenceCaveat(kind="record-skipped", detail=detail))
        for record in records:
            add_caveat(record, "record-skipped", detail)
    return AdapterResult(status="completed", records=records, caveats=caveats)


def _cdxgen_adapter_result(ctx, scan):
    """cdxgen's BOM evidence as records: one adapter call per BOM document
    the inventory stage listed for this type.

    The documents are the ones the inventory stage settled on, a BOM
    directory's BOM files or the type's own BOM, and each carries the
    build-introspection report that sits beside it
    (``<bom>.introspection.json``, cdxgen's own naming). The adapter runs
    whatever the reachability setting, because the presence axis reads the
    usage records of every document it assesses on every scan type (see
    :func:`_exploitability_inputs`); every document's records reach the
    store. Each document's result is kept in ``scan.cdxgen_reads`` and the
    keys and comparable purls of the components of it the loaders keep in
    ``scan.cdxgen_document_keys``, assessed or refused alike. A BOM the
    adapter refuses is logged with the reason and costs its own records
    alone, so the healthy documents' records survive. For a BOM cdxgen
    wrote with an introspection score below its gate, the fidelity tier
    and score are logged from the introspection record.
    """
    from analysis_lib.evidence.adapters import cdxgen as cdxgen_adapter

    base = scan.bom_dir or ctx.reports_dir
    gate_missed = {os.path.realpath(path) for path in scan.introspection_gate_missed}
    reads = []
    for bom_file in scan.bom_files or []:
        if os.path.basename(str(bom_file)).endswith(".introspection.json"):
            # The introspection report of the BOM beside it, not a BOM: it
            # reaches this list because its name contains "bom" and it is
            # handed to that BOM's call instead.
            continue
        document = _bom_document(scan, bom_file)
        if document is None:
            continue
        scan.cdxgen_document_keys[str(bom_file)] = _document_component_keys(document)
        source = _record_source(bom_file, base)
        introspection_file = f"{bom_file}.introspection.json"
        introspection = _read_report_text(introspection_file)
        introspection_source = (
            _record_source(introspection_file, base) if introspection is not None else ""
        )
        read = cdxgen_adapter.extract(
            document,
            source=source,
            introspection=introspection,
            introspection_source=introspection_source,
            source_root=ctx.source_root,
        )
        scan.cdxgen_reads[str(bom_file)] = read
        reads.append((source, read))
        if os.path.realpath(bom_file) in gate_missed:
            _log_introspection_tier(read, introspection_source, introspection_file)
    if not reads:
        return None
    for source, read in reads:
        if read.status != "completed":
            LOG.warning("cdxgen evidence from %s was not assessed: %s", source, read.reason)
    result = _merge_adapter_results(reads)
    if result.status == "completed":
        LOG.debug(
            "cdxgen evidence: the adapter built %d records from %d BOM document(s)",
            len(result.records),
            len(reads),
        )
    return result


def _log_introspection_tier(read, introspection_source: str, introspection_file: str) -> None:
    """Log the fidelity tier and score of one BOM from the introspection
    record cdxgen's adapter built for it."""
    overall = None
    if introspection_source:
        for record in read.records:
            if record.kind == "introspection" and record.source == introspection_source:
                candidate = (record.attributes or {}).get("overall")
                overall = candidate if isinstance(candidate, dict) else None
                break
    if overall:
        LOG.warning(
            "Introspection: overall tier %s, score %s/100 (report: %s).",
            overall.get("tier"),
            overall.get("score"),
            introspection_file,
        )
    else:
        LOG.warning("Introspection report %s was missing or unreadable.", introspection_file)


def _blint_adapter_result(ctx, scan):
    """blint's review reports as evidence records, or None when this scan
    holds none of its documents.

    A scan that requested the review reads the reports the review wrote
    under ``analysis/blint/`` beside the BOM (they are fresh: the review
    removes stale copies before it starts). A BOM directory scan also reads
    the reports an earlier run left there, the way it reads the language
    tools' raw reports; a source scan that did not ask for the review reads
    nothing, so an earlier run's reports never stand in for this scan's. The
    producer version is the one the blint-written BOM's ``metadata.tools``
    names; the locally installed blint is never asked. ``source_root`` is
    the source directory blint reviewed.
    """
    from analysis_lib.evidence.adapters import blint as blint_adapter

    base = scan.bom_dir or ctx.reports_dir
    directory = os.path.join(base, scan_directory.ANALYSIS_DIR, "blint")
    documents = {}
    for key, name in (
        ("findings", "findings.json"),
        ("reviews", "reviews.json"),
        ("coverage", "analysis-coverage.json"),
    ):
        text = _read_report_text(os.path.join(directory, name))
        if text is not None:
            documents[key] = text
    if not documents:
        return None
    requested = blint_reviews_requested(
        {**ctx.depscan_options, "project_type": [scan.project_type]}
    )
    if not requested and not ctx.bom_dir_mode:
        return None

    def source_of(name: str) -> str:
        return _record_source(os.path.join(directory, name), base)

    result = blint_adapter.extract(
        documents.get("findings"),
        source=source_of("findings.json") if "findings" in documents else "",
        producer_version=_blint_bom_version(scan),
        reviews_document=documents.get("reviews"),
        reviews_source=source_of("reviews.json") if "reviews" in documents else None,
        coverage_document=documents.get("coverage"),
        coverage_source=source_of("analysis-coverage.json") if "coverage" in documents else None,
        bom_components=scan.pkg_list,
        extra_components=_bom_metadata_components(scan),
        source_root=ctx.source_root,
    )
    if result.status != "completed":
        LOG.warning("blint evidence was not assessed: %s", result.reason)
    else:
        LOG.debug(
            "blint evidence: the adapter built %d records from %s", len(result.records), directory
        )
    return result


def _blint_bom_version(scan) -> str:
    """The blint version this scan's blint-written BOM names in its
    ``metadata.tools``, or the empty string when no BOM names one.

    The blint-written BOM is the one blint's sbom mode produced. On a scan
    that ran blint it is this scan's own BOM; on a BOM directory scan it is
    the ``sbom-postbuild-*`` document the directory holds. The locally
    installed blint package is never asked: the BOM's own statement is the
    version the records are versioned with."""
    for bom_file in scan.bom_files or []:
        version = bom_tool_version(_bom_document(scan, bom_file), "blint")
        if version:
            return version
    return ""


#: How deep :func:`_bom_metadata_components` follows nested components
#: below a root component; deeper nesting is not a shape blint writes.
_ROOT_COMPONENT_DEPTH = 8


def _bom_metadata_components(scan) -> List[Dict]:
    """The root ``metadata.component`` of this type's BOM documents and the
    components nested below it.

    The package loader walks past them by design, but a binary scan's BOM
    names the scanned binaries there, which are exactly the components a
    blint finding's binary reconciles to: a single-file target is the root
    component itself, and a directory target lists each binary as a
    component nested in the root. The walk stops at
    :data:`_ROOT_COMPONENT_DEPTH` levels and visits each object once."""
    components = []
    seen = set()
    for bom_file in scan.bom_files or []:
        if os.path.basename(str(bom_file)).endswith(".introspection.json"):
            continue
        data = _bom_document(scan, bom_file)
        metadata = data.get("metadata") if isinstance(data, dict) else None
        stack = [(metadata.get("component"), 0)] if isinstance(metadata, dict) else []
        while stack:
            component, depth = stack.pop()
            if not isinstance(component, dict) or id(component) in seen:
                continue
            seen.add(id(component))
            components.append(component)
            nested = component.get("components")
            if depth < _ROOT_COMPONENT_DEPTH and isinstance(nested, list):
                stack.extend((child, depth + 1) for child in reversed(nested))
    return components


def _tracebom_candidates(ctx, scan) -> List[Tuple[str, str]]:
    """The trace BOM files this scan reads, as (path, source base) pairs.

    dep-scan never runs tracebom, so a trace BOM is input the user supplies
    with a BOM directory: ``analysis/tracebom/*.json`` there, following the
    raw-report convention, and any trace-shaped JSON at the top level of the
    directory, recognised by the adapter's own detector. Other scan modes
    read none: a trace BOM in their reports directory was left by an earlier
    run or another tool, never produced by this scan. A top-level file the
    inventory stage already parsed as a BOM is checked from that parse."""
    from analysis_lib.evidence.adapters.tracebom import is_tracebom_report

    if not ctx.bom_dir_mode or not scan.bom_dir:
        return []
    candidates: List[Tuple[str, str]] = []
    seen = set()
    directory = os.path.join(scan.bom_dir, scan_directory.ANALYSIS_DIR, "tracebom")
    for path in sorted(glob.glob(os.path.join(glob.escape(directory), "*.json"))):
        real = os.path.realpath(path)
        if real not in seen:
            seen.add(real)
            candidates.append((path, scan.bom_dir))
    own_files = {
        scan_directory.MANIFEST_FILE,
        scan_directory.FINDINGS_FILE,
        scan_directory.EVIDENCE_INDEX_FILE,
    }
    parsed_boms = {os.path.realpath(str(path)): str(path) for path in scan.bom_files or []}
    for name in sorted(os.listdir(scan.bom_dir)):
        if not name.endswith(".json") or name in own_files or name.endswith(".vdr.json"):
            continue
        path = os.path.join(scan.bom_dir, name)
        real = os.path.realpath(path)
        if not os.path.isfile(path) or real in seen:
            continue
        if real in parsed_boms:
            report = _bom_document(scan, parsed_boms[real])
        else:
            text = _read_report_text(path)
            if text is None:
                continue
            try:
                report = json.loads(text)
            except (ValueError, RecursionError):
                # Not JSON, or nested deeper than the parser reaches: not a
                # trace BOM either way.
                continue
        if is_tracebom_report(report):
            seen.add(real)
            candidates.append((path, scan.bom_dir))
    return candidates


def _tracebom_adapter_result(ctx, scan):
    """The trace BOMs this scan holds as runtime-trace records, or None when
    it holds none. A runtime observation is not reachability evidence: the
    records reach the store and nothing grades on them."""
    from analysis_lib.evidence.adapters import tracebom as tracebom_adapter

    candidates = _tracebom_candidates(ctx, scan)
    if not candidates:
        return None
    parsed_boms = {os.path.realpath(str(path)): str(path) for path in scan.bom_files or []}
    reads = []
    for path, base in candidates:
        parsed = parsed_boms.get(os.path.realpath(path))
        report = _bom_document(scan, parsed) if parsed else _read_report_text(path)
        if report is None:
            continue
        source = _record_source(path, base)
        reads.append(
            (
                source,
                tracebom_adapter.extract(report, source=source, source_root=ctx.source_root),
            )
        )
    if not reads:
        return None
    for source, read in reads:
        if read.status != "completed":
            LOG.warning("tracebom evidence from %s was not assessed: %s", source, read.reason)
    result = _merge_adapter_results(reads)
    if result.status == "completed":
        LOG.debug(
            "tracebom evidence: the adapter built %d records from %d trace BOM(s)",
            len(result.records),
            len(reads),
        )
    return result


def _write_evidence_store(ctx, evidence_file: str, adapter_results: Dict) -> None:
    """Add every adapter result's records to this scan's store and write it.

    The records accumulate on the scan context, so a scan of several project
    types rewrites the file once per type holding every type's records, and
    the store applies its write rules: an exact copy collapses, copies that
    differ only in caveats become one record carrying every caveat, and
    records that share an id but differ otherwise each keep a suffixed id.
    The previous file is never read back: a scan of a reused directory
    replaces what an earlier scan left, so a report this scan did not read
    (because it was deleted, damaged, or moved) stops counting instead of
    surviving in the store. A result that was not assessed contributes no
    records: the reachability ones' reason is what the analyzer entries
    carry instead, and every producer's is logged where it is collected.
    """
    incoming = []
    for name in (*REACHABILITY_PRODUCERS, *EVIDENCE_PRODUCERS):
        result = adapter_results.get(name)
        if result is not None:
            incoming.extend(result.records)
    for record in incoming:
        if id(record) in ctx.evidence_record_objects:
            continue
        ctx.evidence_record_objects.add(id(record))
        ctx.evidence_records.append(record)
    written = evidence_store.write(evidence_file, ctx.evidence_records)
    LOG.debug(
        "The evidence store %s holds %d records (%d from this project type).",
        evidence_file,
        written,
        len(incoming),
    )


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

    The analyzers named are the reachability producers whose adapter
    completed for this type; the evidence producers are not reachability
    analyzers and never enter the scope. The reached sets and purl types
    come from the same adapter results' records. An analyzer that completed
    without a reached-counted record gets an empty reached set, so it
    observed nothing; the engine's reached map, which counts the whole
    store, never stands in for it. When reachability was off, failed or
    produced no purls, the scope says so and every finding of the type
    records ``reach`` as not assessed. The records carry the usage,
    exposure and witness evidence of every producer, so nothing but the
    records this scan produced is graded on: a report left by an earlier
    run is never read.

    Presence reads the cdxgen usage records (occurrences and callstacks) of
    every BOM the scan read and the cdxgen adapter assessed, on every scan
    type, but only for the components the scan loaded
    (:func:`_usage_records`): a record of a loaded component grades
    whatever document it came from, so an aggregated load grades records
    from any of the directory's BOMs. The records of components the loader
    left out still reach the evidence store, which is additive, and grade
    nothing; the matching stage's manifest entry counts them. A BOM the
    adapter did not assess leaves its reason in ``ctx.usage_not_assessed``
    for the findings of the loaded packages it names.
    """
    from analysis_lib.findings.exploitability import ExploitabilityInputs, USAGE_KINDS
    from analysis_lib.findings.vdr_convert import ReachScope, reached_by_analyzer

    results = scan.adapter_results or {}
    analyzers = [
        name
        for name in REACHABILITY_PRODUCERS
        if results.get(name) is not None and results[name].status == "completed"
    ]
    records = []
    for name in (*REACHABILITY_PRODUCERS, *EVIDENCE_PRODUCERS):
        result = results.get(name)
        if result is not None:
            records.extend(
                record
                for record in result.records
                if not (record.producer.name == "cdxgen" and record.kind in USAGE_KINDS)
            )
    records.extend(_usage_records(ctx, scan))
    by_analyzer = reached_by_analyzer(records)
    scope = ReachScope(
        analyzers=analyzers,
        reached=set((scan.reached_purls or {}).keys()),
        succeeded=scan.reachability_succeeded,
        analyzer_types={"atom": by_analyzer.get("atom", {}).get("types", set())},
        reached_by={
            name: set(by_analyzer.get(name, {}).get("purls", set())) for name in analyzers
        },
    )
    return ExploitabilityInputs(
        rules=ctx.grading_rules,
        scope=scope,
        bom_components=scan.pkg_list,
        dosai_ran="dosai" in analyzers,
        records=records,
    )


def _usage_records(ctx, scan) -> List[Any]:
    """cdxgen's usage records of the components the scan loaded, from every
    BOM document the scan read and the cdxgen adapter assessed.

    A record grades when its component is one the scan loaded: a record
    whose subject names a ``bom-ref`` grades when that ref is a loaded
    component's key (the ``bom-ref``, else the purl), and a record whose
    component has no bom-ref grades when one of its purls matches a loaded
    component's comparable purl. The purl match is the join that carries a
    record from any BOM of an aggregated directory to the aggregated
    component. A record whose bom-ref is set but not loaded does not fall
    back to the purl match: a component the loader left out (a ``data``
    component, a nested ``application``) must not prove a ref. Records that
    match no loaded component are counted on the scan and still reach the
    evidence store, but grade nothing. A document the adapter did not
    assess owes every loaded package it names a reason in
    ``ctx.usage_not_assessed``, whether or not another assessed document
    gives the same package usage records."""
    from analysis_lib.findings.exploitability import USAGE_KINDS
    from analysis_lib.findings.vdr_convert import comparable_purl

    loaded_keys = {key for key in map(_component_key, scan.pkg_list or []) if key}
    loaded_purls = {
        comparable_purl(pkg["purl"])
        for pkg in scan.pkg_list or []
        if isinstance(pkg.get("purl"), str) and pkg["purl"]
    }
    records = []
    ungraded = 0
    for document, read in (scan.cdxgen_reads or {}).items():
        if read.status != "completed":
            _mark_usage_not_assessed(ctx, scan, document, read.reason)
            continue
        for record in read.records:
            if record.producer.name != "cdxgen" or record.kind not in USAGE_KINDS:
                continue
            component_ref = record.subject.component_ref
            if component_ref:
                grades = component_ref in loaded_keys
            else:
                grades = any(
                    comparable_purl(purl) in loaded_purls for purl in record.subject.purls
                )
            if grades:
                records.append(record)
            else:
                ungraded += 1
    scan.ungraded_usage_records = ungraded
    if ungraded:
        LOG.info(
            "%d cdxgen usage records grade nothing: their components are not "
            "in the loaded package list",
            ungraded,
        )
    return records


def _mark_usage_not_assessed(ctx, scan, document: str, reason: Optional[str]) -> None:
    """Keep why a BOM document's usage evidence was not assessed for every
    loaded package the document's components name.

    The reason is keyed by comparable purl and written once per package, so
    the first refused document naming it wins. A package another assessed
    document gave usage records keeps the reason as well: the engine grades
    on those records either way, and the finding still names the BOM that
    was not read."""
    from analysis_lib.findings.vdr_convert import comparable_purl

    keys, purls = (scan.cdxgen_document_keys or {}).get(str(document), (set(), set()))
    detail = (
        f"cdxgen's usage evidence in {os.path.basename(str(document))} was not assessed: {reason}"
    )
    for pkg in scan.pkg_list or []:
        purl = pkg.get("purl")
        if not (isinstance(purl, str) and purl):
            continue
        if _component_key(pkg) in keys or comparable_purl(purl) in purls:
            ctx.usage_not_assessed.setdefault(comparable_purl(purl), detail)


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
            # The enrichment stage writes the store at the top of the reports
            # directory, which is not the BOM directory a --bom-dir scan was
            # given; name it so the explanation reads the store this scan
            # wrote.
            evidence_file=os.path.join(ctx.reports_dir, scan_directory.EVIDENCE_FILE),
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


def _scan_requested_blint_reviews(ctx) -> bool:
    """Whether any project type of this scan asked for blint's review.

    This is the gate :func:`finish_scan_directory` applies to the review's
    findings, so a table rendered under it counts the same findings the
    findings file holds.
    """
    return any(
        blint_reviews_requested({**ctx.depscan_options, "project_type": [project_type]})
        for project_type in (ctx.project_types or [None])
    )


def _render_binary_review(ctx) -> None:
    """Print the blint review's binary-hardening findings on the console.

    The rows are the findings :func:`finish_scan_directory` writes to
    ``depscan.findings.json``, built from the same records under the same
    review gate, so the table's count agrees with the file. The printing
    happens before the console is saved, so ``depscan.txt`` and
    ``depscan.html`` carry it. A scan that did not ask for the review
    prints nothing here.
    """
    if not _scan_requested_blint_reviews(ctx):
        return
    from analysis_lib.findings.blint_convert import findings_from_blint_records

    rows = [finding.to_dict() for finding in findings_from_blint_records(ctx.evidence_records)]
    if rows and not ctx.args.no_vuln_table:
        console.print(binary_review.binary_hardening_table(rows))


def stage_render_reports(ctx):
    """Export the console output and render every report file."""
    args = ctx.args
    console.record = True
    _render_binary_review(ctx)
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
