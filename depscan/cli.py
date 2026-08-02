#!/usr/bin/env python3 -W ignore::DeprecationWarning
# -*- coding: utf-8 -*-

import contextlib
import os
import sys
import time
from typing import List

from analysis_lib import ReachabilityAnalysisKV, VdrAnalysisKV, get_all_bom_files
from analysis_lib.vex.emit import export_csaf
from analysis_lib.output import licenses_risk_table, pkg_risks_table, summary_stats
from analysis_lib.reachability import get_reachability_impl
from analysis_lib.search import get_pkgs_by_scope
from analysis_lib.utils import get_all_pkg_list, get_pkg_list
from analysis_lib.vdr import VDRAnalyzer
from custom_json_diff.lib.utils import json_load
from reporting_lib.htmlgen import ReportGenerator
from rich.panel import Panel
from rich.terminal_theme import DEFAULT_TERMINAL_THEME, MONOKAI
from vdb.lib import config
from vdb.lib import db6 as db_lib
from vdb.lib import search
from vdb.lib.utils import parse_purl

from depscan import get_version
from depscan.cli_options import build_parser
from depscan.lib import explainer, utils
from depscan.lib.audit import risk_audit, risk_audit_map
from depscan.lib.bom import (
    annotate_vdr,
    create_bom,
    create_empty_vdr,
    determine_spec_version,
    export_bom,
    get_pkg_by_type,
)
from depscan.lib.config import (
    DEPSCAN_DEFAULT_VDR_FILE,
    UNIVERSAL_SCAN_TYPE,
    VDB_AGE_HOURS,
    license_data_dir,
    pkg_max_risk_score,
    read_vdb_image_marker,
    resolve_vdb_image,
    spdx_license_list,
    vdb_image_size,
    write_vdb_image_marker,
)
from depscan.lib.license import build_license_data, bulk_lookup
from depscan.lib.logger import DEBUG, IS_CI, LOG, SPINNER, console

if sys.platform == "win32" and os.environ.get("PYTHONIOENCODING") is None:
    sys.stdin.reconfigure(encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

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

ORAS_AVAILABLE = False
try:
    from vdb.lib.orasclient import download_image

    ORAS_AVAILABLE = True
except ImportError:
    pass


def _positive_int_env(name: str, default: int) -> int:
    """Read a positive int from the environment, falling back to ``default``."""
    try:
        value = int(os.getenv(name, ""))
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


# The vdb image is a multi-GB oras pull; a dropped connection mid-stream raises
# ChunkedEncodingError / urllib3 ProtocolError / IncompleteRead. These are
# transient (common in CI), so retry a few times before giving up.
VDB_DOWNLOAD_MAX_ATTEMPTS = _positive_int_env("VDB_DOWNLOAD_RETRIES", 3)
VDB_DOWNLOAD_RETRY_BACKOFF_SEC = _positive_int_env("VDB_DOWNLOAD_RETRY_BACKOFF_SEC", 5)


def download_vdb_with_retries(vdb_database_url, data_dir, attempts=VDB_DOWNLOAD_MAX_ATTEMPTS):
    """Download the vulnerability database, retrying transient network errors.

    ``download_image`` streams large blobs and can fail partway through with a
    variety of exceptions raised across the requests/urllib3/oras layers. We
    retry with a linear backoff and re-raise the last error if every attempt
    fails so the caller's existing error handling still applies.
    """
    last_exc = None
    for attempt in range(1, attempts + 1):
        try:
            return download_image(vdb_database_url, data_dir)
        except Exception as e:  # noqa: BLE001 - transient failures vary by layer
            last_exc = e
            if attempt < attempts:
                LOG.warning(
                    "Vulnerability database download failed (attempt %d/%d): %s. Retrying ...",
                    attempt,
                    attempts,
                    e,
                )
                time.sleep(VDB_DOWNLOAD_RETRY_BACKOFF_SEC * attempt)
            else:
                LOG.error(
                    "Vulnerability database download failed after %d attempt(s).",
                    attempts,
                )
    if last_exc is not None:
        raise last_exc


def vdb_download_needed(resolved_url, data_dir):
    """Decide whether the scan should (re-)download the vdb.

    The DB is re-downloaded when it is stale (time-based, via
    ``db6.needs_update``) OR when the depscan-owned variant marker differs
    from the freshly resolved image ref. The marker check catches a
    scope/time/tier/distro switch that ``needs_update`` would otherwise miss
    for up to ``VDB_AGE_HOURS`` because vdb metadata does not record the
    source variant.

    :param resolved_url: the image ref the scan resolved for this run
    :param data_dir: the vdb data directory (``config.DATA_DIR``)
    :return: ``(should_download, reason)`` where *reason* is ``"stale"``,
        ``"variant-change"``, or ``None``.
    """
    # needs_update returns default_status when the on-disk DB has no usable
    # metadata (a fresh install or a missing/corrupt DB). In that case we must
    # download, so default_status is True. (The previous
    # ``get_db_file_metadata is not None`` compared the function object, not its
    # result, so it was always True by accident; calling it would wrongly
    # return False on a fresh install and skip the download.)
    stale = db_lib.needs_update(
        days=0,
        hours=VDB_AGE_HOURS,
        default_status=True,
    )
    if stale:
        return True, "stale"
    marker = read_vdb_image_marker(data_dir)
    if marker is not None and marker != resolved_url:
        LOG.info(
            "vdb variant changed from '%s' to '%s'; forcing re-download.",
            marker,
            resolved_url,
        )
        return True, "variant-change"
    return False, None


def resolve_scan_vdb_image(args):
    """Resolve the vdb image URL for the scan path (T7 Change D).

    Precedence, highest first:

    1. Explicit ``VDB_DATABASE_URL`` env pin -> used verbatim.
    2. ``--vdb-image`` (also settable via the config file as ``vdb_image``) ->
       used verbatim.
    3. The ``--vdb-*`` selection options (``vdb_scope``/``vdb_time``/
       ``vdb_extended``/``vdb_compression``/``vdb_distro``), which may come from
       the command line or be persisted in the depscan config file. Unset
       options fall back to their defaults (app+os, default, standard, xz), and
       ``USE_VDB_10Y`` still maps to ``time=10y`` when ``vdb_time`` is unset.

    When ``--severity`` is set and the user has NOT pinned an image (env or
    ``--vdb-image``), the ``-extended`` variant is auto-selected and
    ``VDB_INCLUDE_METADATA=true`` is set so the severity push-down into the
    search layer fires. If the user pinned a non-extended image, do not
    override; the depscan-side severity floor
    (``analysis_lib.utils.vuln_meets_severity``) still filters the final VDR.

    :return: ``(url, user_pinned)`` tuple.
    """
    pinned = os.getenv("VDB_DATABASE_URL") or getattr(args, "vdb_image", None)
    if pinned:
        if args.severity and "-extended" not in pinned:
            LOG.info(
                "--severity is set but a non-extended vdb image is pinned. The "
                "severity floor is still applied to the final VDR. Use an "
                "*-extended image (or clear the pin) to push the filter into "
                "the search layer."
            )
        return pinned, True

    distro = getattr(args, "vdb_distro", None)
    compression = getattr(args, "vdb_compression", None) or "xz"
    if distro:
        # Distro images are mutually exclusive with scope/time/extended and never
        # carry metadata, so --severity cannot push down here.
        resolved = resolve_vdb_image(distro=distro, compression=compression)
        if args.severity:
            LOG.info(
                "--severity is set but a distro-only vdb image (%s) has no "
                "metadata; the severity floor still applies to the final VDR.",
                resolved,
            )
        return resolved, False

    scope = getattr(args, "vdb_scope", None) or "app+os"
    time_window = getattr(args, "vdb_time", None)
    if not time_window:
        time_window = "10y" if os.getenv("USE_VDB_10Y", "") in ("true", "1") else "default"
    extended = bool(getattr(args, "vdb_extended", None)) or bool(args.severity)
    if extended:
        os.environ["VDB_INCLUDE_METADATA"] = "true"
        resolved = resolve_vdb_image(
            scope=scope, time=time_window, extended=True, compression=compression
        )
        if args.severity:
            LOG.info(
                "--severity needs metadata search; using the extended vdb image (%s).",
                resolved,
            )
        return resolved, False
    return resolve_vdb_image(scope=scope, time=time_window, compression=compression), False


def _warn_large_appos_for_source_scan(scan_vdb_url, args):
    """Advisory warning before pulling a multi-GB App+OS image on a source-only scan."""
    try:
        size_gib = float(vdb_image_size(scan_vdb_url).split()[0])
    except (ValueError, IndexError):
        size_gib = 0.0
    is_source_only = (
        not args.deep_scan and os.path.isdir(str(args.src_dir_image)) and not args.bom_dir
    )
    if size_gib > 10 and is_source_only:
        LOG.warning(
            "The selected vulnerability database is large (~%s GiB "
            "uncompressed) for a source-only scan. For faster downloads, "
            "consider an app-only image: `depscan-vdb download --scope app`.",
            vdb_image_size(scan_vdb_url).split()[0],
        )


def build_args():
    """
    Constructs command line arguments for the depscan tool
    """
    parser = build_parser()
    return parser.parse_args()


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


def configure_vdb_readonly():
    """Default vdb SQLite to read-only/immutable + WAL for scan runs.

    These defaults let SQLite skip lock acquisition and journal overhead on
    the read-only scan path, which is a prerequisite for safe concurrent
    reads and a small speed win. They are applied AFTER the vdb download so
    the update path is never opened immutable.

    Override with ``VDB_SQLITE_IMMUTABLE=false`` or
    ``VDB_SQLITE_JOURNAL_MODE=DELETE``.
    """
    if os.getenv("VDB_SQLITE_IMMUTABLE", "").lower() not in ("false", "0"):
        os.environ["VDB_SQLITE_IMMUTABLE"] = "true"
        # config.VDB_SQLITE_IMMUTABLE was captured at import time; patch it so
        # db6._sqlite_uri picks up immutable=1 on the first connection.
        config.VDB_SQLITE_IMMUTABLE = True
    if not os.getenv("VDB_SQLITE_JOURNAL_MODE"):
        os.environ["VDB_SQLITE_JOURNAL_MODE"] = "WAL"


def vdr_analyze_summarize(
    project_type,
    results,
    suggest_mode,
    scoped_pkgs,
    bom_file,
    bom_dir,
    reports_dir,
    pkg_list,
    reachability_analyzer,
    reachability_options,
    no_vuln_table=False,
    fuzzy_search=False,
    search_order=None,
    spec_version=None,
    severity=None,
    malware_only=False,
    exclude_malware=False,
):
    """
    Method to perform VDR analysis followed by summarization.
    :param project_type: Project type.
    :param results: Scan or audit results.
    :param suggest_mode: Normalize fix versions automatically.
    :param scoped_pkgs: Dict containing package scopes.
    :param bom_file: Single BOM file.
    :param bom_dir: Directory containining bom files.
    :param reports_dir: Directory containining report files.
    :param pkg_list: Direct list of packages when the bom file is empty.
    :param reachability_analyzer: Reachability Analyzer specified.
    :param reachability_options: Reachability Analyzer options.
    :param no_vuln_table: Boolean to indicate if the results should get printed
            to the console.
    :param fuzzy_search: Perform fuzzy search.
    :param search_order: Search order.
    :param severity: Minimum severity threshold (low/medium/high/critical) to
            push down to vdb when extended metadata is available.
    :param malware_only: Only return malware advisories.
    :param exclude_malware: Exclude malware advisories.

    :return: A dict of vulnerability and severity summary statistics
    """
    pkg_vulnerabilities = []
    summary = {}
    direct_purls = {}
    reached_purls = {}
    reached_services = {}
    endpoint_reached_purls = {}
    # Perform the reachability analysis first
    reach_result = get_reachability_impl(reachability_analyzer, reachability_options).process()
    # We now have reachability results, OpenAPI endpoints, BOMs, and component scope information.
    if reach_result and reach_result.success:
        direct_purls = reach_result.direct_purls
        reached_purls = reach_result.reached_purls
        reached_services = reach_result.reached_services
        endpoint_reached_purls = reach_result.endpoint_reached_purls
    console.record = True
    # We might already have the needed slices files when we reach here.
    options = VdrAnalysisKV(
        project_type,
        results,
        pkg_aliases={},
        purl_aliases={},
        suggest_mode=suggest_mode,
        scoped_pkgs=scoped_pkgs,
        no_vuln_table=no_vuln_table,
        bom_file=bom_file,
        bom_dir=bom_dir,
        pkg_list=pkg_list,
        direct_purls=direct_purls,
        reached_purls=reached_purls,
        reached_services=reached_services,
        endpoint_reached_purls=endpoint_reached_purls,
        console=console,
        logger=LOG,
        fuzzy_search=fuzzy_search,
        search_order=search_order,
        severity=severity,
        malware_only=malware_only,
        exclude_malware=exclude_malware,
    )
    ds_version = get_version()
    vdr_result = VDRAnalyzer(vdr_options=options).process()
    # Set vdr_file in report folder
    vdr_file = os.path.join(reports_dir, os.path.basename(bom_file)) if bom_file else None
    vdr_file = vdr_file.replace(".cdx.json", ".vdr.json") if vdr_file else None
    if not vdr_file and bom_dir:
        vdr_file = os.path.join(bom_dir, DEPSCAN_DEFAULT_VDR_FILE)
    if vdr_result.success:
        pkg_vulnerabilities = vdr_result.pkg_vulnerabilities
        cdx_vdr_data = None
        # Always create VDR files even when empty
        if pkg_vulnerabilities is not None:
            # Case 1: Single BOM file resulting in a single VDR file
            if bom_file:
                cdx_vdr_data = json_load(bom_file, log=LOG)
            # Case 2: Multiple BOM files in a bom directory (e.g. lifecycle
            # analysis). Use the max specVersion across those SBOMs, falling
            # back to the user's --spec-version and then the default.
            elif bom_dir:
                lifecycle_spec_version = determine_spec_version(
                    get_all_bom_files(bom_dir), fallback=spec_version
                )
                cdx_vdr_data = create_empty_vdr(
                    pkg_list, ds_version, spec_version=lifecycle_spec_version
                )
        if cdx_vdr_data:
            export_bom(cdx_vdr_data, ds_version, pkg_vulnerabilities, vdr_file)
            LOG.debug(f"The VDR file '{vdr_file}' was created successfully.")
        else:
            LOG.debug(f"VDR file '{vdr_file}' was not created for the type {project_type}.")
        summary = summary_stats(pkg_vulnerabilities)
    elif bom_dir or bom_file or pkg_list:
        if project_type != "bom":
            LOG.info("No vulnerabilities found for project type '%s'!", project_type)
        else:
            LOG.info("No vulnerabilities found!")
    return summary, vdr_file, vdr_result


def set_project_types(args, src_dir):
    """
    Detects the project types and perform the right type of scan

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
    return pkg_list, project_types_list


def run_depscan(args):
    """
    Detects the project type, performs various scans and audits,
    and generates reports based on the results.
    """
    perform_risk_audit = args.risk_audit
    # declare variables that get initialized only conditionally
    (
        summary,
        vdr_file,
        bom_file,
        prebuild_bom_file,
        build_bom_file,
        postbuild_bom_file,
        container_bom_file,
        operations_bom_file,
        pkg_list,
        all_pkg_vulnerabilities,
        all_pkg_group_rows,
    ) = (None, None, None, None, None, None, None, None, None, [], {})
    if (
        os.getenv("CI")
        and not os.getenv("GITHUB_REPOSITORY", "").lower().startswith("owasp")
        and not args.no_banner
        and not os.getenv("INPUT_THANK_YOU", "") == "I have sponsored OWASP-dep-scan."
    ):
        console.print(
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
        args.no_vuln_table = True
    # Should we enable debug
    if args.enable_debug:
        os.environ["SCAN_DEBUG_MODE"] = "debug"
        os.environ["CDXGEN_DEBUG_MODE"] = "debug"
        LOG.setLevel(DEBUG)
    if args.server_mode:
        if SERVER_LIB:
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
                max_content_length=os.getenv("DEPSCAN_SERVER_MAX_CONTENT_LENGTH"),
                custom_data_directory=args.custom_data,
            )
            return simple.run_server(server_options)
        else:
            LOG.info(
                "The required packages for server mode are unavailable. Reinstall depscan using `pip install owasp-depscan[all]`."
            )
            return False
    if not args.no_banner:
        with contextlib.suppress(UnicodeEncodeError):
            print(LOGO)
    # Fail fast on unusable scan inputs. Silently ignoring them produces an
    # empty-looking but successful scan, which is worse than no scan at all.
    input_errors = validate_scan_inputs(args)
    if input_errors:
        for input_error in input_errors:
            LOG.error(input_error)
        sys.exit(1)
    # Break early if the user prefers CPE-based searches
    search_order = args.search_order
    if search_order:
        if search_order.startswith("c") and not args.bom and not args.bom_dir:
            LOG.warning(
                "To perform CPE-based searches, the SBOM must include a CPE identifier for each component. Generate the SBOM using a compatible tool such as Syft or Trivy, and invoke depscan with the --bom or --bom-dir argument."
            )
            LOG.info(
                "Alternatively, run depscan without the `--search-order` argument to perform PURL-based searches. This method is more accurate and recommended."
            )
            sys.exit(1)
        elif search_order.startswith("u") and not os.getenv("FETCH_LICENSE"):
            LOG.warning(
                "To perform URL-based searches, the SBOM must include externalReferences with a URL. Set the environment variable `FETCH_LICENSE=true` to force cdxgen to populate this attribute."
            )
            LOG.info(
                "Alternatively, include the project type `-t license` to ensure this attribute is populated."
            )
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
    reports_dir = args.reports_dir
    # User has not provided an explicit reports_dir. Reuse the bom_dir
    if not reports_dir and args.bom_dir:
        reports_dir = os.path.realpath(args.bom_dir)
    # Are we running for a BOM directory the *user* supplied? This must be
    # captured before the lifecycle branch below repurposes the bom dir as an
    # output directory, otherwise the two modes become indistinguishable.
    user_bom_dir = args.bom_dir
    bom_dir_mode = bool(user_bom_dir and os.path.isdir(user_bom_dir))
    # Are we running with a config file
    config_file_mode = args.config and os.path.exists(args.config)
    depscan_options = {**vars(args), "src_dir": src_dir, "reports_dir": reports_dir}
    # depscan owns the malware-exclusion filter (vdb also reads this env var, but
    # we translate it here so build_search_filters receives an explicit option).
    depscan_options["exclude_malware"] = os.getenv("OSV_EXCLUDE_MALWARE", "") in (
        "true",
        "1",
    )
    # Is the user looking for semantic analysis?
    # We can default to this when run against a BOM directory
    if (
        args.reachability_analyzer == "SemanticReachability"
    ) and args.vuln_analyzer != "LifecycleAnalyzer":
        LOG.debug("Automatically switching to the `LifecycleAnalyzer` for vulnerability analysis.")
        depscan_options["vuln_analyzer"] = "LifecycleAnalyzer"
        args.vuln_analyzer = "LifecycleAnalyzer"
    # Resolve the vdb image for this scan (T7 Change D).
    scan_vdb_url, _user_pinned = resolve_scan_vdb_image(args)
    _warn_large_appos_for_source_scan(scan_vdb_url, args)
    # Should we download the latest vdb.
    should_download, dl_reason = vdb_download_needed(scan_vdb_url, config.DATA_DIR)
    if should_download:
        if ORAS_AVAILABLE:
            with console.status(
                f"Downloading the latest vulnerability database to {config.DATA_DIR}. Please wait ...",
                spinner=SPINNER,
            ) as vdb_download_status:
                if not IS_CI:
                    vdb_download_status.stop()
                # This line may exit with an exception if the database cannot be
                # downloaded even after retries.
                # Example: urllib3.exceptions.IncompleteRead, urllib3.exceptions.ProtocolError, requests.exceptions.ChunkedEncodingError
                download_vdb_with_retries(scan_vdb_url, config.DATA_DIR)
                # Record the variant so a future switch forces a re-download
                # even when the DB is still within the age window.
                write_vdb_image_marker(scan_vdb_url, config.DATA_DIR)
        else:
            LOG.warning(
                "The latest vulnerability database is not found. Follow the documentation to manually download it."
            )
    # Apply read-only SQLite tuning for the scan (T2). Done after the download
    # so the vdb update path is never opened immutable.
    configure_vdb_readonly()
    pkg_list, project_types_list = set_project_types(args, src_dir)
    if args.custom_data:
        LOG.info(f"Loading custom vulnerability data from {args.custom_data}")
        search.load_custom_data(args.custom_data)
    if args.search_purl:
        # Automatically enable risk audit for single purl searches
        perform_risk_audit = True
    # Construct the various report files
    html_report_file = depscan_options.get(
        "html_report_file", os.path.join(reports_dir, "depscan.html")
    )
    txt_report_file = depscan_options.get(
        "txt_report_file", os.path.join(reports_dir, "depscan.txt")
    )
    llm_prompt_file = depscan_options.get(
        "llm_prompt_file", os.path.join(reports_dir, "depscan-prompts.md")
    )
    run_config_file = os.path.join(reports_dir, "depscan.toml.sample")
    depscan_options["html_report_file"] = html_report_file
    depscan_options["txt_report_file"] = txt_report_file
    depscan_options["llm_prompt_file"] = llm_prompt_file
    # Create reports directory
    if reports_dir and not os.path.exists(reports_dir):
        os.makedirs(reports_dir, exist_ok=True)
    if len(project_types_list) > 1:
        LOG.debug("Multiple project types found: %s", project_types_list)
    # Enable license scanning
    if "license" in project_types_list or "license" in args.profile:
        os.environ["FETCH_LICENSE"] = "true"
        project_types_list.remove("license")
        console.print(
            Panel(
                "License audit is enabled for this scan. This would increase "
                "the time by up to 10 minutes.",
                title="License Audit",
                expand=False,
            )
        )
    # Let’s create a sample configuration file based on the CLI options used.
    if not config_file_mode:
        run_config = {**depscan_options}
        del run_config["no_banner"]
        try:
            import toml as _toml

            with open(run_config_file, "w") as _fh:
                _fh.write(_toml.dumps(run_config))
        except OSError as exc:
            LOG.debug("Could not write sample config to %s: %s", run_config_file, exc)
        else:
            LOG.debug(
                f"Created a sample depscan config file at '{run_config_file}', based on this run."
            )
    # We have everything needed to start the composition analysis. There are many approaches to implementing an SCA tool.
    # Our style of analysis is comparable to that of an intelligent Hubble telescope or a rover—examining the same subject through multiple optics, colors, and depths to gain a deeper understanding.
    # We begin by iterating over the project types provided or assumed.
    for project_type in project_types_list:
        results = []
        vuln_analyzer = args.vuln_analyzer
        # Reset every per-iteration path. These used to leak from one project
        # type to the next, so a second type could be handed the first type's
        # lifecycle BOM paths.
        bom_dir = user_bom_dir
        lifecycle_mode = False
        prebuild_bom_file = build_bom_file = postbuild_bom_file = None
        container_bom_file = operations_bom_file = None
        # Are we performing a lifecycle analysis
        if not args.search_purl and (
            vuln_analyzer == "LifecycleAnalyzer" or (vuln_analyzer == "auto" and bom_dir_mode)
        ):
            lifecycle_mode = True
            if args.reachability_analyzer == "SemanticReachability":
                if not bom_dir:
                    LOG.info(
                        "Semantic Reachability analysis requested for project type '%s'. This might take a while ...",
                        project_type,
                    )
                else:
                    LOG.info(
                        "Attempting semantic analysis using existing data at '%s'",
                        bom_dir,
                    )
            else:
                LOG.info(
                    "Lifecycle-based vulnerability analysis requested for project type '%s'. This might take a while ...",
                    project_type,
                )
            prebuild_bom_file = os.path.join(reports_dir, f"sbom-prebuild-{project_type}.cdx.json")
            build_bom_file = os.path.join(reports_dir, f"sbom-build-{project_type}.cdx.json")
            postbuild_bom_file = os.path.join(
                reports_dir, f"sbom-postbuild-{project_type}.cdx.json"
            )
            # We support only one container SBOM per project.
            # Projects that rely on docker compose and multiple services require some thinking
            container_bom_file = os.path.join(
                reports_dir, f"sbom-container-{project_type}.cdx.json"
            )
            operations_bom_file = os.path.join(
                reports_dir, f"sbom-operations-{project_type}.cdx.json"
            )
            if vuln_analyzer == "auto":
                vuln_analyzer = "LifecycleAnalyzer"
                depscan_options["vuln_analyzer"] = "LifecycleAnalyzer"
            # We need to set the following two values to make the rest of the code correctly use
            # the generated BOM files after lifecycle analysis
            depscan_options["lifecycle_analysis_mode"] = True
            if not bom_dir:
                bom_dir = os.path.realpath(reports_dir)
        # If the user opts out of lifecycle analysis, we need to maintain multiple SBOMs based on the project type.
        # This is where we *ask* for a BOM to be written. It is an input to the
        # generator, never evidence that a document exists, so nothing below
        # reads it - `bom_files` holds what was actually produced.
        target_bom_file = os.path.join(reports_dir, f"sbom-{project_type}.cdx.json")
        risk_report_file = os.path.join(reports_dir, f"depscan-risk-{project_type}.json")
        # Every BOM document available for this project type. An empty list is
        # a normal state (purl scans), not a failure.
        bom_files = []
        # The document a producer explicitly nominates as the project's BOM.
        # Lifecycle runs nominate nothing: no one of their per-stage documents
        # represents the project.
        nominated_bom_file = None
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
            bom_files = [args.bom]
            nominated_bom_file = args.bom
            creation_status = True
        # Are we scanning a bom directory
        elif bom_dir_mode:
            creation_status = True
        else:
            # Create a bom for each project type. The generator reports back the
            # documents it wrote, which is not necessarily the path we asked for:
            # lifecycle analysis writes per-stage documents instead.
            bom_result = create_bom(
                target_bom_file,
                src_dir,
                {
                    **depscan_options,
                    "project_type": [project_type],
                    "bom_file": target_bom_file,
                    "prebuild_bom_file": prebuild_bom_file,
                    "build_bom_file": build_bom_file,
                    "postbuild_bom_file": postbuild_bom_file,
                    "container_bom_file": container_bom_file,
                    "operations_bom_file": operations_bom_file,
                },
            )
            creation_status = bom_result.success
            bom_files = list(bom_result.bom_files)
            nominated_bom_file = bom_result.primary
        if not creation_status:
            LOG.warning(
                "The BOM file `%s` was not created successfully. Set the `SCAN_DEBUG_MODE=debug` environment variable to troubleshoot.",
                target_bom_file,
            )
            continue
        # A BOM directory supersedes whatever a single run produced: it is the
        # aggregate view, and in lifecycle mode it is where the per-stage
        # documents were written.
        if bom_dir:
            bom_files = get_all_bom_files(bom_dir)
        # The BOM document for this scan: whichever a producer nominated, or -
        # when only one document is available at all - that one, since a lone
        # document is the project's BOM however it got here. None only when
        # several documents exist and none of them is nominated, as with a
        # lifecycle run's per-stage documents.
        bom_file = nominated_bom_file or (bom_files[0] if len(bom_files) == 1 else None)
        # We have a BOM directory. Let’s aggregate all packages from every file within it.
        if bom_dir:
            LOG.debug(
                "Collecting components from all the BOM files at %s",
                bom_dir,
            )
            pkg_list = get_all_pkg_list(bom_dir)
        # We are working with a single BOM file and will collect all packages from it accordingly.
        elif bom_file:
            LOG.debug("Scanning using the bom file %s", bom_file)
            if not args.bom:
                LOG.info(
                    "To improve performance, cache the bom file and invoke "
                    "depscan with --bom %s instead of -i",
                    bom_file,
                )
            pkg_list, _ = get_pkg_list(bom_file)
        if not pkg_list and not bom_dir:
            LOG.info(
                "No packages were found in the project. Try generating the BOM manually or use the `CdxgenImageBasedGenerator` engine."
            )
            continue
        # Depending on the SBOM tool used, there may be details about component usage and scopes. Let’s analyze and interpret that information.
        scoped_pkgs = get_pkgs_by_scope(pkg_list)
        # Is the user interested in seeing license risks? Handle that first before any security-related analysis.
        if os.getenv("FETCH_LICENSE", "") in (True, "1", "true") or "license" in args.profile:
            licenses_results = bulk_lookup(
                build_license_data(license_data_dir, spdx_license_list),
                pkg_list=pkg_list,
            )
            license_report_file = os.path.join(reports_dir, f"license-{project_type}.json")
            ltable = licenses_risk_table(project_type, licenses_results, license_report_file)
            if ltable and not args.no_vuln_table:
                console.print(ltable)
        # Do we support OSS risk audit for this type? If yes, proceed with the relevant checks.
        if perform_risk_audit:
            pkg_list_to_use = []
            project_type_to_use = project_type
            if project_type in risk_audit_map:
                pkg_list_to_use = pkg_list
            elif project_type in ("bom",):
                pkg_list_to_use = get_pkg_by_type(pkg_list, "npm")
                project_type_to_use = "npm"
            if pkg_list_to_use:
                if len(pkg_list) > 1:
                    console.print(
                        Panel(
                            f"Performing OSS Risk Audit for packages from "
                            f"{src_dir}\nNo of packages [bold]{len(pkg_list)}"
                            f"[/bold]. This will take a while ...",
                            title="OSS Risk Audit",
                            expand=False,
                        )
                    )
                try:
                    risk_results = risk_audit(
                        project_type_to_use,
                        scoped_pkgs,
                        args.private_ns,
                        pkg_list_to_use,
                    )
                    rtable, report_data = pkg_risks_table(
                        project_type_to_use,
                        scoped_pkgs,
                        risk_results,
                        pkg_max_risk_score=pkg_max_risk_score,
                        risk_report_file=risk_report_file,
                    )
                    if not args.no_vuln_table and report_data and rtable:
                        console.print(rtable)
                except Exception as e:
                    LOG.error(e)
                    LOG.error("Risk audit was not successful")
        # Remote npm advisory audit was removed: the npmjs security endpoints
        # (/-/npm/v1/security/audits and /-/npm/v1/security/advisories) were
        # permanently retired upstream, so vdb's NpmSource.bulk_search now
        # returns nothing. Those advisories are served from the local VDB via
        # the purl search path instead.
        if len(pkg_list) > 1:
            if project_type == "bom":
                LOG.info("Scanning CycloneDX xBOMs and atom slices")
            elif args.bom:
                LOG.info(
                    "Scanning %s with type %s",
                    args.bom,
                    project_type,
                )
            else:
                LOG.info(
                    "Scanning %s with type %s",
                    src_dir,
                    project_type,
                )
        # `bom_files` was resolved once, above, from what actually exists.
        if not pkg_list and not bom_files:
            LOG.debug("Empty package search attempted!")
        elif bom_files:
            LOG.debug("Scanning %d bom files for issues", len(bom_files))
        else:
            LOG.debug("Scanning %d oss dependencies for issues", len(pkg_list))
        # There are many ways to perform reachability analysis.
        # Most tools—including commercial ones—rely on a vulnerability database with affected modules (sinks) to detect reachable flows.
        # This has several downsides:
        # 1. These databases are often incomplete and manually maintained.
        # 2. If a CVE or ADP enhancement isn’t available yet, reachability won’t be detected.
        #
        # In contrast, depscan computes reachable flows (via atom) without relying on vulnerability data upfront.
        # It then identifies a smaller subset of those flows that are actually vulnerable.
        # From there, we can further narrow it down to flows that are Endpoint-Reachable, Exploitable, Container-Escapable, etc.
        reachability_analyzer = depscan_options.get("reachability_analyzer")
        reachability_options = None
        if (reachability_analyzer and reachability_analyzer != "off") or depscan_options.get(
            "profile"
        ) != "generic":
            reachability_options = ReachabilityAnalysisKV(
                project_types=[project_type],
                src_dir=src_dir,
                bom_dir=bom_dir or reports_dir,
                require_multi_usage=depscan_options.get("require_multi_usage", False),
                source_tags=depscan_options.get("source_tags"),
                sink_tags=depscan_options.get("sink_tags"),
            )
        # Let’s proceed with the VDR analysis.
        summary, vdr_file, vdr_result = vdr_analyze_summarize(
            project_type,
            results,
            suggest_mode=args.suggest,
            scoped_pkgs=scoped_pkgs,
            bom_file=bom_file,
            bom_dir=bom_dir,
            reports_dir=args.reports_dir,
            pkg_list=pkg_list,
            reachability_analyzer=reachability_analyzer,
            reachability_options=reachability_options,
            no_vuln_table=args.no_vuln_table,
            fuzzy_search=depscan_options.get("fuzzy_search", False),
            search_order=depscan_options.get("search_order"),
            spec_version=depscan_options.get("spec_version"),
            severity=depscan_options.get("severity"),
            malware_only=depscan_options.get("malware_only", False),
            exclude_malware=depscan_options.get("exclude_malware", False),
        )
        if vdr_result.pkg_vulnerabilities:
            all_pkg_vulnerabilities += vdr_result.pkg_vulnerabilities
        if vdr_result.prioritized_pkg_vuln_trees:
            all_pkg_group_rows.update(vdr_result.prioritized_pkg_vuln_trees)
        # Explain the results
        if args.explain:
            explainer.explain(
                project_type,
                src_dir,
                bom_dir or reports_dir,
                vdr_file,
                vdr_result,
                args.explanation_mode,
                depscan_options["llm_prompt_file"],
            )
        else:
            LOG.debug(
                "Pass the `--explain` argument to get a detailed explanation of the analysis."
            )
        # CSAF VEX export
        if args.csaf:
            # Prefer the project BOM so the output is named after the project
            # (<base>.csaf.json) and the product tree is built from it. Fall
            # back to the VDR (also a CycloneDX document), which the analysis
            # may not have written either. The emit layer guarantees the VDR is
            # never overwritten.
            csaf_bom_file = bom_file or (
                vdr_file if vdr_file and os.path.exists(vdr_file) else None
            )
            if not csaf_bom_file:
                LOG.warning(
                    "CSAF export skipped for project type '%s': no readable BOM or "
                    "VDR file is available to name the output and build the product tree.",
                    project_type,
                )
            else:
                csaf_file, _csaf_errors = export_csaf(
                    vdr_result,
                    src_dir=src_dir,
                    reports_dir=reports_dir,
                    bom_file=csaf_bom_file,
                    csaf_version=getattr(args, "csaf_version", "2.1"),
                )
                # A failed export must never look like a successful one.
                if not csaf_file:
                    LOG.warning(
                        "CSAF export failed for project type '%s' using `%s`.",
                        project_type,
                        csaf_bom_file,
                    )
    console.record = True
    # Export the console output
    console.save_html(
        html_report_file,
        clear=False,
        theme=(MONOKAI if os.getenv("USE_DARK_THEME") else DEFAULT_TERMINAL_THEME),
    )
    console.save_text(txt_report_file, clear=False)
    # Prettify the rich html report
    html_report_generator = ReportGenerator(
        input_rich_html_path=html_report_file,
        report_output_path=html_report_file,
        raw_content=False,
    )
    html_report_generator.parse_and_generate_report()
    # This logic needs refactoring
    # render report into template if wished
    if args.report_template and os.path.isfile(args.report_template):
        utils.render_template_report(
            vdr_file=vdr_file,
            bom_file=bom_file,
            pkg_vulnerabilities=all_pkg_vulnerabilities,
            pkg_group_rows=all_pkg_group_rows,
            summary=summary,
            template_file=args.report_template,
            result_file=os.path.join(reports_dir, args.report_name),
            depscan_options=depscan_options,
        )
    elif args.report_template:
        LOG.warning(
            "Template file %s doesn't exist, custom report not created.",
            args.report_template,
        )
    # Should we include the generated text report as an annotation in the VDR file?
    if args.explain or args.annotate:
        annotate_vdr(vdr_file, txt_report_file)


def main():
    cli_args = build_args()
    run_depscan(cli_args)


if __name__ == "__main__":
    main()
