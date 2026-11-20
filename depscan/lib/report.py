"""The ``depscan report`` command: render a saved scan directory again.

The command reads only the scan directory, through
:func:`depscan.api.load_scan`. It never generates BOMs, never runs
analyzers and never opens the vulnerability database: everything it shows
was written by the scan it renders. When the directory does not hold what a
rendering needs, the message names what is missing and the command exits
non-zero rather than printing something the scan did not produce.
"""

import argparse
import sys
from typing import List

from analysis_lib import VdrAnalysisKV
from analysis_lib.output import exploitability_grade_stats, generate_console_output, summary_stats

from depscan import api
from depscan.commands.output import (
    EXIT_FAILURE,
    json_path,
    print_error_document,
    print_json_document,
)
from depscan.lib.logger import LOG, console


def register_arguments(parser: argparse.ArgumentParser) -> None:
    """Add the report options to ``parser``."""
    parser.add_argument("scan_dir", help="The scan directory a depscan scan wrote.")
    parser.add_argument(
        "--explain",
        action="store_true",
        default=False,
        help="Also render the explanation of the analysis, reading the "
        "slices and OpenAPI specifications the scan directory holds.",
    )
    parser.add_argument(
        "--explanation-mode",
        choices=("Endpoints", "EndpointsAndReachables", "NonReachables", "LLMPrompts"),
        default="EndpointsAndReachables",
        dest="explanation_mode",
        help="Style of explanation needed. Defaults to Endpoints and Reachables.",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="text renders the tables, json prints the scan directory's "
        "documents as one JSON object (default: text)",
    )


def parse_report_args(argv: List[str]) -> argparse.Namespace:
    """Parse the arguments after ``report``."""
    parser = argparse.ArgumentParser(
        prog="depscan report",
        description="Render the console tables and explanations of a saved scan.",
    )
    register_arguments(parser)
    return parser.parse_args(argv)


def _graded_pairs(findings, vulnerabilities):
    """The (advisory id, component) -> exploitability map of one project
    type, read from the scan directory's findings.

    The findings document records each component's own grade; the VDR only
    holds the most severe grade of a merged entry. Only pairs this type's VDR
    carries are kept. A pair two project types graded shows the assessment
    the findings kept (the one that assessed more axes), which may be the
    other type's.
    """
    wanted = {
        (str(vuln.get("id") or ""), str(affect.get("ref")))
        for vuln in vulnerabilities
        if isinstance(vuln, dict)
        for affect in vuln.get("affects") or []
        if isinstance(affect, dict) and affect.get("ref")
    }
    pairs = {}
    for finding in findings or []:
        if not isinstance(finding, dict) or not isinstance(finding.get("exploitability"), dict):
            continue
        for component in finding.get("components") or []:
            key = (str(finding.get("rule") or ""), str(component))
            if key in wanted:
                pairs[key] = finding["exploitability"]
    return pairs


def _render_results(tscan, findings=None) -> None:
    """Print the results table and summary stats of one project type.

    The table is the one the scan itself printed, rendered from the VDR the
    scan wrote. The dependency tree column stays empty, because the scan
    directory does not carry the BOM's dependency tree. The table renderer
    expects the fields the scan's writer always sets, so each entry is
    normalized on a copy rather than trusted.
    """
    vulnerabilities = []
    for vuln in tscan.vulnerabilities:
        entry = dict(vuln)
        entry.setdefault("id", "unknown")
        entry.setdefault("bom-ref", entry.get("purl") or entry["id"])
        if not isinstance(entry.get("insights"), list):
            entry["insights"] = []
        vulnerabilities.append(entry)
    options = VdrAnalysisKV(
        tscan.project_type,
        init_results=[],
        pkg_aliases={},
        purl_aliases={},
        suggest_mode=False,
        scoped_pkgs={},
        no_vuln_table=False,
        console=console,
        logger=LOG,
    )
    graded = _graded_pairs(findings, tscan.vulnerabilities)
    _rows, table = generate_console_output(vulnerabilities, {}, set(), options, graded)
    if table is not None:
        console.print(table)
    stats = summary_stats(tscan.vulnerabilities)
    if stats:
        console.print(
            "Summary for project type '{}': {}".format(
                tscan.project_type,
                ", ".join(f"{name.lower()}: {count}" for name, count in stats.items() if count),
            )
        )
    grade_stats = exploitability_grade_stats(graded)
    if grade_stats:
        console.print(
            "Exploitability grades for project type '{}': {}".format(
                tscan.project_type,
                ", ".join(f"{name}: {count}" for name, count in grade_stats.items()),
            )
        )
    if not tscan.vulnerabilities:
        console.print(f"No vulnerabilities found for project type '{tscan.project_type}'.")


def _run_json_report(result) -> int:
    """Print the loaded scan directory as one JSON document on stdout.

    ``scanDir`` carries the absolute, slash-separated form of the scan
    directory, as every path in a json document does outside the manifest
    and the findings; the manifest and the findings keep the
    scan-directory-relative paths their schemas define, with ``scanDir`` as
    their root.
    """
    print_json_document(
        {
            "scanDir": json_path(result.reports_dir),
            "manifest": result.manifest,
            "findings": result.findings,
        }
    )
    return 0


def _unexpected_failure(json_output: bool, exc: Exception) -> int:
    """Report a run that stopped with an error nothing above translates.

    The message and its traceback go on stderr as text; in json format the
    error document follows on stdout, so the stream never carries nothing.
    The exit code is 1, the "could not run" code of the exit table.
    """
    message = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
    LOG.exception("The report stopped with an unexpected error: %s", message)
    if json_output:
        print_error_document(EXIT_FAILURE, "report", message)
    return EXIT_FAILURE


def run_report_args(args: argparse.Namespace) -> int:
    """Run the report command from parsed arguments; the exit code.

    A directory that cannot be loaded, or an explanation whose inputs the
    directory does not hold, is reported with the reason on stderr and
    exits 1; in json format the reason is also the error document on
    stdout, with ``report`` as its verb. In text mode the tables go to
    stdout through the same console the scan renders on; in json mode
    stdout carries exactly one JSON document and nothing else.
    """
    json_output = args.format == "json"
    try:
        result = api.load_scan(args.scan_dir)
    except api.ScanError as exc:
        message = str(exc)
        if json_output:
            print_error_document(EXIT_FAILURE, "report", message)
        else:
            print(f"depscan report: {message}", file=sys.stderr)
        return EXIT_FAILURE
    except Exception as exc:
        return _unexpected_failure(json_output, exc)
    if json_output:
        return _run_json_report(result)
    manifest = result.manifest or {}
    console.print(
        f"Scan of {result.reports_dir}: dep-scan "
        f"{manifest.get('depscanVersion', 'unknown')}, layout "
        f"{manifest.get('layoutVersion', 'unknown')}"
    )
    for tscan in result.types:
        _render_results(tscan, result.findings)
    if args.explain:
        try:
            text = api.explain(result, mode=args.explanation_mode)
        except api.ScanError as exc:
            print(f"depscan report: {exc}", file=sys.stderr)
            return EXIT_FAILURE
        console.print(text)
    return 0


def run_report_command(argv: List[str]) -> int:
    """Run the report command from a raw argv; returns the process exit code."""
    return run_report_args(parse_report_args(argv))
