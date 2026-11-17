"""The ``depscan report`` command: render a saved scan directory again.

The command reads only the scan directory, through
:func:`depscan.api.load_scan`. It never generates BOMs, never runs
analyzers and never opens the vulnerability database: everything it shows
was written by the scan it renders. When the directory does not hold what a
rendering needs, the message names what is missing and the command exits
non-zero rather than printing something the scan did not produce.
"""

import argparse
import json
import sys
from typing import List

from analysis_lib import VdrAnalysisKV
from analysis_lib.output import generate_console_output, summary_stats

from depscan import api
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


def _render_results(tscan) -> None:
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
    _rows, table = generate_console_output(vulnerabilities, {}, set(), options)
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
    if not tscan.vulnerabilities:
        console.print(f"No vulnerabilities found for project type '{tscan.project_type}'.")


def _run_json_report(result) -> int:
    """Print the loaded scan directory as one JSON document on stdout."""
    print(
        json.dumps(
            {
                "scanDir": result.reports_dir,
                "manifest": result.manifest,
                "findings": result.findings,
            },
            indent=2,
        )
    )
    return 0


def run_report_args(args: argparse.Namespace) -> int:
    """Run the report command from parsed arguments; the exit code.

    A directory that cannot be loaded, or an explanation whose inputs the
    directory does not hold, is reported with the reason on stderr and
    exits 1. In text mode the tables go to stdout through the same console
    the scan renders on; in json mode stdout carries exactly one JSON
    document and nothing else.
    """
    try:
        result = api.load_scan(args.scan_dir)
    except api.ScanError as exc:
        print(f"depscan report: {exc}", file=sys.stderr)
        return 1
    if args.format == "json":
        return _run_json_report(result)
    manifest = result.manifest or {}
    console.print(
        f"Scan of {result.reports_dir}: dep-scan "
        f"{manifest.get('depscanVersion', 'unknown')}, layout "
        f"{manifest.get('layoutVersion', 'unknown')}"
    )
    for tscan in result.types:
        _render_results(tscan)
    if args.explain:
        try:
            text = api.explain(result, mode=args.explanation_mode)
        except api.ScanError as exc:
            print(f"depscan report: {exc}", file=sys.stderr)
            return 1
        console.print(text)
    return 0


def run_report_command(argv: List[str]) -> int:
    """Run the report command from a raw argv; returns the process exit code."""
    return run_report_args(parse_report_args(argv))
