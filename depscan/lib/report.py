"""The ``depscan report`` command: render a saved scan directory again.

The command reads only the scan directory, through
:func:`depscan.api.load_scan`. It never generates BOMs, never runs
analyzers and never opens the vulnerability database: everything it shows
was written by the scan it renders. When the directory does not hold what a
rendering needs, the message names what is missing and the command exits
non-zero rather than printing something the scan did not produce.

The command also re-evaluates the decisions: the current decisions file is
applied to the saved findings and the gate runs again, so a decision made
after the scan takes effect without rescanning, one removed or expired
since stops applying, and a CI job can gate a scan made earlier. When the
decisions file the scan recorded cannot be found, the gate result the scan
saved is kept, with a warning, instead of passing silently. The
re-evaluation writes nothing into the scan directory unless ``--out`` names
a file.
"""

import argparse
import os
import sys
from typing import List, Optional, Tuple

from analysis_lib import VdrAnalysisKV
from analysis_lib.findings import decisions as decision_lib
from analysis_lib.output import (
    affects_fix_version,
    exploitability_grade_stats,
    generate_console_output,
    pkg_sub_tree,
    purl_prefix_from_ref,
    summary_stats,
)

from depscan import api
from depscan.lib import binary_review, decisions as decisions_lib, supply_chain_review
from depscan.commands.output import (
    EXIT_FAILURE,
    EXIT_USAGE,
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
    parser.add_argument(
        "--decisions",
        help="Path to the decisions file to apply to the saved findings. "
        "Default: DEPSCAN_DECISIONS, then the decisions key of the "
        "configuration files, then the file the scan's manifest records, "
        "resolved against the scan directory. A file other than the "
        "recorded one is named in a warning.",
    )
    parser.add_argument(
        "--config",
        help="Path to the configuration file whose [scan] decisions key names "
        "a decisions file. Default: DEPSCAN_CONFIG, then "
        "$PWD/.config/depscan.toml.",
    )
    parser.add_argument(
        "--baseline",
        help="Reference scan (a scan directory or a depscan.findings.json "
        "path, relative to the working directory) that marks every finding "
        "new or existing for this run, instead of the [baseline] the "
        "decisions file names.",
    )
    parser.add_argument(
        "--fail-on",
        action="append",
        dest="fail_on",
        metavar="SELECTORS",
        help="Gate for this evaluation, as key=value selector pairs joined by "
        'commas, for example "category=vulnerability,reach=reached". Same grammar '
        "as the decisions file's [[expect]] entries. Replaces the --fail-on "
        "expressions the scan recorded, which apply again otherwise.",
    )
    parser.add_argument(
        "--vex",
        action="append",
        metavar="FILE",
        help="Load a CycloneDX VEX or OpenVEX document as triage decisions "
        "that apply at once, with the document named as their author. "
        "Repeatable. Replaces the VEX documents the scan recorded, which "
        "apply again otherwise.",
    )
    parser.add_argument(
        "--out",
        help="File the re-evaluated gate result is written to, as "
        "depscan.expectations.json would be. Without it the evaluation "
        "writes nothing into the scan directory.",
    )


def parse_report_args(argv: List[str]) -> argparse.Namespace:
    """Parse the arguments after ``report``."""
    parser = argparse.ArgumentParser(
        prog="depscan report",
        description="Render the console tables and explanations of a saved scan.",
    )
    register_arguments(parser)
    return parser.parse_args(argv)


#: The property that carries an entry's plain insights, joined into one
#: value by the backslash-n the VDR writer writes.
INSIGHTS_PROPERTY = "depscan:insights"
INSIGHTS_SEPARATOR = "\\n"


def _table_entry(vuln):
    """One VDR entry as the input the table renderer expects.

    The renderer reads the transient fields the scan's analysis attaches to
    its entries, which the VDR writer strips before the file is written, so
    each is rebuilt from the fields the file persists: the insights from the
    ``depscan:insights`` property, the fix version and the package prefix
    from the first affects entry, and the package column as a single-node
    tree that names the advisory the way the scan-time tree does. Entries
    that name no affects ref keep the renderer's empty forms.
    """
    entry = dict(vuln)
    entry.setdefault("id", "unknown")
    entry.setdefault("bom-ref", entry.get("purl") or entry["id"])
    insights = []
    for prop in entry.get("properties") or []:
        if isinstance(prop, dict) and prop.get("name") == INSIGHTS_PROPERTY:
            insights.extend(
                part for part in str(prop.get("value") or "").split(INSIGHTS_SEPARATOR) if part
            )
    entry["insights"] = insights
    affects = [
        affect
        for affect in entry.get("affects") or []
        if isinstance(affect, dict) and affect.get("ref")
    ]
    if not affects:
        entry["purl_prefix"] = ""
        entry["fixed_location"] = ""
        entry["p_rich_tree"] = None
        return entry
    ref = str(affects[0]["ref"])
    entry["purl_prefix"] = purl_prefix_from_ref(ref)
    # The affects versions are where the scan's writer puts the fix; an
    # entry that instead carries the transient field itself (a hand-made or
    # stub-written VDR) keeps it.
    entry["fixed_location"] = affects_fix_version(affects[0]) or str(
        entry.get("fixed_location") or ""
    )
    rating = (entry.get("ratings") or [{}])[0]
    _, entry["p_rich_tree"] = pkg_sub_tree(
        ref,
        ref.replace(":", "/"),
        {},
        pkg_severity=rating.get("severity") or "unknown",
        as_tree=True,
        extra_text=f":left_arrow: {entry['id']}",
    )
    return entry


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
    scan wrote. The dependency tree column shows the single affected
    component instead of the tree, because the scan directory does not carry
    the BOM's dependency tree. The table renderer expects the fields the
    scan's analysis attaches to its entries, so each entry is rebuilt from
    the persisted VDR fields rather than trusted.
    """
    vulnerabilities = [_table_entry(vuln) for vuln in tscan.vulnerabilities]
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


def _render_binary_review(result) -> None:
    """Print the binary review's findings and coverage of a saved directory.

    The rows come from the binary-hardening findings of the directory's
    ``depscan.findings.json``, so the table's count agrees with that file,
    the way the scan's own rendering counts them, and the coverage line
    from blint's ``analysis-coverage.json`` under ``analysis/blint/``. A
    directory that holds neither, because no review ran, prints nothing
    here; a review that ran states its coverage, clean or not, so a clean
    one never reads as a scan that found nothing to check.
    """
    rows = binary_review.hardening_rows(result.findings)
    coverage_file = binary_review.coverage_path(result.reports_dir)
    has_coverage = os.path.isfile(coverage_file)
    if not rows and not has_coverage:
        return
    if rows:
        console.print(binary_review.binary_hardening_table(rows))
    units = binary_review.read_coverage_units(coverage_file) if has_coverage else None
    console.print(
        binary_review.coverage_summary(len(rows), units, binary_review.COVERAGE_RELATIVE_PATH)
    )


def _render_supply_chain(result) -> None:
    """Print the supply-chain findings of a saved directory, the rows the
    directory's ``depscan.findings.json`` holds with cdx-audit as producer."""
    rows = supply_chain_review.supply_chain_rows(result.findings)
    if rows:
        console.print(supply_chain_review.supply_chain_table(rows))


def _run_json_report(result, expectations: Optional[dict] = None) -> int:
    """Print the loaded scan directory as one JSON document on stdout.

    ``scanDir`` carries the absolute, slash-separated form of the scan
    directory, as every path in a json document does outside the manifest
    and the findings; the manifest and the findings keep the
    scan-directory-relative paths their schemas define, with ``scanDir`` as
    their root. ``expectations`` is the re-evaluated gate result, carried
    when the run applied decisions.
    """
    document = {
        "scanDir": json_path(result.reports_dir),
        "manifest": result.manifest,
        "findings": result.findings,
    }
    if expectations is not None:
        document["expectations"] = expectations
    print_json_document(document)
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


def _reevaluate(args: argparse.Namespace, result) -> Tuple[Optional[dict], int]:
    """The decisions applied to the saved findings, as a gate result.

    The decisions resolve through :func:`depscan.lib.decisions.load_for_saved_scan`
    and apply through :func:`depscan.lib.decisions.apply_run_decisions`, the
    function the scan's decisions stage calls. The findings are changed in
    place, so the renderings and the JSON document show the decisions as
    they stand now; the saved files keep the scan's own application. When a
    file the scan recorded cannot be found, the gate result the scan saved
    is the result: the findings keep the scan's application, and the
    console block, the JSON document and the exit code all come from that
    saved document, with the warnings added.

    :returns: The expectations document, None when there is nothing to
        evaluate and the scan saved no gate result, and the gate's exit code.
    :raises DecisionsUsageError: When a decisions option cannot be used.
    :raises GateUnavailableError: When the scan recorded a gate that can no
        longer be evaluated.
    :raises analysis_lib.findings.decisions.BaselineError: When the baseline
        cannot be read.
    """
    options = decisions_lib.parse_options(
        verb="report",
        decisions=getattr(args, "decisions", None),
        fail_on=getattr(args, "fail_on", None) or (),
        vex=getattr(args, "vex", None) or (),
        baseline=getattr(args, "baseline", None),
        config=getattr(args, "config", None),
    )
    saved = _saved_expectations(result.reports_dir)
    run = decisions_lib.load_for_saved_scan(options, result.manifest, result.reports_dir, saved)
    document = None
    if run.saved is not None:
        document = dict(run.saved)
        document["warnings"] = list(document.get("warnings") or []) + list(run.warnings)
    elif run.active:
        document = decisions_lib.apply_run_decisions(
            run,
            result.findings,
            stages=(result.manifest or {}).get("stages") or [],
            vulns=(vuln for tscan in result.types for vuln in tscan.vulnerabilities),
            source="report",
            scan_dir=result.reports_dir,
        )
    out = getattr(args, "out", None)
    if out and document is not None:
        from depscan.lib.scan_directory import atomic_write_json

        atomic_write_json(str(out), document)
    return document, decisions_lib.gate_exit(document)


def _saved_expectations(reports_dir: str) -> Optional[dict]:
    """The gate result the scan saved, or None when it saved none."""
    import json

    from depscan.lib.scan_directory import EXPECTATIONS_FILE

    try:
        with open(os.path.join(reports_dir, EXPECTATIONS_FILE), encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, ValueError):
        return None
    return document if isinstance(document, dict) else None


def run_report_args(args: argparse.Namespace) -> int:
    """Run the report command from parsed arguments; the exit code.

    A directory that cannot be loaded, or an explanation whose inputs the
    directory does not hold, is reported with the reason on stderr and
    exits 1; in json format the reason is also the error document on
    stdout, with ``report`` as its verb. In text mode the tables go to
    stdout through the same console the scan renders on; in json mode
    stdout carries exactly one JSON document and nothing else.

    The decisions, when the run has any, are applied to the saved findings
    and the gate runs again before anything renders: the decisions and gate
    block prints ahead of the full tables, and the exit code carries the
    gate, 4 over 3, beside the codes the exit table always had. A baseline
    that cannot be read, or whose digest does not match, stops the run with
    exit 1 and the reason, exactly as a scan stops, and so does a scan whose
    recorded gate can no longer be evaluated (the files it recorded and the
    gate result it saved are all gone). A decisions option that cannot be
    used is a usage error and exits 2.
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
    try:
        expectations, gate_exit_code = _reevaluate(args, result)
    except decisions_lib.DecisionsUsageError as exc:
        message = str(exc)
        if json_output:
            print_error_document(EXIT_USAGE, "report", message)
        else:
            print(message, file=sys.stderr)
        return EXIT_USAGE
    except (decision_lib.BaselineError, decisions_lib.GateUnavailableError) as exc:
        message = str(exc)
        if json_output:
            print_error_document(EXIT_FAILURE, "report", message)
        else:
            print(f"depscan report: {message}", file=sys.stderr)
        return EXIT_FAILURE
    except Exception as exc:
        return _unexpected_failure(json_output, exc)
    if json_output:
        # The text rendering prints the warnings in the decisions block; the
        # json document carries them, and stderr names them for a reader.
        for warning in (expectations or {}).get("warnings") or []:
            LOG.warning("depscan report: %s", warning)
        _run_json_report(result, expectations)
        return gate_exit_code
    manifest = result.manifest or {}
    console.print(
        f"Scan of {result.reports_dir}: dep-scan "
        f"{manifest.get('depscanVersion', 'unknown')}, layout "
        f"{manifest.get('layoutVersion', 'unknown')}"
    )
    # The decisions and gate block prints ahead of the full tables, so a
    # reviewer reads the verdict and the entries that need attention first.
    decisions_lib.print_block(expectations, len(result.findings))
    for tscan in result.types:
        _render_results(tscan, result.findings)
    _render_binary_review(result)
    _render_supply_chain(result)
    if args.explain:
        try:
            text = api.explain(result, mode=args.explanation_mode)
        except api.ScanError as exc:
            print(f"depscan report: {exc}", file=sys.stderr)
            return EXIT_FAILURE
        console.print(text)
    return gate_exit_code


def run_report_command(argv: List[str]) -> int:
    """Run the report command from a raw argv; returns the process exit code."""
    return run_report_args(parse_report_args(argv))
