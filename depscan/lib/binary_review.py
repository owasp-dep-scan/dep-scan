"""Rendering of the blint binary review's results on a console.

The review's checks reach the scan directory as the ``binary-hardening``
category of ``depscan.findings.json``, and its coverage as blint's own
``analysis-coverage.json`` under ``analysis/blint/``. This module renders
both: the table of hardening findings and the one-line statement of the
review's coverage. The scan's rendering stage prints them on the console it
records into ``depscan.txt`` and ``depscan.html``, and the ``depscan
report`` verb prints them from a saved scan directory, so the two show the
same section. Nothing here runs blint or reads anything outside what a scan
wrote.
"""

import json
import os
from typing import Any, Dict, Iterable, List, Optional

from rich import box
from rich.markup import escape
from rich.table import Table

#: The findings category the blint review's checks become.
HARDENING_CATEGORY = "binary-hardening"

#: Where a scan directory keeps the review's coverage report, relative to
#: the directory the review wrote its reports beside the BOM in, with
#: forward slashes so it reads the same on every platform.
COVERAGE_RELATIVE_PATH = "analysis/blint/analysis-coverage.json"

#: The unit counts a coverage report carries, in the order they are stated.
_UNIT_KEYS = ("attempted", "succeeded", "failed", "skipped")


def hardening_rows(findings: Optional[Iterable[Any]]) -> List[Dict[str, Any]]:
    """The binary-hardening findings among ``findings``, in their order.

    ``findings`` are the dicts of ``depscan.findings.json``; findings of
    every other category, and entries that are not objects, are left out.
    """
    return [
        finding
        for finding in findings or []
        if isinstance(finding, dict) and finding.get("category") == HARDENING_CATEGORY
    ]


def _binary_name(finding: Dict[str, Any]) -> str:
    """The binary a hardening finding names: its first location's file."""
    for location in finding.get("locations") or []:
        if isinstance(location, dict) and location.get("binary"):
            return str(location["binary"])
    return ""


def binary_hardening_table(rows: List[Dict[str, Any]]) -> Table:
    """The console table of the review's binary-hardening findings.

    The caption counts the rows, so it is the number of binary-hardening
    findings the findings file holds.
    """
    table = Table(
        title="Binary Hardening Results",
        box=box.DOUBLE_EDGE,
        header_style="bold magenta",
        show_lines=False,
        min_width=150,
        caption=f"Binary hardening findings count: {len(rows)}",
    )
    for header in ("Binary", "Check", "Severity", "Title"):
        table.add_column(header=header, vertical="top")
    for finding in rows:
        # The cells are text from the binary and the check, never markup: a
        # title such as "[/x]" would otherwise raise or be rendered away.
        table.add_row(
            escape(_binary_name(finding)),
            escape(str(finding.get("rule") or "")),
            escape(str(finding.get("severity") or "").upper()),
            escape(str(finding.get("title") or "")),
        )
    return table


def coverage_path(base_dir: str) -> str:
    """The coverage report's path under the directory the review wrote its
    reports beside the BOM in."""
    return os.path.join(str(base_dir), *COVERAGE_RELATIVE_PATH.split("/"))


def read_coverage_units(path: str) -> Optional[Dict[str, int]]:
    """The unit counts of one blint coverage report, or None.

    A report reads when it is a JSON object whose ``units`` object carries
    the four counts; a count that is not a number is left out rather than
    guessed. A missing or unreadable file returns None, which the summary
    line reports instead of staying silent.
    """
    try:
        with open(path, encoding="utf-8") as fp:
            document = json.load(fp)
    except (OSError, ValueError):
        return None
    units = document.get("units") if isinstance(document, dict) else None
    if not isinstance(units, dict):
        return None
    counts = {
        key: units[key]
        for key in _UNIT_KEYS
        if isinstance(units.get(key), int) and not isinstance(units.get(key), bool)
    }
    return counts or None


def sum_coverage_units(units: Iterable[Optional[Dict[str, int]]]) -> Optional[Dict[str, int]]:
    """The unit counts of several coverage reports added together.

    A scan of several project types can run the review once per type; the
    counts add up because each unit belongs to one review run. A report
    that could not be read contributes nothing, so it still shows up as the
    missing report in the line the summary builds from the sum.
    """
    total: Dict[str, int] = {}
    for counts in units:
        for key, value in (counts or {}).items():
            total[key] = total.get(key, 0) + value
    return total or None


def coverage_summary(
    findings_count: int, units: Optional[Dict[str, int]], coverage_relative: str
) -> str:
    """The one-line statement of the review's coverage.

    A review whose units all succeeded and produced no findings is said so
    with its unit counts, so a clean binary check never reads as a scan
    that found nothing to check. A report with failed or skipped units
    names the gaps, and a missing or unreadable report is named as such
    with its place in the scan directory, so an unevidenced clean is never
    claimed either.
    """
    if units is None:
        return (
            "Binary hardening checks ran, but the coverage report "
            f"{coverage_relative} is missing or unreadable, so their "
            "coverage was not assessed."
        )
    counts = ", ".join(f"{units.get(key, 0)} {key}" for key in _UNIT_KEYS)
    if units.get("failed", 0) or units.get("skipped", 0):
        return f"Binary hardening checks completed with gaps: {counts} units."
    if findings_count:
        return f"Binary hardening checks completed: {counts} units."
    return f"Binary hardening checks completed with no findings: {counts} units."
