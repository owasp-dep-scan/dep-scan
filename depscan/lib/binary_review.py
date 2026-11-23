"""Rendering of the blint binary review's findings on a console.

The review's checks reach the scan directory as the ``binary-hardening``
category of ``depscan.findings.json``. This module renders that category as
a console table. The scan's rendering stage prints it on the console it
records into ``depscan.txt`` and ``depscan.html``, and the ``depscan
report`` verb prints it from a saved scan directory, so the two show the
same section. Nothing here runs blint or reads anything outside what a scan
wrote.
"""

from typing import Any, Dict, Iterable, List, Optional

from rich import box
from rich.table import Table

#: The findings category the blint review's checks become.
HARDENING_CATEGORY = "binary-hardening"


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
        table.add_row(
            _binary_name(finding),
            str(finding.get("rule") or ""),
            str(finding.get("severity") or "").upper(),
            str(finding.get("title") or ""),
        )
    return table
