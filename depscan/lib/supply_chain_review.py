"""Rendering of the cdx-audit supply-chain findings on a console.

The supply-chain check's findings reach ``depscan.findings.json`` with
``cdx-audit`` as their producer: the ``supply-chain`` category, and the
``crypto`` and ``binary-hardening`` findings the container packs report.
This module renders them as one compact table, rule, severity, packages and
message, from the findings dep-scan writes, so the console, ``depscan.txt``,
``depscan.html`` and the ``depscan report`` verb show the same rows the
findings file holds. Nothing here runs cdx-audit.
"""

from typing import Any, Dict, Iterable, List, Optional

from rich import box
from rich.markup import escape
from rich.table import Table

#: The producer name the supply-chain findings carry.
PRODUCER = "cdx-audit"

#: The table's title, which the HTML report generator recognises.
TABLE_TITLE = "Supply-Chain Audit Results"

#: The caption prefix, which the HTML report generator reads the count from.
COUNT_CAPTION = "Supply-chain findings count"

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _property(finding: Dict[str, Any], name: str) -> str:
    for prop in finding.get("properties") or []:
        if isinstance(prop, dict) and prop.get("name") == name:
            return str(prop.get("value") or "")
    return ""


def supply_chain_rows(findings: Optional[Iterable[Any]]) -> List[Dict[str, Any]]:
    """The findings cdx-audit produced among ``findings``, most severe first.

    ``findings`` are the dicts of ``depscan.findings.json``; findings of
    every other producer, and entries that are not objects, are left out.
    """
    rows = [
        finding
        for finding in findings or []
        if isinstance(finding, dict)
        and isinstance(finding.get("producer"), dict)
        and finding["producer"].get("name") == PRODUCER
    ]
    return sorted(
        rows,
        key=lambda finding: (
            _SEVERITY_ORDER.get(str(finding.get("severity") or ""), 5),
            str(finding.get("rule") or ""),
        ),
    )


def _packages(finding: Dict[str, Any]) -> str:
    """The packages a finding names: its components, else the bom-ref of the
    component it was located by, with the declaring file when it has one."""
    names = [str(component) for component in finding.get("components") or []]
    if not names:
        ref = _property(finding, "cdx-audit:bomRef")
        if ref:
            names = [ref]
    files = [
        str(location.get("file"))
        for location in finding.get("locations") or []
        if isinstance(location, dict) and location.get("file")
    ]
    text = "\n".join(names)
    if files:
        text += ("\n" if text else "") + "(" + ", ".join(files) + ")"
    return text


def supply_chain_table(rows: List[Dict[str, Any]]) -> Table:
    """The console table of the supply-chain findings.

    The caption counts the rows, so it is the number of findings cdx-audit
    produced in the findings file.
    """
    table = Table(
        title=TABLE_TITLE,
        box=box.DOUBLE_EDGE,
        header_style="bold magenta",
        # A line between rows, so a wrapped package list or message reads
        # as one row, on the console and to the HTML report generator.
        show_lines=True,
        min_width=150,
        caption=f"{COUNT_CAPTION}: {len(rows)}",
    )
    for header in ("Rule", "Severity", "Package(s)", "Message"):
        table.add_column(header=header, vertical="top")
    for finding in rows:
        # The cells are text from the audit report, never markup.
        message = _property(finding, "cdx-audit:message") or str(finding.get("title") or "")
        upstream = _property(finding, "cdx-audit:upstreamFile")
        if upstream:
            # A predictive finding: the file is in the package's upstream
            # repository, not in the scanned tree.
            message += f" (upstream {upstream})"
        table.add_row(
            escape(str(finding.get("rule") or "")),
            escape(str(finding.get("severity") or "").upper()),
            escape(_packages(finding)),
            escape(message),
        )
    return table
