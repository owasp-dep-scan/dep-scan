"""The supply-chain audit's findings in the console and HTML reports.

The findings come from cdx-audit through the evidence adapter and the
findings conversion; the table is built from the findings dep-scan writes,
so its count agrees with ``depscan.findings.json``. The scan test stubs
only cdx-audit itself, with the reports of real runs under
``test/data/cdx-audit/``.
"""

import io
import json
from pathlib import Path

from rich.console import Console
from rich.terminal_theme import DEFAULT_TERMINAL_THEME

from analysis_lib.evidence.adapters.cdx_audit import extract
from analysis_lib.findings.cdx_audit_convert import findings_from_cdx_audit_records
from depscan import api
from depscan.lib import pipeline, supply_chain_review
from depscan.lib import report as report_lib
from reporting_lib.htmlgen import ReportGenerator

from test.conftest import fake_cdx_audit
from test.test_scan_directory import scan_stubs  # noqa: F401 - a fixture

DATA_DIR = Path(__file__).parent / "data"
CONTAINER_REPORT = json.loads((DATA_DIR / "cdx-audit" / "container-report.json").read_text())


def _findings(name):
    report = json.loads((DATA_DIR / "cdx-audit" / name).read_text())
    records = extract(report, source="a.json", producer_version="13.10.0", source_root="/src").records
    return [finding.to_dict() for finding in findings_from_cdx_audit_records(records)]


def _text(table):
    buffer = io.StringIO()
    Console(file=buffer, width=200, force_terminal=False).print(table)
    return buffer.getvalue()


def test_the_table_names_rule_severity_packages_and_message():
    rows = supply_chain_review.supply_chain_rows(
        _findings("direct-report.json") + _findings("container-report.json")
    )
    text = _text(supply_chain_review.supply_chain_table(rows))
    assert "Supply-Chain Audit Results" in text
    assert "Supply-chain findings count: 12" in text
    assert "INT-005" in text and "LOW" in text
    assert "pkg:npm/left-pad@1.3.0" in text
    assert "(svc-a/package-lock.json)" in text, "the lockfile names the monorepo copy"
    assert "is deprecated" in text
    # A finding located by a bom-ref names the bom-ref; the most severe
    # findings come first.
    assert "crypto/algorithm/md5@1.2.840.113549.2.5" in text
    assert text.index("CBS-001") < text.index("INT-005")


def test_rows_are_cdx_audits_findings_only():
    blint = {"category": "binary-hardening", "rule": "CHECK_PIE", "producer": {"name": "blint"}}
    rows = supply_chain_review.supply_chain_rows([blint, None, *_findings("container-report.json")])
    assert {row["rule"] for row in rows} == {"CBS-001", "RFS-001"}


def test_report_verb_keeps_rootfs_findings_out_of_the_binary_table(
    scan_stubs, tmp_path, capsys, monkeypatch  # noqa: F811
):
    """A saved container scan whose findings file holds cdx-audit's RFS
    findings renders them in the supply-chain table, not in the blint
    Binary Hardening table."""
    monkeypatch.setenv("COLUMNS", "200")
    fake_cdx_audit(monkeypatch, {}, report=CONTAINER_REPORT)
    result = api.scan(
        api.scan_options(
            bom=str(_container_bom(tmp_path)),
            reports_dir=str(tmp_path / "reports"),
            no_banner=True,
            risk_audit=True,
        ),
        render=False,
    )
    assert any(f["rule"] == "RFS-001" for f in result.findings)
    capsys.readouterr()
    assert report_lib.run_report_command([str(tmp_path / "reports")]) == 0
    out = capsys.readouterr().out
    assert "Binary Hardening Results" not in out
    assert "Supply-Chain Audit Results" in out
    assert "RFS-001" in out


def _container_bom(tmp_path):
    path = tmp_path / "sbom-docker.cdx.json"
    path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "metadata": {"component": {"name": "img", "type": "container"}},
                "components": [
                    {"name": "left-pad", "version": "1.3.0", "purl": "pkg:npm/left-pad@1.3.0", "type": "library"}
                ],
            }
        )
    )
    return path


def test_a_scan_prints_the_table_unless_tables_are_off(
    scan_stubs, tmp_path, monkeypatch  # noqa: F811
):
    """The scan's console, and so depscan.txt, carries the table with the
    count of the findings the scan wrote; --no-vuln-table leaves it out."""
    monkeypatch.setenv("COLUMNS", "200")
    fake_cdx_audit(monkeypatch, {}, report=CONTAINER_REPORT)
    saved = {}

    def save_text(path, clear=False, styles=False):
        saved[str(path)] = pipeline.console.export_text(clear=False)

    monkeypatch.setattr(pipeline.console, "save_text", save_text)
    for no_table in (False, True):
        pipeline.console.record = True
        pipeline.console.export_text(clear=True)
        reports = tmp_path / f"reports-{no_table}"
        result = api.scan(
            api.scan_options(
                bom=str(_container_bom(tmp_path)),
                reports_dir=str(reports),
                no_banner=True,
                risk_audit=True,
                no_vuln_table=no_table,
            )
        )
        text = saved[str(reports / "depscan.txt")]
        supply = [f for f in result.findings if f["producer"]["name"] == "cdx-audit"]
        assert supply
        if no_table:
            assert "Supply-Chain Audit Results" not in text
        else:
            assert "Supply-Chain Audit Results" in text
            assert f"Supply-chain findings count: {len(supply)}" in text


def test_the_html_report_keeps_the_supply_chain_section(tmp_path):
    """The HTML report generator learns the section from the console HTML:
    one table row per finding, even when a message wraps, cells escaped."""
    rows = supply_chain_review.supply_chain_rows(_findings("container-report.json"))
    rows[0] = dict(rows[0], properties=[{"name": "cdx-audit:message", "value": "<b>x</b> " + "long " * 60}])
    console = Console(record=True, width=150, force_terminal=True)
    console.print(supply_chain_review.supply_chain_table(rows))
    rich_html = tmp_path / "rich.html"
    out_html = tmp_path / "depscan.html"
    console.save_html(str(rich_html), theme=DEFAULT_TERMINAL_THEME)
    ReportGenerator(
        input_rich_html_path=str(rich_html), report_output_path=str(out_html), raw_content=False
    ).parse_and_generate_report()
    html = out_html.read_text(encoding="utf-8")
    assert "Supply-Chain Audit Results" in html
    assert "Supply-chain findings count: 4" in html
    assert "<b>x</b>" not in html
    assert html.count("<td>RFS-001</td>") + html.count("<td>CBS-001</td>") == 4
    assert "╔" not in html


#: Finding text that Rich would read as markup, and HTML a report must not
#: carry as markup either.
HOSTILE_MESSAGES = [
    "evil [link=https://attacker.example]click me[/link] tail",
    "close all [/] then [bold red]RED",
    "<script>alert(1)</script> & <img src=x onerror=alert(2)>",
]


def _hostile_rows():
    rows = [
        {
            "producer": {"name": "cdx-audit"},
            "rule": f"R-{index}[/]",
            "severity": "high",
            "components": [f"pkg:npm/x{index}@1.0.0"],
            "properties": [{"name": "cdx-audit:message", "value": message}],
        }
        for index, message in enumerate(HOSTILE_MESSAGES)
    ]
    return supply_chain_review.supply_chain_rows(rows)


def test_finding_text_is_never_rich_markup():
    """A message or rule that looks like Rich markup is printed as written:
    no link is made, no style applied, and a stray closing tag neither
    raises nor swallows text."""
    console = Console(record=True, width=200, file=io.StringIO())
    console.print(supply_chain_review.supply_chain_table(_hostile_rows()))
    text = console.export_text(clear=False)
    html = console.export_html(clear=False)
    assert "[link=https://attacker.example]click me[/link]" in text
    assert "close all [/] then [bold red]RED" in text
    assert "R-0[/]" in text
    assert "attacker.example" not in html.split("<pre")[0]
    assert 'href="https://attacker.example"' not in html


def test_the_html_report_from_saved_text_escapes_the_cells(tmp_path):
    """depscan.html can be rebuilt from depscan.txt, where the cells are
    plain text; the generator escapes them on that path too."""
    console = Console(record=True, width=200, file=io.StringIO())
    console.print(supply_chain_review.supply_chain_table(_hostile_rows()))
    text_report = tmp_path / "depscan.txt"
    text_report.write_text(console.export_text(clear=False), encoding="utf-8")
    out_html = tmp_path / "depscan.html"
    ReportGenerator(
        input_txt_path=str(text_report), report_output_path=str(out_html), raw_content=False
    ).parse_and_generate_report()
    html = out_html.read_text(encoding="utf-8")
    section = html[html.index("Supply-Chain Audit Results</code>") :]
    assert "<script>alert" not in section
    assert "<img src=x" not in section
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in section
    assert "Supply-chain findings count: 3" in section

