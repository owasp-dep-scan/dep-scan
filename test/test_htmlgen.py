import json
import os
from collections import defaultdict

from rich.console import Console
from rich.markdown import Markdown

from depscan.lib import explainer
from reporting_lib.htmlgen import ReportGenerator


RICH_HTML_WRAPPER = """<!DOCTYPE html>
<html>
<head>
<style>
.r1 {{ color: #ffffff; }}
.r2 {{ color: #000000; }}
body {{ color: #000000; }}
</style>
</head>
<body>
<pre style="font-family:Menlo,'DejaVu Sans Mono',consolas,'Courier New',monospace"><code style="font-family:inherit">{report}</code></pre>
</body>
</html>
"""


def test_parse_and_generate_report_handles_split_span_bom_title(tmp_path):
    report = "\n".join(
        [
            "Vulnerability Disclosure Report",
            '<span class="r1">Dependency Scan Results </span><span class="r2">(BOM)</span>',
            "╔══════════════════════╤══════════════════════╤═════════════╤══════════╤═══════╗",
            '║<span class="r1"> Dependency </span><span class="r2">Tree      </span>│<span class="r1"> Insights </span><span class="r2">            </span>│<span class="r1"> Fix </span><span class="r2">Version </span>│<span class="r1"> Severity </span>│<span class="r2"> Score </span>║',
            "╟──────────────────────┼──────────────────────┼─────────────┼──────────┼───────╢",
            '║ <span class="r1">ajv-formats@2.1.1   </span> │ <span class="r2">📓 Indirect </span>         │ <span class="r1">8.18.0</span>      │ MEDIUM   │   5.0 ║',
            '║ <span class="r1">└── </span><span class="r2">ajv@8.17.1 ⬅    </span> │ <span class="r2">dependency</span>           │             │          │       ║',
            '║ <span class="r1">    </span><span class="r2">CVE-2025-69873  </span> │                      │             │          │       ║',
            "╚══════════════════════╧══════════════════════╧═════════════╧══════════╧═══════╝",
            '<span class="r1">Vulnerabilities </span><span class="r2">count: 1</span>',
            "",
            "╭─────────────────────────────── Recommendation ───────────────────────────────╮",
            "│ First recommendation line                                                    │",
            "│ Second recommendation line                                                   │",
            "╰──────────────────────────────────────────────────────────────────────────────╯",
        ]
    )
    input_html = tmp_path / "rich-report.html"
    output_html = tmp_path / "depscan.html"
    input_html.write_text(RICH_HTML_WRAPPER.format(report=report), encoding="utf-8")

    generator = ReportGenerator(
        input_rich_html_path=str(input_html),
        report_output_path=str(output_html),
        raw_content=False,
    )

    generator.parse_and_generate_report()

    rendered_report = output_html.read_text(encoding="utf-8")

    assert (
        "<span>The table below lists all vulnerabilities identified in this project."
        in rendered_report
    )
    assert "CVE-2025-69873" in rendered_report
    assert "First recommendation line" in rendered_report
    assert "<br>" in rendered_report
    assert "Second recommendation line" in rendered_report
    assert "white-space: pre-wrap;" in rendered_report
    assert "╔" not in rendered_report
    assert "<tbody>" in rendered_report and "<tr>" in rendered_report


def test_parse_and_generate_report_handles_universal_title(tmp_path):
    report = "\n".join(
        [
            "Vulnerability Disclosure Report",
            '<span class="r1">Dependency Scan Results </span><span class="r2">(UNIVERSAL)</span>',
            "╔══════════════════════╤══════════════════════╤═════════════╤══════════╤═══════╗",
            "║ Dependency Tree      │ Insights             │ Fix Version │ Severity │ Score ║",
            "╟──────────────────────┼──────────────────────┼─────────────┼──────────┼───────╢",
            "║ ajv-formats@2.1.1    │ 📓 Indirect          │ 8.18.0      │ MEDIUM   │   5.0 ║",
            "║ └── ajv@8.17.1 ⬅     │ dependency           │             │          │       ║",
            "║     CVE-2025-69873   │                      │             │          │       ║",
            "╚══════════════════════╧══════════════════════╧═════════════╧══════════╧═══════╝",
            "Vulnerabilities count: 1",
        ]
    )
    input_html = tmp_path / "rich-universal-report.html"
    output_html = tmp_path / "depscan-universal.html"
    input_html.write_text(RICH_HTML_WRAPPER.format(report=report), encoding="utf-8")

    generator = ReportGenerator(
        input_rich_html_path=str(input_html),
        report_output_path=str(output_html),
        raw_content=False,
    )

    generator.parse_and_generate_report()

    rendered_report = output_html.read_text(encoding="utf-8")

    assert "<h4>Dependency Scan Results (UNIVERSAL)</h4>" in rendered_report
    assert "CVE-2025-69873" in rendered_report
    assert "<tbody>" in rendered_report and "<tr>" in rendered_report
    assert "╔" not in rendered_report
    assert "Dependency Scan Results (UNIVERSAL)" in rendered_report


def test_parse_and_generate_report_accepts_unique_count_caption(tmp_path):
    """Discussion #527 follow-up: when affects[] expansion splits merged VDR
    entries into per-component rows, the caption counts (id, affects) pairs
    and appends the unique vulnerability count. The HTML badge must carry the
    whole caption."""
    report = "\n".join(
        [
            "Vulnerability Disclosure Report",
            '<span class="r1">Dependency Scan Results </span><span class="r2">(NODEJS)</span>',
            "╔══════════════════════╤══════════════════════╤═════════════╤══════════╤═══════╗",
            "║ Dependency Tree      │ Insights             │ Fix Version │ Severity │ Score ║",
            "╟──────────────────────┼──────────────────────┼─────────────┼──────────┼───────╢",
            "║ postcss@8.4.31 ⬅     │                      │ 8.5.0       │ HIGH     │   7.5 ║",
            "║ CVE-2026-41305       │                      │             │          │       ║",
            "║ postcss@8.4.49 ⬅     │                      │             │          │       ║",
            "║ CVE-2026-41305       │                      │             │          │       ║",
            "╚══════════════════════╧══════════════════════╧═════════════╧══════════╧═══════╝",
            "Vulnerabilities count: 2 (1 unique)",
        ]
    )
    input_html = tmp_path / "rich-unique-count-report.html"
    output_html = tmp_path / "depscan-unique-count.html"
    input_html.write_text(RICH_HTML_WRAPPER.format(report=report), encoding="utf-8")

    generator = ReportGenerator(
        input_rich_html_path=str(input_html),
        report_output_path=str(output_html),
        raw_content=False,
    )

    generator.parse_and_generate_report()

    rendered_report = output_html.read_text(encoding="utf-8")

    assert "Vulnerabilities count: 2 (1 unique)" in rendered_report
    assert "postcss@8.4.49" in rendered_report
    assert "<tbody>" in rendered_report and "<tr>" in rendered_report


# ---------------------------------------------------------------------------
# Rust / Go reachable flows through the full console.save_html + ReportGenerator
# ---------------------------------------------------------------------------


def _render_explainer_html(slices_data, project_type, purl_vuln_map, tmp_path):
    """Run the explainer on a recording console, save HTML, and return the path."""
    rec_console = Console(record=True, color_system="256", width=140, theme=None)
    original_console = explainer.console
    explainer.console = rec_console
    try:
        header = Markdown("## Reachable Flows\n\nBelow are several data flows.")
        explainer.explain_reachables(
            "auto", slices_data, project_type, None, purl_vuln_map, None, header
        )
    finally:
        explainer.console = original_console

    rich_html = tmp_path / "rich-report.html"
    rec_console.save_html(str(rich_html))
    return rich_html


def test_parse_and_generate_report_rust_reachable_flows(tmp_path):
    """The HTML report must contain the Rust reachable flow after
    console.save_html + ReportGenerator prettification."""
    data_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "data")
    with open(os.path.join(data_dir, "rust-reachables.slices.json"), encoding="utf-8") as fp:
        rust_slices = json.load(fp)

    purl_vuln_map = defaultdict(list)
    purl_vuln_map["pkg:cargo/sqlx@0.6.2"].append({"id": "CVE-2024-SQLX", "severity": "HIGH"})

    rich_html = _render_explainer_html(rust_slices, "rust", purl_vuln_map, tmp_path)
    output_html = tmp_path / "depscan-rust.html"

    generator = ReportGenerator(
        input_rich_html_path=str(rich_html),
        report_output_path=str(output_html),
        raw_content=False,
    )
    generator.parse_and_generate_report()

    rendered = output_html.read_text(encoding="utf-8")
    # The Reachable Flows section must not be empty
    assert "Reachable Flows" in rendered
    # The sqlx dependency purl must appear in the rendered report
    assert "pkg:cargo/sqlx@0.6.2" in rendered
    # The vulnerability id must appear
    assert "CVE-2024-SQLX" in rendered


def test_parse_and_generate_report_go_reachable_flows(tmp_path):
    """The HTML report must contain the Go reachable flow after
    console.save_html + ReportGenerator prettification."""
    data_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "data")
    with open(os.path.join(data_dir, "go-reachables.slices.json"), encoding="utf-8") as fp:
        go_slices = json.load(fp)

    purl_vuln_map = defaultdict(list)
    purl_vuln_map["pkg:golang/github.com/jackc/pgx/v4@v4.18.1"].append(
        {"id": "CVE-2024-PGX", "severity": "CRITICAL"}
    )

    rich_html = _render_explainer_html(go_slices, "go", purl_vuln_map, tmp_path)
    output_html = tmp_path / "depscan-go.html"

    generator = ReportGenerator(
        input_rich_html_path=str(rich_html),
        report_output_path=str(output_html),
        raw_content=False,
    )
    generator.parse_and_generate_report()

    rendered = output_html.read_text(encoding="utf-8")
    # The Reachable Flows section must not be empty
    assert "Reachable Flows" in rendered
    # The pgx dependency purl must appear in the rendered report
    assert "pkg:golang/github.com/jackc/pgx/v4@v4.18.1" in rendered
    # The vulnerability id must appear
    assert "CVE-2024-PGX" in rendered
