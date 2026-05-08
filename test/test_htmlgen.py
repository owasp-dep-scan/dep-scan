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
            'Vulnerability Disclosure Report',
            '<span class="r1">Dependency Scan Results </span><span class="r2">(BOM)</span>',
            '╔══════════════════════╤══════════════════════╤═════════════╤══════════╤═══════╗',
            '║<span class="r1"> Dependency </span><span class="r2">Tree      </span>│<span class="r1"> Insights </span><span class="r2">            </span>│<span class="r1"> Fix </span><span class="r2">Version </span>│<span class="r1"> Severity </span>│<span class="r2"> Score </span>║',
            '╟──────────────────────┼──────────────────────┼─────────────┼──────────┼───────╢',
            '║ <span class="r1">ajv-formats@2.1.1   </span> │ <span class="r2">📓 Indirect </span>         │ <span class="r1">8.18.0</span>      │ MEDIUM   │   5.0 ║',
            '║ <span class="r1">└── </span><span class="r2">ajv@8.17.1 ⬅    </span> │ <span class="r2">dependency</span>           │             │          │       ║',
            '║ <span class="r1">    </span><span class="r2">CVE-2025-69873  </span> │                      │             │          │       ║',
            '╚══════════════════════╧══════════════════════╧═════════════╧══════════╧═══════╝',
            '<span class="r1">Vulnerabilities </span><span class="r2">count: 1</span>',
            '',
            '╭─────────────────────────────── Recommendation ───────────────────────────────╮',
            '│ First recommendation line                                                    │',
            '│ Second recommendation line                                                   │',
            '╰──────────────────────────────────────────────────────────────────────────────╯',
        ]
    )
    input_html = tmp_path / 'rich-report.html'
    output_html = tmp_path / 'depscan.html'
    input_html.write_text(RICH_HTML_WRAPPER.format(report=report), encoding='utf-8')

    generator = ReportGenerator(
        input_rich_html_path=str(input_html),
        report_output_path=str(output_html),
        raw_content=False,
    )

    generator.parse_and_generate_report()

    rendered_report = output_html.read_text(encoding='utf-8')

    assert '<span>The table below lists all vulnerabilities identified in this project.' in rendered_report
    assert 'CVE-2025-69873' in rendered_report
    assert 'First recommendation line' in rendered_report
    assert '<br>' in rendered_report
    assert 'Second recommendation line' in rendered_report
    assert 'white-space: pre-wrap;' in rendered_report
    assert '╔' not in rendered_report
    assert '<tbody>' in rendered_report and '<tr>' in rendered_report


def test_parse_and_generate_report_handles_universal_title(tmp_path):
    report = "\n".join(
        [
            'Vulnerability Disclosure Report',
            '<span class="r1">Dependency Scan Results </span><span class="r2">(UNIVERSAL)</span>',
            '╔══════════════════════╤══════════════════════╤═════════════╤══════════╤═══════╗',
            '║ Dependency Tree      │ Insights             │ Fix Version │ Severity │ Score ║',
            '╟──────────────────────┼──────────────────────┼─────────────┼──────────┼───────╢',
            '║ ajv-formats@2.1.1    │ 📓 Indirect          │ 8.18.0      │ MEDIUM   │   5.0 ║',
            '║ └── ajv@8.17.1 ⬅     │ dependency           │             │          │       ║',
            '║     CVE-2025-69873   │                      │             │          │       ║',
            '╚══════════════════════╧══════════════════════╧═════════════╧══════════╧═══════╝',
            'Vulnerabilities count: 1',
        ]
    )
    input_html = tmp_path / 'rich-universal-report.html'
    output_html = tmp_path / 'depscan-universal.html'
    input_html.write_text(RICH_HTML_WRAPPER.format(report=report), encoding='utf-8')

    generator = ReportGenerator(
        input_rich_html_path=str(input_html),
        report_output_path=str(output_html),
        raw_content=False,
    )

    generator.parse_and_generate_report()

    rendered_report = output_html.read_text(encoding='utf-8')

    assert '<h4>Dependency Scan Results (UNIVERSAL)</h4>' in rendered_report
    assert 'CVE-2025-69873' in rendered_report
    assert '<tbody>' in rendered_report and '<tr>' in rendered_report
    assert '╔' not in rendered_report
    assert 'Dependency Scan Results (UNIVERSAL)' in rendered_report
