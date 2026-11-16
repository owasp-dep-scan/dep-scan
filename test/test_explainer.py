import json
import os
import re
from collections import defaultdict
from pathlib import Path

import pytest
from rich.console import Console
from rich.markdown import Markdown

from depscan.lib import explainer

DATA_DIR = Path(__file__).resolve().parent / "data"
ATOM4_DIR = DATA_DIR / "atom4"


@pytest.fixture
def test_data():
    """The recorded atom 4.0.2 reachables slice (see atom4/README.md)."""
    with open(ATOM4_DIR / "python-reachables.slices.json", encoding="utf-8") as fp:
        return json.load(fp)


@pytest.fixture
def rust_slices():
    with open(
        os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "data",
            "rust-reachables.slices.json",
        ),
        mode="r",
        encoding="utf-8",
    ) as fp:
        return json.load(fp)


@pytest.fixture
def go_slices():
    with open(
        os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "data",
            "go-reachables.slices.json",
        ),
        mode="r",
        encoding="utf-8",
    ) as fp:
        return json.load(fp)


@pytest.fixture
def dotnet_slices():
    with open(
        os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "data",
            "dotnet-reachables.slices.json",
        ),
        mode="r",
        encoding="utf-8",
    ) as fp:
        return json.load(fp)


def test_explain_reachables(test_data, capsys):
    explainer.explain_reachables("auto", test_data, "python", {}, None)
    captured = capsys.readouterr()
    assert captured.err == ""


def test_print_endpoints_handles_invalid_spec(monkeypatch, capsys):
    monkeypatch.setattr(explainer, "json_load", lambda *_args, **_kwargs: None)

    pattern_methods = explainer.print_endpoints("invalid-openapi.json")

    # print_endpoints returns None only for an empty ospec, which this test
    # does not exercise; the "or {}" keeps the assertion total either way.
    assert dict(pattern_methods or {}) == {}
    captured = capsys.readouterr()
    assert captured.err == ""


def test_explain_reachables_handles_non_list_input(capsys):
    has_explanation, has_crypto_flows, tips = explainer.explain_reachables(
        "auto", None, "python", None, {}
    )

    assert has_explanation is False
    assert has_crypto_flows is False
    assert tips == "## Secure Design Tips"
    captured = capsys.readouterr()
    assert captured.err == ""


def test_explain_flows_handles_non_string_code_and_list_tags(capsys):
    tree, added_ids, comment, source_sink_desc, source_code_str, sink_code_str, *_rest = (
        explainer.explain_flows(
            "auto",
            [
                {
                    "id": 1,
                    "label": "METHOD_PARAMETER_IN",
                    "name": "user_input",
                    "parentFileName": "src/app.py",
                    "parentMethodName": None,
                    "lineNumber": 10,
                    "code": None,
                    "tags": ["crypto", "RESOLVED_MEMBER"],
                },
                {
                    "id": 2,
                    "label": "RETURN",
                    "parentFileName": "src/app.py",
                    "parentMethodName": "handler",
                    "lineNumber": 22,
                    "code": 12345,
                    "tags": None,
                },
            ],
            None,
            "python",
            None,
            {},
        )
    )

    assert tree is not None
    assert added_ids == ["1", "2"]
    assert comment == ""
    assert source_sink_desc
    assert source_code_str == ""
    assert sink_code_str == "12345"
    captured = capsys.readouterr()
    assert captured.err == ""


# ---------------------------------------------------------------------------
# Rust / Go analyzer-slice rendering (console)
# ---------------------------------------------------------------------------


def test_is_analyzer_slice_detects_rust(rust_slices):
    assert explainer.is_analyzer_slice(rust_slices[0].get("flows")) is True


def test_is_analyzer_slice_detects_go(go_slices):
    assert explainer.is_analyzer_slice(go_slices[0].get("flows")) is True


def test_is_analyzer_slice_detects_dotnet(dotnet_slices):
    assert explainer.is_analyzer_slice(dotnet_slices[0].get("flows")) is True


def test_is_analyzer_slice_rejects_atom_slices(test_data):
    """Java/JS atom slices must NOT be detected as analyzer slices."""
    for areach in test_data:
        flows = areach.get("flows", [])
        if flows:
            assert explainer.is_analyzer_slice(flows) is False
            break


def test_explain_reachables_rust_renders_flows(monkeypatch, rust_slices):
    """Rust slices must render a readable source -> sink data-flow with
    file:line, tags, and the vulnerable purl in the console output."""
    rec_console = Console(record=True, color_system=None, width=140)
    monkeypatch.setattr(explainer, "console", rec_console)

    purl_vuln_map = defaultdict(list)
    purl_vuln_map["pkg:cargo/sqlx@0.6.2"].append({"id": "CVE-2024-SQLX", "severity": "HIGH"})

    header = Markdown("## Reachable Flows\n\nTest Rust flows.")
    has_explanation, _, _ = explainer.explain_reachables(
        "auto", rust_slices, "rust", None, purl_vuln_map, None, header
    )

    assert has_explanation, "at least one Rust flow must be explained"
    text = rec_console.export_text()
    # The external call description must appear
    assert "sqlx::query" in text
    # The file:line location must appear
    assert "src/main.rs" in text
    # The reconciled dependency purl must appear in the rendered tags/packages
    assert "pkg:cargo/sqlx@0.6.2" in text
    # The vulnerability id must appear
    assert "CVE-2024-SQLX" in text


def test_explain_reachables_go_renders_flows(monkeypatch, go_slices):
    """Go slices must render a readable source -> sink data-flow with
    file:line, tags, and the vulnerable purl in the console output."""
    rec_console = Console(record=True, color_system=None, width=140)
    monkeypatch.setattr(explainer, "console", rec_console)

    purl_vuln_map = defaultdict(list)
    purl_vuln_map["pkg:golang/github.com/jackc/pgx/v4@v4.18.1"].append(
        {"id": "CVE-2024-PGX", "severity": "CRITICAL"}
    )

    header = Markdown("## Reachable Flows\n\nTest Go flows.")
    has_explanation, _, _ = explainer.explain_reachables(
        "auto", go_slices, "go", None, purl_vuln_map, None, header
    )

    assert has_explanation, "at least one Go flow must be explained"
    text = rec_console.export_text()
    # The external call description must appear
    assert "pgx.Connect" in text
    # The file:line location must appear
    assert "main.go" in text
    # The reconciled dependency purl must appear
    assert "pkg:golang/github.com/jackc/pgx/v4@v4.18.1" in text
    # The vulnerability id must appear
    assert "CVE-2024-PGX" in text


def test_explain_reachables_dotnet_renders_flows(monkeypatch, dotnet_slices):
    """dotnet (dosai) slices must render a readable source -> sink data-flow
    with file:line, tags, and the vulnerable NuGet purl in the console output."""
    rec_console = Console(record=True, color_system=None, width=140)
    monkeypatch.setattr(explainer, "console", rec_console)

    purl_vuln_map = defaultdict(list)
    purl_vuln_map["pkg:nuget/System.Text.Json@10.0.0"].append(
        {"id": "GHSA-STJ-DOSAI", "severity": "HIGH"}
    )

    header = Markdown("## Reachable Flows\n\nTest .NET flows.")
    has_explanation, _, _ = explainer.explain_reachables(
        "auto", dotnet_slices, "dotnet", None, purl_vuln_map, None, header
    )

    assert has_explanation, "at least one dosai flow must be explained"
    text = rec_console.export_text()
    # The file:line location (C# source) must appear
    assert "McpServer.cs" in text
    # The reconciled dependency purl must appear in the rendered tags/packages
    assert "pkg:nuget/System.Text.Json@10.0.0" in text
    # The vulnerability id must appear
    assert "GHSA-STJ-DOSAI" in text


# ---------------------------------------------------------------------------
# Regression: atom explanation must be unchanged by gate relaxation
# ---------------------------------------------------------------------------


def test_explain_reachables_atom_explanation_count_unchanged(monkeypatch, test_data):
    """The gate relaxation for analyzer slices must NOT alter atom output.

    Atom slices carry labels on every node and never include ``rust``/``go``
    tags, so ``is_analyzer_slice`` returns False and the stricter >= 4-node
    gates remain in effect. The recorded slice holds five flows; four pass the
    atom gates and the fifth (2 nodes, no purls) is dropped before them.
    """
    rec_console = Console(record=True, color_system=None, width=140)
    monkeypatch.setattr(explainer, "console", rec_console)

    header = Markdown("## Reachable Flows\n\nTest Python flows.")
    has_explanation, _, _ = explainer.explain_reachables(
        "auto", test_data, "python", {}, None, None, header
    )

    assert has_explanation
    text = rec_console.export_text()
    # Count the rendered flow explanations by their "#N" table titles. This is
    # locked to the exact atom-gate output so that any accidental loosening of
    # the atom node/child gates (e.g. deriving the child gate from the relaxed
    # analyzer minimum) is caught as a regression. The expectation was counted
    # by hand from the fixture: one explanation per purl-carrying flow.
    flow_titles = re.findall(r"(?m)^#\d+ ", text)
    assert len(flow_titles) == 4, (
        f"atom-gate explanation count changed to {len(flow_titles)} "
        "(expected 4) -- the analyzer-slice gate relaxation must not affect "
        "atom output"
    )
    # Double-check: every flow in the fixture is treated as atom (not analyzer)
    for areach in test_data:
        flows = areach.get("flows", [])
        if flows:
            assert explainer.is_analyzer_slice(flows) is False


# ---------------------------------------------------------------------------
# The recorded atom 4 flows, rendered
# ---------------------------------------------------------------------------


def test_explain_flows_renders_one_recorded_atom4_flow(monkeypatch, test_data):
    """The rendered text for one recorded atom 4 flow, field by field.

    Flow 2 of the fixture (``run_scan`` in simple.py) was checked by hand
    against its node objects: every rendered line names a node's
    parentFileName#lineNumber and its code; the LITERAL at 528 renders as the
    bare ``True`` (a literal's quotes are stripped, and its tags - the two
    quart purls - are not printed because tags render only on parameter,
    identifier and call nodes); ``request.files`` at 531 and
    ``str(bom_file.filename)`` at 606 carry the external-call arrow; the
    identifier at 669 keeps atom 4's callee purl in its tags; the two nodes
    that share a file#line with an already-rendered node (the rsplit call at
    606, the NamedTemporaryFile call at 658, the file_write call at 669) are
    collapsed away; and the sink node at 669 closes the tree.
    """
    rec_console = Console(record=True, color_system=None, width=400, highlight=False)
    monkeypatch.setattr(explainer, "console", rec_console)
    flow = test_data[1]
    assert flow["purls"] == [
        "pkg:pypi/quart@0.22.0",
        "pkg:pypi/quart@0.23.1",
        "pkg:pypi/custom-json-diff@2.1.6",
    ]
    (
        tree,
        added_ids,
        comment,
        source_sink_desc,
        source_code_str,
        sink_code_str,
        *_rest,
    ) = explainer.explain_flows("auto", flow["flows"], flow["purls"], "python", None, {})
    rec_console.print(tree)
    expected = "\n".join(
        [
            "packages/server-lib/src/server_lib/simple.py#528    True",
            "├── packages/server-lib/src/server_lib/simple.py#531    request.files ⤴",
            "│   Tags: framework-input",
            "│   ",
            "├── packages/server-lib/src/server_lib/simple.py#583    uploaded_bom_file.get(\"file\", None)",
            "├── packages/server-lib/src/server_lib/simple.py#606    str(bom_file.filename) ⤴",
            "├── packages/server-lib/src/server_lib/simple.py#607    bom_file_suffix not in (\"json\", \"cdx\", \"bom\")",
            "├── packages/server-lib/src/server_lib/simple.py#660    {bom_file_suffix}",
            "├── packages/server-lib/src/server_lib/simple.py#658    tempfile.NamedTemporaryFile(delete = False, suffix = f\".bom.{bom_file_suffix}\", dir = _get_server_temp_dir())",
            "├── packages/server-lib/src/server_lib/simple.py#668    temp_paths.append(path)",
            "└── packages/server-lib/src/server_lib/simple.py#669    file_write(path, bom_file_content)",
            "    Tags: pkg:pypi/custom-json-diff@2.1.6",
            "    ",
            "",
        ]
    )
    assert rec_console.export_text() == expected
    assert added_ids == [
        "190080",
        "190104",
        "190503",
        "190660",
        "190674",
        "190905",
        "190913",
        "190930",
        "190936",
    ]
    assert source_sink_desc == "3 packages reachable from this data-flow."
    assert source_code_str == "True"
    assert sink_code_str == "file_write(path, bom_file_content)"
    assert "pkg:pypi/custom-json-diff@2.1.6" in comment


def test_print_endpoints_renders_atom_tools_1_x_spec(monkeypatch):
    """The endpoints table from the recorded atom-tools 1.0.5 document.

    ``x-atom-usages`` values are per-file line lists for ``call`` and
    ``target`` alike, and the hotspots column lists the ``file#line`` keys
    derived from them.
    """
    rec_console = Console(record=True, color_system=None, width=140)
    monkeypatch.setattr(explainer, "console", rec_console)
    pattern_methods = explainer.print_endpoints(str(ATOM4_DIR / "python-openapi.json"))
    assert set(pattern_methods or {}) == {
        "/analysis_lib/output",
        "/analysis_lib/search",
        "/",
        "/./pipe/x",
        "/LPT/u00b9",
        "/a/nb",
        "/a/rb",
        "/a/x00b",
    }
    text = rec_console.export_text()
    assert "packages/server-lib/src/server_lib/simple.py#433" in text
    assert "packages/analysis-lib/src/analysis_lib/output.py#985" in text
    assert "Identified Endpoints: 8" in text
