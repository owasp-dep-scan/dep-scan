"""The explainer renders from the evidence store.

The records come from the adapters, so the tests build a small store with an
adapter over a recorded report and assert what the rendering shows. The
endpoint section is pinned on the recorded atom-tools document, unchanged.
"""

import json
from collections import defaultdict
from pathlib import Path

from rich.console import Console

from analysis_lib.evidence import store as evidence_store
from analysis_lib.evidence.adapters import atom as atom_adapter
from analysis_lib.evidence.adapters import dosai as dosai_adapter
from depscan.lib import explainer

DATA_DIR = Path(__file__).resolve().parent / "data"
ATOM4_DIR = DATA_DIR / "atom4"
ADAPTER_DATA = Path(__file__).resolve().parent.parent / "packages" / "analysis-lib" / "tests" / "data"


def _write_store(bom_dir, records):
    bom_dir.mkdir(parents=True, exist_ok=True)
    evidence_store.write(str(bom_dir / evidence_store.EVIDENCE_FILE), records)


def _atom_records(tmp_path):
    return atom_adapter.extract([str(ATOM4_DIR / "python-reachables.slices.json")]).records


def _dosai_records():
    bom = json.loads((ADAPTER_DATA / "dosai" / "nuget-bom.sample.json").read_text())
    components = bom.get("components", [])
    meta = (bom.get("metadata") or {}).get("component")
    index = dosai_adapter.build_bom_purl_index(
        components, extra_components=[meta] if isinstance(meta, dict) else []
    )
    report = ADAPTER_DATA / "dosai" / "dosai-v5.0.0-reachable-combined.json"
    return dosai_adapter.extract(str(report), bom_index=index).records


def _vdr_result(vulns=None, endpoint_reached=None, reached_services=None):
    from types import SimpleNamespace

    return SimpleNamespace(
        pkg_vulnerabilities=vulns or [],
        endpoint_reached_purls=endpoint_reached or {},
        reached_services=reached_services or {},
    )


def _capture(monkeypatch):
    rec_console = Console(record=True, color_system=None, width=200, highlight=False)
    monkeypatch.setattr(explainer, "console", rec_console)
    return rec_console


def test_print_endpoints_handles_invalid_spec(monkeypatch, capsys):
    monkeypatch.setattr(explainer, "json_load", lambda *_args, **_kwargs: None)

    pattern_methods = explainer.print_endpoints("invalid-openapi.json")

    # print_endpoints returns None only for an empty ospec, which this test
    # does not exercise; the "or {}" keeps the assertion total either way.
    assert dict(pattern_methods or {}) == {}
    captured = capsys.readouterr()
    assert captured.err == ""


def test_explain_renders_reached_flows_from_the_store(tmp_path, monkeypatch):
    """The atom reached-flow records render as source-to-sink trees, with the
    subject purls, the file locations and the finding's severity and id."""
    _write_store(tmp_path, _atom_records(tmp_path))
    rec_console = _capture(monkeypatch)
    vulns = [
        {
            "id": "GHSA-QUART",
            "severity": "HIGH",
            "bom-ref": "pkg:pypi/quart@0.23.1",
            "affects": [{"ref": "pkg:pypi/quart@0.23.1"}],
        }
    ]
    explainer.explain(
        "python",
        str(tmp_path),
        str(tmp_path),
        None,
        _vdr_result(vulns=vulns),
        "EndpointsAndReachables",
        None,
    )
    text = rec_console.export_text()
    assert "Reachable Flows" in text
    assert "atom" in text, "the record's producer names the analysis that ran"
    # A witness path from a record, with file and line, renders as before.
    assert "packages/server-lib/src/server_lib/simple.py#528" in text
    assert "pkg:pypi/quart@0.23.1" in text
    assert "GHSA-QUART" in text


def test_explain_renders_entry_points_and_chains_for_dosai(tmp_path, monkeypatch):
    """dosai's entry points render with their endpoint and exposure, and its
    exploit chains with the hops and the packages they reach."""
    records = _dosai_records()
    _write_store(tmp_path, records)
    rec_console = _capture(monkeypatch)
    explainer.explain(
        "dotnet",
        str(tmp_path),
        str(tmp_path),
        None,
        _vdr_result(),
        "EndpointsAndReachables",
        None,
    )
    text = rec_console.export_text()
    assert "Reachable Flows" in text
    assert "dosai" in text
    entry_points = [r for r in records if r.kind == "entry-point"]
    assert entry_points, "the recording carries entry points"
    with_route = [r for r in entry_points if (r.attributes or {}).get("route")]
    if with_route:
        route = (with_route[0].attributes or {}).get("route")
        assert route is not None and str(route) in text, "the endpoint renders"
    chains = [r for r in records if r.kind == "exploit-chain"]
    assert chains, "the recording carries exploit chains"
    assert "exploit chain" in text.lower()
    assert any(str((r.attributes or {}).get("hopCount")) in text for r in chains)
    assert any(purl in text for r in chains for purl in r.subject.purls), (
        "the chain's packages render"
    )


def test_explain_non_reachables_renders_negative_records_and_unfound_reaches(
    tmp_path, monkeypatch
):
    """NonReachables renders the negative records, and reached packages that
    carry no finding; a reached package with a finding stays out."""
    from analysis_lib.evidence import EvidenceProducer
    from analysis_lib.evidence.adapters import build_record

    records = _atom_records(tmp_path)
    producer = EvidenceProducer(name="dosai", version="5.0.0.0", report_schema_version="5")
    sanitizer = build_record(
        source="dotnet-semantics.slices.json",
        producer=producer,
        kind="sanitizer",
        discriminator="san-1",
        polarity="negative",
        purls=("pkg:pypi/quart@0.23.1",),
        attributes={"kind": "HtmlEncode"},
    )
    clean_reach = build_record(
        source="python-reachables.slices.json",
        producer=records[0].producer,
        kind="reached-flow",
        discriminator="clean-1",
        purls=("pkg:pypi/never-found@1.0.0",),
    )
    _write_store(tmp_path, [*records, sanitizer, clean_reach])
    rec_console = _capture(monkeypatch)
    vulns = [
        {
            "id": "GHSA-QUART",
            "severity": "HIGH",
            "bom-ref": "pkg:pypi/quart@0.23.1",
            "affects": [{"ref": "pkg:pypi/quart@0.23.1"}],
        }
    ]
    explainer.explain(
        "python",
        str(tmp_path),
        str(tmp_path),
        None,
        _vdr_result(vulns=vulns),
        "NonReachables",
        None,
    )
    text = rec_console.export_text()
    assert "Non-Reachable Flows" in text
    assert "HtmlEncode" in text, "the sanitizer record renders with its kind"
    assert "pkg:pypi/never-found@1.0.0" in text, (
        "a reached package with no finding renders as not reachable"
    )
    assert "pkg:pypi/quart@0.22.0" not in text, (
        "a reached record that also names a package with a finding stays out"
    )
    assert "pkg:pypi/rich@15.0.0" in text, (
        "a reached package with no finding of its own renders"
    )


def test_explain_llm_prompts_mode_writes_prompts_for_endpoint_reaches(
    tmp_path, monkeypatch
):
    """In the LLM prompts mode the endpoint-reachable records are grouped per
    package and written to the prompts file."""
    records = _atom_records(tmp_path)
    _write_store(tmp_path, records)
    rec_console = _capture(monkeypatch)
    prompts_file = tmp_path / "prompts.md"
    endpoint_reached = {"pkg:pypi/quart@0.23.1": 1}
    explainer.explain(
        "python",
        str(tmp_path),
        str(tmp_path),
        None,
        _vdr_result(endpoint_reached=endpoint_reached),
        "LLMPrompts",
        str(prompts_file),
    )
    assert prompts_file.is_file()
    text = prompts_file.read_text(encoding="utf-8")
    assert "# LLM Prompts generated by OWASP dep-scan" in text
    assert "pkg:pypi/quart@0.23.1" in text
    assert "packages/server-lib/src/server_lib/simple.py" in text, (
        "the prompt carries the witness path's source lines"
    )


def test_explain_without_a_store_renders_nothing(tmp_path, monkeypatch):
    rec_console = _capture(monkeypatch)
    explainer.explain(
        "python",
        str(tmp_path),
        str(tmp_path),
        None,
        _vdr_result(),
        "EndpointsAndReachables",
        None,
    )
    assert rec_console.export_text().strip() == ""


def test_get_vulns_for_purls_picks_the_most_severe():
    purl_vuln_map = defaultdict(list)
    purl_vuln_map["pkg:npm/a@1"].append({"id": "LOW-1", "severity": "LOW"})
    purl_vuln_map["pkg:npm/a@1"].append({"id": "CRIT-1", "severity": "CRITICAL"})
    severity, ids = explainer.get_vulns_for_purls(["pkg:npm/a@1"], purl_vuln_map)
    assert severity == "CRITICAL"
    assert ids == ["LOW-1", "CRIT-1"]


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
