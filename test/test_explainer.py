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
ADAPTER_DATA = (
    Path(__file__).resolve().parent.parent / "packages" / "analysis-lib" / "tests" / "data"
)


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


def _path(file_name, rows, method="handle"):
    """A witness path of ``rows`` nodes on distinct lines of one file."""
    from analysis_lib.evidence import EvidencePathNode

    return tuple(
        EvidencePathNode(file=file_name, line=10 + row, method=method, symbol=f"step{row}")
        for row in range(rows)
    )


def _flow_record(discriminator, purls, path, producer="atom", kind="reached-flow", source=None):
    from analysis_lib.evidence import EvidenceProducer
    from analysis_lib.evidence.adapters import build_record

    return build_record(
        source=source or "python-reachables.slices.json",
        producer=EvidenceProducer(name=producer, version="1", report_schema_version="1"),
        kind=kind,
        discriminator=discriminator,
        purls=tuple(purls),
        path=tuple(path),
    )


def _explain(tmp_path, monkeypatch, records, mode="EndpointsAndReachables"):
    _write_store(tmp_path, records)
    rec_console = _capture(monkeypatch)
    explainer.explain("python", str(tmp_path), str(tmp_path), None, _vdr_result(), mode, None)
    return rec_console.export_text()


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


def test_explain_renders_the_exploit_chains_for_dosai(tmp_path, monkeypatch):
    """dosai's exploit chains render with the hops and the packages they
    reach. Its entry points name no package and walk no path, so they are
    context for the chains and are not explained on their own."""
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
    assert all(not r.subject.purls and not r.path for r in entry_points)
    assert "dosai entry-point:" not in text
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
        path=_path("app/clean.py", 5),
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
    assert "pkg:pypi/rich@15.0.0" in text, "a reached package with no finding of its own renders"


def test_explain_llm_prompts_mode_writes_prompts_for_endpoint_reaches(tmp_path, monkeypatch):
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


# --- the quality gates -------------------------------------------------------------


def test_records_without_purls_or_a_followable_path_are_not_explained(tmp_path, monkeypatch):
    """atom's usage records name no package and dosai's package summaries
    walk no path; neither may fill the explanation cap. An exploit chain is
    context and renders without either."""
    usage = _flow_record("usage-1", [], _path("app/usage.py", 6), kind="usage")
    summary = _flow_record("summary-1", ["pkg:nuget/a@1"], [], producer="dosai")
    chain = _flow_record("chain-1", [], [], producer="dosai", kind="exploit-chain")
    shown = _flow_record("shown-1", ["pkg:pypi/shown@1"], _path("app/shown.py", 5))
    text = _explain(tmp_path, monkeypatch, [usage, summary, chain, shown])
    assert "app/usage.py" not in text, "a record without purls is not a reachable flow"
    assert "pkg:nuget/a@1" not in text, "a record without a path shows no flow"
    assert "exploit-chain" in text, "an exploit chain renders as context"
    assert "pkg:pypi/shown@1" in text


def test_short_and_repeated_paths_are_not_explained(tmp_path, monkeypatch):
    """atom paths need five distinct rows and the language analyzers' two;
    nodes on the line just shown and rows that loop back do not count, and a
    path whose rows were already shown renders once."""
    from analysis_lib.evidence import EvidencePathNode

    short = _flow_record("short", ["pkg:pypi/short@1"], _path("app/short.py", 4))
    looping = _flow_record(
        "looping",
        ["pkg:pypi/looping@1"],
        [
            *_path("app/loop.py", 3),
            EvidencePathNode(file="app/loop.py", line=12, method="handle", symbol="again"),
            *_path("app/loop.py", 2),
        ],
    )
    same_line = _flow_record(
        "same-line",
        ["pkg:pypi/same-line@1"],
        [
            EvidencePathNode(file="app/line.py", line=1, method="m", symbol=f"s{i}")
            for i in range(6)
        ],
    )
    two_rows = _flow_record("rusi", ["pkg:cargo/sqlx@0.6.2"], _path("src/main.rs", 2), "rusi")
    first = _flow_record("first", ["pkg:pypi/first@1"], _path("app/dup.py", 5))
    again = _flow_record("again", ["pkg:pypi/again@1"], _path("app/dup.py", 5))
    text = _explain(tmp_path, monkeypatch, [short, looping, same_line, two_rows, first, again])
    assert "pkg:pypi/short@1" not in text
    assert "pkg:pypi/looping@1" not in text, "rows that loop back are not new rows"
    assert "pkg:pypi/same-line@1" not in text, "one line is one row"
    assert "pkg:cargo/sqlx@0.6.2" in text, "a two-row path is enough for a language analyzer"
    assert ("pkg:pypi/first@1" in text) != ("pkg:pypi/again@1" in text), (
        "the same rows render once"
    )


def test_the_per_purl_source_and_sink_caps_apply(tmp_path, monkeypatch):
    """The three caps are live: a package set, a path start and a path end
    (the symbol the first and the last witness node name) each get at most
    the configured number of explanations."""
    from analysis_lib.evidence import EvidencePathNode

    monkeypatch.setattr(explainer, "max_purls_reachable_explanations", 1)
    monkeypatch.setattr(explainer, "max_source_reachable_explanations", 1)
    monkeypatch.setattr(explainer, "max_sink_reachable_explanations", 1)

    def path(file_name, source, sink):
        return [
            EvidencePathNode(file=file_name, line=1, method="view", symbol=source),
            *_path(file_name, 3),
            EvidencePathNode(file=file_name, line=99, method="call", symbol=sink),
        ]

    same_purls = [
        _flow_record("p1", ["pkg:pypi/one@1"], path("app/p1.py", "request.GET", "a.get")),
        _flow_record("p2", ["pkg:pypi/one@1"], path("app/p2.py", "request.POST", "b.get")),
    ]
    same_source = [
        _flow_record("s1", ["pkg:pypi/two@1"], path("app/q1.py", "request.user", "c.get")),
        _flow_record("s2", ["pkg:pypi/three@1"], path("app/q2.py", "request.user", "d.get")),
    ]
    same_sink = [
        _flow_record("k1", ["pkg:pypi/four@1"], path("app/r1.py", "self.kwargs", "requests.get")),
        _flow_record("k2", ["pkg:pypi/five@1"], path("app/r2.py", "self.args", "requests.get")),
    ]
    text = _explain(tmp_path, monkeypatch, [*same_purls, *same_source, *same_sink])
    assert text.count("Reachable Packages:") == 3, text
    assert sum(f"app/p{n}.py" in text for n in (1, 2)) == 1
    assert sum(f"app/q{n}.py" in text for n in (1, 2)) == 1
    assert sum(f"app/r{n}.py" in text for n in (1, 2)) == 1


def test_each_source_gets_its_own_cap_and_label(tmp_path, monkeypatch):
    """Records from two sources are explained in two labelled sections, each
    under the explanation cap, the way each slices file always was."""
    monkeypatch.setattr(explainer, "max_reachable_explanations", 1)
    records = [
        _flow_record("a1", ["pkg:pypi/a1@1"], _path("app/a1.py", 5), source="a.slices.json"),
        _flow_record("a2", ["pkg:pypi/a2@1"], _path("app/a2.py", 5), source="a.slices.json"),
        _flow_record("b1", ["pkg:pypi/b1@1"], _path("app/b1.py", 5), source="b.slices.json"),
    ]
    text = _explain(tmp_path, monkeypatch, records)
    assert "Explanations for a.slices.json" in text
    assert "Explanations for b.slices.json" in text
    assert text.count("Reachable Packages:") == 2
    assert "pkg:pypi/b1@1" in text
    assert text.count("Reachable Flows") == 1, "the section heading is printed once"
