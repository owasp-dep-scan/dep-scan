"""Unit tests for ``analysis_lib.dosai_slices`` -- native reader, purl
reconciler, native-reachability extractor (Gate 3) and atom projection
(Gate 4).

Fixtures under ``tests/data/dosai/`` are trimmed from real dosai v3.0.5 output
(``dosai-dataflows.json`` / ``dosai-methods.json``) so the PascalCase schema is
authentic.
"""

import json
import os

import pytest

from analysis_lib.dosai_slices import (
    DOSAI_LANG_TOKEN,
    build_bom_purl_index,
    convert_dosai_report,
    extract_native_reachability,
    is_dosai_report,
    reconcile_purl,
    split_dosai_report,
    write_slices_file,
)

DATA_DIR = os.path.join(os.path.dirname(__file__), "data", "dosai")


def _load(name):
    with open(os.path.join(DATA_DIR, name), encoding="utf-8") as fp:
        return json.load(fp)


@pytest.fixture(scope="module")
def combined():
    return _load("dosai-combined.sample.json")


@pytest.fixture(scope="module")
def standalone_dataflows():
    return _load("dosai-dataflows.sample.json")


@pytest.fixture(scope="module")
def bom_index():
    bom = _load("nuget-bom.sample.json")
    extra = []
    mc = (bom.get("metadata") or {}).get("component")
    if isinstance(mc, dict):
        extra.append(mc)
    return build_bom_purl_index(bom.get("components", []), extra)


# ---------------------------------------------------------------------------
# is_dosai_report -- shape-based detection (combined + standalone)
# ---------------------------------------------------------------------------


def test_is_dosai_report_recognizes_combined(combined):
    assert is_dosai_report(combined) is True


def test_is_dosai_report_recognizes_standalone_dataflows(standalone_dataflows):
    assert is_dosai_report(standalone_dataflows) is True


def test_is_dosai_report_recognizes_standalone_methods():
    methods = {
        "Metadata": {"Tool": "Dosai"},
        "CallGraph": {"Nodes": [], "Edges": []},
        "ApiEndpoints": [],
    }
    assert is_dosai_report(methods) is True


def test_is_dosai_report_rejects_non_dosai():
    # an atom-produced semantics slice that happens to share the path must NOT
    # be mistaken for a dosai report (no Metadata.Tool == "Dosai").
    assert is_dosai_report({"flows": [], "purls": []}) is False
    assert is_dosai_report({"schemaVersion": "1.0", "callGraph": {}}) is False
    assert is_dosai_report(None) is False
    assert is_dosai_report([]) is False
    # Metadata present but wrong tool
    assert is_dosai_report({"Metadata": {"Tool": "atom"}, "Slices": []}) is False


def test_split_combined_report(combined):
    df, mt = split_dosai_report(combined)
    assert df is not None and "Slices" in df
    assert mt is not None and "CallGraph" in mt


def test_split_standalone_dataflows(standalone_dataflows):
    df, mt = split_dosai_report(standalone_dataflows)
    assert df is standalone_dataflows
    assert mt is None


# ---------------------------------------------------------------------------
# Purl reconciliation (mirror cdxgen dosaiParsers.js)
# ---------------------------------------------------------------------------


def test_build_bom_purl_index_only_nuget():
    idx = build_bom_purl_index(
        [
            {"purl": "pkg:nuget/Newtonsoft.Json@13.0.3"},
            {"purl": "pkg:npm/left-pad@1.0.0"},  # ignored
            {"purl": "pkg:nuget/System.Text.Json@10.0.0"},
            {"purl": "not-a-purl"},  # ignored
            {},  # ignored
        ]
    )
    assert idx["pkg:nuget/Newtonsoft.Json@13.0.3"] == "pkg:nuget/Newtonsoft.Json@13.0.3"
    # normalized alias key (lowercased name, empty namespace segment)
    assert idx["nuget//newtonsoft.json"] == "pkg:nuget/Newtonsoft.Json@13.0.3"
    assert idx["nuget//system.text.json"] == "pkg:nuget/System.Text.Json@10.0.0"
    assert "pkg:npm/left-pad@1.0.0" not in idx


def test_reconcile_exact_versioned_match():
    idx = build_bom_purl_index([{"purl": "pkg:nuget/Newtonsoft.Json@13.0.3"}])
    assert (
        reconcile_purl("pkg:nuget/Newtonsoft.Json@13.0.3", idx)
        == "pkg:nuget/Newtonsoft.Json@13.0.3"
    )


def test_reconcile_versionless_framework_via_normalized_name(bom_index):
    """dosai emits versionless framework purls; they reconcile to the BOM's
    versioned purl via case-insensitive normalized name."""
    assert (
        reconcile_purl("pkg:nuget/System.Text.Json", bom_index)
        == "pkg:nuget/System.Text.Json@10.0.0"
    )
    # case-insensitive
    assert (
        reconcile_purl("pkg:nuget/system.text.json", bom_index)
        == "pkg:nuget/System.Text.Json@10.0.0"
    )


def test_reconcile_unmatched_framework_kept_as_is(bom_index):
    """A versionless framework purl NOT in the BOM is KEPT (low confidence), not
    dropped, and no version is invented. Mirrors cdxgen resolveDosaiComponentPurl."""
    p = reconcile_purl("pkg:nuget/System.Runtime", bom_index)
    assert p == "pkg:nuget/System.Runtime"


def test_reconcile_versioned_unmatched_kept_as_is(bom_index):
    """A versioned purl absent from the BOM (e.g. Microsoft.CodeAnalysis.CSharp)
    is kept as-is rather than None."""
    p = reconcile_purl("pkg:nuget/Microsoft.CodeAnalysis.CSharp@5.3.0", bom_index)
    assert p == "pkg:nuget/Microsoft.CodeAnalysis.CSharp@5.3.0"


def test_reconcile_non_nuget_returns_none(bom_index):
    assert reconcile_purl("pkg:npm/left-pad@1.0.0", bom_index) is None
    assert reconcile_purl("not a purl", bom_index) is None
    assert reconcile_purl("", bom_index) is None
    assert reconcile_purl(None, bom_index) is None


# ---------------------------------------------------------------------------
# extract_native_reachability -- the native truth (Gate 3)
# ---------------------------------------------------------------------------


def test_native_reachability_marks_dataflow_evidence_high(combined, bom_index):
    facts = extract_native_reachability(combined, bom_index)
    reached = facts["reached_purls"]
    # System.Text.Json slice => DataFlowNode => High, reconciled to versioned
    assert "pkg:nuget/System.Text.Json@10.0.0" in reached
    rec = reached["pkg:nuget/System.Text.Json@10.0.0"]
    assert rec["kind"] in ("DataFlowNode", "CallGraphEdge")
    assert rec["confidence"] == "High"


def test_native_reachability_dependency_kind_low(combined, bom_index):
    facts = extract_native_reachability(combined, bom_index)
    reached = facts["reached_purls"]
    # Microsoft.CodeAnalysis.CSharp is Reachable with Dependency kind => Low,
    # kept as the original versioned purl (absent from BOM).
    rec = reached.get("pkg:nuget/Microsoft.CodeAnalysis.CSharp@5.3.0")
    assert rec is not None
    assert rec["kind"] == "Dependency"
    assert rec["confidence"] == "Low"


def test_native_reachability_carries_source_locations(combined, bom_index):
    facts = extract_native_reachability(combined, bom_index)
    # source locations are source-file-only (.cs/.vb/.fs/.r); .dll filtered out
    for purl, locs in facts["source_locations"].items():
        for loc in locs:
            assert not loc.lower().endswith(".dll")
            assert "#" in loc or "." in loc


def test_native_reachability_passes_through_weakness_candidates(combined, bom_index):
    facts = extract_native_reachability(combined, bom_index)
    # the fixture carries one CWE-tagged weakness candidate
    assert isinstance(facts["weakness_candidates"], list)
    if facts["weakness_candidates"]:
        wc = facts["weakness_candidates"][0]
        assert "Cwe" in wc or "Id" in wc


def test_native_reachability_high_beats_low_for_same_purl():
    """When the same purl is High in dataflows and Low in methods, the
    higher-confidence fact wins."""
    report = {
        "Metadata": {"Tool": "Dosai"},
        "methods": {
            "PackageReachability": [
                {"Purl": "pkg:nuget/X@1.0.0", "Reachable": True, "ReachabilityKind": "Dependency"}
            ]
        },
        "dataflows": {
            "PackageReachability": [
                {
                    "Purl": "pkg:nuget/X@1.0.0",
                    "Reachable": True,
                    "ReachabilityKind": "DataFlowNode",
                    "Confidence": "High",
                    "SourceLocations": [
                        {"Path": "Program.cs", "FileName": "Program.cs", "LineNumber": 7}
                    ],
                }
            ]
        },
    }
    facts = extract_native_reachability(report, {})
    assert facts["reached_purls"]["pkg:nuget/X@1.0.0"]["confidence"] == "High"
    assert facts["reached_purls"]["pkg:nuget/X@1.0.0"]["kind"] == "DataFlowNode"
    assert "Program.cs#7" in facts["source_locations"]["pkg:nuget/X@1.0.0"]


def test_native_reachability_excludes_unreachable():
    report = {
        "Metadata": {"Tool": "Dosai"},
        "dataflows": {
            "PackageReachability": [
                {"Purl": "pkg:nuget/X@1.0.0", "Reachable": False, "ReachabilityKind": "Dependency"}
            ]
        },
    }
    facts = extract_native_reachability(report, {})
    assert facts["reached_purls"] == {}


# ---------------------------------------------------------------------------
# convert_dosai_report -- atom projection (Gate 4)
# ---------------------------------------------------------------------------


def test_projection_carries_every_native_reachable_purl(combined, bom_index):
    """CRITICAL: every native-reachable purl (Reachable==true with call/dataflow
    evidence) MUST appear in at least one flow's ``purls`` so the existing
    engine's ``reached_purls`` loop picks it up unchanged."""
    flows = convert_dosai_report(combined, bom_index)
    all_proj_purls = set()
    for f in flows:
        all_proj_purls.update(f.get("purls", []))
    facts = extract_native_reachability(combined, bom_index)
    native_reachable_call_df = {
        p
        for p, info in facts["reached_purls"].items()
        if info["kind"] in ("DataFlowNode", "CallGraphEdge")
    }
    # the System.Text.Json reachable purl (reconciled versioned) is in the projection
    assert "pkg:nuget/System.Text.Json@10.0.0" in native_reachable_call_df
    assert "pkg:nuget/System.Text.Json@10.0.0" in all_proj_purls, (
        "native-reachable purl must be carried by the atom projection"
    )


def test_projection_dependency_only_not_rendered_as_flow(combined, bom_index):
    """A Dependency-only reachable purl (import/lockfile evidence) is NOT
    rendered as a reachability flow (too weak); it stays only in native facts."""
    flows = convert_dosai_report(combined, bom_index)
    # Microsoft.CodeAnalysis.CSharp is Dependency-only -> no dedicated flow
    dep_flows = [
        f
        for f in flows
        if "pkg:nuget/Microsoft.CodeAnalysis.CSharp@5.3.0" in (f.get("purls") or [])
    ]
    # it should not have a dedicated 2-node reachability flow (no slice references it)
    for f in dep_flows:
        assert not any(n["id"].startswith("dosai-pr-") for n in f.get("flows", []))


def test_projection_tags_order_purl_service_dotnet_rule(combined, bom_index):
    """The ``tags`` string order MUST be: <purl>, <service-tag>, dotnet, <rule>.
    The service tag immediately follows the purl (positional attribution), and a
    standalone ``dotnet`` token is always present so explainer.is_analyzer_slice
    relaxes the node-count gates."""
    flows = convert_dosai_report(combined, bom_index)
    assert flows, "expected at least one projected flow"
    found_dotnet_token = False
    found_purl_first = False
    for f in flows:
        for node in f.get("flows", []):
            tags = node.get("tags") or ""
            if DOSAI_LANG_TOKEN not in tags:
                continue
            found_dotnet_token = True
            pieces = [p.strip() for p in tags.split(",") if p.strip()]
            # when a purl is present, it MUST be the first token
            if any(p.startswith("pkg:") for p in pieces):
                assert pieces[0].startswith("pkg:"), (
                    f"purl must be the first tag token, got: {tags}"
                )
                found_purl_first = True
    assert found_dotnet_token, "every node must carry the standalone dotnet token"
    assert found_purl_first or all(
        not any(p.startswith("pkg:") for p in (n.get("tags", "").split(",")))
        for f in flows
        for n in f.get("flows", [])
    )


def test_projection_slice_flow_is_multi_node(combined, bom_index):
    """A dataflow slice flow walks its NodeIds into an ordered atom path."""
    flows = convert_dosai_report(combined, bom_index)
    slice_flows = [f for f in flows if any(n["id"].startswith("dfn") for n in f.get("flows", []))]
    if slice_flows:
        # nodes carry atom labels and source-file parentFileName
        for sf in slice_flows:
            for node in sf["flows"]:
                assert node["label"] in (
                    "METHOD_PARAMETER_IN",
                    "CALL",
                    "IDENTIFIER",
                    "RETURN",
                )
                assert "parentFileName" in node


def test_projection_reachability_flow_is_two_nodes(combined, bom_index):
    """A native-reachable PackageReachability emits an honest 2-node flow
    (source -> dependency sink) that always renders."""
    flows = convert_dosai_report(combined, bom_index)
    pr_flows = [
        f for f in flows if any(n["id"].startswith("dosai-pr-") for n in f.get("flows", []))
    ]
    assert pr_flows, "expected at least one 2-node PackageReachability flow"
    for pf in pr_flows:
        nodes = pf["flows"]
        assert len(nodes) == 2
        assert nodes[0]["isExternal"] is False
        assert nodes[1]["isExternal"] is True
        assert nodes[1]["label"] == "CALL"


def test_projection_keeps_external_call_graph_node_purl():
    """A PackageReachability entry of kind ExternalCallGraphNode is call-graph
    evidence: a package dosai reported reachable through it (no explicit
    Confidence, so the kind default applies) must land in the converted flows
    beside the call/dataflow kinds, while a Dependency-kind entry for a second
    package stays out of the flows and keeps its Low confidence."""
    report = {
        "Metadata": {"Tool": "Dosai"},
        "dataflows": {
            "PackageReachability": [
                {
                    "Purl": "pkg:nuget/External.Graph@2.1.0",
                    "Reachable": True,
                    "ReachabilityKind": "ExternalCallGraphNode",
                },
                {
                    "Purl": "pkg:nuget/Only.Dependency@1.4.0",
                    "Reachable": True,
                    "ReachabilityKind": "Dependency",
                },
            ]
        },
    }
    flows = convert_dosai_report(report, {})
    projected = set()
    for f in flows:
        projected.update(f.get("purls") or [])
    assert "pkg:nuget/External.Graph@2.1.0" in projected
    assert "pkg:nuget/Only.Dependency@1.4.0" not in projected

    facts = extract_native_reachability(report, {})
    rec = facts["reached_purls"]["pkg:nuget/External.Graph@2.1.0"]
    assert rec["kind"] == "ExternalCallGraphNode"
    assert rec["confidence"] == "High"
    assert facts["reached_purls"]["pkg:nuget/Only.Dependency@1.4.0"]["confidence"] == "Low"


def _issue_561_report(kind, confidence="High"):
    """The reproducer from the issue: one methods PackageReachability entry."""
    entry = {
        "Purl": "pkg:nuget/Serilog.Sinks.Console@6.1.1",
        "Reachable": True,
        "ReachabilityKind": kind,
        "EvidenceKinds": ["AssemblyIlDirect"],
        "SourceLocations": [{"File": "Program.cs", "Line": 3}],
    }
    if confidence is not None:
        entry["Confidence"] = confidence
    return {
        "Metadata": {"Tool": "Dosai"},
        "methods": {
            "Metadata": {"Tool": "Dosai"},
            "CallGraph": {"Nodes": [], "Edges": []},
            "PackageReachability": [entry],
        },
        "dataflows": {
            "Metadata": {"Tool": "Dosai"},
            "Nodes": [],
            "Slices": [],
            "PackageReachability": [],
        },
    }


def _projected(report):
    return sorted(
        {purl for flow in convert_dosai_report(report) for purl in flow.get("purls", [])}
    )


@pytest.mark.parametrize("kind", ["ExternalCallGraphNode", "CallGraphEdge"])
def test_issue_561_reproducer_projects_the_reached_package(kind):
    """The issue's own script: both kinds at High land in the projected flows,
    matching what extract_native_reachability reports."""
    report = _issue_561_report(kind)
    facts = extract_native_reachability(report)
    assert sorted(facts["reached_purls"]) == ["pkg:nuget/Serilog.Sinks.Console@6.1.1"]
    assert _projected(report) == ["pkg:nuget/Serilog.Sinks.Console@6.1.1"]


@pytest.mark.parametrize(
    "kind, confidence, projected",
    [
        ("ExternalCallGraphNode", "Low", False),
        ("ExternalCallGraphNode", "Medium", False),
        ("CallGraphEdge", "Low", False),
        ("DataFlowNode", "Low", False),
        ("CallGraphEdge", "Medium", True),
        ("DataFlowEdge", "High", True),
        ("DataFlowSlice", "High", True),
        ("DataFlowEdge", None, True),
        ("DataFlowSlice", "Low", False),
        ("InternalCallGraphNode", "High", False),
        ("Dependency", "High", False),
    ],
)
def test_projection_follows_kind_and_confidence(kind, confidence, projected):
    """Low entries never render a verdict flow; an external call graph node
    needs High; data flow edges and slices count like data flow nodes."""
    expected = ["pkg:nuget/Serilog.Sinks.Console@6.1.1"] if projected else []
    assert _projected(_issue_561_report(kind, confidence)) == expected


def test_projection_deterministic(combined, bom_index):
    """Two conversions of the same report produce identical output (sorted +
    deduped)."""
    a = convert_dosai_report(combined, bom_index)
    b = convert_dosai_report(combined, bom_index)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_projection_witness_node_purl_is_deterministic():
    """A purl-less internal witness node in a slice must borrow a DETERMINISTIC
    fallback purl (sorted-min of the flow's purls), not an arbitrary set-order
    pick -- otherwise the emitted slice bytes vary with PYTHONHASHSEED across
    processes. Guards the sorted(flow_purls)[0] fix in _emit_slice_flows."""
    report = {
        "Metadata": {"Tool": "Dosai"},
        "Nodes": [
            # a witness node with NO Purl of its own
            {"Id": "dfn1", "Symbol": "sink", "Path": "Program.cs", "LineNumber": 5},
        ],
        "Slices": [
            {
                "Id": "dfs1",
                # multiple purls so set-iteration order would differ
                "Purls": [
                    "pkg:nuget/Zeta.Pkg@1.0.0",
                    "pkg:nuget/Alpha.Pkg@1.0.0",
                    "pkg:nuget/Mid.Pkg@1.0.0",
                ],
                "NodeIds": ["dfn1"],
                "SinkCategory": "sql-query",
            }
        ],
    }
    flows = convert_dosai_report(report, {})
    slice_flow = next(f for f in flows if any(n["id"] == "dfn1" for n in f["flows"]))
    witness = next(n for n in slice_flow["flows"] if n["id"] == "dfn1")
    # sorted-min of the three reconciled purls is Alpha.Pkg
    assert witness["tags"].split(",")[0].strip() == "pkg:nuget/Alpha.Pkg@1.0.0"


def test_projection_empty_report():
    assert convert_dosai_report(None, {}) == []
    assert convert_dosai_report({}, {}) == []
    assert convert_dosai_report({"Metadata": {"Tool": "Dosai"}}, {}) == []


def test_write_slices_file_atomic_and_readback(combined, bom_index, tmp_path):
    flows = convert_dosai_report(combined, bom_index)
    out = tmp_path / "dotnet-reachables.slices.json"
    write_slices_file(str(out), flows)
    assert out.exists()
    data = json.loads(out.read_text())
    assert isinstance(data, list)
    assert len(data) == len(flows)


def test_write_slices_file_splits_over_1000(tmp_path):
    """Mirrors golem/rusi: >1000 flows split into batched files."""
    fake_flows = [
        {"flows": [{"id": f"n{i}", "tags": "dotnet"}], "purls": [f"pkg:nuget/X@1.{i}"]}
        for i in range(2500)
    ]
    out = tmp_path / "dotnet-reachables.slices.json"
    write_slices_file(str(out), fake_flows)
    # primary + 2 batch files (1000 + 1000 + 500)
    assert (out).exists()
    base = str(out).rsplit(".", 1)[0]
    import glob

    batches = glob.glob(base + "*")
    assert len(batches) >= 2
