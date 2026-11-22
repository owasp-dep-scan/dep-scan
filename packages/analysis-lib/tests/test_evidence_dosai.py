"""Tests for the dosai evidence adapter.

The recordings in ``data/dosai/`` are trimmed combined reports of two
current dosai builds (the 5.0.0 release binary and a main-branch build,
both writing report schema 5.1.0); ``README.md`` beside them says how each
was made. The adapter's four fixture cases run on those recordings: an
unknown major version, a newer minor version, a truncated or malformed
report, and the budget, timeout and truncation markers dosai reports
through its diagnostics. The reached-set tests pin the literal purl sets
of the same recordings, checked by hand: every package dosai calls
reachable, minus its Dependency-kind and Low-confidence entries, with the
ExternalCallGraphNode entries at High confidence counted.

The external call graph regression test runs the reproducer of dep-scan
issue 561 verbatim: its report with an ``ExternalCallGraphNode`` entry at
High confidence must count the package as reached, exactly as the
``CallGraphEdge`` control does. Current releases state an explicit
confidence on every entry, so the entries without one, and the sanitizer,
endpoint, service and dead-code section shapes the two apps do not
produce, are built from the report shapes of the checked-in samples of
earlier dosai releases. The minimal-API case follows the report shape
dosai issue 140 describes.
"""

import copy
import json
import os
from typing import Any, Dict, List, Set

import pytest
from jsonschema import Draft202012Validator

from analysis_lib.evidence.adapters import dosai
from analysis_lib.findings.schemas import load_schema

DATA_DIR = os.path.join(os.path.dirname(__file__), "data", "dosai")

SOURCE = "analysis/dosai/dotnet-dataflows.json"
PRODUCER_VERSION = "5.0.0.0"

#: The record kinds the engine counts as reached evidence.
REACHED_KINDS = frozenset({"reached-flow", "usage", "entry-point"})

V5_REACHABLE = "dosai-v5.0.0-reachable-combined.json"
MAIN_UNREACHABLE = "dosai-main-unreachable-combined.json"

#: The reached-counted purl sets of the two recordings, worked out by hand
#: from the report contents: every PackageReachability entry on them is
#: Reachable with High confidence and a call/dataflow or external-call
#: kind, and the slices name no other purls.
V5_REACHED = {
    "pkg:nuget/Newtonsoft.Json@13.0.3",
    "pkg:nuget/System.Console",
    "pkg:nuget/System.Runtime",
}
MAIN_REACHED = {
    "pkg:nuget/System.Console",
    "pkg:nuget/System.Runtime",
}


def _load(name: str) -> Dict[str, Any]:
    with open(os.path.join(DATA_DIR, name), encoding="utf-8") as fp:
        return json.load(fp)


def _bom_index() -> Dict[str, str]:
    components = [
        {"purl": "pkg:nuget/Newtonsoft.Json@13.0.3", "name": "Newtonsoft.Json"},
        {"purl": "pkg:nuget/reachable-app@1.0.0", "name": "reachable-app"},
    ]
    return dosai.build_bom_purl_index(components)


def _extract(report: Any, **overrides: Any):
    kwargs: Dict[str, Any] = {
        "source": SOURCE,
        "producer_version": PRODUCER_VERSION,
        "bom_index": _bom_index(),
    }
    kwargs.update(overrides)
    return dosai.extract(report, **kwargs)


def _reached_purls(result) -> Set[str]:
    """The purls the result counts as reached, per the engine counting rule."""
    purls: Set[str] = set()
    for record in result.records:
        if record.polarity == "positive" and record.kind in REACHED_KINDS:
            purls.update(record.subject.purls)
    return purls


def _purls_of(result, kind: str) -> Set[str]:
    purls: Set[str] = set()
    for record in result.records:
        if record.kind == kind:
            purls.update(record.subject.purls)
    return purls


def _attrs(record) -> Dict[str, Any]:
    """The record's attributes, which every record built here carries."""
    assert record.attributes is not None
    return record.attributes


def _caveat_kinds(result) -> Set[str]:
    return {caveat.kind for caveat in result.caveats}


def _record_caveat_kinds(result) -> Set[str]:
    kinds: Set[str] = set()
    for record in result.records:
        kinds.update(caveat.kind for caveat in record.caveats)
    return kinds


# --- the recordings pass through whole ------------------------------------------


@pytest.mark.parametrize("name", [V5_REACHABLE, MAIN_UNREACHABLE], ids=["v5.0.0", "main"])
def test_recording_completes_with_the_producer_as_reported(name):
    result = _extract(_load(name))
    assert result.status == "completed"
    assert result.reason is None
    producers = {
        (r.producer.name, r.producer.version, r.producer.report_schema_version)
        for r in result.records
    }
    assert producers == {("dosai", "5.0.0.0", "5.1.0")}
    assert all(r.source == SOURCE for r in result.records)


def test_v5_recording_record_kinds():
    result = _extract(_load(V5_REACHABLE))
    kinds: Dict[str, int] = {}
    for record in result.records:
        kinds[record.kind] = kinds.get(record.kind, 0) + 1
    assert kinds == {
        # 5 slices plus 6 PackageReachability entries (the dataflows and the
        # methods sections both state the reachability of the same three
        # packages, and both statements are kept)
        "reached-flow": 11,
        "exploit-chain": 6,
        "entry-point": 1,  # the attack surface group's one entry
        "dead-code": 13,  # the methods reachability negatives
        "weakness": 6,  # WeaknessCandidates
        "dangerous-api": 8,  # DangerousApiReachability
    }
    assert _reached_purls(result) == V5_REACHED


def test_main_recording_record_kinds():
    result = _extract(_load(MAIN_UNREACHABLE))
    kinds: Dict[str, int] = {}
    for record in result.records:
        kinds[record.kind] = kinds.get(record.kind, 0) + 1
    assert kinds == {
        # 2 slices plus 4 PackageReachability entries
        "reached-flow": 6,
        "exploit-chain": 3,
        "entry-point": 1,
    }
    assert _reached_purls(result) == MAIN_REACHED
    # The purl-less slice dfs2 is counted, never dropped silently.
    assert [c.detail for c in result.caveats if c.kind == "record-skipped"] == [
        "1 data-flow slices name no package purl of their own and became no record"
    ]


def test_records_validate_against_the_evidence_schema():
    schema = load_schema("depscan-evidence")
    validator = Draft202012Validator(schema)
    for name in (V5_REACHABLE, MAIN_UNREACHABLE):
        result = _extract(_load(name))
        for record in result.records:
            errors = list(validator.iter_errors(record.to_dict()))
            assert not errors, f"{name}: {record.id}: {errors[:1]}"


def test_extract_is_deterministic():
    first = _extract(_load(V5_REACHABLE))
    second = _extract(_load(V5_REACHABLE))
    assert [r.to_dict() for r in first.records] == [r.to_dict() for r in second.records]
    assert [r.id for r in first.records] == [r.id for r in second.records]


def test_report_text_and_path_are_read_by_the_adapter(tmp_path):
    text = json.dumps(_load(V5_REACHABLE))
    from_text = _extract(text)
    assert from_text.status == "completed"
    path = tmp_path / "report.json"
    path.write_text(text, encoding="utf-8")
    from_path = _extract(str(path))
    assert from_path.status == "completed"
    assert [r.to_dict() for r in from_path.records] == [r.to_dict() for r in from_text.records]


def test_standalone_halves_of_a_recording_are_read_on_their_own():
    report = _load(V5_REACHABLE)
    dataflows = copy.deepcopy(report["dataflows"])
    dataflows["Metadata"] = copy.deepcopy(report["Metadata"])
    result = _extract(dataflows, source="analysis/dosai/dotnet-dataflows.json")
    assert result.status == "completed"
    assert _reached_purls(result) == V5_REACHED
    methods = copy.deepcopy(report["methods"])
    result = _extract(methods, source="analysis/dosai/dotnet-methods.json")
    assert result.status == "completed"
    # The methods half carries the external call graph entries (three
    # reached-flow records) and the reachability negatives.
    assert len([r for r in result.records if r.kind == "reached-flow"]) == 3
    assert len([r for r in result.records if r.kind == "dead-code"]) == 13


def test_producer_version_falls_back_to_the_caller_when_the_report_names_none():
    report = copy.deepcopy(_load(MAIN_UNREACHABLE))
    del report["Metadata"]["AnalyzerVersion"]
    result = _extract(report, producer_version="9.9.9")
    assert result.status == "completed"
    assert result.records
    assert result.records[0].producer.version == "9.9.9"
    # The version the report states wins over the caller's.
    result = _extract(_load(MAIN_UNREACHABLE), producer_version="9.9.9")
    assert result.records[0].producer.version == "5.0.0.0"


# --- the four fixture cases -------------------------------------------------------


def test_unknown_major_is_refused_with_the_reason():
    for version in ("4.1.0", "3.3.0"):
        report = copy.deepcopy(_load(V5_REACHABLE))
        report["Metadata"]["SchemaVersion"] = version
        result = _extract(report)
        assert result.status == "not-assessed"
        assert result.records == []
        assert version in (result.reason or "")
        assert "major 5" in (result.reason or "")


def test_refuses_the_schema_3_sample_report():
    result = _extract(_load("dosai-combined.sample.json"))
    assert result.status == "not-assessed"
    assert "3.3.0" in (result.reason or "")


def test_newer_minor_is_accepted_with_a_schema_minor_caveat():
    report = copy.deepcopy(_load(V5_REACHABLE))
    report["Metadata"]["SchemaVersion"] = "5.2.0"
    result = _extract(report)
    assert result.status == "completed"
    assert result.records
    assert "schema-minor" in _caveat_kinds(result)
    assert "schema-minor" in _record_caveat_kinds(result)
    assert all(any(c.kind == "schema-minor" for c in r.caveats) for r in result.records)
    assert result.records[0].producer.report_schema_version == "5.2.0"


def test_report_without_a_version_is_accepted_as_schema_unknown():
    report = copy.deepcopy(_load(V5_REACHABLE))
    del report["Metadata"]["SchemaVersion"]
    del report["methods"]["Metadata"]["SchemaVersion"]
    result = _extract(report)
    assert result.status == "completed"
    assert result.records
    assert "schema-unknown" in _caveat_kinds(result)
    assert result.records[0].producer.report_schema_version == "unknown"


def test_truncated_report_is_not_assessed():
    text = json.dumps(_load(V5_REACHABLE))
    truncated = text[: len(text) // 2]
    result = _extract(truncated)
    assert result.status == "not-assessed"
    assert result.records == []
    assert "JSON" in (result.reason or "") or "json" in (result.reason or "")


def test_malformed_sections_are_not_assessed():
    result = _extract("[]")
    assert result.status == "not-assessed"
    report = copy.deepcopy(_load(V5_REACHABLE))
    report["dataflows"]["Slices"] = {"dfs1": {}}
    result = _extract(report)
    assert result.status == "not-assessed"
    assert "Slices" in (result.reason or "")


def test_a_dict_that_is_not_a_dosai_report_is_not_assessed():
    result = _extract({"foo": "bar"})
    assert result.status == "not-assessed"
    assert "dosai" in (result.reason or "")
    # An empty object is what a swallowed JSON decode failure leaves behind;
    # it must never read as a clean analysis of nothing.
    result = _extract({})
    assert result.status == "not-assessed"
    assert result.records == []


def test_an_empty_but_well_formed_analysis_completes_with_no_records():
    report = {
        "Metadata": {"Tool": "Dosai", "SchemaVersion": "5.1.0", "AnalyzerVersion": "5.0.0.0"},
        "methods": {},
        "dataflows": {},
    }
    result = _extract(report)
    assert result.status == "completed"
    assert result.records == []
    assert result.caveats == []


def test_missing_file_is_not_assessed(tmp_path):
    result = _extract(str(tmp_path / "absent.json"))
    assert result.status == "not-assessed"
    assert result.records == []
    assert result.reason


def test_budget_timeout_and_truncation_markers_become_caveats():
    report = copy.deepcopy(_load(V5_REACHABLE))
    report["dataflows"]["Diagnostics"] = list(report["dataflows"]["Diagnostics"]) + [
        "Reachability budget of 200000 nodes exhausted while walking from entry "
        "point ep1; deeper reachability facts for this run are incomplete.",
        "Dead-code report truncated at 300 entries; query "
        "reachability[reachable=false] for the full set.",
    ]
    report["methods"]["Diagnostics"] = list(report["methods"]["Diagnostics"]) + [
        "dotnet build timed out after 60s and was stopped; analyzing the tree as-is.",
    ]
    report["dataflows"]["AttackSurface"][0]["EntryPointsTruncated"] = True
    result = _extract(report)
    assert result.status == "completed"
    kinds = _caveat_kinds(result)
    assert "budget" in kinds
    assert "timeout" in kinds
    assert "budget" in _record_caveat_kinds(result)
    assert "timeout" in _record_caveat_kinds(result)
    # The dataflows markers land on the records built from the dataflows
    # sections, the methods marker on the methods records.
    slice_records = [r for r in result.records if r.attributes and _attrs(r).get("sliceId")]
    assert slice_records
    assert all(any(c.kind == "budget" for c in r.caveats) for r in slice_records)
    dead = [r for r in result.records if r.kind == "dead-code"]
    assert dead
    assert all(any(c.kind == "timeout" for c in r.caveats) for r in dead)
    surface = [r for r in result.records if r.kind == "entry-point"]
    assert all(any(c.kind == "budget" for c in r.caveats) for r in surface)


# --- the reachability matrix --------------------------------------------------------


def _pr_report(entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    """A combined report whose only content is PackageReachability entries."""
    return {
        "Metadata": {
            "Tool": "Dosai",
            "SchemaVersion": "5.1.0",
            "AnalyzerVersion": "5.0.0.0",
        },
        "methods": {"PackageReachability": entries},
        "dataflows": {},
    }


def _issue_561_report(kind):
    """The report of dep-scan issue 561's reproducer, verbatim."""
    return {
        "Metadata": {"Tool": "Dosai"},
        "methods": {
            "Metadata": {"Tool": "Dosai"},
            "CallGraph": {"Nodes": [], "Edges": []},
            "PackageReachability": [
                {
                    "Purl": "pkg:nuget/Serilog.Sinks.Console@6.1.1",
                    "Reachable": True,
                    "ReachabilityKind": kind,
                    "Confidence": "High",
                    "EvidenceKinds": ["AssemblyIlDirect"],
                    "SourceLocations": [{"File": "Program.cs", "Line": 3}],
                }
            ],
        },
        "dataflows": {
            "Metadata": {"Tool": "Dosai"},
            "Nodes": [],
            "Slices": [],
            "PackageReachability": [],
        },
    }


@pytest.mark.parametrize("kind", ["ExternalCallGraphNode", "CallGraphEdge"])
def test_issue_561_external_call_graph_node_is_reached_like_the_control(kind):
    """The reproducer of dep-scan issue 561, run for the issue's kind and
    for its CallGraphEdge control: both count the package as reached, keep
    the stated confidence, and carry the File and Line source location."""
    result = dosai.extract(_issue_561_report(kind))
    assert result.status == "completed"
    assert _reached_purls(result) == {"pkg:nuget/Serilog.Sinks.Console@6.1.1"}
    (record,) = result.records
    assert record.kind == "reached-flow"
    assert record.confidence == "High"
    assert record.attributes == {"kind": kind}
    assert [(loc.file, loc.line) for loc in record.locations] == [("Program.cs", 3)]
    # The report names no schema version anywhere.
    assert [c.kind for c in result.caveats] == ["schema-unknown"]


def test_external_call_graph_node_without_confidence_is_reached():
    # An ExternalCallGraphNode entry, Reachable true, no explicit
    # Confidence: the kind's default (High) decides the counting, and the
    # record's confidence stays absent because the entry states none.
    report = _pr_report(
        [
            {
                "Purl": "pkg:nuget/Lib.A@1.0.0",
                "Reachable": True,
                "ReachabilityKind": "ExternalCallGraphNode",
                "SourceLocations": [{"Path": "Program.cs", "LineNumber": 12}],
            },
            {
                "Purl": "pkg:nuget/Lib.B@2.0.0",
                "Reachable": True,
                "ReachabilityKind": "Dependency",
            },
        ]
    )
    result = _extract(report)
    assert result.status == "completed"
    assert _purls_of(result, "reached-flow") == {"pkg:nuget/Lib.A@1.0.0"}
    assert _purls_of(result, "dependency") == {"pkg:nuget/Lib.B@2.0.0"}
    assert _reached_purls(result) == {"pkg:nuget/Lib.A@1.0.0"}
    reached = [r for r in result.records if r.subject.purls == ["pkg:nuget/Lib.A@1.0.0"]]
    assert reached[0].kind == "reached-flow"
    assert reached[0].confidence is None
    assert reached[0].attributes == {
        "kind": "ExternalCallGraphNode",
        "confidenceSource": "kind-default",
        "confidenceDefault": "High",
    }
    assert reached[0].locations[0].file == "Program.cs"
    assert reached[0].locations[0].line == 12
    dependency = [r for r in result.records if r.subject.purls == ["pkg:nuget/Lib.B@2.0.0"]]
    assert dependency[0].kind == "dependency"
    assert dependency[0].confidence is None
    assert dependency[0].attributes == {
        "kind": "Dependency",
        "confidenceSource": "kind-default",
        "confidenceDefault": "Low",
    }


def test_dataflow_and_callgraph_entries_count_at_medium_or_high():
    report = _pr_report(
        [
            {
                "Purl": "pkg:nuget/Lib.A@1.0.0",
                "Reachable": True,
                "ReachabilityKind": "DataFlowNode",
                "Confidence": "High",
            },
            {
                "Purl": "pkg:nuget/Lib.B@2.0.0",
                "Reachable": True,
                "ReachabilityKind": "CallGraphEdge",
                "Confidence": "Medium",
            },
        ]
    )
    result = _extract(report)
    assert _reached_purls(result) == {"pkg:nuget/Lib.A@1.0.0", "pkg:nuget/Lib.B@2.0.0"}
    assert result.records[0].confidence == "High"
    assert result.records[1].confidence == "Medium"


def test_low_confidence_and_dependency_entries_never_count():
    report = _pr_report(
        [
            {
                "Purl": "pkg:nuget/Lib.A@1.0.0",
                "Reachable": True,
                "ReachabilityKind": "DataFlowNode",
                "Confidence": "Low",
            },
            {
                "Purl": "pkg:nuget/Lib.B@2.0.0",
                "Reachable": True,
                "ReachabilityKind": "Dependency",
                "Confidence": "High",
            },
            {
                "Purl": "pkg:nuget/Lib.C@3.0.0",
                "Reachable": False,
                "ReachabilityKind": "DataFlowNode",
                "Confidence": "High",
            },
        ]
    )
    result = _extract(report)
    assert _reached_purls(result) == set()
    assert _purls_of(result, "dependency") == {
        "pkg:nuget/Lib.A@1.0.0",
        "pkg:nuget/Lib.B@2.0.0",
    }
    # An entry dosai marked not reachable is the negative verdict dosai
    # states, kept as a no-path record.
    (no_path,) = [r for r in result.records if r.subject.purls == ["pkg:nuget/Lib.C@3.0.0"]]
    assert (no_path.kind, no_path.polarity, no_path.confidence) == ("no-path", "negative", "High")


def test_external_call_graph_node_at_medium_or_low_is_not_counted():
    report = _pr_report(
        [
            {
                "Purl": "pkg:nuget/Lib.A@1.0.0",
                "Reachable": True,
                "ReachabilityKind": "ExternalCallGraphNode",
                "Confidence": "Medium",
            },
            {
                "Purl": "pkg:nuget/Lib.B@2.0.0",
                "Reachable": True,
                "ReachabilityKind": "ExternalCallGraphNode",
                "Confidence": "Low",
            },
        ]
    )
    result = _extract(report)
    assert _reached_purls(result) == set()
    assert _purls_of(result, "dependency") == {
        "pkg:nuget/Lib.A@1.0.0",
        "pkg:nuget/Lib.B@2.0.0",
    }
    kinds = {tuple(sorted(r.subject.purls)): _attrs(r).get("kind") for r in result.records}
    assert kinds == {
        ("pkg:nuget/Lib.A@1.0.0",): "ExternalCallGraphNode",
        ("pkg:nuget/Lib.B@2.0.0",): "ExternalCallGraphNode",
    }


def test_unreconciled_nuget_purl_is_kept_and_non_nuget_dropped():
    report = _pr_report(
        [
            {
                "Purl": "pkg:nuget/Unknown.Framework",
                "Reachable": True,
                "ReachabilityKind": "DataFlowNode",
                "Confidence": "High",
            },
            {
                "Purl": "pkg:npm/left-pad@1.3.0",
                "Reachable": True,
                "ReachabilityKind": "DataFlowNode",
                "Confidence": "High",
            },
        ]
    )
    result = _extract(report)
    assert _reached_purls(result) == {"pkg:nuget/Unknown.Framework"}
    # The entry whose purl this adapter cannot attribute is counted, not
    # dropped silently.
    assert [c.detail for c in result.caveats if c.kind == "record-skipped"] == [
        "1 PackageReachability entries name a purl outside NuGet, which this adapter "
        "cannot attribute, and became no record"
    ]


def test_entry_without_a_purl_is_record_skipped():
    report = _pr_report([{"Reachable": True, "ReachabilityKind": "DataFlowNode"}])
    result = _extract(report)
    assert result.status == "completed"
    assert result.records == []
    skipped = [c for c in result.caveats if c.kind == "record-skipped"]
    assert skipped


# --- the transparency sections ------------------------------------------------------


def test_slice_records_carry_witness_path_and_annotation():
    result = _extract(_load(V5_REACHABLE))
    slices = [
        r
        for r in result.records
        if r.kind == "reached-flow" and r.attributes and r.attributes.get("sliceId")
    ]
    assert slices
    dfs1 = next(r for r in slices if _attrs(r)["sliceId"] == "dfs1")
    assert [p.method for p in dfs1.path or []] == [
        "Program.Run",
        "Program.Run",
        "Program.Run",
        "Program.Run",
    ]
    assert [p.line for p in dfs1.path or []] == [10, 11, 11, 12]
    assert all(p.file == "Program.cs" for p in dfs1.path or [])
    assert (dfs1.path or [])[3].symbol == ("Newtonsoft.Json.JsonConvert.DeserializeObject(string)")
    assert dfs1.subject.purls == [
        "pkg:nuget/Newtonsoft.Json@13.0.3",
        "pkg:nuget/System.Runtime",
    ]
    assert _attrs(dfs1)["exposure"] == "cli"
    assert _attrs(dfs1)["exploitChains"][0]["entryPointId"] == "ep1"
    assert _attrs(dfs1)["exploitChains"][0]["hopCount"] == 1


def test_exploit_chain_records_carry_the_sidecar_facts():
    result = _extract(_load(V5_REACHABLE))
    chains = [r for r in result.records if r.kind == "exploit-chain"]
    assert len(chains) == 6
    ec1 = next(r for r in chains if _attrs(r).get("sliceId") == "dfs1")
    assert _attrs(ec1)["entryPointId"] == "ep1"
    assert _attrs(ec1)["exposure"] == "cli"
    assert _attrs(ec1)["hopCount"] == 1
    assert ec1.confidence == "High"
    # The subject purls are the covered slice's purls.
    assert ec1.subject.purls == [
        "pkg:nuget/Newtonsoft.Json@13.0.3",
        "pkg:nuget/System.Runtime",
    ]
    # A chain whose slice names no purls is still recorded, with no subject.
    ec4 = next(r for r in chains if _attrs(r).get("sliceId") == "dfs4")
    assert ec4.subject.purls == []


def test_attack_surface_entry_becomes_an_entry_point_record():
    result = _extract(_load(V5_REACHABLE))
    entry_points = [r for r in result.records if r.kind == "entry-point"]
    assert len(entry_points) == 1
    ep = entry_points[0]
    assert _attrs(ep)["entryPointId"] == "ep1"
    assert _attrs(ep)["exposure"] == "cli"
    assert _attrs(ep)["kind"] == "Cli"
    assert ep.subject.purls == []
    assert ep.locations[0].file == "Program.cs"
    assert ep.locations[0].line == 16
    # A cli entry without a route is dosai's honest attribution: no caveat.
    assert not any(c.kind == "minimal-api" for c in ep.caveats)


def test_api_endpoints_become_entry_point_records_with_exposure_and_zone():
    report = {
        "Metadata": {"Tool": "Dosai", "SchemaVersion": "5.1.0", "AnalyzerVersion": "5.0.0.0"},
        "dataflows": {
            "AttackSurface": [
                {
                    "Exposure": "anonymous-http",
                    "EntryPoints": [
                        {
                            "EntryPointId": "ep:op:svc#GET:/api/run",
                            "Exposure": "anonymous-http",
                            "Kind": "HttpController",
                            "HttpMethod": "GET",
                            "Route": "/api/run",
                            "FileName": "Controllers.cs",
                            "LineNumber": 14,
                        }
                    ],
                }
            ],
        },
        "methods": {
            "ApiEndpoints": [
                {
                    "OperationId": "op1",
                    "ServiceId": "svc1",
                    "EndpointKind": "Attribute",
                    "HttpMethod": "GET",
                    "Route": "/api/run",
                    "Path": "/api/run",
                    "FileName": "Controllers.cs",
                    "LineNumber": 14,
                    "MethodName": "Run",
                    "ClassName": "ToolsController",
                }
            ],
            "Services": [
                {
                    "Id": "svc1",
                    "Name": "Tools",
                    "ServiceKind": "http",
                    "Direction": "inbound",
                    "TrustZone": "internet",
                    "CrossesTrustBoundary": True,
                    "Operations": [{"Id": "op1", "HttpMethod": "GET", "Path": "/api/run"}],
                }
            ],
        },
    }
    result = _extract(report)
    assert result.status == "completed"
    endpoints = [r for r in result.records if r.kind == "entry-point"]
    # One from ApiEndpoints, one from AttackSurface, one from the inbound
    # service the trust zone comes from.
    assert len(endpoints) == 3
    api = next(r for r in endpoints if _attrs(r).get("entryPointId") == "op1")
    assert _attrs(api)["exposure"] == "anonymous-http"
    assert _attrs(api)["trustZone"] == "internet"
    assert _attrs(api)["route"] == "/api/run"
    assert _attrs(api)["serviceId"] == "svc1"
    assert _attrs(api)["kind"] == "Attribute"
    assert api.locations[0].method == "ToolsController.Run"
    surface = next(
        r for r in endpoints if _attrs(r).get("entryPointId") == "ep:op:svc#GET:/api/run"
    )
    assert _attrs(surface)["exposure"] == "anonymous-http"
    assert _attrs(surface)["trustZone"] == "internet"
    assert not any(c.kind == "minimal-api" for c in api.caveats)


def test_route_bearing_cli_tier_entry_carries_the_minimal_api_caveat():
    report = {
        "Metadata": {"Tool": "Dosai", "SchemaVersion": "5.1.0", "AnalyzerVersion": "5.0.0.0"},
        "dataflows": {
            "AttackSurface": [
                {
                    "Exposure": "cli",
                    "EntryPoints": [
                        {
                            "EntryPointId": "ep-route",
                            "Exposure": "cli",
                            "Kind": "Cli",
                            "Route": "/prices",
                            "FileName": "Program.cs",
                            "LineNumber": 6,
                        },
                        {
                            "EntryPointId": "ep-plain",
                            "Exposure": "cli",
                            "Kind": "Cli",
                            "FileName": "Program.cs",
                            "LineNumber": 15,
                        },
                    ],
                }
            ],
        },
        "methods": {},
    }
    result = _extract(report)
    entry_points = {
        _attrs(r)["entryPointId"]: r for r in result.records if r.kind == "entry-point"
    }
    assert any(c.kind == "minimal-api" for c in entry_points["ep-route"].caveats)
    assert not any(c.kind == "minimal-api" for c in entry_points["ep-plain"].caveats)


def test_sanitized_flows_become_negative_sanitizer_records():
    report = {
        "Metadata": {"Tool": "Dosai", "SchemaVersion": "5.1.0", "AnalyzerVersion": "5.0.0.0"},
        "dataflows": {
            "Nodes": [
                {
                    "Id": "dfn3",
                    "Path": "Controllers.cs",
                    "LineNumber": 20,
                    "ClassName": "Tools",
                    "MethodName": "Page",
                },
                {
                    "Id": "dfn4",
                    "Path": "Controllers.cs",
                    "LineNumber": 26,
                    "ClassName": "Tools",
                    "MethodName": "Page",
                },
            ],
            "Slices": [
                {
                    "Id": "dfs9",
                    "NodeIds": ["dfn3", "dfn4"],
                    "Purls": ["pkg:nuget/Lib.A@1.0.0"],
                }
            ],
            "SanitizedFlows": [
                {
                    "Id": "sf1",
                    "Kind": "SanitizerMatch",
                    "SanitizerSymbol": "System.Net.WebUtility.HtmlEncode",
                    "SanitizerCategory": "html-encoding",
                    "SourceIds": ["dfn3"],
                    "FileName": "Controllers.cs",
                    "LineNumber": 26,
                    "Expression": "WebUtility.HtmlEncode(name)",
                }
            ],
        },
        "methods": {},
    }
    result = _extract(report)
    sanitizers = [r for r in result.records if r.kind == "sanitizer"]
    assert len(sanitizers) == 1
    sf = sanitizers[0]
    assert sf.polarity == "negative"
    assert _attrs(sf)["SanitizerSymbol"] == "System.Net.WebUtility.HtmlEncode"
    assert _attrs(sf)["SanitizerCategory"] == "html-encoding"
    assert _attrs(sf)["SourceIds"] == ["dfn3"]
    assert sf.locations[0].file == "Controllers.cs"
    assert sf.locations[0].line == 26
    # The sanitized flow sits on the slice's path: the slice record lists it
    # as a nearby sanitizer, so the sidecar's map stays recoverable.
    slices = [r for r in result.records if r.attributes and _attrs(r).get("sliceId")]
    assert _attrs(slices[0])["sanitizersNearby"] == [{"id": "sf1", "category": "html-encoding"}]


def test_services_become_entry_point_and_presence_records():
    report = {
        "Metadata": {"Tool": "Dosai", "SchemaVersion": "5.1.0", "AnalyzerVersion": "5.0.0.0"},
        "dataflows": {},
        "methods": {
            "Services": [
                {
                    "Id": "svc-in",
                    "Name": "Api",
                    "ServiceKind": "http",
                    "Direction": "inbound",
                    "TrustZone": "internet",
                    "CrossesTrustBoundary": True,
                },
                {
                    "Id": "svc-out",
                    "Name": "Model Provider",
                    "ServiceKind": "llm",
                    "Direction": "outbound",
                    "TrustZone": "internal",
                    "CrossesTrustBoundary": False,
                },
            ],
        },
    }
    result = _extract(report)
    by_id = {
        _attrs(r)["serviceId"]: r
        for r in result.records
        if r.attributes and _attrs(r).get("serviceId")
    }
    assert by_id["svc-in"].kind == "entry-point"
    assert by_id["svc-in"].polarity == "positive"
    assert _attrs(by_id["svc-in"])["trustZone"] == "internet"
    assert _attrs(by_id["svc-in"])["crossesTrustBoundary"] is True
    assert by_id["svc-out"].kind == "presence"
    # Services attribute no package: neither record carries subject purls,
    # so neither moves the reached set.
    assert all(r.subject.purls == [] for r in by_id.values())
    assert _reached_purls(result) == set()


def test_dead_code_entries_and_reachability_negatives_become_dead_code_records():
    report = {
        "Metadata": {"Tool": "Dosai", "SchemaVersion": "5.1.0", "AnalyzerVersion": "5.0.0.0"},
        "dataflows": {},
        "methods": {
            "DeadCode": [
                {
                    "NodeId": "app.Helper.Unused():void",
                    "Name": "Unused",
                    "ClassName": "Helper",
                    "Namespace": "app",
                    "Kind": "Method",
                    "FileName": "Helper.cs",
                    "LineNumber": 40,
                }
            ],
            "Reachability": [
                {
                    "NodeId": "app.Helper.AlsoUnused():void",
                    "Reachable": False,
                    "DepthFromEntryPoint": None,
                    "FanIn": 0,
                    "FanOut": 1,
                },
                {
                    "NodeId": "app.Program.Main():void",
                    "Reachable": True,
                    "DepthFromEntryPoint": 0,
                },
            ],
        },
    }
    result = _extract(report)
    dead = [r for r in result.records if r.kind == "dead-code"]
    assert len(dead) == 2
    assert all(r.polarity == "negative" for r in dead)
    listed = next(r for r in dead if _attrs(r).get("nodeId") == "app.Helper.AlsoUnused():void")
    entry = next(r for r in dead if r.locations and r.locations[0].file == "Helper.cs")
    assert entry.locations[0].line == 40
    assert entry.locations[0].method == "Unused"
    assert _attrs(entry)["kind"] == "Method"
    assert _attrs(listed)["fanOut"] == 1
    assert _reached_purls(result) == set()


# --- the transparency facts stay recoverable ----------------------------------------


def test_transparency_facts_of_the_v5_recording_are_recoverable():
    # The literal facts the removed facts sidecar carried for this
    # recording, worked out by hand from the report: six exploit chains,
    # one cli attack surface entry, no sanitized flows and no services.
    result = _extract(_load(V5_REACHABLE))
    chains = sorted(
        (
            _attrs(r)["id"],
            _attrs(r)["sliceId"],
            _attrs(r)["entryPointId"],
            _attrs(r)["exposure"],
            _attrs(r)["hopCount"],
            r.confidence,
        )
        for r in result.records
        if r.kind == "exploit-chain"
    )
    assert chains == [
        ("ec1", "dfs1", "ep1", "cli", 1, "High"),
        ("ec2", "dfs2", "ep1", "cli", 1, "High"),
        ("ec3", "dfs3", "ep1", "cli", 1, "High"),
        ("ec4", "dfs4", "ep1", "cli", 1, "High"),
        ("ec5", "dfs5", "ep1", "cli", 1, "High"),
        ("ec6", "dfs6", "ep1", "cli", 1, "High"),
    ]
    # The slice annotations carry the chains that cover a recorded slice;
    # ec4's slice names no purls and is a caveat, so its chain id lives only
    # on the chain record.
    annotated = sorted(
        chain["id"]
        for r in result.records
        if r.kind == "reached-flow" and r.attributes
        for chain in _attrs(r).get("exploitChains", [])
    )
    assert annotated == ["ec1", "ec2", "ec3", "ec5", "ec6"]
    entry_points = [r for r in result.records if r.kind == "entry-point"]
    assert sorted(_attrs(r)["entryPointId"] for r in entry_points) == ["ep1"]
    assert sorted(_attrs(r)["exposure"] for r in entry_points) == ["cli"]
    assert not [r for r in result.records if r.kind == "sanitizer"]
    assert not [r for r in result.records if _attrs(r).get("serviceId")]
    assert not any(_attrs(r).get("sanitizersNearby") for r in result.records)


# --- the reached-set equality check -------------------------------------------------


@pytest.mark.parametrize(
    ("name", "expected"),
    [(V5_REACHABLE, V5_REACHED), (MAIN_UNREACHABLE, MAIN_REACHED)],
    ids=["v5.0.0", "main"],
)
def test_reached_purls_equal_the_pinned_set(name, expected):
    # Pinned literal sets, worked out by hand from the recording: every
    # package dosai calls reachable (all High confidence here, none of the
    # Dependency kind), the ExternalCallGraphNode entries at High confidence
    # included.
    result = _extract(_load(name))
    assert result.status == "completed"
    assert _reached_purls(result) == expected
    # The recorded dependency evidence on these recordings is empty: every
    # PackageReachability entry is reached evidence at High confidence.
    assert _purls_of(result, "dependency") == set()


# --- confidence as given ------------------------------------------------------------


def test_the_record_keeps_the_confidence_exactly_as_stated():
    """A stated confidence is kept with its own spelling; a stated value the
    matrix does not know is no confidence and never counts."""
    report = _pr_report(
        [
            {
                "Purl": "pkg:nuget/Lower@1.0.0",
                "Reachable": True,
                "ReachabilityKind": "DataFlowNode",
                "Confidence": "high",
            },
            {
                "Purl": "pkg:nuget/Number@1.0.0",
                "Reachable": True,
                "ReachabilityKind": "DataFlowNode",
                "Confidence": 3,
            },
            {
                "Purl": "pkg:nuget/Odd@1.0.0",
                "Reachable": True,
                "ReachabilityKind": "DataFlowNode",
                "Confidence": "Certain",
            },
        ]
    )
    result = _extract(report)
    by_purl = {r.subject.purls[0]: r for r in result.records}
    assert (
        by_purl["pkg:nuget/Lower@1.0.0"].kind,
        by_purl["pkg:nuget/Lower@1.0.0"].confidence,
    ) == (
        "reached-flow",
        "high",
    )
    number = by_purl["pkg:nuget/Number@1.0.0"]
    assert (number.kind, number.confidence) == ("dependency", None)
    assert number.attributes == {"kind": "DataFlowNode", "confidenceGiven": 3}
    odd = by_purl["pkg:nuget/Odd@1.0.0"]
    assert (odd.kind, odd.confidence) == ("dependency", "Certain")
    assert _reached_purls(result) == {"pkg:nuget/Lower@1.0.0"}


@pytest.mark.parametrize("kind", ["DataFlowEdge", "DataFlowSlice"])
def test_data_flow_edge_and_slice_kinds_count_like_data_flow_nodes(kind):
    report = _pr_report(
        [
            {
                "Purl": "pkg:nuget/High@1.0.0",
                "Reachable": True,
                "ReachabilityKind": kind,
                "Confidence": "High",
            },
            {
                "Purl": "pkg:nuget/Medium@1.0.0",
                "Reachable": True,
                "ReachabilityKind": kind,
                "Confidence": "Medium",
            },
            {"Purl": "pkg:nuget/Absent@1.0.0", "Reachable": True, "ReachabilityKind": kind},
            {
                "Purl": "pkg:nuget/Low@1.0.0",
                "Reachable": True,
                "ReachabilityKind": kind,
                "Confidence": "Low",
            },
        ]
    )
    result = _extract(report)
    assert _reached_purls(result) == {
        "pkg:nuget/High@1.0.0",
        "pkg:nuget/Medium@1.0.0",
        "pkg:nuget/Absent@1.0.0",
    }
    assert _purls_of(result, "dependency") == {"pkg:nuget/Low@1.0.0"}


def test_internal_call_graph_nodes_never_count():
    report = _pr_report(
        [
            {
                "Purl": "pkg:nuget/Internal@1.0.0",
                "Reachable": True,
                "ReachabilityKind": "InternalCallGraphNode",
                "Confidence": "High",
            },
        ]
    )
    result = _extract(report)
    assert _reached_purls(result) == set()
    assert _purls_of(result, "dependency") == {"pkg:nuget/Internal@1.0.0"}


# --- the version gate over every Metadata block -----------------------------------


def test_a_half_that_names_another_major_refuses_the_report():
    """The top-level Metadata names no version and the methods half names
    6.0.0: the report is refused, not read as schema-unknown."""
    report = copy.deepcopy(_load(V5_REACHABLE))
    del report["Metadata"]["SchemaVersion"]
    report["methods"]["Metadata"]["SchemaVersion"] = "6.0.0"
    result = _extract(report)
    assert result.status == "not-assessed"
    assert result.records == []
    assert result.reason is not None and "6.0.0" in result.reason
    assert "methods metadata" in result.reason


def test_a_5_0_report_is_read_without_a_caveat():
    report = copy.deepcopy(_load(V5_REACHABLE))
    report["Metadata"]["SchemaVersion"] = "5.0.0"
    report["methods"]["Metadata"]["SchemaVersion"] = "5.0.0"
    result = _extract(report)
    assert result.status == "completed"
    assert {r.producer.report_schema_version for r in result.records} == {"5.0.0"}
    assert not {"schema-minor", "schema-unknown"} & _caveat_kinds(result)
    assert _reached_purls(result) == V5_REACHED


@pytest.mark.parametrize("version", [5.1, 5])
def test_a_numeric_schema_version_is_read_as_its_text(version):
    report = copy.deepcopy(_load(V5_REACHABLE))
    report["Metadata"]["SchemaVersion"] = version
    result = _extract(report)
    assert result.status == "completed"
    assert {r.producer.report_schema_version for r in result.records} == {str(version)}


@pytest.mark.parametrize("version", ["v5", "five"])
def test_a_schema_version_without_a_numeric_major_is_refused(version):
    report = copy.deepcopy(_load(V5_REACHABLE))
    report["Metadata"]["SchemaVersion"] = version
    result = _extract(report)
    assert result.status == "not-assessed"
    assert version in (result.reason or "")


# --- the two halves ---------------------------------------------------------------


def test_one_entry_in_both_halves_keeps_each_half_and_its_caveats():
    """The same PackageReachability entry in both halves is two records,
    each carrying its own half's budget caveat; neither absorbs the other."""
    entry = {
        "Purl": "pkg:nuget/A@1.0.0",
        "Reachable": True,
        "ReachabilityKind": "DataFlowNode",
        "Confidence": "High",
    }
    report = {
        "Metadata": {"Tool": "Dosai", "SchemaVersion": "5.1.0"},
        "methods": {"PackageReachability": [dict(entry)], "Diagnostics": []},
        "dataflows": {
            "PackageReachability": [dict(entry)],
            "Diagnostics": ["the data-flow budget was exhausted after 100 slices"],
        },
    }
    result = _extract(report)
    assert len(result.records) == 2
    assert len({r.id for r in result.records}) == 2
    budgets = sorted([c.kind for c in r.caveats if c.kind == "budget"] for r in result.records)
    assert budgets == [[], ["budget"]]


def test_slice_purls_include_the_methods_call_graph_nodes():
    """A slice node that lives only in the methods call graph still gives
    the slice its purl."""
    report = {
        "Metadata": {"Tool": "Dosai", "SchemaVersion": "5.1.0"},
        "methods": {
            "CallGraph": {
                "Nodes": [
                    {
                        "Id": "m1",
                        "Purl": "pkg:nuget/Dep@1.0.0",
                        "FileName": "P.cs",
                        "LineNumber": 3,
                    }
                ]
            }
        },
        "dataflows": {
            "Nodes": [],
            "Slices": [{"Id": "s1", "NodeIds": ["m1"], "SinkPurl": "pkg:nuget/Sink@1.0.0"}],
        },
    }
    result = _extract(report)
    (record,) = result.records
    assert record.subject.purls == ["pkg:nuget/Dep@1.0.0", "pkg:nuget/Sink@1.0.0"]
    assert [(node.file, node.line) for node in record.path or []] == [("P.cs", 3)]


def test_an_api_endpoint_subject_is_its_first_reconciled_purl():
    """dosai lists the serving package first; the rest are kept as given in
    the purls attribute and are neither reached nor services."""
    report = {
        "Metadata": {"Tool": "Dosai", "SchemaVersion": "5.1.0"},
        "methods": {
            "ApiEndpoints": [
                {
                    "Route": "api/x",
                    "HttpMethod": "GET",
                    "OperationId": "op1",
                    "Purls": ["pkg:npm/ignored@1.0", "pkg:nuget/Mvc@2.0", "pkg:nuget/Other@1.0"],
                }
            ]
        },
        "dataflows": {},
    }
    result = _extract(report)
    (record,) = result.records
    assert record.kind == "entry-point"
    assert record.subject.purls == ["pkg:nuget/Mvc@2.0"]
    assert _attrs(record)["purls"] == [
        "pkg:npm/ignored@1.0",
        "pkg:nuget/Mvc@2.0",
        "pkg:nuget/Other@1.0",
    ]
    assert _reached_purls(result) == {"pkg:nuget/Mvc@2.0"}


# --- negative verdicts and skipped objects ----------------------------------------


def test_objects_that_make_no_record_are_counted_per_reason():
    report = {
        "Metadata": {"Tool": "Dosai", "SchemaVersion": "5.1.0"},
        "methods": {
            "Services": ["svc"],
            "PackageReachability": [
                {"Purl": "pkg:nuget/A@1.0.0", "ReachabilityKind": "DataFlowNode"},
                {"Purl": "pkg:nuget/B@1.0.0", "Reachable": "yes"},
            ],
        },
        "dataflows": {"ExploitChains": ["x", 3], "SanitizedFlows": [None]},
    }
    result = _extract(report)
    assert result.status == "completed"
    assert result.records == []
    assert [c.detail for c in result.caveats if c.kind == "record-skipped"] == [
        "2 ExploitChains entries are not JSON objects and became no record",
        "1 SanitizedFlows entries are not JSON objects and became no record",
        "1 Services entries are not JSON objects and became no record",
        "2 PackageReachability entries state no Reachable verdict and became no record",
    ]


# --- malformed nested values --------------------------------------------------------


def test_nested_values_of_the_wrong_type_are_read_without_raising():
    """An attack surface entry with a route but no EntryPointId, an id that
    is a list, a slice whose Purls is a number and NodeIds a string, and
    source locations that are a number: none of them raises."""
    report = {
        "Metadata": {"Tool": "Dosai", "SchemaVersion": "5.1.0"},
        "methods": {
            "PackageReachability": [
                {
                    "Purl": "pkg:nuget/A@1.0.0",
                    "Reachable": True,
                    "ReachabilityKind": "DataFlowNode",
                    "SourceLocations": 3,
                    "EntryPointIds": [["ep1"]],
                    "SliceIds": "s1",
                },
            ]
        },
        "dataflows": {
            "AttackSurface": [
                {
                    "Exposure": "anonymous-http",
                    "EntryPoints": [
                        {"Route": "/x", "Exposure": "anonymous-http"},
                        {"EntryPointId": ["ep1"], "Exposure": "cli"},
                    ],
                }
            ],
            "Slices": [
                {"Id": "s1", "Purls": 5, "NodeIds": "abc", "SinkPurl": "pkg:nuget/B@1.0.0"}
            ],
            "ExploitChains": [{"Id": ["ec1"], "EntryPointId": ["ep1"], "SliceId": {"a": 1}}],
        },
    }
    result = _extract(report)
    assert result.status == "completed"
    kinds = sorted(r.kind for r in result.records)
    assert kinds == ["entry-point", "entry-point", "exploit-chain", "reached-flow"]
    assert [c.detail for c in result.caveats if c.kind == "record-skipped"] == [
        "1 data-flow slices walk no node and became no record"
    ]


@pytest.mark.parametrize(
    ("half", "section", "value"),
    [("dataflows", "Slices", 5), ("methods", "CallGraph", [1]), ("methods", "Services", "x")],
)
def test_a_section_of_the_wrong_type_is_not_assessed(half, section, value):
    report = {
        "Metadata": {"Tool": "Dosai", "SchemaVersion": "5.1.0"},
        "methods": {},
        "dataflows": {},
    }
    report[half][section] = value
    result = _extract(report)
    assert result.status == "not-assessed"
    assert section in (result.reason or "")


# --- record paths -------------------------------------------------------------------


def test_absolute_paths_are_made_relative_to_the_input_path():
    """dosai's InputPath is the root: an absolute POSIX or Windows path under
    it becomes relative, a NuGet cache file takes the cache spelling, and any
    other absolute path is left out with a caveat."""
    entries = [
        {
            "Purl": "pkg:nuget/A@1.0.0",
            "Reachable": True,
            "ReachabilityKind": "DataFlowNode",
            "SourceLocations": [{"Path": "/home/u/app/src/Program.cs", "LineNumber": 3}],
        },
        {
            "Purl": "pkg:nuget/B@1.0.0",
            "Reachable": True,
            "ReachabilityKind": "DataFlowNode",
            "SourceLocations": [{"Path": "C:\\Users\\u\\app\\src\\Program.cs", "LineNumber": 4}],
        },
        {
            "Purl": "pkg:nuget/C@1.0.0",
            "Reachable": True,
            "ReachabilityKind": "DataFlowNode",
            "SourceLocations": [
                {
                    "Path": "/home/u/.nuget/packages/newtonsoft.json/13.0.3/src/JsonConvert.cs",
                    "LineNumber": 5,
                }
            ],
        },
        {
            "Purl": "pkg:nuget/D@1.0.0",
            "Reachable": True,
            "ReachabilityKind": "DataFlowNode",
            "SourceLocations": [{"Path": "/opt/elsewhere/Other.cs", "LineNumber": 6}],
        },
    ]
    files = {}
    for root in ("/home/u/app", "C:\\Users\\u\\app"):
        report = _pr_report(entries)
        report["Metadata"]["InputPath"] = root
        result = _extract(report)
        for record in result.records:
            files.setdefault(record.subject.purls[0], set()).update(
                loc.file for loc in record.locations
            )
    assert files["pkg:nuget/A@1.0.0"] == {"src/Program.cs"}
    assert files["pkg:nuget/B@1.0.0"] == {"src/Program.cs"}
    assert files["pkg:nuget/C@1.0.0"] == {"newtonsoft.json/13.0.3/src/JsonConvert.cs"}
    assert files["pkg:nuget/D@1.0.0"] == set()
    outside = next(r for r in result.records if r.subject.purls == ["pkg:nuget/D@1.0.0"])
    assert [c.kind for c in outside.caveats] == ["location-outside-root"]


def test_the_caller_source_root_makes_paths_relative_too():
    report = _pr_report(
        [
            {
                "Purl": "pkg:nuget/A@1.0.0",
                "Reachable": True,
                "ReachabilityKind": "DataFlowNode",
                "SourceLocations": [{"Path": "/ci/work/app/Program.cs", "LineNumber": 3}],
            }
        ]
    )
    without = _extract(report)
    assert without.records[0].locations == []
    with_root = _extract(report, source_root="/ci/work/app")
    assert [loc.file for loc in with_root.records[0].locations] == ["Program.cs"]


# --- minimal-API attribution --------------------------------------------------------


def _minimal_api_report(chain_entry: str, entry_point_ids: List[str]) -> Dict[str, Any]:
    """The report shape dosai issue 140 describes: two minimal-API routes,
    the program's Cli entry point ep3, and the deserialization slice."""
    return {
        "Metadata": {"Tool": "Dosai", "SchemaVersion": "5.1.0"},
        "dataflows": {
            "EntryPoints": [
                {
                    "Id": "ep:op:svc:minimal-api:_/Program.cs#GET:/health",
                    "Route": "/health",
                    "HttpMethod": "GET",
                },
                {
                    "Id": "ep:op:svc:minimal-api:_/Program.cs#POST:/import",
                    "Route": "/import",
                    "HttpMethod": "POST",
                    "LineNumber": 10,
                },
                {"Id": "ep3", "Kind": "Cli", "MethodName": "<Main>$"},
            ],
            "Nodes": [
                {
                    "Id": "n1",
                    "Purl": "pkg:nuget/Newtonsoft.Json@12.0.3",
                    "FileName": "Program.cs",
                    "LineNumber": 14,
                }
            ],
            "Slices": [
                {
                    "Id": "dfs1",
                    "NodeIds": ["n1"],
                    "SinkPurl": "pkg:nuget/Newtonsoft.Json@12.0.3",
                    "SinkCategory": "deserialization",
                }
            ],
            "ExploitChains": [
                {
                    "Id": "ec1",
                    "EntryPointId": chain_entry,
                    "Exposure": "cli",
                    "SliceId": "dfs1",
                    "HopCount": 0,
                    "Confidence": "High",
                }
            ],
            "PackageReachability": [
                {
                    "Purl": "pkg:nuget/Newtonsoft.Json@12.0.3",
                    "Reachable": True,
                    "ReachabilityKind": "DataFlowNode",
                    "Confidence": "High",
                    "EntryPointIds": entry_point_ids,
                    "SliceIds": ["dfs1"],
                }
            ],
        },
        "methods": {},
    }


def test_minimal_api_flows_tied_to_the_cli_entry_point_carry_the_caveat():
    """dosai 5.0.0 ties the minimal-API chain to ep3 and gives the package no
    entry point: the chain, the slice and the reachability record carry the
    minimal-API caveat, and the reached set is unchanged."""
    result = _extract(_minimal_api_report("ep3", []), bom_index={})
    flagged = sorted(
        (r.kind, r.subject.purls[0] if r.subject.purls else "")
        for r in result.records
        if any(c.kind == "minimal-api" for c in r.caveats)
    )
    assert flagged == [
        ("exploit-chain", "pkg:nuget/Newtonsoft.Json@12.0.3"),
        ("reached-flow", "pkg:nuget/Newtonsoft.Json@12.0.3"),
        ("reached-flow", "pkg:nuget/Newtonsoft.Json@12.0.3"),
    ]
    chain = next(r for r in result.records if r.kind == "exploit-chain")
    (caveat,) = [c for c in chain.caveats if c.kind == "minimal-api"]
    assert caveat.detail == (
        "the report has minimal-API routes and dosai tied the exploit chain ec1 to the entry "
        "point(s) ep3, none of which is a route; dosai can attribute minimal-API flows to "
        "the wrong entry point (dosai issue 140)"
    )
    assert _reached_purls(result) == {"pkg:nuget/Newtonsoft.Json@12.0.3"}


def test_flows_tied_to_a_minimal_api_route_carry_no_caveat():
    """The attribution dosai issue 140 expects: the chain and the package
    name the POST /import route, and nothing is flagged."""
    route = "ep:op:svc:minimal-api:_/Program.cs#POST:/import"
    result = _extract(_minimal_api_report(route, [route]), bom_index={})
    assert not any(c.kind == "minimal-api" for r in result.records for c in r.caveats)


def test_a_report_without_minimal_api_routes_carries_no_caveat():
    """A console app's flows tied to its Cli entry point are dosai's honest
    attribution: the v5 recording carries no minimal-API caveat."""
    result = _extract(_load(V5_REACHABLE))
    assert "minimal-api" not in _record_caveat_kinds(result)


def test_ids_do_not_depend_on_the_input_path():
    ids = []
    for root in ("/home/u/app", "/srv/build/app"):
        report = _pr_report(
            [
                {
                    "Purl": "pkg:nuget/A@1.0.0",
                    "Reachable": True,
                    "ReachabilityKind": "DataFlowNode",
                    "SourceLocations": [{"Path": f"{root}/Program.cs", "LineNumber": 3}],
                }
            ]
        )
        report["Metadata"]["InputPath"] = root
        ids.append([r.id for r in _extract(report).records])
    assert len(ids[0]) == 1
    assert ids[0] == ids[1]


# --- weakness candidates and dangerous API reachability -----------------------------


def test_weakness_candidates_become_weakness_records_as_given():
    """Each WeaknessCandidates entry is a weakness record: the purls dosai
    names as the subject, its confidence as stated, every field it wrote kept
    in the attributes, and its sink location as the record location."""
    report = _load(V5_REACHABLE)
    result = _extract(report)
    weaknesses = [r for r in result.records if r.kind == "weakness"]
    assert [_attrs(r)["Id"] for r in weaknesses] == ["wc1", "wc2", "wc3", "wc4", "wc5", "wc6"]
    wc1 = weaknesses[0]
    assert wc1.polarity == "positive"
    assert wc1.subject.purls == ["pkg:nuget/Newtonsoft.Json@13.0.3", "pkg:nuget/System.Runtime"]
    assert wc1.confidence == "High"
    assert wc1.attributes == report["dataflows"]["WeaknessCandidates"][0]
    assert [(loc.file, loc.line) for loc in wc1.locations] == [("Program.cs", 12)]


def test_dangerous_api_reachability_becomes_dangerous_api_records_as_given():
    report = _load(V5_REACHABLE)
    result = _extract(report)
    dangerous = [r for r in result.records if r.kind == "dangerous-api"]
    assert len(dangerous) == 8
    dar1 = dangerous[0]
    assert dar1.subject.purls == ["pkg:nuget/Newtonsoft.Json@13.0.3"]
    assert dar1.confidence == "High"
    assert dar1.attributes == report["dataflows"]["DangerousApiReachability"][0]
    assert [(loc.file, loc.line) for loc in dar1.locations] == [("Program.cs", 12)]
    # dar8 names no purl, so its record has no subject rather than one
    # the adapter guessed.
    assert [tuple(r.subject.purls) for r in dangerous] == [
        ("pkg:nuget/Newtonsoft.Json@13.0.3",)
    ] * 4 + [("pkg:nuget/System.Console",)] * 3 + [()]


def test_weakness_and_dangerous_api_records_leave_the_reached_set_alone():
    """Without the two sections the reached set is the same pinned set."""
    report = copy.deepcopy(_load(V5_REACHABLE))
    with_sections = _extract(report)
    del report["dataflows"]["WeaknessCandidates"]
    del report["dataflows"]["DangerousApiReachability"]
    without = _extract(report)
    assert not any(r.kind in ("weakness", "dangerous-api") for r in without.records)
    assert _reached_purls(with_sections) == _reached_purls(without) == V5_REACHED


def test_a_weakness_on_a_non_route_entry_point_carries_the_minimal_api_caveat():
    """dosai issue 140: main attaches the weakness to a route whose handler
    has no sink, 5.0.0 to the Cli entry point ep3. The weakness on ep3 is
    flagged, the one on a minimal-API route is not."""
    report = _minimal_api_report("ep3", [])
    report["dataflows"]["WeaknessCandidates"] = [
        {
            "Id": "wc1",
            "Kind": "UnsafeDeserializationCandidate",
            "EntryPointId": "ep3",
            "Purls": ["pkg:nuget/Newtonsoft.Json@12.0.3"],
            "Confidence": "High",
            "SinkLocation": "Program.cs:14:19",
        },
        {
            "Id": "wc2",
            "Kind": "UnsafeDeserializationCandidate",
            "EntryPointId": "ep:op:svc:minimal-api:_/Program.cs#GET:/health",
            "Purls": ["pkg:nuget/Newtonsoft.Json@12.0.3"],
            "Confidence": "High",
            "SinkLocation": "Program.cs:14:19",
        },
    ]
    result = _extract(report, bom_index={})
    flagged = {
        _attrs(r)["Id"]: any(c.kind == "minimal-api" for c in r.caveats)
        for r in result.records
        if r.kind == "weakness"
    }
    assert flagged == {"wc1": True, "wc2": False}


def test_malformed_weakness_and_dangerous_api_entries_are_counted():
    report = {
        "Metadata": {"Tool": "Dosai", "SchemaVersion": "5.1.0"},
        "methods": {},
        "dataflows": {
            "WeaknessCandidates": ["x", {"Id": "wc9", "Purls": 5, "SinkLocation": 3}],
            "DangerousApiReachability": [None, {"Id": "dar9", "Purl": "pkg:npm/x@1"}],
        },
    }
    result = _extract(report)
    assert result.status == "completed"
    assert [(r.kind, r.subject.purls, r.locations) for r in result.records] == [
        ("weakness", [], []),
        ("dangerous-api", [], []),
    ]
    assert [c.detail for c in result.caveats if c.kind == "record-skipped"] == [
        "1 WeaknessCandidates entries are not JSON objects and became no record",
        "1 DangerousApiReachability entries are not JSON objects and became no record",
    ]


@pytest.mark.parametrize("section", ["WeaknessCandidates", "DangerousApiReachability"])
def test_a_weakness_section_of_the_wrong_type_is_not_assessed(section):
    report = {
        "Metadata": {"Tool": "Dosai", "SchemaVersion": "5.1.0"},
        "methods": {},
        "dataflows": {section: {"a": 1}},
    }
    result = _extract(report)
    assert result.status == "not-assessed"
    assert section in (result.reason or "")
