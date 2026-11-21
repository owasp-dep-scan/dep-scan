"""Tests for the dosai evidence adapter.

The recordings in ``data/dosai/`` are trimmed combined reports of two
current dosai builds (the 5.0.0 release binary and a main-branch build,
both writing report schema 5.1.0); ``README.md`` beside them says how each
was made. The adapter's four fixture cases run on those recordings: an
unknown major version, a newer minor version, a truncated or malformed
report, and the budget, timeout and truncation markers dosai reports
through its diagnostics. The reached-set equality tests pin the literal
purl sets the native reachability extractor yields on the same recordings,
checked by hand: the extractor's reached purls, minus its Dependency-kind
and Low-confidence entries, plus the ExternalCallGraphNode entries at High
confidence that the old flow projection dropped.

One reproducer follows the report the reporter of the external call graph
problem quoted in the upstream issue: an ``ExternalCallGraphNode`` entry
with ``Reachable`` true and no explicit ``Confidence`` whose purl must land
in a reached-flow record, beside a ``Dependency`` entry whose purl must
land only in a dependency record. Current releases state an explicit
confidence on every entry, so the reproducer and the sanitizer, endpoint,
service and dead-code section shapes the two apps do not produce are built
from the report shapes of the checked-in samples of earlier dosai releases.
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


@pytest.mark.parametrize(
    "name", [V5_REACHABLE, MAIN_UNREACHABLE], ids=["v5.0.0", "main"]
)
def test_recording_completes_with_the_producer_as_reported(name):
    result = _extract(_load(name))
    assert result.status == "completed"
    assert result.reason is None
    producers = {(r.producer.name, r.producer.version, r.producer.report_schema_version) for r in result.records}
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
    # The purl-less slice dfs2 is a caveat, never a silent drop.
    skipped = [c for c in result.caveats if c.kind == "record-skipped"]
    assert any("dfs2" in c.detail for c in skipped)


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
    assert all(
        any(c.kind == "schema-minor" for c in r.caveats) for r in result.records
    )
    assert result.records[0].producer.report_schema_version == "5.2.0"


def test_report_without_a_version_is_accepted_as_schema_unknown():
    report = copy.deepcopy(_load(V5_REACHABLE))
    del report["Metadata"]["SchemaVersion"]
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
        "Metadata": {"Tool": "Dosai", "SchemaVersion": "5.1.0",
                     "AnalyzerVersion": "5.0.0.0"},
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
    slice_records = [r for r in result.records
                     if r.attributes and _attrs(r).get("sliceId")]
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


def test_external_call_graph_node_without_confidence_is_reached():
    # The reproducer: an ExternalCallGraphNode entry, Reachable true, no
    # explicit Confidence, whose purl lands in a reached-flow record; the
    # old flow projection dropped exactly this entry because the kind was
    # missing from its confidence table.
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
    assert reached[0].confidence == "High"
    assert reached[0].locations[0].file == "Program.cs"
    assert reached[0].locations[0].line == 12
    dependency = [r for r in result.records if r.subject.purls == ["pkg:nuget/Lib.B@2.0.0"]]
    assert dependency[0].kind == "dependency"
    assert dependency[0].confidence == "Low"
    assert dependency[0].attributes == {"kind": "Dependency"}


def test_dataflow_and_callgraph_entries_count_at_medium_or_high():
    report = _pr_report(
        [
            {"Purl": "pkg:nuget/Lib.A@1.0.0", "Reachable": True,
             "ReachabilityKind": "DataFlowNode", "Confidence": "High"},
            {"Purl": "pkg:nuget/Lib.B@2.0.0", "Reachable": True,
             "ReachabilityKind": "CallGraphEdge", "Confidence": "Medium"},
        ]
    )
    result = _extract(report)
    assert _reached_purls(result) == {"pkg:nuget/Lib.A@1.0.0", "pkg:nuget/Lib.B@2.0.0"}
    assert result.records[0].confidence == "High"
    assert result.records[1].confidence == "Medium"


def test_low_confidence_and_dependency_entries_never_count():
    report = _pr_report(
        [
            {"Purl": "pkg:nuget/Lib.A@1.0.0", "Reachable": True,
             "ReachabilityKind": "DataFlowNode", "Confidence": "Low"},
            {"Purl": "pkg:nuget/Lib.B@2.0.0", "Reachable": True,
             "ReachabilityKind": "Dependency", "Confidence": "High"},
            {"Purl": "pkg:nuget/Lib.C@3.0.0", "Reachable": False,
             "ReachabilityKind": "DataFlowNode", "Confidence": "High"},
        ]
    )
    result = _extract(report)
    assert _reached_purls(result) == set()
    assert _purls_of(result, "dependency") == {
        "pkg:nuget/Lib.A@1.0.0",
        "pkg:nuget/Lib.B@2.0.0",
    }
    # An entry dosai marked not reachable leaves no record at all: dosai
    # states the verdict on the entry, and the Dependency-kind entries above
    # are the recorded weak evidence.
    assert all(
        r.subject.purls != ["pkg:nuget/Lib.C@3.0.0"] for r in result.records
    )


def test_external_call_graph_node_at_medium_or_low_is_not_counted():
    report = _pr_report(
        [
            {"Purl": "pkg:nuget/Lib.A@1.0.0", "Reachable": True,
             "ReachabilityKind": "ExternalCallGraphNode", "Confidence": "Medium"},
            {"Purl": "pkg:nuget/Lib.B@2.0.0", "Reachable": True,
             "ReachabilityKind": "ExternalCallGraphNode", "Confidence": "Low"},
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
            {"Purl": "pkg:nuget/Unknown.Framework", "Reachable": True,
             "ReachabilityKind": "DataFlowNode", "Confidence": "High"},
            {"Purl": "pkg:npm/left-pad@1.3.0", "Reachable": True,
             "ReachabilityKind": "DataFlowNode", "Confidence": "High"},
        ]
    )
    result = _extract(report)
    assert _reached_purls(result) == {"pkg:nuget/Unknown.Framework"}
    # The entry whose purl this adapter cannot attribute is a caveat, not a
    # silent drop.
    skipped = [c for c in result.caveats if c.kind == "record-skipped"]
    assert any("left-pad" in c.detail for c in skipped)


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
    slices = [r for r in result.records if r.kind == "reached-flow" and r.attributes
              and r.attributes.get("sliceId")]
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
    assert (dfs1.path or [])[3].symbol == (
        "Newtonsoft.Json.JsonConvert.DeserializeObject(string)"
    )
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
        "Metadata": {"Tool": "Dosai", "SchemaVersion": "5.1.0",
                     "AnalyzerVersion": "5.0.0.0"},
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
                    "Operations": [
                        {"Id": "op1", "HttpMethod": "GET", "Path": "/api/run"}
                    ],
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
        "Metadata": {"Tool": "Dosai", "SchemaVersion": "5.1.0",
                     "AnalyzerVersion": "5.0.0.0"},
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
    entry_points = {_attrs(r)["entryPointId"]: r for r in result.records
                    if r.kind == "entry-point"}
    assert any(c.kind == "minimal-api" for c in entry_points["ep-route"].caveats)
    assert not any(c.kind == "minimal-api" for c in entry_points["ep-plain"].caveats)


def test_sanitized_flows_become_negative_sanitizer_records():
    report = {
        "Metadata": {"Tool": "Dosai", "SchemaVersion": "5.1.0",
                     "AnalyzerVersion": "5.0.0.0"},
        "dataflows": {
            "Nodes": [
                {"Id": "dfn3", "Path": "Controllers.cs", "LineNumber": 20,
                 "ClassName": "Tools", "MethodName": "Page"},
                {"Id": "dfn4", "Path": "Controllers.cs", "LineNumber": 26,
                 "ClassName": "Tools", "MethodName": "Page"},
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
    assert _attrs(slices[0])["sanitizersNearby"] == [
        {"id": "sf1", "category": "html-encoding"}
    ]


def test_services_become_entry_point_and_presence_records():
    report = {
        "Metadata": {"Tool": "Dosai", "SchemaVersion": "5.1.0",
                     "AnalyzerVersion": "5.0.0.0"},
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
    by_id = {_attrs(r)["serviceId"]: r for r in result.records
             if r.attributes and _attrs(r).get("serviceId")}
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
        "Metadata": {"Tool": "Dosai", "SchemaVersion": "5.1.0",
                     "AnalyzerVersion": "5.0.0.0"},
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
def test_reached_purls_equal_the_native_extractor_set(name, expected):
    # Pinned literal sets, worked out by hand from the recording: the native
    # extractor's reached purls (all High confidence here, none of the
    # Dependency kind), with the ExternalCallGraphNode entries at High
    # confidence that the old projection dropped counted back in.
    result = _extract(_load(name))
    assert result.status == "completed"
    assert _reached_purls(result) == expected
    # The recorded dependency evidence on these recordings is empty: every
    # PackageReachability entry is reached evidence at High confidence.
    assert _purls_of(result, "dependency") == set()
