"""Tests for the kosi evidence adapter.

The fixtures under ``tests/data/kosi`` are real kosi 4.3.1 recordings of
the resolved and syntax tiers (current-release output, kept from earlier
recordings). The tests cover the version gate, malformed and truncated
reports, kosi's stats and diagnostics markers, and the equality contract:
the reached purls the adapter's records count must be exactly the purls
the ``kosi_slices`` converter carried on its flows for the same report,
and the service attribution must match the engine's positional walk over
those flows. Those golden sets were computed from the converter and
checked against the reports by hand; they are pinned below.

The converter never read kosi's ``apiEndpoints`` and never emitted flows
for it, so the adapter records no endpoint evidence either: emitting it
would count purls master never counted. The equality contract below holds
the adapter to that.
"""

import json
from pathlib import Path

import pytest

from analysis_lib.evidence.adapters import STATUS_COMPLETED, STATUS_NOT_ASSESSED
from analysis_lib.evidence.adapters.kosi import (
    attribute_name,
    build_bom_purl_index,
    extract,
    is_kosi_report,
    reconcile_purl,
)

DATA = Path(__file__).parent / "data" / "kosi"
SOURCE = "analysis/kosi/kosi.json"
REACHED_COUNTED = frozenset({"reached-flow", "usage", "entry-point"})

OKHTTP = {"purl": "pkg:maven/com.squareup.okhttp3/okhttp@4.12.0"}
KT2 = {"purl": "pkg:generic/kt2@unspecified"}

# The reached purls and service purls the kosi_slices converter's flows
# carry for each recording, with the BOM components (and the metadata
# component) those flows were computed against. Verified against the
# reports by hand: the resolved tier's two slices cross the workspace
# (kt2) and the okhttp dependency its first slice sinks into, while its
# call graph holds only workspace functions so no edge flow exists; the
# syntax tier publishes no call graph or data flow at all, so only the
# four usages the imports can qualify reach okhttp.
CASES = {
    "kosi-resolved-report.json": {
        "bom": [OKHTTP],
        "extra": [KT2],
        "reached": ["pkg:generic/kt2@unspecified", "pkg:maven/com.squareup.okhttp3/okhttp@4.12.0"],
        "services": ["pkg:generic/kt2@unspecified", "pkg:maven/com.squareup.okhttp3/okhttp@4.12.0"],
    },
    "kosi-syntax-report.json": {
        "bom": [OKHTTP],
        "extra": [KT2],
        "reached": ["pkg:maven/com.squareup.okhttp3/okhttp@4.12.0"],
        "services": [],
    },
}


def _report(name):
    return json.loads((DATA / name).read_text(encoding="utf-8"))


def _extract(name, **overrides):
    kwargs = {
        "source": SOURCE,
        "producer_version": "4.3.1",
        "bom_components": CASES[name]["bom"],
        "extra_components": CASES[name]["extra"],
    }
    kwargs.update(overrides)
    return extract(_report(name), **kwargs)


def _reached(result):
    out = set()
    for record in result.records:
        if record.kind in REACHED_COUNTED and record.polarity == "positive":
            out.update(record.subject.purls)
    return out


def _services(result):
    out = set()
    for record in result.records:
        if record.polarity != "positive":
            continue
        out.update((record.attributes or {}).get("servicePurls") or ())
    return out


@pytest.mark.parametrize("name", sorted(CASES))
def test_reached_set_matches_the_converter_flows(name):
    result = _extract(name)
    assert result.status == STATUS_COMPLETED
    assert _reached(result) == set(CASES[name]["reached"])


@pytest.mark.parametrize("name", sorted(CASES))
def test_service_attribution_matches_the_converter_flows(name):
    result = _extract(name)
    assert _services(result) == set(CASES[name]["services"])


@pytest.mark.parametrize("name", sorted(CASES))
def test_ids_and_records_are_byte_stable(name):
    first = _extract(name)
    second = _extract(name)
    left = [json.dumps(r.to_dict(), sort_keys=True) for r in first.records]
    right = [json.dumps(r.to_dict(), sort_keys=True) for r in second.records]
    assert left == right
    assert len({r.id for r in first.records}) == len(first.records)


def test_resolved_recording_record_kinds():
    """The resolved tier's two slices carry their frame witness paths, the
    producer's confidence, and the service purls the sink categories map
    to; the four attributed usages become usage records."""
    result = _extract("kosi-resolved-report.json")
    slices = [r for r in result.records if r.kind == "reached-flow"]
    assert len(slices) == 2
    for record in slices:
        assert record.confidence == "high"
        assert record.producer.report_schema_version == "kosi/1"
        assert record.path is not None
        assert len(record.path) >= 7
        assert record.locations[0].file == "src/main/kotlin/demo/App.kt"
    ssrf = next(r for r in slices if (r.attributes or {}).get("servicePurls") == [
        "pkg:generic/kt2@unspecified",
        "pkg:maven/com.squareup.okhttp3/okhttp@4.12.0",
    ])
    # the producer states no tier on these slices, so none is invented
    assert ssrf.attributes is not None
    assert "tier" not in ssrf.attributes
    other = [r for r in slices if r is not ssrf]
    assert len(other) == 1
    # the process-exec slice's only BOM purl is the workspace, attributed
    # through the sink category exactly as the converter's flow carried it
    other_attrs = other[0].attributes
    assert other_attrs is not None
    assert other_attrs["servicePurls"] == ["pkg:generic/kt2@unspecified"]
    usages = [r for r in result.records if r.kind == "usage"]
    assert len(usages) == 4
    assert all(r.subject.purls == ["pkg:maven/com.squareup.okhttp3/okhttp@4.12.0"] for r in usages)
    assert not any(r.kind == "entry-point" for r in result.records)


def test_syntax_recording_has_only_usage_records():
    result = _extract("kosi-syntax-report.json")
    assert result.status == STATUS_COMPLETED
    assert all(r.kind == "usage" for r in result.records)
    assert len(result.records) == 4


def test_producer_version_falls_back_to_the_report_tool_version():
    report = _report("kosi-resolved-report.json")
    result = extract(
        report,
        source=SOURCE,
        bom_components=[OKHTTP],
        extra_components=[KT2],
    )
    assert result.status == STATUS_COMPLETED
    assert {r.producer.version for r in result.records} == {"4.3.1"}
    assert all(r.producer.name == "kosi" for r in result.records)


def test_call_graph_edge_into_a_dependency_becomes_a_reached_flow():
    """The resolved tier keeps workspace functions only, so an external
    edge arrives with other call-graph modes; the adapter must record it
    as reached evidence the same way the converter did."""
    report = _report("kosi-resolved-report.json")
    report["callGraph"]["nodes"].append(
        {
            "id": "node-external-1",
            "name": "execute",
            "canonicalName": "okhttp3.Call.execute",
            "qualifiedName": "okhttp3.Call.execute",
            "external": True,
            "stdlib": False,
            "local": False,
            "filePath": "",
            "purl": "pkg:maven/com.squareup.okhttp3/okhttp@4.12.0",
        }
    )
    report["callGraph"]["edges"].append(
        {
            "id": "edge-external-1",
            "sourceId": "node-000001",
            "targetId": "node-external-1",
            "callType": "static",
            "line": 20,
        }
    )
    result = extract(
        report,
        source=SOURCE,
        producer_version="4.3.1",
        bom_components=[OKHTTP],
        extra_components=[KT2],
    )
    assert result.status == STATUS_COMPLETED
    edges = [
        r
        for r in result.records
        if r.kind == "reached-flow"
        and r.subject.purls == ["pkg:maven/com.squareup.okhttp3/okhttp@4.12.0"]
        and r.path is not None
        and len(r.path) == 2
    ]
    assert len(edges) == 1
    assert edges[0].locations[0].line == 20


def test_unknown_major_version_is_refused():
    report = _report("kosi-resolved-report.json")
    report["schemaVersion"] = "kosi/2"
    result = extract(
        report,
        source=SOURCE,
        producer_version="4.3.1",
        bom_components=[OKHTTP],
    )
    assert result.status == STATUS_NOT_ASSESSED
    assert not result.records
    assert "kosi/2" in (result.reason or "")


def test_newer_minor_version_is_accepted_with_a_caveat():
    report = _report("kosi-resolved-report.json")
    report["schemaVersion"] = "kosi/1.1"
    result = extract(
        report,
        source=SOURCE,
        producer_version="4.3.1",
        bom_components=[OKHTTP],
        extra_components=[KT2],
    )
    assert result.status == STATUS_COMPLETED
    assert any(c.kind == "schema-minor" for c in result.caveats)
    assert result.records
    assert all(
        any(c.kind == "schema-minor" for c in record.caveats) for record in result.records
    )


def test_report_without_a_version_is_accepted_as_schema_unknown():
    report = _report("kosi-resolved-report.json")
    report.pop("schemaVersion")
    result = extract(
        report,
        source=SOURCE,
        producer_version="4.3.1",
        bom_components=[OKHTTP],
        extra_components=[KT2],
    )
    assert result.status == STATUS_COMPLETED
    assert any(c.kind == "schema-unknown" for c in result.caveats)
    assert all(r.producer.report_schema_version == "unknown" for r in result.records)


def test_not_a_kosi_report_is_refused_with_a_reason():
    report = _report("kosi-resolved-report.json")
    report["schemaVersion"] = "atom/4"
    result = extract(
        report,
        source=SOURCE,
        producer_version="4.3.1",
        bom_components=[OKHTTP],
    )
    assert result.status == STATUS_NOT_ASSESSED
    assert not result.records


def test_truncated_report_is_not_assessed_without_raising():
    text = (DATA / "kosi-resolved-report.json").read_text(encoding="utf-8")
    result = extract(
        text[: len(text) // 2],
        source=SOURCE,
        producer_version="4.3.1",
        bom_components=[OKHTTP],
    )
    assert result.status == STATUS_NOT_ASSESSED
    assert not result.records


def test_malformed_report_is_not_assessed_without_raising():
    for raw in ("[]", '"a string"', '{"tool": {}, "dataFlow": }', ""):
        result = extract(
            raw,
            source=SOURCE,
            producer_version="4.3.1",
            bom_components=[OKHTTP],
        )
        assert result.status == STATUS_NOT_ASSESSED
        assert not result.records


def test_unnameable_invoke_diagnostics_are_a_coverage_gap():
    """The resolved recording's diagnostics say taint stops at unnameable
    invokes, so an absent flow means unexamined, not clean; that is a
    coverage gap on the producer and on every record."""
    result = _extract("kosi-resolved-report.json")
    assert result.status == STATUS_COMPLETED
    assert any(c.kind == "coverage-gap" for c in result.caveats)
    assert result.records
    assert all(
        any(c.kind == "coverage-gap" for c in record.caveats) for record in result.records
    )


def test_syntax_tier_not_run_diagnostics_are_a_coverage_gap():
    result = _extract("kosi-syntax-report.json")
    assert result.status == STATUS_COMPLETED
    assert any(
        c.kind == "coverage-gap" and "callgraph-not-run" in c.detail
        for c in result.caveats
    )


def test_stats_truncations_are_a_budget_caveat():
    report = _report("kosi-resolved-report.json")
    report["stats"]["truncations"] = {"dataflow-slices": 3}
    result = extract(
        report,
        source=SOURCE,
        producer_version="4.3.1",
        bom_components=[OKHTTP],
        extra_components=[KT2],
    )
    assert result.status == STATUS_COMPLETED
    assert any(c.kind == "budget" and "dataflow-slices" in c.detail for c in result.caveats)
    assert result.records
    assert all(
        any(c.kind == "budget" for c in record.caveats) for record in result.records
    )


def test_stats_cap_hits_are_a_budget_caveat():
    report = _report("kosi-resolved-report.json")
    report["stats"]["fixpointCapHits"] = 2
    result = extract(
        report,
        source=SOURCE,
        producer_version="4.3.1",
        bom_components=[OKHTTP],
        extra_components=[KT2],
    )
    assert result.status == STATUS_COMPLETED
    assert any(c.kind == "budget" and "fixpointCapHits" in c.detail for c in result.caveats)


def test_timeout_diagnostic_is_a_timeout_caveat():
    report = _report("kosi-resolved-report.json")
    report["diagnostics"] = [
        {"code": "callgraph-timeout", "count": 1, "message": "call graph stopped at its time budget"}
    ]
    result = extract(
        report,
        source=SOURCE,
        producer_version="4.3.1",
        bom_components=[OKHTTP],
        extra_components=[KT2],
    )
    assert result.status == STATUS_COMPLETED
    assert any(c.kind == "timeout" for c in result.caveats)
    assert all(
        any(c.kind == "timeout" for c in record.caveats) for record in result.records
    )


def test_collapsed_edge_hops_are_a_caveat_and_an_attribute():
    """A call-graph edge that collapsed intermediate hops says so on its
    record, both as the producer's attribute and as a caveat."""
    report = _report("kosi-resolved-report.json")
    report["callGraph"]["nodes"].append(
        {
            "id": "node-external-1",
            "name": "execute",
            "canonicalName": "okhttp3.Call.execute",
            "qualifiedName": "okhttp3.Call.execute",
            "external": True,
            "stdlib": False,
            "local": False,
            "filePath": "",
            "purl": "pkg:maven/com.squareup.okhttp3/okhttp@4.12.0",
        }
    )
    report["callGraph"]["edges"].append(
        {
            "id": "edge-external-1",
            "sourceId": "node-000001",
            "targetId": "node-external-1",
            "callType": "static",
            "line": 20,
            "collapsedHops": 2,
            "collapsedPackages": ["okhttp3.internal"],
        }
    )
    result = extract(
        report,
        source=SOURCE,
        producer_version="4.3.1",
        bom_components=[OKHTTP],
        extra_components=[KT2],
    )
    edges = [
        r
        for r in result.records
        if r.subject.purls == ["pkg:maven/com.squareup.okhttp3/okhttp@4.12.0"]
        and (r.attributes or {}).get("collapsed")
    ]
    assert len(edges) == 1
    edge_attrs = edges[0].attributes
    assert edge_attrs is not None
    assert edge_attrs["collapsed"] == {
        "collapsedHops": 2,
        "collapsedPackages": ["okhttp3.internal"],
    }
    assert any(c.kind == "collapsed-edges" for c in edges[0].caveats)


def test_unexpected_object_shape_is_a_record_skipped_caveat():
    report = _report("kosi-resolved-report.json")
    report["usages"].append(7)
    result = extract(
        report,
        source=SOURCE,
        producer_version="4.3.1",
        bom_components=[OKHTTP],
        extra_components=[KT2],
    )
    assert result.status == STATUS_COMPLETED
    skipped = [
        c for c in result.caveats if c.kind == "record-skipped" and "usages" in c.detail
    ]
    assert skipped


def test_is_kosi_report_detects_by_shape():
    report = _report("kosi-resolved-report.json")
    assert is_kosi_report(report)
    assert not is_kosi_report({"tool": {}})
    assert not is_kosi_report({"schemaVersion": "kosi/1"})
    assert not is_kosi_report([])


def test_attribute_name_by_coordinates():
    index = build_bom_purl_index([OKHTTP], extra_components=[KT2])
    assert attribute_name("okhttp3.Request.Builder.url", index) == {
        "pkg:maven/com.squareup.okhttp3/okhttp@4.12.0"
    }
    assert attribute_name("okhttp3.OkHttpClient", index) == {
        "pkg:maven/com.squareup.okhttp3/okhttp@4.12.0"
    }


@pytest.mark.parametrize(
    "name",
    [
        "java.lang.Runtime.exec",
        "kotlin.io.readLine",
        "android.app.Activity.onStart",
        "demo.readTarget",
        "",
    ],
)
def test_attribute_name_never_claims_runtime_or_unknown_packages(name):
    index = build_bom_purl_index([OKHTTP], extra_components=[KT2])
    assert attribute_name(name, index) == set()


def test_import_that_ties_two_artifacts_of_a_group_attributes_none():
    index = build_bom_purl_index(
        [
            {"purl": "pkg:maven/org.jetbrains.kotlinx/kotlinx-serialization-json@1.7.0"},
            {"purl": "pkg:maven/org.jetbrains.kotlinx/kotlinx-coroutines-core@1.9.0"},
        ]
    )
    assert attribute_name("kotlinx.serialization.json.Json", index) == set()


def test_reconciler_behaviour_is_unchanged():
    index = build_bom_purl_index([OKHTTP], extra_components=[KT2])
    assert (
        reconcile_purl("pkg:maven/com.squareup.okhttp3/okhttp", index)
        == "pkg:maven/com.squareup.okhttp3/okhttp@4.12.0"
    )
    assert (
        reconcile_purl("pkg:maven/com.squareup.okhttp3/okhttp@4.12.0", index)
        == "pkg:maven/com.squareup.okhttp3/okhttp@4.12.0"
    )
    assert reconcile_purl("pkg:maven/com.squareup.okhttp3/okhttp-jvm@4.12.0", index) is None
    assert reconcile_purl("pkg:npm/express@4.21.2", index) is None
    assert reconcile_purl("", index) is None


def test_bom_index_holds_only_maven_components_and_the_root():
    index = build_bom_purl_index(
        [OKHTTP, {"purl": "pkg:npm/express@4.21.2"}], extra_components=[KT2]
    )
    assert index["pkg:maven/com.squareup.okhttp3/okhttp@4.12.0"] == OKHTTP["purl"]
    assert index["pkg:maven/com.squareup.okhttp3/okhttp"] == OKHTTP["purl"]
    # the workspace root is indexed whatever its purl type
    assert index["pkg:generic/kt2@unspecified"] == KT2["purl"]
    assert "pkg:npm/express@4.21.2" not in index
