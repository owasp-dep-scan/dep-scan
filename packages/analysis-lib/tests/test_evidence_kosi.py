"""Tests for the kosi evidence adapter.

The fixtures under ``tests/data/kosi`` are real kosi 4.3.1 recordings of
the resolved and syntax tiers (current-release output, kept from earlier
recordings, described in the README next to them). The tests cover the
version gate, malformed and truncated reports, kosi's stats and
diagnostics markers, record paths and ids that do not depend on the
directory kosi ran in, the count of report objects that make no record,
and the reached-set contract: the reached purls and service purls the
records count for each recording are pinned below, checked against the
reports by hand, and must not change.

kosi's ``apiEndpoints`` become ``entry-point`` records that name no
package, so the pinned reached sets hold with them in place.
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

# The reached purls and service purls the records count for each recording,
# with the BOM components (and the metadata component) they are reconciled
# against. Verified against the
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
        "services": [
            "pkg:generic/kt2@unspecified",
            "pkg:maven/com.squareup.okhttp3/okhttp@4.12.0",
        ],
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
def test_reached_set_on_the_recording(name):
    result = _extract(name)
    assert result.status == STATUS_COMPLETED
    assert _reached(result) == set(CASES[name]["reached"])


@pytest.mark.parametrize("name", sorted(CASES))
def test_service_attribution_on_the_recording(name):
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
    ssrf = next(
        r
        for r in slices
        if (r.attributes or {}).get("servicePurls")
        == [
            "pkg:generic/kt2@unspecified",
            "pkg:maven/com.squareup.okhttp3/okhttp@4.12.0",
        ]
    )
    # the producer states no tier on these slices, so none is invented
    assert ssrf.attributes is not None
    assert "tier" not in ssrf.attributes
    other = [r for r in slices if r is not ssrf]
    assert len(other) == 1
    # the process-exec slice's only BOM purl is the workspace, attributed
    # through the sink category
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
    as reached evidence."""
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
    assert all(any(c.kind == "schema-minor" for c in record.caveats) for record in result.records)


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
    assert all(any(c.kind == "coverage-gap" for c in record.caveats) for record in result.records)


def test_syntax_tier_not_run_diagnostics_are_a_coverage_gap():
    result = _extract("kosi-syntax-report.json")
    assert result.status == STATUS_COMPLETED
    assert any(
        c.kind == "coverage-gap" and "callgraph-not-run" in c.detail for c in result.caveats
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
    assert all(any(c.kind == "budget" for c in record.caveats) for record in result.records)


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
        {
            "code": "callgraph-timeout",
            "count": 1,
            "message": "call graph stopped at its time budget",
        }
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
    assert all(any(c.kind == "timeout" for c in record.caveats) for record in result.records)


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
    skipped = [c for c in result.caveats if c.kind == "record-skipped" and "usages" in c.detail]
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


# --- usages ------------------------------------------------------------------


def test_every_call_site_of_a_symbol_keeps_its_own_record():
    """Two call sites of one okhttp symbol are two usage records, each with
    its own line; the usages that attribute to no BOM package are counted."""
    report = _report("kosi-resolved-report.json")
    again = json.loads(json.dumps(report["usages"][0]))
    again["id"] = "use-000099"
    again["position"]["line"] = 30
    report["usages"].append(again)
    result = extract(report, source=SOURCE, bom_components=[OKHTTP], extra_components=[KT2])
    usages = [r for r in result.records if r.kind == "usage"]
    assert [(r.locations[0].method, r.locations[0].line) for r in usages] == [
        ("okhttp3.OkHttpClient", 13),
        ("okhttp3.Request.Builder", 14),
        ("okhttp3.Request.Builder.url", 14),
        ("okhttp3.Request.Builder.url.build", 14),
        ("okhttp3.OkHttpClient", 30),
    ]
    assert len({r.id for r in usages}) == 5
    assert [c.detail for c in result.caveats if c.kind == "record-skipped"] == [
        "12 usages entries name no import that attributes to a BOM package and became no record"
    ]


# --- api endpoints -----------------------------------------------------------


ENDPOINT = {
    "id": "ep-000001",
    "framework": "ktor",
    "httpMethods": ["GET"],
    "pathTemplate": "/fetch",
    "pathParameters": [],
    "queryParameters": [],
    "consumes": [],
    "produces": [],
    "authentication": [],
    "handlerSymbol": "fetch",
    "handlerCanonicalName": "demo.fetch",
    "modulePath": ".",
    "purl": "pkg:generic/kt2@unspecified",
    "position": {"filename": "src/main/kotlin/demo/App.kt", "line": 19, "column": 1},
    "reachableSources": [],
    "sliceIds": [],
    "foundBy": "dsl",
}


@pytest.mark.parametrize("name", sorted(CASES))
def test_api_endpoints_are_kept_without_changing_the_reached_sets(name):
    """An endpoint becomes an entry-point record that names no package: the
    workspace module that declares it is the modulePurl attribute. The
    reached and service sets are the pinned ones."""
    report = _report(name)
    assert report["apiEndpoints"] == []
    report["apiEndpoints"] = [ENDPOINT]
    result = extract(report, source=SOURCE, bom_components=[OKHTTP], extra_components=[KT2])
    entries = [r for r in result.records if r.kind == "entry-point"]
    assert len(entries) == 1
    entry = entries[0]
    assert entry.subject.purls == []
    assert entry.attributes == {
        "framework": "ktor",
        "httpMethods": ["GET"],
        "pathTemplate": "/fetch",
        "handlerSymbol": "fetch",
        "handlerCanonicalName": "demo.fetch",
        "foundBy": "dsl",
        "modulePurl": "pkg:generic/kt2@unspecified",
    }
    assert entry.locations[0].file == "src/main/kotlin/demo/App.kt"
    assert entry.locations[0].line == 19
    assert _reached(result) == set(CASES[name]["reached"])
    assert _services(result) == set(CASES[name]["services"])


# --- record paths, ids, malformed values -------------------------------------


def test_record_paths_are_relative_and_never_absolute():
    """An absolute path under kosi's working directory becomes relative, a
    Windows path too, a file in a Gradle cache takes its group, artifact
    and version spelling, and any other absolute path is left out."""
    report = _report("kosi-resolved-report.json")
    report["runtime"]["workingDirectory"] = "C:\\src\\kt2"
    frames = report["dataFlow"]["slices"][0]["frames"]
    frames[0]["file"] = "C:\\src\\kt2\\src\\main\\kotlin\\demo\\App.kt"
    frames[1]["file"] = (
        "/home/someone/.gradle/caches/modules-2/files-2.1/com.squareup.okhttp3/okhttp/"
        "4.12.0/0123abcd/okhttp-4.12.0-sources.jar"
    )
    frames[2]["file"] = "/opt/elsewhere/App.kt"
    result = extract(report, source=SOURCE, bom_components=[OKHTTP], extra_components=[KT2])
    record = next(r for r in result.records if r.kind == "reached-flow")
    assert [node.file for node in (record.path or [])[:3]] == [
        "src/main/kotlin/demo/App.kt",
        "com.squareup.okhttp3/okhttp/4.12.0/okhttp-4.12.0-sources.jar",
        None,
    ]
    assert "location-outside-root" in {c.kind for c in record.caveats}
    for rec in result.records:
        for location in rec.locations:
            assert not location.file.startswith("/") and ":" not in location.file


def test_ids_do_not_depend_on_the_directory_kosi_ran_in():
    report = _report("kosi-resolved-report.json")
    absolute = "/src/kt2/src/main/kotlin/demo/App.kt"
    for entry in report["usages"] + report["imports"]:
        entry["filePath"] = absolute
    moved = json.loads(json.dumps(report).replace("/src/kt2", "/work/elsewhere/kt2"))
    assert moved != report
    kwargs = {"source": SOURCE, "bom_components": [OKHTTP], "extra_components": [KT2]}
    first = extract(report, **kwargs)
    second = extract(moved, **kwargs)
    assert len(first.records) == 6
    assert [r.to_dict() for r in first.records] == [r.to_dict() for r in second.records]


def test_nested_values_of_the_wrong_type_are_read_without_raising():
    """A frame line that is text and a usage position that is a list are no
    line; the records are still built."""
    report = _report("kosi-resolved-report.json")
    report["dataFlow"]["slices"][0]["frames"][0]["line"] = "abc"
    report["usages"][0]["position"] = [1, 2]
    result = extract(report, source=SOURCE, bom_components=[OKHTTP], extra_components=[KT2])
    assert result.status == STATUS_COMPLETED
    record = next(r for r in result.records if r.kind == "reached-flow")
    assert (record.path or [])[0].line is None
    usage = next(r for r in result.records if r.kind == "usage")
    assert usage.locations[0].line is None


@pytest.mark.parametrize(
    "path, value, problem",
    [
        (("callGraph",), [], "callGraph is a list, expected an object"),
        (("usages",), 5, "usages is a int, expected an array"),
        (("apiEndpoints",), {}, "apiEndpoints is a dict, expected an array"),
    ],
)
def test_a_section_of_the_wrong_type_is_not_assessed(path, value, problem):
    report = _report("kosi-resolved-report.json")
    holder = report
    for key in path[:-1]:
        holder = holder[key]
    holder[path[-1]] = value
    result = extract(report, source=SOURCE)
    assert result.status == STATUS_NOT_ASSESSED
    assert result.reason == f"the kosi report is malformed and was not assessed: {problem}"


@pytest.mark.parametrize("version", ["kosi/v2", "kosi/latest"])
def test_a_version_without_a_numeric_major_is_refused(version):
    report = _report("kosi-resolved-report.json")
    report["schemaVersion"] = version
    result = extract(report, source=SOURCE)
    assert result.status == STATUS_NOT_ASSESSED
    assert version in (result.reason or "")
