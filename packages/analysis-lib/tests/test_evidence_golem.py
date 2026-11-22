"""Tests for the golem evidence adapter.

The fixtures under ``tests/data/golem`` are real golem 4.3.1 reports,
recorded over the small repos in ``test/data/golem/repos`` and trimmed per
the README next to them. The tests cover the version gate, malformed and
truncated reports, the budget markers golem stamps, record paths and ids
that do not depend on the directory golem ran in, the count of report
objects that make no record, and the reached-set contract: the reached
purls and service purls the records count for each recording are pinned
below, checked against the reports by hand, and must not change.
"""

import json
from pathlib import Path

import pytest

from analysis_lib.evidence.adapters import STATUS_COMPLETED, STATUS_NOT_ASSESSED
from analysis_lib.evidence.adapters.golem import (
    build_bom_purl_index,
    extract,
    reconcile_purl,
)

DATA = Path(__file__).parent / "data" / "golem"
SOURCE = "analysis/golem/golem.json"
REACHED_COUNTED = frozenset({"reached-flow", "usage", "entry-point"})

# The reached purls and service purls the records count for each recording,
# with the BOM components (and the metadata component) they are reconciled
# against. Verified against the reports by hand: reachable-app's slice, two
# call-graph edges, one usage and two endpoints cover the workspace purl and
# vuln-lib. In real-cve-app golem's sound (rta) graph marks both kept
# dataflow slices reachableFromRoots false, so neither is reached, and its
# reachablePackages list leaves out gorilla/mux, so the mux edges are not
# reached either; the gate is per package, so the go.uuid edges count even
# where golem marks the target node itself unreachable from the roots
# (the init edge), and only go.uuid is reached. unreachable-app has two
# endpoints and no dependencies.
CASES = {
    "golem-reachable-app.json": {
        "bom": [{"purl": "pkg:golang/github.com/example/vuln-lib@v0.0.0"}],
        "extra": [{"purl": "pkg:golang/github.com/example/reachable-app"}],
        "reached": [
            "pkg:golang/github.com/example/reachable-app",
            "pkg:golang/github.com/example/vuln-lib@v0.0.0",
        ],
        "services": ["pkg:golang/github.com/example/reachable-app"],
    },
    "golem-real-cve-app.json": {
        "bom": [
            {"purl": "pkg:golang/github.com/gorilla/mux@v1.8.1"},
            {"purl": "pkg:golang/github.com/satori/go.uuid@v1.2.0"},
        ],
        "extra": [{"purl": "pkg:golang/github.com/example/real-cve-app"}],
        "reached": ["pkg:golang/github.com/satori/go.uuid@v1.2.0"],
        "services": [],
    },
    "golem-unreachable-app.json": {
        "bom": [],
        "extra": [{"purl": "pkg:golang/github.com/example/unreachable-app"}],
        "reached": ["pkg:golang/github.com/example/unreachable-app"],
        "services": ["pkg:golang/github.com/example/unreachable-app"],
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


def test_record_kinds_on_the_recording():
    """The recording's one slice, two edges, one usage and two endpoints
    become the kinds the record matrix settles, with the witness paths the
    producer walked."""
    result = _extract("golem-reachable-app.json")
    kinds = sorted(record.kind for record in result.records)
    assert kinds == [
        "entry-point",
        "entry-point",
        "reached-flow",
        "reached-flow",
        "reached-flow",
        "usage",
    ]
    slices = [
        r for r in result.records if r.kind == "reached-flow" and r.path and len(r.path) == 6
    ]
    assert len(slices) == 1
    assert slices[0].confidence == "medium"
    assert slices[0].producer.report_schema_version == (
        "https://cdxgen.github.io/cdxgen-plugins-bin/golem/schema/v6"
    )
    endpoints = [r for r in result.records if r.kind == "entry-point"]
    assert sorted(
        r.locations[0].line for r in endpoints if r.locations and r.locations[0].line is not None
    ) == [14, 16]
    usage = next(r for r in result.records if r.kind == "usage")
    assert usage.subject.purls == ["pkg:golang/github.com/example/vuln-lib@v0.0.0"]
    assert usage.locations[0].file == "main.go"


def test_producer_names_the_tool_and_report_version():
    result = _extract("golem-reachable-app.json")
    assert result.records
    for record in result.records:
        assert record.producer.name == "golem"
        assert record.producer.version == "4.3.1"
    assert not any(c.kind in ("schema-minor", "schema-unknown") for c in result.caveats)


def test_producer_version_falls_back_to_the_report_tool_version():
    report = _report("golem-reachable-app.json")
    result = extract(
        report,
        source=SOURCE,
        bom_components=CASES["golem-reachable-app.json"]["bom"],
        extra_components=CASES["golem-reachable-app.json"]["extra"],
    )
    assert result.status == STATUS_COMPLETED
    assert {r.producer.version for r in result.records} == {"4.3.1"}


def test_records_carry_the_reach_fields_as_given():
    report = _report("golem-reachable-app.json")
    report["callGraph"]["reachability"]["nodes"] = [
        {
            "nodeId": "github.com/example/vuln-lib.ProcessQuery",
            "reachableFromRoots": True,
            "minDepth": 1,
            "rootIds": ["github.com/example/reachable-app.handleProcess"],
        }
    ]
    result = extract(
        report,
        source=SOURCE,
        producer_version="4.3.1",
        bom_components=CASES["golem-reachable-app.json"]["bom"],
        extra_components=CASES["golem-reachable-app.json"]["extra"],
    )
    with_reach = [
        r
        for r in result.records
        if r.kind == "reached-flow" and (r.attributes or {}).get("reachableFromRoots") is True
    ]
    assert with_reach
    for record in with_reach:
        attrs = record.attributes
        assert attrs is not None
        assert attrs["minDepth"] == 1
        assert attrs["rootIds"] == ["github.com/example/reachable-app.handleProcess"]


def test_witness_symbol_is_carried_when_requested():
    report = _report("golem-reachable-app.json")
    report["callGraph"]["reachability"]["paths"] = [
        {
            "symbol": "vulnlib.ProcessQuery",
            "nodeIds": [
                "github.com/example/reachable-app.handleProcess",
                "github.com/example/vuln-lib.ProcessQuery",
            ],
            "depth": 1,
        }
    ]
    result = extract(
        report,
        source=SOURCE,
        producer_version="4.3.1",
        bom_components=CASES["golem-reachable-app.json"]["bom"],
        extra_components=CASES["golem-reachable-app.json"]["extra"],
    )
    witnesses = [r for r in result.records if (r.attributes or {}).get("symbol")]
    assert witnesses
    witness_attrs = witnesses[0].attributes
    assert witness_attrs is not None
    assert witness_attrs["symbol"] == "vulnlib.ProcessQuery"
    witness_path = witnesses[0].path
    assert witness_path is not None
    assert len(witness_path) == 2


def test_unknown_major_version_is_refused():
    report = _report("golem-reachable-app.json")
    report["schemaVersion"] = "https://cdxgen.github.io/cdxgen-plugins-bin/golem/schema/v7"
    result = extract(
        report,
        source=SOURCE,
        producer_version="4.3.1",
        bom_components=CASES["golem-reachable-app.json"]["bom"],
    )
    assert result.status == STATUS_NOT_ASSESSED
    assert not result.records
    assert "v7" in (result.reason or "")


def test_older_major_version_is_refused():
    report = _report("golem-reachable-app.json")
    report["schemaVersion"] = "0.1"
    result = extract(
        report,
        source=SOURCE,
        producer_version="2.5.2",
        bom_components=CASES["golem-reachable-app.json"]["bom"],
    )
    assert result.status == STATUS_NOT_ASSESSED
    assert "0.1" in (result.reason or "")


def test_an_endpoint_that_resolves_to_no_module_is_a_caveat_not_a_drop():
    report = _report("golem-reachable-app.json")
    report["apiEndpoints"] = [
        {"path": "/health", "method": "GET", "handler": "handleHealth", "packagePath": "ghost/pkg"}
    ]
    result = extract(
        report,
        source=SOURCE,
        producer_version="4.3.1",
        bom_components=CASES["golem-reachable-app.json"]["bom"],
        extra_components=CASES["golem-reachable-app.json"]["extra"],
    )
    assert result.status == STATUS_COMPLETED
    assert not any(r.kind == "entry-point" for r in result.records)
    assert [c.detail for c in result.caveats if c.kind == "record-skipped"] == [
        "1 apiEndpoints entries resolve to no BOM module purl and became no record"
    ]


def test_newer_minor_version_is_accepted_with_a_caveat():
    report = _report("golem-reachable-app.json")
    report["schemaVersion"] = "https://cdxgen.github.io/cdxgen-plugins-bin/golem/schema/v6.1"
    result = extract(
        report,
        source=SOURCE,
        producer_version="4.3.1",
        bom_components=CASES["golem-reachable-app.json"]["bom"],
        extra_components=CASES["golem-reachable-app.json"]["extra"],
    )
    assert result.status == STATUS_COMPLETED
    assert any(c.kind == "schema-minor" for c in result.caveats)
    assert result.records
    assert all(any(c.kind == "schema-minor" for c in record.caveats) for record in result.records)


def test_report_without_a_version_is_accepted_as_schema_unknown():
    report = _report("golem-reachable-app.json")
    report.pop("schemaVersion")
    result = extract(
        report,
        source=SOURCE,
        producer_version="4.3.1",
        bom_components=CASES["golem-reachable-app.json"]["bom"],
        extra_components=CASES["golem-reachable-app.json"]["extra"],
    )
    assert result.status == STATUS_COMPLETED
    assert any(c.kind == "schema-unknown" for c in result.caveats)
    assert result.records
    assert all(r.producer.report_schema_version == "unknown" for r in result.records)


def test_not_a_golem_report_is_refused_with_a_reason():
    report = _report("golem-reachable-app.json")
    report.pop("callGraph")
    report.pop("dataFlow")
    result = extract(
        report,
        source=SOURCE,
        producer_version="4.3.1",
        bom_components=CASES["golem-reachable-app.json"]["bom"],
    )
    assert result.status == STATUS_NOT_ASSESSED
    assert not result.records


def test_truncated_report_is_not_assessed_without_raising():
    text = (DATA / "golem-reachable-app.json").read_text(encoding="utf-8")
    result = extract(
        text[: len(text) // 2],
        source=SOURCE,
        producer_version="4.3.1",
        bom_components=CASES["golem-reachable-app.json"]["bom"],
    )
    assert result.status == STATUS_NOT_ASSESSED
    assert not result.records


def test_malformed_report_is_not_assessed_without_raising():
    for raw in ("[]", '"a string"', '{"tool": {"name": "golem"}, "callGraph": }', ""):
        result = extract(
            raw,
            source=SOURCE,
            producer_version="4.3.1",
            bom_components=CASES["golem-reachable-app.json"]["bom"],
        )
        assert result.status == STATUS_NOT_ASSESSED
        assert not result.records


def test_partial_slice_reachability_is_a_budget_caveat():
    report = _report("golem-reachable-app.json")
    report["dataFlow"]["sliceReachability"]["status"] = "partial"
    result = extract(
        report,
        source=SOURCE,
        producer_version="4.3.1",
        bom_components=CASES["golem-reachable-app.json"]["bom"],
        extra_components=CASES["golem-reachable-app.json"]["extra"],
    )
    assert result.status == STATUS_COMPLETED
    assert any(c.kind == "budget" for c in result.caveats)
    assert result.records
    assert all(any(c.kind == "budget" for c in record.caveats) for record in result.records)


def test_dataflow_truncation_marker_is_a_budget_caveat():
    report = _report("golem-reachable-app.json")
    report["dataFlow"]["stats"]["truncated"] = True
    report["dataFlow"]["stats"]["truncationReasons"] = ["max-slices"]
    result = extract(
        report,
        source=SOURCE,
        producer_version="4.3.1",
        bom_components=CASES["golem-reachable-app.json"]["bom"],
        extra_components=CASES["golem-reachable-app.json"]["extra"],
    )
    assert any(c.kind == "budget" for c in result.caveats)
    slice_records = [r for r in result.records if r.kind == "reached-flow"]
    assert slice_records
    assert all(any(c.kind == "budget" for c in record.caveats) for record in slice_records)


def test_unresolvable_usage_is_a_record_skipped_caveat():
    """A usage whose module resolves to nothing cannot become a record; the
    adapter must say so instead of dropping it silently."""
    report = _report("golem-reachable-app.json")
    usage = report["usages"][0]
    usage["module"]["purl"] = ""
    usage["packagePath"] = ""
    result = extract(
        report,
        source=SOURCE,
        producer_version="4.3.1",
        bom_components=CASES["golem-reachable-app.json"]["bom"],
        extra_components=CASES["golem-reachable-app.json"]["extra"],
    )
    assert result.status == STATUS_COMPLETED
    assert not any(r.kind == "usage" for r in result.records)
    skipped = [c for c in result.caveats if c.kind == "record-skipped" and "usage" in c.detail]
    assert skipped


def test_unexpected_object_shape_is_a_record_skipped_caveat():
    """A slice entry that is not an object cannot become a record; the
    adapter must say so instead of raising or dropping it silently."""
    report = _report("golem-reachable-app.json")
    report["dataFlow"]["slices"].append("not-a-slice")
    result = extract(
        report,
        source=SOURCE,
        producer_version="4.3.1",
        bom_components=CASES["golem-reachable-app.json"]["bom"],
        extra_components=CASES["golem-reachable-app.json"]["extra"],
    )
    assert result.status == STATUS_COMPLETED
    skipped = [c for c in result.caveats if c.kind == "record-skipped" and "slices" in c.detail]
    assert skipped


def test_reconciler_behaviour_is_unchanged():
    """The three-form reconciliation, owned by the
    adapter."""
    bom = [
        {"purl": "pkg:golang/github.com/jackc/pgx/v4@v4.18.1"},
        {"purl": "pkg:golang/github.com/foo-bar@v1.0.0"},
    ]
    index = build_bom_purl_index(bom)
    pgx = "pkg:golang/github.com/jackc/pgx/v4@v4.18.1"
    assert reconcile_purl(pgx, index) == pgx
    assert reconcile_purl(pgx + "#pgxpool", index) == pgx
    assert reconcile_purl("pkg:golang/github.com/jackc/pgx/v4", index) == pgx
    assert reconcile_purl("pkg:golang/github.com/nonexistent/pkg@v1.0.0", index) is None
    assert reconcile_purl("pkg:cargo/sqlx@0.6.2", index) is None
    assert reconcile_purl("", index) is None
    # Go module paths are literal: no dash/underscore normalisation
    assert reconcile_purl("pkg:golang/github.com/foo_bar@v1.0.0", index) is None


def test_bom_index_ignores_non_golang_components_and_holds_the_root():
    index = build_bom_purl_index(
        [{"purl": "pkg:npm/express@4.21.2"}, {"purl": "pkg:golang/github.com/x/y@v1.0.0"}],
        extra_components=[{"purl": "pkg:golang/github.com/x/y"}],
    )
    assert index["pkg:golang/github.com/x/y@v1.0.0"] == "pkg:golang/github.com/x/y@v1.0.0"
    assert index["pkg:golang/github.com/x/y"] == "pkg:golang/github.com/x/y@v1.0.0"
    assert "pkg:npm/express@4.21.2" not in index


# --- record paths and ids ---------------------------------------------------

REACHABLE_FILES = {"main.go", "github.com/example/vuln-lib@v0.0.0/vuln.go"}


def _files(result):
    """Every file a record names, in its locations or on its witness path."""
    files = set()
    for record in result.records:
        files.update(location.file for location in record.locations)
        files.update(node.file for node in record.path or [] if node.file)
    return files


def _rewrite(report, old, new):
    return json.loads(json.dumps(report).replace(old, new))


def test_record_paths_are_relative_to_the_analysed_directory():
    """A file in the analysed directory is relative to it, and a file of the
    replaced vuln-lib module outside it is spelled under its module path and
    version; no record carries the absolute path golem printed."""
    result = _extract("golem-reachable-app.json")
    assert _files(result) == REACHABLE_FILES
    assert not any(c.kind == "location-outside-root" for c in result.caveats)


def test_a_windows_report_gives_the_same_relative_paths():
    """The same report as golem prints it on Windows: drive letter and
    backslashes in every path."""
    report = _report("golem-reachable-app.json")
    windows = _rewrite(report, "/src/repos/", "C:\\\\src\\\\repos\\\\")
    assert windows != report
    result = extract(
        windows,
        source=SOURCE,
        bom_components=CASES["golem-reachable-app.json"]["bom"],
        extra_components=CASES["golem-reachable-app.json"]["extra"],
    )
    assert result.status == STATUS_COMPLETED
    assert _files(result) == REACHABLE_FILES


def test_a_trailing_slash_or_a_missing_options_block_keeps_paths_relative():
    """A root spelled with a trailing slash, and a report without its options
    block whose root comes from the caller, both give relative paths."""
    report = _report("golem-reachable-app.json")
    report["options"]["directory"] = "/src/repos/reachable-app/"
    assert _files(_extract_report(report)) == REACHABLE_FILES
    bare = _report("golem-reachable-app.json")
    bare.pop("options")
    bare["runtime"].pop("workingDir")
    for module in bare["modules"]:
        module.pop("dir", None)
    without_root = _extract_report(bare)
    assert "main.go" not in _files(without_root)
    assert [c.kind for c in without_root.caveats] == ["location-outside-root"]
    # The caller's source root restores the workspace paths; the vuln-lib
    # file, whose module directory the report no longer names, stays out.
    with_root = _extract_report(bare, source_root="/src/repos/reachable-app")
    assert _files(with_root) == {"main.go"}
    assert [c.kind for c in with_root.caveats] == ["location-outside-root"]


def _extract_report(report, **overrides):
    kwargs = {
        "source": SOURCE,
        "bom_components": CASES["golem-reachable-app.json"]["bom"],
        "extra_components": CASES["golem-reachable-app.json"]["extra"],
    }
    kwargs.update(overrides)
    return extract(report, **kwargs)


def test_files_outside_the_root_take_the_module_cache_spelling_or_are_left_out():
    """A file in the Go module cache is spelled by the module and version
    the cache path names; any other absolute path is left out of the record
    with a caveat."""
    report = _report("golem-reachable-app.json")
    report["usages"][0]["range"]["start"]["filename"] = (
        "/home/someone/go/pkg/mod/github.com/example/vuln-lib@v0.0.0/vuln.go"
    )
    report["apiEndpoints"][0]["range"]["start"]["filename"] = "/opt/elsewhere/main.go"
    result = _extract_report(report)
    usage = next(r for r in result.records if r.kind == "usage")
    assert usage.locations[0].file == "github.com/example/vuln-lib@v0.0.0/vuln.go"
    endpoint = next(r for r in result.records if r.kind == "entry-point" and not r.locations)
    assert [c.kind for c in endpoint.caveats] == ["location-outside-root"]
    assert [c.detail for c in result.caveats if c.kind == "location-outside-root"] == [
        "1 file path(s) the producer named lie outside the source root and no package "
        "directory; the records leave them out"
    ]
    assert not any(f.startswith("/") for f in _files(result))


def test_ids_do_not_depend_on_the_directory_golem_ran_in():
    """The same report produced in another directory: golem embeds the
    directory in endpoint ids and positions, and the record ids must not
    change with it."""
    report = _report("golem-reachable-app.json")
    moved = _rewrite(report, "/src/repos", "/work/elsewhere")
    assert moved != report
    first = _extract_report(report)
    second = _extract_report(moved)
    assert len(first.records) == 6
    assert [r.id for r in first.records] == [r.id for r in second.records]
    assert [r.to_dict() for r in first.records] == [r.to_dict() for r in second.records]


# --- malformed values and skipped objects -----------------------------------


@pytest.mark.parametrize(
    "path, value, problem",
    [
        (("callGraph",), [], "callGraph is a list, expected an object"),
        (("options",), "x", "options is a str, expected an object"),
        (("dataFlow", "nodes"), 5, "dataFlow.nodes is a int, expected an array"),
        (("callGraph", "edges"), {"a": 1}, "callGraph.edges is a dict, expected an array"),
    ],
)
def test_a_section_of_the_wrong_type_is_not_assessed(path, value, problem):
    report = _report("golem-reachable-app.json")
    holder = report
    for key in path[:-1]:
        holder = holder[key]
    holder[path[-1]] = value
    result = _extract_report(report)
    assert result.status == STATUS_NOT_ASSESSED
    assert result.reason == f"the golem report is malformed and was not assessed: {problem}"


def test_nested_values_of_the_wrong_type_are_read_without_raising():
    """A null section reads as absent, and a nested value of the wrong type
    (an id list that is a number, a line that is text, a position that is a
    list) is no value; the rest of the report still becomes records."""
    report = _report("golem-reachable-app.json")
    report["callGraph"]["nodes"] = None
    report["dataFlow"]["slices"][0]["nodeIds"] = 7
    report["usages"][0]["range"]["start"]["line"] = "abc"
    report["apiEndpoints"][0]["range"] = [1, 2]
    result = _extract_report(report)
    assert result.status == STATUS_COMPLETED
    usage = next(r for r in result.records if r.kind == "usage")
    assert usage.locations[0].line is None
    assert sorted(r.kind for r in result.records) == [
        "entry-point",
        "entry-point",
        "reached-flow",
        "reached-flow",
        "reached-flow",
        "usage",
    ]


@pytest.mark.parametrize("version", ["https://x/golem/schema/vlatest", "v6-beta"])
def test_a_version_without_a_numeric_major_is_refused(version):
    report = _report("golem-reachable-app.json")
    report["schemaVersion"] = version
    result = _extract_report(report)
    assert result.status == STATUS_NOT_ASSESSED
    assert version in (result.reason or "")


def test_objects_that_make_no_record_are_counted_per_reason():
    """real-cve-app: the two kept slices golem marked unreachable from every
    root, and the two mux edges outside golem's reachablePackages, are
    counted, not dropped silently."""
    result = _extract("golem-real-cve-app.json")
    assert [c.detail for c in result.caveats if c.kind == "record-skipped"] == [
        "2 dataFlow.slices entries golem marked unreachable from every root "
        "(reachableFromRoots false on a dispatch-aware graph) became no record",
        "2 callGraph.edges entries call into packages golem's dispatch-aware graph never "
        "reaches from non-init code and became no record",
    ]
    # Without the BOM, every object that names a dependency is counted.
    bare = _extract("golem-reachable-app.json", bom_components=[], extra_components=[])
    assert bare.records == []
    assert [c.detail for c in bare.caveats if c.kind == "record-skipped"] == [
        "1 dataFlow.slices entries name no package this BOM carries and became no record",
        "2 callGraph.edges entries call a package this BOM does not carry and became no record",
        "1 usages entries resolve to no BOM module purl and became no record",
        "2 apiEndpoints entries resolve to no BOM module purl and became no record",
    ]
