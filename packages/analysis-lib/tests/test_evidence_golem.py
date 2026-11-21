"""Tests for the golem evidence adapter.

The fixtures under ``tests/data/golem`` are real golem 4.3.1 reports,
recorded over the small repos in ``test/data/golem/repos`` and trimmed per
the README next to them. The tests cover the version gate, malformed and
truncated reports, the budget markers golem stamps, and the equality
contract: the reached purls the adapter's records count must be exactly the
purls the ``golem_slices`` converter carried on its flows for the same
report, and the service attribution must match the engine's positional walk
over those flows. Those golden sets were computed from the converter and
checked against the reports by hand; they are pinned below.
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

# The reached purls and service purls the golem_slices converter's flows
# carry for each recording, with the BOM components (and the metadata
# component) those flows were computed against. Verified against the
# reports by hand: reachable-app's slice, two call-graph edges, one usage
# and two endpoints cover the workspace purl and vuln-lib; real-cve-app's
# unrooted dataflow slices are dropped on golem's sound graph, the mux
# edges fall outside its reachablePackages, so only the app-driven
# go.uuid edges and the go.uuid usage are reached; unreachable-app has two
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


def test_record_kinds_on_the_recording():
    """The recording's one slice, two edges, one usage and two endpoints
    become the kinds the record matrix settles, with the witness paths the
    producer walked."""
    result = _extract("golem-reachable-app.json")
    kinds = sorted(record.kind for record in result.records)
    assert kinds == ["entry-point", "entry-point", "reached-flow", "reached-flow", "reached-flow", "usage"]
    slices = [r for r in result.records if r.kind == "reached-flow" and r.path and len(r.path) == 6]
    assert len(slices) == 1
    assert slices[0].confidence == "medium"
    assert slices[0].producer.report_schema_version == (
        "https://cdxgen.github.io/cdxgen-plugins-bin/golem/schema/v6"
    )
    endpoints = [r for r in result.records if r.kind == "entry-point"]
    assert sorted(r.locations[0].line for r in endpoints if r.locations) == [14, 16]
    usage = next(r for r in result.records if r.kind == "usage")
    assert usage.subject.purls == ["pkg:golang/github.com/example/vuln-lib@v0.0.0"]
    assert usage.locations[0].file == "main.go"


def test_producer_names_the_tool_and_report_version():
    result = _extract("golem-reachable-app.json")
    assert result.records
    for record in result.records:
        assert record.producer.name == "golem"
        assert record.producer.version == "4.3.1"
    assert not any(
        c.kind in ("schema-minor", "schema-unknown") for c in result.caveats
    )


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
        if r.kind == "reached-flow"
        and (r.attributes or {}).get("reachableFromRoots") is True
    ]
    assert with_reach
    for record in with_reach:
        attrs = record.attributes
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
    assert witnesses[0].attributes["symbol"] == "vulnlib.ProcessQuery"
    assert len(witnesses[0].path) == 2


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
    assert all(
        any(c.kind == "schema-minor" for c in record.caveats) for record in result.records
    )


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
    assert all(
        any(c.kind == "budget" for c in record.caveats) for record in result.records
    )


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
    assert all(
        any(c.kind == "budget" for c in record.caveats) for record in slice_records
    )


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
    skipped = [
        c for c in result.caveats if c.kind == "record-skipped" and "usage" in c.detail
    ]
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
    skipped = [
        c for c in result.caveats if c.kind == "record-skipped" and "slices" in c.detail
    ]
    assert skipped


def test_reconciler_behaviour_is_unchanged():
    """The three-form reconciliation the converter pinned, now owned by the
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
