"""Tests for the rusi evidence adapter.

The fixtures under ``tests/data/rusi`` are real rusi 4.3.1 reports,
recorded over the small repos in ``test/data/rusi/repos`` and trimmed per
the README next to them. The tests cover the version gate, malformed and
truncated reports, rusi's diagnostics, and the equality contract: the
reached purls the adapter's records count must be exactly the purls the
``rusi_slices`` converter carried on its flows for the same report, and the
service attribution must match the engine's positional walk over those
flows. Those golden sets were computed from the converter and checked
against the reports by hand; they are pinned below.

The converter never read rusi's ``usages[]`` section and never emitted
flows for it, so the adapter records no usage evidence either: emitting it
would count purls master never counted. The equality contract below holds
the adapter to that.
"""

import json
from pathlib import Path

import pytest

from analysis_lib.evidence.adapters import STATUS_COMPLETED, STATUS_NOT_ASSESSED
from analysis_lib.evidence.adapters.rusi import (
    build_bom_purl_index,
    extract,
    reconcile_purl,
)

DATA = Path(__file__).parent / "data" / "rusi"
SOURCE = "analysis/rusi/rusi.json"
REACHED_COUNTED = frozenset({"reached-flow", "usage", "entry-point"})

# The reached purls and service purls the rusi_slices converter's flows
# carry for each recording, with the BOM components (and the metadata
# component) those flows were computed against. Verified against the
# reports by hand: reachable-app's one slice crosses workspace code only,
# and its unresolved call targets (sqlx, stdlib) name no BOM component;
# rustsec-app's call graph carries the edge into time::now, reconciled to
# the BOM's time 0.1.45, plus a workspace-internal edge the converter
# kept; unreachable-app has no edges, slices or endpoints at all.
CASES = {
    "rusi-reachable-app.json": {
        "bom": [],
        "extra": [{"purl": "pkg:cargo/reachable-app@0.1.0"}],
        "reached": ["pkg:cargo/reachable-app@0.1.0"],
        "services": ["pkg:cargo/reachable-app@0.1.0"],
    },
    "rusi-rustsec-app.json": {
        "bom": [{"purl": "pkg:cargo/time@0.1.45"}],
        "extra": [{"purl": "pkg:cargo/rustsec-app@0.1.0"}],
        "reached": ["pkg:cargo/rustsec-app@0.1.0", "pkg:cargo/time@0.1.45"],
        "services": [],
    },
    "rusi-unreachable-app.json": {
        "bom": [],
        "extra": [{"purl": "pkg:cargo/unreachable-app@0.1.0"}],
        "reached": [],
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


def test_record_kinds_on_the_recording():
    """reachable-app's one slice carries its witness path and rule;
    rustsec-app's two call-graph edges carry the time and workspace
    purls."""
    slice_result = _extract("rusi-reachable-app.json")
    assert [r.kind for r in slice_result.records] == ["reached-flow"]
    slice_record = slice_result.records[0]
    slice_path = slice_record.path
    assert slice_path is not None
    assert len(slice_path) == 6
    slice_attrs = slice_record.attributes
    assert slice_attrs is not None
    assert slice_attrs["ruleId"] == "file-to-sql-query"
    assert slice_attrs["backend"] == "stable"
    assert slice_attrs["servicePurls"] == ["pkg:cargo/reachable-app@0.1.0"]
    assert slice_record.locations[0].file == "src/main.rs"

    edge_result = _extract("rusi-rustsec-app.json")
    assert sorted(r.kind for r in edge_result.records) == ["reached-flow", "reached-flow"]
    time_record = next(
        r
        for r in edge_result.records
        if r.subject.purls == ["pkg:cargo/time@0.1.45"]
    )
    assert time_record.path and len(time_record.path) == 2
    assert time_record.producer.name == "rusi"
    assert time_record.producer.version == "4.3.1"
    assert time_record.producer.report_schema_version == (
        "https://appthreat.github.io/rusi/schema/report-0.1"
    )


def test_producer_version_falls_back_to_the_report_tool_version():
    report = _report("rusi-reachable-app.json")
    result = extract(
        report,
        source=SOURCE,
        bom_components=CASES["rusi-reachable-app.json"]["bom"],
        extra_components=CASES["rusi-reachable-app.json"]["extra"],
    )
    assert result.status == STATUS_COMPLETED
    assert {r.producer.version for r in result.records} == {"4.3.1"}


def test_empty_report_is_completed_with_no_records():
    """unreachable-app's report is a genuine clean result: the tool ran, the
    report parsed, and it names nothing in the BOM."""
    result = _extract("rusi-unreachable-app.json")
    assert result.status == STATUS_COMPLETED
    assert result.records == []


def test_unknown_major_version_is_refused():
    report = _report("rusi-reachable-app.json")
    report["schema_version"] = "https://appthreat.github.io/rusi/schema/report-1.0"
    result = extract(
        report,
        source=SOURCE,
        producer_version="4.3.1",
        bom_components=CASES["rusi-reachable-app.json"]["bom"],
    )
    assert result.status == STATUS_NOT_ASSESSED
    assert not result.records
    assert "report-1.0" in (result.reason or "")


def test_older_minor_version_is_accepted_without_a_caveat():
    report = _report("rusi-reachable-app.json")
    report["schema_version"] = "https://appthreat.github.io/rusi/schema/report-0.0"
    result = extract(
        report,
        source=SOURCE,
        producer_version="4.3.1",
        bom_components=CASES["rusi-reachable-app.json"]["bom"],
        extra_components=CASES["rusi-reachable-app.json"]["extra"],
    )
    assert result.status == STATUS_COMPLETED
    assert not any(c.kind == "schema-minor" for c in result.caveats)


def test_newer_minor_version_is_accepted_with_a_caveat():
    report = _report("rusi-reachable-app.json")
    report["schema_version"] = "https://appthreat.github.io/rusi/schema/report-0.2"
    result = extract(
        report,
        source=SOURCE,
        producer_version="4.3.1",
        bom_components=CASES["rusi-reachable-app.json"]["bom"],
        extra_components=CASES["rusi-reachable-app.json"]["extra"],
    )
    assert result.status == STATUS_COMPLETED
    assert any(c.kind == "schema-minor" for c in result.caveats)
    assert result.records
    assert all(
        any(c.kind == "schema-minor" for c in record.caveats) for record in result.records
    )


def test_report_without_a_version_is_accepted_as_schema_unknown():
    report = _report("rusi-reachable-app.json")
    report.pop("schema_version")
    result = extract(
        report,
        source=SOURCE,
        producer_version="4.3.1",
        bom_components=CASES["rusi-reachable-app.json"]["bom"],
        extra_components=CASES["rusi-reachable-app.json"]["extra"],
    )
    assert result.status == STATUS_COMPLETED
    assert any(c.kind == "schema-unknown" for c in result.caveats)
    assert all(r.producer.report_schema_version == "unknown" for r in result.records)


def test_not_a_rusi_report_is_refused_with_a_reason():
    report = _report("rusi-reachable-app.json")
    report.pop("call_graph")
    report.pop("data_flow")
    result = extract(
        report,
        source=SOURCE,
        producer_version="4.3.1",
        bom_components=CASES["rusi-reachable-app.json"]["bom"],
    )
    assert result.status == STATUS_NOT_ASSESSED
    assert not result.records


def test_truncated_report_is_not_assessed_without_raising():
    text = (DATA / "rusi-reachable-app.json").read_text(encoding="utf-8")
    result = extract(
        text[: len(text) // 2],
        source=SOURCE,
        producer_version="4.3.1",
        bom_components=CASES["rusi-reachable-app.json"]["bom"],
    )
    assert result.status == STATUS_NOT_ASSESSED
    assert not result.records


def test_malformed_report_is_not_assessed_without_raising():
    for raw in ("[]", '"a string"', '{"tool": {}, "call_graph": }', ""):
        result = extract(
            raw,
            source=SOURCE,
            producer_version="4.3.1",
            bom_components=CASES["rusi-reachable-app.json"]["bom"],
        )
        assert result.status == STATUS_NOT_ASSESSED
        assert not result.records


def test_resolution_diagnostics_become_unresolved_call_site_caveats():
    """The recordings carry rusi's resolution diagnostics for every external
    call target; the producer caveat names them and the caveat lands on the
    call-graph record about the target it names."""
    result = _extract("rusi-rustsec-app.json")
    assert result.status == STATUS_COMPLETED
    producer_caveats = [c for c in result.caveats if c.kind == "unresolved-call-sites"]
    assert producer_caveats
    assert "time::now" in producer_caveats[0].detail
    time_record = next(
        r for r in result.records if r.subject.purls == ["pkg:cargo/time@0.1.45"]
    )
    assert any(c.kind == "unresolved-call-sites" for c in time_record.caveats)


def test_timeout_diagnostic_is_a_timeout_caveat_on_every_record():
    report = _report("rusi-reachable-app.json")
    report["diagnostics"] = [
        {"kind": "timeout", "message": "data-flow analysis exceeded its time budget"}
    ]
    result = extract(
        report,
        source=SOURCE,
        producer_version="4.3.1",
        bom_components=CASES["rusi-reachable-app.json"]["bom"],
        extra_components=CASES["rusi-reachable-app.json"]["extra"],
    )
    assert result.status == STATUS_COMPLETED
    assert any(c.kind == "timeout" for c in result.caveats)
    assert result.records
    assert all(
        any(c.kind == "timeout" for c in record.caveats) for record in result.records
    )


def test_truncation_diagnostic_is_a_budget_caveat_on_every_record():
    report = _report("rusi-rustsec-app.json")
    report["call_graph"]["diagnostics"] = [
        {
            "kind": "call-candidates-truncated",
            "message": "call sites past the candidate cap were cut",
        }
    ]
    result = extract(
        report,
        source=SOURCE,
        producer_version="4.3.1",
        bom_components=CASES["rusi-rustsec-app.json"]["bom"],
        extra_components=CASES["rusi-rustsec-app.json"]["extra"],
    )
    assert result.status == STATUS_COMPLETED
    assert any(c.kind == "budget" for c in result.caveats)
    assert result.records
    assert all(
        any(c.kind == "budget" for c in record.caveats) for record in result.records
    )


def test_unexpected_object_shape_is_a_record_skipped_caveat():
    report = _report("rusi-rustsec-app.json")
    report["call_graph"]["edges"].append(42)
    result = extract(
        report,
        source=SOURCE,
        producer_version="4.3.1",
        bom_components=CASES["rusi-rustsec-app.json"]["bom"],
        extra_components=CASES["rusi-rustsec-app.json"]["extra"],
    )
    assert result.status == STATUS_COMPLETED
    skipped = [
        c for c in result.caveats if c.kind == "record-skipped" and "edges" in c.detail
    ]
    assert skipped


def test_reconciler_behaviour_is_unchanged():
    """The name-based reconciliation the converter pinned, now owned by the
    adapter."""
    bom = [
        {"purl": "pkg:cargo/sqlx@0.6.2"},
        {"purl": "pkg:cargo/time@0.1.45"},
    ]
    index = build_bom_purl_index(bom)
    # the critical pin: an unversioned rusi external maps to the BOM's
    # versioned purl, and the BOM version wins over a rusi version
    assert reconcile_purl("pkg:cargo/sqlx", index) == "pkg:cargo/sqlx@0.6.2"
    assert reconcile_purl("pkg:cargo/sqlx@9.9.9", index) == "pkg:cargo/sqlx@0.6.2"
    assert reconcile_purl("pkg:cargo/time@0.1.45", index) == "pkg:cargo/time@0.1.45"
    # stdlib pseudo-crates are dropped unconditionally
    for pseudo in ("pkg:cargo/std", "pkg:cargo/fs", "pkg:cargo/core", "pkg:cargo/alloc"):
        assert reconcile_purl(pseudo, index) is None
    # an unmatched crate name cannot correspond to a BOM component
    assert reconcile_purl("pkg:cargo/serde", index) is None
    assert reconcile_purl("pkg:npm/express@4.22.2", index) is None
    assert reconcile_purl("not-a-purl", index) is None
    assert reconcile_purl("", index) is None
    assert reconcile_purl(None, index) is None


def test_reconciler_dash_underscore_normalization():
    """Cargo ``-`` in the manifest matches ``_`` in the module path, both
    directions."""
    idx = build_bom_purl_index(
        [{"purl": "pkg:cargo/vulnerable-web-app@0.1.0", "name": "vulnerable-web-app"}]
    )
    assert reconcile_purl("pkg:cargo/vulnerable_web_app@0.1.0", idx) == (
        "pkg:cargo/vulnerable-web-app@0.1.0"
    )
    idx2 = build_bom_purl_index([{"purl": "pkg:cargo/some_lib@1.0.0", "name": "some_lib"}])
    assert reconcile_purl("pkg:cargo/some-lib", idx2) == "pkg:cargo/some_lib@1.0.0"


def test_reconciler_is_case_insensitive_and_decodes_percent_encoding():
    idx = build_bom_purl_index([{"purl": "pkg:cargo/SQLx@0.6.2", "name": "SQLx"}])
    assert reconcile_purl("pkg:cargo/sqlx", idx) == "pkg:cargo/SQLx@0.6.2"
    idx2 = build_bom_purl_index([{"purl": "pkg:cargo/foo-bar@1.0.0"}])
    # decoding must not corrupt a plain name
    assert reconcile_purl("pkg:cargo/foo-bar", idx2) == "pkg:cargo/foo-bar@1.0.0"


def test_bom_index_ignores_non_cargo_components_and_holds_the_root():
    index = build_bom_purl_index(
        [{"purl": "pkg:npm/express@4.21.2"}, {"purl": "pkg:cargo/time@0.1.45"}],
        extra_components=[{"purl": "pkg:cargo/rustsec-app@0.1.0"}],
    )
    assert index["time"] == "pkg:cargo/time@0.1.45"
    assert index["rustsec-app"] == "pkg:cargo/rustsec-app@0.1.0"
    assert "express" not in index
