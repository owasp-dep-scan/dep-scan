"""Tests for the atom evidence adapter.

Covers the four cases every adapter must handle (an unknown major report
shape refused with the version named, a newer minor accepted with the schema
caveat, a truncated or malformed report that yields not-assessed and raises
nothing, and the budget and timeout markers the runner saw), plus the
contracts the reached sets depend on: the reached-counted purl set of the
records equals the purls the reachability engine's unique-flow walk yields
over the same slices, service attribution equals the positional tag walk per
flow, ids are byte-stable, a flow duplicated across split slice files is
counted once, and every record validates against the evidence schema.

Fixtures: the recorded atom 4 slices under ``test/data/atom4`` and the
trimmed pinned repotests recordings under ``tests/data/atom`` (see the README
next to them).
"""

import json
from collections import Counter
from pathlib import Path

import pytest

from analysis_lib.evidence import MAX_PATH_NODES, EvidenceLocation, adapters
from analysis_lib.evidence.adapters import gate_report_version
from analysis_lib.evidence.adapters.atom import extract
from analysis_lib.evidence.store import canonical_record
from analysis_lib.findings.schemas import validate
from analysis_lib.reachability import _flow_service_purls, _iter_unique_reachable_flows

ATOM4_DIR = Path(__file__).resolve().parents[3] / "test" / "data" / "atom4"
ATOM4_REACHABLES = ATOM4_DIR / "python-reachables.slices.json"
ATOM4_OPENAPI = ATOM4_DIR / "python-openapi.json"
DATA_DIR = Path(__file__).parent / "data" / "atom"
PINNED_REACHABLES = DATA_DIR / "java-reachables.slices.json"
PINNED_USAGES = DATA_DIR / "java-usages.slices.json"
PINNED_CALLSITES = DATA_DIR / "java-callsites.slices.json"
LATEST_REACHABLES = DATA_DIR / "python-reachables.slices.json"
LATEST_USAGES = DATA_DIR / "python-usages.slices.json"
LATEST_CALLSITES = DATA_DIR / "python-callsites.slices.json"


def _flows(path):
    """The flow objects of a reachables slice fixture."""
    with open(path, encoding="utf-8") as fp:
        return json.load(fp)


def _unique_flows(paths):
    """The flows the engine's unique-flow walk yields over the given files."""
    return list(_iter_unique_reachable_flows([str(p) for p in paths]))


def _reached_purls(records):
    """The reached-counted purls of a record set, per the engine counting rule."""
    return {
        purl
        for record in records
        if record.kind == "reached-flow" and record.polarity == "positive"
        for purl in record.subject.purls
    }


def _walk_purls(flows):
    """The purls a unique-flow walk yields, the engine-side of the equality."""
    return {purl for flow in flows for purl in flow.get("purls") or []}


def _purl_counts(records):
    """How many records carry each purl, the dedup-free count the engine keeps."""
    return Counter(
        purl
        for record in records
        if record.kind == "reached-flow" and record.polarity == "positive"
        for purl in record.subject.purls
    )


def _service_pairs(records):
    """(purls, service purls) per reached-flow record, for per-flow comparison."""
    return Counter(
        (
            tuple(sorted(record.subject.purls)),
            tuple(sorted((record.attributes or {}).get("servicePurls") or [])),
        )
        for record in records
        if record.kind == "reached-flow"
    )


def _flow_pairs(flows):
    """(purls, service purls) per flow object, the attribution the tag walk gives."""
    return Counter(
        (
            tuple(sorted(flow.get("purls") or [])),
            tuple(sorted(_flow_service_purls(flow))),
        )
        for flow in flows
    )


# --- reachables become reached-flow records -----------------------------


def test_reachables_become_reached_flow_records():
    """One reached-flow record per flow, with the shape-implied schema
    version and the producing slice file as the source."""
    result = extract([str(ATOM4_REACHABLES)], producer_version="4.0.2")
    assert result.status == adapters.STATUS_COMPLETED
    flows = _flows(ATOM4_REACHABLES)
    reached = [r for r in result.records if r.kind == "reached-flow"]
    assert len(reached) == len(flows)
    assert _purl_counts(reached) == Counter(
        purl for flow in flows for purl in flow.get("purls") or []
    )
    for record in reached:
        assert record.polarity == "positive"
        assert record.producer.name == "atom"
        assert record.producer.version == "4.0.2"
        assert record.producer.report_schema_version == "4"
        assert record.source == "python-reachables.slices.json"


def test_the_records_validate_against_the_evidence_schema():
    """Every record of a full adapter run, caveats and attributes included,
    validates against the served evidence schema."""
    result = extract(
        [str(PINNED_REACHABLES)],
        usages_files=[str(PINNED_USAGES)],
        callsites_files=[str(PINNED_CALLSITES)],
        producer_version="4.0.2",
    )
    assert result.records
    kinds = {record.kind for record in result.records}
    assert {"reached-flow", "usage", "callsite"} <= kinds
    for record in result.records:
        validate("depscan-evidence", record.to_dict())


def test_an_empty_reachables_array_is_completed_with_no_records(tmp_path):
    """A syntactically valid slice with zero flows says the producer found
    nothing; it is completed, not not-assessed."""
    empty = tmp_path / "python-reachables.slices.json"
    empty.write_text("[]", encoding="utf-8")
    result = extract([str(empty)])
    assert result.status == adapters.STATUS_COMPLETED
    assert result.records == []


# --- the reached sets ----------------------------------------------------


def test_reached_purls_equal_the_engine_walk_atom4():
    """The reached-counted set equals the purls of the unique-flow walk on
    the recorded atom 4 slices."""
    result = extract([str(ATOM4_REACHABLES)])
    assert _reached_purls(result.records) == _walk_purls(_unique_flows([ATOM4_REACHABLES]))


def test_reached_purls_equal_the_engine_walk_pinned_slice():
    """The same equality on the trimmed pinned repotests recording."""
    result = extract([str(PINNED_REACHABLES)])
    assert _reached_purls(result.records) == _walk_purls(_unique_flows([PINNED_REACHABLES]))
    assert _reached_purls(result.records)


def test_reached_purls_equal_the_engine_walk_current_release():
    """The same equality on the recording made with cdxgen master and atom
    4.0.3, the current release output the adapter must read."""
    result = extract([str(LATEST_REACHABLES)])
    assert result.status == adapters.STATUS_COMPLETED
    assert _reached_purls(result.records) == _walk_purls(_unique_flows([LATEST_REACHABLES]))
    assert len(_reached_purls(result.records)) == 6


def test_current_release_records_cover_every_role():
    """One record per flow, per purl-attributed callsite and per usage entry
    of the current-release recording, every record valid."""
    result = extract(
        [str(LATEST_REACHABLES)],
        usages_files=[str(LATEST_USAGES)],
        callsites_files=[str(LATEST_CALLSITES)],
    )
    assert result.status == adapters.STATUS_COMPLETED
    flows = _flows(LATEST_REACHABLES)
    with open(LATEST_CALLSITES, encoding="utf-8") as fp:
        callsites = json.load(fp)["callsites"]
    with open(LATEST_USAGES, encoding="utf-8") as fp:
        object_slices = json.load(fp)["objectSlices"]
    by_kind = Counter(record.kind for record in result.records)
    assert by_kind["reached-flow"] == len(flows)
    assert by_kind["callsite"] == len(callsites)
    assert by_kind["usage"] == len(object_slices)
    for record in result.records:
        validate("depscan-evidence", record.to_dict())
    callsite_records = [record for record in result.records if record.kind == "callsite"]
    with_purl = [record for record in callsite_records if record.subject.purls]
    assert len(with_purl) == sum(1 for entry in callsites if entry.get("purl"))
    flow_purls = {purl for flow in flows for purl in flow.get("purls") or []}
    callsite_purls = {purl for record in with_purl for purl in record.subject.purls}
    assert callsite_purls <= flow_purls | {
        str(entry.get("purl")) for entry in callsites if entry.get("purl")
    }


def test_current_release_producer_names_the_recorded_versions():
    """The records name the producing slice file as their source and carry the
    shape-implied report schema version; the versions recorded in the fixture
    README are the ones the tools printed."""
    result = extract([str(LATEST_REACHABLES)], producer_version="4.0.3")
    for record in result.records:
        assert record.producer.name == "atom"
        assert record.producer.version == "4.0.3"
        assert record.producer.report_schema_version == "4"
        assert record.source == "python-reachables.slices.json"


def test_reached_purl_counts_match_the_unique_flows():
    """Counts, not only sets, follow the engine's one-record-per-unique-flow
    rule, so the dedup-free counting keeps the same numbers."""
    for path in (ATOM4_REACHABLES, PINNED_REACHABLES):
        result = extract([str(path)])
        unique = _unique_flows([path])
        expected = Counter(purl for flow in unique for purl in flow.get("purls") or [])
        assert _purl_counts(result.records) == expected, path


def test_flow_nodes_become_the_witness_path():
    """The flow's nodes are the record's path, first node first, with the
    first node's position as the record's location."""
    result = extract([str(ATOM4_REACHABLES)])
    flows = _flows(ATOM4_REACHABLES)
    reached = [r for r in result.records if r.kind == "reached-flow"]
    by_purls = {tuple(record.subject.purls): record for record in reached}
    for flow in flows:
        record = by_purls[tuple(flow.get("purls") or [])]
        nodes = flow.get("flows") or []
        assert len(record.path or []) == len(nodes)
        if nodes:
            first = nodes[0]
            location = record.locations[0]
            assert location.file == first.get("parentFileName")
            assert location.line == first.get("lineNumber")
            assert location.method == first.get("parentMethodName")
            assert record.path is not None
            assert record.path[0].symbol == (first.get("fullName") or first.get("name"))


def test_long_paths_are_capped_with_a_caveat(tmp_path):
    """A flow with more witness nodes than the cap keeps the first nodes and
    carries the truncation caveat."""
    flow = {
        "purls": ["pkg:npm/longpath@1.0.0"],
        "flows": [
            {
                "id": i,
                "label": "CALL",
                "name": f"call{i}",
                "fullName": f"mod.call{i}",
                "parentFileName": f"src/mod{i}.py",
                "parentMethodName": "handle",
                "lineNumber": i,
                "tags": "",
            }
            for i in range(MAX_PATH_NODES + 10)
        ],
    }
    slice_file = tmp_path / "long-reachables.slices.json"
    slice_file.write_text(json.dumps([flow]), encoding="utf-8")
    result = extract([str(slice_file)])
    assert result.status == adapters.STATUS_COMPLETED
    record = result.records[0]
    assert record.path is not None and len(record.path) == MAX_PATH_NODES
    assert "path-truncated" in {c.kind for c in record.caveats}


# --- service attribution -------------------------------------------------


def test_service_attribution_matches_the_tag_walk_atom4():
    """Every fixture flow's service purls land on its record; the recorded
    atom 4 slices carry none."""
    result = extract([str(ATOM4_REACHABLES)])
    assert _service_pairs(result.records) == _flow_pairs(_flows(ATOM4_REACHABLES))


def test_service_attribution_matches_the_tag_walk_pinned_slice():
    """The same per-flow equality on the pinned recording, where one flow
    carries a service tag on a node that names no purl of its own."""
    result = extract([str(PINNED_REACHABLES)])
    flows = _flows(PINNED_REACHABLES)
    assert _service_pairs(result.records) == _flow_pairs(flows)
    # Guard against a vacuous all-empty comparison: the recording does carry
    # one flow whose purls the tag walk marks as services.
    assert any(_flow_service_purls(flow) for flow in flows)


def test_duplicate_flows_across_files_count_once(tmp_path):
    """A flow that appears in two slice files produces one record, attributed
    to the first file, and the reached counts stay at the unique-flow level."""
    flows = _flows(ATOM4_REACHABLES)
    first = tmp_path / "python-reachables.slices.json"
    second = tmp_path / "python-reachables_1.slices.json"
    first.write_text(json.dumps([flows[0], flows[1]]), encoding="utf-8")
    second.write_text(json.dumps([flows[0], flows[2]]), encoding="utf-8")
    result = extract([str(first), str(second)])
    reached = [r for r in result.records if r.kind == "reached-flow"]
    assert len(reached) == 3
    assert _purl_counts(reached) == Counter(
        purl for flow in (flows[0], flows[1], flows[2]) for purl in flow.get("purls") or []
    )
    duplicated = next(r for r in reached if r.subject.purls == flows[0].get("purls"))
    assert duplicated.source == "python-reachables.slices.json"


# --- stable ids ----------------------------------------------------------


def test_ids_are_byte_stable_across_runs():
    """Two runs over the same input build the same records byte for byte."""
    runs = []
    for _ in range(2):
        result = extract(
            [str(PINNED_REACHABLES)],
            usages_files=[str(PINNED_USAGES)],
            callsites_files=[str(PINNED_CALLSITES)],
        )
        runs.append([canonical_record(r) for r in result.records])
    assert runs[0] == runs[1]
    assert len(runs[0]) > 10


# --- the version gate ----------------------------------------------------


def test_atom2_wrapped_shape_is_refused_with_the_version_named(tmp_path):
    """The atom 2 shape wraps the flow objects in a top-level ``reachables``
    object; the adapter reads major 4 only and refuses with the version it
    saw."""
    flows = _flows(ATOM4_REACHABLES)
    wrapped = tmp_path / "python-reachables.slices.json"
    wrapped.write_text(json.dumps({"reachables": flows}), encoding="utf-8")
    result = extract([str(wrapped)])
    assert result.status == adapters.STATUS_NOT_ASSESSED
    assert result.records == []
    assert result.reason is not None
    assert "2" in result.reason
    assert "4" in result.reason


def test_version_gate_accepts_a_newer_minor_with_a_caveat():
    """The version gate the adapter applies: a newer minor of the supported
    major is accepted with the schema-minor caveat, the supported version is
    accepted cleanly, and a report that names no version is accepted with the
    schema-unknown caveat."""
    gate = gate_report_version("4.1", supported_major=4, known_minor=0)
    assert gate.accepted
    assert [c.kind for c in gate.caveats] == ["schema-minor"]
    gate = gate_report_version("4", supported_major=4, known_minor=0)
    assert gate.accepted
    assert gate.caveats == []
    gate = gate_report_version("", supported_major=4, known_minor=0)
    assert gate.accepted
    assert [c.kind for c in gate.caveats] == ["schema-unknown"]


def test_version_gate_refuses_an_unknown_major():
    """A different major is refused with the version it saw named."""
    gate = gate_report_version("5.0", supported_major=4, known_minor=0)
    assert not gate.accepted
    assert gate.reason is not None and "5.0" in gate.reason


# --- malformed and damaged reports ---------------------------------------


def test_truncated_reachables_give_not_assessed(tmp_path):
    """A slice cut off mid-flow is not-assessed with the file named, and
    raises nothing."""
    text = json.dumps(_flows(ATOM4_REACHABLES))
    truncated = tmp_path / "python-reachables.slices.json"
    truncated.write_text(text[: len(text) // 2], encoding="utf-8")
    result = extract([str(truncated)])
    assert result.status == adapters.STATUS_NOT_ASSESSED
    assert result.records == []
    assert result.reason is not None and "python-reachables.slices.json" in result.reason


def test_malformed_reachables_give_not_assessed(tmp_path):
    """Text that is not JSON at all is not-assessed, not zero records."""
    garbage = tmp_path / "python-reachables.slices.json"
    garbage.write_text("not json at all {", encoding="utf-8")
    result = extract([str(garbage)])
    assert result.status == adapters.STATUS_NOT_ASSESSED
    assert result.records == []


def test_one_damaged_file_fails_the_whole_result(tmp_path):
    """A truncated slice among readable ones keeps nothing back: the result
    says not-assessed rather than reporting the readable part as complete."""
    good = tmp_path / "python-reachables.slices.json"
    text = json.dumps(_flows(ATOM4_REACHABLES))
    truncated = tmp_path / "python-reachables_1.slices.json"
    good.write_text(text, encoding="utf-8")
    truncated.write_text(text[: len(text) // 2], encoding="utf-8")
    result = extract([str(good), str(truncated)])
    assert result.status == adapters.STATUS_NOT_ASSESSED
    assert result.records == []
    assert result.reason is not None and "python-reachables_1.slices.json" in result.reason


def test_a_non_array_reachables_file_is_not_assessed(tmp_path):
    """A file that is neither a bare array nor the atom 2 wrapped shape is
    refused with what it starts with named."""
    other = tmp_path / "python-reachables.slices.json"
    other.write_text(json.dumps({"objectSlices": []}), encoding="utf-8")
    result = extract([str(other)])
    assert result.status == adapters.STATUS_NOT_ASSESSED
    assert result.reason is not None and "objectSlices" in result.reason


def test_a_missing_reachables_file_is_not_assessed(tmp_path):
    result = extract([str(tmp_path / "absent-reachables.slices.json")])
    assert result.status == adapters.STATUS_NOT_ASSESSED
    assert result.records == []


def test_no_reports_given_is_not_assessed():
    result = extract([])
    assert result.status == adapters.STATUS_NOT_ASSESSED
    assert result.records == []


def test_non_dict_flow_entries_become_record_skipped(tmp_path):
    """An array element that is not a flow object cannot become a record; it
    becomes a caveat, and the flow objects around it still do."""
    flows = _flows(ATOM4_REACHABLES)
    slice_file = tmp_path / "python-reachables.slices.json"
    slice_file.write_text(json.dumps([flows[0], "not a flow", flows[1]]), encoding="utf-8")
    result = extract([str(slice_file)])
    assert result.status == adapters.STATUS_COMPLETED
    assert len([r for r in result.records if r.kind == "reached-flow"]) == 2
    assert any(c.kind == "record-skipped" for c in result.caveats)


@pytest.mark.parametrize("role", ["reachables", "usages", "callsites", "openapi"])
def test_a_damaged_report_in_any_role_fails_the_result(tmp_path, role):
    """A damaged report in any input role yields not-assessed; the analysis
    is never reported as complete with a part of its input unread."""
    good_reachables = tmp_path / "python-reachables.slices.json"
    good_reachables.write_text(json.dumps(_flows(ATOM4_REACHABLES)), encoding="utf-8")
    damaged = tmp_path / f"{role}-damaged.json"
    damaged.write_text("{not json", encoding="utf-8")
    if role == "reachables":
        result = extract([str(damaged)])
    elif role == "usages":
        result = extract([str(good_reachables)], usages_files=[str(damaged)])
    elif role == "callsites":
        result = extract([str(good_reachables)], callsites_files=[str(damaged)])
    else:
        result = extract([str(good_reachables)], openapi_files=[str(damaged)])
    assert result.status == adapters.STATUS_NOT_ASSESSED
    assert result.records == []
    assert result.reason is not None
    assert role in result.reason or str(damaged.name) in result.reason


def test_a_usages_file_of_the_wrong_shape_is_not_assessed(tmp_path):
    """A usages report that is not the objectSlices shape is refused with the
    shape named, not read as an empty usages list."""
    wrong = tmp_path / "python-usages.slices.json"
    wrong.write_text(json.dumps([{"fileName": "a.py"}]), encoding="utf-8")
    good = tmp_path / "python-reachables.slices.json"
    good.write_text(json.dumps(_flows(ATOM4_REACHABLES)), encoding="utf-8")
    result = extract([str(good)], usages_files=[str(wrong)])
    assert result.status == adapters.STATUS_NOT_ASSESSED
    assert result.reason is not None and "objectSlices" in result.reason


# --- budget and timeout markers ------------------------------------------


def test_budget_and_timeout_markers_carry_through(tmp_path):
    """The parse report the runner saw and the exit-124 timeouts become
    caveats in the producer caveats and on every record."""
    parse_report = tmp_path / "parse-report.json"
    parse_report.write_text(
        json.dumps(
            {
                "atomVersion": "4.0.2",
                "language": "java",
                "inputRoot": "/project",
                "total": 2,
                "counts": {"byOutcome": {"partial": 1, "unparsed": 1}},
                "records": [
                    {
                        "frontend": "java",
                        "file": "src/A.java",
                        "outcome": "unparsed",
                        "stage": "create-cpg",
                        "message": "syntax",
                    },
                    {
                        "frontend": "java",
                        "file": "src/B.java",
                        "outcome": "partial",
                        "stage": "post-processing",
                        "message": "time",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    timeout_reason = "atom did not finish within its timeout and was stopped"
    result = extract(
        [str(ATOM4_REACHABLES)],
        parse_reports=[str(parse_report)],
        timeout_reasons=[timeout_reason],
    )
    assert result.status == adapters.STATUS_COMPLETED
    kinds = sorted(c.kind for c in result.caveats)
    assert kinds == ["budget", "timeout"]
    budget = next(c for c in result.caveats if c.kind == "budget")
    assert "parse-report.json" in budget.detail
    assert "2" in budget.detail
    timeout = next(c for c in result.caveats if c.kind == "timeout")
    assert timeout.detail == timeout_reason
    assert result.records
    for record in result.records:
        record_kinds = {c.kind for c in record.caveats}
        assert {"budget", "timeout"} <= record_kinds


def test_an_unreadable_parse_report_still_caveats(tmp_path):
    """A parse report path that cannot be read still becomes a caveat that
    names the file; it raises nothing."""
    result = extract(
        [str(ATOM4_REACHABLES)],
        parse_reports=[str(tmp_path / "absent-parse-report.json")],
    )
    assert result.status == adapters.STATUS_COMPLETED
    assert [c.kind for c in result.caveats] == ["budget"]
    assert "absent-parse-report.json" in result.caveats[0].detail


def test_a_clean_parse_report_adds_no_caveat(tmp_path):
    """A parse report with no failed files says nothing; the run was whole."""
    parse_report = tmp_path / "parse-report.json"
    parse_report.write_text(
        json.dumps({"total": 0, "counts": {"byOutcome": {}, "byFrontend": {}}, "records": []}),
        encoding="utf-8",
    )
    result = extract([str(ATOM4_REACHABLES)], parse_reports=[str(parse_report)])
    assert result.status == adapters.STATUS_COMPLETED
    assert result.caveats == []


# --- usages slices -------------------------------------------------------


def test_usages_slices_become_usage_records():
    """One usage record per objectSlice, with no purls, the slice's own
    location, and the usage entries' target objects as the witness path."""
    with open(PINNED_USAGES, encoding="utf-8") as fp:
        object_slices = json.load(fp)["objectSlices"]
    result = extract([str(PINNED_REACHABLES)], usages_files=[str(PINNED_USAGES)])
    usages = [r for r in result.records if r.kind == "usage"]
    assert len(usages) == len(object_slices)
    for record in usages:
        assert record.subject.purls == []
        assert record.polarity == "positive"
        assert record.producer.report_schema_version == "4"
    first = object_slices[0]
    record = usages[0]
    assert record.locations[0].file == first.get("fileName")
    assert record.locations[0].line == first.get("lineNumber")
    assert record.locations[0].method == first.get("fullName")
    assert len(record.path or []) == min(len(first.get("usages") or []), MAX_PATH_NODES)
    first_target = first["usages"][0]["targetObj"]
    assert record.path is not None
    assert record.path[0].symbol == first_target.get("name")
    assert record.path[0].line == first_target.get("lineNumber")
    # Entries with no usages become records without a path, not skips.
    assert any(record.path is None for record in usages)


# --- callsites slices ----------------------------------------------------


def test_callsites_slices_become_callsite_records():
    """One callsite record per entry, with the entry's purl as the subject and
    the kind and via facts kept in attributes."""
    with open(PINNED_CALLSITES, encoding="utf-8") as fp:
        callsites = json.load(fp)["callsites"]
    result = extract([str(PINNED_REACHABLES)], callsites_files=[str(PINNED_CALLSITES)])
    records = [r for r in result.records if r.kind == "callsite"]
    assert len(records) == len(callsites)
    for record, entry in zip(records, callsites):
        assert record.subject.purls == ([entry["purl"]] if entry.get("purl") else [])
        assert record.locations[0].file == entry.get("file")
        assert record.locations[0].line == entry.get("line")
        assert (record.attributes or {}).get("kind") == entry.get("kind")
        assert (record.attributes or {}).get("via") == entry.get("via")
    annotated = next(r for r in records if (r.attributes or {}).get("kind") == "annotation")
    assert annotated.kind == "callsite"


# --- OpenAPI x-atom-usages -----------------------------------------------


def test_openapi_usages_become_entry_point_records():
    """One entry-point record per path object that carries the extension, with
    no purls, the files and lines of the extension as locations, and the
    endpoint named in attributes."""
    result = extract([str(ATOM4_REACHABLES)], openapi_files=[str(ATOM4_OPENAPI)])
    entries = [r for r in result.records if r.kind == "entry-point"]
    assert len(entries) == 8
    for record in entries:
        assert record.subject.purls == []
        assert record.source == "python-openapi.json"
        assert record.attributes is not None and record.attributes.get("endpoint")
    locations = {(loc.file, loc.line) for record in entries for loc in record.locations}
    assert ("packages/server-lib/src/server_lib/simple.py", 433) in locations
    assert ("packages/analysis-lib/src/analysis_lib/output.py", 985) in locations
    endpoints = set()
    for record in entries:
        attributes = record.attributes or {}
        endpoints.add(attributes["endpoint"])
    assert "/analysis_lib/output" in endpoints
    assert "/" in endpoints


def test_nested_x_atom_usages_name_the_method(tmp_path):
    """The Ruby and Scala shape nests the extension inside a method object;
    the record names the endpoint and the method it came from."""
    spec = {
        "openapi": "3.1.0",
        "paths": {
            "/widgets": {
                "get": {"responses": {}},
                "post": {
                    "responses": {},
                    "x-atom-usages": {"call": {"app/widgets.rb": [14]}},
                },
            }
        },
    }
    spec_file = tmp_path / "openapi.json"
    spec_file.write_text(json.dumps(spec), encoding="utf-8")
    result = extract([], openapi_files=[str(spec_file)])
    entries = [r for r in result.records if r.kind == "entry-point"]
    assert len(entries) == 1
    assert entries[0].attributes == {"endpoint": "/widgets", "method": "post"}
    assert entries[0].locations == [EvidenceLocation(file="app/widgets.rb", line=14)]
    assert entries[0].subject.purls == []


# --- producer version ----------------------------------------------------


def test_producer_version_defaults_to_unknown():
    result = extract([str(ATOM4_REACHABLES)])
    assert result.records
    assert all(r.producer.version == "unknown" for r in result.records)
