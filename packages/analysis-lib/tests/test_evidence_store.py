"""Tests for the evidence store and the shared adapter plumbing.

The store is the byte-level contract of ``evidence.jsonl`` and
``evidence.index.json``: same records in, same bytes out, ids stable across
builds, reads streaming one record at a time. The adapter helpers at the
bottom pin the version gate, the witness path cap and the record builder the
per-producer adapters share.
"""

import hashlib
import json
from typing import Any, Dict, List

import pytest

from analysis_lib.evidence import (
    EVIDENCE_SCHEMA_VERSION,
    Evidence,
    EvidenceCaveat,
    EvidenceLocation,
    EvidencePathNode,
    EvidenceProducer,
    MAX_PATH_NODES,
    record_id,
)
from analysis_lib.evidence import adapters
from analysis_lib.evidence import store

FINDING_ID = "dsf1:" + "a" * 64


def _record(discriminator: str, **overrides: Any) -> Evidence:
    """One reached-flow record whose identity is steered by the discriminator."""
    kwargs: Dict[str, Any] = {
        "source": "python-reachables.slices.json",
        "producer": EvidenceProducer(name="atom", version="4.0.2", report_schema_version="4"),
        "kind": "reached-flow",
        "purls": ["pkg:pypi/requests@2.32.1"],
        "locations": [EvidenceLocation(file="src/app/main.py", line=10, method="handle")],
        "discriminator": discriminator,
    }
    kwargs.update(overrides)
    return adapters.build_record(**kwargs)


# --- ids -------------------------------------------------------------------------


def test_ids_are_stable_across_builds():
    first = _record("flow-1").id
    second = _record("flow-1").id
    assert first == second
    assert first.startswith("ev-")


def test_a_different_discriminator_changes_the_id():
    assert _record("flow-1").id != _record("flow-2").id


def test_ids_use_comparable_purls():
    """Qualifier- and case-spelled purls that compare equal get one id."""
    plain = _record("flow-1", purls=["pkg:nuget/Newtonsoft.Json@13.0.3"]).id
    qualified = _record("flow-1", purls=["pkg:nuget/newtonsoft.json@13.0.3?a=1#x"]).id
    assert plain == qualified


def test_record_id_is_the_documented_digest():
    """The id is ev- plus the first 16 hex digits of the SHA-256 over the
    canonical JSON of the documented array, so other implementations can
    reproduce it."""
    payload = json.dumps(
        [
            EVIDENCE_SCHEMA_VERSION,
            "atom",
            "reached-flow",
            ["pkg:pypi/requests@2.32.1"],
            ["src/app/main.py", 10, "handle"],
            "flow-1",
        ],
        sort_keys=True,
        separators=(",", ":"),
    )
    expected = "ev-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
    assert (
        record_id(
            "atom",
            "reached-flow",
            ["pkg:pypi/requests@2.32.1"],
            EvidenceLocation(file="src/app/main.py", line=10, method="handle"),
            "flow-1",
        )
        == expected
    )


def test_record_id_without_locations_encodes_an_empty_location():
    with_location = record_id(
        "atom",
        "reached-flow",
        ["pkg:pypi/requests@2.32.1"],
        EvidenceLocation(file="src/app/main.py"),
        "flow-1",
    )
    without_location = record_id(
        "atom", "reached-flow", ["pkg:pypi/requests@2.32.1"], None, "flow-1"
    )
    assert with_location != without_location


# --- the store -------------------------------------------------------------------


def test_a_store_written_twice_is_byte_identical_and_sorted(tmp_path):
    records = [_record(name) for name in ("zeta", "alpha", "mid")]
    first = tmp_path / "first.jsonl"
    second = tmp_path / "second.jsonl"
    assert store.write(str(first), records) == 3
    store.write(str(second), records)
    assert first.read_bytes() == second.read_bytes()
    read_back = store.read(str(first))
    ids = [record.id for record in read_back]
    assert ids == sorted(ids)
    by_id = {record.id: record for record in records}
    for record in read_back:
        assert record == by_id[record.id]


def test_every_written_line_is_the_canonical_form_of_its_record(tmp_path):
    path = tmp_path / "evidence.jsonl"
    store.write(str(path), [_record("flow-1")])
    line = json.loads(path.read_text(encoding="utf-8"))
    assert (
        path.read_text(encoding="utf-8")
        == json.dumps(line, sort_keys=True, separators=(",", ":")) + "\n"
    )
    assert line["schemaVersion"] == EVIDENCE_SCHEMA_VERSION


def test_exact_duplicates_collapse(tmp_path):
    path = tmp_path / "evidence.jsonl"
    record = _record("flow-1")
    assert store.write(str(path), [record, record]) == 1
    assert len(store.read(str(path))) == 1


def test_a_colliding_truncated_id_gets_a_deterministic_suffix(tmp_path):
    """Two distinct records whose 16-hex ids truncate to the same value keep
    both: the store appends -2 to the loser, chosen by canonical-JSON order,
    so a rerun suffixes the same record."""
    one = _record("flow-1", attributes={"order": "first"})
    two = _record("flow-1", attributes={"order": "second"})
    assert one.id == two.id, "the test needs two records that truncate alike"

    path = tmp_path / "evidence.jsonl"
    store.write(str(path), [two, one])
    read_back = store.read(str(path))
    assert len(read_back) == 2
    assert {record.id for record in read_back} == {one.id, one.id + "-2"}
    loser = next(record for record in read_back if record.id.endswith("-2"))
    loser_document = loser.to_dict()
    winner_document = next(
        record.to_dict() for record in read_back if not record.id.endswith("-2")
    )
    assert json.dumps(loser_document, sort_keys=True, separators=(",", ":")) > json.dumps(
        winner_document, sort_keys=True, separators=(",", ":")
    ), "the record that sorts later canonically takes the suffix"

    again = tmp_path / "again.jsonl"
    store.write(str(again), [one, two])
    assert again.read_bytes() == path.read_bytes()


def test_copies_that_differ_only_in_caveats_merge_their_caveats(tmp_path):
    """The same record built by two runs, one of which hit a timeout, is one
    record carrying the timeout: the caveat is never lost to whichever copy
    the store saw last, and the write is the same whatever the order."""
    timeout = EvidenceCaveat(kind="timeout", detail="atom was stopped")
    budget = EvidenceCaveat(kind="budget", detail="two files parsed only partly")
    plain = _record("flow-1")
    timed_out = _record("flow-1", caveats=[timeout])
    both = _record("flow-1", caveats=[budget, timeout])
    assert plain.id == timed_out.id == both.id

    path = tmp_path / "evidence.jsonl"
    assert store.write(str(path), [timed_out, plain, both]) == 1
    (merged,) = store.read(str(path))
    assert merged.id == plain.id, "a caveat merge never suffixes the id"
    assert {(c.kind, c.detail) for c in merged.caveats} == {
        ("timeout", "atom was stopped"),
        ("budget", "two files parsed only partly"),
    }
    again = tmp_path / "again.jsonl"
    store.write(str(again), [both, plain, timed_out])
    assert again.read_bytes() == path.read_bytes()


def test_a_caveat_merge_keeps_the_collision_rule_for_other_differences(tmp_path):
    """Records that share an id and differ in more than caveats still keep
    both, the later one suffixed, with each copy's caveats merged first."""
    timeout = EvidenceCaveat(kind="timeout", detail="atom was stopped")
    first = _record("flow-1", attributes={"order": "first"})
    first_timed_out = _record("flow-1", attributes={"order": "first"}, caveats=[timeout])
    second = _record("flow-1", attributes={"order": "second"})
    path = tmp_path / "evidence.jsonl"
    assert store.write(str(path), [first, second, first_timed_out]) == 2
    by_order = {(record.attributes or {})["order"]: record for record in store.read(str(path))}
    assert by_order["first"].caveats == [timeout]
    assert by_order["second"].caveats == []
    assert {by_order["first"].id, by_order["second"].id} == {first.id, first.id + "-2"}


def test_merge_keeps_earlier_records_and_adds_new_ones():
    base = [_record("flow-1")]
    merged = store.merge(base, [base[0], _record("flow-2")])
    assert len(merged) == 3
    finalized = store.finalize(merged)
    assert sorted(record.id for record in finalized) == sorted(
        [_record("flow-1").id, _record("flow-2").id]
    )


def test_an_empty_store_is_written_so_the_layout_stays_uniform(tmp_path):
    path = tmp_path / "evidence.jsonl"
    assert store.write(str(path), []) == 0
    assert path.read_bytes() == b""
    assert store.read(str(path)) == []


def test_an_interrupted_write_leaves_the_previous_store_intact(tmp_path, monkeypatch):
    path = tmp_path / "evidence.jsonl"
    store.write(str(path), [_record("flow-1")])
    original = path.read_bytes()

    def explode(*args: Any, **kwargs: Any) -> str:
        raise OSError("disk full")

    monkeypatch.setattr(store.json, "dumps", explode)
    with pytest.raises(OSError):
        store.write(str(path), [_record("flow-2")])
    assert path.read_bytes() == original
    assert list(tmp_path.iterdir()) == [path], "no temporary file is left behind"


def test_streaming_read_does_not_materialize_the_file(tmp_path, monkeypatch):
    records = [_record(f"flow-{index}") for index in range(2000)]
    path = tmp_path / "large.jsonl"
    store.write(str(path), records)

    class CountingEvidence:
        calls = 0

        @classmethod
        def from_dict(cls, data: Dict[str, Any]) -> Evidence:
            cls.calls += 1
            return Evidence.from_dict(data)

    monkeypatch.setattr(store, "Evidence", CountingEvidence)
    streamed = store.stream(str(path))
    assert iter(streamed) is streamed, "the stream is a lazy iterator, not a list"
    first = next(streamed)
    assert CountingEvidence.calls == 1, "one yielded record parsed one line"
    # The file holds the records in id order, whatever order they were given.
    expected = store.finalize(records)
    assert first == expected[0]

    monkeypatch.setattr(store, "Evidence", Evidence)
    assert store.read(str(path)) == expected


# --- the index -------------------------------------------------------------------


def _index_records() -> List[Evidence]:
    return [
        _record("flow-1", purls=["pkg:npm/lodash@4.17.21"]),
        _record("flow-2", purls=["pkg:nuget/Newtonsoft.Json@13.0.3"]),
        _record("flow-3", purls=["pkg:npm/lodash@4.17.21", "pkg:pypi/requests@2.32.1"]),
    ]


def test_the_index_groups_records_by_component_and_finding(tmp_path):
    flow1 = _record("flow-1", purls=["pkg:npm/lodash@4.17.21"])
    flow2 = _record("flow-2", purls=["pkg:nuget/Newtonsoft.Json@13.0.3"])
    flow3 = _record("flow-3", purls=["pkg:npm/lodash@4.17.21", "pkg:pypi/requests@2.32.1"])
    findings = [
        {
            "id": FINDING_ID,
            "components": ["pkg:npm/lodash@4.17.21"],
        },
        {
            "id": "dsf1:" + "b" * 64,
            # Qualifiers and subpaths must not hide the component.
            "components": ["pkg:npm/semver@7.6.0?arch=x86#subpath"],
        },
        {
            "id": "dsf1:" + "c" * 64,
            "components": ["pkg:golang/nothing/matches@1.0.0"],
        },
    ]
    index = store.build_index([flow1, flow2, flow3], findings)
    assert index["schemaVersion"] == "1"
    assert index["byComponent"] == {
        "pkg:npm/lodash@4.17.21": sorted([flow1.id, flow3.id]),
        "pkg:nuget/newtonsoft.json@13.0.3": [flow2.id],
        "pkg:pypi/requests@2.32.1": [flow3.id],
    }
    assert index["byFinding"] == {
        f"{FINDING_ID} pkg:npm/lodash@4.17.21": sorted([flow1.id, flow3.id]),
        f"dsf1:{'b' * 64} pkg:npm/semver@7.6.0?arch=x86#subpath": [],
        f"dsf1:{'c' * 64} pkg:golang/nothing/matches@1.0.0": [],
    }

    path = tmp_path / "evidence.index.json"
    store.write_index(str(path), index)
    written = json.loads(path.read_text(encoding="utf-8"))
    assert written == index


def test_two_versions_of_one_package_keep_separate_index_entries():
    """Two findings share a fingerprint when one advisory hits two versions
    of a package, because the fingerprint leaves the version out so
    suppressions survive upgrades. Each version must keep its own index
    entry, keyed by the finding id and the finding's first component purl,
    joining only that version's records."""
    flow56 = _record("flow-56", purls=["pkg:golang/golang.org/x/crypto@v0.56.0"])
    flow57 = _record("flow-57", purls=["pkg:golang/golang.org/x/crypto@v0.57.0"])
    findings = [
        {"id": FINDING_ID, "components": ["pkg:golang/golang.org/x/crypto@v0.56.0"]},
        {"id": FINDING_ID, "components": ["pkg:golang/golang.org/x/crypto@v0.57.0"]},
    ]

    index = store.build_index([flow56, flow57], findings)

    assert index["byFinding"] == {
        f"{FINDING_ID} pkg:golang/golang.org/x/crypto@v0.56.0": [flow56.id],
        f"{FINDING_ID} pkg:golang/golang.org/x/crypto@v0.57.0": [flow57.id],
    }, "two versions of one package must not share one entry"


def test_an_index_written_twice_is_byte_identical(tmp_path):
    findings = [{"id": FINDING_ID, "components": ["pkg:npm/lodash@4.17.21"]}]
    index = store.build_index(_index_records(), findings)
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    store.write_index(str(first), index)
    store.write_index(str(second), index)
    assert first.read_bytes() == second.read_bytes()
    document = json.loads(first.read_text(encoding="utf-8"))
    assert list(document) == sorted(document), "index keys are written sorted"


def test_an_index_write_survives_a_finding_without_components():
    findings = [{"id": FINDING_ID}]
    index = store.build_index(_index_records(), findings)
    assert index["byFinding"] == {FINDING_ID: []}


# --- the shared adapter plumbing --------------------------------------------------


def test_the_version_gate_refuses_an_unknown_major_and_names_the_version_seen():
    gate = adapters.gate_report_version("6.1.0", supported_major=5, known_minor=1)
    assert not gate.accepted
    assert gate.reason is not None and "6.1.0" in gate.reason
    assert gate.caveats == []


def test_the_version_gate_accepts_a_newer_minor_with_a_schema_minor_caveat():
    gate = adapters.gate_report_version("5.9.0", supported_major=5, known_minor=1)
    assert gate.accepted
    assert [caveat.kind for caveat in gate.caveats] == ["schema-minor"]
    assert "5.9.0" in gate.caveats[0].detail


def test_the_version_gate_accepts_the_known_version_without_caveats():
    gate = adapters.gate_report_version("5.1.0", supported_major=5, known_minor=1)
    assert gate.accepted
    assert gate.reason is None
    assert gate.caveats == []


def test_the_version_gate_accepts_a_report_that_names_no_version():
    for unnamed in (None, "", "  "):
        gate = adapters.gate_report_version(unnamed, supported_major=5, known_minor=1)
        assert gate.accepted, unnamed
        assert [caveat.kind for caveat in gate.caveats] == ["schema-unknown"]


def test_the_version_gate_refuses_a_version_without_a_numeric_major():
    """A version is named but its major cannot be read, so nothing says the
    report is one the adapter can read: it is refused, naming what was seen."""
    for unreadable in ("not-a-version", "v6", "latest"):
        gate = adapters.gate_report_version(unreadable, supported_major=5, known_minor=1)
        assert not gate.accepted, unreadable
        assert gate.reason and unreadable in gate.reason


def test_not_assessed_carries_a_reason_and_no_records():
    result = adapters.not_assessed("the golem report was truncated")
    assert result.status == "not-assessed"
    assert result.reason == "the golem report was truncated"
    assert result.records == []


def test_cap_path_keeps_the_first_nodes_and_flags_the_rest():
    nodes = [
        EvidencePathNode(file=f"src/frame_{index}.py", line=index + 1)
        for index in range(MAX_PATH_NODES + 10)
    ]
    capped, caveat = adapters.cap_path(nodes)
    assert len(capped) == MAX_PATH_NODES
    assert capped == nodes[:MAX_PATH_NODES]
    assert caveat is not None and caveat.kind == "path-truncated"

    exact, caveat = adapters.cap_path(nodes[:MAX_PATH_NODES])
    assert len(exact) == MAX_PATH_NODES
    assert caveat is None


def test_build_record_applies_the_path_cap_and_records_the_caveat():
    nodes = [
        EvidencePathNode(file=f"src/frame_{index}.py", line=index + 1)
        for index in range(MAX_PATH_NODES + 1)
    ]
    record = _record("flow-1", path=nodes)
    assert record.path is not None and len(record.path) == MAX_PATH_NODES
    assert record.caveats[0].kind == "path-truncated"


def test_build_record_omits_unset_optional_fields():
    record = _record("flow-1")
    document = record.to_dict()
    for absent in ("path", "confidence", "attributes", "componentRef"):
        assert absent not in document
    assert document["caveats"] == []


def test_add_caveat_does_not_duplicate_the_same_caveat():
    record = _record("flow-1")
    adapters.add_caveat(record, "budget", "the tool stopped at its slice budget")
    adapters.add_caveat(record, "budget", "the tool stopped at its slice budget")
    assert record.caveats == [
        EvidenceCaveat(kind="budget", detail="the tool stopped at its slice budget")
    ]


def test_the_content_discriminator_hashes_the_object_it_was_given():
    obj = {"purls": ["pkg:npm/lodash@4.17.21"], "nodes": [{"file": "a.js", "line": 3}]}
    expected = hashlib.md5(
        json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    reordered = {"nodes": [{"line": 3, "file": "a.js"}], "purls": ["pkg:npm/lodash@4.17.21"]}
    assert adapters.content_discriminator(obj) == expected
    assert adapters.content_discriminator(reordered) == expected
