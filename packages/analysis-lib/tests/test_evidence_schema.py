"""Tests for the dep-scan evidence schema, its examples and its model.

The schema is the contract for every line of ``evidence.jsonl``; the
``Evidence`` dataclasses in ``analysis_lib.evidence`` mirror it, and the walk
test keeps the two from drifting apart the way the finding schema and model
are kept in step. The example records embedded in the schema are the three
producer shapes the evidence store was designed around: a blint presence
record, a cdxgen occurrence record and a tracebom runtime-trace record.
"""

from dataclasses import fields
from typing import Any, Dict, List

import pytest
from jsonschema import Draft202012Validator

from analysis_lib.evidence import (
    CAVEAT_KINDS,
    EVIDENCE_SCHEMA_VERSION,
    KINDS,
    MAX_PATH_NODES,
    POLARITIES,
    Evidence,
    EvidenceCaveat,
    EvidenceLocation,
    EvidencePathNode,
    EvidenceProducer,
    EvidenceSubject,
)
from analysis_lib.findings.schemas import load_schema, schema_names, validate

SCHEMA_NAME = "depscan-evidence"
ID_PATTERN = r"^ev-[0-9a-f]{16}(-[0-9]+)?$"


def _schema() -> Dict[str, Any]:
    return load_schema(SCHEMA_NAME)


def _example_record() -> Dict[str, Any]:
    """A minimal valid record the rejection tests mutate."""
    return {
        "schemaVersion": "1",
        "id": "ev-0123456789abcdef",
        "producer": {"name": "atom", "version": "4.0.2", "reportSchemaVersion": "4"},
        "kind": "reached-flow",
        "polarity": "positive",
        "subject": {"purls": ["pkg:pypi/requests@2.32.1"]},
        "locations": [{"file": "src/app/main.py", "line": 10, "method": "handle"}],
        "caveats": [],
        "source": "python-reachables.slices.json",
    }


def _rejects(document: Dict[str, Any], *fragments: str) -> None:
    with pytest.raises(ValueError) as excinfo:
        validate(SCHEMA_NAME, document)
    for fragment in fragments:
        assert fragment in str(excinfo.value), (
            f"expected {fragment!r} in the error, got: {excinfo.value}"
        )


# --- serving and metadata ---------------------------------------------------------


def test_the_schema_is_served_by_name_and_alias():
    assert load_schema(SCHEMA_NAME) == load_schema("evidence")
    schema = _schema()
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["$id"] == "urn:owasp:depscan:schema:evidence:1"
    assert schema["additionalProperties"] is False


def test_the_listing_names_the_schema_next_to_the_manifest():
    names = schema_names()
    assert "depscan-evidence" in names
    assert names.index("depscan-evidence") == names.index("depscan-manifest") + 1


def test_the_schema_is_valid_2020_12():
    Draft202012Validator.check_schema(_schema())


def test_every_property_has_a_description():
    schema = _schema()
    for name, prop in schema["properties"].items():
        assert prop.get("description"), f"property {name} has no description"
    for def_name, definition in schema["$defs"].items():
        for name, prop in definition["properties"].items():
            assert prop.get("description"), f"$defs/{def_name} property {name} has no description"


# --- the example records ----------------------------------------------------------


def test_the_schema_carries_three_example_records():
    examples = _schema()["examples"]
    assert len(examples) == 3
    producers = [example["producer"]["name"] for example in examples]
    assert producers == ["blint", "cdxgen", "tracebom"]


@pytest.mark.parametrize(
    "index",
    range(3),
    ids=["blint-presence", "cdxgen-occurrence", "tracebom-runtime-trace"],
)
def test_example_records_validate(index):
    example = _schema()["examples"][index]
    validate(SCHEMA_NAME, example)
    assert example["schemaVersion"] == EVIDENCE_SCHEMA_VERSION


@pytest.mark.parametrize(
    "index",
    range(3),
    ids=["blint-presence", "cdxgen-occurrence", "tracebom-runtime-trace"],
)
def test_example_records_round_trip_through_the_model(index):
    example = _schema()["examples"][index]
    assert Evidence.from_dict(example).to_dict() == example


def test_the_cdxgen_example_carries_a_component_ref():
    example = _schema()["examples"][1]
    assert example["kind"] == "occurrence"
    assert example["subject"]["componentRef"]


# --- what the schema accepts ------------------------------------------------------


def _path_nodes(count: int) -> List[Dict[str, Any]]:
    return [
        {"file": f"src/frame_{index}.py", "line": index + 1, "symbol": f"sym_{index}"}
        for index in range(count)
    ]


def test_a_path_at_the_cap_validates():
    document = _example_record()
    document["path"] = _path_nodes(MAX_PATH_NODES)
    validate(SCHEMA_NAME, document)


def test_a_path_over_the_cap_is_rejected():
    document = _example_record()
    document["path"] = _path_nodes(MAX_PATH_NODES + 1)
    _rejects(document, str(MAX_PATH_NODES), "too long")


def test_a_record_with_caveats_validates():
    document = _example_record()
    document["caveats"] = [
        {"kind": "schema-minor", "detail": "the report names schema 5.9.0; known is 5.1"},
        {"kind": "path-truncated", "detail": "kept the first 64 of 90 witness nodes"},
    ]
    validate(SCHEMA_NAME, document)


def test_a_location_outside_root_caveat_validates():
    document = _example_record()
    document["caveats"] = [
        {
            "kind": "location-outside-root",
            "detail": "1 file path(s) the producer named lie outside the source root",
        }
    ]
    validate(SCHEMA_NAME, document)
    assert Evidence.from_dict(document).caveats[0].kind == "location-outside-root"


def test_a_suffixed_id_with_caveats_validates():
    document = _example_record()
    document["id"] = "ev-fedcba9876543210-2"
    document["caveats"] = [{"kind": "coverage-gap", "detail": "no usages slices were given"}]
    validate(SCHEMA_NAME, document)


# --- what the schema rejects ------------------------------------------------------


def test_unknown_fields_are_rejected_at_every_level():
    document = _example_record()
    document["notes"] = "an unknown field"
    _rejects(document, "notes", "Additional properties")
    document = _example_record()
    document["subject"]["oops"] = True
    _rejects(document, "oops", "Additional properties")
    document = _example_record()
    document["producer"]["oops"] = True
    _rejects(document, "oops", "Additional properties")
    document = _example_record()
    document["locations"][0]["oops"] = True
    _rejects(document, "oops", "Additional properties")
    document = _example_record()
    document["path"] = [{"file": "a.py", "oops": True}]
    _rejects(document, "oops", "Additional properties")
    document = _example_record()
    document["caveats"] = [{"kind": "budget", "detail": "d", "oops": True}]
    _rejects(document, "oops", "Additional properties")


def test_an_unknown_kind_is_rejected():
    document = _example_record()
    document["kind"] = "vibes"
    _rejects(document, "kind", "not one of")


def test_an_unknown_polarity_is_rejected():
    document = _example_record()
    document["polarity"] = "neutral"
    _rejects(document, "polarity", "not one of")


def test_an_unknown_caveat_kind_is_rejected():
    document = _example_record()
    document["caveats"] = [{"kind": "vibes", "detail": "d"}]
    _rejects(document, "not one of")


def test_a_bad_id_pattern_is_rejected():
    for bad in (
        "dsf1:" + "0" * 64,
        "ev-XYZ",
        "ev-0123456789abcdeg",
        "0123456789abcdef",
        "ev-0123456789abcde",
    ):
        document = _example_record()
        document["id"] = bad
        _rejects(document, "id", "does not match")


def test_a_suffixed_id_is_accepted():
    document = _example_record()
    document["id"] = "ev-0123456789abcdef-3"
    validate(SCHEMA_NAME, document)


def test_missing_required_properties_are_rejected():
    for required in (
        "schemaVersion",
        "id",
        "producer",
        "kind",
        "polarity",
        "subject",
        "locations",
        "caveats",
        "source",
    ):
        document = _example_record()
        del document[required]
        _rejects(document, required, "required")


def test_a_producer_without_a_report_schema_version_is_rejected():
    document = _example_record()
    document["producer"] = {"name": "atom", "version": "4.0.2"}
    _rejects(document, "reportSchemaVersion", "required")


def test_a_location_without_a_file_is_rejected():
    document = _example_record()
    document["locations"] = [{"line": 10}]
    _rejects(document, "file", "required")


def test_a_non_positive_line_is_rejected():
    document = _example_record()
    document["locations"] = [{"file": "src/app/main.py", "line": 0}]
    _rejects(document, "line", "minimum")


def test_an_unknown_schema_version_is_rejected():
    document = _example_record()
    document["schemaVersion"] = "2"
    _rejects(document, "schemaVersion")


# --- the constants and the model agree with the schema ----------------------------


def test_the_kind_and_polarity_and_caveat_constants_match_the_schema():
    schema = _schema()
    assert list(schema["properties"]["kind"]["enum"]) == list(KINDS)
    assert list(schema["properties"]["polarity"]["enum"]) == list(POLARITIES)
    assert list(schema["$defs"]["caveat"]["properties"]["kind"]["enum"]) == list(CAVEAT_KINDS)
    assert schema["properties"]["path"]["maxItems"] == MAX_PATH_NODES
    assert schema["properties"]["schemaVersion"]["const"] == EVIDENCE_SCHEMA_VERSION
    assert schema["properties"]["id"]["pattern"] == ID_PATTERN


def test_schema_and_model_agree():
    """A property must exist in the schema and the dataclass or in neither."""
    schema = _schema()
    mapping = {
        "producer": EvidenceProducer,
        "subject": EvidenceSubject,
        "location": EvidenceLocation,
        "path-node": EvidencePathNode,
        "caveat": EvidenceCaveat,
    }

    def json_keys(model_class: Any) -> List[str]:
        keys = []
        for field in fields(model_class):
            keys.append(getattr(model_class, "_KEYS", {}).get(field.name, field.name))
        return keys

    assert set(schema["properties"]) == set(json_keys(Evidence))
    object_defs = {
        name for name, definition in schema["$defs"].items() if "properties" in definition
    }
    assert object_defs == set(mapping)
    for def_name, model_class in mapping.items():
        definition = schema["$defs"][def_name]
        assert definition["additionalProperties"] is False, def_name
        assert set(definition["properties"]) == set(json_keys(model_class))
    assert schema["additionalProperties"] is False


def test_the_model_rejects_unknown_and_missing_properties():
    document = _example_record()
    with pytest.raises(ValueError, match="unknown properties for Evidence: notes"):
        Evidence.from_dict({**document, "notes": True})
    broken = {key: value for key, value in document.items() if key != "source"}
    with pytest.raises(ValueError, match="missing required properties for Evidence: source"):
        Evidence.from_dict(broken)


def test_the_model_requires_the_fields_the_schema_requires():
    """Locations and caveats are required in the schema, so the model does
    not read a record that leaves either out as an empty one."""
    for required in ("locations", "caveats"):
        document = _example_record()
        del document[required]
        with pytest.raises(
            ValueError, match=f"missing required properties for Evidence: {required}"
        ):
            Evidence.from_dict(document)


def test_the_model_resolves_nested_types():
    document = _example_record()
    record = Evidence.from_dict(document)
    assert isinstance(record.producer, EvidenceProducer)
    assert isinstance(record.subject, EvidenceSubject)
    assert isinstance(record.locations[0], EvidenceLocation)
    document["path"] = [{"file": "src/frame_0.py", "line": 1, "symbol": "sym"}]
    document["caveats"] = [{"kind": "budget", "detail": "stopped at the budget"}]
    record = Evidence.from_dict(document)
    assert record.path is not None and isinstance(record.path[0], EvidencePathNode)
    assert isinstance(record.caveats[0], EvidenceCaveat)
    assert record.path[0].symbol == "sym"
