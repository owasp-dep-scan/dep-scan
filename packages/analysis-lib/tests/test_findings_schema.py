"""Tests for the dep-scan finding schema and its validation helpers."""

import json
from dataclasses import fields
from pathlib import Path
from typing import Any, Dict

import pytest
from jsonschema import Draft202012Validator

from analysis_lib.findings.model import (
    Coverage,
    CoverageReason,
    Exploitability,
    ExploitabilityAxes,
    Finding,
    FindingProperty,
    Fix,
    Location,
    Producer,
    Reference,
    Triage,
)
from analysis_lib.findings.schemas import (
    load_schema,
    schema_names,
    validate,
)

EXAMPLES_DIR = Path(__file__).parent / "data" / "findings"


def _examples():
    return sorted(EXAMPLES_DIR.glob("*.json"))


def _example(name: str) -> Dict[str, Any]:
    return json.loads((EXAMPLES_DIR / name).read_text(encoding="utf-8"))


def _base_finding() -> Dict[str, Any]:
    """A minimal valid finding that each invalid-document test mutates."""
    return {
        "id": "dsf1:" + "0" * 64,
        "category": "vulnerability",
        "rule": "CVE-2021-23337",
        "title": "Command injection in the lodash template function",
        "severity": "high",
        "coverage": {"state": "assessed"},
        "producer": {"name": "dep-scan", "version": "7.0.0.dev0"},
    }


def test_schema_names():
    assert schema_names() == ["finding"]


def test_load_schema_metadata():
    schema = load_schema("finding")
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["$id"] == "urn:owasp:depscan:schema:finding:1"
    assert schema["additionalProperties"] is False


def test_load_schema_unknown_name():
    with pytest.raises(ValueError) as excinfo:
        load_schema("evidence")
    assert "evidence" in str(excinfo.value)
    assert "finding" in str(excinfo.value)


def test_schema_is_valid_2020_12():
    Draft202012Validator.check_schema(load_schema("finding"))


def test_every_property_has_a_description():
    schema = load_schema("finding")
    for name, prop in schema["properties"].items():
        assert prop.get("description"), f"property {name} has no description"
    for def_name, definition in schema["$defs"].items():
        for name, prop in definition["properties"].items():
            assert prop.get("description"), f"$defs/{def_name} property {name} has no description"


def test_schema_and_model_agree():
    """A property must exist in the schema and the dataclass or in neither."""
    schema = load_schema("finding")
    assert set(schema["properties"]) == {field.name for field in fields(Finding)}
    # Every $defs object maps to one dataclass, and every dataclass to a $def.
    mapping = {
        "location": Location,
        "coverage": Coverage,
        "coverage-reason": CoverageReason,
        "exploitability": Exploitability,
        "exploitability-axes": ExploitabilityAxes,
        "triage": Triage,
        "fix": Fix,
        "producer": Producer,
        "reference": Reference,
        "finding-property": FindingProperty,
    }
    object_defs = {
        name for name, definition in schema["$defs"].items() if "properties" in definition
    }
    assert object_defs == set(mapping)
    for def_name, model_class in mapping.items():
        definition = schema["$defs"][def_name]
        assert definition["additionalProperties"] is False, def_name
        assert set(definition["properties"]) == {field.name for field in fields(model_class)}


@pytest.mark.parametrize("path", _examples(), ids=lambda p: p.name)
def test_example_validates(path):
    validate("finding", json.loads(path.read_text(encoding="utf-8")))


@pytest.mark.parametrize(
    "name",
    [p.name for p in _examples()],
)
def test_examples_cover_every_category(name):
    example = _example(name)
    assert example["category"] in load_schema("finding")["properties"]["category"]["enum"]


def test_examples_have_one_per_category():
    categories = sorted(_example(p.name)["category"] for p in _examples())
    assert categories == [
        "binary-hardening",
        "code",
        "crypto",
        "health",
        "license",
        "malware",
        "memory-safety",
        "mobile",
        "supply-chain",
        "vulnerability",
    ]


def _rejects(document: Dict[str, Any], *fragments: str) -> None:
    with pytest.raises(ValueError) as excinfo:
        validate("finding", document)
    for fragment in fragments:
        assert fragment in str(excinfo.value), (
            f"expected {fragment!r} in the error for {fragments}, got: {excinfo.value}"
        )


def test_not_assessed_without_reasons_rejected():
    document = _base_finding()
    document["coverage"] = {"state": "not_assessed"}
    _rejects(document, "coverage", "reasons", "required")


def test_not_assessed_with_empty_reasons_rejected():
    document = _base_finding()
    document["coverage"] = {"state": "not_assessed", "reasons": []}
    _rejects(document, "coverage", "reasons", "non-empty")


def test_unknown_category_rejected():
    document = _base_finding()
    document["category"] = "typo"
    _rejects(document, "category", "not one of")


def test_extra_property_rejected():
    document = _base_finding()
    document["notes"] = "an unknown field"
    _rejects(document, "notes", "Additional properties")


def test_extra_nested_property_rejected():
    document = _base_finding()
    document["coverage"] = {"state": "assessed", "note": "nested extension"}
    _rejects(document, "note", "Additional properties")


def test_negative_line_number_rejected():
    document = _base_finding()
    document["locations"] = [{"file": "src/app/main.c", "line": -3}]
    _rejects(document, "line", "minimum")


def test_missing_severity_rejected():
    document = _base_finding()
    del document["severity"]
    _rejects(document, "severity", "required")


def test_bad_id_rejected():
    document = _base_finding()
    document["id"] = "not-a-fingerprint"
    _rejects(document, "id", "does not match")


def test_producer_without_version_rejected():
    document = _base_finding()
    document["producer"] = {"name": "dep-scan"}
    _rejects(document, "version", "required")


def test_unknown_triage_state_rejected():
    document = _base_finding()
    document["triage"] = {"state": "wont_fix"}
    _rejects(document, "triage", "not one of")


def test_unknown_axis_value_rejected():
    document = _base_finding()
    document["exploitability"] = {
        "axes": {
            "presence": "maybe",
            "reach": "unknown",
            "exposure": "unknown",
            "barrier": "unlikely",
            "pressure": "unknown",
        }
    }
    _rejects(document, "presence", "not one of")


def test_error_lists_every_violation():
    document = _base_finding()
    document["category"] = "typo"
    del document["title"]
    with pytest.raises(ValueError) as excinfo:
        validate("finding", document)
    message = str(excinfo.value)
    assert "category" in message and "title" in message
    assert message.count("\n") >= 2
