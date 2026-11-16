"""Tests for the finding dataclasses and their JSON round trips."""

import json
from dataclasses import replace
from pathlib import Path
from typing import Any, Dict

import pytest

from analysis_lib.findings.model import (
    Coverage,
    CoverageReason,
    Exploitability,
    ExploitabilityAxes,
    Finding,
    Location,
    Producer,
)

EXAMPLES_DIR = Path(__file__).parent / "data" / "findings"


def _examples():
    return sorted(EXAMPLES_DIR.glob("*.json"))


def _example(name: str) -> Dict:
    return json.loads((EXAMPLES_DIR / name).read_text(encoding="utf-8"))


@pytest.mark.parametrize("path", _examples(), ids=lambda p: p.name)
def test_example_round_trip(path):
    document = json.loads(path.read_text(encoding="utf-8"))
    finding = Finding.from_dict(document)
    assert finding.to_dict() == document


@pytest.mark.parametrize("path", _examples(), ids=lambda p: p.name)
def test_example_nested_types(path):
    document = json.loads(path.read_text(encoding="utf-8"))
    finding = Finding.from_dict(document)
    assert isinstance(finding.coverage, Coverage)
    assert isinstance(finding.producer, Producer)
    if finding.locations:
        assert isinstance(finding.locations[0], Location)
    if finding.exploitability:
        assert isinstance(finding.exploitability, Exploitability)
        assert isinstance(finding.exploitability.axes, ExploitabilityAxes)
    if finding.coverage.reasons:
        assert isinstance(finding.coverage.reasons[0], CoverageReason)


def test_to_dict_omits_unset_optional_fields():
    finding = Finding(
        id="dsf1:" + "0" * 64,
        category="vulnerability",
        rule="CVE-2021-23337",
        title="Command injection in the lodash template function",
        severity="high",
        coverage=Coverage(state="assessed"),
        producer=Producer(name="dep-scan", version="7.0.0.dev0"),
    )
    document = finding.to_dict()
    assert set(document) == {
        "id",
        "category",
        "rule",
        "title",
        "severity",
        "coverage",
        "producer",
    }
    # An optional field given an empty list is set, and stays in the JSON.
    finding2 = replace(finding, components=[])
    assert finding2.to_dict()["components"] == []


def test_from_dict_rejects_unknown_and_missing():
    document = _example("vulnerability.json")
    with pytest.raises(ValueError, match="unknown properties for Finding: oops"):
        Finding.from_dict({**document, "oops": True})
    broken = {key: value for key, value in document.items() if key != "severity"}
    with pytest.raises(ValueError, match="missing required properties for Finding: severity"):
        Finding.from_dict(broken)


def test_from_dict_rejects_unknown_nested_property():
    document = _example("vulnerability.json")
    document["coverage"] = {"state": "assessed", "note": "extension"}
    with pytest.raises(ValueError, match="unknown properties for Coverage: note"):
        Finding.from_dict(document)


def test_from_dict_rejects_missing_nested_required():
    document = _example("health.json")
    document["coverage"]["reasons"] = [{"reason": "data-missing"}]
    with pytest.raises(ValueError, match="missing required properties for CoverageReason: capability"):
        Finding.from_dict(document)


def test_from_dict_rejects_non_object_and_bad_array():
    not_an_object: Any = "not a finding"
    with pytest.raises(ValueError, match="expects a JSON object"):
        Finding.from_dict(not_an_object)
    document = _example("memory-safety.json")
    document["locations"] = {"file": "src/cart/parse.rs"}
    with pytest.raises(ValueError, match="Finding.locations expects an array"):
        Finding.from_dict(document)


def test_from_dict_nested_documents():
    document = _example("memory-safety.json")
    finding = Finding.from_dict(document)
    exploitability = finding.exploitability
    assert exploitability is not None
    assert exploitability.axes.presence == "proven"
    locations = finding.locations
    assert locations
    assert locations[0].line == 42
