"""Tests for the cdxgen evidence adapter.

The fixtures under ``tests/data/cdxgen`` are a real cdxgen 13.9.0 BOM and
its build-introspection report, recorded over a small Flask application and
trimmed per the README next to them. The tests cover the two version gates
(the BOM's ``specVersion`` and the introspection report's own
``schemaVersion``), malformed and truncated inputs, record paths and ids
that do not depend on the directory the BOM was produced in, the count of
report objects that make no record, and the presence parity: the
occurrence and callstack records cover exactly the components whose BOM
evidence the exploitability axis reads as usage evidence.
"""

import json
from pathlib import Path

import pytest

from analysis_lib.evidence.adapters import STATUS_COMPLETED, STATUS_NOT_ASSESSED
from analysis_lib.evidence.adapters.cdxgen import extract
from analysis_lib.findings.schemas import validate

DATA = Path(__file__).parent / "data" / "cdxgen"
SOURCE = "sbom-python.cdx.json"
INTROSPECTION_SOURCE = "sbom-python.cdx.json.introspection.json"
ROOT = "/src/repos/recapp"
SQLPARSE_PURL = "pkg:pypi/sqlparse@0.5.3"
DEFUSEDXML_PURL = "pkg:pypi/defusedxml@0.7.1"
RECAPP_PURL = "pkg:pypi/recapp@0.1.0"

# The kinds and counts the recording yields: fourteen occurrence records
# (4 + 4 + 3 + 3 over sqlparse 0.5.3, sqlparse 0.6.1, flask and defusedxml),
# one callstack record per component that carries a callstack object, one
# annotation record per annotation (the SaaSBOM provenance note and the
# bom-audit rule finding), and one introspection record. Verified against
# the recording by hand.
EXPECTED_KINDS = {
    "annotation": 2,
    "callstack": 4,
    "introspection": 1,
    "occurrence": 14,
}


def _bom():
    return json.loads((DATA / "sbom-python.cdx.json").read_text(encoding="utf-8"))


def _introspection():
    return json.loads(
        (DATA / "sbom-python.cdx.json.introspection.json").read_text(encoding="utf-8")
    )


def _extract(bom=None, **overrides):
    kwargs = {
        "source": SOURCE,
        "introspection": _introspection(),
        "introspection_source": INTROSPECTION_SOURCE,
        "source_root": ROOT,
    }
    kwargs.update(overrides)
    return extract(bom if bom is not None else _bom(), **kwargs)


def _component(bom, name, version):
    return next(
        c for c in bom["components"] if c.get("name") == name and c.get("version") == version
    )


def _files(result):
    """Every file a record names, in its locations or on its witness path."""
    files = set()
    for record in result.records:
        files.update(location.file for location in record.locations)
        files.update(node.file for node in record.path or [] if node.file)
    return files


def _rewrite(value, old, new):
    return json.loads(json.dumps(value).replace(old, new))


def _skipped_details(result):
    return [c.detail for c in result.caveats if c.kind == "record-skipped"]


def _usage_evidence(component):
    """The verdict the exploitability presence axis computes on a BOM
    component: occurrences, or a callstack object truthy in Python (an
    empty ``{"frames": []}`` object counts)."""
    evidence = component.get("evidence")
    if not isinstance(evidence, dict):
        return False
    return bool(evidence.get("occurrences") or evidence.get("callstack"))


def _population(bom):
    """The components the package loader walks: the root component's nested
    components, the top-level components, and one level of nesting below
    each of them."""
    out = []
    metadata = bom.get("metadata") if isinstance(bom.get("metadata"), dict) else {}
    root = metadata.get("component") if isinstance(metadata.get("component"), dict) else {}
    out.extend(c for c in root.get("components", []) if isinstance(c, dict))
    for comp in bom.get("components", []):
        if not isinstance(comp, dict):
            continue
        out.append(comp)
        out.extend(c for c in comp.get("components", []) if isinstance(c, dict))
    return out


# --- the recording ------------------------------------------------------------


def test_the_recording_becomes_the_expected_records_and_validates():
    result = _extract()
    assert result.status == STATUS_COMPLETED
    kinds = {}
    for record in result.records:
        kinds[record.kind] = kinds.get(record.kind, 0) + 1
    assert kinds == EXPECTED_KINDS
    assert len({r.id for r in result.records}) == len(result.records)
    for record in result.records:
        validate("depscan-evidence", record.to_dict())


def test_records_are_byte_stable():
    first = _extract()
    second = _extract()
    left = [json.dumps(r.to_dict(), sort_keys=True) for r in first.records]
    right = [json.dumps(r.to_dict(), sort_keys=True) for r in second.records]
    assert left == right


def test_records_carry_no_timestamps():
    result = _extract()
    assert not any("timestamp" in json.dumps(r.to_dict()) for r in result.records)


# --- occurrence records -------------------------------------------------------


def test_occurrence_records_keep_the_producer_values():
    result = _extract()
    by_purl = [
        r for r in result.records if r.kind == "occurrence" and SQLPARSE_PURL in r.subject.purls
    ]
    assert len(by_purl) == 4
    call = next(r for r in by_purl if r.locations[0].line == 18)
    assert call.locations[0].file == "app.py"
    assert call.locations[0].method == "sqlparse.format"
    assert call.attributes == {"offset": 13}
    assert call.subject.purls == [SQLPARSE_PURL]
    assert call.subject.component_ref == SQLPARSE_PURL
    assert call.producer.name == "cdxgen"
    # A plain import line names no symbol and no offset, so the record
    # carries the line and nothing it would have to invent.
    plain_import = next(r for r in by_purl if r.locations[0].line == 4)
    assert plain_import.locations[0].method is None
    assert plain_import.attributes is None


def test_components_without_evidence_make_no_records():
    """The SaaSBOM annotation legitimately subjects the application purl;
    the check is that no usage record names an evidence-free component."""
    result = _extract()
    for purl in ("pkg:pypi/pip@26.2.2", RECAPP_PURL, "pkg:pypi/werkzeug@3.1.9"):
        assert not [
            r
            for r in result.records
            if r.kind in ("occurrence", "callstack") and purl in r.subject.purls
        ]


def test_nested_and_metadata_components_are_walked():
    bom = _bom()
    bom["metadata"]["component"]["components"] = [
        {
            "type": "library",
            "name": "meta-lib",
            "version": "1.0.0",
            "purl": "pkg:pypi/meta-lib@1.0.0",
            "bom-ref": "pkg:pypi/meta-lib@1.0.0",
            "evidence": {"occurrences": [{"location": "app.py", "line": 3}]},
        }
    ]
    bom["components"].append(
        {
            "type": "library",
            "name": "outer",
            "version": "2.0.0",
            "purl": "pkg:pypi/outer@2.0.0",
            "bom-ref": "pkg:pypi/outer@2.0.0",
            "components": [
                {
                    "type": "library",
                    "name": "inner",
                    "version": "3.0.0",
                    "purl": "pkg:pypi/inner@3.0.0",
                    "bom-ref": "pkg:pypi/inner@3.0.0",
                    "evidence": {"occurrences": [{"location": "app.py", "line": 7}]},
                }
            ],
        }
    )
    result = _extract(bom)
    assert result.status == STATUS_COMPLETED
    purls = {r.subject.purls[0] for r in result.records if r.kind == "occurrence"}
    assert {"pkg:pypi/meta-lib@1.0.0", "pkg:pypi/inner@3.0.0"} <= purls


# --- callstack records --------------------------------------------------------


def test_callstack_frames_become_the_witness_path():
    result = _extract()
    callstack = next(
        r for r in result.records if r.kind == "callstack" and DEFUSEDXML_PURL in r.subject.purls
    )
    bom = _bom()
    frames = _component(bom, "defusedxml", "0.7.1")["evidence"]["callstack"]["frames"]
    assert callstack.path is not None
    assert len(callstack.path) == len(frames)
    assert [n.method for n in callstack.path] == [f["function"] for f in frames]
    assert [n.line for n in callstack.path] == [f["line"] for f in frames]
    first = frames[0]
    assert callstack.path[0].file == first["fullFilename"]
    # The witness path is the whole place evidence; no location is invented
    # from its first frame. The frame column has no field on a witness
    # node; nothing carries it.
    assert callstack.locations == []
    assert "column" not in json.dumps(callstack.to_dict())


def test_a_callstack_with_empty_frames_still_becomes_a_record():
    """``{"frames": []}`` is a truthy callstack object, so it proves usage
    exactly like a populated one; the record keeps an empty path."""
    bom = _bom()
    _component(bom, "pip", "26.2.2")["evidence"] = {"callstack": {"frames": []}}
    result = _extract(bom)
    record = next(
        r
        for r in result.records
        if r.kind == "callstack" and "pkg:pypi/pip@26.2.2" in r.subject.purls
    )
    assert record.path is None
    assert record.locations == []


def test_an_empty_callstack_object_makes_no_record_and_is_counted():
    """``{}`` is falsy in Python, so the presence axis reads no usage
    evidence in it; the adapter counts it rather than dropping it."""
    bom = _bom()
    _component(bom, "pip", "26.2.2")["evidence"] = {"callstack": {}}
    result = _extract(bom)
    assert not [r for r in result.records if "pkg:pypi/pip@26.2.2" in r.subject.purls]
    assert _skipped_details(result) == [
        "1 evidence.callstack objects are empty and became no record"
    ]


# --- annotation records -------------------------------------------------------


def test_the_annotation_record_keeps_the_subjects_annotator_and_text():
    """The SaaSBOM provenance annotation: its subject is a purl, so the
    record carries it as the subject purl, and its text is kept as given."""
    result = _extract()
    record = next(r for r in result.records if r.kind == "annotation" and r.subject.purls)
    assert record.subject.purls == [RECAPP_PURL]
    assert record.locations == []
    attributes = record.attributes or {}
    assert attributes["subjects"] == [RECAPP_PURL]
    assert attributes["annotator"]["component"]["name"] == "cdxgen"
    assert attributes["annotator"]["component"]["version"] == "13.9.0"
    assert attributes["text"].startswith("This Software-as-a-Service BOM")
    # The annotation timestamp is the one field the record never carries.
    assert "timestamp" not in attributes
    assert "timestamp" not in json.dumps(record.to_dict())


def test_the_bom_audit_annotation_record_keeps_the_real_shape():
    """The recorded bom-audit annotation from a firing custom rule: cdxgen
    subjects the BOM serial number, which is not a purl, and renders its
    cdx:audit facts into the text as a markdown table instead of a
    properties array. The record keeps the text and the subjects as given,
    with empty subject purls and no invented properties key."""
    result = _extract()
    bom = _bom()
    serial = bom["serialNumber"]
    record = next(r for r in result.records if r.kind == "annotation" and not r.subject.purls)
    attributes = record.attributes or {}
    assert attributes["subjects"] == [serial]
    assert attributes["annotator"]["component"]["version"] == "13.9.0"
    assert "REC-001" in attributes["text"]
    assert "cdx:audit:ruleId" in attributes["text"]
    assert "properties" not in attributes
    assert "timestamp" not in attributes
    assert "timestamp" not in json.dumps(record.to_dict())


def test_an_annotation_properties_array_is_kept_as_given():
    """cdxgen 13.9.0 renders its audit facts into the annotation text, but
    the CycloneDX shape allows a properties array; a BOM that carries one
    has it kept as name/value pairs."""
    bom = _bom()
    serial = bom["serialNumber"]
    bom["annotations"].append(
        {
            "bom-ref": "audit-2",
            "subjects": [serial],
            "annotator": {"component": {"name": "cdxgen", "version": "13.9.0"}},
            "timestamp": "2026-11-22T23:00:00Z",
            "text": "A foreign annotation with structured properties.",
            "properties": [
                {"name": "cdx:audit:severity", "value": "medium"},
                {"name": "cdx:audit:location:purl", "value": SQLPARSE_PURL},
            ],
        }
    )
    result = _extract(bom)
    audit = next(
        r
        for r in result.records
        if r.kind == "annotation" and r.attributes and "properties" in r.attributes
    )
    attributes = audit.attributes or {}
    assert attributes["properties"] == [
        {"name": "cdx:audit:severity", "value": "medium"},
        {"name": "cdx:audit:location:purl", "value": SQLPARSE_PURL},
    ]
    assert audit.subject.purls == []
    assert "timestamp" not in attributes


def test_annotations_differing_only_in_timestamp_share_one_id():
    """A regenerated BOM rewrites the annotation timestamp while the
    annotation stays the same; the id must not change with it."""
    result = _extract()
    original = next(r for r in result.records if r.kind == "annotation" and not r.subject.purls)
    bom = _bom()
    for annotation in bom["annotations"]:
        if annotation.get("subjects") and str(annotation["subjects"][0]).startswith("urn:uuid:"):
            annotation["timestamp"] = "2030-01-01T00:00:00Z"
    regenerated = _extract(bom)
    changed = next(
        r
        for r in regenerated.records
        if r.kind == "annotation"
        and not r.subject.purls
        and r.attributes
        and "REC-001" in r.attributes.get("text", "")
    )
    assert changed.id == original.id
    assert changed.to_dict() == original.to_dict()


# --- the introspection record -------------------------------------------------


def test_the_introspection_record_keeps_overall_and_ledger():
    result = _extract()
    record = next(r for r in result.records if r.kind == "introspection")
    assert record.producer.version == "13.9.0"
    assert record.producer.report_schema_version == "1.1"
    assert record.source == INTROSPECTION_SOURCE
    assert record.subject.purls == []
    assert record.locations == []
    introspection = _introspection()
    assert record.attributes == {
        "overall": introspection["overall"],
        "ledger": introspection["ledger"],
    }
    assert not any(c.kind == "budget" for c in result.caveats)


def test_a_truncated_introspection_report_is_a_caveat_not_a_failed_bom():
    text = (DATA / "sbom-python.cdx.json.introspection.json").read_text(encoding="utf-8")
    result = _extract(introspection=text[: len(text) // 2])
    assert result.status == STATUS_COMPLETED
    assert not [r for r in result.records if r.kind == "introspection"]
    assert any("not valid JSON" in detail for detail in _skipped_details(result))
    assert {r.kind for r in result.records} >= {"occurrence", "callstack", "annotation"}


def test_an_introspection_report_of_the_wrong_shape_is_a_caveat():
    result = _extract(introspection=["not", "a", "report"])
    assert result.status == STATUS_COMPLETED
    assert not [r for r in result.records if r.kind == "introspection"]
    assert len(_skipped_details(result)) == 1


def test_a_refused_introspection_version_is_a_caveat_naming_the_version():
    introspection = _introspection()
    introspection["schemaVersion"] = "2.0"
    result = _extract(introspection=introspection)
    assert result.status == STATUS_COMPLETED
    assert not [r for r in result.records if r.kind == "introspection"]
    assert any("2.0" in detail for detail in _skipped_details(result))


def test_a_newer_introspection_minor_is_accepted_with_a_caveat():
    introspection = _introspection()
    introspection["schemaVersion"] = "1.2"
    result = _extract(introspection=introspection)
    record = next(r for r in result.records if r.kind == "introspection")
    assert record.producer.report_schema_version == "1.2"
    assert any(c.kind == "schema-minor" for c in record.caveats)
    assert any(c.kind == "schema-minor" for c in result.caveats)
    # The introspection's drift does not mark the BOM's own records.
    assert not any(
        c.kind == "schema-minor"
        for r in result.records
        if r.kind != "introspection"
        for c in r.caveats
    )


def test_a_ledger_truncation_is_a_budget_caveat():
    introspection = _introspection()
    introspection["ledger"]["truncated"] = True
    result = _extract(introspection=introspection)
    record = next(r for r in result.records if r.kind == "introspection")
    assert any(c.kind == "budget" for c in record.caveats)
    assert any(c.kind == "budget" for c in result.caveats)


def test_no_introspection_report_means_no_introspection_record():
    result = _extract(introspection=None)
    assert result.status == STATUS_COMPLETED
    assert not [r for r in result.records if r.kind == "introspection"]
    assert not result.caveats


# --- the BOM version gate -----------------------------------------------------


def test_a_2_0_bom_is_refused_naming_the_version():
    bom = _bom()
    bom["specVersion"] = "2.0.0"
    result = _extract(bom)
    assert result.status == STATUS_NOT_ASSESSED
    assert not result.records
    assert "2.0.0" in (result.reason or "")


def test_a_newer_minor_bom_is_accepted_with_a_caveat_on_every_bom_record():
    bom = _bom()
    bom["specVersion"] = "1.8.0"
    result = _extract(bom)
    assert result.status == STATUS_COMPLETED
    assert any(c.kind == "schema-minor" for c in result.caveats)
    bom_records = [r for r in result.records if r.kind != "introspection"]
    assert bom_records
    assert all(
        r.producer.report_schema_version == "1.8.0"
        and any(c.kind == "schema-minor" for c in r.caveats)
        for r in bom_records
    )
    # The introspection report keeps its own 1.1 schema version.
    introspection = next(r for r in result.records if r.kind == "introspection")
    assert introspection.producer.report_schema_version == "1.1"
    assert not any(c.kind == "schema-minor" for c in introspection.caveats)


def test_a_bom_without_a_spec_version_is_accepted_as_schema_unknown():
    bom = _bom()
    bom.pop("specVersion")
    result = _extract(bom)
    assert result.status == STATUS_COMPLETED
    assert any(c.kind == "schema-unknown" for c in result.caveats)
    bom_records = [r for r in result.records if r.kind != "introspection"]
    assert bom_records
    assert all(r.producer.report_schema_version == "unknown" for r in bom_records)
    assert all(any(c.kind == "schema-unknown" for c in r.caveats) for r in bom_records)


# --- the producer version -----------------------------------------------------


def _bom_records(result):
    return [r for r in result.records if r.kind != "introspection"]


def test_the_producer_version_comes_from_the_bom_metadata_tools():
    result = _extract()
    assert {r.producer.version for r in result.records} == {"13.9.0"}


def test_the_producer_version_reads_the_1_5_tools_list_form():
    bom = _bom()
    bom["metadata"]["tools"] = [
        {"vendor": "OWASP Foundation", "name": "cdxgen", "version": "10.3.0"}
    ]
    result = _extract(bom)
    assert {r.producer.version for r in _bom_records(result)} == {"10.3.0"}
    # The introspection record keeps its own report's cdxgen version.
    introspection = next(r for r in result.records if r.kind == "introspection")
    assert introspection.producer.version == "13.9.0"


def test_the_producer_version_is_unknown_when_the_bom_names_no_cdxgen():
    bom = _bom()
    bom["metadata"]["tools"]["components"] = [
        c for c in bom["metadata"]["tools"]["components"] if c.get("name") != "cdxgen"
    ]
    result = _extract(bom)
    assert result.status == STATUS_COMPLETED
    assert {r.producer.version for r in _bom_records(result)} == {"unknown"}


# --- malformed input ----------------------------------------------------------


def test_components_of_the_wrong_type_is_not_assessed():
    bom = _bom()
    bom["components"] = {"pkg:pypi/pip": {}}
    result = _extract(bom)
    assert result.status == STATUS_NOT_ASSESSED
    assert "components is a dict, expected an array" in (result.reason or "")


def test_annotations_of_the_wrong_type_is_not_assessed():
    bom = _bom()
    bom["annotations"] = "metadata-annotations"
    result = _extract(bom)
    assert result.status == STATUS_NOT_ASSESSED
    assert "annotations is a str, expected an array" in (result.reason or "")


def test_bom_text_is_parsed_and_truncated_text_is_not_assessed():
    text = (DATA / "sbom-python.cdx.json").read_text(encoding="utf-8")
    assert _extract(text).status == STATUS_COMPLETED
    truncated = _extract(text[: len(text) // 2])
    assert truncated.status == STATUS_NOT_ASSESSED
    assert not truncated.records


def test_a_bom_that_is_not_an_object_is_not_assessed():
    for raw in ("[]", '"cdx"', "3", ""):
        result = _extract(raw)
        assert result.status == STATUS_NOT_ASSESSED
        assert not result.records


def test_a_component_that_is_not_an_object_is_counted():
    bom = _bom()
    bom["components"].append("not-a-component")
    result = _extract(bom)
    assert result.status == STATUS_COMPLETED
    assert "1 components entries are not JSON objects and became no record" in _skipped_details(
        result
    )


def test_occurrences_of_the_wrong_type_are_counted_and_the_rest_stands():
    bom = _bom()
    component = _component(bom, "sqlparse", "0.5.3")
    component["evidence"]["occurrences"] = "app.py:4"
    result = _extract(bom)
    assert result.status == STATUS_COMPLETED
    assert not [
        r for r in result.records if r.kind == "occurrence" and SQLPARSE_PURL in r.subject.purls
    ]
    # The component's callstack still becomes a record.
    assert [
        r for r in result.records if r.kind == "callstack" and SQLPARSE_PURL in r.subject.purls
    ]
    assert _skipped_details(result) == [
        "1 evidence.occurrences values are not arrays and became no occurrence record"
    ]


def test_a_callstack_of_the_wrong_type_is_counted():
    bom = _bom()
    _component(bom, "defusedxml", "0.7.1")["evidence"]["callstack"] = [
        {"function": "parse_config"}
    ]
    result = _extract(bom)
    assert result.status == STATUS_COMPLETED
    assert not [
        r for r in result.records if r.kind == "callstack" and DEFUSEDXML_PURL in r.subject.purls
    ]
    assert [
        r for r in result.records if r.kind == "occurrence" and DEFUSEDXML_PURL in r.subject.purls
    ]
    assert _skipped_details(result) == [
        "1 evidence.callstack values are not JSON objects and became no record"
    ]


def test_an_annotation_that_is_not_an_object_is_counted():
    bom = _bom()
    bom["annotations"].append("not-an-annotation")
    result = _extract(bom)
    assert result.status == STATUS_COMPLETED
    assert len([r for r in result.records if r.kind == "annotation"]) == 2
    assert _skipped_details(result) == [
        "1 annotations entries are not JSON objects and became no record"
    ]


def test_nested_sections_of_the_wrong_type_are_counted():
    """A wrong type one level inside the report hides what that section
    would have carried; each case is counted, nothing raises, and the rest
    of the BOM still becomes records."""
    bom = _bom()
    bom["metadata"]["component"] = "recapp"
    result = _extract(bom)
    assert result.status == STATUS_COMPLETED
    assert _skipped_details(result) == [
        "1 metadata.component values are not JSON objects, "
        "so their nested components became no record"
    ]

    bom = _bom()
    _component(bom, "pip", "26.2.2")["components"] = {"inner": {}}
    result = _extract(bom)
    assert result.status == STATUS_COMPLETED
    assert _skipped_details(result) == [
        "1 nested components values are not arrays and became no record"
    ]

    bom = _bom()
    _component(bom, "defusedxml", "0.7.1")["evidence"]["callstack"]["frames"] = "frames"
    result = _extract(bom)
    # The callstack object is still truthy evidence of usage, so its record
    # stands, with no witness path and the loss counted.
    callstack = next(
        r for r in result.records if r.kind == "callstack" and DEFUSEDXML_PURL in r.subject.purls
    )
    assert callstack.path is None
    assert _skipped_details(result) == [
        "1 evidence.callstack frames values are not arrays and name no witness node"
    ]


def test_annotation_subjects_or_properties_of_the_wrong_type_are_counted():
    bom = _bom()
    bom["annotations"].append(
        {
            "bom-ref": "audit-3",
            "subjects": "urn:uuid:not-a-list",
            "annotator": {"component": {"name": "cdxgen", "version": "13.9.0"}},
            "timestamp": "2026-11-22T23:00:00Z",
            "text": "An annotation whose subjects and properties are strings.",
            "properties": "cdx:audit:severity=medium",
        }
    )
    result = _extract(bom)
    assert result.status == STATUS_COMPLETED
    record = next(
        r
        for r in result.records
        if r.kind == "annotation"
        and r.attributes
        and r.attributes.get("subjects") == "urn:uuid:not-a-list"
    )
    assert record.subject.purls == []
    assert record.attributes is not None
    assert record.attributes["subjects"] == "urn:uuid:not-a-list"
    assert "properties" not in record.attributes
    assert _skipped_details(result) == [
        "1 annotation subjects values are not arrays and name no subject",
        "1 annotation properties values are not arrays and name no property",
    ]


def test_occurrence_entries_without_a_location_are_counted():
    bom = _bom()
    component = _component(bom, "sqlparse", "0.5.3")
    component["evidence"]["occurrences"] = [
        {"line": 5},
        {"location": "app.py", "line": 4},
        "not-an-object",
    ]
    result = _extract(bom)
    purl_records = [
        r for r in result.records if r.kind == "occurrence" and SQLPARSE_PURL in r.subject.purls
    ]
    assert len(purl_records) == 1
    assert _skipped_details(result) == [
        "1 evidence.occurrences entries name no location and became no record",
        "1 evidence.occurrences entries are not JSON objects and became no record",
    ]


def test_nested_values_of_the_wrong_type_are_read_without_raising():
    """A null section reads as absent, and a value of the wrong type inside
    a component (an evidence section that is a string, a line that is text,
    a frame with no file) is no value; the rest of the BOM still becomes
    records."""
    bom = _bom()
    bom["components"].append(
        {
            "type": "library",
            "name": "odd",
            "version": "1.0",
            "purl": "pkg:pypi/odd@1.0",
            "bom-ref": "pkg:pypi/odd@1.0",
            "evidence": "trusted",
        }
    )
    component = _component(bom, "sqlparse", "0.6.1")
    component["evidence"]["occurrences"][0]["line"] = "abc"
    frames = _component(bom, "Flask", "3.1.3")["evidence"]["callstack"]["frames"]
    frames[0]["fullFilename"] = 12
    result = _extract(bom)
    assert result.status == STATUS_COMPLETED
    assert not [r for r in result.records if "pkg:pypi/odd@1.0" in r.subject.purls]
    text_line = next(
        r
        for r in result.records
        if r.kind == "occurrence"
        and "pkg:pypi/sqlparse@0.6.1" in r.subject.purls
        and r.locations[0].line is None
    )
    assert text_line.locations[0].file == "app.py"
    flask_callstack = next(
        r
        for r in result.records
        if r.kind == "callstack" and "pkg:pypi/flask@3.1.3" in r.subject.purls
    )
    assert flask_callstack.path is not None
    assert flask_callstack.path[0].file is None


# --- record paths and ids -----------------------------------------------------


def test_locations_and_frames_stay_relative():
    result = _extract()
    assert _files(result) == {"app.py"}
    assert not any(c.kind == "location-outside-root" for c in result.caveats)


def test_a_moved_source_root_gives_identical_ids_and_paths():
    """The same BOM produced under another directory: the occurrence
    locations and the callstack frame files are absolute there, and the
    record ids and paths must not change with the directory."""
    bom = _bom()
    left = _rewrite(bom, "app.py", "/src/repos/recapp/app.py")
    right = _rewrite(bom, "app.py", "/work/elsewhere/recapp/app.py")
    first = _extract(left, source_root="/src/repos/recapp")
    second = _extract(right, source_root="/work/elsewhere/recapp")
    assert first.status == STATUS_COMPLETED
    assert _files(first) == {"app.py"}
    assert [r.id for r in first.records] == [r.id for r in second.records]
    assert [r.to_dict() for r in first.records] == [r.to_dict() for r in second.records]


def test_windows_style_locations_give_the_same_relative_paths():
    bom = _bom()
    # The replacement is spelled the way it appears inside JSON text, where
    # each backslash is escaped, so the rewritten document still parses.
    windows = _rewrite(bom, "app.py", "C:\\\\src\\\\repos\\\\recapp\\\\app.py")
    result = _extract(windows, source_root="C:\\src\\repos\\recapp")
    assert result.status == STATUS_COMPLETED
    assert _files(result) == {"app.py"}
    posix = _rewrite(bom, "app.py", "/src/repos/recapp/app.py")
    reference = _extract(posix, source_root="/src/repos/recapp")
    assert [r.id for r in result.records] == [r.id for r in reference.records]


def test_absolute_locations_outside_the_root_are_left_out_with_a_caveat():
    bom = _bom()
    _component(bom, "sqlparse", "0.5.3")["evidence"]["occurrences"][0]["location"] = (
        "/opt/elsewhere/legacy.py"
    )
    result = _extract(bom)
    assert result.status == STATUS_COMPLETED
    outside = [
        r
        for r in result.records
        if r.kind == "occurrence" and SQLPARSE_PURL in r.subject.purls and r.locations == []
    ]
    assert outside
    assert any(c.kind == "location-outside-root" for c in outside[0].caveats)
    assert any(c.kind == "location-outside-root" for c in result.caveats)
    assert not any("/opt" in f for f in _files(result))
    assert "/opt" not in json.dumps([r.to_dict() for r in result.records])


# --- presence parity ----------------------------------------------------------


@pytest.mark.parametrize(
    "mutate",
    [
        lambda bom: None,
        lambda bom: _component(bom, "pip", "26.2.2").update(
            {"evidence": {"callstack": {"frames": []}}}
        ),
        lambda bom: _component(bom, "Werkzeug", "3.1.9").update(
            {"evidence": {"occurrences": [{"location": "app.py", "line": 2}]}}
        ),
        lambda bom: _component(bom, "Flask", "3.1.3")["evidence"].pop("occurrences"),
        lambda bom: _component(bom, "recapp", "0.1.0").update({"evidence": {"callstack": {}}}),
    ],
    ids=[
        "as-recorded",
        "empty-frames-callstack",
        "occurrence-added",
        "occurrences-removed",
        "empty-callstack-object",
    ],
)
def test_records_agree_with_the_component_evidence_verdict(mutate):
    """For every component the package loader walks, a usage-evidence
    verdict of true means an occurrence or callstack record exists for it,
    and a verdict of false means none does; and every such record points
    back at a component the verdict was true for."""
    bom = _bom()
    mutate(bom)
    result = _extract(bom)
    assert result.status == STATUS_COMPLETED
    usage_refs = set()
    for component in _population(bom):
        ref = component.get("bom-ref") or component.get("purl")
        has_records = any(
            r.kind in ("occurrence", "callstack") and r.subject.component_ref == ref
            for r in result.records
        )
        assert has_records == _usage_evidence(component), (
            f"component {ref} disagrees: verdict {_usage_evidence(component)}"
        )
        if _usage_evidence(component):
            usage_refs.add(ref)
    recorded_refs = {
        r.subject.component_ref for r in result.records if r.kind in ("occurrence", "callstack")
    }
    assert recorded_refs == usage_refs
