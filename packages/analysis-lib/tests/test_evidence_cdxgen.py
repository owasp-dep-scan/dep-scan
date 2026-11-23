"""Tests for the cdxgen evidence adapter.

The fixtures under ``tests/data/cdxgen`` are real cdxgen 13.9.0 BOMs, one
recorded over a small Flask application with its build-introspection
report and one over a small Kotlin project that kosi analysed, trimmed per
the README next to them. The tests cover the version gates (the BOM's
``specVersion``, the cdxgen version its ``metadata.tools`` names and the
introspection report's own ``schemaVersion``), malformed, truncated and
over-deep inputs, record paths and ids that depend neither on the
directory the BOM was produced in nor on the user, annotation ids that
survive a regenerated BOM, the ``cdx:kosi:*`` properties, the count of
report objects that make no record, and the presence parity: the
occurrence and callstack records cover exactly the components whose BOM
evidence the exploitability axis reads as usage evidence.
"""

import json
from pathlib import Path

import pytest

from analysis_lib.evidence import EvidenceLocation
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


def _kinds(result):
    kinds = {}
    for record in result.records:
        kinds[record.kind] = kinds.get(record.kind, 0) + 1
    return kinds


def _location(file, line=None, method=None):
    return EvidenceLocation(file=file, line=line, method=method)


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
    assert call.attributes == {"offset": 13, "bomPosition": "top-level"}
    assert call.subject.purls == [SQLPARSE_PURL]
    assert call.subject.component_ref == SQLPARSE_PURL
    assert call.producer.name == "cdxgen"
    # A plain import line names no symbol and no offset, so the record
    # carries the line and nothing it would have to invent.
    plain_import = next(r for r in by_purl if r.locations[0].line == 4)
    assert plain_import.locations[0].method is None
    assert plain_import.attributes == {"bomPosition": "top-level"}


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
    # from its first frame. A witness node has no field for the frame's
    # column, so the frames attribute keeps every frame as given, with the
    # file relativized.
    assert callstack.locations == []
    assert callstack.attributes["frames"] == frames


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
        "1 evidence.callstack values are empty and became no record"
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
    properties array. The record keeps the text and the annotator as given
    and spells the serial-number subject <bom>, with empty subject purls
    and no invented properties key."""
    result = _extract()
    bom = _bom()
    serial = bom["serialNumber"]
    record = next(r for r in result.records if r.kind == "annotation" and not r.subject.purls)
    attributes = record.attributes or {}
    assert attributes["subjects"] == ["<bom>"]
    assert serial not in json.dumps(record.to_dict())
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
    # Every verdict block the report carries is kept as given; an empty
    # block (no coverage gap, no remediation) adds no attribute.
    assert record.attributes == {
        "overall": introspection["overall"],
        "ledger": introspection["ledger"],
        "ecosystems": introspection["ecosystems"],
        "observations": introspection["observations"],
    }
    assert introspection["coverageGaps"] == introspection["remediation"] == []
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


def test_non_object_introspection_blocks_are_counted_not_dropped():
    introspection = _introspection()
    introspection["overall"] = "high"
    introspection["ledger"] = 3
    result = _extract(introspection=introspection)
    record = next(r for r in result.records if r.kind == "introspection")
    attributes = record.attributes or {}
    assert "overall" not in attributes and "ledger" not in attributes
    details = " ".join(_skipped_details(result))
    assert "overall block is a str" in details
    assert "ledger block is a int" in details


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
        {"vendor": "OWASP Foundation", "name": "cdxgen", "version": "13.1.0"}
    ]
    result = _extract(bom)
    assert {r.producer.version for r in _bom_records(result)} == {"13.1.0"}
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


def test_components_of_the_wrong_type_cost_that_section_alone():
    """A malformed section is a counted skip: the annotations and the
    introspection report still give records."""
    bom = _bom()
    bom["components"] = {"pkg:pypi/pip": {}}
    result = _extract(bom)
    assert result.status == STATUS_COMPLETED
    assert _kinds(result) == {"annotation": 2, "introspection": 1}
    assert _skipped_details(result) == [
        "1 components sections are a dict, expected an array, and their contents became no record"
    ]


def test_annotations_of_the_wrong_type_cost_that_section_alone():
    bom = _bom()
    bom["annotations"] = "metadata-annotations"
    result = _extract(bom)
    assert result.status == STATUS_COMPLETED
    assert _kinds(result) == {"callstack": 4, "introspection": 1, "occurrence": 14}
    assert _skipped_details(result) == [
        "1 annotations sections are a str, expected an array, and their contents became no record"
    ]
    metadata = _bom()
    metadata["metadata"] = ["not", "an", "object"]
    result = _extract(metadata)
    assert result.status == STATUS_COMPLETED
    assert _kinds(result)["occurrence"] == 14


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


def test_occurrences_of_the_wrong_type_stand_as_one_location_less_record():
    """A truthy occurrences value that is not an array is still usage
    evidence on the component reading, so it becomes one occurrence record
    with no location and the value in its attributes; a falsy one is
    counted."""
    bom = _bom()
    component = _component(bom, "sqlparse", "0.5.3")
    component["evidence"]["occurrences"] = "app.py:4"
    result = _extract(bom)
    assert result.status == STATUS_COMPLETED
    occurrences = [
        r for r in result.records if r.kind == "occurrence" and SQLPARSE_PURL in r.subject.purls
    ]
    assert [(r.locations, r.attributes) for r in occurrences] == [
        ([], {"occurrence": "app.py:4", "bomPosition": "top-level"})
    ]
    # The component's callstack still becomes a record.
    assert [
        r for r in result.records if r.kind == "callstack" and SQLPARSE_PURL in r.subject.purls
    ]
    assert _skipped_details(result) == []
    component["evidence"]["occurrences"] = {}
    result = _extract(bom)
    assert not [
        r for r in result.records if r.kind == "occurrence" and SQLPARSE_PURL in r.subject.purls
    ]
    assert _skipped_details(result) == [
        "1 evidence.occurrences values are empty and became no record"
    ]


def test_a_callstack_of_the_wrong_type_is_counted():
    bom = _bom()
    _component(bom, "defusedxml", "0.7.1")["evidence"]["callstack"] = [
        {"function": "parse_config"}
    ]
    result = _extract(bom)
    assert result.status == STATUS_COMPLETED
    callstacks = [
        r for r in result.records if r.kind == "callstack" and DEFUSEDXML_PURL in r.subject.purls
    ]
    assert [(r.path, r.attributes) for r in callstacks] == [
        (None, {"callstack": [{"function": "parse_config"}], "bomPosition": "top-level"})
    ]
    assert [
        r for r in result.records if r.kind == "occurrence" and DEFUSEDXML_PURL in r.subject.purls
    ]
    assert _skipped_details(result) == []
    _component(bom, "defusedxml", "0.7.1")["evidence"]["callstack"] = []
    assert _skipped_details(_extract(bom)) == [
        "1 evidence.callstack values are empty and became no record"
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


def test_occurrence_entries_without_a_location_still_prove_usage():
    """An occurrence entry with no location, or one that is not an object,
    is still usage evidence on the component reading: each becomes a
    record with no location and the entry in its attributes."""
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
    assert [(r.locations, r.attributes) for r in purl_records] == [
        ([], {"line": 5, "bomPosition": "top-level"}),
        ([_location("app.py", 4)], {"bomPosition": "top-level"}),
        ([], {"occurrence": "not-an-object", "bomPosition": "top-level"}),
    ]
    assert _skipped_details(result) == []


def test_records_name_the_position_of_their_component_in_the_bom():
    """Each occurrence and callstack record names where its component sits:
    a top-level component, one nested below it, or one nested in the root
    metadata component. The reachability engine counts direct uses from the
    top-level ones alone."""
    from analysis_lib.evidence.adapters import cdxgen as cdxgen_adapter

    def used(name):
        return {
            "type": "library",
            "name": name,
            "purl": f"pkg:pypi/{name}@1.0",
            "bom-ref": f"pkg:pypi/{name}@1.0",
            "evidence": {"occurrences": [{"location": "app.py", "line": 1}]},
        }

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "metadata": {
            "component": {"type": "application", "name": "root", "components": [used("mc")]}
        },
        "components": [{**used("top"), "components": [used("child")]}],
    }
    result = cdxgen_adapter.extract(bom, source="sbom.cdx.json")
    positions = {
        r.subject.purls[0]: (r.attributes or {}).get("bomPosition") for r in result.records
    }
    assert positions == {
        "pkg:pypi/mc@1.0": "root-nested",
        "pkg:pypi/top@1.0": "top-level",
        "pkg:pypi/child@1.0": "nested",
    }


def test_repeated_identical_occurrences_stay_one_record_each_in_the_store(tmp_path):
    """Two identical occurrence entries of one component are two uses, as
    the BOM lists them: the second carries its ordinal in the discriminator,
    so the store keeps both records instead of folding them into one, and
    a second read of the same BOM still folds onto the same two ids."""
    from analysis_lib.evidence import store
    from analysis_lib.evidence.adapters import cdxgen as cdxgen_adapter

    entry = {"location": "app.py", "line": 3}
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "components": [
            {
                "type": "library",
                "name": "top",
                "purl": "pkg:pypi/top@1.0",
                "bom-ref": "pkg:pypi/top@1.0",
                "evidence": {"occurrences": [dict(entry), dict(entry)]},
            }
        ],
    }
    first = cdxgen_adapter.extract(bom, source="sbom.cdx.json").records
    again = cdxgen_adapter.extract(bom, source="sbom.cdx.json").records
    assert len({r.id for r in first}) == 2
    path = str(tmp_path / "evidence.jsonl")
    assert store.write(path, [*first, *again]) == 2


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
        lambda bom: _component(bom, "pip", "26.2.2").update(
            {"evidence": {"occurrences": [{"line": 3}]}}
        ),
        lambda bom: _component(bom, "pip", "26.2.2").update(
            {"evidence": {"occurrences": ["app.py", None]}}
        ),
        lambda bom: _component(bom, "pip", "26.2.2").update(
            {"evidence": {"occurrences": {"location": "app.py"}}}
        ),
        lambda bom: _component(bom, "pip", "26.2.2").update(
            {"evidence": {"callstack": ["frame"], "occurrences": []}}
        ),
        lambda bom: _component(bom, "pip", "26.2.2").update(
            {"evidence": {"callstack": [], "occurrences": ""}}
        ),
    ],
    ids=[
        "as-recorded",
        "empty-frames-callstack",
        "occurrence-added",
        "occurrences-removed",
        "empty-callstack-object",
        "occurrence-without-location",
        "occurrence-entries-not-objects",
        "occurrences-an-object",
        "callstack-a-list",
        "falsy-values-of-the-wrong-type",
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


# --- ids that survive a regenerated BOM ----------------------------------------


def _regenerated(bom):
    """The same BOM generated again: a new serial number, new timestamps and
    a new creation date in the SaaSBOM note."""
    out = _rewrite(bom, bom["serialNumber"], "urn:uuid:11111111-2222-4333-8444-555555555555")
    out["metadata"]["timestamp"] = "2030-03-04T05:06:07Z"
    for annotation in out["annotations"]:
        annotation["timestamp"] = "2030-03-04T05:06:08Z"
        if isinstance(annotation.get("text"), str):
            annotation["text"] = annotation["text"].replace(
                "Sunday, November 22, 2026", "Monday, March 4, 2030"
            )
    return out


def test_annotation_ids_survive_a_regenerated_serial_number_and_date():
    original = _extract()
    regenerated = _extract(_regenerated(_bom()))
    assert sorted(r.id for r in original.records) == sorted(r.id for r in regenerated.records)


def test_annotation_records_survive_a_regenerated_serial_number():
    """A regenerated BOM writes a fresh urn:uuid serial, and the bom-audit
    annotation subjects that serial. The record's attributes spell the
    subject <bom>, the way its id already does, so the whole record is the
    same across the two serials and neither uuid reaches a record."""
    original = _extract()
    regenerated_bom = _regenerated(_bom())
    regenerated = _extract(regenerated_bom)
    first = next(r for r in original.records if r.kind == "annotation" and not r.subject.purls)
    second = next(r for r in regenerated.records if r.kind == "annotation" and not r.subject.purls)
    assert (first.attributes or {})["subjects"] == ["<bom>"]
    assert (second.attributes or {})["subjects"] == ["<bom>"]
    assert second.to_dict() == first.to_dict()
    for bom, result in ((_bom(), original), (regenerated_bom, regenerated)):
        assert bom["serialNumber"] not in json.dumps([r.to_dict() for r in result.records])


def test_an_annotation_subjecting_a_foreign_serial_keeps_it_as_given():
    """A subject that names another document's serial number is evidence
    about that document, not a per-run value of this BOM, so it is kept
    verbatim; only this BOM's own serial is spelled <bom>."""
    bom = _bom()
    foreign = "urn:uuid:99999999-8888-4777-8666-555555555555"
    bom["annotations"].append(
        {
            "bom-ref": "audit-foreign",
            "subjects": [foreign],
            "annotator": {"component": {"name": "cdxgen", "version": "13.9.0"}},
            "timestamp": "2026-11-22T23:40:00Z",
            "text": "An annotation about another document.",
        }
    )
    result = _extract(bom)
    own = next(r for r in result.records if r.kind == "annotation" and not r.subject.purls)
    assert (own.attributes or {})["subjects"] == ["<bom>"]
    foreign_record = next(
        r
        for r in result.records
        if r.kind == "annotation" and r.attributes and r.attributes.get("subjects") == [foreign]
    )
    assert foreign_record.subject.purls == []
    assert foreign != bom["serialNumber"]


def test_a_different_audit_rule_or_text_gives_a_different_annotation_id():
    bom = _bom()
    first = {r.id for r in _extract(bom).records if r.kind == "annotation"}
    for annotation in bom["annotations"]:
        if "cdx:audit:ruleId" in annotation.get("text", ""):
            annotation["text"] = annotation["text"].replace("REC-001", "REC-002")
        else:
            annotation["text"] += " One more sentence."
    second = {r.id for r in _extract(bom).records if r.kind == "annotation"}
    assert not first & second


# --- the cdxgen tool version gate ------------------------------------------------


def _with_tools(tools):
    bom = _bom()
    bom["metadata"]["tools"] = tools
    return bom


def test_a_bom_another_tool_wrote_carries_a_caveat_naming_the_tool():
    result = _extract(_with_tools({"components": [{"name": "syft", "version": "1.0"}]}))
    assert result.status == STATUS_COMPLETED
    expected = (
        "schema-unknown",
        "the BOM's metadata.tools names syft 1.0 and no cdxgen; this adapter reads the "
        "shapes cdxgen's BOM writes",
    )
    for record in _bom_records(result):
        assert record.producer.version == "unknown"
        assert expected in [(c.kind, c.detail) for c in record.caveats]
    bom = _bom()
    bom["metadata"].pop("tools")
    details = [c.detail for c in _extract(bom).caveats]
    assert (
        "the BOM's metadata.tools names no tool and no cdxgen; this adapter reads the "
        "shapes cdxgen's BOM writes" in details
    )


_OLDER = "older than the 10.0 through 13.9 range this adapter knows"


@pytest.mark.parametrize(
    "version, status, caveat",
    [
        (
            "9.11.0",
            STATUS_COMPLETED,
            ("schema-unknown", f"the BOM names cdxgen version 9.11.0, {_OLDER}"),
        ),
        ("10.10.0", STATUS_COMPLETED, None),
        ("12.1.2", STATUS_COMPLETED, None),
        ("13.9.0", STATUS_COMPLETED, None),
        (
            "13.10.0",
            STATUS_COMPLETED,
            (
                "schema-minor",
                "the BOM names cdxgen version 13.10.0; this adapter knows 13.9 and earlier",
            ),
        ),
        ("14.0.0", STATUS_NOT_ASSESSED, None),
        (None, STATUS_COMPLETED, ("schema-unknown", "the BOM names no cdxgen version")),
    ],
    ids=[
        "9-older",
        "10-known",
        "12-known",
        "13.9-known",
        "13.10-newer-minor",
        "14-newer-major",
        "missing",
    ],
)
def test_the_cdxgen_version_gate_knows_10_through_13(version, status, caveat):
    """cdxgen 10 through 13 write the same occurrence and callstack shapes,
    so all of them are read; the minor rule applies to 13 alone, a newer
    major is refused and an older release is read with a caveat."""
    tool = {"name": "cdxgen"}
    if version is not None:
        tool["version"] = version
    result = _extract(_with_tools([tool]))
    assert result.status == status
    if status == STATUS_NOT_ASSESSED:
        assert result.reason == (
            "the BOM cdxgen version 14.0.0 is newer than this adapter knows; "
            "it reads cdxgen 10.0 through 13.9 BOMs"
        )
        assert result.records == []
        return
    records = _bom_records(result)
    assert records
    for record in records:
        tool_caveats = [(c.kind, c.detail) for c in record.caveats if "cdxgen version" in c.detail]
        assert tool_caveats == ([caveat] if caveat else [])
        assert record.producer.version == (version or "unknown")


def test_a_pre_12_4_location_with_the_line_inside_is_read_as_file_and_line():
    bom = _bom()
    bom["metadata"]["tools"] = [{"name": "cdxgen", "version": "11.2.0"}]
    _component(bom, "sqlparse", "0.5.3")["evidence"]["occurrences"] = [
        {"location": "app.py#12"},
        {"location": "app.py#7", "line": 7},
    ]
    result = _extract(bom)
    occurrences = [
        r for r in result.records if r.kind == "occurrence" and SQLPARSE_PURL in r.subject.purls
    ]
    assert [r.locations for r in occurrences] == [
        [_location("app.py", 12)],
        [_location("app.py#7", 7)],
    ]


# --- no machine paths, ids that do not follow the user ----------------------------


def test_locations_outside_the_root_give_the_same_ids_for_every_user():
    """The same flask occurrence and callstack in two users' virtualenvs
    outside their roots: the ids agree and no user name reaches a record."""
    bom = _bom()
    flask = _component(bom, "Flask", "3.1.3")
    flask["evidence"]["occurrences"][0]["location"] = "/home/alice/.venv/lib/flask/app.py"
    flask["evidence"]["occurrences"][0]["additionalContext"] = (
        "/home/alice/proj/app.py: import flask"
    )
    flask["evidence"]["callstack"]["frames"][0]["fullFilename"] = (
        "/home/alice/.venv/lib/flask/app.py"
    )
    first = _extract(bom, source_root="/home/alice/proj")
    second = _extract(_rewrite(bom, "alice", "bob"), source_root="/home/bob/proj")
    assert [r.id for r in first.records] == [r.id for r in second.records]
    for result, user in ((first, "alice"), (second, "bob")):
        text = json.dumps([r.to_dict() for r in result.records])
        assert user not in text
        assert "/home/" not in text
    occurrence = next(
        r
        for r in first.records
        if r.kind == "occurrence"
        and "pkg:pypi/flask@3.1.3" in r.subject.purls
        and r.locations == []
    )
    assert occurrence.attributes["additionalContext"] == "app.py: import flask"


def test_fields_no_witness_node_carries_stay_in_the_attributes():
    """A frame's package beside its module, its column and parameters, and
    an occurrence line or symbol the location cannot carry are kept."""
    bom = _bom()
    sqlparse = _component(bom, "sqlparse", "0.6.1")
    sqlparse["evidence"]["occurrences"][0].update({"line": "x", "symbol": ["s"]})
    frame = _component(bom, "defusedxml", "0.7.1")["evidence"]["callstack"]["frames"][0]
    frame.update({"package": "defusedxml", "module": "import", "parameters": ["a"]})
    result = _extract(bom)
    odd = next(
        r
        for r in result.records
        if r.kind == "occurrence"
        and "pkg:pypi/sqlparse@0.6.1" in r.subject.purls
        and r.locations[0].line is None
    )
    assert odd.attributes["line"] == "x"
    assert odd.attributes["symbol"] == ["s"]
    callstack = next(
        r for r in result.records if r.kind == "callstack" and DEFUSEDXML_PURL in r.subject.purls
    )
    kept = callstack.attributes["frames"][0]
    assert (kept["package"], kept["module"], kept["parameters"]) == ("defusedxml", "import", ["a"])
    assert "column" in kept
    assert callstack.path[0].symbol == "import"


def test_a_deep_value_costs_its_own_component_alone():
    deep = []
    for _ in range(3000):
        deep = [deep]
    bom = _bom()
    _component(bom, "Flask", "3.1.3")["evidence"]["occurrences"][0]["additionalContext"] = deep
    result = _extract(bom)
    assert result.status == STATUS_COMPLETED
    assert "pkg:pypi/flask@3.1.3" not in {p for r in result.records for p in r.subject.purls}
    assert _kinds(result)["occurrence"] == 11
    assert any(d.startswith("1 report objects nest deeper") for d in _skipped_details(result))


# --- kosi properties ------------------------------------------------------------

KOSI_BOM = DATA / "sbom-kotlin-kosi.cdx.json"
KOTLIN_ROOT = "/src/kt2"
OKHTTP_PURL = "pkg:maven/com.squareup.okhttp3/okhttp@4.12.0?type=jar"


def _kosi_bom():
    return json.loads(KOSI_BOM.read_text(encoding="utf-8"))


def _kosi_extract(bom=None):
    return extract(
        bom if bom is not None else _kosi_bom(),
        source="sbom-kotlin.cdx.json",
        source_root=KOTLIN_ROOT,
    )


def test_the_kotlin_recording_keeps_the_kosi_component_properties():
    result = _kosi_extract()
    assert result.status == STATUS_COMPLETED
    assert _kinds(result) == {"callstack": 1, "occurrence": 2}
    for record in result.records:
        assert record.subject.purls == [OKHTTP_PURL]
        assert record.attributes["kosiProperties"] == {"cdx:kosi:reachableFromRoots": "true"}
        validate("evidence", record.to_dict())


def test_the_kosi_run_diagnostics_become_caveats_on_every_record():
    """The root component carries the run's diagnostics; the truncation
    count is a budget caveat and the others say where kosi could not look.
    The rest of the run-level properties are counted by name."""
    result = _kosi_extract()
    expected = [
        ("coverage-gap", "kosi diagnostic bytecode-unlowered reported 12 time(s)"),
        ("coverage-gap", "kosi diagnostic dataflow-convergence reported 1 time(s)"),
        ("budget", "kosi diagnostic dataflow-truncated reported 1952814 time(s)"),
        ("coverage-gap", "kosi diagnostic deps-bodyless reported 60 time(s)"),
        ("coverage-gap", "kosi diagnostic taint-unnameable-invoke reported 1 time(s)"),
    ]
    for record in result.records:
        assert [(c.kind, c.detail) for c in record.caveats] == expected
    assert [(c.kind, c.detail) for c in result.caveats][:5] == expected
    skipped = _skipped_details(result)
    assert any(
        d.startswith("16 root cdx:kosi: properties") and "cdx:kosi:dataFlowCategories" in d
        for d in skipped
    )
    assert "1 services kosi found as outbound calls name no package and became no record" in (
        skipped
    )


def test_a_degraded_kosi_run_and_its_error_diagnostics_are_coverage_gaps():
    bom = _kosi_bom()
    bom["metadata"]["component"]["properties"].extend(
        [
            {"name": "cdx:kosi:degraded", "value": "no-jdk"},
            {"name": "cdx:kosi:diagnosticErrors", "value": "callgraph-failed"},
            {"name": "cdx:kosi:diagnostic:analysis-timeout", "value": "1"},
        ]
    )
    caveats = [(c.kind, c.detail) for c in _kosi_extract(bom).records[0].caveats]
    assert (
        "coverage-gap",
        "kosi marked its analysis degraded (no-jdk), so its counts are not facts about the code",
    ) in caveats
    assert (
        "coverage-gap",
        "kosi reported error diagnostics (callgraph-failed): those parts of its analysis "
        "are absent from the BOM",
    ) in caveats
    assert ("timeout", "kosi diagnostic analysis-timeout reported 1 time(s)") in caveats


def test_a_kosi_endpoint_service_becomes_an_entry_point_naming_no_package():
    """The service shape cdxgen's collectKosiApiEndpoints writes for a
    route kosi found: an entry point with empty purls, so it never counts
    a package as reached."""
    bom = _kosi_bom()
    bom["services"].append(
        {
            "name": "service-orders{id}-get",
            "bom-ref": "urn:service:kosi:orders",
            "endpoints": ["/orders/{id}"],
            "authenticated": True,
            "x-trust-boundary": True,
            "properties": [
                {"name": "cdx:kosi:endpoint:authentication", "value": "bearer"},
                {"name": "cdx:service:httpMethod", "value": "GET"},
                {"name": "cdx:kosi:endpoint:framework", "value": "ktor"},
                {"name": "cdx:kosi:endpoint:handler", "value": "demo.Orders.get"},
                {"name": "cdx:kosi:endpoint:produces", "value": "application/json"},
            ],
        }
    )
    result = _kosi_extract(bom)
    entry = next(r for r in result.records if r.kind == "entry-point")
    assert entry.subject.purls == []
    assert entry.attributes["endpoints"] == ["/orders/{id}"]
    assert entry.attributes["authenticated"] is True
    assert entry.attributes["properties"]["cdx:kosi:endpoint:framework"] == "ktor"
    assert entry.caveats == result.records[0].caveats
    validate("evidence", entry.to_dict())


def test_bom_tool_version_reads_both_tools_forms():
    """The shared reader finds a tool's version in the CycloneDX 1.5 list
    form and the 1.6 ``components`` form, and gives the empty string for a
    missing tool, a missing version or a document that is not an object."""
    from analysis_lib.evidence.adapters import bom_tool_version

    listed = {"metadata": {"tools": [{"name": "atom", "version": "4.0.3"}]}}
    nested = {"metadata": {"tools": {"components": [{"name": "blint", "version": "4.0.1"}]}}}
    assert bom_tool_version(listed, "atom") == "4.0.3"
    assert bom_tool_version(nested, "blint") == "4.0.1"
    assert bom_tool_version(nested, "atom") == ""
    assert bom_tool_version({"metadata": {"tools": [{"name": "atom"}]}}, "atom") == ""
    assert bom_tool_version({"metadata": {"tools": "atom"}}, "atom") == ""
    assert bom_tool_version([], "atom") == ""
