"""Tests for the tracebom evidence adapter.

The fixture under ``tests/data/tracebom`` is a real trace BOM written by
tracebom 13.9.0 (the dynamic-trace mode shipped inside the cdxgen package)
over a command that loaded a local shared library and fetched one http and
one https endpoint on localhost. The README next to it records how it was
made and that macOS reports no library loads to cdxgen, so the BOM holds
cryptographic assets and services only. The library component the path
tests add is the exact shape the producer's writer gives a traced library,
taken from the producer's own tests (including the Windows DLL spelling),
so the file path relativisation is covered on producer-shaped input.

The tests cover the shape detection, the version gate, malformed nested
input, record paths and ids that do not depend on the directory the trace
ran in, the producer's values kept as given, and the rule that a runtime
observation never counts as reached evidence.
"""

import json
import re
from pathlib import Path

from analysis_lib.evidence.adapters import STATUS_COMPLETED, STATUS_NOT_ASSESSED
from analysis_lib.evidence.adapters.tracebom import extract, is_tracebom_report
from analysis_lib.findings.schemas import validate
from analysis_lib.reachability import REACHED_COUNTED_KINDS, counts_as_reached

DATA = Path(__file__).parent / "data" / "tracebom"
ORDINARY_BOM = Path(__file__).parent / "data" / "bom-js.json"
SOURCE = "analysis/tracebom/tracebom.json"
ROOT = "/src"


def _report():
    return json.loads((DATA / "tracebom.json").read_text(encoding="utf-8"))


def _extract(report=None, **overrides):
    kwargs = {"source": SOURCE, "source_root": ROOT}
    kwargs.update(overrides)
    return extract(_report() if report is None else report, **kwargs)


def _library_subpath(file_path):
    """The purl subpath the producer's writer derives from a library path:
    Windows drive and UNC prefixes dropped, backslashes read as forward
    slashes, no leading separator."""
    subpath = file_path
    drive = re.match(r"^[A-Za-z]:[\\/]", subpath)
    if drive or subpath.startswith("\\\\"):
        subpath = subpath.replace("\\", "/")
        if drive:
            subpath = subpath[3:]
    return subpath.lstrip("/") or None


def _library_component(file_path):
    """A traced library component in the shape the producer's writer emits:
    the loaded file's hash, the full path it was loaded from as a
    ``cdx:dynamic:filePath`` property, and a generic purl whose subpath is
    derived from that path."""
    subpath = _library_subpath(file_path)
    name = subpath.rsplit("/", 1)[-1]
    purl = f"pkg:generic/{name}#{subpath}"
    return {
        "name": name,
        "type": "library",
        "scope": "required",
        "hashes": [{"alg": "SHA-256", "content": "ab" * 32}],
        "purl": purl,
        "bom-ref": purl,
        "properties": [
            {"name": "cdx:dynamic:filePath", "value": file_path},
            {"name": "cdx:dynamic:cryptoLibrary", "value": "Trace Demo Crypto"},
        ],
        "evidence": {
            "identity": [
                {
                    "field": "purl",
                    "confidence": 0.5,
                    "methods": [
                        {"technique": "instrumentation", "confidence": 0.5, "value": purl}
                    ],
                }
            ]
        },
    }


def _with_library(report, file_path):
    out = json.loads(json.dumps(report))
    out["components"].append(_library_component(file_path))
    return out


# --- the recording -----------------------------------------------------------


def test_the_recording_becomes_runtime_trace_records():
    """Four cryptographic assets and two services become six runtime-trace
    records, positive, produced by tracebom at the version the BOM's own
    metadata.tools names, with the specVersion as the report schema
    version, and every record validates against the evidence schema."""
    result = _extract()
    assert result.status == STATUS_COMPLETED
    assert len(result.records) == 6
    assert {r.kind for r in result.records} == {"runtime-trace"}
    assert {r.polarity for r in result.records} == {"positive"}
    for record in result.records:
        assert record.producer.name == "tracebom"
        assert record.producer.version == "13.9.0"
        assert record.producer.report_schema_version == "1.7"
        assert record.source == SOURCE
        validate("evidence", record.to_dict())
    assert len({r.id for r in result.records}) == 6
    assert result.caveats == []


def test_records_do_not_count_as_reached():
    """A runtime observation is evidence about the traced command's
    environment, never reached evidence for a scanned dependency."""
    result = _extract()
    assert "runtime-trace" not in REACHED_COUNTED_KINDS
    assert not any(counts_as_reached(r) for r in result.records)


def test_ids_and_records_are_byte_stable():
    first = _extract()
    second = _extract()
    left = [json.dumps(r.to_dict(), sort_keys=True) for r in first.records]
    right = [json.dumps(r.to_dict(), sort_keys=True) for r in second.records]
    assert left == right


def test_json_text_is_accepted_as_the_report():
    text = (DATA / "tracebom.json").read_text(encoding="utf-8")
    parsed = _extract()
    from_text = extract(text, source=SOURCE, source_root=ROOT)
    assert from_text.status == STATUS_COMPLETED
    assert [r.id for r in from_text.records] == [r.id for r in parsed.records]


# --- shape detection ---------------------------------------------------------


def test_is_tracebom_report_accepts_the_recording_and_refuses_an_ordinary_bom():
    assert is_tracebom_report(_report()) is True
    ordinary = json.loads(ORDINARY_BOM.read_text(encoding="utf-8"))
    assert is_tracebom_report(ordinary) is False
    assert is_tracebom_report({}) is False
    assert is_tracebom_report("not a report") is False
    # A cdx:dynamic: property on the metadata alone marks a trace BOM, and
    # so does one on a nested component.
    dry_run = _report()
    dry_run["metadata"]["properties"] = [{"name": "cdx:dynamic:dryRun", "value": "true"}]
    assert is_tracebom_report(dry_run) is True
    nested = {"components": [{"name": "app", "components": [_library_component("/src/l.dylib")]}]}
    assert is_tracebom_report(nested) is True


def test_extract_refuses_an_ordinary_source_bom():
    ordinary = json.loads(ORDINARY_BOM.read_text(encoding="utf-8"))
    result = extract(ordinary, source=SOURCE, source_root=ROOT)
    assert result.status == STATUS_NOT_ASSESSED
    assert "cdx:dynamic:" in result.reason


# --- the version gate --------------------------------------------------------


def test_a_newer_major_is_refused():
    report = _report()
    report["specVersion"] = "2.0.0"
    result = _extract(report)
    assert result.status == STATUS_NOT_ASSESSED
    assert "2.0.0" in result.reason
    assert result.records == []


def test_a_newer_minor_is_accepted_with_a_caveat_on_every_record():
    report = _report()
    report["specVersion"] = "1.8.0"
    result = _extract(report)
    assert result.status == STATUS_COMPLETED
    for record in result.records:
        assert record.producer.report_schema_version == "1.8.0"
        assert [(c.kind, c.detail) for c in record.caveats] == [
            (
                "schema-minor",
                "the report names schema version 1.8.0; this adapter knows 1.7 and earlier",
            )
        ]


def test_a_bom_without_a_specversion_is_accepted_with_a_caveat():
    report = _report()
    report.pop("specVersion")
    result = _extract(report)
    assert result.status == STATUS_COMPLETED
    for record in result.records:
        assert record.producer.report_schema_version == "unknown"
        assert [c.kind for c in record.caveats] == ["schema-unknown"]
    assert {c.kind for c in result.caveats} == {"schema-unknown"}


# --- traced library components -----------------------------------------------


def test_a_traced_library_component_carries_its_relative_file():
    """The file the component was loaded from becomes the record's location
    relative to the source root, and the remaining properties are kept as
    given; the hash, scope and identity evidence the producer stated are
    the purl's and the location's business and add no attribute."""
    report = _with_library(_report(), "/src/libs/libtrace-demo.dylib")
    result = _extract(report)
    assert result.status == STATUS_COMPLETED
    record = next(r for r in result.records if r.subject.purls)
    purl = "pkg:generic/libtrace-demo.dylib#src/libs/libtrace-demo.dylib"
    assert [loc.file for loc in record.locations] == ["libs/libtrace-demo.dylib"]
    assert record.subject.purls == [purl]
    assert record.subject.component_ref == purl
    assert record.attributes == {"cdx:dynamic:cryptoLibrary": "Trace Demo Crypto"}
    assert record.confidence is None
    assert record.caveats == []


def test_a_moved_root_gives_identical_ids_and_relative_library_paths():
    """The same trace produced in another directory: the file the component
    was loaded from is relative to whichever root holds it, and the record
    ids do not follow the directory."""
    first = _extract(_with_library(_report(), "/src/libs/libtrace-demo.dylib"))
    second = _extract(
        _with_library(_report(), "/work/elsewhere/libs/libtrace-demo.dylib"),
        source_root="/work/elsewhere",
    )
    assert first.status == second.status == STATUS_COMPLETED
    assert [r.id for r in first.records] == [r.id for r in second.records]
    library_first = next(r for r in first.records if r.subject.purls)
    library_second = next(r for r in second.records if r.subject.purls)
    assert [loc.file for loc in library_first.locations] == ["libs/libtrace-demo.dylib"]
    assert [loc.file for loc in library_second.locations] == ["libs/libtrace-demo.dylib"]
    # The purl is the producer's own and keeps the directory it was derived
    # from; only the id is neutral to it.
    assert library_second.subject.purls == [
        "pkg:generic/libtrace-demo.dylib#work/elsewhere/libs/libtrace-demo.dylib"
    ]


def test_windows_file_paths_become_relative_locations():
    report = _with_library(_report(), "C:\\src\\libs\\libtrace-demo.dylib")
    result = _extract(report, source_root="C:\\src")
    assert result.status == STATUS_COMPLETED
    record = next(r for r in result.records if r.subject.purls)
    assert [loc.file for loc in record.locations] == ["libs/libtrace-demo.dylib"]
    assert record.subject.purls == ["pkg:generic/libtrace-demo.dylib#src/libs/libtrace-demo.dylib"]


def test_a_library_outside_the_root_is_left_out_with_a_caveat():
    """A system library no root holds never appears as an absolute path: the
    record keeps its identity and says which file it left out."""
    report = _with_library(_report(), "/opt/homebrew/lib/libssl.3.dylib")
    result = _extract(report)
    assert result.status == STATUS_COMPLETED
    record = next(r for r in result.records if r.subject.purls)
    assert record.locations == []
    assert [c.kind for c in record.caveats] == ["location-outside-root"]
    assert [c.kind for c in result.caveats] == ["location-outside-root"]
    for other in result.records:
        assert not any(
            isinstance(value, str) and value.startswith("/")
            for value in (other.attributes or {}).values()
        )


# --- values kept as given ----------------------------------------------------


def test_service_values_are_kept_as_given():
    result = _extract()
    services = {r.attributes["name"]: r for r in result.records if "name" in (r.attributes or {})}
    http = services["dynamic-localhost-8471"]
    assert http.attributes["endpoints"] == ["http://localhost:8471"]
    assert http.attributes["egressDecision"] == "allowed"
    https = services["dynamic-localhost-8472"]
    assert https.attributes["endpoints"] == ["https://localhost:8472"]
    assert https.subject.component_ref is None
    assert https.locations == []


def test_crypto_properties_are_kept_as_given():
    report = _report()
    sha = next(c for c in report["components"] if c["name"] == "sha-256")
    result = _extract()
    record = next(
        r
        for r in result.records
        if (r.attributes or {}).get("cryptoProperties", {}).get("oid")
        == sha["cryptoProperties"]["oid"]
    )
    assert record.attributes == {"cryptoProperties": sha["cryptoProperties"]}
    assert record.subject.purls == []
    assert record.subject.component_ref == sha["bom-ref"]


def test_property_values_that_are_not_strings_are_kept():
    report = _with_library(_report(), "/src/libs/libtrace-demo.dylib")
    report["services"][0]["properties"].append(
        {"name": "cdx:dynamic:httpQueryParams", "value": ["q", "page"]}
    )
    result = _extract(report)
    service = next(
        r for r in result.records if (r.attributes or {}).get("name") == "dynamic-localhost-8471"
    )
    assert service.attributes["cdx:dynamic:httpQueryParams"] == ["q", "page"]


# --- malformed input ---------------------------------------------------------


def test_components_of_the_wrong_type_is_not_assessed():
    report = _report()
    report["components"] = "nope"
    result = _extract(report)
    assert result.status == STATUS_NOT_ASSESSED
    assert "components" in result.reason


def test_a_report_that_is_not_json_is_not_assessed():
    result = extract("{oops", source=SOURCE, source_root=ROOT)
    assert result.status == STATUS_NOT_ASSESSED
    assert "not valid JSON" in result.reason
    result = extract(["a", "list"], source=SOURCE, source_root=ROOT)
    assert result.status == STATUS_NOT_ASSESSED


def test_nested_malformed_values_count_skips_and_never_raise():
    """A service whose endpoints are a number, a service or component whose
    properties are a string and property entries that are not objects all
    become counted skips; the rest of the BOM is still assessed."""
    report = _with_library(_report(), "/src/libs/libtrace-demo.dylib")
    report["services"][0]["endpoints"] = 5
    report["services"][1]["properties"] = "nope"
    report["components"][0]["properties"] = "nope"
    report["components"][-1]["properties"].extend(["just a string", 7, None])
    result = _extract(report)
    assert result.status == STATUS_COMPLETED
    # The recording's four crypto assets and two services plus the traced
    # library lose the two services and the malformed crypto asset.
    assert len(result.records) == 4
    details = " ".join(c.detail for c in result.caveats if c.kind == "record-skipped")
    assert "services whose endpoints are not an array" in details
    assert "services whose properties are not an array" in details
    assert "components whose properties are not an array" in details
    assert "property entries that are not objects with a name" in details


def test_nested_components_of_the_wrong_type_count_skips():
    report = _report()
    report["components"].append({"name": "app", "components": "nope"})
    result = _extract(report)
    assert result.status == STATUS_COMPLETED
    assert any(
        c.kind == "record-skipped" and "nested components" in c.detail for c in result.caveats
    )


def test_a_traced_component_without_a_purl_still_becomes_a_record():
    component = _library_component("/src/libs/libtrace-demo.dylib")
    del component["purl"]
    component["bom-ref"] = "urn:uuid:00000000-0000-0000-0000-000000000000"
    report = _report()
    report["components"].append(component)
    result = _extract(report)
    assert result.status == STATUS_COMPLETED
    record = next(r for r in result.records if r.locations)
    assert record.subject.purls == []
    assert record.subject.component_ref == "urn:uuid:00000000-0000-0000-0000-000000000000"
