"""Tests for the tracebom evidence adapter.

The fixtures under ``tests/data/tracebom`` are real trace BOMs written by
tracebom 13.9.0 (the dynamic-trace mode shipped inside the cdxgen
package). One holds what a traced run observed over a command that loaded
a local shared library and fetched one http and one https endpoint on
localhost; the README next to them records how they were made and that
macOS reports no library loads to cdxgen, so the observed BOM holds
cryptographic assets and services only. The other holds a dry run, where
every side effect was denied and only the attempted-operation counts in
the metadata remain. The library components and eBPF services the tests
add are the exact shapes the producer's writer gives them, taken from the
producer's own code and tests (the generic purl with the file path as its
subpath, the Windows DLL spelling, the OS package purl), so the path
handling is covered on producer-shaped input.

The tests cover the shape detection, the two version gates, malformed and
over-deep input, record paths, subjects and ids that depend neither on the
directory the trace ran in nor on the user, the producer's values kept as
given, a dry run never reading as a trace that observed nothing, and the
rule that a runtime observation never counts as reached evidence.
"""

import json
import re
from pathlib import Path

import pytest

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
    slashes, no leading separator. The writer yields no subpath only for a
    path that is nothing but separators, which no test input is."""
    subpath = file_path
    drive = re.match(r"^[A-Za-z]:[\\/]", subpath)
    if drive or subpath.startswith("\\\\"):
        subpath = subpath.replace("\\", "/")
        if drive:
            subpath = subpath[3:]
    return subpath.lstrip("/") or ""


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


def _assert_no_machine_paths(result, *needles):
    """No record of ``result`` names any of ``needles`` (a root, a user
    name, a home directory) in its subject, id, locations, attributes or
    caveats."""
    for record in result.records:
        text = json.dumps(record.to_dict(), sort_keys=True)
        for needle in needles:
            assert needle not in text, f"{needle!r} reached record {record.id}: {text}"


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


def test_a_dry_run_trace_is_never_read_as_an_empty_trace():
    """A dry run denies every side effect and leaves only the
    attempted-operation counts in the metadata: no component, no service.
    The counts are counted as metadata properties that became no record,
    so the BOM never reads as a trace that observed nothing."""
    report = json.loads((DATA / "tracebom-dry-run.json").read_text(encoding="utf-8"))
    assert is_tracebom_report(report) is True
    result = _extract(report)
    assert result.status == STATUS_COMPLETED
    assert result.records == []
    skipped = [c for c in result.caveats if c.kind == "record-skipped"]
    assert len(skipped) == 1
    count = len(report["metadata"]["properties"])
    assert skipped[0].detail.startswith(f"{count} metadata cdx:dynamic: properties")
    assert "cdx:dynamic:dryRun:fileWrites" in skipped[0].detail


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


def test_a_specversion_of_the_wrong_type_is_refused():
    report = _report()
    report["specVersion"] = ["1.7"]
    result = _extract(report)
    assert result.status == STATUS_NOT_ASSESSED
    assert "list" in result.reason
    assert "not a version string" in result.reason


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
    purl = "pkg:generic/libtrace-demo.dylib#libs/libtrace-demo.dylib"
    assert [loc.file for loc in record.locations] == ["libs/libtrace-demo.dylib"]
    assert record.subject.purls == [purl]
    assert record.subject.component_ref == purl
    assert record.attributes == {"cdx:dynamic:cryptoLibrary": "Trace Demo Crypto"}
    assert record.confidence is None
    assert record.caveats == []


def test_a_moved_root_gives_identical_ids_and_relative_library_paths():
    """The same trace produced in another directory: the file the component
    was loaded from is relative to whichever root holds it, in the location
    and in the purl subpath, and neither the record ids nor the subjects
    follow the directory."""
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
    # The producer derived the purl subpath from the absolute path; the
    # record spells it from the root, so the subject is the same too.
    purl = "pkg:generic/libtrace-demo.dylib#libs/libtrace-demo.dylib"
    assert library_first.subject.purls == library_second.subject.purls == [purl]
    assert library_first.subject.component_ref == library_second.subject.component_ref == purl
    _assert_no_machine_paths(second, "/work/elsewhere", "work/elsewhere")


def test_windows_file_paths_become_relative_locations():
    report = _with_library(_report(), "C:\\src\\libs\\libtrace-demo.dylib")
    result = _extract(report, source_root="C:\\src")
    assert result.status == STATUS_COMPLETED
    record = next(r for r in result.records if r.subject.purls)
    assert [loc.file for loc in record.locations] == ["libs/libtrace-demo.dylib"]
    assert record.subject.purls == ["pkg:generic/libtrace-demo.dylib#libs/libtrace-demo.dylib"]


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


def test_absolute_paths_nested_in_property_values_are_never_stored_absolute():
    """A property value that is an object or array is kept with the same
    shape. A path-named key inside it holds a file path: relative when a
    root holds it, otherwise left out and named by the location-outside-root
    caveat. Any other string has the root taken out."""
    report = _with_library(_report(), "/src/libs/libtrace-demo.dylib")
    report["components"][-1]["properties"].append(
        {
            "name": "cdx:dynamic:meta",
            "value": {"path": "/opt/homebrew/lib/l.dylib", "kept": "as given"},
        }
    )
    report["components"][-1]["properties"].append(
        {"name": "cdx:dynamic:inside", "value": ["/src/libs/other.dylib", 7]}
    )
    result = _extract(report)
    assert result.status == STATUS_COMPLETED
    record = next(r for r in result.records if r.subject.purls)
    assert record.attributes["cdx:dynamic:meta"] == {"path": None, "kept": "as given"}
    assert record.attributes["cdx:dynamic:inside"] == ["libs/other.dylib", 7]
    assert [c.kind for c in record.caveats] == ["location-outside-root"]


# --- values kept as given ----------------------------------------------------


def test_service_values_are_kept_as_given():
    result = _extract()
    services = {r.attributes["name"]: r for r in result.records if "name" in (r.attributes or {})}
    http = services["dynamic-localhost-8471"]
    assert http.attributes["endpoints"] == ["http://localhost:8471"]
    assert http.attributes["properties"] == {"cdx:dynamic:egressDecision": "allowed"}
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
    assert service.attributes["properties"]["cdx:dynamic:httpQueryParams"] == ["q", "page"]


# --- malformed input ---------------------------------------------------------


def test_components_of_the_wrong_type_is_a_counted_skip_and_services_stand():
    """A section of the wrong type costs that section alone: the services
    still become records and the components section is counted."""
    report = _report()
    report["components"] = "nope"
    result = _extract(report)
    assert result.status == STATUS_COMPLETED
    assert len(result.records) == 2
    assert any(
        c.kind == "record-skipped" and c.detail.startswith("1 components sections are a str")
        for c in result.caveats
    )


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


# --- subjects carry no machine paths ------------------------------------------


def test_a_library_under_a_home_directory_names_no_user_anywhere():
    """A library loaded from a home directory outside the root: the purl
    subpath and the bom-ref the producer derived from its absolute path are
    reduced to the bare generic purl, and the user name reaches no part of
    the record."""
    report = _with_library(_report(), "/home/alice/.cache/x/libtrace-demo.dylib")
    result = _extract(report, source_root="/home/alice/proj")
    record = next(r for r in result.records if r.subject.purls)
    assert record.subject.purls == ["pkg:generic/libtrace-demo.dylib"]
    assert record.subject.component_ref == "pkg:generic/libtrace-demo.dylib"
    assert record.locations == []
    assert [(c.kind, c.detail[:2]) for c in record.caveats] == [("location-outside-root", "1 ")]
    _assert_no_machine_paths(result, "alice", "/home/", ".cache")


def test_the_same_library_under_two_users_gives_one_record():
    """Two users trace the same in-root library: ids and subjects agree and
    neither the root nor the user name reaches the record."""
    first = _extract(
        _with_library(_report(), "/home/alice/proj/build/libtrace-demo.dylib"),
        source_root="/home/alice/proj",
    )
    second = _extract(
        _with_library(_report(), "/srv/bob/proj/build/libtrace-demo.dylib"),
        source_root="/srv/bob/proj",
    )
    assert [r.to_dict() for r in first.records] == [r.to_dict() for r in second.records]
    _assert_no_machine_paths(first, "alice", "/home/")
    _assert_no_machine_paths(second, "bob", "/srv/")


def test_a_versioned_windows_dll_keeps_its_version_and_a_relative_subpath():
    """The producer versions a crypto DLL's generic purl with the file
    version and encodes the subpath; the record keeps the version and spells
    the subpath from the root."""
    component = _library_component("C:\\Users\\alice\\app\\bin\\bcrypt.dll")
    component["version"] = "10.0.26100.1"
    component["purl"] = "pkg:generic/bcrypt.dll@10.0.26100.1#Users/alice/app/bin/bcrypt.dll"
    component["bom-ref"] = component["purl"]
    report = _report()
    report["components"].append(component)
    result = _extract(report, source_root="C:\\Users\\alice\\app")
    record = next(r for r in result.records if r.subject.purls)
    assert record.subject.purls == ["pkg:generic/bcrypt.dll@10.0.26100.1#bin/bcrypt.dll"]
    assert record.subject.component_ref == "pkg:generic/bcrypt.dll@10.0.26100.1#bin/bcrypt.dll"
    assert [loc.file for loc in record.locations] == ["bin/bcrypt.dll"]
    _assert_no_machine_paths(result, "alice", "Users")


def test_a_path_qualifier_follows_the_same_rule():
    """Older cdxgen releases spelled the library path as a ``path``
    qualifier of the generic purl; it is relativized or dropped the same
    way as a subpath."""
    inside = _library_component("/src/libs/a.so")
    inside["purl"] = inside["bom-ref"] = "pkg:generic/a.so?path=/src/libs/a.so"
    outside = _library_component("/home/alice/b.so")
    outside["purl"] = outside["bom-ref"] = "pkg:generic/b.so?path=%2Fhome%2Falice%2Fb.so"
    report = _report()
    report["components"].extend([inside, outside])
    result = _extract(report)
    purls = sorted(p for r in result.records for p in r.subject.purls)
    assert purls == ["pkg:generic/a.so?path=libs/a.so", "pkg:generic/b.so"]
    _assert_no_machine_paths(result, "alice", "/src/")


def test_a_resolved_os_package_keeps_its_purl_and_several_libraries_stand():
    """The producer names a library the OS package manager owns by that
    package's purl (with arch and distro qualifiers, confidence 0.8 in its
    identity evidence); the purl carries no path and is kept as given, the
    system file outside the root is left out of the location, and every
    library of the trace becomes its own record."""
    resolved = _library_component("/lib/x86_64-linux-gnu/libc.so.6")
    purl = "pkg:deb/ubuntu/libc6@2.39-0ubuntu8.9?arch=amd64&distro=ubuntu-24.04&distro_name=noble"
    resolved.update({"name": "libc6", "version": "2.39-0ubuntu8.9", "purl": purl})
    resolved["bom-ref"] = purl
    resolved["evidence"]["identity"][0]["confidence"] = 0.8
    resolved["evidence"]["identity"][0]["methods"][0].update({"confidence": 0.8, "value": purl})
    report = _report()
    report["components"].extend(
        [
            resolved,
            _library_component("/src/build/liba.so"),
            _library_component("/src/build/libb.so"),
        ]
    )
    result = _extract(report)
    libraries = [r for r in result.records if r.subject.purls]
    assert sorted(p for r in libraries for p in r.subject.purls) == [
        "pkg:deb/ubuntu/libc6@2.39-0ubuntu8.9?arch=amd64&distro=ubuntu-24.04&distro_name=noble",
        "pkg:generic/liba.so#build/liba.so",
        "pkg:generic/libb.so#build/libb.so",
    ]
    libc = next(r for r in libraries if r.subject.purls[0].startswith("pkg:deb/"))
    assert libc.subject.component_ref == purl
    assert libc.locations == []
    assert len({r.id for r in libraries}) == 3


# --- deep nesting ---------------------------------------------------------------


def _nested_chain(depth):
    leaf = _library_component("/src/libs/deep.so")
    node = leaf
    for _ in range(depth):
        node = {"name": "n", "type": "library", "components": [node]}
    return node


def test_a_deep_component_chain_is_counted_and_never_raises():
    report = _report()
    report["components"].append(_nested_chain(2000))
    assert is_tracebom_report(report) is True
    assert is_tracebom_report({"components": [_nested_chain(2000)]}) is False
    result = _extract(report)
    assert result.status == STATUS_COMPLETED
    # The recording's six records stand; the chain's first levels are
    # components that observed nothing and the rest is cut at the depth cap.
    assert len(result.records) == 6
    details = [c.detail for c in result.caveats if c.kind == "record-skipped"]
    assert any("nested deeper than 64 levels" in d for d in details)
    text = extract(json.dumps(report), source=SOURCE, source_root=ROOT)
    assert [r.id for r in text.records] == [r.id for r in result.records]


def test_a_deep_property_value_costs_its_own_record_alone():
    deep = []
    for _ in range(3000):
        deep = [deep]
    report = _with_library(_report(), "/src/libs/libtrace-demo.dylib")
    report["components"][-1]["properties"].append({"name": "cdx:dynamic:deep", "value": deep})
    report["services"][0]["properties"].append({"name": "cdx:dynamic:deep", "value": deep})
    result = _extract(report)
    assert result.status == STATUS_COMPLETED
    assert len(result.records) == 5
    assert any(
        c.kind == "record-skipped" and c.detail.startswith("2 report objects nest deeper")
        for c in result.caveats
    )


# --- the cdxgen tool version gate ----------------------------------------------


def _with_tools(tools):
    report = _report()
    report["metadata"]["tools"] = tools
    return report


def test_a_trace_bom_another_tool_wrote_carries_a_caveat_naming_it():
    report = _with_tools({"components": [{"name": "syft", "version": "1.0"}]})
    result = _extract(report)
    assert result.status == STATUS_COMPLETED
    expected = (
        "schema-unknown",
        "the BOM's metadata.tools names syft 1.0 and no cdxgen; this adapter reads the "
        "shapes cdxgen's tracebom writes",
    )
    for record in result.records:
        assert record.producer.version == "unknown"
        assert [(c.kind, c.detail) for c in record.caveats] == [expected]
    absent = _report()
    absent["metadata"].pop("tools")
    details = [c.detail for c in _extract(absent).caveats]
    assert any("names no tool and no cdxgen" in d for d in details)


_TRACE_OLDER = "older than the 12.6 through 13.9 range this adapter knows"


@pytest.mark.parametrize(
    "version, status, caveat",
    [
        (
            "12.5.1",
            STATUS_COMPLETED,
            ("schema-unknown", f"the BOM names cdxgen version 12.5.1, {_TRACE_OLDER}"),
        ),
        ("12.6.0", STATUS_COMPLETED, None),
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
        "12.5-older",
        "12.6-known",
        "13.9-known",
        "13.10-newer-minor",
        "14-newer-major",
        "missing",
    ],
)
def test_the_cdxgen_version_gate_knows_the_releases_that_ship_tracebom(version, status, caveat):
    tool = {"name": "cdxgen"}
    if version is not None:
        tool["version"] = version
    result = _extract(_with_tools([tool]))
    assert result.status == status
    if status == STATUS_NOT_ASSESSED:
        assert "cdxgen version 14.0.0 is newer than this adapter knows" in result.reason
        return
    assert result.records
    for record in result.records:
        assert [(c.kind, c.detail) for c in record.caveats] == ([caveat] if caveat else [])


def test_a_12_x_path_qualifier_library_names_no_machine_path():
    """cdxgen 12.x spelled the library path as a ``path`` qualifier and set
    the bom-ref to the encoded purl."""
    component = _library_component("/home/alice/proj/build/liba.so")
    component["purl"] = component["bom-ref"] = (
        "pkg:generic/liba.so?path=%2Fhome%2Falice%2Fproj%2Fbuild%2Fliba.so"
    )
    report = _with_tools([{"name": "cdxgen", "version": "12.6.0"}])
    report["components"].append(component)
    result = _extract(report, source_root="/home/alice/proj")
    record = next(r for r in result.records if r.subject.purls)
    assert record.subject.purls == ["pkg:generic/liba.so?path=build/liba.so"]
    assert record.subject.component_ref == "pkg:generic/liba.so?path=build/liba.so"
    _assert_no_machine_paths(result, "alice", "/home/")


# --- property values and names --------------------------------------------------


def test_only_path_named_properties_are_read_as_files_and_text_is_redacted():
    """A URL route in a property is kept as given; a path-named property
    outside the root is left out and counted; a command line keeps its text
    with the root and the home directory taken out."""
    report = _with_library(_report(), "/home/alice/proj/libs/libtrace-demo.dylib")
    report["components"][-1]["properties"].extend(
        [
            {"name": "cdx:dynamic:route", "value": "/api/v1/users"},
            {"name": "cdx:dynamic:configFile", "value": "/home/alice/secret/app.ini"},
            {
                "name": "cdx:dynamic:cmdline",
                "value": "python3 /home/alice/proj/app.py --cache /home/alice/.cache",
            },
        ]
    )
    result = _extract(report, source_root="/home/alice/proj")
    record = next(r for r in result.records if r.subject.purls)
    assert record.attributes["cdx:dynamic:route"] == "/api/v1/users"
    assert "cdx:dynamic:configFile" not in record.attributes
    assert record.attributes["cdx:dynamic:cmdline"] == "python3 app.py --cache ~/.cache"
    assert [c.kind for c in record.caveats] == ["location-outside-root"]
    _assert_no_machine_paths(result, "alice", "/home/")


def test_service_property_names_never_merge_with_service_fields():
    report = _report()
    report["services"][0]["properties"].extend(
        [
            {"name": "cdx:dynamic:name", "value": "other"},
            {"name": "egressDecision", "value": "denied"},
        ]
    )
    result = _extract(report)
    service = next(
        r for r in result.records if (r.attributes or {}).get("name") == "dynamic-localhost-8471"
    )
    assert service.attributes["name"] == "dynamic-localhost-8471"
    assert service.attributes["properties"] == {
        "cdx:dynamic:egressDecision": "allowed",
        "cdx:dynamic:name": "other",
        "egressDecision": "denied",
    }


def test_a_component_that_observed_nothing_is_counted():
    report = _report()
    report["components"].append({"name": "zlib", "type": "library", "purl": "pkg:generic/zlib"})
    result = _extract(report)
    assert len(result.records) == 6
    assert any(
        c.kind == "record-skipped"
        and c.detail.startswith("1 components carry no cdx:dynamic: property")
        for c in result.caveats
    )


# --- trace BOMs without a cdx:dynamic: property -----------------------------------


def test_an_ebpf_http_trace_is_a_trace_bom():
    """Services built from eBPF HTTP access entries carry only the
    ``cdx:service:httpMethod`` property and tracebom's service bom-ref."""
    report = _report()
    report["components"] = []
    report["services"] = [
        {
            "name": "dynamic-example.com",
            "bom-ref": "urn:service:dynamic:dynamic-example.com",
            "endpoints": ["http://example.com/api"],
            "properties": [{"name": "cdx:service:httpMethod", "value": "GET"}],
        }
    ]
    assert is_tracebom_report(report) is True
    result = _extract(report)
    assert result.status == STATUS_COMPLETED
    assert [r.attributes for r in result.records] == [
        {
            "name": "dynamic-example.com",
            "endpoints": ["http://example.com/api"],
            "properties": {"cdx:service:httpMethod": "GET"},
        }
    ]


def test_a_trace_that_saw_only_cryptography_is_a_trace_bom():
    report = _report()
    report["services"] = []
    assert is_tracebom_report(report) is True
    assert len(_extract(report).records) == 4
    # A cdxgen BOM that names its root component is a source BOM, even when
    # it carries cryptographic assets alone.
    report["metadata"]["component"] = {"name": "app", "type": "application"}
    assert is_tracebom_report(report) is False


def test_a_trace_bom_text_nested_too_deep_to_parse_is_not_assessed():
    result = extract("[" * 100000 + "]" * 100000, source=SOURCE, source_root=ROOT)
    assert result.status == STATUS_NOT_ASSESSED
    assert "deeper than this adapter reads" in result.reason
