"""Tests for the reachability analyzers.

The engine counts the evidence records of the scan directory's evidence
store: positive records of the counted kinds (reached-flow, usage,
entry-point) put their subject purls on an executed path, a record's
``servicePurls`` attribute and an entry point's handler purls feed the
reached-services set, and a reached purl typed ``framework`` in the BOM
and not filterable lands in the endpoint-reached set. Everything that does
not come from records keeps its behaviour: the occurrences in the BOMs feed
the direct purls and the endpoint set through the ``x-atom-usages`` usage
targets, and a post-build BOM feeds the binary reachability support.

Records reach the engine through the atom evidence adapter and the store:
the tests extract records from recorded slices, write them to an evidence
store in a temporary scan directory, and point a ``ReachabilityAnalysisKV``
at that directory.

Covers:
  - the counting rule over records, the records that never count as reached
    (callsites, dependency notes, negative polarity), and the duplicate
    collapse the store applies before the engine reads it
  - the perf-review rule on records: two producers whose records carry one
    purl each keep it in their own reached set
  - the recorded atom 4 slices under ``test/data/atom4`` (see the README
    next to them)
  - the pinned repotests data of the java-sec-code project, trimmed under
    ``tests/data/atom`` (slices) and ``tests/data/engine`` (BOM), whose
    reached sets the engine reproduces exactly
  - the streaming JSON array parser
"""

import json
from pathlib import Path

import pytest

from analysis_lib import ReachabilityAnalysisKV
from analysis_lib.evidence import EvidenceLocation, EvidencePathNode, EvidenceProducer
from analysis_lib.evidence.adapters import build_record
from analysis_lib.evidence.adapters.atom import extract as atom_extract
from analysis_lib.evidence.store import merge, read as read_store, write as write_store
from analysis_lib.reachability import (
    FrameworkReachability,
    SemanticReachability,
    _iter_json_list,
)

ATOM4_DIR = Path(__file__).resolve().parents[3] / "test" / "data" / "atom4"
ATOM4_REACHABLES = ATOM4_DIR / "python-reachables.slices.json"
ATOM4_OPENAPI = ATOM4_DIR / "python-openapi.json"
DATA_DIR = Path(__file__).resolve().parent / "data" / "atom"
PINNED_REACHABLES = DATA_DIR / "java-reachables.slices.json"
PINNED_USAGES = DATA_DIR / "java-usages.slices.json"
PINNED_CALLSITES = DATA_DIR / "java-callsites.slices.json"
PINNED_BOM = Path(__file__).resolve().parent / "data" / "engine" / "sbom-java.cdx.json"


def _write(path, obj):
    with open(path, mode="w", encoding="utf-8") as fp:
        json.dump(obj, fp)
    return path


def _producer(name):
    return EvidenceProducer(name=name, version="1.0.0", report_schema_version="4")


def _record(
    purls,
    *,
    producer_name="atom",
    kind="reached-flow",
    discriminator="d1",
    polarity="positive",
    source=None,
    attributes=None,
    confidence=None,
):
    """One evidence record of the given shape, built the way the adapters
    build theirs."""
    if source is None:
        source = "js-reachables.slices.json" if producer_name == "atom" else "other.slices.json"
    return build_record(
        source=source,
        producer=_producer(producer_name),
        kind=kind,
        discriminator=discriminator,
        polarity=polarity,
        purls=tuple(purls),
        attributes=attributes,
        confidence=confidence,
    )


def _fill_store(bom_dir, records):
    """Write the records to the evidence store of ``bom_dir`` and return the
    store path."""
    store = Path(bom_dir) / "evidence.jsonl"
    write_store(str(store), records)
    return str(store)


def _options(bom_dir, records=None, bom_files=None, openapi=None):
    """Options whose scan directory holds the given records as its evidence
    store."""
    if records is not None:
        _fill_store(bom_dir, records)
    return ReachabilityAnalysisKV(
        project_types=["js"],
        src_dir=str(bom_dir),
        bom_dir=str(bom_dir),
        bom_files=[str(p) for p in bom_files or []],
        slices_files=[],
        openapi_spec_files=[str(p) for p in openapi or []],
    )


# --- the KV resolves the evidence store path ---------------------------


def test_the_kv_resolves_the_evidence_file_from_bom_dir(tmp_path):
    """The evidence store sits at the top of the scan directory, resolved
    like the slices files are."""
    kv = ReachabilityAnalysisKV(
        project_types=["java"], src_dir=str(tmp_path), bom_dir=str(tmp_path)
    )
    assert kv.evidence_file == str((tmp_path / "evidence.jsonl").resolve())


def test_the_kv_keeps_an_explicit_evidence_file(tmp_path):
    other = tmp_path / "elsewhere" / "evidence.jsonl"
    kv = ReachabilityAnalysisKV(
        project_types=["java"],
        src_dir=str(tmp_path),
        bom_dir=str(tmp_path),
        evidence_file=str(other),
    )
    assert kv.evidence_file == str(other)


def test_the_kv_names_no_evidence_file_without_a_bom_dir(tmp_path):
    kv = ReachabilityAnalysisKV(project_types=["java"], src_dir=str(tmp_path), bom_dir=None)
    assert kv.evidence_file is None


# --- the counting rule over records -------------------------------------


def test_reached_purls_count_the_positive_records_of_the_counted_kinds(tmp_path):
    """Only positive records of the counted kinds put purls on an executed
    path. A callsite, a dependency note or a negative record is evidence
    about the package, never reached evidence."""
    records = [
        _record(["pkg:npm/reached-flow@1"], discriminator="r1"),
        _record(["pkg:npm/usage@1"], kind="usage", discriminator="r2"),
        _record(["pkg:npm/entry-point@1"], kind="entry-point", discriminator="r3"),
        _record(["pkg:npm/callsite@1"], kind="callsite", discriminator="r4"),
        _record(["pkg:npm/dependency@1"], kind="dependency", discriminator="r5"),
        _record(["pkg:npm/dead-code@1"], polarity="negative", discriminator="r6"),
        _record(["pkg:npm/negative-flow@1"], polarity="negative", discriminator="r7"),
    ]
    res = SemanticReachability(_options(tmp_path, records)).process()
    assert set((res.reached_purls or {}).keys()) == {
        "pkg:npm/reached-flow@1",
        "pkg:npm/usage@1",
        "pkg:npm/entry-point@1",
    }


def test_two_producers_sharing_a_purl_each_keep_it(tmp_path):
    """The perf-review rule on records: a purl two producers both reached
    stays in both of their reached sets. The records are not deduplicated
    against each other across producers, so the engine counts one record
    per producer and the grouping keeps the purl under each producer."""
    from analysis_lib.findings.vdr_convert import reached_by_analyzer

    records = [
        _record(["pkg:npm/shared@1"], producer_name="atom", source="js-reachables.slices.json"),
        _record(["pkg:npm/shared@1"], producer_name="golem", source="go-reachables.slices.json"),
    ]
    store = _fill_store(tmp_path, records)
    res = SemanticReachability(_options(tmp_path)).process()
    # The reached SET carries the purl once; the COUNT carries one entry per
    # producer record.
    assert (res.reached_purls or {})["pkg:npm/shared@1"] == 2
    grouped = reached_by_analyzer(read_store(store))
    assert grouped["atom"]["purls"] == {"pkg:npm/shared@1"}
    assert grouped["golem"]["purls"] == {"pkg:npm/shared@1"}
    # atom's purl types come from its records' source file prefix; the
    # language tools cover one ecosystem each and carry no types here.
    assert grouped["atom"]["types"] == {"npm"}
    assert grouped["golem"]["types"] == set()


def test_a_store_with_duplicate_records_does_not_double_count(tmp_path):
    """The enrichment stage can merge the same records twice; the store
    collapses exact duplicates, so the engine counts each record once."""
    records = [
        _record(["pkg:npm/dup@1"], discriminator="d1"),
        _record(["pkg:npm/other@1"], discriminator="d2"),
    ]
    store = _fill_store(tmp_path, merge(records, records))
    assert len(read_store(store)) == 2
    res = SemanticReachability(_options(tmp_path)).process()
    assert (res.reached_purls or {}) == {
        "pkg:npm/dup@1": 1,
        "pkg:npm/other@1": 1,
    }


def test_distinct_records_of_one_purl_each_count(tmp_path):
    """Counting is per record: two records that agree on the purl but differ
    otherwise are two pieces of reached evidence and count twice."""
    records = [
        _record(["pkg:npm/express@4.22.2"], discriminator="d1"),
        _record(["pkg:npm/express@4.22.2"], discriminator="d2"),
    ]
    res = SemanticReachability(_options(tmp_path, records)).process()
    assert set((res.reached_purls or {}).keys()) == {"pkg:npm/express@4.22.2"}
    assert (res.reached_purls or {})["pkg:npm/express@4.22.2"] == 2


def test_reached_services_come_from_the_record_service_purls(tmp_path):
    """A record's ``servicePurls`` attribute marks the subject purls the
    producer attributed to a service; a service purl that no subject purl
    carries is not counted, exactly as a tag naming a purl outside its flow
    was not."""
    records = [
        _record(
            ["pkg:npm/service-purl@1", "pkg:npm/plain@1"],
            discriminator="d1",
            attributes={"servicePurls": ["pkg:npm/service-purl@1"]},
        ),
        _record(
            ["pkg:npm/other@1"],
            discriminator="d2",
            attributes={"servicePurls": ["pkg:npm/not-a-subject@9"]},
        ),
    ]
    res = SemanticReachability(_options(tmp_path, records)).process()
    assert (res.reached_services or {}) == {"pkg:npm/service-purl@1": 1}
    assert set((res.reached_purls or {}).keys()) == {
        "pkg:npm/service-purl@1",
        "pkg:npm/plain@1",
        "pkg:npm/other@1",
    }


def test_entry_point_handler_purls_count_as_reached_services(tmp_path):
    """An entry point's handler purls are subject purls of an entry-point
    record; they count as reached services without a ``servicePurls``
    attribute, and a record that names its handler purl in the attribute
    as well still counts once."""
    records = [
        _record(
            ["pkg:npm/handler-a@1", "pkg:npm/handler-b@1"], kind="entry-point", discriminator="d1"
        ),
        _record(
            ["pkg:npm/handler-c@1"],
            kind="entry-point",
            discriminator="d2",
            attributes={"servicePurls": ["pkg:npm/handler-c@1"]},
        ),
    ]
    res = SemanticReachability(_options(tmp_path, records)).process()
    assert (res.reached_services or {}) == {
        "pkg:npm/handler-a@1": 1,
        "pkg:npm/handler-b@1": 1,
        "pkg:npm/handler-c@1": 1,
    }


def test_endpoint_reached_purls_follow_the_bom_types_and_the_filter_list(tmp_path):
    """A reached purl is endpoint-reachable when the BOM types it
    ``framework`` (by component type or by tag) and it is not on the filter
    list of safe build tools."""
    bom = _write(
        tmp_path / "bom.cdx.json",
        {
            "components": [
                {"type": "framework", "purl": "pkg:npm/framework-typed@1"},
                {"type": "library", "purl": "pkg:npm/tagged-framework@1", "tags": ["framework"]},
                {"type": "framework", "purl": "pkg:npm/bootstrap@5"},
                {"type": "library", "purl": "pkg:npm/plain@1"},
            ]
        },
    )
    records = [
        _record(
            ["pkg:npm/framework-typed@1", "pkg:npm/tagged-framework@1", "pkg:npm/bootstrap@5"],
            discriminator="d1",
        ),
        _record(["pkg:npm/plain@1"], discriminator="d2"),
    ]
    res = SemanticReachability(_options(tmp_path, records, bom_files=[bom])).process()
    assert set((res.endpoint_reached_purls or {}).keys()) == {
        "pkg:npm/framework-typed@1",
        "pkg:npm/tagged-framework@1",
    }


def _cdxgen_records(bom_path, base, source_root=None):
    """cdxgen's adapter records of one BOM, sourced the way the scan sources
    them: the file's path relative to the scan directory."""
    from analysis_lib.evidence.adapters import cdxgen as cdxgen_adapter
    from analysis_lib.reachability import report_source

    result = cdxgen_adapter.extract(
        bom_path.read_text(encoding="utf-8"),
        source=report_source(str(bom_path), str(base)),
        source_root=source_root,
    )
    assert result.status == "completed", result.reason
    return list(result.records)


def _usage_bom(path, location="src/app.js"):
    return _write(
        path,
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "components": [
                {
                    "type": "library",
                    "purl": "pkg:npm/used@1",
                    "bom-ref": "pkg:npm/used@1",
                    "evidence": {
                        "occurrences": [{"location": location}, {"location": "src/other.js"}]
                    },
                }
            ],
        },
    )


def test_usage_targets_still_reach_endpoints_through_bom_occurrences(tmp_path):
    """The OpenAPI usage targets and the BOM's occurrence records keep their
    role: a component whose own occurrence file is an ``x-atom-usages``
    target is endpoint-reachable even when no record types it framework."""
    bom = _usage_bom(tmp_path / "bom.cdx.json")
    openapi = _write(
        tmp_path / "openapi.json",
        {"paths": {"/x": {"x-atom-usages": {"call": {"src/app.js": [10]}}}}},
    )
    records = [_record(["pkg:npm/used@1"], discriminator="d1"), *_cdxgen_records(bom, tmp_path)]
    res = SemanticReachability(
        _options(tmp_path, records, bom_files=[bom], openapi=[openapi])
    ).process()
    assert (res.reached_purls or {}) == {"pkg:npm/used@1": 1}
    assert (res.endpoint_reached_purls or {}) == {"pkg:npm/used@1": 1}
    assert (res.direct_purls or {}) == {"pkg:npm/used@1": 2}


@pytest.mark.parametrize("spelling", ["relative", "absolute", "dot", "backslash"])
def test_endpoint_usage_targets_match_whatever_the_file_spelling(tmp_path, spelling):
    """atom-tools and cdxgen take the file names from the same atom slices,
    so an x-atom-usages key and an occurrence location share a spelling:
    relative, absolute under the source root, ``./``-prefixed, or with
    Windows backslashes. The adapter rewrites the location into its
    relative form, and the engine spells the key the same way, so each
    spelling makes the framework endpoint-reachable."""
    src = tmp_path / "src"
    src.mkdir()
    location = {
        "relative": "app/routes.py",
        "absolute": str(src / "app" / "routes.py"),
        "dot": "./app/routes.py",
        "backslash": "app\\routes.py",
    }[spelling]
    bom = _write(
        tmp_path / "sbom-python.cdx.json",
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "components": [
                {
                    "type": "framework",
                    "name": "flask",
                    "purl": "pkg:pypi/flask@3.1.3",
                    "bom-ref": "pkg:pypi/flask@3.1.3",
                    "evidence": {"occurrences": [{"location": location, "line": 4}]},
                }
            ],
        },
    )
    openapi = _write(
        tmp_path / "python-openapi.json",
        {"paths": {"/x": {"x-atom-usages": {"call": {location: [4]}}}}},
    )
    records = _cdxgen_records(bom, tmp_path, source_root=str(src))
    _fill_store(tmp_path, records)
    options = ReachabilityAnalysisKV(
        project_types=["python"],
        src_dir=str(src),
        bom_dir=str(tmp_path),
        bom_files=[str(bom)],
        slices_files=[],
        openapi_spec_files=[str(openapi)],
        source_root=str(src),
    )
    res = SemanticReachability(options).process()
    assert dict(res.direct_purls or {}) == {"pkg:pypi/flask@3.1.3": 1}
    assert dict(res.endpoint_reached_purls or {}) == {"pkg:pypi/flask@3.1.3": 1}


def _used(name, occurrences=1):
    return {
        "type": "library",
        "name": name,
        "purl": f"pkg:pypi/{name}@1.0",
        "bom-ref": f"pkg:pypi/{name}@1.0",
        "evidence": {"occurrences": [{"location": "app.py", "line": 3}] * occurrences},
    }


@pytest.mark.parametrize("analyzer", [FrameworkReachability, SemanticReachability])
def test_direct_purls_count_top_level_components_and_every_entry(tmp_path, analyzer):
    """A direct use is an occurrence entry of a top-level component, counted
    once per entry as the BOM lists them, identical entries included. The
    occurrences of a nested component and of a component nested in the
    root metadata component stay in the store as usage evidence but are not
    direct uses."""
    bom = _write(
        tmp_path / "sbom-python.cdx.json",
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "metadata": {
                "component": {
                    "type": "application",
                    "name": "root",
                    "purl": "pkg:pypi/root@1.0",
                    "evidence": {"occurrences": [{"location": "root.py"}]},
                    "components": [_used("mc")],
                }
            },
            "components": [{**_used("top", occurrences=2), "components": [_used("child", 2)]}],
        },
    )
    records = _cdxgen_records(bom, tmp_path)
    res = analyzer(_options(tmp_path, records, bom_files=[bom])).process()
    assert dict(res.direct_purls or {}) == {"pkg:pypi/top@1.0": 2}
    stored = {r.subject.purls[0] for r in read_store(str(tmp_path / "evidence.jsonl"))}
    assert {"pkg:pypi/mc@1.0", "pkg:pypi/child@1.0"} <= stored


@pytest.mark.parametrize("analyzer", [FrameworkReachability, SemanticReachability])
def test_direct_purls_count_the_occurrence_records_of_the_given_boms(tmp_path, analyzer):
    """Each cdxgen occurrence record of a BOM the analysis was given is one
    direct use of its package. The occurrence records of a BOM the analysis
    was not given (a user BOM outside the scan directory, which the BOM glob
    never finds) count nothing, and with nothing reached either the run is
    not a success."""
    given = _usage_bom(tmp_path / "bom.cdx.json")
    elsewhere_dir = tmp_path / "elsewhere"
    elsewhere_dir.mkdir()
    elsewhere = _usage_bom(elsewhere_dir / "user.cdx.json")
    records = _cdxgen_records(given, tmp_path)
    # The engine reads the records, never the BOM's evidence blocks: the
    # document on disk keeps its components and loses its evidence.
    stripped = json.loads(given.read_text(encoding="utf-8"))
    for component in stripped["components"]:
        component.pop("evidence")
    _write(given, stripped)
    res = analyzer(_options(tmp_path, records, bom_files=[given])).process()
    assert res.success is True
    assert dict(res.direct_purls or {}) == {"pkg:npm/used@1": 2}

    other = tmp_path / "other"
    other.mkdir()
    records = _cdxgen_records(elsewhere, other)
    res = analyzer(_options(other, records, bom_files=[])).process()
    assert dict(res.direct_purls or {}) == {}
    assert res.success is False


def _flask_bom(path):
    """The shape of a default Python scan's pre-build BOM: Flask declared at
    2.2.0 in requirements.txt, and again at 3.1.3, the newest release, which
    cdxgen picked for the ``import flask`` lines because the source does not
    say which release it uses. Trimmed from a real scan."""
    return _write(
        path,
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "metadata": {"lifecycles": [{"phase": "pre-build"}]},
            "components": [
                {
                    "type": "framework",
                    "name": "Flask",
                    "version": "2.2.0",
                    "purl": "pkg:pypi/flask@2.2.0",
                    "bom-ref": "pkg:pypi/flask@2.2.0",
                    "evidence": {
                        "identity": [
                            {
                                "field": "purl",
                                "confidence": 0.5,
                                "methods": [
                                    {
                                        "technique": "manifest-analysis",
                                        "confidence": 0.5,
                                        "value": "requirements.txt",
                                    }
                                ],
                            }
                        ],
                        "occurrences": [{"location": "requirements.txt"}],
                    },
                },
                {
                    "type": "framework",
                    "name": "Flask",
                    "version": "3.1.3",
                    "purl": "pkg:pypi/flask@3.1.3",
                    "bom-ref": "pkg:pypi/flask@3.1.3",
                    "evidence": {
                        "identity": [
                            {
                                "field": "version",
                                "confidence": 0.5,
                                "methods": [
                                    {
                                        "technique": "source-code-analysis",
                                        "confidence": 0.5,
                                        "value": "PyPI package: Flask",
                                    }
                                ],
                            }
                        ],
                        "occurrences": [
                            {"location": "app.py", "line": 1},
                            {"location": "app.py", "line": 5},
                        ],
                    },
                },
            ],
        },
    )


@pytest.mark.parametrize("analyzer", [FrameworkReachability, SemanticReachability])
def test_an_inferred_version_is_counted_under_the_declared_one(tmp_path, analyzer):
    """The occurrences and reached flows cdxgen recorded against Flask 3.1.3,
    a version it inferred from the imports, belong to the Flask 2.2.0 the
    project declares and the findings name."""
    bom = _flask_bom(tmp_path / "bom.cdx.json")
    openapi = _write(
        tmp_path / "openapi.json",
        {"paths": {"/x": {"x-atom-usages": {"call": {"app.py": [5]}}}}},
    )
    records = [
        _record(["pkg:pypi/flask@3.1.3"], discriminator="d1"),
        *_cdxgen_records(bom, tmp_path),
    ]
    options = _options(tmp_path, records, bom_files=[bom], openapi=[openapi])
    res = analyzer(options).process()
    assert (res.direct_purls or {}) == {"pkg:pypi/flask@2.2.0": 3}
    assert (res.reached_purls or {}) == {"pkg:pypi/flask@2.2.0": 1}
    if analyzer is SemanticReachability:
        assert (res.endpoint_reached_purls or {}) == {"pkg:pypi/flask@2.2.0": 3}


def test_two_declared_versions_keep_the_inferred_one_apart(tmp_path):
    """With two declared versions there is no one component the inferred
    version belongs to, so its purl is left alone."""
    bom = _flask_bom(tmp_path / "bom.cdx.json")
    document = json.loads(bom.read_text(encoding="utf-8"))
    extra = json.loads(json.dumps(document["components"][0]))
    extra["purl"] = extra["bom-ref"] = "pkg:pypi/flask@2.1.0"
    document["components"].append(extra)
    _write(bom, document)
    records = [_record(["pkg:pypi/flask@3.1.3"], discriminator="d1")]
    res = SemanticReachability(_options(tmp_path, records, bom_files=[bom])).process()
    assert (res.reached_purls or {}) == {"pkg:pypi/flask@3.1.3": 1}


@pytest.mark.parametrize("analyzer", [FrameworkReachability, SemanticReachability])
def test_one_occurrence_listed_by_two_lifecycle_boms_is_one_use(tmp_path, analyzer):
    """A default research scan writes a pre-build and a build BOM that list
    the same occurrences. "Used in N locations" counts each place once, while
    an occurrence a single document lists twice stays two uses."""
    first = _usage_bom(tmp_path / "sbom-prebuild-universal.cdx.json")
    second = _usage_bom(tmp_path / "sbom-build-universal.cdx.json")
    records = [*_cdxgen_records(first, tmp_path), *_cdxgen_records(second, tmp_path)]
    assert len(records) == 4
    res = analyzer(_options(tmp_path, records, bom_files=[first, second])).process()
    assert dict(res.direct_purls or {}) == {"pkg:npm/used@1": 2}
    # The same package seen at a place only the second document lists counts.
    third = _usage_bom(tmp_path / "sbom-postbuild-universal.cdx.json", location="src/new.js")
    more = [*records, *_cdxgen_records(third, tmp_path)]
    res = analyzer(_options(tmp_path, more, bom_files=[first, second, third])).process()
    assert dict(res.direct_purls or {}) == {"pkg:npm/used@1": 3}


def test_atom_usages_are_attributed_to_the_packages_they_call(tmp_path):
    """A usage whose path calls ``flask.Flask.route`` is about the package
    that occurs in the usage's file and is imported as ``flask``; a package
    in the file that no path names, and a file no package occurs in, get
    nothing."""
    from analysis_lib.reachability import attribute_atom_usages

    bom = _write(
        tmp_path / "bom.cdx.json",
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [
                {
                    "type": "library",
                    "purl": f"pkg:pypi/{name}@1.0",
                    "bom-ref": f"pkg:pypi/{name}@1.0",
                    "evidence": {"occurrences": [{"location": "app.py", "line": 1}]},
                }
                for name in ("flask", "requests")
            ],
        },
    )

    def usage(file, discriminator):
        return build_record(
            source="universal-usages.slices.json",
            producer=_producer("atom"),
            kind="usage",
            discriminator=discriminator,
            purls=(),
            locations=(EvidenceLocation(file=file, line=1),),
            path=(EvidencePathNode(symbol="route", method="flask.Flask.route"),),
        )

    here, elsewhere = usage("app.py", "u"), usage("other.py", "v")
    attributed = attribute_atom_usages([*_cdxgen_records(bom, tmp_path), here, elsewhere])
    assert [(r.subject.purls, r.path[0].method) for r in attributed] == [
        (["pkg:pypi/flask@1.0"], "flask.Flask.route")
    ]
    assert attributed[0].id != here.id


def test_atom_usages_are_attributed_by_the_module_names_cdxgen_declares(tmp_path):
    """PyYAML is imported as ``yaml`` and beautifulsoup4 as ``bs4``; cdxgen
    writes those names on the component as it does for a real scan
    (``internal:Namespaces`` one per line, ``internal:ImportedModules``
    comma-separated with symbols, and ``cdx:pypi:modulesFrom`` for where they
    came from). A usage of a module no component declares stays unattributed."""
    from analysis_lib.reachability import attribute_atom_usages, declared_modules

    def component(name, props):
        purl = f"pkg:pypi/{name}@1.0"
        return {
            "type": "library",
            "name": name,
            "purl": purl,
            "bom-ref": purl,
            "properties": [{"name": k, "value": v} for k, v in props.items()],
            "evidence": {"occurrences": [{"location": "app.py", "line": 1}]},
        }

    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            component(
                "PyYAML",
                {
                    "internal:Namespaces": "yaml",
                    "cdx:pypi:modulesFrom": "alias-map,distribution-name",
                },
            ),
            component(
                "beautifulsoup4",
                {
                    "internal:ImportedModules": "bs4.BeautifulSoup,bs4",
                    "internal:Namespaces": "bs4",
                },
            ),
        ],
    }
    bom = _write(tmp_path / "bom.cdx.json", document)

    def usage(method, discriminator):
        return build_record(
            source="universal-usages.slices.json",
            producer=_producer("atom"),
            kind="usage",
            discriminator=discriminator,
            purls=(),
            locations=(EvidenceLocation(file="app.py", line=1),),
            path=(EvidencePathNode(symbol="x", method=method),),
        )

    records = [
        *_cdxgen_records(bom, tmp_path),
        usage("yaml.safe_load", "a"),
        usage("bs4.BeautifulSoup", "b"),
        usage("toml.loads", "c"),
    ]
    # Without the declared names the purl name alone finds neither package.
    assert attribute_atom_usages(records) == []
    attributed = attribute_atom_usages(records, declared_modules([document]))
    assert sorted((r.path[0].method, r.subject.purls[0].lower()) for r in attributed) == [
        ("bs4.BeautifulSoup", "pkg:pypi/beautifulsoup4@1.0"),
        ("yaml.safe_load", "pkg:pypi/pyyaml@1.0"),
    ]
    assert all(r.caveats[-1].kind == "attributed" for r in attributed)
    assert any("the module yaml" in r.caveats[-1].detail for r in attributed)


def test_binary_reachability_still_reaches_post_build_frameworks(tmp_path):
    """A post-build BOM keeps its binary reachability: a post-build purl
    that matches a framework-typed component counts as reached through the
    component it names, with no record behind it. The endpoint extension of
    that support only extends an endpoint set the records already started,
    so a scan whose records reached nothing endpoint-wise keeps the empty
    endpoint set."""
    bom = _write(
        tmp_path / "bom.cdx.json",
        {
            "metadata": {"lifecycles": [{"phase": "post-build"}]},
            "components": [
                {"type": "framework", "purl": "pkg:maven/com.example/framework@2.0.0"},
                {"type": "framework", "purl": "pkg:maven/com.example/other@1.0.0"},
                {"type": "library", "purl": "pkg:maven/com.example/lib@1.0.0"},
            ],
        },
    )
    openapi = _write(
        tmp_path / "openapi.json",
        {"paths": {"/x": {"x-atom-usages": {"call": {"App.kt": [3]}}}}},
    )
    records = [_record(["pkg:maven/com.example/other@1.0.0"], discriminator="d1")]
    res = SemanticReachability(
        _options(tmp_path, records, bom_files=[bom], openapi=[openapi])
    ).process()
    # The record reaches ``other``; the binary support reaches ``framework``
    # through the post-build purl, counts ``other`` a second time through
    # the framework component it names, and the unmatched ``lib`` stays out.
    assert (res.reached_purls or {}) == {
        "pkg:maven/com.example/other@1.0.0": 2,
        "pkg:maven/com.example/framework@2.0.0": 1,
    }
    assert (res.endpoint_reached_purls or {}) == {
        "pkg:maven/com.example/other@1.0.0": 2,
        "pkg:maven/com.example/framework@2.0.0": 1,
    }


def test_a_scan_without_a_store_and_without_a_bom_is_not_a_clean_result(tmp_path):
    """A scan directory whose evidence store is missing reads as no reached
    evidence, and the analyzer reports no success: an empty result never
    pretends the analysis ran clean. The store path is passed explicitly so
    the test pins the engine's handling of a resolved path with no file
    behind it."""
    kv = ReachabilityAnalysisKV(
        project_types=["js"],
        src_dir=str(tmp_path),
        bom_dir=str(tmp_path),
        bom_files=[],
        slices_files=[],
        openapi_spec_files=[],
        evidence_file=str((tmp_path / "evidence.jsonl").resolve()),
    )
    res = SemanticReachability(kv).process()
    assert res.success is False
    assert not res.reached_purls


# --- FrameworkReachability counts the same records -----------------------


def test_framework_reachability_counts_the_records_without_services(tmp_path):
    """FrameworkReachability keeps its shape: reached purls from the same
    records, no services dict of its own."""
    records = [
        _record(["pkg:npm/express@4.22.2"], discriminator="d1"),
        _record(
            ["pkg:npm/lodash@4.17.21"],
            kind="callsite",
            discriminator="d2",
        ),
    ]
    res = FrameworkReachability(_options(tmp_path, records)).process()
    assert set((res.reached_purls or {}).keys()) == {"pkg:npm/express@4.22.2"}
    assert res.reached_services is None or res.reached_services == {}


# --- the recorded atom 4 slices (test/data/atom4) ----------------------


def _atom4_records(tmp_path):
    """The records of the recorded atom 4 slices, written to the temporary
    scan directory's evidence store."""
    result = atom_extract(
        [ATOM4_REACHABLES],
        producer_version="4.0.2",
        openapi_files=[ATOM4_OPENAPI],
    )
    assert result.status == "completed"
    _fill_store(tmp_path, result.records)
    return result.records


def _atom4_options(bom_dir):
    """Options pointing at the recorded atom 4 fixture set."""
    return ReachabilityAnalysisKV(
        project_types=["python"],
        src_dir=str(bom_dir),
        bom_dir=str(bom_dir),
        bom_files=[str(ATOM4_DIR / "sbom-python.cdx.json")],
        slices_files=[],
        openapi_spec_files=[str(ATOM4_OPENAPI)],
    )


def test_recorded_atom4_reachables_reach_their_purls(tmp_path):
    """FrameworkReachability on the records of the recorded atom 4.0.2
    slices. The reached set is the four purls the five recorded flows
    carry; the counts follow the flows: the two quart flows contribute one
    count each because their flow objects differ."""
    _atom4_records(tmp_path)
    res = FrameworkReachability(_atom4_options(tmp_path)).process()
    assert res.success
    assert (res.reached_purls or {}) == {
        "pkg:pypi/custom-json-diff@2.1.6": 2,
        "pkg:pypi/quart@0.22.0": 2,
        "pkg:pypi/quart@0.23.1": 2,
        "pkg:pypi/rich@15.0.0": 1,
    }


def test_recorded_atom4_semantic_reachability(tmp_path):
    """SemanticReachability on the records of the recorded atom 4 fixture
    set. The recorded BOM types both quart versions as framework, so they
    are endpoint-reachable; the recorded tags carry no service tag, so no
    package is a reached service."""
    _atom4_records(tmp_path)
    res = SemanticReachability(_atom4_options(tmp_path)).process()
    assert res.success
    assert set((res.reached_purls or {}).keys()) == {
        "pkg:pypi/custom-json-diff@2.1.6",
        "pkg:pypi/quart@0.22.0",
        "pkg:pypi/quart@0.23.1",
        "pkg:pypi/rich@15.0.0",
    }
    assert res.reached_services == {}
    assert set((res.endpoint_reached_purls or {}).keys()) == {
        "pkg:pypi/quart@0.22.0",
        "pkg:pypi/quart@0.23.1",
    }


def test_recorded_atom4_openapi_usage_targets():
    """The recorded atom-tools 1.x OpenAPI document lights up usage targets.

    ``x-atom-usages`` values are per-file lists for both ``call`` and
    ``target`` (atom-tools 0.9.x wrote ``target`` as a bare int), and the
    recorded server endpoint is the call at simple.py line 433.
    """
    kv = _atom4_options(ATOM4_DIR)
    usage_targets = {}
    for ospec in kv.openapi_spec_files or []:
        spec_data = json.loads(Path(ospec).read_text())
        for path_obj in (spec_data.get("paths") or {}).values():
            if isinstance(path_obj, dict) and "x-atom-usages" in path_obj:
                SemanticReachability._track_usage_targets(usage_targets, path_obj["x-atom-usages"])
    assert "packages/server-lib/src/server_lib/simple.py" in usage_targets
    assert usage_targets["packages/server-lib/src/server_lib/simple.py#433"]
    # The target entries are lists; their lines are tracked the same way.
    assert usage_targets["packages/analysis-lib/src/analysis_lib/output.py#985"]


# --- _track_usage_targets shape tolerance ------------------------------


def test_track_usage_targets_list_lines():
    """The atom-tools 1.x shape: every per-file value is a list of line
    numbers, ``call`` and ``target`` alike."""
    usage_targets = {}
    SemanticReachability._track_usage_targets(
        usage_targets, {"call": {"Foo.java": [10, 20]}, "target": {"Foo.java": [15]}}
    )
    assert usage_targets == {
        "Foo.java": True,
        "Foo.java#10": True,
        "Foo.java#20": True,
        "Foo.java#15": True,
    }


def test_track_usage_targets_ignores_non_list_values():
    """Values that are not lists (e.g. the bare int atom-tools 0.9.x wrote
    for ``target``) mark the file but contribute no line: the shape is gone
    and a guessed line would be a hotspot that is not one."""
    usage_targets = {}
    SemanticReachability._track_usage_targets(usage_targets, {"target": {"Foo.java": 42}})
    assert usage_targets == {"Foo.java": True}


def test_track_usage_targets_ignores_non_dict_values():
    """Garbage shapes are skipped rather than crashing."""
    usage_targets = {}
    SemanticReachability._track_usage_targets(usage_targets, {"GET /x": ["not", "a", "dict"]})
    SemanticReachability._track_usage_targets(usage_targets, "not a dict")
    assert usage_targets == {}


# --- the pinned repotests data (java-sec-code) -------------------------


def _pinned_records(tmp_path):
    """The records of the pinned java-sec-code slices, written to the
    temporary scan directory's evidence store."""
    result = atom_extract(
        [PINNED_REACHABLES],
        producer_version="4.0.2",
        usages_files=[PINNED_USAGES],
        callsites_files=[PINNED_CALLSITES],
    )
    assert result.status == "completed"
    _fill_store(tmp_path, result.records)
    return result.records


def test_pinned_java_sec_code_keeps_the_slices_reached_sets(tmp_path):
    """The engine reproduces the reached sets the slices counting gives on
    the pinned java-sec-code data, services and endpoint reachability
    included, records driving every part of it.

    The pinned slices carry thirteen reachables flows over thirteen maven
    purls. slf4j-api is the purl of two of the flows, so it counts twice;
    one flow's tags name the service ``sql`` ahead of slf4j-api's purl
    (atom's callee-purl order), so slf4j-api is the only reached service.
    The BOM types seven of the purls framework and none is on the filter
    list, so the endpoint set is those seven. The usages and callsites
    slices the adapter also reads must not move any set: their records are
    usage records without purls and callsite records, which never count.
    """
    records = _pinned_records(tmp_path)
    res = SemanticReachability(_options(tmp_path, bom_files=[PINNED_BOM])).process()
    assert res.success
    assert (res.reached_purls or {}) == {
        "pkg:maven/com.alibaba/fastjson@1.2.24?type=jar": 1,
        "pkg:maven/com.auth0/java-jwt@4.0.0?type=jar": 1,
        "pkg:maven/com.squareup.okhttp/okhttp@2.5.0?type=jar": 1,
        "pkg:maven/commons-collections/commons-collections@3.1?type=jar": 1,
        "pkg:maven/org.apache.httpcomponents/httpclient@4.5.12?type=jar": 1,
        "pkg:maven/org.apache.logging.log4j/log4j-core@2.9.1?type=jar": 1,
        "pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.85?type=jar": 1,
        "pkg:maven/org.codehaus.groovy/groovy@2.4.7?type=jar": 1,
        "pkg:maven/org.jsoup/jsoup@1.10.2?type=jar": 1,
        "pkg:maven/org.slf4j/slf4j-api@1.7.22?type=jar": 2,
        "pkg:maven/org.springframework/spring-context@4.3.6.RELEASE?type=jar": 1,
        "pkg:maven/org.springframework/spring-web@4.3.6.RELEASE?type=jar": 1,
        "pkg:maven/org.yaml/snakeyaml@1.21?type=jar": 1,
    }
    assert (res.reached_services or {}) == {
        "pkg:maven/org.slf4j/slf4j-api@1.7.22?type=jar": 1,
    }
    assert (res.endpoint_reached_purls or {}) == {
        "pkg:maven/commons-collections/commons-collections@3.1?type=jar": 1,
        "pkg:maven/org.apache.httpcomponents/httpclient@4.5.12?type=jar": 1,
        "pkg:maven/org.apache.logging.log4j/log4j-core@2.9.1?type=jar": 1,
        "pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.85?type=jar": 1,
        "pkg:maven/org.slf4j/slf4j-api@1.7.22?type=jar": 2,
        "pkg:maven/org.springframework/spring-context@4.3.6.RELEASE?type=jar": 1,
        "pkg:maven/org.springframework/spring-web@4.3.6.RELEASE?type=jar": 1,
    }
    # The store holds every distinct record the adapter gave; the exact
    # duplicates among the usages entries collapsed.
    from analysis_lib.evidence.store import canonical_record

    assert len(read_store(str(Path(tmp_path) / "evidence.jsonl"))) == len(
        {canonical_record(record) for record in records}
    )


def test_pinned_java_sec_code_framework_reachability(tmp_path):
    """FrameworkReachability reaches the same purls on the pinned data,
    without services of its own."""
    _pinned_records(tmp_path)
    res = FrameworkReachability(_options(tmp_path, bom_files=[PINNED_BOM])).process()
    assert res.success
    assert set((res.reached_purls or {}).keys()) >= {
        "pkg:maven/org.slf4j/slf4j-api@1.7.22?type=jar",
    }
    assert res.reached_services is None or res.reached_services == {}


def test_pinned_java_sec_code_analyzer_grouping(tmp_path):
    """The grouping the grading stage reads from the pinned store: every
    reached-counted record lands under its producer, and atom's purl types
    come from the reachables file prefix."""
    from analysis_lib.findings.vdr_convert import reached_by_analyzer

    records = _pinned_records(tmp_path)
    grouped = reached_by_analyzer(records)
    assert set(grouped) == {"atom"}
    assert grouped["atom"]["types"] == {"maven"}
    flow_purls = {
        purl
        for record in records
        if record.kind == "reached-flow" and record.polarity == "positive"
        for purl in record.subject.purls
    }
    assert grouped["atom"]["purls"] == flow_purls


# --- streaming JSON parser ---------------------------------------------


def _write_raw(path, text):
    with open(path, mode="w", encoding="utf-8") as fp:
        fp.write(text)
    return path


def test_iter_json_list_yields_each_element(tmp_path):
    """A top-level JSON list is streamed one parsed element at a time."""
    text = '[{"id": 1}, {"id": 2}, {"id": 3}]'
    assert list(_iter_json_list(_write_raw(tmp_path / "_r3c_test_1.json", text))) == [
        {"id": 1},
        {"id": 2},
        {"id": 3},
    ]


def test_iter_json_list_tolerates_whitespace_between_elements(tmp_path):
    text = '[\n  {"a": 1},\n  {"b": 2},\n\n  {"c": 3}\n]'
    out = list(_iter_json_list(_write_raw(tmp_path / "_r3c_test_2.json", text)))
    assert out == [{"a": 1}, {"b": 2}, {"c": 3}]


def test_iter_json_list_empty_list_yields_nothing(tmp_path):
    assert list(_iter_json_list(_write_raw(tmp_path / "_r3c_test_3.json", "[]"))) == []
    # With whitespace
    assert list(_iter_json_list(_write_raw(tmp_path / "_r3c_test_4.json", "[  ]"))) == []


def test_iter_json_list_handles_nested_objects_and_strings_with_commas(tmp_path):
    """Commas inside strings or nested objects must not break element scan."""
    text = '[{"tags": "a, b, c", "nested": {"x": 1, "y": [1, 2, 3]}}, {"id": 2}]'
    out = list(_iter_json_list(_write_raw(tmp_path / "_r3c_test_5.json", text)))
    assert out == [
        {"tags": "a, b, c", "nested": {"x": 1, "y": [1, 2, 3]}},
        {"id": 2},
    ]


def test_iter_json_list_returns_nothing_for_non_list_top_level(tmp_path):
    """A wrapped envelope (e.g. {"reachables": [...]}) is not a slice atom
    writes; it is not streamed and yields nothing."""
    f = tmp_path / "wrapped.json"
    _write_raw(f, '{"reachables": [{"id": 1}]}')
    assert list(_iter_json_list(str(f))) == []


def test_iter_json_list_missing_file_yields_nothing():
    assert list(_iter_json_list("/nonexistent/path/to/file.json")) == []


def test_iter_json_list_matches_json_load_on_real_slices(tmp_path):
    """Streaming parser must produce identical elements to json.load on a
    realistic reachables slice (atom shape)."""
    payload = [
        {
            "flows": [
                {
                    "id": f"node-{i}-a",
                    "tags": f"pkg:npm/express@4.22.2, framework, web, marker-{i}",
                    "code": "function() { return arg + 1; }",
                    "signature": "L: int -> int",
                    "fullName": f"module.fn{i}a",
                    "lineNumber": i * 10,
                    "columnNumber": i,
                },
                {
                    "id": f"node-{i}-b",
                    "tags": "framework-output",
                    "code": "return value;",
                },
            ],
            "purls": ["pkg:npm/express@4.22.2", f"pkg:npm/pkg{i}@1.{i}.0"],
        }
        for i in range(50)
    ]
    f = tmp_path / "js-reachables.slices.json"
    _write(f, payload)
    streamed = list(_iter_json_list(str(f)))
    import json as _json

    with open(f) as fp:
        loaded = _json.load(fp)
    assert streamed == loaded


# --- a stated Low confidence never counts -----------------------------------


def _confidence_records():
    """One reached record per stated confidence, for every counted kind, and
    a Low record that names a service and a framework."""
    records = []
    for index, (confidence, kind) in enumerate(
        [
            ("Low", "reached-flow"),
            ("low", "usage"),
            (" LOW ", "entry-point"),
            ("Medium", "reached-flow"),
            ("high", "reached-flow"),
            (None, "reached-flow"),
        ]
    ):
        records.append(
            _record(
                [f"pkg:npm/{kind}-{(confidence or 'none').strip().lower()}@1"],
                kind=kind,
                producer_name="golem",
                discriminator=f"c{index}",
                confidence=confidence,
            )
        )
    records.append(
        _record(
            ["pkg:npm/express@4.0.0"],
            producer_name="golem",
            discriminator="svc",
            confidence="Low",
            attributes={"servicePurls": ["pkg:npm/express@4.0.0"]},
        )
    )
    return records


def test_a_record_stating_low_confidence_never_counts_as_reached(tmp_path):
    """The rule holds for every producer and every counted kind: a record
    whose stated confidence is Low, in any letter case, puts no purl in the
    reached set and no service in the reached services; Medium, High and an
    absent confidence count."""
    res = SemanticReachability(_options(tmp_path, _confidence_records())).process()
    assert set((res.reached_purls or {}).keys()) == {
        "pkg:npm/reached-flow-medium@1",
        "pkg:npm/reached-flow-high@1",
        "pkg:npm/reached-flow-none@1",
    }
    assert set((res.reached_services or {}).keys()) == set()


def test_framework_reachability_skips_low_confidence_records_too(tmp_path):
    res = FrameworkReachability(_options(tmp_path, _confidence_records())).process()
    assert set((res.reached_purls or {}).keys()) == {
        "pkg:npm/reached-flow-medium@1",
        "pkg:npm/reached-flow-high@1",
        "pkg:npm/reached-flow-none@1",
    }


def test_reached_by_analyzer_skips_low_confidence_records():
    from analysis_lib.findings.vdr_convert import reached_by_analyzer

    grouped = reached_by_analyzer(_confidence_records())
    assert grouped["golem"]["purls"] == {
        "pkg:npm/reached-flow-medium@1",
        "pkg:npm/reached-flow-high@1",
        "pkg:npm/reached-flow-none@1",
    }
