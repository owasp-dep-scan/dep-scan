"""The join evaluators, tested on hand-built scan directories.

The join tests write tiny BOM and evidence files with known answers, so a
broken join shows as a failed assertion rather than as an empty result.
"""

import json


from contrib.corpus import score as corpus_score
from analysis_lib.evidence import (
    Evidence,
    EvidenceCaveat,
    EvidenceLocation,
    EvidenceProducer,
    EvidenceSubject,
)


def _write_bom(reports_dir, name, components, tool=None):
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {"tools": {"components": [{"name": tool}] if tool else []}},
        "components": [
            {"purl": purl, "type": "library", "bom-ref": f"r{i}"}
            for i, purl in enumerate(components)
        ],
    }
    (reports_dir / name).write_text(json.dumps(document), encoding="utf-8")


def _record(producer, kind, purls, locations=None, attributes=None):
    location = EvidenceLocation(
        file=locations[0][0] if locations else "",
        line=locations[0][1] if locations else None,
    )
    return Evidence(
        schema_version="1",
        id=f"ev-{producer}-{kind}-{abs(hash(tuple(purls)))}",
        producer=EvidenceProducer(name=producer, version="1", report_schema_version="1"),
        kind=kind,
        polarity="positive",
        subject=EvidenceSubject(purls=list(purls)),
        source="fixture",
        locations=[EvidenceLocation(file=f, line=ln) for f, ln in (locations or [])],
        caveats=[EvidenceCaveat(kind="coverage-gap", detail="test fixture")],
        attributes=attributes,
    )


def _write_evidence(reports_dir, records):
    lines = []
    for record in records:
        document = json.loads(json.dumps(record.to_dict(), default=lambda o: o.to_dict()))
        lines.append(json.dumps(document))
    (reports_dir / "evidence.jsonl").write_text("\n".join(lines), encoding="utf-8")


def _result(reports_dir):
    from types import SimpleNamespace

    return SimpleNamespace(
        reports_dir=str(reports_dir), findings=[], manifest={"stages": []}, project_types=[]
    )


def test_two_manifests_counts_two_versions_and_declaring_paths(tmp_path):
    _write_bom(
        tmp_path,
        "sbom-js.cdx.json",
        ["pkg:npm/ms@2.1.3", "pkg:npm/ms@0.7.1", "pkg:npm/express@4.19.2"],
    )
    labels = {
        "joins": {
            "two-manifests": {
                "source": "hand",
                "package": "pkg:npm/ms",
                "versions": ["2.1.3", "0.7.1"],
            }
        }
    }
    item = {"scan": {"types": ["js"], "args": []}}
    scored = corpus_score.score_join_two_manifests(
        corpus_score.ItemScan(item, _result(tmp_path)), labels
    )
    assert scored["outcome"] == "measured"
    assert scored["distinctVersions"] == ["0.7.1", "2.1.3"]
    # The fixture BOMs carry no SrcFile property, so the declaring path is
    # the field the score reports as missing.
    assert scored["withDeclaringPath"] == 0


def test_two_producers_measures_one_identity_across_types(tmp_path):
    _write_bom(
        tmp_path,
        "sbom-build-go.cdx.json",
        ["pkg:golang/github.com/google/go-github/v81@v81.0.0", "pkg:golang/gin-gonic/gin@v1.9.1"],
        tool="cdxgen",
    )
    _write_bom(
        tmp_path,
        "sbom-binary.cdx.json",
        ["pkg:golang/github.com/google/go-github/v81@v81.0.0", "pkg:golang/go-jwt/jwt/v4@v4.5.0"],
        tool="blint",
    )
    _write_evidence(
        tmp_path,
        [
            _record("cdxgen", "dependency", ["pkg:golang/gin-gonic/gin@v1.9.1"]),
            _record("blint", "dependency", ["pkg:golang/go-jwt/jwt/v4@v4.5.0"]),
        ],
    )
    labels = {
        "joins": {
            "two-producers": {
                "source": "hand",
                "package": "pkg:golang/github.com/google/go-github/v81",
            }
        }
    }
    item = {"scan": {"types": ["go", "binary"], "args": []}}
    scored = corpus_score.score_join_two_producers(
        corpus_score.ItemScan(item, _result(tmp_path)), labels
    )
    assert scored["outcome"] == "measured"
    assert scored["identical"] is True
    assert sorted(scored["byProducer"]) == ["blint", "cdxgen"]
    assert scored["producers"] == ["blint", "cdxgen"]


def test_two_producers_counts_producers_not_bom_files(tmp_path):
    # A type BOM and its build-phase copy come from one producer.
    package = "pkg:golang/github.com/google/go-github/v81@v81.0.0"
    for name in ("sbom-go.cdx.json", "sbom-build-go.cdx.json"):
        _write_bom(tmp_path, name, [package], tool="cdxgen")
    labels = {"joins": {"two-producers": {"source": "hand", "package": package}}}
    item = {"scan": {"types": ["go"], "args": []}}
    scored = corpus_score.score_join_two_producers(
        corpus_score.ItemScan(item, _result(tmp_path)), labels
    )
    assert scored["outcome"] == "not-assessed"
    assert "1 BOM producer ran (cdxgen)" in scored["reason"]
    # A second producer that lacks the package leaves the join partial.
    _write_bom(tmp_path, "sbom-binary.cdx.json", [], tool="blint")
    scored = corpus_score.score_join_two_producers(
        corpus_score.ItemScan(item, _result(tmp_path)), labels
    )
    assert scored["outcome"] == "partial"
    assert list(scored["byProducer"]) == ["cdxgen"]


def test_route_join_matches_dosai_handler_spans(tmp_path):
    # /weather's handler at Program.cs:8 with Newtonsoft on line 11 inside
    # the span; /health at line 16 with nothing third-party inside.
    _write_evidence(
        tmp_path,
        [
            _record(
                "dosai",
                "entry-point",
                [],
                locations=[("Program.cs", 8)],
                attributes={"entryPointId": "ep:op:svc:minimal-api:_/Program.cs#GET:/weather"},
            ),
            _record(
                "dosai",
                "entry-point",
                [],
                locations=[("Program.cs", 16)],
                attributes={"entryPointId": "ep:op:svc:minimal-api:_/Program.cs#GET:/health"},
            ),
            _record(
                "dosai",
                "reached-flow",
                ["pkg:nuget/Newtonsoft.Json@13.0.3"],
                locations=[("Program.cs", 11)],
            ),
        ],
    )
    labels = {
        "joins": {
            "route-package": {
                "source": "hand",
                "routes": [
                    {
                        "path": "/weather",
                        "method": "GET",
                        "packages": ["pkg:nuget/Newtonsoft.Json@13.0.3"],
                    },
                    {
                        "path": "/health",
                        "method": "GET",
                        "controls": ["pkg:nuget/Newtonsoft.Json@13.0.3"],
                    },
                ],
            }
        }
    }
    item = {"scan": {"types": ["dotnet"], "args": []}}
    scored = corpus_score.score_join_route_package(
        corpus_score.ItemScan(item, _result(tmp_path)), labels
    )
    assert scored["outcome"] == "measured"
    assert scored["routesMatched"] == 2


def test_route_join_reports_a_missed_route(tmp_path):
    _write_evidence(
        tmp_path,
        [
            _record(
                "dosai",
                "entry-point",
                [],
                locations=[("Program.cs", 8)],
                attributes={"entryPointId": "ep:op:svc:minimal-api:_/Program.cs#GET:/weather"},
            ),
        ],
    )
    labels = {
        "joins": {
            "route-package": {
                "source": "hand",
                "routes": [
                    {"path": "/weather", "method": "GET", "packages": ["pkg:nuget/Serilog@4.2.0"]},
                    {"path": "/health", "method": "GET", "packages": []},
                ],
            }
        }
    }
    item = {"scan": {"types": ["dotnet"], "args": []}}
    scored = corpus_score.score_join_route_package(
        corpus_score.ItemScan(item, _result(tmp_path)), labels
    )
    assert scored["outcome"] == "partial"
    assert scored["routesMatched"] == 0
    missed_paths = [entry["path"] for entry in scored["missed"]]
    assert missed_paths == ["/weather", "/health"]


def _dev(purl):
    return {
        "purl": purl,
        "scope": "optional",
        "properties": [{"name": "cdx:npm:package:development", "value": "true"}],
    }


LIFECYCLE_LABELS = {
    "joins": {
        "lifecycle-phase": {
            "source": "hand",
            "packages": [
                {"purl": "pkg:npm/express", "phase": "shipped"},
                {"purl": "pkg:npm/chalk@5.6.2", "phase": "shipped"},
                {"purl": "pkg:npm/chalk@4.1.2", "phase": "dev-only"},
                {"purl": "pkg:npm/eslint", "phase": "dev-only"},
                {"purl": "pkg:npm/uglify-js", "phase": "build-only"},
            ],
        }
    }
}


def test_lifecycle_join_reads_the_development_scope_of_the_build_bom(tmp_path):
    # A source scan's post-build BOM is empty, so the build BOM's
    # development markers decide what must not ship; the two chalk versions
    # are told apart by their versioned labels.
    _write_props_bom(
        tmp_path / "sbom-build-js.cdx.json",
        [
            {"purl": "pkg:npm/express@4.22.3", "scope": "required"},
            {"purl": "pkg:npm/chalk@5.6.2"},
            _dev("pkg:npm/chalk@4.1.2"),
            _dev("pkg:npm/eslint@9.39.5"),
            {"purl": "pkg:npm/uglify-js@3.19.3"},
        ],
    )
    _write_props_bom(tmp_path / "sbom-postbuild-js.cdx.json", [])
    scored = corpus_score.score_join_lifecycle_phase(_scan({}, tmp_path), LIFECYCLE_LABELS)
    assert scored["measuredFrom"] == "build-scope"
    assert scored["matched"] == 4
    # uglify-js carries no development marker, so the scan says it ships.
    assert [m["purl"] for m in scored["missed"]] == ["pkg:npm/uglify-js"]
    assert scored["outcome"] == "partial"
    # Each label is reported on its own, with the marker the BOM carried.
    phases = scored["byPhase"]
    assert list(phases) == ["shipped", "build-only", "dev-only"]
    assert (phases["shipped"]["packages"], phases["shipped"]["matched"]) == (2, 2)
    assert (phases["build-only"]["packages"], phases["build-only"]["matched"]) == (1, 0)
    assert phases["build-only"]["observed"] == [{"purl": "pkg:npm/uglify-js", "state": "shipped"}]
    assert (phases["dev-only"]["packages"], phases["dev-only"]["matched"]) == (2, 2)
    assert {o.get("marker") for o in phases["dev-only"]["observed"]} == {
        "cdx:npm:package:development"
    }
    assert scored["buildOnlyDistinct"] is False


def test_lifecycle_join_prefers_a_post_build_bom_that_holds_components(tmp_path):
    _write_props_bom(
        tmp_path / "sbom-build-js.cdx.json",
        [_dev("pkg:npm/eslint@9.39.5"), {"purl": "pkg:npm/express@4.22.3"}],
    )
    _write_props_bom(
        tmp_path / "sbom-postbuild-js.cdx.json",
        [{"purl": "pkg:npm/express@4.22.3"}, {"purl": "pkg:npm/chalk@5.6.2"}],
    )
    labels = {
        "joins": {
            "lifecycle-phase": {
                "source": "hand",
                "packages": LIFECYCLE_LABELS["joins"]["lifecycle-phase"]["packages"][:2]
                + [{"purl": "pkg:npm/eslint", "phase": "dev-only"}],
            }
        }
    }
    scored = corpus_score.score_join_lifecycle_phase(_scan({}, tmp_path), labels)
    assert scored["measuredFrom"] == "post-build"
    assert scored["outcome"] == "measured"
    assert scored["matched"] == 3


def test_component_layer_gap_when_no_component_carries_a_layer(tmp_path):
    _write_bom(
        tmp_path,
        "sbom-container.cdx.json",
        ["pkg:apk/alpine/busybox@1.37.0", "pkg:generic/node@22.23.5"],
    )
    labels = {
        "joins": {
            "component-layer": {
                "source": "hand",
                "packages": [
                    {"purl": "pkg:apk/alpine/busybox", "layer": "os"},
                    {"purl": "pkg:generic/node@22.23.5", "layer": "application"},
                ],
            }
        }
    }
    item = {"scan": {"types": ["container"], "args": []}}
    scored = corpus_score.score_join_component_layer(
        corpus_score.ItemScan(item, _result(tmp_path)), labels
    )
    assert scored["outcome"] == "gap"
    assert scored["labelledSeen"] == 2
    assert scored["withLayer"] == 0


def _scan(item, reports_dir, findings=None):
    result = _result(reports_dir)
    result.findings = findings or []
    return corpus_score.ItemScan(item, result)


class _Reach:
    def __init__(self, reached):
        self.reached_purls = {p: 1 for p in reached}
        self.direct_purls = {}
        self.success = True


def test_advisory_join_counts_reached_findings_on_used_packages_only(tmp_path):
    findings = [
        {
            "category": "vulnerability",
            "rule": "A",
            "components": ["pkg:npm/chalk@5.3.0"],
            "id": "a",
        },
        {"category": "vulnerability", "rule": "B", "components": ["pkg:npm/koa@1.0.0"], "id": "b"},
        {
            "category": "malware",
            "rule": "MAL-1",
            "components": ["pkg:npm/lodash@4.0.0"],
            "id": "c",
        },
        {
            "category": "vulnerability",
            "rule": "D",
            "components": ["pkg:npm/express@4.0.0"],
            "id": "d",
        },
    ]
    scan = _scan({"scan": {"types": ["js"]}}, tmp_path, findings)
    scan._reach["SemanticReachability"] = (
        _Reach(["pkg:npm/chalk@5.3.0", "pkg:npm/koa@1.0.0", "pkg:npm/lodash@4.0.0"]),
        None,
    )
    labels = {
        "reachability": {
            "used": [{"purl": "pkg:npm/lodash"}, {"purl": "pkg:npm/express"}],
            "unused": [{"purl": "pkg:npm/chalk"}],
        }
    }
    scored = corpus_score.score_join_advisory_usage_reach(scan, labels)
    assert scored["findings"] == 4
    # Only the malware finding on used lodash is reached on a used package.
    assert scored["reachedOnUsed"] == 1
    assert [f["id"] for f in scored["reachedOnUnused"]] == ["a"]
    assert scored["reachedUnlabelled"] == 1
    assert [f["id"] for f in scored["notReachedOnUsed"]] == ["d"]


def _write_props_bom(path, components):
    path.write_text(
        json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": components}),
        encoding="utf-8",
    )


def test_component_layer_ignores_unrelated_layer_like_properties(tmp_path):
    _write_props_bom(
        tmp_path / "sbom-container.cdx.json",
        [
            {"purl": "pkg:apk/alpine/busybox@1.37.0", "properties": []},
            {"purl": "pkg:npm/x@1.0.0", "properties": [{"name": "cdx:npm:player", "value": "1"}]},
        ],
    )
    labels = {
        "joins": {
            "component-layer": {
                "source": "hand",
                "packages": [{"purl": "pkg:apk/alpine/busybox", "layer": "os"}],
            }
        }
    }
    scored = corpus_score.score_join_component_layer(_scan({}, tmp_path), labels)
    assert scored["outcome"] == "gap"


def test_component_layer_compares_the_labelled_layer(tmp_path):
    def layer(value):
        return [{"name": "aquasecurity:trivy:LayerDiffID", "value": value}]

    _write_props_bom(
        tmp_path / "sbom-container.cdx.json",
        [
            {"purl": "pkg:apk/alpine/busybox@1.37.0", "properties": layer("sha256:base")},
            {"purl": "pkg:apk/alpine/musl@1.2.5", "properties": layer("sha256:node")},
            {"purl": "pkg:generic/node@22.23.5", "properties": layer("sha256:node")},
        ],
    )
    labels = {
        "joins": {
            "component-layer": {
                "source": "hand",
                "packages": [
                    {"purl": "pkg:apk/alpine/busybox", "layer": "os"},
                    {"purl": "pkg:apk/alpine/musl", "layer": "os"},
                    {"purl": "pkg:generic/node@22.23.5", "layer": "application"},
                ],
            }
        }
    }
    scored = corpus_score.score_join_component_layer(_scan({}, tmp_path), labels)
    # musl shares the application's layer, so it is attributed wrongly.
    assert scored["outcome"] == "partial"
    assert scored["withLayer"] == 3
    assert scored["matched"] == 1
    assert [m["purl"] for m in scored["missed"]] == [
        "pkg:apk/alpine/musl",
        "pkg:generic/node@22.23.5",
    ]


def test_openapi_route_matches_on_method_and_path(tmp_path):
    spec = {
        "paths": {
            "/rest/user/login": {
                "get": {"x-atom-usages": {"call": {"routes/login.ts": [12]}}},
            }
        }
    }
    (tmp_path / "js-openapi.json").write_text(json.dumps(spec), encoding="utf-8")
    _write_evidence(
        tmp_path,
        [
            _record(
                "atom",
                "reached-flow",
                ["pkg:npm/jsonwebtoken@0.4.0"],
                locations=[("routes/login.ts", 12)],
            )
        ],
    )
    route = {"path": "/rest/user/login", "method": "POST", "packages": ["pkg:npm/jsonwebtoken"]}
    labels = {"joins": {"route-package": {"source": "hand", "routes": [route]}}}
    scored = corpus_score.score_join_route_package(_scan({}, tmp_path), labels)
    assert scored["routesMatched"] == 0
    route["method"] = "GET"
    scored = corpus_score.score_join_route_package(_scan({}, tmp_path), labels)
    assert scored["routesMatched"] == 1


def test_bom_phases_come_from_the_file_name_not_the_path(tmp_path):
    reports_dir = tmp_path / "postbuild-runs" / "node-22-alpine"
    reports_dir.mkdir(parents=True)
    _write_bom(reports_dir, "sbom-container.cdx.json", ["pkg:apk/alpine/busybox@1.37.0"])
    labels = {
        "joins": {
            "component-layer": {
                "source": "hand",
                "packages": [{"purl": "pkg:apk/alpine/busybox", "layer": "os"}],
            }
        }
    }
    scored = corpus_score.score_join_component_layer(_scan({}, reports_dir), labels)
    assert scored["labelledSeen"] == 1


def test_two_manifests_reads_cdxgen_internal_srcfile(tmp_path):
    _write_props_bom(
        tmp_path / "sbom-build-js.cdx.json",
        [
            {
                "purl": "pkg:npm/ms@2.1.3",
                "properties": [{"name": "internal:SrcFile", "value": "package-lock.json"}],
            },
            {
                "purl": "pkg:npm/ms@0.7.1",
                "properties": [
                    {"name": "internal:SrcFile", "value": "packages/b/package-lock.json"}
                ],
            },
        ],
    )
    labels = {
        "joins": {
            "two-manifests": {
                "source": "hand",
                "package": "pkg:npm/ms",
                "versions": ["2.1.3", "0.7.1"],
            }
        }
    }
    scored = corpus_score.score_join_two_manifests(_scan({}, tmp_path), labels)
    assert scored["withDeclaringPath"] == 2
    assert scored["distinctVersionCount"] == 2


def test_runtime_join_reason_does_not_assume_an_operating_system(tmp_path):
    labels = {
        "joins": {
            "component-runtime": {"source": "fixture", "packages": [{"purl": "pkg:pypi/pyyaml"}]}
        }
    }
    scored = corpus_score.score_join_component_runtime(_scan({}, tmp_path), labels)
    assert scored["outcome"] == "partial"
    assert "macOS" not in scored["reason"]
