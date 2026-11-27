"""The join evaluators, tested on hand-built scan directories.

The join tests write tiny BOM and evidence files with known answers, so a
broken join shows as a failed assertion rather than as an empty result.
"""

import json

import pytest

from contrib.corpus import score as corpus_score
from analysis_lib.evidence import (
    Evidence,
    EvidenceCaveat,
    EvidenceLocation,
    EvidenceProducer,
    EvidenceSubject,
)


def _write_bom(reports_dir, name, components):
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
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
        locations=[
            EvidenceLocation(file=f, line=ln) for f, ln in (locations or [])
        ],
        caveats=[EvidenceCaveat(kind="coverage-gap", detail="test fixture")],
        attributes=attributes,
    )


def _write_evidence(reports_dir, records):
    lines = []
    for record in records:
        document = json.loads(
            json.dumps(record.to_dict(), default=lambda o: o.to_dict())
        )
        lines.append(json.dumps(document))
    (reports_dir / "evidence.jsonl").write_text("\n".join(lines), encoding="utf-8")


def _result(reports_dir):
    from types import SimpleNamespace

    return SimpleNamespace(
        reports_dir=str(reports_dir), findings=[], manifest={"stages": []}, types=[]
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
        item, _result(tmp_path), labels, str(tmp_path)
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
    )
    _write_bom(
        tmp_path,
        "sbom-binary.cdx.json",
        ["pkg:golang/github.com/google/go-github/v81@v81.0.0", "pkg:golang/go-jwt/jwt/v4@v4.5.0"],
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
        item, _result(tmp_path), labels, str(tmp_path)
    )
    assert scored["outcome"] == "measured"
    assert scored["identical"] is True
    assert scored["producers"] == ["blint", "cdxgen"]


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
        item, _result(tmp_path), labels, str(tmp_path)
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
        item, _result(tmp_path), labels, str(tmp_path)
    )
    assert scored["outcome"] == "partial"
    assert scored["routesMatched"] == 0
    missed_paths = [entry["path"] for entry in scored["missed"]]
    assert missed_paths == ["/weather", "/health"]


def test_lifecycle_join_marks_shipped_labels_not_assessed_without_postbuild(tmp_path):
    _write_bom(
        tmp_path,
        "sbom-prebuild-js.cdx.json",
        ["pkg:npm/express@4.19.2", "pkg:npm/eslint@9.0.0", "pkg:npm/chalk@5.3.0"],
    )
    _write_bom(
        tmp_path,
        "sbom-build-js.cdx.json",
        [
            "pkg:npm/express@4.19.2",
            "pkg:npm/eslint@9.0.0",
            "pkg:npm/chalk@5.3.0",
            "pkg:npm/body-parser@1.20.2",
        ],
    )
    labels = {
        "joins": {
            "lifecycle-phase": {
                "source": "hand",
                "packages": [
                    {"purl": "pkg:npm/express", "phase": "shipped"},
                    {"purl": "pkg:npm/eslint", "phase": "dev-only"},
                ],
            }
        }
    }
    item = {"scan": {"types": ["js"], "args": []}}
    scored = corpus_score.score_join_lifecycle_phase(
        item, _result(tmp_path), labels, str(tmp_path)
    )
    assert scored["outcome"] == "partial"
    assert scored["matched"] == 0
    reasons = {entry["purl"]: entry["reason"] for entry in scored["notAssessed"]}
    assert "pkg:npm/express" in reasons
    assert "post-build" in reasons["pkg:npm/express"]


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
        item, _result(tmp_path), labels, str(tmp_path)
    )
    assert scored["outcome"] == "gap"
    assert scored["labelledSeen"] == 2
    assert scored["withLayer"] == 0
