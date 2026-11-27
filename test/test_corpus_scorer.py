"""The corpus scorer's scoring behaviour on tiny hand-built inputs.

Every test builds its findings, labels and score entries by hand, so the
expected values are written, not recorded from a run. The module under test
is contrib/corpus/score.py; the join and reachability functions it shares
with contrib/reachability_eval.py are exercised through it.
"""

import json
import os
import sys
from types import SimpleNamespace

import pytest

from contrib.corpus import score as corpus_score

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

USED = ["pkg:npm/lodash@4.17.21", "pkg:npm/express@4.19.2"]
UNUSED = ["pkg:npm/chalk@5.3.0"]


def _reach_labels():
    return {
        "used": [{"purl": p} for p in USED],
        "unused": [{"purl": p} for p in UNUSED],
    }


def _purl(name, version="1.0.0"):
    return f"pkg:npm/{name}@{version}"


def test_reached_used_is_true_positive():
    scores = corpus_score.score_purl_set(
        {corpus_score.purl_key(p) for p in USED[:1]},
        {corpus_score.purl_key(p) for p in USED},
        {corpus_score.purl_key(p) for p in UNUSED},
    )
    assert scores["recall"] == 0.5
    assert scores["precision"] == 1.0
    assert scores["missed"] == [corpus_score.purl_key(USED[1])]
    assert scores["wrong"] == []


def test_reached_unused_is_false_positive():
    reached = {corpus_score.purl_key(USED[0]), corpus_score.purl_key(UNUSED[0])}
    scores = corpus_score.score_purl_set(
        reached, {corpus_score.purl_key(p) for p in USED}, {corpus_score.purl_key(p) for p in UNUSED}
    )
    assert scores["recall"] == 0.5
    assert scores["precision"] == 0.5
    assert scores["wrong"] == [corpus_score.purl_key(UNUSED[0])]


def test_missed_used_is_false_negative():
    scores = corpus_score.score_purl_set(
        set(), {corpus_score.purl_key(p) for p in USED}, {corpus_score.purl_key(p) for p in UNUSED}
    )
    assert scores["recall"] == 0.0
    assert sorted(scores["missed"]) == sorted(corpus_score.purl_key(p) for p in USED)


def test_comparable_purl_folds_spelling():
    # The same scoped package spelled with the encoded @ and a different
    # version, as a BOM and a slice spell it.
    assert (
        corpus_score.purl_key("pkg:npm/%40babel/core@7.0.0")
        == corpus_score.purl_key("pkg:npm/@babel/core@6.5.0")
    )


def _finding(category, rule, purls):
    return {"category": category, "rule": rule, "components": purls, "id": "dsf1:x"}


def test_expected_finding_scores_recall_and_precision():
    findings = [_finding("vulnerability", "CVE-1", [_purl("lodash", "4.17.21")])]
    expected = [
        {
            "category": "vulnerability",
            "purl": "pkg:npm/lodash@4.17.15",
            "rules": ["CVE-1"],
        }
    ]
    scored = corpus_score.score_findings(findings, expected, [])
    assert scored["hits"] == 1
    assert scored["recall"] == 1.0
    assert scored["precision"] == 1.0
    assert scored["missed"] == []


def test_missed_expected_finding_is_a_miss():
    expected = [
        {"category": "vulnerability", "purl": "pkg:npm/lodash", "rules": ["CVE-1"]},
        {"category": "vulnerability", "purl": "pkg:npm/express", "rules": ["CVE-2"]},
    ]
    scored = corpus_score.score_findings(
        [_finding("vulnerability", "CVE-1", [_purl("lodash")])], expected, []
    )
    assert scored["hits"] == 1
    assert scored["recall"] == 0.5
    assert [entry["purl"] for entry in scored["missed"]] == ["pkg:npm/express"]


def test_finding_on_labelled_purl_without_expected_entry_is_unexpected():
    expected = [
        {"category": "vulnerability", "purl": "pkg:npm/lodash", "rules": ["CVE-1"]}
    ]
    findings = [
        _finding("vulnerability", "CVE-1", [_purl("lodash")]),
        _finding("vulnerability", "CVE-9", [_purl("lodash", "4.17.20")]),
    ]
    scored = corpus_score.score_findings(findings, expected, [])
    assert scored["unexpected"] == 1
    assert scored["precision"] == 0.5


def test_finding_on_unlabelled_purl_counts_nowhere():
    expected = [
        {"category": "vulnerability", "purl": "pkg:npm/lodash", "rules": ["CVE-1"]}
    ]
    findings = [_finding("vulnerability", "CVE-7", [_purl("koa")])]
    scored = corpus_score.score_findings(findings, expected, [])
    assert scored["unexpected"] == 0
    assert scored["recall"] == 0.0
    assert scored["precision"] is None


def test_negative_control_fires_with_finding_id():
    forbidden = [
        {
            "category": "malware",
            "purl": "pkg:npm/left-pad@1.3.0",
            "reason": "benign",
        }
    ]
    findings = [_finding("malware", "MAL-1", [_purl("left-pad", "1.3.0")])]
    scored = corpus_score.score_findings(findings, [], forbidden)
    assert len(scored["forbiddenFired"]) == 1
    assert scored["forbiddenFired"][0]["rule"] == "MAL-1"
    assert scored["forbiddenFired"][0]["id"] == "dsf1:x"


def test_negative_control_with_other_purl_does_not_fire():
    forbidden = [
        {"category": "malware", "purl": "pkg:npm/left-pad@1.3.0", "reason": "benign"}
    ]
    findings = [_finding("malware", "MAL-1", [_purl("right-pad")])]
    scored = corpus_score.score_findings(findings, [], forbidden)
    assert scored["forbiddenFired"] == []


def _result_with_stages(stages, findings=None, reports_dir="."):
    return SimpleNamespace(
        reports_dir=reports_dir,
        findings=findings or [],
        manifest={"stages": stages},
        types=[],
        project_types=[],
    )


def test_not_assessed_stage_is_its_own_column(monkeypatch):
    # No BOM files to count: glob finds nothing, which the component count
    # tolerates.
    monkeypatch.chdir(REPO_ROOT)
    result = _result_with_stages(
        [
            {"name": "risk", "status": "not-assessed", "reason": "cdx-audit missing"},
            {"name": "matching", "status": "completed"},
        ],
        findings=[],
    )
    entry = corpus_score.score_item(
        {"name": "t", "kind": "fixture", "scan": {"types": ["js"], "args": []}},
        {"findings": {"source": "hand", "expected": [], "forbidden": []}},
        result,
        None,
    )
    supply = entry["categories"]["supply-chain"]
    assert supply["status"] == "not-assessed"
    assert supply["reason"] == "cdx-audit missing"
    assert supply["recall"] is None
    # A category whose stage completed and which no label names appears
    # nowhere: it is neither scored nor reported.
    assert "vulnerability" not in entry["categories"]


def test_unlabelled_category_is_not_reported_as_clean(monkeypatch):
    monkeypatch.chdir(REPO_ROOT)
    result = _result_with_stages(
        [{"name": "matching", "status": "completed"}], findings=[]
    )
    entry = corpus_score.score_item(
        {"name": "t", "kind": "fixture", "scan": {"types": ["js"], "args": []}},
        {
            "findings": {
                "source": "hand",
                "expected": [
                    {"category": "vulnerability", "purl": "pkg:npm/lodash", "rules": ["C"]}
                ],
            }
        },
        result,
        None,
    )
    # The labelled category is scored; the unlabelled licence category never
    # appears at all, because the run labelled nothing for it.
    assert entry["categories"]["vulnerability"]["status"] == "assessed"
    assert "license" not in entry["categories"]


def test_label_without_source_is_refused_by_schema():
    import jsonschema

    here = os.path.join(REPO_ROOT, "contrib", "corpus")
    with open(os.path.join(here, "depscan-labels.schema.json"), encoding="utf-8") as fp:
        schema = json.load(fp)
    document = {
        "item": "t",
        "findings": {"expected": [], "forbidden": []},
    }
    with pytest.raises(jsonschema.ValidationError) as excinfo:
        jsonschema.validate(document, schema)
    assert "source" in str(excinfo.value)


def test_manifest_and_labels_validate_against_their_schemas():
    import jsonschema

    here = os.path.join(REPO_ROOT, "contrib", "corpus")
    with open(os.path.join(here, "depscan-corpus.schema.json"), encoding="utf-8") as fp:
        corpus_schema = json.load(fp)
    with open(os.path.join(here, "depscan-labels.schema.json"), encoding="utf-8") as fp:
        labels_schema = json.load(fp)
    with open(os.path.join(here, "depscan.corpus.json"), encoding="utf-8") as fp:
        manifest = json.load(fp)
    jsonschema.validate(manifest, corpus_schema)
    for item in manifest["items"]:
        with open(os.path.join(here, item["labels"]), encoding="utf-8") as fp:
            labels = json.load(fp)
        jsonschema.validate(labels, labels_schema)


def test_floor_drop_exits_1(tmp_path):
    # A corpus manifest whose only CI item cannot run (no pulled data), and a
    # floor recorded for it: the floor is violated and the scorer exits 1.
    here = os.path.join(REPO_ROOT, "contrib", "corpus")
    manifest = {
        "schemaVersion": 1,
        "items": [
            {
                "name": "needs-data",
                "description": "A BOM item whose data is not pulled here.",
                "source": "https://example.invalid/repo@0000000000000000000000000000000000000000",
                "sha256": "0" * 64,
                "license": "MIT",
                "storage": {"kind": "bom", "location": "ghcr.io/example/needs-data"},
                "kind": "bom",
                "scan": {"types": ["js"], "args": []},
                "testdata": {"artifact": "needs-data", "digest": "sha256:" + "0" * 64},
                "subset": "ci",
                "labels": "labels/needs-data.json",
            }
        ],
    }
    labels = {"item": "needs-data", "findings": {"source": "hand"}}
    manifest_path = tmp_path / "depscan.corpus.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    labels_dir = tmp_path / "labels"
    labels_dir.mkdir()
    (labels_dir / "needs-data.json").write_text(json.dumps(labels), encoding="utf-8")
    floors_path = tmp_path / "floors.json"
    floors_path.write_text(
        json.dumps(
            {
                "commit": "0" * 40,
                "floors": [
                    {
                        "item": "needs-data",
                        "path": "categories.vulnerability.recall",
                        "minimum": 0.9,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    output_dir = tmp_path / "out"
    argv = [
        "score.py",
        "--manifest",
        str(manifest_path),
        "--subset",
        "ci",
        "--floors",
        str(floors_path),
        "--testdata-root",
        str(tmp_path / "no-data"),
        "--output",
        str(output_dir),
    ]
    old_argv = sys.argv
    sys.argv = argv
    try:
        rc = corpus_score.main()
    finally:
        sys.argv = old_argv
    assert rc == 1
    score_doc = json.loads((output_dir / "score.json").read_text(encoding="utf-8"))
    assert score_doc["summary"]["floors"]["violations"], "the floor must be violated"
    assert score_doc["items"][0]["state"] == "not-assessed"


def test_floors_pass_when_values_hold():
    score_doc = {
        "items": [
            {
                "item": "t",
                "state": "scored",
                "categories": {"vulnerability": {"recall": 1.0}},
            }
        ]
    }
    floors = {
        "floors": [
            {"item": "t", "path": "categories.vulnerability.recall", "minimum": 0.8}
        ]
    }
    assert corpus_score.check_floors(floors, score_doc) == []


def test_not_assessed_item_violates_its_floor():
    score_doc = {
        "items": [
            {"item": "t", "state": "not-assessed", "reason": "data missing"}
        ]
    }
    floors = {
        "floors": [
            {"item": "t", "path": "categories.vulnerability.recall", "minimum": 0.8}
        ]
    }
    violations = corpus_score.check_floors(floors, score_doc)
    assert len(violations) == 1
    assert violations[0]["value"] is None
