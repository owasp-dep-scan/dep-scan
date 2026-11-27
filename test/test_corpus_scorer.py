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

from contrib.corpus import inputs as corpus_inputs
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
        reached,
        {corpus_score.purl_key(p) for p in USED},
        {corpus_score.purl_key(p) for p in UNUSED},
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
    assert corpus_score.purl_key("pkg:npm/%40babel/core@7.0.0") == corpus_score.purl_key(
        "pkg:npm/@babel/core@6.5.0"
    )


def _finding(category, rule, purls):
    return {"category": category, "rule": rule, "components": purls, "id": "dsf1:x"}


def test_expected_finding_scores_recall_and_precision():
    findings = [_finding("vulnerability", "CVE-1", [_purl("lodash", "4.17.21")])]
    expected = [
        {
            "category": "vulnerability",
            "purl": "pkg:npm/lodash",
            "rules": ["CVE-1"],
        }
    ]
    scored = corpus_score.score_findings(findings, expected, [])
    assert scored["hits"] == 1
    assert scored["recall"] == 1.0
    assert scored["precision"] == 1.0
    assert scored["missed"] == []
    # A label that names a version matches that version only.
    expected[0]["purl"] = "pkg:npm/lodash@4.17.15"
    assert corpus_score.score_findings(findings, expected, [])["hits"] == 0


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
    # A rule-scoped control names left-pad for MAL rules only; an
    # unrelated supply-chain rule on the same benign package is unexpected.
    expected = [{"category": "vulnerability", "purl": "pkg:npm/lodash", "rules": ["CVE-1"]}]
    forbidden = [
        {"category": "supply-chain", "purl": "pkg:npm/left-pad@1.3.0", "rules": ["INT-005"]}
    ]
    findings = [
        _finding("vulnerability", "CVE-1", [_purl("lodash")]),
        _finding("supply-chain", "INT-026", [_purl("left-pad", "1.3.0")]),
    ]
    scored = corpus_score.score_findings(findings, expected, forbidden)
    assert scored["unexpected"] == 1
    assert scored["forbiddenFired"] == []


def test_finding_on_a_labelled_purl_whose_category_no_label_names_is_not_unexpected():
    # The vulnerability labels name lodash; a vulnerability advisory on a
    # purl the supply-chain controls name is a true advisory, not noise.
    expected = [{"category": "vulnerability", "purl": "pkg:npm/lodash", "rules": ["CVE-1"]}]
    forbidden = [
        {"category": "supply-chain", "purl": "pkg:npm/express@4.19.2", "rules": ["INT-005"]}
    ]
    findings = [
        _finding("vulnerability", "CVE-1", [_purl("lodash")]),
        _finding("vulnerability", "CVE-9", [_purl("express", "4.19.2")]),
    ]
    scored = corpus_score.score_findings(findings, expected, forbidden)
    assert scored["unexpected"] == 0
    assert scored["precision"] == 1.0


def test_finding_on_unlabelled_purl_counts_nowhere():
    expected = [{"category": "vulnerability", "purl": "pkg:npm/lodash", "rules": ["CVE-1"]}]
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
    forbidden = [{"category": "malware", "purl": "pkg:npm/left-pad@1.3.0", "reason": "benign"}]
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
        corpus_score.ItemScan(
            {"name": "t", "kind": "fixture", "scan": {"types": ["js"], "args": []}}, result
        ),
        {"findings": {"source": "hand", "expected": [], "forbidden": []}},
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
    result = _result_with_stages([{"name": "matching", "status": "completed"}], findings=[])
    entry = corpus_score.score_item(
        corpus_score.ItemScan(
            {"name": "t", "kind": "fixture", "scan": {"types": ["js"], "args": []}}, result
        ),
        {
            "findings": {
                "source": "hand",
                "expected": [
                    {"category": "vulnerability", "purl": "pkg:npm/lodash", "rules": ["C"]}
                ],
            }
        },
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
    floors = {"floors": [{"item": "t", "path": "categories.vulnerability.recall", "minimum": 0.8}]}
    assert corpus_score.check_floors(floors, score_doc) == []


def test_not_assessed_item_violates_its_floor():
    score_doc = {"items": [{"item": "t", "state": "not-assessed", "reason": "data missing"}]}
    floors = {"floors": [{"item": "t", "path": "categories.vulnerability.recall", "minimum": 0.8}]}
    violations = corpus_score.check_floors(floors, score_doc)
    assert len(violations) == 1
    assert violations[0]["value"] is None


def test_versionless_scoped_label_keeps_its_name():
    # A version-less scoped label must not collapse to the bare type: the
    # scope marker is not a version separator.
    assert corpus_score.purl_key("pkg:npm/%40babel/core") == "pkg:npm/@babel/core"
    assert corpus_score.purl_key("pkg:npm/%40angular/core") == "pkg:npm/@angular/core"
    used = corpus_score.label_keys(["pkg:npm/%40babel/core", "pkg:npm/%40angular/core"])
    scores = corpus_score.score_purl_set(
        corpus_score.keys_of(["pkg:npm/@babel/core@7.24.0"]), used, set()
    )
    assert scores["recall"] == 0.5
    assert scores["missed"] == ["pkg:npm/@angular/core"]
    assert scores["seen"] == 1


def test_versioned_label_matches_only_that_version():
    label = corpus_score.label_keys(["pkg:npm/chalk@5.6.2"])
    assert label & corpus_score.keys_of(["pkg:npm/chalk@5.6.2"])
    assert not label & corpus_score.keys_of(["pkg:npm/chalk@4.1.2"])
    # A version-less label matches any version.
    assert corpus_score.label_keys(["pkg:npm/chalk"]) & corpus_score.keys_of(
        ["pkg:npm/chalk@4.1.2"]
    )


def test_pinned_control_does_not_fire_on_the_unpinned_expectation():
    # The supply-chain fixture expects CI-001 on the branch-pinned action
    # and forbids it on the SHA-pinned twin; a true positive on @main must
    # not fire the control, and a finding on the SHA must.
    with open(
        os.path.join(REPO_ROOT, "contrib", "corpus", "labels", "supply-chain-fixture.json"),
        encoding="utf-8",
    ) as fp:
        section = json.load(fp)["findings"]
    expected = [e for e in section["expected"] if e["rules"] == ["CI-001"]]
    forbidden = [e for e in section["forbidden"] if e["rules"] == ["CI-001"]]
    on_main = _finding("supply-chain", "CI-001", ["pkg:github/example-org/shared-workflows@main"])
    scored = corpus_score.score_findings([on_main], expected, forbidden)
    assert scored["hits"] == 1
    assert scored["forbiddenFired"] == []
    on_sha = _finding("supply-chain", "CI-001", [forbidden[0]["purl"]])
    scored = corpus_score.score_findings([on_sha], expected, forbidden)
    assert scored["hits"] == 0
    assert len(scored["forbiddenFired"]) == 1


def _scan(stages, findings=None, types=("js",)):
    return corpus_score.ItemScan(
        {"name": "t", "kind": "fixture", "scan": {"types": list(types), "args": []}},
        _result_with_stages(stages, findings=findings, reports_dir=REPO_ROOT),
    )


def test_one_skipped_type_does_not_blank_a_category_another_type_assessed():
    scan = _scan(
        [
            {"name": "risk", "projectType": "github", "status": "skipped", "reason": "no audit"},
            {"name": "risk", "projectType": "python", "status": "completed"},
        ],
        findings=[_finding("supply-chain", "PKG-011", ["pkg:pypi/requests-git-fixture@1.0"])],
        types=("github", "python"),
    )
    labels = {
        "findings": {
            "source": "hand",
            "expected": [
                {
                    "category": "supply-chain",
                    "purl": "pkg:pypi/requests-git-fixture",
                    "rules": ["PKG-011"],
                }
            ],
        }
    }
    supply = corpus_score.score_categories(scan, labels)["supply-chain"]
    assert supply["status"] == "assessed"
    assert supply["recall"] == 1.0
    assert supply["notAssessedTypes"] == [
        {"projectType": "github", "stage": "risk", "status": "skipped", "reason": "no audit"}
    ]


def test_category_is_not_assessed_when_every_type_skipped_it():
    scan = _scan(
        [
            {"name": "risk", "projectType": "github", "status": "skipped", "reason": "a"},
            {"name": "risk", "projectType": "python", "status": "failed", "reason": "b"},
        ],
        types=("github", "python"),
    )
    supply = corpus_score.score_categories(scan, {})["supply-chain"]
    assert supply["status"] == "not-assessed"
    assert supply["reason"] == "github: a; python: b"


def test_one_failed_inventory_does_not_blank_the_item():
    stages = [
        {"name": "inventory", "projectType": "go", "status": "completed"},
        {"name": "inventory", "projectType": "binary", "status": "failed", "reason": "blint"},
    ]
    assert corpus_score.inventory_failed(_scan(stages, types=("go", "binary"))) is None
    stages[0]["status"] = "failed"
    assert corpus_score.inventory_failed(_scan(stages, types=("go", "binary")))


def test_failed_binary_review_is_not_assessed_not_a_miss():
    scan = _scan(
        [{"name": "binary-review", "status": "failed", "reason": "blint crashed"}],
        types=("binary",),
    )
    labels = {
        "findings": {
            "source": "fixture",
            "expected": [
                {
                    "category": "binary-hardening",
                    "purl": "pkg:generic/binary-unprotected",
                    "rules": ["CHECK_CANARY"],
                }
            ],
        }
    }
    entry = corpus_score.score_categories(scan, labels)["binary-hardening"]
    assert entry["status"] == "not-assessed"
    assert entry["recall"] is None


def test_failed_matching_leaves_malware_not_assessed():
    scan = _scan([{"name": "matching", "status": "failed", "reason": "no database"}])
    with open(
        os.path.join(REPO_ROOT, "contrib", "corpus", "labels", "malware-fixture.json"),
        encoding="utf-8",
    ) as fp:
        labels = json.load(fp)
    categories = corpus_score.score_categories(scan, labels)
    assert categories["malware"]["status"] == "not-assessed"
    assert categories["vulnerability"]["status"] == "not-assessed"


def test_malware_fixture_control_fires_on_a_malware_finding():
    with open(
        os.path.join(REPO_ROOT, "contrib", "corpus", "labels", "malware-fixture.json"),
        encoding="utf-8",
    ) as fp:
        section = json.load(fp)["findings"]
    findings = [
        _finding("malware", "MAL-2024-1000", ["pkg:npm/custom-solutions@20.8.9"]),
        _finding("malware", "MAL-2099-1", ["pkg:npm/left-pad@1.3.0"]),
    ]
    scored = corpus_score.score_findings(findings, section["expected"], section["forbidden"])
    assert scored["recall"] == 1.0
    assert [f["rule"] for f in scored["forbiddenFired"]] == ["MAL-2099-1"]


def _scan_dir_corpus(tmp_path, labels, floors=None):
    """A one-item corpus over a copy of test/data/scan-directory, scored in
    scan-dir mode: the manifest, the label file, the scans root and the
    floors file, all built here."""
    import shutil

    item = {
        "name": "scan-fixture",
        "description": "The committed scan directory of the API tests.",
        "source": "fixture:scan-fixture",
        "sha256": "0" * 64,
        "license": "Apache-2.0",
        "storage": {"kind": "fixture"},
        "kind": "fixture",
        "scan": {"types": ["bom"], "args": []},
        "labels": "labels/scan-fixture.json",
        "subset": "ci",
    }
    (tmp_path / "labels").mkdir()
    (tmp_path / "labels" / "scan-fixture.json").write_text(
        json.dumps({"item": "scan-fixture", **labels}), encoding="utf-8"
    )
    manifest = tmp_path / "depscan.corpus.json"
    manifest.write_text(json.dumps({"schemaVersion": 1, "items": [item]}), encoding="utf-8")
    shutil.copytree(
        os.path.join(REPO_ROOT, "test", "data", "scan-directory"),
        tmp_path / "scans" / "scan-fixture",
    )
    argv = ["--manifest", str(manifest), "--scan-dir", str(tmp_path / "scans")]
    argv += ["--output", str(tmp_path / "out")]
    if floors is not None:
        (tmp_path / "floors.json").write_text(json.dumps(floors), encoding="utf-8")
        argv += ["--floors", str(tmp_path / "floors.json")]
    return argv


REQUESTS_EXPECTED = {
    "category": "vulnerability",
    "purl": "pkg:pypi/requests",
    "rules": ["CVE-2024-1111"],
    "citation": "the fixture BOM declares requests 2.32.1",
}


def _validate_score(path):
    import jsonschema

    with open(
        os.path.join(REPO_ROOT, "contrib", "corpus", "depscan-score.schema.json"),
        encoding="utf-8",
    ) as fp:
        schema = json.load(fp)
    with open(path, encoding="utf-8") as fp:
        jsonschema.validate(json.load(fp), schema)


def test_written_score_validates_against_its_schema(tmp_path):
    # The item labels findings only, so it has no reachability section, and
    # the two-manifests join over a scan without the package is partial.
    labels = {
        "findings": {"source": "hand", "expected": [REQUESTS_EXPECTED]},
        "joins": {
            "two-manifests": {
                "source": "hand",
                "package": "pkg:npm/ms",
                "versions": ["1.0.0", "2.0.0"],
                "citation": "a:1",
            }
        },
    }
    argv = _scan_dir_corpus(tmp_path, labels)
    assert corpus_score.main(argv) == 0
    _validate_score(tmp_path / "out" / "score.json")
    entry = json.loads((tmp_path / "out" / "score.json").read_text(encoding="utf-8"))["items"][0]
    assert entry["state"] == "scored"
    assert entry["categories"]["vulnerability"]["recall"] == 1.0
    assert "reachability" not in entry


def test_a_numeric_drop_below_a_floor_exits_1(tmp_path):
    labels = {
        "findings": {
            "source": "hand",
            "expected": [
                REQUESTS_EXPECTED,
                {**REQUESTS_EXPECTED, "purl": "pkg:pypi/urllib3", "rules": ["CVE-1"]},
            ],
        }
    }
    floors = {
        "commit": "0" * 40,
        "floors": [
            {"item": "scan-fixture", "path": "categories.vulnerability.recall", "minimum": 1.0}
        ],
    }
    assert corpus_score.main(_scan_dir_corpus(tmp_path, labels, floors)) == 1
    _validate_score(tmp_path / "out" / "score.json")
    score = json.loads((tmp_path / "out" / "score.json").read_text(encoding="utf-8"))
    assert score["summary"]["floors"]["violations"][0]["value"] == 0.5


def test_a_fired_negative_control_exits_1(tmp_path):
    labels = {
        "findings": {
            "source": "hand",
            "forbidden": [
                {
                    "category": "vulnerability",
                    "purl": "pkg:pypi/requests@2.32.1",
                    "reason": "the control",
                }
            ],
        }
    }
    floors = {"commit": "0" * 40, "floors": []}
    assert corpus_score.main(_scan_dir_corpus(tmp_path, labels, floors)) == 1
    score = json.loads((tmp_path / "out" / "score.json").read_text(encoding="utf-8"))
    fired = score["summary"]["forbiddenFired"]
    assert fired[0]["id"].startswith("dsf1:")


def test_unexpected_findings_carry_their_id():
    forbidden = [{"category": "supply-chain", "purl": "pkg:npm/left-pad@1.3.0", "rules": ["X"]}]
    findings = [_finding("supply-chain", "INT-026", [_purl("left-pad", "1.3.0")])]
    scored = corpus_score.score_findings(findings, [], forbidden)
    assert scored["unexpectedFindings"][0]["id"] == "dsf1:x"


def test_usage_errors_exit_2(tmp_path, capsys):
    argv = _scan_dir_corpus(tmp_path, {"findings": {"source": "hand"}})
    assert corpus_score.main(argv + ["--items", "nope"]) == 2
    assert "nope" in capsys.readouterr().err
    assert corpus_score.main(argv + ["--floors", str(tmp_path / "missing.json")]) == 2
    assert "floors" in capsys.readouterr().err


def test_schema_ids_follow_the_repository_convention():
    here = os.path.join(REPO_ROOT, "contrib", "corpus")
    # The repository's form: the file name without "depscan-", then the
    # major version, as analysis_lib.findings.schemas documents.
    for name in ("corpus", "labels", "score"):
        with open(os.path.join(here, f"depscan-{name}.schema.json"), encoding="utf-8") as fp:
            assert json.load(fp)["$id"] == f"urn:owasp:depscan:schema:{name}:1"


def _labels_schema():
    with open(
        os.path.join(REPO_ROOT, "contrib", "corpus", "depscan-labels.schema.json"),
        encoding="utf-8",
    ) as fp:
        return json.load(fp)


def test_misspelt_join_keys_are_refused_by_schema():
    import jsonschema

    document = {
        "item": "t",
        "joins": {"route-package": {"source": "hand", "rotues": []}},
    }
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(document, _labels_schema())
    document = {"item": "t", "joins": {"route-packages": {"source": "hand"}}}
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(document, _labels_schema())


def test_hand_labels_need_citations():
    import jsonschema

    expected = {"category": "vulnerability", "purl": "pkg:npm/x", "rules": ["C"]}
    document = {"item": "t", "findings": {"source": "hand", "expected": [expected]}}
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(document, _labels_schema())
    route = {"path": "/a", "method": "GET", "packages": []}
    document = {"item": "t", "joins": {"route-package": {"source": "hand", "routes": [route]}}}
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(document, _labels_schema())
    document = {"item": "t", "joins": {"two-producers": {"source": "hand", "package": "pkg:a/b"}}}
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(document, _labels_schema())


def test_unmapped_names_count_as_recall_misses():
    used = corpus_score.label_keys(["pkg:npm/lodash", "pkg:npm/express"])
    reached = corpus_score.keys_of(["pkg:npm/lodash@4.17.21", "pkg:npm/express@4.19.2"])
    scores = corpus_score.score_purl_set(reached, used, set(), unmapped_used=2)
    assert scores["recall"] == 0.5
    assert scores["unmappedUsed"] == 2
    assert scores["precision"] == 1.0


def test_pypi_names_compare_under_pep_503():
    assert corpus_score.label_keys(["pkg:pypi/flask-sqlalchemy"]) & corpus_score.keys_of(
        ["pkg:pypi/Flask_SQLAlchemy@3.1.1"]
    )


def test_paths_default_to_the_user_cache_and_there_is_no_timeout(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    args = corpus_score.parse_args([])
    for root in (args.scans_root, args.corpus_root, args.testdata_root):
        assert root.startswith(str(tmp_path / "depscan" / "corpus"))
    # The budget was checked only after a scan finished; the option is gone.
    with pytest.raises(SystemExit):
        corpus_score.parse_args(["--timeout", "10"])


def test_fixture_copies_never_land_inside_the_checkout():
    item = {
        "name": "malware-fixture",
        "source": "fixture:malware-fixture",
        "sha256": corpus_score.fixture_digest(
            os.path.join(REPO_ROOT, "contrib", "corpus", "fixtures", "malware-fixture")
        ),
    }
    payload, reason = corpus_inputs.resolve_fixture(item, os.path.join(REPO_ROOT, "corpus-scans"))
    assert payload is None and reason is not None
    assert "inside the dep-scan checkout" in reason


FIXTURES = os.path.join(REPO_ROOT, "contrib", "corpus", "fixtures")


def test_every_committed_fixture_matches_its_manifest_digest():
    with open(
        os.path.join(REPO_ROOT, "contrib", "corpus", "depscan.corpus.json"), encoding="utf-8"
    ) as fp:
        items = [i for i in json.load(fp)["items"] if i["source"].startswith("fixture:")]
    assert items
    for item in items:
        directory = os.path.join(FIXTURES, item["source"].split(":", 1)[1])
        assert corpus_score.fixture_digest(directory) == item["sha256"], item["name"]


def test_every_fixture_is_checked_out_without_line_ending_conversion():
    import subprocess

    files = subprocess.run(
        ["git", "-C", REPO_ROOT, "ls-files", "contrib/corpus/fixtures"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    attrs = subprocess.run(
        ["git", "-C", REPO_ROOT, "check-attr", "text", "--", *files],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.splitlines()
    assert attrs and all(line.endswith(": text: unset") for line in attrs)


def test_ignored_and_generated_files_do_not_change_a_fixture_digest(tmp_path):
    import shutil

    copy = tmp_path / "binary-hardening-fixture"
    shutil.copytree(os.path.join(FIXTURES, "binary-hardening-fixture"), copy)
    before = corpus_score.fixture_digest(str(copy))
    (copy / "binary-protected").write_bytes(b"\x7fELF")
    (copy / ".DS_Store").write_bytes(b"x")
    (copy / "node_modules").mkdir()
    (copy / "node_modules" / "x.js").write_text("x", encoding="utf-8")
    assert corpus_score.fixture_digest(str(copy)) == before
    (copy / "src" / "vulnerable.c").write_text("int main(void){return 0;}", encoding="utf-8")
    assert corpus_score.fixture_digest(str(copy)) != before


def _fixture_item(name, **extra):
    return {
        "name": name,
        "source": f"fixture:{name}",
        "sha256": corpus_score.fixture_digest(os.path.join(FIXTURES, name)),
        **extra,
    }


def test_a_failed_fixture_build_is_not_assessed_with_its_reason(tmp_path, monkeypatch):
    monkeypatch.setenv("CC", "no-such-compiler-on-path")
    item = _fixture_item("binary-hardening-fixture", build="build.sh")
    payload, reason = corpus_inputs.resolve_fixture(item, str(tmp_path))
    assert payload is None and reason is not None
    assert "build.sh" in reason
    assert ("no C compiler" in reason) or ("Linux C compiler" in reason)


@pytest.mark.skipif(
    not sys.platform.startswith("linux") or not __import__("shutil").which("cc"),
    reason="the fixture builds ELF binaries with a Linux C compiler",
)
def test_the_binary_fixture_builds_in_the_copy_only(tmp_path):
    item = _fixture_item("binary-hardening-fixture", build="build.sh")
    payload, reason = corpus_inputs.resolve_fixture(item, str(tmp_path))
    assert reason is None and payload is not None
    for name in ("binary-protected", "binary-unprotected"):
        with open(os.path.join(payload, name), "rb") as fp:
            assert fp.read(4) == b"\x7fELF"
        assert not os.path.exists(os.path.join(FIXTURES, "binary-hardening-fixture", name))


def test_a_join_no_producer_feeds_is_a_gap_without_a_scan(tmp_path):
    item = {
        "name": "tracebom-fixture",
        "kind": "fixture",
        "notProduced": {"join": "component-runtime", "reason": "no capture names a component"},
    }
    entry = corpus_score.score_one(
        item,
        {"item": "tracebom-fixture"},
        corpus_score.parse_args(["--scans-root", str(tmp_path)]),
    )
    assert entry["state"] == "not-assessed"
    assert entry["joins"]["component-runtime"]["outcome"] == "gap"
    assert not os.listdir(tmp_path)


def test_a_scans_root_on_another_drive_is_outside_the_checkout(tmp_path, monkeypatch):
    # On Windows, commonpath raises when the scans root and the checkout sit
    # on different drives; that is outside the checkout, not a crash.
    def other_drive(paths):
        raise ValueError("Paths don't have the same drive")

    monkeypatch.setattr(corpus_inputs.os.path, "commonpath", other_drive)
    payload, reason = corpus_inputs.resolve_fixture(
        _fixture_item("malware-fixture"), str(tmp_path)
    )
    assert reason is None and payload is not None
    assert os.path.isdir(payload)


def test_a_fixture_build_without_bash_is_not_assessed(tmp_path, monkeypatch):
    real_which = corpus_inputs.shutil.which
    monkeypatch.setattr(
        corpus_inputs.shutil, "which", lambda name: None if name == "bash" else real_which(name)
    )
    item = _fixture_item("binary-hardening-fixture", build="build.sh")
    payload, reason = corpus_inputs.resolve_fixture(item, str(tmp_path))
    assert payload is None and reason is not None
    assert "bash is not on PATH" in reason


def test_a_host_without_git_leaves_repository_items_not_assessed(tmp_path, monkeypatch):
    def no_git(*args, **kwargs):
        raise FileNotFoundError(2, "No such file or directory", "git")

    monkeypatch.setattr(corpus_inputs.subprocess, "run", no_git)
    assert corpus_inputs.git(str(tmp_path), "rev-parse", "HEAD").returncode != 0
    monkeypatch.setattr(corpus_inputs.shutil, "which", lambda name: None)
    item = {"name": "x", "source": "https://example.invalid/x.git@" + "0" * 40}
    payload, reason = corpus_inputs.resolve_repository(item, str(tmp_path), fetch=True)
    assert payload is None and reason is not None
    assert "git is not on PATH" in reason


def test_an_item_that_raises_is_an_error_entry_not_a_crash(tmp_path, monkeypatch):
    argv = _scan_dir_corpus(tmp_path, {"findings": {"source": "hand", "expected": []}})

    def broken(item, labels, args):
        raise FileNotFoundError(2, "No such file or directory", "bash")

    monkeypatch.setattr(corpus_score, "score_one", broken)
    assert corpus_score.main(argv) == 0
    _validate_score(tmp_path / "out" / "score.json")
    score = json.loads((tmp_path / "out" / "score.json").read_text(encoding="utf-8"))
    assert score["items"][0]["state"] == "error"
    assert "FileNotFoundError" in score["items"][0]["reason"]
    assert score["summary"]["errors"] == 1
    assert "| scan-fixture | error |" in (tmp_path / "out" / "score.md").read_text(
        encoding="utf-8"
    )


def test_items_with_floors_check_only_the_selected_items_floors(tmp_path):
    floors = {
        "commit": "0" * 40,
        "floors": [
            {"item": "scan-fixture", "path": "categories.vulnerability.recall", "minimum": 1.0},
            {"item": "other-item", "path": "categories.malware.recall", "minimum": 1.0},
        ],
    }
    labels = {"findings": {"source": "hand", "expected": [REQUESTS_EXPECTED]}}
    argv = _scan_dir_corpus(tmp_path, labels, floors)
    assert corpus_score.main(argv + ["--items", "scan-fixture"]) == 0
    _validate_score(tmp_path / "out" / "score.json")
    summary = json.loads((tmp_path / "out" / "score.json").read_text(encoding="utf-8"))["summary"]
    assert summary["floors"]["checked"] == 1
    assert summary["floors"]["skipped"] == 1
    assert summary["floors"]["violations"] == []


def test_a_version_holding_a_slash_splits_off_the_key():
    for purl in (
        "pkg:github/actions/checkout@refs/heads/main",
        "pkg:github/actions/checkout@refs%2Fheads%2Fmain",
    ):
        assert corpus_score.split_purl(purl) == ("pkg:github/actions/checkout", "refs/heads/main")
        assert corpus_score.label_key("pkg:github/actions/checkout") in corpus_score.keys_of(
            [purl]
        )
    assert corpus_score.split_purl("pkg:github/actions/checkout@release/v1")[1] == "release/v1"
    assert corpus_score.split_purl("pkg:npm/%40babel/core@7.1.0") == (
        "pkg:npm/@babel/core",
        "7.1.0",
    )
    assert corpus_score.split_purl("pkg:npm/@babel/core") == ("pkg:npm/@babel/core", None)
    assert corpus_score.split_purl("pkg:pypi/Flask_SQLAlchemy@3.1.1") == (
        "pkg:pypi/flask-sqlalchemy",
        "3.1.1",
    )
