"""Unit tests for the analysis_lib.vex package.

These tests assert real behavior -- schema validity against the bundled CSAF
2.0 and 2.1 schemas, reference resolution, reachability semantics and
serialization invariants -- rather than dict-equality against hand-authored
fixtures.
"""

import json
import os
from pathlib import Path

import pytest

from analysis_lib.vex import models
from analysis_lib.vex.cvss import best_severity, parse_one, parse_ratings
from analysis_lib.vex.csaf import build_csaf
from analysis_lib.vex.emit import export_csaf, output_path, validate
from analysis_lib.vex.product_tree import (
    build_product_tree,
    defined_product_ids,
    referenced_product_ids,
    resolve_purl,
)
from analysis_lib.vex.dates import is_rfc3339, now_csaf, to_csaf_datetime
from analysis_lib.vex.reachability import classify, KNOWN_AFFECTED, KNOWN_NOT_AFFECTED
from analysis_lib.vex.refs import build_references_and_ids, synthesize_id
from analysis_lib.vex.semantic import validate_semantic
from analysis_lib.vex.tracking import build_tracking
from analysis_lib.vex.vulnerabilities import build_vulnerability

DATA_DIR = Path(__file__).resolve().parent / "data"

VERSIONS = ["2.0", "2.1"]


# ---------------------------------------------------------------------------
# models
# ---------------------------------------------------------------------------


def test_models_clean_drops_empty_containers():
    assert models._clean({"a": None, "b": "", "c": [], "d": {}, "e": "x"}) == {"e": "x"}
    assert models._clean([None, "", [], {}, "keep"]) == ["keep"]


def test_full_product_name_helper_2_0_uses_purl():
    fpn = models.FullProductName(name="x", product_id="pkg:x@1", purl="pkg:x@1", cpe="cpe:2.3")
    out = fpn.to_dict("2.0")
    assert out["product_identification_helper"]["purl"] == "pkg:x@1"
    assert out["product_identification_helper"]["cpe"] == "cpe:2.3"


def test_full_product_name_helper_2_1_uses_purls_list():
    fpn = models.FullProductName(name="x", product_id="pkg:x@1", purl="pkg:x@1")
    out = fpn.to_dict("2.1")
    assert out["product_identification_helper"]["purls"] == ["pkg:x@1"]


def test_vulnerability_omits_note_without_text():
    # A note with empty text must never reach the serialized vulnerability.
    vuln = models.Vulnerability(
        cve="CVE-2024-1",
        title="t",
        cwes=[],
        notes=[
            models.Note(category="description", text=""),
            models.Note(category="description", text="real"),
        ],
        product_status={"known_affected": ["pkg:x@1"]},
        scores=[],
        flags=[],
        references=[],
        ids=[],
    )
    out = vuln.to_dict()
    assert [n["text"] for n in out["notes"]] == ["real"]


def test_vulnerability_cwe_2_0_single_object():
    vuln = models.Vulnerability(
        cve="CVE-2024-1",
        title="t",
        cwes=[
            {"id": "CWE-787", "name": "Out-of-bounds Write"},
            {"id": "CWE-125", "name": "Out-of-bounds Read"},
        ],
        notes=[],
        product_status={},
        scores=[],
        flags=[],
        references=[],
        ids=[],
    )
    out = vuln.to_dict("2.0")
    # 2.0 permits a single cwe object.
    assert out["cwe"] == {"id": "CWE-787", "name": "Out-of-bounds Write"}
    assert "cwes" not in out


def test_vulnerability_cwe_2_1_array_with_version():
    vuln = models.Vulnerability(
        cve="CVE-2024-1",
        title="t",
        cwes=[
            {"id": "CWE-787", "name": "Out-of-bounds Write"},
            {"id": "CWE-125", "name": "Out-of-bounds Read"},
        ],
        notes=[],
        product_status={},
        scores=[],
        flags=[],
        references=[],
        ids=[],
    )
    out = vuln.to_dict("2.1")
    assert "cwe" not in out
    assert [c["id"] for c in out["cwes"]] == ["CWE-787", "CWE-125"]
    assert all(c["version"] == models.CWE_CATALOG_VERSION for c in out["cwes"])


def test_score_2_0_flat_and_2_1_content_wrapped():
    s = models.Score(products=["pkg:b@1"], cvss_v3={"baseScore": 9.8})
    flat = s.to_dict("2.0")
    assert "cvss_v3" in flat and "content" not in flat
    wrapped = s.to_dict("2.1")
    assert wrapped["content"]["cvss_v3"] == {"baseScore": 9.8}
    assert wrapped["products"] == ["pkg:b@1"]


def test_flag_has_no_justification_field():
    f = models.Flag(label="vulnerable_code_not_in_execute_path", product_ids=["pkg:b@1"])
    out = f.to_dict()
    assert out == {
        "label": "vulnerable_code_not_in_execute_path",
        "product_ids": ["pkg:b@1"],
    }
    assert "justification" not in out


def test_disclosure_vs_release_date_by_version():
    common = dict(
        cve="CVE-2024-1",
        title="t",
        cwes=[],
        notes=[],
        product_status={"known_affected": ["pkg:x@1"]},
        scores=[],
        flags=[],
        references=[],
        ids=[],
        disclosure_date="2024-01-01T00:00:00",
    )
    v20 = models.Vulnerability(**common).to_dict("2.0")
    v21 = models.Vulnerability(**common).to_dict("2.1")
    assert v20["release_date"] == "2024-01-01T00:00:00" and "disclosure_date" not in v20
    assert v21["disclosure_date"] == "2024-01-01T00:00:00" and "release_date" not in v21


# ---------------------------------------------------------------------------
# product_tree
# ---------------------------------------------------------------------------


def _sample_bom():
    return {
        "metadata": {
            "component": {
                "name": "juice-shop",
                "version": "20.1.1",
                "purl": "pkg:npm/juice-shop@20.1.1",
            }
        },
        "components": [
            {
                "name": "express",
                "version": "4.22.2",
                "purl": "pkg:npm/express@4.22.2",
            },
            {
                "group": "@codemirror",
                "name": "lang-json",
                "version": "6.0.2",
                "purl": "pkg:npm/@codemirror/lang-json@6.0.2",
            },
        ],
    }


def test_product_tree_purl_is_product_id():
    tree, pmap = build_product_tree(_sample_bom())
    ids = {p["product_id"] for p in tree["full_product_names"]}
    assert "pkg:npm/juice-shop@20.1.1" in ids
    assert "pkg:npm/express@4.22.2" in ids
    # The product_id IS the purl (single source of truth).
    assert resolve_purl(pmap, "pkg:npm/express@4.22.2") == "pkg:npm/express@4.22.2"


def test_product_tree_helper_shape_by_version():
    tree20, _ = build_product_tree(_sample_bom(), "2.0")
    tree21, _ = build_product_tree(_sample_bom(), "2.1")
    assert all("purl" in p["product_identification_helper"] for p in tree20["full_product_names"])
    assert all("purls" in p["product_identification_helper"] for p in tree21["full_product_names"])


def test_product_tree_resolves_at_namespace_encoding():
    # affects[].ref may use the raw '@' form while the canonical purl uses '%40'.
    _, pmap = build_product_tree(_sample_bom())
    assert resolve_purl(pmap, "pkg:npm/@codemirror/lang-json@6.0.2") == resolve_purl(
        pmap, "pkg:npm/%40codemirror/lang-json@6.0.2"
    )


def test_product_tree_unknown_purl_resolves_empty():
    _, pmap = build_product_tree(_sample_bom())
    # Unknown purls resolve to "" so callers never reference an undefined product.
    assert resolve_purl(pmap, "pkg:npm/does-not-exist@1.0.0") == ""


def test_product_tree_is_deterministic():
    bom = _sample_bom()
    t1, _ = build_product_tree(bom)
    t2, _ = build_product_tree(bom)
    assert t1 == t2


def test_referenced_and_defined_collectors():
    doc = {
        "product_tree": {
            "full_product_names": [
                {"product_id": "A"},
                {"product_id": "B"},
            ]
        },
        "vulnerabilities": [
            {
                "product_status": {"known_affected": ["A"], "known_not_affected": ["B"]},
                "scores": [{"products": ["A"]}],
                "flags": [{"product_ids": ["B"]}],
                "remediations": [{"product_ids": ["A"]}],
            }
        ],
    }
    assert referenced_product_ids(doc) == {"A", "B"}
    assert defined_product_ids(doc) == {"A", "B"}


# ---------------------------------------------------------------------------
# cvss
# ---------------------------------------------------------------------------


_V3 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
_V4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
_V2 = "AV:N/AC:L/Au:N/C:P/I:P/A:P"


def test_parse_one_v3():
    parsed = parse_one({"vector": _V3})
    assert parsed is not None
    family, body = parsed
    assert family == "cvss_v3"
    assert body["baseScore"] == 9.8
    assert body["baseSeverity"] == "CRITICAL"


def test_parse_one_v2():
    parsed = parse_one({"vector": _V2})
    assert parsed is not None
    family, body = parsed
    assert family == "cvss_v2"
    assert body["baseScore"] == 7.5


def test_parse_one_v4_minimal_valid_body():
    parsed = parse_one({"vector": _V4})
    assert parsed is not None
    family, body = parsed
    assert family == "cvss_v4"
    # Only the core, schema-guaranteed fields are emitted; version is "4.0".
    assert set(body) == {"version", "vectorString", "baseScore", "baseSeverity"}
    assert body["version"] == "4.0"
    assert body["baseSeverity"] == body["baseSeverity"].upper()


def test_parse_ratings_drops_v4_for_csaf_2():
    assert parse_ratings([{"vector": _V4}], "2.0") == []
    kept = parse_ratings([{"vector": _V4}], "2.1")
    assert kept and "cvss_v4" in kept[0]


def test_parse_ratings_malformed_vector_skipped():
    # Missing mandatory metrics must not crash the export.
    assert parse_ratings([{"vector": "CVSS:4.0/AV:N"}], "2.1") == []
    assert parse_ratings([{"vector": "nonsense"}], "2.0") == []


def test_parse_ratings_dedupes_identical_vectors():
    out = parse_ratings([{"vector": _V3}, {"vector": _V3}], "2.0")
    assert len(out) == 1


def test_best_severity_picks_highest():
    scores = parse_ratings([{"vector": _V3}], "2.0") + parse_ratings([{"vector": _V2}], "2.0")
    assert best_severity(scores) == "critical"


# ---------------------------------------------------------------------------
# refs
# ---------------------------------------------------------------------------


def test_refs_skips_non_url():
    references = [{"id": "x", "source": {"name": "N", "url": "not-a-url"}}]
    refs, ids = build_references_and_ids(references, [])
    assert refs == []
    assert ids == []


def test_refs_emits_summary_and_url():
    references = [
        {
            "id": "CVE-2021-1234",
            "source": {
                "name": "NVD",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-1234",
            },
        }
    ]
    refs, ids = build_references_and_ids(references, [])
    assert refs == [
        {
            "summary": "CVE Record",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-1234",
            "category": "external",
        }
    ]
    assert {"system_name": "CVE Record", "text": "CVE-2021-1234"} in ids


def test_refs_advisory_token_extracted_from_title():
    advisories = [
        {
            "title": "GitHub Advisory GHSA-w5hq-g745-h8pq",
            "url": "https://github.com/uuidjs/uuid/security/advisories/GHSA-w5hq-g745-h8pq",
        }
    ]
    _, ids = build_references_and_ids([], advisories)
    texts = [i["text"] for i in ids]
    assert "GHSA-W5HQ-G745-H8PQ" in texts


def test_refs_dedup():
    references = [
        {
            "id": "CVE-2021-1234",
            "source": {"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-1234"},
        },
        {
            "id": "CVE-2021-1234",
            "source": {"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-1234"},
        },
    ]
    refs, ids = build_references_and_ids(references, [])
    assert len(refs) == 1
    assert len(ids) == 1


# ---------------------------------------------------------------------------
# reachability
# ---------------------------------------------------------------------------


def _purl_map():
    bom = {
        "components": [
            {"name": "express", "version": "4.22.2", "purl": "pkg:npm/express@4.22.2"},
            {"name": "left-pad", "version": "1.3.0", "purl": "pkg:npm/left-pad@1.3.0"},
            {"name": "ghost", "version": "1.0.0", "purl": "pkg:npm/ghost@1.0.0"},
        ]
    }
    _, pmap = build_product_tree(bom)
    return pmap


def test_reachability_reachable_is_known_affected():
    pmap = _purl_map()
    vuln = {"affects": [{"ref": "pkg:npm/express@4.22.2"}]}
    status, flags, scores = classify(vuln, pmap, {"pkg:npm/express@4.22.2": 240})
    assert status == {KNOWN_AFFECTED: ["pkg:npm/express@4.22.2"]}
    assert flags == []
    assert scores == ["pkg:npm/express@4.22.2"]


def test_reachability_unreachable_gets_flag_with_justification_label():
    pmap = _purl_map()
    vuln = {"affects": [{"ref": "pkg:npm/left-pad@1.3.0"}]}
    status, flags, scores = classify(vuln, pmap, {"pkg:npm/express@4.22.2": 1})
    assert status == {KNOWN_NOT_AFFECTED: ["pkg:npm/left-pad@1.3.0"]}
    assert len(flags) == 1
    # In CSAF the flag label is itself the justification value.
    assert flags[0]["label"] == "vulnerable_code_not_in_execute_path"
    assert "justification" not in flags[0]
    assert flags[0]["product_ids"] == ["pkg:npm/left-pad@1.3.0"]
    assert scores == ["pkg:npm/left-pad@1.3.0"]


def test_reachability_unknown_when_no_reachability_data():
    pmap = _purl_map()
    vuln = {"affects": [{"ref": "pkg:npm/ghost@1.0.0"}]}
    status, flags, scores = classify(vuln, pmap, {})
    assert status == {"under_investigation": ["pkg:npm/ghost@1.0.0"]}
    assert flags == []


def test_reachability_drops_unknown_purl():
    pmap = _purl_map()
    vuln = {"affects": [{"ref": "pkg:npm/does-not-exist@9.9.9"}]}
    status, flags, scores = classify(vuln, pmap, {"pkg:npm/express@4.22.2": 1})
    assert status == {}
    assert flags == []
    assert scores == []


def _multi_lang_purl_map():
    """Product tree with Rust (cargo), Go (golang) and .NET (nuget) components,
    mirroring the versioned purls the rusi/golem/dosai converters reconcile
    against the BOM."""
    bom = {
        "components": [
            {"name": "sqlx", "version": "0.6.2", "purl": "pkg:cargo/sqlx@0.6.2"},
            {"name": "serde", "version": "1.0.152", "purl": "pkg:cargo/serde@1.0.152"},
            {
                "name": "pgx",
                "version": "4.18.1",
                "purl": "pkg:golang/github.com/jackc/pgx/v4@v4.18.1",
            },
            {
                "name": "yaml.v2",
                "version": "2.4.0",
                "purl": "pkg:golang/gopkg.in/yaml.v2@v2.4.0",
            },
            {
                "name": "Newtonsoft.Json",
                "version": "13.0.3",
                "purl": "pkg:nuget/Newtonsoft.Json@13.0.3",
            },
            {
                "name": "AWSSDK.Core",
                "version": "3.7.0",
                "purl": "pkg:nuget/AWSSDK.Core@3.7.0",
            },
        ]
    }
    _, pmap = build_product_tree(bom)
    return pmap


def test_reachability_rust_reachable_is_known_affected():
    """A Rust crate whose reconciled purl carries a reachable flow (rusi) must
    map to known_affected -- CSAF VEX is purl-keyed and language-agnostic."""
    pmap = _multi_lang_purl_map()
    vuln = {"affects": [{"ref": "pkg:cargo/sqlx@0.6.2"}]}
    status, flags, scores = classify(vuln, pmap, {"pkg:cargo/sqlx@0.6.2": 3})
    assert status == {KNOWN_AFFECTED: ["pkg:cargo/sqlx@0.6.2"]}
    assert flags == []
    assert scores == ["pkg:cargo/sqlx@0.6.2"]


def test_reachability_rust_unreachable_gets_not_in_path_flag():
    """A Rust crate present but unreached must map to known_not_affected with
    the vulnerable_code_not_in_execute_path justification flag."""
    pmap = _multi_lang_purl_map()
    vuln = {"affects": [{"ref": "pkg:cargo/serde@1.0.152"}]}
    status, flags, scores = classify(vuln, pmap, {"pkg:cargo/sqlx@0.6.2": 3})
    assert status == {KNOWN_NOT_AFFECTED: ["pkg:cargo/serde@1.0.152"]}
    assert len(flags) == 1
    assert flags[0]["label"] == "vulnerable_code_not_in_execute_path"
    assert flags[0]["product_ids"] == ["pkg:cargo/serde@1.0.152"]


def test_reachability_go_reachable_is_known_affected():
    """A Go module whose versioned purl (golem) carries a reachable flow must
    map to known_affected."""
    pmap = _multi_lang_purl_map()
    vuln = {"affects": [{"ref": "pkg:golang/github.com/jackc/pgx/v4@v4.18.1"}]}
    status, flags, scores = classify(vuln, pmap, {"pkg:golang/github.com/jackc/pgx/v4@v4.18.1": 1})
    assert status == {KNOWN_AFFECTED: ["pkg:golang/github.com/jackc/pgx/v4@v4.18.1"]}
    assert flags == []
    assert scores == ["pkg:golang/github.com/jackc/pgx/v4@v4.18.1"]


def test_reachability_go_unreachable_gets_not_in_path_flag():
    """A Go module present but unreached must map to known_not_affected with
    the vulnerable_code_not_in_execute_path justification flag."""
    pmap = _multi_lang_purl_map()
    vuln = {"affects": [{"ref": "pkg:golang/gopkg.in/yaml.v2@v2.4.0"}]}
    status, flags, scores = classify(vuln, pmap, {"pkg:golang/github.com/jackc/pgx/v4@v4.18.1": 1})
    assert status == {KNOWN_NOT_AFFECTED: ["pkg:golang/gopkg.in/yaml.v2@v2.4.0"]}
    assert len(flags) == 1
    assert flags[0]["label"] == "vulnerable_code_not_in_execute_path"
    assert flags[0]["product_ids"] == ["pkg:golang/gopkg.in/yaml.v2@v2.4.0"]


def test_reachability_dotnet_reachable_is_known_affected():
    """A NuGet package whose reconciled purl carries a reachable flow (dosai)
    must map to known_affected -- CSAF VEX is purl-keyed and language-agnostic."""
    pmap = _multi_lang_purl_map()
    vuln = {"affects": [{"ref": "pkg:nuget/Newtonsoft.Json@13.0.3"}]}
    status, flags, scores = classify(vuln, pmap, {"pkg:nuget/Newtonsoft.Json@13.0.3": 2})
    assert status == {KNOWN_AFFECTED: ["pkg:nuget/Newtonsoft.Json@13.0.3"]}
    assert flags == []
    assert scores == ["pkg:nuget/Newtonsoft.Json@13.0.3"]


def test_reachability_dotnet_unreachable_gets_not_in_path_flag():
    """A NuGet package present but unreached (dosai marks only referenced, not
    called) must map to known_not_affected with the not-in-execute-path flag."""
    pmap = _multi_lang_purl_map()
    vuln = {"affects": [{"ref": "pkg:nuget/AWSSDK.Core@3.7.0"}]}
    status, flags, scores = classify(vuln, pmap, {"pkg:nuget/Newtonsoft.Json@13.0.3": 2})
    assert status == {KNOWN_NOT_AFFECTED: ["pkg:nuget/AWSSDK.Core@3.7.0"]}
    assert len(flags) == 1
    assert flags[0]["label"] == "vulnerable_code_not_in_execute_path"
    assert flags[0]["product_ids"] == ["pkg:nuget/AWSSDK.Core@3.7.0"]


# ---------------------------------------------------------------------------
# tracking
# ---------------------------------------------------------------------------


def test_tracking_always_has_revision_entry():
    t = build_tracking({})
    out = t.to_dict()
    assert len(out["revision_history"]) >= 1
    assert out["version"] == out["revision_history"][-1]["number"]


def test_tracking_preserves_existing_revisions():
    raw = {
        "status": "final",
        "version": "1",
        "initial_release_date": "2024-01-01T00:00:00",
        "current_release_date": "2024-02-01T00:00:00",
        "revision_history": [{"date": "2024-01-01T00:00:00", "number": "1", "summary": "Initial"}],
    }
    out = build_tracking(raw).to_dict()
    assert len(out["revision_history"]) == 1
    assert out["status"] == "final"
    assert out["version"] == "1"


def test_tracking_bumps_version_to_match_revisions():
    raw = {
        "status": "final",
        "version": "5",
        "revision_history": [{"date": "2024-01-01T00:00:00", "number": "1", "summary": "Initial"}],
    }
    out = build_tracking(raw).to_dict()
    assert out["version"] == "1"


# ---------------------------------------------------------------------------
# orchestrator (build_csaf) + emit (path safety, schema validation)
# ---------------------------------------------------------------------------

DEMO_BOM_PATH = DATA_DIR / "vex" / "demo_bom.json"


def _load_demo():
    with open(DEMO_BOM_PATH) as fh:
        return json.load(fh)


@pytest.mark.parametrize("version", VERSIONS)
def test_build_csaf_schema_valid_and_semantically_correct(version):
    bom = _load_demo()
    # express is reachable, everything else is not.
    reached = {"pkg:npm/express@4.22.2": 10}
    doc = build_csaf(bom, bom["vulnerabilities"], reached_purls=reached, csaf_version=version)

    errors = validate(doc, version)
    assert errors == [], f"Expected 0 schema errors for {version}, got:\n" + "\n".join(errors[:10])
    # No product reference is left undefined in the product tree.
    assert referenced_product_ids(doc) <= defined_product_ids(doc)

    by_cve = {v.get("cve"): v for v in doc["vulnerabilities"]}
    metric_key = "metrics" if version == "2.1" else "scores"

    def _cvss(vuln, family):
        for m in vuln.get(metric_key, []):
            body = m.get("content", m)
            if family in body:
                return True
        return False

    # Reachable -> known_affected, no flag.
    express = by_cve["CVE-2024-10001"]
    assert express["product_status"]["known_affected"] == ["pkg:npm/express@4.22.2"]
    assert express.get("flags", []) == []
    assert _cvss(express, "cvss_v3")
    # CWE carries the CWE- prefix and known MITRE name.
    if version == "2.0":
        assert express["cwe"]["id"] == "CWE-787"
        assert express["cwe"]["name"] == "Out-of-bounds Write"
    else:
        assert express["cwes"][0]["id"] == "CWE-787"

    # Unreachable -> known_not_affected + execute-path flag.
    left_pad = by_cve["CVE-2024-20002"]
    assert left_pad["product_status"]["known_not_affected"] == ["pkg:npm/left-pad@1.3.0"]
    assert any(f["label"] == "vulnerable_code_not_in_execute_path" for f in left_pad["flags"])

    # Unknown CWE name -> cwe omitted entirely.
    ghost = by_cve["CVE-2024-30003"]
    assert "cwe" not in ghost and "cwes" not in ghost
    assert _cvss(ghost, "cvss_v2")

    # Revision history is always populated.
    assert len(doc["document"]["tracking"]["revision_history"]) >= 1
    # No note without text.
    for v in doc["vulnerabilities"]:
        for n in v.get("notes", []):
            assert n.get("text")


def test_build_csaf_asserts_no_dangling_refs():
    bom = _load_demo()
    doc = build_csaf(bom, bom["vulnerabilities"], reached_purls={}, csaf_version="2.1")
    assert referenced_product_ids(doc) <= defined_product_ids(doc)


def test_build_csaf_2_1_has_schema_uri_2_0_does_not():
    bom = _load_demo()
    doc21 = build_csaf(bom, bom["vulnerabilities"], csaf_version="2.1")
    doc20 = build_csaf(bom, bom["vulnerabilities"], csaf_version="2.0")
    assert doc21["$schema"].endswith("v2.1/schema/csaf.json")
    assert doc21["document"]["csaf_version"] == "2.1"
    assert "$schema" not in doc20
    assert doc20["document"]["csaf_version"] == "2.0"


def test_output_path_never_touches_vdr_or_bom():
    # A .vdr.json input must yield a standalone .csaf.json output.
    out = output_path("/proj/reports/sbom-js-build.vdr.json", "/proj/reports")
    assert out == "/proj/reports/sbom-js-build.csaf.json"
    assert out.endswith(".csaf.json")
    assert not out.endswith(".vdr.json")
    out_cdx = output_path("/proj/reports/sbom-js-build.cdx.json", "/proj/reports")
    assert out_cdx == "/proj/reports/sbom-js-build.csaf.json"


@pytest.mark.parametrize("version", VERSIONS)
def test_export_csaf_writes_csaf_file_and_leaves_vdr_intact(tmp_path, version):
    bom = _load_demo()
    # Stage a fake VDR file alongside the output dir to prove it is never touched.
    vdr_path = tmp_path / "demo.vdr.json"
    vdr_path.write_text('{"vdr": true}')
    reached = {"pkg:npm/express@4.22.2": 1}

    class _Result:
        pkg_vulnerabilities = bom["vulnerabilities"]
        reached_purls = reached

    outfile, errors = export_csaf(
        _Result(),
        src_dir=str(tmp_path),
        reports_dir=str(tmp_path),
        bom_file=str(vdr_path),
        bom=bom,
        csaf_version=version,
    )
    assert outfile is not None
    assert outfile.endswith(".csaf.json")
    assert errors == []
    # The VDR file must be untouched.
    assert json.loads(vdr_path.read_text()) == {"vdr": True}
    assert Path(outfile).exists()


# ---------------------------------------------------------------------------
# juice-shop e2e (environment-gated; runs when fixtures are available so the
# full real-world document stays under schema/reachability assertion).
# ---------------------------------------------------------------------------

JUICE_SHOP_DIR = os.getenv("DEPSCAN_JUICE_SHOP_DIR", "/Users/prabhu/sandbox/juice-shop")
JUICE_SHOP_BOM = os.path.join(JUICE_SHOP_DIR, "reports", "sbom-js-build.cdx.json")
JUICE_SHOP_VDR = os.path.join(JUICE_SHOP_DIR, "reports", "sbom-js-build.vdr.json")
JUICE_SHOP_SLICES = os.path.join(JUICE_SHOP_DIR, "reports", "js-reachables.slices.json")

juice_shop_present = all(
    os.path.exists(p) for p in (JUICE_SHOP_BOM, JUICE_SHOP_VDR, JUICE_SHOP_SLICES)
)


# ---------------------------------------------------------------------------
# Issue #511: CSAF §6.1 semantic compliance
# ---------------------------------------------------------------------------
def test_dates_normalize_to_rfc3339_utc_z():
    # Naive timestamps (the #511 bug) gain a Z; offsets convert to UTC.
    assert to_csaf_datetime("2026-07-24T03:45:16") == "2026-07-24T03:45:16Z"
    assert to_csaf_datetime("2025-07-01T17:15:30") == "2025-07-01T17:15:30Z"
    assert to_csaf_datetime("2026-07-24T12:27:58+09:00") == "2026-07-24T03:27:58Z"
    assert to_csaf_datetime("2026-07-24T03:45:16Z") == "2026-07-24T03:45:16Z"
    assert is_rfc3339(now_csaf())
    assert to_csaf_datetime("") is None
    assert to_csaf_datetime("not-a-date", "2020-01-01T00:00:00") == "2020-01-01T00:00:00Z"


def test_is_rfc3339_rejects_missing_timezone():
    assert not is_rfc3339("2026-07-24T03:45:16")
    assert is_rfc3339("2026-07-24T03:45:16Z")
    assert is_rfc3339("2026-07-24T03:45:16+09:00")


def test_tracking_dates_are_rfc3339():
    t = build_tracking({"initial_release_date": "2026-07-24T03:45:16"}).to_dict()
    assert is_rfc3339(t["initial_release_date"])
    assert is_rfc3339(t["current_release_date"])
    assert is_rfc3339(t["revision_history"][0]["date"])


def test_synthesize_id_for_distro_advisory():
    got = synthesize_id("DLA-4485-1/pkg:deb/debian/ca-certificates@20210119")
    assert got == {"system_name": "Debian LTS Advisory", "text": "DLA-4485-1"}
    assert synthesize_id("USN-1234-5") == {
        "system_name": "Ubuntu Security Notice",
        "text": "USN-1234-5",
    }
    assert synthesize_id("just a title with no id") is None


def test_vulnerability_without_cve_gets_synthesized_id():
    # A distro advisory whose only id lives in title must still carry an id
    # (§6.1.27.8).
    vuln = {
        "id": "DLA-4485-1/pkg:deb/debian/curl@7.74.0",
        "bom-ref": "DLA-4485-1/pkg:deb/debian/curl@7.74.0",
        "affects": [{"ref": "pkg:deb/debian/curl@7.74.0"}],
    }
    purl_to_id = {"pkg:deb/debian/curl@7.74.0": "pkg:deb/debian/curl@7.74.0"}
    model = build_vulnerability(vuln, purl_to_id, {"pkg:deb/debian/curl@7.74.0": 1}, "2.1")
    assert model is not None
    assert model.cve is None
    assert model.ids and model.ids[0]["text"] == "DLA-4485-1"


def test_scores_deduped_per_cvss_version():
    # Two different v3.1 vectors on the same product -> only one v3 score
    # (§6.1.7).
    vuln = {
        "id": "CVE-2024-0001",
        "bom-ref": "CVE-2024-0001/pkg:deb/debian/nghttp2@1.43.0-1",
        "ratings": [
            {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
            {"vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        ],
        "affects": [{"ref": "pkg:deb/debian/nghttp2@1.43.0-1"}],
    }
    pid = "pkg:deb/debian/nghttp2@1.43.0-1"
    model = build_vulnerability(vuln, {pid: pid}, {pid: 1}, "2.1")
    # The vuln references a known product, so a model must come back.
    assert model is not None
    v3_scores = [s for s in model.scores if s.cvss_v3]
    assert len(v3_scores) == 1


def _clean_doc():
    bom = _load_demo()
    return build_csaf(bom, bom["vulnerabilities"], reached_purls={}, csaf_version="2.1")


@pytest.mark.parametrize("version", VERSIONS)
def test_generated_document_passes_all_semantic_tests(version):
    bom = _load_demo()
    doc = build_csaf(bom, bom["vulnerabilities"], reached_purls={}, csaf_version=version)
    assert validate_semantic(doc, version) == []


def test_semantic_catches_naive_datetime():
    doc = _clean_doc()
    doc["document"]["tracking"]["current_release_date"] = "2026-07-24T03:45:16"
    errs = validate_semantic(doc, "2.1")
    assert any(e.startswith("6.1.37") and "current_release_date" in e for e in errs)


def test_semantic_catches_missing_vuln_id():
    doc = _clean_doc()
    doc["vulnerabilities"][0].pop("cve", None)
    doc["vulnerabilities"][0].pop("ids", None)
    errs = validate_semantic(doc, "2.1")
    assert any(e.startswith("6.1.27.8") for e in errs)


def test_semantic_catches_duplicate_cvss_version_per_product():
    doc = _clean_doc()
    vuln = doc["vulnerabilities"][0]
    metric = {
        "products": ["pkg:npm/express@4.22.2"],
        "content": {"cvss_v3": {"version": "3.1", "baseScore": 5.0}},
    }
    vuln["metrics"] = [metric, dict(metric)]
    vuln["product_status"] = {"known_affected": ["pkg:npm/express@4.22.2"]}
    errs = validate_semantic(doc, "2.1")
    assert any(e.startswith("6.1.7") for e in errs)


def test_semantic_catches_dangling_and_contradicting_status():
    doc = _clean_doc()
    vuln = doc["vulnerabilities"][0]
    vuln["product_status"] = {
        "known_affected": ["pkg:npm/ghost@1.0.0"],
        "known_not_affected": ["pkg:npm/ghost@1.0.0"],
    }
    errs = validate_semantic(doc, "2.1")
    assert any(e.startswith("6.1.1") for e in errs)  # dangling
    assert any(e.startswith("6.1.6") for e in errs)  # contradiction


def test_semantic_catches_multiple_use_of_same_cve():
    doc = _clean_doc()
    doc["vulnerabilities"][1]["cve"] = doc["vulnerabilities"][0]["cve"]
    errs = validate_semantic(doc, "2.1")
    assert any(e.startswith("6.1.23") for e in errs)


def test_semantic_catches_inconsistent_cvss_severity():
    doc = _clean_doc()
    vuln = doc["vulnerabilities"][0]
    vuln["product_status"] = {"known_affected": ["pkg:npm/express@4.22.2"]}
    vuln["metrics"] = [
        {
            "products": ["pkg:npm/express@4.22.2"],
            "content": {
                "cvss_v3": {
                    "version": "3.1",
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "baseScore": 9.8,
                    "baseSeverity": "LOW",
                }
            },
        }
    ]
    errs = validate_semantic(doc, "2.1")
    assert any(e.startswith("6.1.10") for e in errs)


def test_semantic_accepts_lowercase_t_z_as_invalid():
    # §2.3 requires upper-case T and Z.
    assert not is_rfc3339("2026-07-24t03:45:16z")
    assert is_rfc3339("2026-07-24T03:45:16Z")


def test_semantic_allows_recommended_overlap_but_flags_real_contradiction():
    doc = _clean_doc()
    vuln = doc["vulnerabilities"][0]
    pid = "pkg:npm/express@4.22.2"
    # recommended may overlap known_affected -> no contradiction.
    vuln["product_status"] = {"known_affected": [pid], "recommended": [pid]}
    vuln["remediations"] = [{"category": "none_available", "details": "x", "product_ids": [pid]}]
    assert not any(e.startswith("6.1.6") for e in validate_semantic(doc, "2.1"))
    # fixed + known_affected is a genuine contradiction.
    vuln["product_status"] = {"known_affected": [pid], "fixed": [pid]}
    assert any(e.startswith("6.1.6") for e in validate_semantic(doc, "2.1"))


def test_semantic_allows_unknown_status_value():
    doc = _clean_doc()
    vuln = doc["vulnerabilities"][0]
    pid = "pkg:npm/express@4.22.2"
    vuln["product_status"] = {"under_investigation": [pid], "unknown": [pid]}
    assert not any("unknown status" in e for e in validate_semantic(doc, "2.1"))


def test_semantic_flag_with_group_ids_is_accepted():
    doc = _clean_doc()
    vuln = doc["vulnerabilities"][0]
    vuln["flags"] = [{"label": "component_not_present", "group_ids": ["grp-1"]}]
    assert not any(e.startswith("6.1.32") for e in validate_semantic(doc, "2.1"))


def test_semantic_scores_from_distinct_sources_not_flagged():
    doc = _clean_doc()
    vuln = doc["vulnerabilities"][0]
    pid = "pkg:npm/express@4.22.2"
    vuln["product_status"] = {"known_affected": [pid]}
    vuln["remediations"] = [{"category": "none_available", "details": "x", "product_ids": [pid]}]
    vuln["metrics"] = [
        {
            "products": [pid],
            "source": "nvd",
            "content": {"cvss_v3": {"version": "3.1", "baseScore": 5.0}},
        },
        {
            "products": [pid],
            "source": "debian",
            "content": {"cvss_v3": {"version": "3.1", "baseScore": 5.0}},
        },
    ]
    assert not any(e.startswith("6.1.7") for e in validate_semantic(doc, "2.1"))


def test_known_affected_gets_remediation_action_statement():
    bom = _load_demo()
    reached = {"pkg:npm/express@4.22.2": 3}
    doc = build_csaf(bom, bom["vulnerabilities"], reached_purls=reached, csaf_version="2.1")
    affected = [
        v
        for v in doc["vulnerabilities"]
        if "pkg:npm/express@4.22.2" in (v.get("product_status") or {}).get("known_affected", [])
    ]
    assert affected, "expected express to be known_affected"
    for v in affected:
        rem_products = {p for r in v.get("remediations", []) for p in r.get("product_ids", [])}
        assert "pkg:npm/express@4.22.2" in rem_products
    # And the full document passes every semantic test.
    assert validate_semantic(doc, "2.1") == []


def test_semantic_catches_missing_action_statement():
    doc = _clean_doc()
    vuln = doc["vulnerabilities"][0]
    vuln["product_status"] = {"known_affected": ["pkg:npm/express@4.22.2"]}
    vuln.pop("remediations", None)
    assert any(e.startswith("6.1.27.10") for e in validate_semantic(doc, "2.1"))


def test_vex_profile_tests_do_not_fire_for_security_advisory():
    # A csaf_security_advisory legitimately uses first_affected and needs no
    # VEX action statement -- the §6.1.27.x tests must not fire.
    doc = _clean_doc()
    doc["document"]["category"] = "csaf_security_advisory"
    vuln = doc["vulnerabilities"][0]
    vuln["product_status"] = {"first_affected": ["pkg:npm/express@4.22.2"]}
    vuln.pop("remediations", None)
    errs = validate_semantic(doc, "2.1")
    assert not any(e.startswith("6.1.27") for e in errs)


def test_impact_statement_satisfied_via_group_ids():
    doc = _clean_doc()
    pid = "pkg:npm/express@4.22.2"
    doc["product_tree"]["product_groups"] = [{"group_id": "grp-1", "product_ids": [pid]}]
    vuln = doc["vulnerabilities"][0]
    vuln["product_status"] = {"known_not_affected": [pid]}
    # Flag references the product only through its group.
    vuln["flags"] = [{"label": "component_not_present", "group_ids": ["grp-1"]}]
    assert not any(e.startswith("6.1.27.9") for e in validate_semantic(doc, "2.1"))


def test_action_statement_satisfied_via_group_ids():
    doc = _clean_doc()
    pid = "pkg:npm/express@4.22.2"
    doc["product_tree"]["product_groups"] = [{"group_id": "grp-1", "product_ids": [pid]}]
    vuln = doc["vulnerabilities"][0]
    vuln["product_status"] = {"known_affected": [pid]}
    vuln["remediations"] = [{"category": "vendor_fix", "details": "x", "group_ids": ["grp-1"]}]
    assert not any(e.startswith("6.1.27.10") for e in validate_semantic(doc, "2.1"))


def test_released_status_flags_zero_revision_entry():
    # §6.1.18: a final document may not carry a revision-history entry with a
    # zero version number.
    doc = _clean_doc()
    tracking = doc["document"]["tracking"]
    tracking["status"] = "final"
    tracking["version"] = "2"
    tracking["revision_history"] = [
        {"number": "0", "date": "2026-07-24T00:00:00Z", "summary": "draft"},
        {"number": "2", "date": "2026-07-24T01:00:00Z", "summary": "release"},
    ]
    assert any(e.startswith("6.1.18") for e in validate_semantic(doc, "2.1"))


def test_semantic_flags_prerelease_revision_number():
    # §6.1.19: no revision number may carry pre-release information.
    doc = _clean_doc()
    doc["document"]["tracking"]["revision_history"][0]["number"] = "1.0.0-rc1"
    doc["document"]["tracking"]["version"] = "1.0.0-rc1"
    assert any(e.startswith("6.1.19") for e in validate_semantic(doc, "2.1"))


def test_semantic_allows_build_metadata_hyphen_for_final():
    # §3.1.11.2: build metadata (after '+') is allowed for final docs even
    # when it contains a hyphen; it is not pre-release information.
    doc = _clean_doc()
    tracking = doc["document"]["tracking"]
    tracking["status"] = "final"
    tracking["version"] = "1.0.0+build-2"
    tracking["revision_history"] = [
        {"number": "1.0.0+build-2", "date": "2026-07-24T00:00:00Z", "summary": "release"}
    ]
    errs = validate_semantic(doc, "2.1")
    assert not any(e.startswith("6.1.17") for e in errs)
    assert not any(e.startswith("6.1.19") for e in errs)


def test_semantic_flags_vex_vuln_without_product_status():
    # §6.1.27.7: a VEX vulnerability with no core status (empty product_status)
    # must be flagged.
    doc = _clean_doc()
    doc["vulnerabilities"][0]["product_status"] = {}
    assert any(e.startswith("6.1.27.7") for e in validate_semantic(doc, "2.1"))


def test_semantic_unknown_status_uses_schema_label_not_6_1_6():
    doc = _clean_doc()
    doc["vulnerabilities"][0]["product_status"] = {"bogus_status": ["pkg:npm/express@4.22.2"]}
    errs = validate_semantic(doc, "2.1")
    assert any(e.startswith("schema") and "unknown status" in e for e in errs)
    assert not any(e.startswith("6.1.6") and "unknown status" in e for e in errs)


def test_validate_end_to_end_flags_naive_datetime_via_format_checker():
    # Even a schema-valid document must fail validate() when a timestamp lacks
    # a timezone -- the regression that shipped in #511.
    doc = _clean_doc()
    doc["document"]["tracking"]["current_release_date"] = "2026-07-24T03:45:16"
    errs = validate(doc, "2.1")
    assert errs, "expected validate() to report the naive datetime"


@pytest.mark.skipif(not juice_shop_present, reason="juice-shop fixtures not available")
@pytest.mark.parametrize("version", VERSIONS)
def test_juice_shop_csaf_is_schema_valid_and_reachability_aware(version):
    import urllib.parse as _up

    bom = json.load(open(JUICE_SHOP_BOM))
    vdr = json.load(open(JUICE_SHOP_VDR))
    reached = {}
    for slice_obj in json.load(open(JUICE_SHOP_SLICES)) or []:
        for p in slice_obj.get("purls") or []:
            key = _up.unquote(p)
            reached[key] = reached.get(key, 0) + 1
    doc = build_csaf(
        bom, vdr.get("vulnerabilities", []), reached_purls=reached, csaf_version=version
    )
    # Zero schema errors and no dangling product references.
    assert validate(doc, version) == []
    assert referenced_product_ids(doc) <= defined_product_ids(doc)
    # Reachability is reflected: some known_affected and some known_not_affected
    # carrying the execute-path flag.
    statuses = set()
    for v in doc["vulnerabilities"]:
        statuses.update((v.get("product_status") or {}).keys())
    assert "known_affected" in statuses
    assert "known_not_affected" in statuses
    assert any(
        f.get("label") == "vulnerable_code_not_in_execute_path"
        for v in doc["vulnerabilities"]
        for f in v.get("flags", [])
    )
