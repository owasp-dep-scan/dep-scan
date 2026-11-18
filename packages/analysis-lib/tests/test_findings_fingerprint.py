"""Tests for the dsf1 fingerprint and its cross-implementation vectors."""

import hashlib
import json
from importlib import resources
from typing import Any, Dict

import pytest

from analysis_lib.findings.schemas import load_schema
from analysis_lib.findings.fingerprint import (
    CATEGORIES,
    FINGERPRINT_VERSION,
    _canonical_payload,
    finding_fingerprint,
    normalise_file,
    normalise_purl,
    normalise_rule,
)

# The keys finding_fingerprint accepts. The only keys a vector's input may
# carry beyond these are line and column, which exist to show that they are
# ignored; the invariant test below keeps any other key from sneaking in.
FINGERPRINT_INPUTS = {"category", "rule", "components", "file", "function", "symbols"}
IGNORED_INPUTS = {"line", "column"}


def _vectors():
    vectors_path = (
        resources.files("analysis_lib.findings")
        .joinpath("schemas")
        .joinpath("depscan-finding-fingerprint-vectors.json")
    )
    return json.loads(vectors_path.read_text(encoding="utf-8"))


def test_fingerprint_version_is_1():
    assert FINGERPRINT_VERSION == 1
    assert finding_fingerprint("vulnerability", "CVE-2021-23337", ["pkg:npm/lodash@4.17.20"]).startswith(
        "dsf1:"
    )


def test_vector_inputs_only_carry_known_keys():
    for vector in _vectors():
        extra = set(vector["input"]) - FINGERPRINT_INPUTS - IGNORED_INPUTS
        assert not extra, f"{vector['name']} carries unknown input keys: {extra}"


@pytest.mark.parametrize("vector", _vectors(), ids=lambda v: v["name"])
def test_vector_reproduces(vector):
    kwargs: Dict[str, Any] = {
        key: value for key, value in vector["input"].items() if key in FINGERPRINT_INPUTS
    }
    assert finding_fingerprint(**kwargs) == vector["id"]
    # The encoding contract: the id is dsf1: plus the SHA-256 of the exact
    # canonical bytes, checked here without going through the module.
    digest = hashlib.sha256(vector["canonical"].encode("utf-8")).hexdigest()
    assert vector["id"] == f"dsf{FINGERPRINT_VERSION}:{digest}"
    # The normalisation contract: the module must serialise the same bytes.
    canonical = json.dumps(
        _canonical_payload(**kwargs), ensure_ascii=False, separators=(",", ":")
    )
    assert canonical == vector["canonical"], vector["name"]


def test_line_and_column_are_never_fingerprinted():
    vectors = {v["name"]: v for v in _vectors()}
    base = vectors["category-memory-safety"]["id"]
    assert vectors["same-finding-different-line-42"]["id"] == base
    assert vectors["same-finding-different-line-9999"]["id"] == base


def test_monorepo_manifests_give_different_ids():
    vectors = {v["name"]: v for v in _vectors()}
    billing = vectors["monorepo-billing-manifest"]["id"]
    web = vectors["monorepo-web-manifest-different-id"]["id"]
    assert billing != web


def test_normalise_rule_canonical_cases():
    assert normalise_rule("cve-2021-23337") == "CVE-2021-23337"
    assert normalise_rule("  CVE-2021-23337  ") == "CVE-2021-23337"
    assert normalise_rule("ghsa-p6mc-m468-83gw") == "GHSA-p6mc-m468-83gw"
    assert normalise_rule("GHSA-P6MC-M468-83GW") == "GHSA-p6mc-m468-83gw"
    assert normalise_rule("RUSI-MS-PANIC-001") == "RUSI-MS-PANIC-001"
    assert normalise_rule("  cdx-audit-001 ") == "cdx-audit-001"


def test_normalise_purl_strips_version_qualifiers_subpath():
    assert normalise_purl("pkg:npm/lodash@4.17.20") == "pkg:npm/lodash"
    assert normalise_purl("pkg:maven/org.apache.commons/commons-text@1.9?type=jar") == (
        "pkg:maven/org.apache.commons/commons-text"
    )
    assert normalise_purl("pkg:npm/express@4.21.2#/lib/express.js") == "pkg:npm/express"
    assert normalise_purl("pkg:NPM/Express@4.2.0") == "pkg:npm/express"
    assert normalise_purl("pkg:npm/%40appthreat/cdxgen@7.1.0") == "pkg:npm/%40appthreat/cdxgen"


def test_normalise_file_paths():
    assert normalise_file("src\\app\\main.c") == "src/app/main.c"
    assert normalise_file("./src/app/main.c") == "src/app/main.c"
    assert normalise_file("././src/app/main.c") == "src/app/main.c"
    assert normalise_file("SRC/App/Main.c") == "SRC/App/Main.c"


def test_component_and_symbol_normalisation():
    # Components sort and dedupe after normalisation; symbols keep their
    # first occurrence in path order.
    payload = _canonical_payload(
        "vulnerability",
        "CVE-2021-23337",
        ["pkg:npm/lodash@4.17.20", "pkg:npm/express@4.21.2", "pkg:npm/lodash@4.17.21"],
        "package-lock.json",
        "",
        ["read", "memcpy", "read"],
    )
    assert payload[4] == ["pkg:npm/express", "pkg:npm/lodash"]
    assert payload[7] == ["read", "memcpy"]


def test_invalid_purl_raises():
    with pytest.raises(ValueError) as excinfo:
        finding_fingerprint("vulnerability", "CVE-2021-23337", ["not-a-purl"])
    assert "not-a-purl" in str(excinfo.value)


def test_single_string_inputs_raise():
    with pytest.raises(ValueError, match="components"):
        finding_fingerprint("vulnerability", "CVE-2021-23337", "pkg:npm/lodash@4.17.20")
    with pytest.raises(ValueError, match="symbols"):
        finding_fingerprint(
            "memory-safety", "RUSI-MS-PANIC-001", ["pkg:cargo/shopcart@0.1.0"],
            symbols="memcpy",
        )


def test_categories_match_the_schema_enum():
    assert list(CATEGORIES) == load_schema("finding")["properties"]["category"]["enum"]


@pytest.mark.parametrize("category", ["", "Vulnerability", "secret"])
def test_unknown_category_raises(category):
    with pytest.raises(ValueError, match="category"):
        finding_fingerprint(category, "CVE-2021-23337", ["pkg:npm/lodash@4.17.20"])


@pytest.mark.parametrize(
    "path",
    ["/home/user/app/package-lock.json", "C:\\work\\app\\main.c", "c:/work/main.c", "\\\\server\\share\\main.c"],
)
def test_absolute_paths_raise(path):
    with pytest.raises(ValueError, match="relative to the scan root"):
        finding_fingerprint("code", "RULE-1", [], file=path)


def test_drive_letter_lookalikes_stay_relative():
    assert normalise_file("c/main.c") == "c/main.c"
    assert normalise_file("src/C:/odd") == "src/C:/odd"


def test_empty_category_or_rule_raise():
    with pytest.raises(ValueError, match="category"):
        finding_fingerprint("", "CVE-2021-23337", ["pkg:npm/lodash@4.17.20"])
    with pytest.raises(ValueError, match="rule"):
        finding_fingerprint("vulnerability", "  ", ["pkg:npm/lodash@4.17.20"])
