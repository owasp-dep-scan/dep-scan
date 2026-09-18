"""Tests for the duplicate filter in VDRAnalyzer.process().

Discussion #527: the filter keyed duplicates on (vulnerability id, fix version)
alone, without the affected component. In a single BOM that contains multiple
versions of the same package (common for transitive npm dependencies), every
occurrence after the first was marked likely_false_positive and dropped from
pkg_vulnerabilities — so dedupe_vdrs never got the chance to merge the extra
affects[].refs and the VDR under-reported the affected components. The filter
must only collapse exact duplicates of the same (CVE, fix version, component),
which is the cross-BOM (--bom-dir) case it was written for.
"""

import json
import os
from types import SimpleNamespace
from typing import Any

import pytest

from analysis_lib import VdrAnalysisKV, utils
from analysis_lib import vdr as vdr_module
from analysis_lib.vdr import VDRAnalyzer

DATA_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "data")


class DummyCVE:
    """Stands in for vdb.lib.cve_model.CVE so analyze_cve_vuln's isinstance
    check takes the full enrichment path without a real vdb record."""

    root: Any


def _raw_vdb_result(cve_id, purl, fix_version=""):
    """Build a raw vdb search result shaped like search.py's output for one
    matched component: matched_by carries the full component purl."""
    cve_record = DummyCVE()
    cve_record.root = SimpleNamespace(
        containers=SimpleNamespace(
            cna=SimpleNamespace(
                references=None,
                metrics=None,
                descriptions=None,
                problemTypes=None,
                affected=None,
            )
        )
    )
    return {
        "cve_id": cve_id,
        "matched_by": purl,
        "matching_vers": "vers:apache/>=0.0.0",
        "purl_prefix": purl.rsplit("@", 1)[0],
        "source_data": cve_record,
        "fix_version": fix_version,
        "type": "npm",
    }


@pytest.fixture
def dummy_cve(monkeypatch):
    monkeypatch.setattr(utils, "CVE", DummyCVE)


def _run_analyzer(monkeypatch, raw_results, *, bom_file=None, pkg_list=None, fuzzy_search=False):
    def _fake_find_vulns(*_args, **_kwargs):
        return list(raw_results), {}, {}

    monkeypatch.setattr(vdr_module, "find_vulns", _fake_find_vulns)
    options = VdrAnalysisKV(
        project_type="nodejs",
        init_results=[],
        pkg_aliases={},
        purl_aliases={},
        suggest_mode=False,
        scoped_pkgs={"required": [], "optional": []},
        no_vuln_table=True,
        bom_file=bom_file,
        pkg_list=pkg_list or [{"purl": "pkg:npm/demo@1.0.0"}],
        direct_purls={},
        reached_purls={},
        reached_services={},
        endpoint_reached_purls={},
        fuzzy_search=fuzzy_search,
    )
    return VDRAnalyzer(options).process()


def _vdr_refs(vdr):
    return {a["ref"] for a in vdr["affects"]}


# ---------------------------------------------------------------------------
# Discussion #527 — multiple versions of one package in a single BOM must all
# survive the process() filter and merge into one VDR entry per CVE.
# ---------------------------------------------------------------------------


def test_same_cve_and_fix_on_two_components_is_not_a_duplicate(dummy_cve, monkeypatch):
    """The exact trigger from the discussion: two versions of postcss share a
    CVE and its fix version. The old key (id|fixed_location) collapsed them;
    the fix must keep both so dedupe_vdrs merges their affects refs."""
    result = _run_analyzer(
        monkeypatch,
        [
            _raw_vdb_result("CVE-2026-41305", "pkg:npm/postcss@8.4.31", "8.4.50"),
            _raw_vdb_result("CVE-2026-41305", "pkg:npm/postcss@8.4.49", "8.4.50"),
        ],
    )

    vdrs = result.pkg_vulnerabilities
    assert result.success is True
    assert len(vdrs) == 1
    assert _vdr_refs(vdrs[0]) == {"pkg:npm/postcss@8.4.31", "pkg:npm/postcss@8.4.49"}
    # Each component keeps its own unaffected (fix) version entry
    fix_versions = {
        a["ref"]: [v["version"] for v in a["versions"] if v.get("status") == "unaffected"]
        for a in vdrs[0]["affects"]
    }
    assert fix_versions == {
        "pkg:npm/postcss@8.4.31": ["8.4.50"],
        "pkg:npm/postcss@8.4.49": ["8.4.50"],
    }


def test_exact_duplicates_are_still_filtered(dummy_cve, monkeypatch):
    """Cross-BOM (--bom-dir) scans surface the same component matched by the
    same CVE with the same fix version more than once. Those exact duplicates
    must still collapse — one affects entry per ref, no repeated versions."""
    result = _run_analyzer(
        monkeypatch,
        [
            _raw_vdb_result("CVE-2026-41305", "pkg:npm/postcss@8.4.31", "8.4.50"),
            # exact duplicate of the first result
            _raw_vdb_result("CVE-2026-41305", "pkg:npm/postcss@8.4.31", "8.4.50"),
            _raw_vdb_result("CVE-2026-41305", "pkg:npm/postcss@8.4.49", "8.4.50"),
        ],
    )

    vdrs = result.pkg_vulnerabilities
    assert len(vdrs) == 1
    assert _vdr_refs(vdrs[0]) == {"pkg:npm/postcss@8.4.31", "pkg:npm/postcss@8.4.49"}
    # No duplicate version rows for the twice-seen component
    versions_8431 = next(
        a["versions"] for a in vdrs[0]["affects"] if a["ref"] == "pkg:npm/postcss@8.4.31"
    )
    assert len(versions_8431) == 2  # one affected range + one unaffected fix


def test_mixed_fix_versions_across_components(dummy_cve, monkeypatch):
    """A CVE whose fix version differs per matched component already worked
    under the old key; it must keep working under the new one."""
    result = _run_analyzer(
        monkeypatch,
        [
            _raw_vdb_result("CVE-2026-41305", "pkg:npm/postcss@8.4.31", "8.4.50"),
            _raw_vdb_result("CVE-2026-41305", "pkg:npm/postcss@8.4.49", "8.4.50"),
            _raw_vdb_result("CVE-2026-41305", "pkg:npm/postcss@8.5.4", "8.5.5"),
        ],
    )

    vdrs = result.pkg_vulnerabilities
    assert len(vdrs) == 1
    assert _vdr_refs(vdrs[0]) == {
        "pkg:npm/postcss@8.4.31",
        "pkg:npm/postcss@8.4.49",
        "pkg:npm/postcss@8.5.4",
    }


def test_multiple_cves_across_multiple_packages(dummy_cve, monkeypatch):
    """Two packages, two versions each, both hit by two CVEs — the synthetic
    reproducer offered in the discussion. One merged entry per CVE, each
    carrying every affected component."""
    postcss = ["pkg:npm/postcss@8.4.31", "pkg:npm/postcss@8.4.49"]
    minimatch = ["pkg:npm/minimatch@3.0.4", "pkg:npm/minimatch@3.1.2"]
    raw = []
    for cve, fix in (("CVE-2026-41305", "8.4.50"), ("CVE-2026-41306", "9.0.0")):
        for purl in postcss:
            raw.append(_raw_vdb_result(cve, purl, fix))
        for purl in minimatch:
            raw.append(_raw_vdb_result(cve, purl, fix))

    result = _run_analyzer(monkeypatch, raw)

    vdrs = result.pkg_vulnerabilities
    assert len(vdrs) == 2
    by_id = {v["id"]: v for v in vdrs}
    assert set(by_id) == {"CVE-2026-41305", "CVE-2026-41306"}
    for vdr in by_id.values():
        assert _vdr_refs(vdr) == set(postcss) | set(minimatch)


def test_fuzzy_search_surfaces_all_components(dummy_cve, monkeypatch):
    """In fuzzy mode likely-false-positive entries are surfaced rather than
    hidden; distinct components sharing a CVE must still merge to one entry."""
    result = _run_analyzer(
        monkeypatch,
        [
            _raw_vdb_result("CVE-2026-41305", "pkg:npm/postcss@8.4.31", "8.4.50"),
            _raw_vdb_result("CVE-2026-41305", "pkg:npm/postcss@8.4.49", "8.4.50"),
        ],
        fuzzy_search=True,
    )

    vdrs = result.pkg_vulnerabilities
    assert len(vdrs) == 1
    assert _vdr_refs(vdrs[0]) == {"pkg:npm/postcss@8.4.31", "pkg:npm/postcss@8.4.49"}


# ---------------------------------------------------------------------------
# Fixture-driven end-to-end test: a single BOM with three versions of postcss
# and two of minimatch (the shape of the reporter's SBOM), scanned through
# VDRAnalyzer with the BOM file feeding lifecycle and dependency-tree parsing.
# ---------------------------------------------------------------------------


def test_multiversion_bom_scan_reports_every_affected_component(dummy_cve, monkeypatch):
    bom_file = os.path.join(DATA_DIR, "bom-multiversion-npm.json")
    with open(bom_file, encoding="utf-8") as f:
        bom = json.load(f)
    purls = [c["purl"] for c in bom["components"]]

    # CVE-A hits every postcss version with one shared fix version (the
    # old-key collision). CVE-B hits only the two minimatch versions.
    raw = [_raw_vdb_result("CVE-2026-41305", p, "8.5.0") for p in purls if "postcss" in p]
    raw += [_raw_vdb_result("CVE-2026-52001", p, "3.1.2") for p in purls if "minimatch" in p]

    result = _run_analyzer(monkeypatch, raw, bom_file=bom_file, pkg_list=bom["components"])

    vdrs = result.pkg_vulnerabilities
    assert result.success is True
    by_id = {v["id"]: v for v in vdrs}
    assert set(by_id) == {"CVE-2026-41305", "CVE-2026-52001"}
    assert _vdr_refs(by_id["CVE-2026-41305"]) == {
        "pkg:npm/postcss@8.4.31",
        "pkg:npm/postcss@8.4.49",
        "pkg:npm/postcss@8.5.4",
    }
    assert _vdr_refs(by_id["CVE-2026-52001"]) == {
        "pkg:npm/minimatch@3.0.4",
        "pkg:npm/minimatch@3.1.2",
    }


def test_multiversion_bom_fixture_shape():
    """Guard the fixture itself: distinct bom-refs per version so components
    never collapse before the analyzer runs."""
    with open(os.path.join(DATA_DIR, "bom-multiversion-npm.json"), encoding="utf-8") as f:
        bom = json.load(f)
    postcss_versions = sorted(c["version"] for c in bom["components"] if c["name"] == "postcss")
    assert postcss_versions == ["8.4.31", "8.4.49", "8.5.4"]
    minimatch_versions = sorted(
        c["version"] for c in bom["components"] if c["name"] == "minimatch"
    )
    assert minimatch_versions == ["3.0.4", "3.1.2"]
    assert len({c["bom-ref"] for c in bom["components"]}) == 5


def test_merged_multiref_entries_render_in_console_output(dummy_cve, monkeypatch):
    """The merged multi-component entries produced after the fix must flow
    through generate_console_output (the #519 KeyError guard) unharmed. The
    table is rendered inside process() before remove_extra_metadata strips the
    transient fields, so capture it there via a wrapper."""
    from analysis_lib.output import generate_console_output as real_gco

    captured = {}

    def _capture(pkg_vulnerabilities, bom_dependency_tree, include, options):
        captured["vdrs"] = pkg_vulnerabilities
        captured["include"] = include
        captured["result"] = real_gco(pkg_vulnerabilities, bom_dependency_tree, include, options)
        return captured["result"]

    monkeypatch.setattr(vdr_module, "generate_console_output", _capture)
    options = VdrAnalysisKV(
        project_type="nodejs",
        init_results=[],
        pkg_aliases={},
        purl_aliases={},
        suggest_mode=False,
        scoped_pkgs={"required": [], "optional": []},
        no_vuln_table=False,
        pkg_list=[{"purl": "pkg:npm/demo@1.0.0"}],
        direct_purls={},
        reached_purls={},
        reached_services={},
        endpoint_reached_purls={},
    )
    monkeypatch.setattr(
        vdr_module,
        "find_vulns",
        lambda *_a, **_k: (
            [
                _raw_vdb_result("CVE-2026-41305", "pkg:npm/postcss@8.4.31", "8.4.50"),
                _raw_vdb_result("CVE-2026-41305", "pkg:npm/postcss@8.4.49", "8.4.50"),
            ],
            {},
            {},
        ),
    )
    result = VDRAnalyzer(options).process()

    assert result.success is True
    vdrs = captured["vdrs"]
    assert len(vdrs) == 1
    # The merged entry lists every affected component before metadata trimming
    assert {a["ref"] for a in vdrs[0]["affects"]} == {
        "pkg:npm/postcss@8.4.31",
        "pkg:npm/postcss@8.4.49",
    }
    # One console row per merged CVE entry, rendered without KeyError
    pkg_group_rows, table = captured["result"]
    assert table.row_count == 1
