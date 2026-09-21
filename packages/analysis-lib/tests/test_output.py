"""Tests for generate_console_output's rendering of merged VDR entries.

Discussion #527 follow-up: after dedupe_vdrs merges every component affected
by the same CVE into a single VDR entry carrying multiple affects[].refs, the
console table (and depscan.txt, which is the saved console text) rendered one
row per entry using the transient purl_prefix/p_rich_tree/fixed_location of
just one component — the extra affects refs appeared nowhere outside the VDR
JSON. The table must expand affects[] into per-component rows and the caption
must count (id, affects) pairs.
"""

import os

from rich.console import Console

from analysis_lib import VdrAnalysisKV
from analysis_lib.output import generate_console_output
from analysis_lib.utils import retrieve_bom_dependency_tree

DATA_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "data")

POSTCSS_8431 = "pkg:npm/postcss@8.4.31"
POSTCSS_8449 = "pkg:npm/postcss@8.4.49"
POSTCSS_8554 = "pkg:npm/postcss@8.5.4"
MINIMATCH_304 = "pkg:npm/minimatch@3.0.4"
MINIMATCH_312 = "pkg:npm/minimatch@3.1.2"


def _affects_entry(ref, affected_range="vers:apache/>=0.0.0", fix_version=""):
    versions = [{"range": affected_range, "status": "affected"}]
    if fix_version:
        versions.append({"version": fix_version, "status": "unaffected"})
    return {"ref": ref, "versions": versions}


def _merged_vdr(vid, affects, *, matched_by="", fixed_location="", severity="HIGH", score=7.5):
    """A VDR entry shaped like dedupe_vdrs + combine_vdrs output: several
    affects refs merged under one id, entry-level transient fields describing
    only the first merged component."""
    return {
        "id": vid,
        "matched_by": matched_by,
        "bom-ref": f"{vid}/{matched_by}",
        "affects": affects,
        "ratings": [{"severity": severity, "score": score, "method": "CVSSv31", "vector": ""}],
        "purl_prefix": matched_by.rsplit("@", 1)[0] if "@" in matched_by else "",
        "p_rich_tree": None,
        "insights": [],
        "fixed_location": fixed_location,
        "recommendation": "",
        "source": {},
        "references": [],
        "advisories": [],
        "cwes": [],
        "description": "",
        "detail": "",
        "published": "",
        "updated": "",
        "analysis": {},
        "properties": [],
    }


def _options(**overrides):
    return VdrAnalysisKV(
        project_type="nodejs",
        init_results=[],
        pkg_aliases={},
        purl_aliases={},
        suggest_mode=False,
        scoped_pkgs={"required": [], "optional": []},
        no_vuln_table=True,
        pkg_list=[{"purl": "pkg:npm/demo@1.0.0"}],
        direct_purls={},
        reached_purls={},
        reached_services={},
        endpoint_reached_purls={},
        **overrides,
    )


def _render(table):
    console = Console(record=True, width=250, force_terminal=False)
    console.print(table)
    return console.export_text()


def _multiversion_tree():
    bom_file = os.path.join(DATA_DIR, "bom-multiversion-npm.json")
    return retrieve_bom_dependency_tree(bom_file, None)


# ---------------------------------------------------------------------------
# Row expansion
# ---------------------------------------------------------------------------


def test_merged_vdr_expands_into_one_row_per_affected_component():
    """A single merged entry carrying three postcss versions must render three
    rows — one per affects ref — each with its own dependency tree."""
    vdr = _merged_vdr(
        "CVE-2026-41305",
        [
            _affects_entry(POSTCSS_8431, fix_version="8.5.0"),
            _affects_entry(POSTCSS_8449, fix_version="8.5.0"),
            _affects_entry(POSTCSS_8554, fix_version="8.5.5"),
        ],
        matched_by=POSTCSS_8431,
        fixed_location="8.5.0",
    )
    _, table = generate_console_output([vdr], _multiversion_tree(), set(), _options())
    assert table.row_count == 3
    rendered = _render(table)
    for version in ("8.4.31", "8.4.49", "8.5.4"):
        assert version in rendered, f"affected version {version} missing from the table"
    assert rendered.count("CVE-2026-41305") >= 3


def test_caption_counts_id_affects_pairs():
    """The caption counts (id, affects ref) pairs and calls out the unique
    vulnerability count whenever the merge collapsed components."""
    vdr_a = _merged_vdr(
        "CVE-2026-41305",
        [_affects_entry(p, fix_version="8.5.0") for p in (POSTCSS_8431, POSTCSS_8449, POSTCSS_8554)],
        matched_by=POSTCSS_8431,
    )
    vdr_b = _merged_vdr(
        "CVE-2026-52001",
        [_affects_entry(p, fix_version="3.1.2") for p in (MINIMATCH_304, MINIMATCH_312)],
        matched_by=MINIMATCH_304,
    )
    _, table = generate_console_output([vdr_a, vdr_b], _multiversion_tree(), set(), _options())
    assert table.caption == "Vulnerabilities count: 5 (2 unique)"
    assert table.row_count == 5
    rendered = _render(table)
    # postcss rows group together, then minimatch rows (sorted by purl prefix)
    assert rendered.index("8.4.31") < rendered.index("3.0.4")


def test_single_component_entries_keep_plain_caption_and_one_row():
    """Entries that were never merged (single affects ref) must render exactly
    one row each with the historical plain caption — no regression for the
    common scan."""
    vdrs = [
        _merged_vdr(
            "CVE-2026-41305",
            [_affects_entry(POSTCSS_8431, fix_version="8.5.0")],
            matched_by=POSTCSS_8431,
            fixed_location="8.5.0",
        ),
        _merged_vdr(
            "CVE-2026-52001",
            [_affects_entry(MINIMATCH_304, fix_version="3.1.2")],
            matched_by=MINIMATCH_304,
            fixed_location="3.1.2",
        ),
    ]
    _, table = generate_console_output(vdrs, _multiversion_tree(), set(), _options())
    assert table.caption == "Vulnerabilities count: 2"
    assert table.row_count == 2


def test_per_component_fix_version_is_used_for_each_row():
    """Components merged under one CVE can have different fix versions (8.5.5
    for postcss@8.5.4, 8.4.50 for the older pair). Each package group must
    show its own fix, not the fix of whichever component happened to win the
    entry-level fixed_location during the merge."""
    vdr = _merged_vdr(
        "CVE-2026-41305",
        [
            _affects_entry(POSTCSS_8431, fix_version="8.4.50"),
            _affects_entry(POSTCSS_8449, fix_version="8.4.50"),
            _affects_entry(POSTCSS_8554, fix_version="8.5.5"),
        ],
        matched_by=POSTCSS_8431,
        fixed_location="8.4.50",
    )
    minimatch = _merged_vdr(
        "CVE-2026-52001",
        [_affects_entry(p, fix_version="3.1.2") for p in (MINIMATCH_304, MINIMATCH_312)],
        matched_by=MINIMATCH_304,
        fixed_location="3.1.2",
    )
    _, table = generate_console_output([vdr, minimatch], _multiversion_tree(), set(), _options())
    rendered = _render(table)
    assert "8.4.50" in rendered
    assert "3.1.2" in rendered


def test_rows_sorted_by_cve_descending_within_package_group():
    """Multiple CVEs on the same package keep the historical descending CVE
    ordering inside the group, with every affected component still present."""
    postcss_cves = []
    for cve, fix in (("CVE-2026-41305", "8.5.0"), ("CVE-2026-41306", "9.0.0")):
        postcss_cves.append(
            _merged_vdr(
                cve,
                [_affects_entry(p, fix_version=fix) for p in (POSTCSS_8431, POSTCSS_8449)],
                matched_by=POSTCSS_8431,
                fixed_location=fix,
            )
        )
    _, table = generate_console_output(postcss_cves, _multiversion_tree(), set(), _options())
    assert table.row_count == 4
    assert table.caption == "Vulnerabilities count: 4 (2 unique)"
    rendered = _render(table)
    assert rendered.index("CVE-2026-41306") < rendered.index("CVE-2026-41305")


def test_vdr_without_affects_renders_entry_level_row():
    """Defensive: an entry with no affects at all (or refs that are all empty)
    must still render one row from the entry-level fields instead of
    vanishing from the table."""
    vdr = _merged_vdr("CVE-2026-41305", [], matched_by=POSTCSS_8431, fixed_location="8.5.0")
    _, table = generate_console_output([vdr], _multiversion_tree(), set(), _options())
    assert table.row_count == 1
    assert table.caption == "Vulnerabilities count: 1"

    vdr_empty_refs = _merged_vdr(
        "CVE-2026-41306",
        [{"ref": "", "versions": []}, {"ref": "", "versions": []}],
        matched_by=POSTCSS_8449,
        fixed_location="8.5.0",
    )
    _, table = generate_console_output([vdr_empty_refs], _multiversion_tree(), set(), _options())
    assert table.row_count == 1
    assert table.caption == "Vulnerabilities count: 1"
