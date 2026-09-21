"""Tests for generate_console_output's rendering of merged VDR entries.

Discussion #527 follow-up: after dedupe_vdrs merges every component affected
by the same CVE into a single VDR entry carrying multiple affects[].refs, the
console table (and depscan.txt, which is the saved console text) rendered one
row per entry using the transient purl_prefix/p_rich_tree/fixed_location of
just one component — the extra affects refs appeared nowhere outside the VDR
JSON. The table must expand affects[] into per-component rows and the caption
must count (id, affects) pairs.
"""

import json
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
    for postcss@8.5.4, 8.4.50 for the older pair). The package group shows a
    single fix — the best (highest) one — on its top row, so remediating the
    package is one upgrade decision."""
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
        [_affects_entry(p, fix_version="9.9.9") for p in (MINIMATCH_304, MINIMATCH_312)],
        matched_by=MINIMATCH_304,
        fixed_location="9.9.9",
    )
    _, table = generate_console_output([vdr, minimatch], _multiversion_tree(), set(), _options())
    rendered = _render(table)
    # Best fix per group, rendered once on the top row
    assert rendered.count("8.5.5") == 1
    assert "8.4.50" not in rendered
    assert rendered.count("9.9.9") == 1


def test_best_fix_version_shown_once_on_top_row_of_each_package_group():
    """Discussion #527 follow-up: the fix column shows one value per package
    group — the best (highest) fix across its CVEs and affected components —
    on the top row only. Here the postcss group's top rows belong to CVEs
    with no fix while CVE-2026-41305 carries 8.5.10 (which must still land on
    the top row), and minimatch mixes 3.1.4/3.1.3/3.1.3/3.0.5 with 3.1.4
    winning."""
    postcss_rows = []
    # CVE order within the group after descending sort: 73646, 69153, 45623, 41305
    for cve, fixes in (
        ("CVE-2026-73646", ("", "", "")),
        ("CVE-2026-69153", ("", "", "")),
        ("CVE-2026-45623", ("", "", "")),
        ("CVE-2026-41305", ("8.5.10", "8.5.10", "8.5.10")),
    ):
        postcss_rows.append(
            _merged_vdr(
                cve,
                [
                    _affects_entry(p, fix_version=f)
                    for p, f in zip((POSTCSS_8431, POSTCSS_8449, POSTCSS_8554), fixes)
                ],
                matched_by=POSTCSS_8431,
                fixed_location=fixes[0],
            )
        )
    minimatch_rows = []
    for cve, fixes in (
        ("CVE-2026-27904", ("3.1.4", "3.1.4")),
        ("CVE-2026-27903", ("3.1.3", "3.1.3")),
        ("CVE-2026-26996", ("3.1.3", "3.1.3")),
        ("CVE-2022-3517", ("3.0.5",)),  # only the older component is affected
    ):
        minimatch_rows.append(
            _merged_vdr(
                cve,
                [
                    _affects_entry(p, fix_version=f)
                    for p, f in zip((MINIMATCH_304, MINIMATCH_312)[: len(fixes)], fixes)
                ],
                matched_by=MINIMATCH_304,
                fixed_location=fixes[0],
            )
        )
    _, table = generate_console_output(
        postcss_rows + minimatch_rows, _multiversion_tree(), set(), _options()
    )
    rendered = _render(table)
    # Only the best fix of each group renders, exactly once, on its top row
    assert rendered.count("3.1.4") == 1
    assert rendered.count("8.5.10") == 1
    # The lower fixes of the group are not repeated per row
    assert "3.1.3" not in rendered
    assert "3.0.5" not in rendered


def test_reporter_bom_fixture_shows_best_fix_per_group_on_top():
    """End-to-end guard using the merged VDR fixture generated from the
    reporter's sample BOM (8 entries / 19 affects refs): each package group
    renders one fix version — its best — on the top row."""
    fixture = os.path.join(DATA_DIR, "vdr-merged-multiversion.json")
    with open(fixture, encoding="utf-8") as f:
        vdrs = json.load(f)
    assert len(vdrs) == 8
    assert sum(len(v["affects"]) for v in vdrs) == 19
    # Single-ref entries rely on the entry-level tree, which JSON cannot
    # carry; hydrate it exactly like analyze_cve_vuln does.
    from analysis_lib.output import pkg_sub_tree

    for vdr in vdrs:
        if len(vdr.get("affects") or []) <= 1 and vdr.get("matched_by"):
            ref = vdr["affects"][0]["ref"]
            rating = (vdr.get("ratings") or [{}])[0]
            _, vdr["p_rich_tree"] = pkg_sub_tree(
                ref,
                ref.replace(":", "/"),
                _multiversion_tree(),
                pkg_severity=rating.get("severity") or "unknown",
                as_tree=True,
                extra_text=f":left_arrow: {vdr['id']}",
            )
    _, table = generate_console_output(vdrs, _multiversion_tree(), set(), _options())
    assert table.row_count == 19
    assert table.caption == "Vulnerabilities count: 19 (8 unique)"
    rendered = _render(table)
    # minimatch's best fix is 3.1.4, postcss's is 8.5.10; each shows once
    assert rendered.count("3.1.4") == 1
    assert rendered.count("8.5.10") == 1
    assert "3.1.3" not in rendered
    assert "3.0.5" not in rendered
    # The postcss group's top row is CVE-2026-73646, which has no own fix —
    # the group's best fix still lands on that row.
    top_row_line = next(
        line for line in rendered.splitlines() if "CVE-2026-73646" in line
    )
    assert "8.5.10" in top_row_line
    # And no other postcss row repeats it
    assert rendered.count("8.5.10") == 1


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
