import json
import os
from collections import defaultdict
from types import SimpleNamespace
from typing import Any

from analysis_lib import utils


def _make_vdr(
    cve_id,
    purl,
    *,
    fixed_location="",
    insights=None,
    properties=None,
    matching_vers="vers:apache/>=0.0.1|<9.0.0",
    ratings=None,
):
    """Build a minimal vdict matching the shape returned by analyze_cve_vuln."""
    versions = [{"range": matching_vers, "status": "affected"}]
    if fixed_location:
        versions.append({"version": fixed_location, "status": "unaffected"})
    return {
        "id": cve_id,
        "matched_by": purl,
        "bom-ref": f"{cve_id}/{purl}",
        "affects": [{"ref": purl, "versions": versions}],
        "recommendation": f"Update to version {fixed_location}." if fixed_location else "",
        "purl_prefix": purl.split("@")[0] if "@" in purl else purl,
        "source": {},
        "references": [],
        "advisories": [],
        "cwes": [],
        "description": "",
        "fixed_location": fixed_location,
        "detail": "",
        "ratings": ratings
        if ratings is not None
        else [{"method": "CVSSv31", "score": 7.5, "severity": "high"}],
        "published": "",
        "updated": "",
        "analysis": "",
        "insights": list(insights or []),
        "p_rich_tree": None,
        "properties": list(properties or []),
    }


def test_is_malware_vuln_uses_native_field_when_present():
    """When the vdb is_malware field is carried on the result, it is authoritative."""
    assert utils.is_malware_vuln({"cve_id": "CVE-2024-1", "is_malware": True}) is True
    assert utils.is_malware_vuln({"cve_id": "MAL-1234", "is_malware": False}) is False
    # is_malware=False wins even though the cve_id has the MAL- prefix
    assert utils.is_malware_vuln({"id": "MAL-9999", "is_malware": False}) is False


def test_is_malware_vuln_falls_back_to_mal_prefix_on_default_db():
    """On the default DB the is_malware key is absent, so the helper falls back
    to the MAL- prefix on whichever id field is present (cve_id or id)."""
    assert utils.is_malware_vuln({"cve_id": "MAL-2024-1"}) is True
    assert utils.is_malware_vuln({"id": "MAL-2024-1"}) is True
    assert utils.is_malware_vuln({"cve_id": "CVE-2024-1"}) is False
    assert utils.is_malware_vuln({"id": "CVE-2024-1"}) is False
    assert utils.is_malware_vuln({}) is False


def test_check_malware_cve_delegates_to_helper():
    """check_malware_cve must detect MAL- ids via the is_malware_vuln helper."""
    from analysis_lib.output import check_malware_cve

    assert check_malware_cve(["CVE-2024-1", "MAL-2024-1"]) is True
    assert check_malware_cve(["CVE-2024-1", "GHSA-aaaa"]) is False
    assert check_malware_cve([]) is False
    assert check_malware_cve(None) is False


def test_vuln_meets_severity_floor():
    """--severity keeps findings at or above the floor and drops lower ones."""
    crit = {"ratings": [{"severity": "CRITICAL"}]}
    med = {"ratings": [{"severity": "MEDIUM"}]}
    # No threshold -> everything passes
    assert utils.vuln_meets_severity(crit, None) is True
    assert utils.vuln_meets_severity(med, "") is True
    # At/above floor passes, below floor drops
    assert utils.vuln_meets_severity(crit, "high") is True
    assert utils.vuln_meets_severity(med, "high") is False
    assert utils.vuln_meets_severity(med, "medium") is True
    # Highest rating across the list wins
    mixed = {"ratings": [{"severity": "LOW"}, {"severity": "CRITICAL"}]}
    assert utils.vuln_meets_severity(mixed, "critical") is True


def test_vuln_meets_severity_keeps_unrated():
    """Unrated/unknown findings are kept rather than silently hidden."""
    assert utils.vuln_meets_severity({"ratings": []}, "high") is True
    assert utils.vuln_meets_severity({"ratings": [{"severity": "unknown"}]}, "high") is True
    assert utils.vuln_meets_severity({}, "critical") is True


def test_max_version():
    ret = utils.max_version("1.0.0")
    assert ret == "1.0.0"
    ret = utils.max_version(["1.0.0", "1.0.1", "2.0.0"])
    assert ret == "2.0.0"
    ret = utils.max_version(["1.1.0", "2.1.1", "2.0.0"])
    assert ret == "2.1.1"
    ret = utils.max_version(["2.9.10.1", "2.9.10.4", "2.9.10", "2.8.11.5", "2.8.11", "2.8.11.2"])
    assert ret == "2.9.10.4"
    ret = utils.max_version(["2.9.10", "2.9.10.4"])
    assert ret == "2.9.10.4"


def test_get_description_detail_preserves_markdown_structure():
    description, detail = utils.get_description_detail(
        "## Impact\\n\\n- keeps list items\\n- supports \\`inline code\\`\n\nParagraph two"
    )

    assert description == "Impact"
    assert detail == "## Impact\n\n- keeps list items\n- supports `inline code`\n\nParagraph two"


def test_parse_metrics_does_not_crash_on_missing_cvss_v3_fields():
    metrics = SimpleNamespace(
        root=[
            SimpleNamespace(
                cvssV4_0=None,
                cvssV3_1=SimpleNamespace(
                    vectorString="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    version=None,
                    baseSeverity=None,
                    baseScore=None,
                ),
                cvssV3_0=None,
            )
        ]
    )

    assert utils.parse_metrics(metrics) == (
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSSv3",
        "unknown",
        "",
    )


def test_parse_metrics_prefers_cvss_v31_over_cvss_v30_until_v4_is_found():
    metrics = SimpleNamespace(
        root=[
            SimpleNamespace(
                cvssV4_0=None,
                cvssV3_1=None,
                cvssV3_0=SimpleNamespace(
                    vectorString="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
                    version=SimpleNamespace(value="3.0"),
                    baseSeverity=SimpleNamespace(value="MEDIUM"),
                    baseScore=SimpleNamespace(root=6.5),
                ),
            ),
            SimpleNamespace(
                cvssV4_0=None,
                cvssV3_1=SimpleNamespace(
                    vectorString="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    version=SimpleNamespace(value="3.1"),
                    baseSeverity=SimpleNamespace(value="CRITICAL"),
                    baseScore=SimpleNamespace(root=9.8),
                ),
                cvssV3_0=None,
            ),
        ]
    )

    assert utils.parse_metrics(metrics) == (
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSSv31",
        "CRITICAL",
        9.8,
    )


def test_refs_to_vdr_skips_malformed_references_without_crashing():
    references: Any = SimpleNamespace(
        root=[
            SimpleNamespace(url=None),
            SimpleNamespace(
                url=SimpleNamespace(root="https://nvd.nist.gov/vuln/detail/CVE-2024-1234")
            ),
        ]
    )

    advisories, refs, *_rest, source = utils.refs_to_vdr(references, "cve-2024-1234")

    assert advisories == [
        {"title": "CVE-2024-1234", "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"}
    ]
    assert refs == [
        {
            "id": "CVE-2024-1234",
            "source": {"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234", "name": "NVD"},
        }
    ]
    assert source == {"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234", "name": "NVD"}


def test_analyze_cve_vuln_handles_missing_cve_metadata_and_affected(monkeypatch):
    class DummyCVE:
        root: Any

    monkeypatch.setattr(utils, "CVE", DummyCVE)

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

    counts = SimpleNamespace(
        malicious_count=0,
        pkg_attention_count=0,
        fix_version_count=0,
        critical_count=0,
        has_reachable_poc_count=0,
        has_reachable_exploit_count=0,
        has_poc_count=0,
        has_exploit_count=0,
        wont_fix_version_count=0,
        distro_packages_count=0,
        has_os_packages=False,
        ids_seen={},
    )

    updated_counts, vdict, add_to_pkg_group_rows, likely_false_positive = utils.analyze_cve_vuln(
        {
            "cve_id": "CVE-2024-1234",
            "matched_by": "",
            "matching_vers": "",
            "purl_prefix": "pkg:npm/demo",
            "source_data": cve_record,
        },
        reached_purls={},
        direct_purls={},
        reached_services={},
        endpoint_reached_purls={},
        optional_pkgs=[],
        required_pkgs=[],
        prebuild_purls={},
        build_purls={},
        postbuild_purls={},
        purl_identities={},
        bom_dependency_tree=[],
        counts=counts,
    )

    assert updated_counts is counts
    assert add_to_pkg_group_rows is False
    assert likely_false_positive is False
    assert vdict["published"] == ""
    assert vdict["updated"] == ""
    assert vdict["references"] == []
    assert vdict["advisories"] == []


# ---------------------------------------------------------------------------
# Issue #504 — dedupe_vdrs must merge VDR entries by vulnerability id so that
# multiple components affected by the same CVE collapse into one entry with
# multiple affects[].ref.
# ---------------------------------------------------------------------------


def test_dedupe_vdrs_merges_two_versions_of_same_cve():
    """Two versions of a package affected by the same CVE produce a single VDR
    entry whose affects references both component purls."""
    v1 = _make_vdr("CVE-2024-9999", "pkg:npm/postcss@8.4.31", fixed_location="8.4.50")
    v2 = _make_vdr("CVE-2024-9999", "pkg:npm/postcss@8.4.49", fixed_location="8.4.50")

    result = utils.dedupe_vdrs([v1, v2])

    assert len(result) == 1
    refs = {a["ref"] for a in result[0]["affects"]}
    assert refs == {"pkg:npm/postcss@8.4.31", "pkg:npm/postcss@8.4.49"}


def test_dedupe_vdrs_preserves_differing_fix_versions():
    """When two versions have different fix versions, each ref retains its own
    unaffected (fix) version in the merged affects."""
    v1 = _make_vdr("CVE-2024-8888", "pkg:npm/demo@1.0.0", fixed_location="2.0.0")
    v2 = _make_vdr("CVE-2024-8888", "pkg:npm/demo@1.5.0", fixed_location="3.0.0")

    result = utils.dedupe_vdrs([v1, v2])

    assert len(result) == 1
    fix_by_ref = {}
    for aff in result[0]["affects"]:
        for ver in aff["versions"]:
            if ver.get("status") == "unaffected":
                fix_by_ref[aff["ref"]] = ver.get("version")
    assert fix_by_ref == {
        "pkg:npm/demo@1.0.0": "2.0.0",
        "pkg:npm/demo@1.5.0": "3.0.0",
    }


def test_dedupe_vdrs_preserves_reachable_insight_and_bom_ref():
    """When only one of two merged versions is reachable, the reachable badge
    survives the merge and the prioritized entry's bom-ref is kept so console
    grouping attributes correctly."""
    v1 = _make_vdr(
        "CVE-2024-7777",
        "pkg:npm/scope/pkg@1.0.0",
        insights=["Has PoC"],
    )
    v2 = _make_vdr(
        "CVE-2024-7777",
        "pkg:npm/scope/pkg@2.0.0",
        insights=[":receipt: Reachable"],
        properties=[{"name": "depscan:prioritized", "value": "true"}],
    )

    result = utils.dedupe_vdrs([v1, v2])

    assert len(result) == 1
    merged = result[0]
    # The reachable badge from v2 must not be shadowed by v1's non-empty insights
    assert ":receipt: Reachable" in merged["insights"]
    assert "Has PoC" in merged["insights"]
    # bom-ref of the prioritized entry is preferred for console grouping
    assert merged["bom-ref"] == "CVE-2024-7777/pkg:npm/scope/pkg@2.0.0"


# ---------------------------------------------------------------------------
# Issue #519 — KeyError: 'matched_by' when a scanned BOM contains two
# components matched to the same CVE. combine_vdrs must propagate
# matched_by so the merged VDR remains consumable by generate_console_output.
# This happens whenever SBOMs are merged (e.g. via cyclonedx-cli merge) from
# multiple applications that share a vulnerable dependency — even at different
# versions, since matching can be CPE- or vers-range-based.
#
# Root cause: combine_vdrs built the merged dict from a hardcoded key set that
# omitted matched_by. The bom-ref of the preferred entry was still preserved,
# so the include_pkg_group_rows check passed, but output.py then crashed with
# KeyError on vdr["matched_by"].
#
# The fix has two layers:
#   1. combine_vdrs propagates matched_by (preferred → v1 → v2 fallback)
#   2. output.py uses vdr.get("matched_by", "") so a missing key degrades
#      gracefully instead of crashing the entire scan.
# ---------------------------------------------------------------------------


def test_combine_vdrs_preserves_matched_by():
    """combine_vdrs must propagate matched_by so the merged VDR retains the
    field that generate_console_output reads unconditionally."""
    v1 = _make_vdr("CVE-2024-5001", "pkg:maven/org.springframework/spring-web@5.3.22")
    v2 = _make_vdr("CVE-2024-5001", "pkg:maven/org.springframework/spring-web@5.0.5.RELEASE")

    merged = utils.combine_vdrs(v1, v2)

    assert "matched_by" in merged
    # preferred is v1 (neither is prioritized), so matched_by comes from v1
    assert merged["matched_by"] == "pkg:maven/org.springframework/spring-web@5.3.22"


def test_combine_vdrs_matched_by_prefers_prioritized_entry():
    """When the second entry is prioritized, matched_by should come from it to
    stay consistent with the bom-ref that include_pkg_group_rows tracks."""
    v1 = _make_vdr("CVE-2024-5002", "pkg:npm/demo@1.0.0")
    v2 = _make_vdr(
        "CVE-2024-5002",
        "pkg:npm/demo@2.0.0",
        properties=[{"name": "depscan:prioritized", "value": "true"}],
    )

    merged = utils.combine_vdrs(v1, v2)

    assert merged["matched_by"] == "pkg:npm/demo@2.0.0"


def test_dedupe_vdrs_preserves_matched_after_merge():
    """After dedupe_vdrs collapses two components sharing a CVE, the merged
    result must still carry matched_by — otherwise generate_console_output
    crashes with KeyError."""
    v1 = _make_vdr(
        "CVE-2024-5003",
        "pkg:maven/org.springframework/spring-web@5.3.22",
        fixed_location="5.3.30",
    )
    v2 = _make_vdr(
        "CVE-2024-5003",
        "pkg:maven/org.springframework/spring-web@5.0.5.RELEASE",
        fixed_location="5.0.20",
    )

    result = utils.dedupe_vdrs([v1, v2])

    assert len(result) == 1
    assert "matched_by" in result[0]
    assert result[0]["matched_by"] != ""


def test_generate_console_output_survives_missing_matched_by():
    """generate_console_output must not crash when a VDR entry lacks
    matched_by (the pre-fix regression). The defensive .get() should
    degrade gracefully with an empty string."""
    from analysis_lib.output import generate_console_output

    options = SimpleNamespace(project_type="java")
    # Simulate a merged VDR that lost matched_by (pre-fix combine_vdrs output)
    vdr_no_matched_by = {
        "id": "CVE-2024-5004",
        "bom-ref": "CVE-2024-5004/pkg:maven/demo@1.0.0",
        "affects": [{"ref": "pkg:maven/demo@1.0.0", "versions": []}],
        "matched_by": None,  # explicitly absent / None
        "fixed_location": "2.0.0",
        "p_rich_tree": None,
        "purl_prefix": "pkg:maven/demo",
        "insights": [],
        "ratings": [{"method": "CVSSv31", "score": 7.5, "severity": "high"}],
        "description": "",
        "cwes": [],
    }
    bom_ref = vdr_no_matched_by["bom-ref"]
    # If we remove matched_by entirely, it should still work (belt-and-suspenders)
    del vdr_no_matched_by["matched_by"]
    include = {bom_ref}

    # This call used to raise KeyError: 'matched_by'
    pkg_group_rows, table = generate_console_output(
        [vdr_no_matched_by],
        [],
        include,
        options,
    )

    assert bom_ref in pkg_group_rows
    assert pkg_group_rows[bom_ref][0]["matched_by"] == ""


def test_generate_console_output_with_deduped_duplicate_cves():
    """End-to-end regression: two components sharing a CVE are deduped, and
    generate_console_output should render without crashing even when one of
    them was added to include_pkg_group_rows before the merge."""
    from analysis_lib.output import generate_console_output

    options = SimpleNamespace(project_type="java")
    v1 = _make_vdr(
        "CVE-2024-5005",
        "pkg:maven/org.springframework/spring-web@5.3.22",
        fixed_location="5.3.30",
        insights=["[bright_red]:exclamation_mark: Exploitable[/bright_red]"],
        properties=[{"name": "depscan:prioritized", "value": "true"}],
    )
    v2 = _make_vdr(
        "CVE-2024-5005",
        "pkg:maven/org.springframework/spring-web@5.0.5.RELEASE",
        fixed_location="5.0.20",
    )
    # Both bom-refs are added to include_pkg_group_rows before dedup
    include = {v1["bom-ref"], v2["bom-ref"]}
    deduped = utils.dedupe_vdrs([v1, v2])

    assert len(deduped) == 1
    # The merged entry carries matched_by and the preferred bom-ref
    assert "matched_by" in deduped[0]

    # This used to raise KeyError: 'matched_by'
    pkg_group_rows, table = generate_console_output(
        deduped,
        [],
        include,
        options,
    )
    # The prioritized bom-ref should be in the group rows
    prioritized_ref = v1["bom-ref"]
    assert prioritized_ref in pkg_group_rows


# ---------------------------------------------------------------------------
# SBOM fixture validation — verifies that the test SBOMs with duplicate
# components are parsed correctly, simulating the merged-BOM scenario from
# the issue report.
# ---------------------------------------------------------------------------


def test_merged_duplicate_cve_bom_has_two_spring_web_versions():
    """The merged-BOM fixture must contain two distinct versions of
    spring-web so that a real scan would produce two VDR entries that
    dedupe_vdrs collapses into one (the trigger for issue #519)."""
    bom_path = os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        "data",
        "bom-merged-duplicate-cve.json",
    )
    with open(bom_path, encoding="utf-8") as f:
        bom = json.load(f)

    spring_versions = [c["version"] for c in bom["components"] if c.get("name") == "spring-web"]
    assert len(spring_versions) == 2
    assert "5.3.22" in spring_versions
    assert "5.0.5.RELEASE" in spring_versions
    # bom-refs must be distinct (different purls) so they don't collapse
    # before reaching dedupe_vdrs
    bom_refs = {c["bom-ref"] for c in bom["components"]}
    assert len(bom_refs) == 2


def test_syft_duplicate_components_bom_has_overlapping_cves():
    """The syft-style fixture must contain multiple versions of the same
    package so that CPE/vers matching produces overlapping CVEs — the exact
    condition that triggers the dedup path."""
    bom_path = os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        "data",
        "bom-syft-duplicate-components.json",
    )
    with open(bom_path, encoding="utf-8") as f:
        bom = json.load(f)

    names = defaultdict(list)
    for c in bom["components"]:
        names[c["name"]].append(c["version"])

    # log4j-core has 3 versions — all would match CVE-2021-44228
    assert len(names["log4j-core"]) == 3
    # jackson-databind has 2 versions
    assert len(names["jackson-databind"]) == 2
    # spring-web has 2 versions
    assert len(names["spring-web"]) == 2
    # All bom-refs must be distinct
    bom_refs = [c["bom-ref"] for c in bom["components"]]
    assert len(bom_refs) == len(set(bom_refs))
