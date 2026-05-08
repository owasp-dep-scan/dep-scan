from types import SimpleNamespace

from analysis_lib import utils


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
    references = SimpleNamespace(
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
        pass

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
