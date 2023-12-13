import os.path

from depscan.lib.csaf import (
    CsafOccurence,
    add_vulnerabilities,
    cleanup_dict,
    cleanup_list,
    format_references,
    get_product_status,
    get_ref_summary,
    import_csaf_toml,
    import_root_component,
    parse_cvss,
    parse_cwe,
    parse_revision_history,
    parse_toml,
    verify_components_present,
    version_helper,
)


def test_parse_revision_history():
    # add revision entry w/existing entries when final
    tracking = {
        "current_release_date": "2023-10-03T00:21:34",
        "id": "ID",
        "initial_release_date": "2022-09-22T20:54:06",
        "status": "final",
        "version": "2",
        "revision_history": [
            {
                "date": "2023-10-02T23:50:07",
                "number": "2",
                "summary": "Update",
            },
            {
                "date": "2022-09-22T20:54:06",
                "number": "1",
                "summary": "Initial",
            },
        ],
    }
    assert parse_revision_history(tracking) == {
        "current_release_date": "2023-10-03T00:21:34",
        "id": "ID",
        "initial_release_date": "2022-09-22T20:54:06",
        "revision_history": [
            {
                "date": "2022-09-22T20:54:06",
                "number": "1",
                "summary": "Initial",
            },
            {
                "date": "2023-10-02T23:50:07",
                "number": "2",
                "summary": "Update",
            },
            {"date": "2023-10-03T00:21:34", "number": "3", "summary": "Update"},
        ],
        "status": "final",
        "version": "3",
    }

    # add revision entry w/no existing entries when final
    tracking = {
        "current_release_date": "2022-09-22T20:54:06.186927",
        "id": "ID",
        "initial_release_date": "2022-09-22T20:54:06.186927",
        "status": "final",
        "version": "",
        "revision_history": [],
    }
    assert parse_revision_history(tracking) == {
        "current_release_date": "2022-09-22T20:54:06",
        "id": "ID",
        "initial_release_date": "2022-09-22T20:54:06",
        "revision_history": [
            {"date": "2022-09-22T20:54:06", "number": "1", "summary": "Initial"}
        ],
        "status": "final",
        "version": "1",
    }

    # do not add when status is not final
    tracking = {
        "current_release_date": "2023-10-03T00:21:34",
        "id": "ID",
        "initial_release_date": "2022-09-22T20:54:06",
        "status": "draft",
        "version": "2",
        "revision_history": [
            {
                "date": "2022-09-22T20:54:06",
                "number": "1",
                "summary": "Initial",
            }
        ],
    }
    assert parse_revision_history(tracking) == {
        "current_release_date": "2023-10-03T00:21:34",
        "id": "ID",
        "initial_release_date": "2022-09-22T20:54:06",
        "status": "draft",
        "version": "2",
        "revision_history": [
            {
                "date": "2022-09-22T20:54:06",
                "number": "1",
                "summary": "Initial",
            }
        ],
    }

    # deal with a revision history inconsistent with the version number
    tracking = {
        "current_release_date": "2023-10-03T00:21:34",
        "id": "ID",
        "initial_release_date": "2022-09-22T20:54:06",
        "status": "final",
        "version": "5",
        "revision_history": [
            {
                "date": "2022-09-22T20:54:06",
                "number": "1",
                "summary": "Initial",
            }
        ],
    }
    assert parse_revision_history(tracking) == {
        "current_release_date": "2023-10-03T00:21:34",
        "id": "ID",
        "initial_release_date": "2022-09-22T20:54:06",
        "status": "final",
        "version": "2",
        "revision_history": [
            {
                "date": "2022-09-22T20:54:06",
                "number": "1",
                "summary": "Initial",
            },
            {
                "date": "2023-10-03T00:21:34",
                "number": "2",
                "summary": "Update",
            },
        ],
    }

    # deal with a missing revision history
    tracking = {
        "current_release_date": "2022-09-22T20:54:06.186927",
        "id": "ID",
        "initial_release_date": "2022-09-22T20:54:06.186927",
        "status": "final",
        "version": "",
    }
    assert parse_revision_history(tracking) == {
        "current_release_date": "2022-09-22T20:54:06",
        "id": "ID",
        "initial_release_date": "2022-09-22T20:54:06",
        "revision_history": [
            {"date": "2022-09-22T20:54:06", "number": "1", "summary": "Initial"}
        ],
        "status": "final",
        "version": "1",
    }

    # deal with a NoneType revision history
    tracking = {
        "current_release_date": "2022-09-22T20:54:06.186927",
        "id": "ID",
        "initial_release_date": "2022-09-22T20:54:06.186927",
        "status": "final",
        "version": "",
        "revision_history": None,
    }
    assert parse_revision_history(tracking) == {
        "current_release_date": "2022-09-22T20:54:06",
        "id": "ID",
        "initial_release_date": "2022-09-22T20:54:06",
        "revision_history": [
            {"date": "2022-09-22T20:54:06", "number": "1", "summary": "Initial"}
        ],
        "status": "final",
        "version": "1",
    }

    # update initial release date when adding initial release
    tracking = {
        "current_release_date": "2022-09-22T20:54:06.186927",
        "id": "ID",
        "initial_release_date": "2022-08-22T20:54:06.186927",
        "status": "final",
        "version": "1",
        "revision_history": [],
    }
    assert parse_revision_history(tracking) == {
        "current_release_date": "2022-09-22T20:54:06",
        "id": "ID",
        "initial_release_date": "2022-09-22T20:54:06",
        "revision_history": [
            {"date": "2022-09-22T20:54:06", "number": "1", "summary": "Initial"}
        ],
        "status": "final",
        "version": "1",
    }


def test_cleanup_list():
    assert cleanup_list([{}]) == []
    assert cleanup_list([{"a": "a", "b": "b", "c": ""}]) == [
        {"a": "a", "b": "b"}
    ]
    assert cleanup_list(["test", None]) == ["test"]


def test_cleanup_dict():
    assert cleanup_dict({"test": {"a": []}}) == {}
    assert cleanup_dict({"test": ""}) == {}
    assert cleanup_dict({"test": "", "test2": "test2"}) == {"test2": "test2"}
    assert cleanup_dict({"a": "a", "b": "b", "c": ""}) == {"a": "a", "b": "b"}
    assert cleanup_dict({"dict": ["test", None]}) == {"dict": ["test"]}


def test_get_ref_summary():
    url = "https://nvd.nist.gov/vuln/detail/cve-2021-1234"
    assert get_ref_summary(url) == "CVE Record"
    url = "https://github.com/user/repo/security/advisories/GHSA-1234-1234-1234"
    assert get_ref_summary(url) == "Advisory"
    url = "https://github.com/user/repo/pull/123"
    assert get_ref_summary(url) == "GitHub Pull Request"
    url = "https://github.com/user/repo/commit/123"
    assert get_ref_summary(url) == "GitHub Commit"
    url = ""
    assert get_ref_summary(url) == "Other"
    url = "https://example.com"
    assert get_ref_summary(url) == "Other"
    url = "https://github.com/user/repo/release"
    assert get_ref_summary(url) == "GitHub Repository Release"
    url = "https://github.com/user/repo"
    assert get_ref_summary(url) == "GitHub Repository"
    url = "https://access.redhat.com/security/cve/CVE-2023-26136"
    assert get_ref_summary(url) == "CVE Record"
    url = "https://access.redhat.com/errata/RHSA-2023:5484"
    assert get_ref_summary(url) == "Advisory"
    url = "https://bugzilla.redhat.com/show_bug.cgi?id=2224245"
    assert get_ref_summary(url) == "Bugzilla"


def test_format_references():
    ref = [
        "https://access.redhat.com/errata/RHSA-2023:5484",
        "https://bugzilla.redhat.com/show_bug.cgi?id=2224245",
        "https://nvd.nist.gov/vuln/detail/cve-2021-1234",
        "https://github.com/advisories/GHSA-1234-1234-1234",
        "https://github.com/user/repo/security/advisories/GHSA-5432-5432-5432",
        "https://github.com/user/repo/pull/123",
        "https://github.com/user/repo/commit/123",
        "https://example.com",
        "https://github.com/user/repo/release",
        "https://github.com/user/repo",
        "https://bugzilla.redhat.com/show_bug.cgi?id=cve-2021-1234",
        "https://github.com/FasterXML/jackson-databind/issues/2816",
        "https://sec.cloudapps.cisco.com/security/center/content"
        "/CiscoSecurityAdvisory/cisco-sa-apache-log4j-qRuKNEbd",
        "https://bitbucket.org/snakeyaml/snakeyaml/issues/525",
        "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=47027",
    ]
    [ids, refs] = format_references(ref)
    # For consistency in tests
    ids = sorted(ids, key=lambda x: x["text"])
    refs = sorted(refs, key=lambda x: x["url"])
    assert ids == [
        {"system_name": "Red Hat Bugzilla ID", "text": "2224245"},
        {
            "system_name": "GitHub Issue [FasterXML/jackson-databind]",
            "text": "2816",
        },
        {"system_name": "Chromium Issue [oss-fuzz]", "text": "47027"},
        {"system_name": "Bitbucket Issue [snakeyaml/snakeyaml]", "text": "525"},
        {"system_name": "GitHub Advisory", "text": "GHSA-1234-1234-1234"},
        {"system_name": "GitHub Advisory", "text": "GHSA-5432-5432-5432"},
        {"system_name": "Red Hat Advisory", "text": "RHSA-2023:5484"},
        {
            "system_name": "Cisco Advisory",
            "text": "cisco-sa-apache-log4j-qRuKNEbd",
        },
        {"system_name": "Red Hat Bugzilla ID", "text": "cve-2021-1234"},
    ]
    assert refs == [
        {
            "summary": "Red Hat Advisory",
            "url": "https://access.redhat.com/errata/RHSA-2023:5484",
        },
        {
            "summary": "Bitbucket Issue",
            "url": "https://bitbucket.org/snakeyaml/snakeyaml/issues/525",
        },
        {
            "summary": "Chromium Issue",
            "url": "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=47027",
        },
        {
            "summary": "Red Hat Bugzilla",
            "url": "https://bugzilla.redhat.com/show_bug.cgi?id=2224245",
        },
        {
            "summary": "Red Hat Bugzilla",
            "url": "https://bugzilla.redhat.com/show_bug.cgi?id=cve-2021-1234",
        },
        {"summary": "Other", "url": "https://example.com"},
        {
            "summary": "GitHub Issue",
            "url": "https://github.com/FasterXML/jackson-databind/issues/2816",
        },
        {
            "summary": "GitHub Advisory",
            "url": "https://github.com/advisories/GHSA-1234-1234-1234",
        },
        {"summary": "GitHub Repository", "url": "https://github.com/user/repo"},
        {
            "summary": "GitHub Commit",
            "url": "https://github.com/user/repo/commit/123",
        },
        {
            "summary": "GitHub Pull Request",
            "url": "https://github.com/user/repo/pull/123",
        },
        {
            "summary": "GitHub Repository Release",
            "url": "https://github.com/user/repo/release",
        },
        {
            "summary": "GitHub Advisory",
            "url": "https://github.com/user/repo/security/advisories/GHSA"
            "-5432-5432-5432",
        },
        {
            "summary": "CVE Record",
            "url": "https://nvd.nist.gov/vuln/detail/cve-2021-1234",
        },
        {
            "summary": "Cisco Advisory",
            "url": "https://sec.cloudapps.cisco.com/security/center/content"
            "/CiscoSecurityAdvisory/cisco-sa-apache-log4j-qRuKNEbd",
        },
    ]


def test_parse_cwe():
    assert parse_cwe("['CWE-20', 'CWE-668']") == (
        {"id": "CWE-20", "name": "Improper Input Validation"},
        [
            {
                "title": "Additional CWE: CWE-668",
                "audience": "developers",
                "category": "other",
                "text": "Exposure of Resource to Wrong Sphere",
            }
        ],
    )
    assert parse_cwe("CWE-1333") == (
        {
            "id": "CWE-1333",
            "name": "Inefficient Regular Expression Complexity",
        },
        [],
    )
    assert parse_cwe("") == (None, [])
    assert parse_cwe("CWE-000") == (None, [])


def test_parse_toml():
    # If running tests using an IDE such as PyCharm, pytest may execute from
    # the test directory rather than the project root.
    if os.path.exists(os.path.join(os.getcwd(), "contrib/csaf.toml")):
        filepath = os.path.join(os.getcwd(), "contrib/csaf.toml")
    else:
        filepath = "../contrib/csaf.toml"
    metadata = import_csaf_toml(filepath)
    # We don't want a dynamically generated ID
    metadata["tracking"]["id"] = "1234"
    parsed_toml = parse_toml(metadata)
    assert parsed_toml["document"]["category"] == "csaf_vex"
    assert parsed_toml["document"]["notes"] == [
        {"audience": "", "category": "", "text": "", "title": ""}
    ]
    assert parsed_toml["document"]["publisher"] == {
        "category": "vendor",
        "contact_details": "vendor@mcvendorson.com",
        "name": "Vendor McVendorson",
        "namespace": "https://appthreat.com",
    }


def test_parse_cvss():
    # Test parsing
    res = {
        "cvss_v3": {
            "attack_complexity": "LOW",
            "attack_vector": "NETWORK",
            "availability_impact": "HIGH",
            "base_score": 7.5,
            "impact_score": 7.5,
            "confidentiality_impact": "NONE",
            "integrity_impact": "NONE",
            "privileges_required": "NONE",
            "scope": "UNCHANGED",
            "user_interaction": "NONE",
            "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        },
        "severity": "HIGH",
        "id": "CVE-2023-37788",
    }
    assert parse_cvss(res) == {
        "baseScore": 7.5,
        "attackVector": "NETWORK",
        "privilegesRequired": "NONE",
        "userInteraction": "NONE",
        "scope": "UNCHANGED",
        "baseSeverity": "HIGH",
        "version": "3.1",
        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    }
    res["cvss_v3"]["vector_string"] = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I"
    assert parse_cvss(res) == {
        "baseScore": 7.5,
        "attackVector": "NETWORK",
        "privilegesRequired": "NONE",
        "userInteraction": "NONE",
        "scope": "UNCHANGED",
        "baseSeverity": "HIGH",
        "version": "3.0",
        "vectorString": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I",
    }
    # Test no cvss_v3
    res = {
        "severity": "HIGH",
        "id": "CVE-2023-37788",
    }
    assert parse_cvss(res) is None
    res["cvss_v3"] = {}
    assert parse_cvss(res) is None
    # Test missing or pre-3.0 vector string
    res = {
        "cvss_v3": {
            "attack_complexity": "LOW",
            "attack_vector": "NETWORK",
            "availability_impact": "HIGH",
            "base_score": 7.5,
            "impact_score": 7.5,
            "confidentiality_impact": "NONE",
            "integrity_impact": "NONE",
            "privileges_required": "NONE",
            "scope": "UNCHANGED",
            "user_interaction": "NONE",
        },
        "severity": "HIGH",
        "id": "CVE-2023-37788",
    }
    assert parse_cvss(res) is None
    res["cvss_v3"]["vector_string"] = "CVSS:2.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I"
    assert parse_cvss(res) is None
    res["cvss_v3"]["vector_string"] = ""
    assert parse_cvss(res) is None
    res["cvss_v3"]["vector_string"] = None
    assert parse_cvss(res) is None
    # Test missing base score
    res = {
        "cvss_v3": {
            "attack_complexity": "LOW",
            "attack_vector": "NETWORK",
            "availability_impact": "HIGH",
            "impact_score": 7.5,
            "confidentiality_impact": "NONE",
            "integrity_impact": "NONE",
            "privileges_required": "NONE",
            "scope": "UNCHANGED",
            "user_interaction": "NONE",
            "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        },
        "severity": "HIGH",
        "id": "CVE-2023-37788",
    }
    assert parse_cvss(res) is None
    res["cvss_v3"]["base_score"] = ""
    assert parse_cvss(res) is None
    res["cvss_v3"]["base_score"] = None
    assert parse_cvss(res) is None


def test_get_product_status():
    assert get_product_status(
        {
            "affected_location": {
                "cpe_uri": "cpe:2.3:a:npm:taffydb:*:*:*:*:*:*:*:*",
                "package": "taffydb",
                "version": "<=2.7.3",
            },
            "fixed_location": None,
        },
        "1089386|taffydb|2.6.2",
    ) == (
        "taffydb",
        {"known_affected": ["taffydb:<=2.7.3"]},
        "<=2.7.3",
        "taffydb",
    )

    assert get_product_status(
        {
            "affected_location": {
                "cpe_uri": "cpe:2.3:a:npm:taffydb:*:*:*:*:*:*:*:*",
                "package": "taffydb",
                "version": "<=2.7.3",
            },
            "fixed_location": None,
        },
        "1089386_32636283|taffygroup|taffydb|2.6.2",
    ) == (
        "taffydb",
        {"known_affected": ["taffydb:<=2.7.3"]},
        "<=2.7.3",
        "taffygroup/taffydb",
    )


def test_csaf_occurence():
    res = [
        {
            "id": "CVE-2019-10790",
            "problem_type": "['CWE-20', 'CWE-668']",
            "type": "npm",
            "severity": "HIGH",
            "cvss_score": "7.5",
            "cvss_v3": {
                "base_score": 7.5,
                "exploitability_score": 7.5,
                "impact_score": 7.5,
                "attack_vector": "NETWORK",
                "attack_complexity": "LOW",
                "privileges_required": "NONE",
                "user_interaction": "REQUIRED",
                "scope": "UNCHANGED",
                "confidentiality_impact": "HIGH",
                "integrity_impact": "HIGH",
                "availability_impact": "HIGH",
                "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
            },
            "package_issue": {
                "affected_location": {
                    "cpe_uri": "cpe:2.3:a:npm:taffydb:*:*:*:*:*:*:*:*",
                    "package": "taffydb",
                    "version": "<=2.7.3",
                },
                "fixed_location": None,
            },
            "short_description": "# TaffyDB can allow access to any data items "
            "in the DB\nTaffyDB allows attackers to forge "
            "adding additional properties into user input "
            "processed by taffy which can allow access to "
            "any data items in the DB. Taffy sets an "
            "internal index for each data item in its DB. "
            "However, it is found that the internal index "
            "can be forged by adding additional properties "
            "into user input. If index is found in the "
            "query, TaffyDB will ignore other query "
            "conditions and directly return the indexed "
            "data item. Moreover, the internal index is in "
            "an easily guessable format (e.g., "
            "T000002R000001). As such, attackers can use "
            "this vulnerability to access any data items in "
            "the DB. **Note:** `taffy` and its successor "
            "package `taffydb` are not maintained.\nNone",
            "long_description": None,
            "related_urls": [],
            "effective_severity": "HIGH",
            "source_update_time": "2023-01-30T19:22:18",
            "source_orig_time": "2020-02-19T16:43:42",
            "matched_by": "1089386|taffydb|2.6.2",
        },
        {
            "id": "CVE-2023-36665",
            "problem_type": "CWE-1321",
            "type": "npm",
            "severity": "CRITICAL",
            "cvss_score": "9.8",
            "cvss_v3": {
                "base_score": 9.8,
                "exploitability_score": 9.8,
                "impact_score": 9.8,
                "attack_vector": "NETWORK",
                "attack_complexity": "LOW",
                "privileges_required": "NONE",
                "user_interaction": "REQUIRED",
                "scope": "UNCHANGED",
                "confidentiality_impact": "CRITICAL",
                "integrity_impact": "CRITICAL",
                "availability_impact": "CRITICAL",
                "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            },
            "package_issue": {
                "affected_location": {
                    "cpe_uri": "cpe:2.3:a:npm:protobufjs:*:*:*:*:*:*:*:*",
                    "package": "protobufjs",
                    "version": ">=7.0.0-<7.2.4",
                },
                "fixed_location": "7.2.4",
            },
            "short_description": "# protobufjs Prototype Pollution "
            "vulnerability\nprotobuf.js ("
            "aka protobufjs) 6.10.0 until 6.11.4 and 7.0.0 until 7.2.4 "
            "allows Prototype Pollution, a different vulnerability than "
            "CVE-2022-25878. A user-controlled protobuf message can be used "
            "by an attacker to pollute the prototype of Object.prototype by "
            "adding and overwriting its data and functions. Exploitation can "
            "involve: (1) using the function parse to parse protobuf "
            "messages on the fly, (2) loading .proto files by using "
            "load/loadSync functions, or (3) providing untrusted input to "
            "the functions ReflectionObject.setParsedOption and "
            "util.setProperty. NOTE: this CVE Record is about "
            "`Object.constructor.prototype.<new-property> = ...;` whereas "
            "CVE-2022-25878 was about `Object.__proto__.<new-property> = "
            "...;` instead.",
            "long_description": None,
            "related_urls": [
                "https://github.com/markdown-it/markdown-it/security"
                "/advisories/GHSA-6vfc-qv3f-vr6c",
                "https://nvd.nist.gov/vuln/detail/CVE-2022-21670",
                "https://github.com/markdown-it/markdown-it/commit"
                "/ffc49ab46b5b751cd2be0aabb146f2ef84986101",
                "https://github.com/markdown-it/markdown-it",
            ],
            "effective_severity": "CRITICAL",
            "source_update_time": "2023-08-15T21:16:36",
            "source_orig_time": "2023-07-05T15:30:24",
            "matched_by": "2499923747_2499958328|npm|protobufjs|7.1.2",
        },
    ]
    occs = []
    for r in res:
        vuln = CsafOccurence(r)
        occs.append(vuln)
    result = [o.to_dict() for o in occs]
    assert result == [
        {
            "cve": "CVE-2019-10790",
            "cwe": {"id": "CWE-20", "name": "Improper Input Validation"},
            "discovery_date": "2020-02-19T16:43:42",
            "ids": [],
            "notes": [
                {
                    "audience": "developers",
                    "category": "other",
                    "text": "Exposure of Resource to Wrong Sphere",
                    "title": "Additional CWE: CWE-668",
                },
                {
                    "category": "general",
                    "details": "Vulnerability Description",
                    "text": "# TaffyDB can allow access to any data items in the DB "
                    "TaffyDB allows attackers to forge adding additional "
                    "properties into user input processed by taffy which can "
                    "allow access to any data items in the DB. Taffy sets an "
                    "internal index for each data item in its DB. However, it "
                    "is found that the internal index can be forged by adding "
                    "additional properties into user input. If index is found "
                    "in the query, TaffyDB will ignore other query conditions "
                    "and directly return the indexed data item. Moreover, the "
                    "internal index is in an easily guessable format (e.g., "
                    "T000002R000001). As such, attackers can use this "
                    "vulnerability to access any data items in the DB. "
                    "**Note:** `taffy` and its successor package `taffydb` "
                    "are not maintained. None",
                },
            ],
            "product_status": {"known_affected": ["taffydb:<=2.7.3"]},
            "references": [],
            "scores": [
                {
                    "cvss_v3": {
                        "attackVector": "NETWORK",
                        "baseScore": 7.5,
                        "baseSeverity": "HIGH",
                        "privilegesRequired": "NONE",
                        "scope": "UNCHANGED",
                        "userInteraction": "REQUIRED",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L"
                        "/I:L/A:L",
                        "version": "3.1",
                    },
                    "products": ["taffydb"],
                }
            ],
        },
        {
            "cve": "CVE-2023-36665",
            "cwe": {
                "id": "CWE-1321",
                "name": "Improperly Controlled Modification of Object Prototype "
                "Attributes",
            },
            "discovery_date": "2023-07-05T15:30:24",
            "ids": [
                {
                    "system_name": "GitHub Advisory",
                    "text": "GHSA-6vfc-qv3f-vr6c",
                }
            ],
            "notes": [
                {
                    "category": "general",
                    "details": "Vulnerability Description",
                    "text": "# protobufjs Prototype Pollution vulnerability "
                    "protobuf.js (aka protobufjs) 6.10.0 until 6.11.4 and "
                    "7.0.0 until 7.2.4 allows Prototype Pollution, a "
                    "different vulnerability than CVE-2022-25878. A "
                    "user-controlled protobuf message can be used by an "
                    "attacker to pollute the prototype of Object.prototype by "
                    "adding and overwriting its data and functions. "
                    "Exploitation can involve: (1) using the function parse "
                    "to parse protobuf messages on the fly, (2) loading "
                    ".proto files by using load/loadSync functions, or (3) "
                    "providing untrusted input to the functions "
                    "ReflectionObject.setParsedOption and util.setProperty. "
                    "NOTE: this CVE Record is about "
                    "`Object.constructor.prototype.<new-property> = ...;` "
                    "whereas CVE-2022-25878 was about "
                    "`Object.__proto__.<new-property> = ...;` instead.",
                }
            ],
            "product_status": {
                "fixed": ["protobufjs:7.2.4"],
                "known_affected": ["protobufjs:>=7.0.0-<7.2.4"],
            },
            "references": [
                {
                    "summary": "CVE Record",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-21670",
                },
                {
                    "summary": "GitHub Commit",
                    "url": "https://github.com/markdown-it/markdown-it/commit"
                    "/ffc49ab46b5b751cd2be0aabb146f2ef84986101",
                },
                {
                    "summary": "GitHub Repository",
                    "url": "https://github.com/markdown-it/markdown-it",
                },
                {
                    "summary": "GitHub Advisory",
                    "url": "https://github.com/markdown-it/markdown-it"
                    "/security/advisories/GHSA-6vfc-qv3f-vr6c",
                },
            ],
            "scores": [
                {
                    "cvss_v3": {
                        "attackVector": "NETWORK",
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                        "privilegesRequired": "NONE",
                        "scope": "UNCHANGED",
                        "userInteraction": "REQUIRED",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H"
                        "/I:H/A:H",
                        "version": "3.1",
                    },
                    "products": ["protobufjs"],
                }
            ],
        },
    ]


def test_import_root_component():
    if os.path.exists("test/data/bom-root-comp.json"):
        [prod, ref] = import_root_component("test/data/bom-root-comp.json")
    else:
        [prod, ref] = import_root_component("data/bom-root-comp.json")

    assert prod == {
        "full_product_names": [
            {
                "name": "vuln-spring",
                "product_id": "vuln-spring:0.0.1-SNAPSHOT",
                "product_identification_helper": {
                    "purl": "pkg:maven/com.example/vuln-spring@0.0.1-SNAPSHOT"
                    "?type=jar"
                },
            }
        ]
    }

    assert ref == [
        {
            "summary": "website",
            "url": "https://projects.spring.io/spring-boot/#/spring"
            "-boot-starter-parent/vuln-spring",
        },
        {
            "summary": "vcs",
            "url": "https://github.com/spring-projects/spring-boot"
            "/spring-boot-starter-parent/vuln-spring",
        },
    ]


def test_verify_components_present():
    data = {
        "document": {
            "aggregate_severity": {"text": "Critical"},
            "category": "csaf_vex",
            "title": "Your Title",
            "csaf_version": "2.0",
            "lang": "en",
            "publisher": {
                "category": "vendor",
                "contact_details": "vendor@mcvendorson.com",
                "name": "Vendor McVendorson",
                "namespace": "https://appthreat.com",
            },
            "references": [
                {
                    "category": "self",
                    "summary": "dcksdnskljskl",
                    "url": "sdhasdjhslk.com",
                }
            ],
            "tracking": {
                "status": "draft",
                "initial_release_date": "2023-11-12T06:51:08",
                "current_release_date": "2023-11-12T06:51:08",
                "version": "1",
                "id": "2023-11-22T10:35:03_v1",
            },
        },
        "vulnerabilities": [
            {
                "id": "CVE-2020-36180",
                "problem_type": "CWE-502",
                "type": "fasterxml",
                "severity": "HIGH",
                "cvss_score": "8.1",
                "cvss_v3": {
                    "base_score": 8.1,
                    "exploitability_score": 2.2,
                    "impact_score": 5.9,
                    "attack_vector": "NETWORK",
                    "attack_complexity": "HIGH",
                    "privileges_required": "NONE",
                    "user_interaction": "NONE",
                    "scope": "UNCHANGED",
                    "confidentiality_impact": "HIGH",
                    "integrity_impact": "HIGH",
                    "availability_impact": "HIGH",
                    "vector_string": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                },
                "package_issue": {
                    "affected_location": {
                        "cpe_uri": "cpe:2.3:a:fasterxml:jackson-databind:*:*:*:*:*:*:*:*",
                        "package": "jackson-databind",
                        "version": ">=2.7.0-<2.9.10.8",
                    },
                    "fixed_location": "2.9.10.8",
                },
                "short_description": "FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the interaction between serialization gadgets and typing, related to org.apache.commons.dbcp2.cpdsadapter.DriverAdapterCPDS.",
                "long_description": None,
                "related_urls": [
                    "https://github.com/FasterXML/jackson-databind/issues/3004",
                    "https://cowtowncoder.medium.com/on-jackson-cves-dont-panic-here-is-what-you-need-to-know-54cd0d6e8062",
                ],
                "effective_severity": "HIGH",
                "source_update_time": "2023-09-13T14:56:00",
                "source_orig_time": "2021-01-07T00:15:00",
                "matched_by": "3647951461_3647986090|fasterxml|jackson-databind|2.9.6",
            },
            {
                "id": "CVE-2019-12086",
                "problem_type": "CWE-502",
                "type": "fasterxml",
                "severity": "HIGH",
                "cvss_score": "7.5",
                "cvss_v3": {
                    "base_score": 7.5,
                    "exploitability_score": 3.9,
                    "impact_score": 3.6,
                    "attack_vector": "NETWORK",
                    "attack_complexity": "LOW",
                    "privileges_required": "NONE",
                    "user_interaction": "NONE",
                    "scope": "UNCHANGED",
                    "confidentiality_impact": "HIGH",
                    "integrity_impact": "NONE",
                    "availability_impact": "NONE",
                    "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                },
                "package_issue": {
                    "affected_location": {
                        "cpe_uri": "cpe:2.3:a:fasterxml:jackson-databind:*:*:*:*:*:*:*:*",
                        "package": "jackson-databind",
                        "version": ">=2.9.0-<2.9.9",
                    },
                    "fixed_location": "2.9.9",
                },
                "short_description": "A Polymorphic Typing issue was discovered in FasterXML jackson-databind 2.x before 2.9.9. When Default Typing is enabled (either globally or for a specific property) for an externally exposed JSON endpoint, the service has the mysql-connector-java jar (8.0.14 or earlier) in the classpath, and an attacker can host a crafted MySQL server reachable by the victim, an attacker can send a crafted JSON message that allows them to read arbitrary local files on the server. This occurs because of missing com.mysql.cj.jdbc.admin.MiniAdmin validation.",
                "long_description": None,
                "related_urls": [
                    "https://www.oracle.com/security-alerts/cpujul2020.html",
                    "https://lists.apache.org/thread.html/rda99599896c3667f2cc9e9d34c7b6ef5d2bbed1f4801e1d75a2b0679@%3Ccommits.nifi.apache.org%3E",
                    "https://www.oracle.com/security-alerts/cpuoct2020.html",
                    "https://www.oracle.com/security-alerts/cpuApr2021.html",
                    "https://www.oracle.com/security-alerts/cpuapr2022.html",
                ],
                "effective_severity": "HIGH",
                "source_update_time": "2023-09-13T14:16:00",
                "source_orig_time": "2019-05-17T17:29:00",
                "matched_by": "3747044328_3747096861|fasterxml|jackson-databind|2.9.6",
            },
            {
                "id": "CVE-2018-11784",
                "problem_type": "CWE-601",
                "type": "org.apache.tomcat.embed",
                "severity": "MEDIUM",
                "cvss_score": "4.3",
                "cvss_v3": {
                    "base_score": 4.3,
                    "exploitability_score": 4.3,
                    "impact_score": 4.3,
                    "attack_vector": "NETWORK",
                    "attack_complexity": "LOW",
                    "privileges_required": "NONE",
                    "user_interaction": "REQUIRED",
                    "scope": "UNCHANGED",
                    "confidentiality_impact": "MEDIUM",
                    "integrity_impact": "MEDIUM",
                    "availability_impact": "MEDIUM",
                    "vector_string": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                },
                "package_issue": {
                    "affected_location": {
                        "cpe_uri": "cpe:2.3:a:org.apache.tomcat.embed:tomcat-embed-core:*:*:*:*:*:*:*:*",
                        "package": "tomcat-embed-core",
                        "version": ">=8.5.0-<8.5.34",
                    },
                    "fixed_location": "8.5.34",
                },
                "short_description": "# Moderate severity vulnerability that affects org.apache.tomcat.embed:tomcat-embed-core\nWhen the default servlet in Apache Tomcat versions 9.0.0.M1 to 9.0.11, 8.5.0 to 8.5.33 and 7.0.23 to 7.0.90 returned a redirect to a directory (e.g. redirecting to '/foo/' when the user requested '/foo') a specially crafted URL could be used to cause the redirect to be generated to any URI of the attackers choice.",
                "long_description": None,
                "related_urls": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2018-11784",
                    "https://access.redhat.com/errata/RHSA-2019:0130",
                    "https://access.redhat.com/errata/RHSA-2019:0131",
                    "https://access.redhat.com/errata/RHSA-2019:0485",
                    "https://access.redhat.com/errata/RHSA-2019:1529",
                    "https://github.com/advisories/GHSA-5q99-f34m-67gc",
                    "https://seclists.org/bugtraq/2019/Dec/43",
                    "https://security.netapp.com/advisory/ntap-20181014-0002/",
                ],
                "effective_severity": "MEDIUM",
                "source_update_time": "2023-04-11T01:35:23",
                "source_orig_time": "2018-10-17T16:31:02",
                "matched_by": "2650801486_2650849443|org.apache.tomcat.embed|tomcat-embed-core|8.5.31",
            },
            {
                "id": "CVE-2022-22971",
                "problem_type": "CWE-770",
                "type": "org.springframework",
                "severity": "MEDIUM",
                "cvss_score": "6.5",
                "cvss_v3": {
                    "base_score": 6.5,
                    "exploitability_score": 6.5,
                    "impact_score": 6.5,
                    "attack_vector": "NETWORK",
                    "attack_complexity": "LOW",
                    "privileges_required": "NONE",
                    "user_interaction": "REQUIRED",
                    "scope": "UNCHANGED",
                    "confidentiality_impact": "MEDIUM",
                    "integrity_impact": "MEDIUM",
                    "availability_impact": "MEDIUM",
                    "vector_string": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
                },
                "package_issue": {
                    "affected_location": {
                        "cpe_uri": "cpe:2.3:a:org.springframework:spring-core:*:*:*:*:*:*:*:*",
                        "package": "spring-core",
                        "version": ">=0-<5.2.22.RELEASE",
                    },
                    "fixed_location": "5.2.22.RELEASE",
                },
                "short_description": "# Allocation of Resources Without Limits or Throttling in Spring Framework\nIn spring framework versions prior to 5.3.20+ , 5.2.22+ and old unsupported versions, application with a STOMP over WebSocket endpoint is vulnerable to a denial of service attack by an authenticated user.",
                "long_description": None,
                "related_urls": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22971",
                    "https://security.netapp.com/advisory/ntap-20220616-0003/",
                    "https://tanzu.vmware.com/security/cve-2022-22971",
                    "https://www.oracle.com/security-alerts/cpujul2022.html",
                ],
                "effective_severity": "MEDIUM",
                "source_update_time": "2023-04-11T01:33:53",
                "source_orig_time": "2022-05-13T00:00:29",
                "matched_by": "2660437234_2660469022|org.springframework|spring-core|5.0.7.RELEASE",
            },
            {
                "id": "CVE-2022-40150",
                "problem_type": "CWE-400,CWE-674",
                "type": "org.codehaus.jettison",
                "severity": "HIGH",
                "cvss_score": "7.5",
                "cvss_v3": {
                    "base_score": 7.5,
                    "exploitability_score": 7.5,
                    "impact_score": 7.5,
                    "attack_vector": "NETWORK",
                    "attack_complexity": "LOW",
                    "privileges_required": "NONE",
                    "user_interaction": "REQUIRED",
                    "scope": "UNCHANGED",
                    "confidentiality_impact": "HIGH",
                    "integrity_impact": "HIGH",
                    "availability_impact": "HIGH",
                    "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                },
                "package_issue": {
                    "affected_location": {
                        "cpe_uri": "cpe:2.3:a:org.codehaus.jettison:jettison:*:*:*:*:*:*:*:*",
                        "package": "jettison",
                        "version": ">=0-<1.5.2",
                    },
                    "fixed_location": "1.5.2",
                },
                "short_description": "# Jettison memory exhaustion\nThose using Jettison to parse untrusted XML or JSON data may be vulnerable to Denial of Service attacks (DOS). If the parser is running on user supplied input, an attacker may supply content that causes the parser to crash by Out of memory. This effect may support a denial of service attack.",
                "long_description": None,
                "related_urls": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-40150",
                    "https://github.com/jettison-json/jettison/issues/45",
                    "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=46549",
                    "https://github.com/jettison-json/jettison",
                    "https://lists.debian.org/debian-lts-announce/2022/12/msg00045.html",
                    "https://www.debian.org/security/2023/dsa-5312",
                ],
                "effective_severity": "HIGH",
                "source_update_time": "2023-07-13T19:19:12",
                "source_orig_time": "2022-09-17T00:00:41",
                "matched_by": "2662034264_2662079740|org.codehaus.jettison|jettison|1.3.7",
            },
        ],
    }
    metadata = {
        "depscan_version": "4.3.3",
        "note": [
            {"audience": "", "category": "", "text": "", "title": ""},
            {"audience": "", "category": "", "text": "", "title": ""},
        ],
        "reference": [
            {
                "category": "self",
                "summary": "dcksdnskljskl",
                "url": "sdhasdjhslk.com",
            },
            {"category": "", "summary": "", "url": ""},
        ],
        "distribution": {"label": "", "text": "", "url": ""},
        "document": {"category": "csaf_vex", "title": "Your Title"},
        "product_tree": {"easy_import": ""},
        "publisher": {
            "category": "vendor",
            "contact_details": "vendor@mcvendorson.com",
            "name": "Vendor McVendorson",
            "namespace": "https://appthreat.com",
        },
        "tracking": {
            "status": "draft",
            "initial_release_date": "2023-11-12T06:51:08",
            "current_release_date": "2023-11-12T06:51:08",
            "version": "1",
            "id": "",
        },
    }
    if os.path.exists("test/data/bom-root-comp.json"):
        vdr_file = "test/data/bom-root-comp.json"
    else:
        vdr_file = "data/bom-root-comp.json"

    [template, new_metadata] = verify_components_present(
        data, metadata, vdr_file
    )
    assert template["document"]["notes"] == [
        {
            "category": "legal_disclaimer",
            "text": "Depscan reachable code only covers the "
            "project source code, not the code of "
            "dependencies. A dependency may execute "
            "vulnerable code when called even if it is "
            "not in the project's source code. Regard the "
            "Depscan-set flag of "
            "'code_not_in_execute_path' with this in "
            "mind.",
        }
    ]
    assert template["product_tree"] == {
        "full_product_names": [
            {
                "name": "vuln-spring",
                "product_id": "vuln-spring:0.0.1-SNAPSHOT",
                "product_identification_helper": {
                    "purl": "pkg:maven/com.example/vuln-spring@0.0.1-SNAPSHOT?type=jar"
                },
            }
        ]
    }

    assert new_metadata["tracking"] == {
        "current_release_date": "2023-11-12T06:51:08",
        "id": "",
        "initial_release_date": "2023-11-12T06:51:08",
        "status": "draft",
        "version": "1",
    }


def test_add_vulnerabilities():
    data = {
        "document": {
            "aggregate_severity": {},
            "category": "csaf_vex",
            "title": "Your Title",
            "csaf_version": "2.0",
            "distribution": {"label": "", "text": "", "url": ""},
            "lang": "en",
            "notes": [
                {"audience": "", "category": "", "text": "", "title": ""},
                {"audience": "", "category": "", "text": "", "title": ""},
            ],
            "publisher": {
                "category": "vendor",
                "contact_details": "vendor@mcvendorson.com",
                "name": "Vendor McVendorson",
                "namespace": "https://appthreat.com",
            },
            "references": [
                {
                    "category": "self",
                    "summary": "dcksdnskljskl",
                    "url": "sdhasdjhslk.com",
                },
                {"category": "", "summary": "", "url": ""},
            ],
            "tracking": {
                "status": "draft",
                "initial_release_date": "2023-11-12T06:51:08",
                "current_release_date": "2023-11-12T06:51:08",
                "version": "1",
                "id": "2023-11-21T21:39:14_v1",
                "revision_history": [],
            },
        },
        "product_tree": None,
        "vulnerabilities": [],
    }
    reached_purls = {
        "pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.31"
        "?type=jar": 3,
        "pkg:maven/org.codehaus.jettison/jettison@1.3.7?type=jar": 19,
    }
    direct_purls = {}
    results = [
        {
            "id": "CVE-2020-36180",
            "problem_type": "CWE-502",
            "type": "fasterxml",
            "severity": "HIGH",
            "cvss_score": "8.1",
            "cvss_v3": {
                "base_score": 8.1,
                "exploitability_score": 2.2,
                "impact_score": 5.9,
                "attack_vector": "NETWORK",
                "attack_complexity": "HIGH",
                "privileges_required": "NONE",
                "user_interaction": "NONE",
                "scope": "UNCHANGED",
                "confidentiality_impact": "HIGH",
                "integrity_impact": "HIGH",
                "availability_impact": "HIGH",
                "vector_string": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
            },
            "package_issue": {
                "affected_location": {
                    "cpe_uri": "cpe:2.3:a:fasterxml:jackson-databind:*:*:*:*:*:*:*:*",
                    "package": "jackson-databind",
                    "version": ">=2.7.0-<2.9.10.8",
                },
                "fixed_location": "2.9.10.8",
            },
            "short_description": "FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the interaction between serialization gadgets and typing, related to org.apache.commons.dbcp2.cpdsadapter.DriverAdapterCPDS.",
            "long_description": None,
            "related_urls": [
                "https://github.com/FasterXML/jackson-databind/issues/3004",
                "https://cowtowncoder.medium.com/on-jackson-cves-dont-panic-here-is-what-you-need-to-know-54cd0d6e8062",
            ],
            "effective_severity": "HIGH",
            "source_update_time": "2023-09-13T14:56:00",
            "source_orig_time": "2021-01-07T00:15:00",
            "matched_by": "3647951461_3647986090|fasterxml|jackson-databind|2.9.6",
        },
        {
            "id": "CVE-2019-12086",
            "problem_type": "CWE-502",
            "type": "fasterxml",
            "severity": "HIGH",
            "cvss_score": "7.5",
            "cvss_v3": {
                "base_score": 7.5,
                "exploitability_score": 3.9,
                "impact_score": 3.6,
                "attack_vector": "NETWORK",
                "attack_complexity": "LOW",
                "privileges_required": "NONE",
                "user_interaction": "NONE",
                "scope": "UNCHANGED",
                "confidentiality_impact": "HIGH",
                "integrity_impact": "NONE",
                "availability_impact": "NONE",
                "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            },
            "package_issue": {
                "affected_location": {
                    "cpe_uri": "cpe:2.3:a:fasterxml:jackson-databind:*:*:*:*:*:*:*:*",
                    "package": "jackson-databind",
                    "version": ">=2.9.0-<2.9.9",
                },
                "fixed_location": "2.9.9",
            },
            "short_description": "A Polymorphic Typing issue was discovered in FasterXML jackson-databind 2.x before 2.9.9. When Default Typing is enabled (either globally or for a specific property) for an externally exposed JSON endpoint, the service has the mysql-connector-java jar (8.0.14 or earlier) in the classpath, and an attacker can host a crafted MySQL server reachable by the victim, an attacker can send a crafted JSON message that allows them to read arbitrary local files on the server. This occurs because of missing com.mysql.cj.jdbc.admin.MiniAdmin validation.",
            "long_description": None,
            "related_urls": [
                "https://www.oracle.com/security-alerts/cpujul2020.html",
                "https://lists.apache.org/thread.html/rda99599896c3667f2cc9e9d34c7b6ef5d2bbed1f4801e1d75a2b0679@%3Ccommits.nifi.apache.org%3E",
                "https://www.oracle.com/security-alerts/cpuoct2020.html",
                "https://www.oracle.com/security-alerts/cpuApr2021.html",
                "https://www.oracle.com/security-alerts/cpuapr2022.html",
            ],
            "effective_severity": "HIGH",
            "source_update_time": "2023-09-13T14:16:00",
            "source_orig_time": "2019-05-17T17:29:00",
            "matched_by": "3747044328_3747096861|fasterxml|jackson-databind|2.9.6",
        },
        {
            "id": "CVE-2018-11784",
            "problem_type": "CWE-601",
            "type": "org.apache.tomcat.embed",
            "severity": "MEDIUM",
            "cvss_score": "4.3",
            "cvss_v3": {
                "base_score": 4.3,
                "exploitability_score": 4.3,
                "impact_score": 4.3,
                "attack_vector": "NETWORK",
                "attack_complexity": "LOW",
                "privileges_required": "NONE",
                "user_interaction": "REQUIRED",
                "scope": "UNCHANGED",
                "confidentiality_impact": "MEDIUM",
                "integrity_impact": "MEDIUM",
                "availability_impact": "MEDIUM",
                "vector_string": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
            },
            "package_issue": {
                "affected_location": {
                    "cpe_uri": "cpe:2.3:a:org.apache.tomcat.embed:tomcat-embed-core:*:*:*:*:*:*:*:*",
                    "package": "tomcat-embed-core",
                    "version": ">=8.5.0-<8.5.34",
                },
                "fixed_location": "8.5.34",
            },
            "short_description": "# Moderate severity vulnerability that affects org.apache.tomcat.embed:tomcat-embed-core\nWhen the default servlet in Apache Tomcat versions 9.0.0.M1 to 9.0.11, 8.5.0 to 8.5.33 and 7.0.23 to 7.0.90 returned a redirect to a directory (e.g. redirecting to '/foo/' when the user requested '/foo') a specially crafted URL could be used to cause the redirect to be generated to any URI of the attackers choice.",
            "long_description": None,
            "related_urls": [
                "https://nvd.nist.gov/vuln/detail/CVE-2018-11784",
                "https://access.redhat.com/errata/RHSA-2019:0130",
                "https://access.redhat.com/errata/RHSA-2019:0131",
                "https://access.redhat.com/errata/RHSA-2019:0485",
                "https://access.redhat.com/errata/RHSA-2019:1529",
                "https://github.com/advisories/GHSA-5q99-f34m-67gc",
                "https://seclists.org/bugtraq/2019/Dec/43",
                "https://security.netapp.com/advisory/ntap-20181014-0002/",
            ],
            "effective_severity": "MEDIUM",
            "source_update_time": "2023-04-11T01:35:23",
            "source_orig_time": "2018-10-17T16:31:02",
            "matched_by": "2650801486_2650849443|org.apache.tomcat.embed|tomcat-embed-core|8.5.31",
        },
        {
            "id": "CVE-2022-22971",
            "problem_type": "CWE-770",
            "type": "org.springframework",
            "severity": "MEDIUM",
            "cvss_score": "6.5",
            "cvss_v3": {
                "base_score": 6.5,
                "exploitability_score": 6.5,
                "impact_score": 6.5,
                "attack_vector": "NETWORK",
                "attack_complexity": "LOW",
                "privileges_required": "NONE",
                "user_interaction": "REQUIRED",
                "scope": "UNCHANGED",
                "confidentiality_impact": "MEDIUM",
                "integrity_impact": "MEDIUM",
                "availability_impact": "MEDIUM",
                "vector_string": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
            },
            "package_issue": {
                "affected_location": {
                    "cpe_uri": "cpe:2.3:a:org.springframework:spring-core:*:*:*:*:*:*:*:*",
                    "package": "spring-core",
                    "version": ">=0-<5.2.22.RELEASE",
                },
                "fixed_location": "5.2.22.RELEASE",
            },
            "short_description": "# Allocation of Resources Without Limits or Throttling in Spring Framework\nIn spring framework versions prior to 5.3.20+ , 5.2.22+ and old unsupported versions, application with a STOMP over WebSocket endpoint is vulnerable to a denial of service attack by an authenticated user.",
            "long_description": None,
            "related_urls": [
                "https://nvd.nist.gov/vuln/detail/CVE-2022-22971",
                "https://security.netapp.com/advisory/ntap-20220616-0003/",
                "https://tanzu.vmware.com/security/cve-2022-22971",
                "https://www.oracle.com/security-alerts/cpujul2022.html",
            ],
            "effective_severity": "MEDIUM",
            "source_update_time": "2023-04-11T01:33:53",
            "source_orig_time": "2022-05-13T00:00:29",
            "matched_by": "2660437234_2660469022|org.springframework|spring-core|5.0.7.RELEASE",
        },
        {
            "id": "CVE-2022-40150",
            "problem_type": "CWE-400,CWE-674",
            "type": "org.codehaus.jettison",
            "severity": "HIGH",
            "cvss_score": "7.5",
            "cvss_v3": {
                "base_score": 7.5,
                "exploitability_score": 7.5,
                "impact_score": 7.5,
                "attack_vector": "NETWORK",
                "attack_complexity": "LOW",
                "privileges_required": "NONE",
                "user_interaction": "REQUIRED",
                "scope": "UNCHANGED",
                "confidentiality_impact": "HIGH",
                "integrity_impact": "HIGH",
                "availability_impact": "HIGH",
                "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            },
            "package_issue": {
                "affected_location": {
                    "cpe_uri": "cpe:2.3:a:org.codehaus.jettison:jettison:*:*:*:*:*:*:*:*",
                    "package": "jettison",
                    "version": ">=0-<1.5.2",
                },
                "fixed_location": "1.5.2",
            },
            "short_description": "# Jettison memory exhaustion\nThose using Jettison to parse untrusted XML or JSON data may be vulnerable to Denial of Service attacks (DOS). If the parser is running on user supplied input, an attacker may supply content that causes the parser to crash by Out of memory. This effect may support a denial of service attack.",
            "long_description": None,
            "related_urls": [
                "https://nvd.nist.gov/vuln/detail/CVE-2022-40150",
                "https://github.com/jettison-json/jettison/issues/45",
                "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=46549",
                "https://github.com/jettison-json/jettison",
                "https://lists.debian.org/debian-lts-announce/2022/12/msg00045.html",
                "https://www.debian.org/security/2023/dsa-5312",
            ],
            "effective_severity": "HIGH",
            "source_update_time": "2023-07-13T19:19:12",
            "source_orig_time": "2022-09-17T00:00:41",
            "matched_by": "2662034264_2662079740|org.codehaus.jettison|jettison|1.3.7",
        },
    ]
    new_results = add_vulnerabilities(
        data, results, direct_purls, reached_purls
    )

    assert new_results.get("vulnerabilities") == [
        {
            "cve": "CVE-2020-36180",
            "cwe": {
                "id": "CWE-502",
                "name": "Deserialization of Untrusted Data",
            },
            "discovery_date": "2021-01-07T00:15:00",
            "flags": [{"label": "vulnerable_code_not_in_execute_path"}],
            "ids": [
                {
                    "system_name": "GitHub Issue [FasterXML/jackson-databind]",
                    "text": "3004",
                }
            ],
            "notes": [
                {
                    "category": "general",
                    "details": "Vulnerability Description",
                    "text": "FasterXML jackson-databind 2.x before 2.9.10.8 "
                    "mishandles the interaction between serialization gadgets "
                    "and typing, related to "
                    "org.apache.commons.dbcp2.cpdsadapter.DriverAdapterCPDS.",
                }
            ],
            "product_status": {
                "fixed": ["jackson-databind:2.9.10.8"],
                "known_affected": ["jackson-databind:>=2.7.0-<2.9.10.8"],
            },
            "references": [
                {
                    "summary": "Other",
                    "url": "https://cowtowncoder.medium.com/on-jackson-cves-dont-panic-here-is-what-you-need-to-know-54cd0d6e8062",
                },
                {
                    "summary": "GitHub Issue",
                    "url": "https://github.com/FasterXML/jackson-databind/issues/3004",
                },
            ],
            "scores": [
                {
                    "cvss_v3": {
                        "attackVector": "NETWORK",
                        "baseScore": 8.1,
                        "baseSeverity": "HIGH",
                        "privilegesRequired": "NONE",
                        "scope": "UNCHANGED",
                        "userInteraction": "NONE",
                        "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "version": "3.1",
                    },
                    "products": ["jackson-databind"],
                }
            ],
        },
        {
            "cve": "CVE-2019-12086",
            "cwe": {
                "id": "CWE-502",
                "name": "Deserialization of Untrusted Data",
            },
            "discovery_date": "2019-05-17T17:29:00",
            "flags": [{"label": "vulnerable_code_not_in_execute_path"}],
            "ids": [],
            "notes": [
                {
                    "category": "general",
                    "details": "Vulnerability Description",
                    "text": "A Polymorphic Typing issue was discovered in FasterXML "
                    "jackson-databind 2.x before 2.9.9. When Default Typing "
                    "is enabled (either globally or for a specific property) "
                    "for an externally exposed JSON endpoint, the service has "
                    "the mysql-connector-java jar (8.0.14 or earlier) in the "
                    "classpath, and an attacker can host a crafted MySQL "
                    "server reachable by the victim, an attacker can send a "
                    "crafted JSON message that allows them to read arbitrary "
                    "local files on the server. This occurs because of "
                    "missing com.mysql.cj.jdbc.admin.MiniAdmin validation.",
                }
            ],
            "product_status": {
                "fixed": ["jackson-databind:2.9.9"],
                "known_affected": ["jackson-databind:>=2.9.0-<2.9.9"],
            },
            "references": [
                {
                    "summary": "Oracle Security Alert",
                    "url": "https://www.oracle.com/security-alerts/cpujul2020.html",
                },
                {
                    "summary": "Mailing List Other",
                    "url": "https://lists.apache.org/thread.html/rda99599896c3667f2cc9e9d34c7b6ef5d2bbed1f4801e1d75a2b0679@%3Ccommits.nifi.apache.org%3E",
                },
                {
                    "summary": "Oracle Security Alert",
                    "url": "https://www.oracle.com/security-alerts/cpuoct2020.html",
                },
                {
                    "summary": "Oracle Security Alert",
                    "url": "https://www.oracle.com/security-alerts/cpuApr2021.html",
                },
                {
                    "summary": "Oracle Security Alert",
                    "url": "https://www.oracle.com/security-alerts/cpuapr2022.html",
                },
            ],
            "scores": [
                {
                    "cvss_v3": {
                        "attackVector": "NETWORK",
                        "baseScore": 7.5,
                        "baseSeverity": "HIGH",
                        "privilegesRequired": "NONE",
                        "scope": "UNCHANGED",
                        "userInteraction": "NONE",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        "version": "3.1",
                    },
                    "products": ["jackson-databind"],
                }
            ],
        },
        {
            "cve": "CVE-2018-11784",
            "cwe": {
                "id": "CWE-601",
                "name": "URL Redirection to Untrusted Site",
            },
            "discovery_date": "2018-10-17T16:31:02",
            "ids": [
                {
                    "system_name": "GitHub Advisory",
                    "text": "GHSA-5q99-f34m-67gc",
                },
                {"system_name": "Red Hat Advisory", "text": "RHSA-2019:0130"},
                {"system_name": "Red Hat Advisory", "text": "RHSA-2019:0131"},
                {"system_name": "Red Hat Advisory", "text": "RHSA-2019:0485"},
                {"system_name": "Red Hat Advisory", "text": "RHSA-2019:1529"},
                {
                    "system_name": "NetApp Advisory",
                    "text": "ntap-20181014-0002",
                },
            ],
            "notes": [
                {
                    "category": "general",
                    "details": "Vulnerability Description",
                    "text": "# Moderate severity vulnerability that affects "
                    "org.apache.tomcat.embed:tomcat-embed-core When the "
                    "default servlet in Apache Tomcat versions 9.0.0.M1 to "
                    "9.0.11, 8.5.0 to 8.5.33 and 7.0.23 to 7.0.90 returned a "
                    "redirect to a directory (e.g. redirecting to '/foo/' "
                    "when the user requested '/foo') a specially crafted URL "
                    "could be used to cause the redirect to be generated to "
                    "any URI of the attackers choice.",
                }
            ],
            "product_status": {
                "fixed": ["tomcat-embed-core:8.5.34"],
                "known_affected": ["tomcat-embed-core:>=8.5.0-<8.5.34"],
            },
            "references": [
                {
                    "summary": "CVE Record",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2018-11784",
                },
                {
                    "summary": "Other",
                    "url": "https://seclists.org/bugtraq/2019/Dec/43",
                },
                {
                    "summary": "Red Hat Advisory",
                    "url": "https://access.redhat.com/errata/RHSA-2019:0130",
                },
                {
                    "summary": "Red Hat Advisory",
                    "url": "https://access.redhat.com/errata/RHSA-2019:0131",
                },
                {
                    "summary": "Red Hat Advisory",
                    "url": "https://access.redhat.com/errata/RHSA-2019:0485",
                },
                {
                    "summary": "Red Hat Advisory",
                    "url": "https://access.redhat.com/errata/RHSA-2019:1529",
                },
                {
                    "summary": "GitHub Advisory",
                    "url": "https://github.com/advisories/GHSA-5q99-f34m-67gc",
                },
                {
                    "summary": "NetApp Advisory",
                    "url": "https://security.netapp.com/advisory/ntap-20181014-0002/",
                },
            ],
            "scores": [
                {
                    "cvss_v3": {
                        "attackVector": "NETWORK",
                        "baseScore": 4.3,
                        "baseSeverity": "MEDIUM",
                        "privilegesRequired": "NONE",
                        "scope": "UNCHANGED",
                        "userInteraction": "REQUIRED",
                        "vectorString": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                        "version": "3.0",
                    },
                    "products": ["tomcat-embed-core"],
                }
            ],
        },
        {
            "cve": "CVE-2022-22971",
            "cwe": {
                "id": "CWE-770",
                "name": "Allocation of Resources Without Limits or Throttling",
            },
            "discovery_date": "2022-05-13T00:00:29",
            "flags": [{"label": "vulnerable_code_not_in_execute_path"}],
            "ids": [
                {"system_name": "NetApp Advisory", "text": "ntap-20220616-0003"}
            ],
            "notes": [
                {
                    "category": "general",
                    "details": "Vulnerability Description",
                    "text": "# Allocation of Resources Without Limits or Throttling "
                    "in Spring Framework In spring framework versions prior "
                    "to 5.3.20+ , 5.2.22+ and old unsupported versions, "
                    "application with a STOMP over WebSocket endpoint is "
                    "vulnerable to a denial of service attack by an "
                    "authenticated user.",
                }
            ],
            "product_status": {
                "fixed": ["spring-core:5.2.22.RELEASE"],
                "known_affected": ["spring-core:>=0-<5.2.22.RELEASE"],
            },
            "references": [
                {
                    "summary": "CVE Record",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-22971",
                },
                {
                    "summary": "CVE Record",
                    "url": "https://tanzu.vmware.com/security/cve-2022-22971",
                },
                {
                    "summary": "Oracle Security Alert",
                    "url": "https://www.oracle.com/security-alerts/cpujul2022.html",
                },
                {
                    "summary": "NetApp Advisory",
                    "url": "https://security.netapp.com/advisory/ntap-20220616-0003/",
                },
            ],
            "scores": [
                {
                    "cvss_v3": {
                        "attackVector": "NETWORK",
                        "baseScore": 6.5,
                        "baseSeverity": "MEDIUM",
                        "privilegesRequired": "NONE",
                        "scope": "UNCHANGED",
                        "userInteraction": "REQUIRED",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
                        "version": "3.1",
                    },
                    "products": ["spring-core"],
                }
            ],
        },
        {
            "cve": "CVE-2022-40150",
            "cwe": {
                "id": "CWE-400",
                "name": "Uncontrolled Resource Consumption",
            },
            "discovery_date": "2022-09-17T00:00:41",
            "ids": [
                {
                    "system_name": "GitHub Issue [jettison-json/jettison]",
                    "text": "45",
                },
                {"system_name": "Chromium Issue [oss-fuzz]", "text": "46549"},
                {"system_name": "Debian Advisory", "text": "dsa-5312"},
            ],
            "notes": [
                {
                    "audience": "developers",
                    "category": "other",
                    "text": "Uncontrolled Recursion",
                    "title": "Additional CWE: CWE-674",
                },
                {
                    "category": "general",
                    "details": "Vulnerability Description",
                    "text": "# Jettison memory exhaustion Those using Jettison to "
                    "parse untrusted XML or JSON data may be vulnerable to "
                    "Denial of Service attacks (DOS). If the parser is "
                    "running on user supplied input, an attacker may supply "
                    "content that causes the parser to crash by Out of "
                    "memory. This effect may support a denial of service "
                    "attack.",
                },
            ],
            "product_status": {
                "fixed": ["jettison:1.5.2"],
                "known_affected": ["jettison:>=0-<1.5.2"],
            },
            "references": [
                {
                    "summary": "CVE Record",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-40150",
                },
                {
                    "summary": "GitHub Repository",
                    "url": "https://github.com/jettison-json/jettison",
                },
                {
                    "summary": "Mailing List Announcement",
                    "url": "https://lists.debian.org/debian-lts-announce/2022/12/msg00045.html",
                },
                {
                    "summary": "GitHub Issue",
                    "url": "https://github.com/jettison-json/jettison/issues/45",
                },
                {
                    "summary": "Chromium Issue",
                    "url": "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=46549",
                },
                {
                    "summary": "Debian Advisory",
                    "url": "https://www.debian.org/security/2023/dsa-5312",
                },
            ],
            "scores": [
                {
                    "cvss_v3": {
                        "attackVector": "NETWORK",
                        "baseScore": 7.5,
                        "baseSeverity": "HIGH",
                        "privilegesRequired": "NONE",
                        "scope": "UNCHANGED",
                        "userInteraction": "REQUIRED",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                        "version": "3.1",
                    },
                    "products": ["jettison"],
                }
            ],
        },
    ]


def test_version_helper():
    # Returns True if the version in 'reached' satisfies the conditions
    # specified by 'vdata'.
    reached = ["1.0.0", "2.0.0", "3.0.0"]
    vdata = {"lower": "2.0.0", "lmod": ">=", "upper": "3.0.0", "umod": "<"}
    result = version_helper(reached, vdata)
    assert result is True

    # Returns False if the version in 'reached' does not satisfy the
    # conditions specified by 'vdata'.
    vdata = {"lower": "4.0.0", "lmod": ">=", "upper": "5.0.0", "umod": "<"}
    result = version_helper(reached, vdata)
    assert result is False

    # Returns True if the lower bound modifier is ">=" and the version in
    # 'reached' is equal to the lower bound of the version range.
    vdata = {"lower": "2.0.0", "lmod": ">=", "upper": "3.0.0", "umod": "<"}
    result = version_helper(reached, vdata)
    assert result is True

    # Returns False if the lower bound modifier is ">=" and the version in
    # 'reached' is less than the lower bound of the version range.
    vdata = {"lower": "4.0.0", "lmod": ">=", "upper": "5.0.0", "umod": "<"}
    result = version_helper(reached, vdata)
    assert result is False

    # Returns False if the upper bound modifier is "<=" and the version in
    # 'reached' is greater than the upper bound of the version range.
    vdata = {"lower": "2.0.0", "lmod": ">=", "upper": "3.0.0", "umod": "<="}
    result = version_helper(reached, vdata)
    assert result is True

    #  Returns False if the lower bound modifier is ">" and the version in
    # 'reached' is less than or equal to the lower bound of the version range.
    vdata = {"lower": "2.0.0", "lmod": ">", "upper": "3.0.0", "umod": "<"}
    result = version_helper(reached, vdata)
    assert result is False
