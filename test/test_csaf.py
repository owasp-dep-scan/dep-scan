import os.path

from depscan.lib.csaf import (
    CsafOccurence,
    format_references,
    import_csaf_toml,
    parse_cwe,
    get_product_status,
    get_ref_summary,
    parse_cvss,
    parse_revision_history,
    cleanup_list,
    cleanup_dict,
    parse_toml,
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

    # Cope with a missing revision history
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

    # Cope with a NoneType revision history
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
    url = "https://github.com/advisories"
    assert get_ref_summary(url) == "GitHub Advisory"
    url = "https://github.com/user/repo/security/advisories"
    assert get_ref_summary(url) == "GitHub Advisory"
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
    assert get_ref_summary(url) == "Red Hat Security Advisory"
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
        "https://github.com/FasterXML/jackson-databind/issues/2816"
        "https://sec.cloudapps.cisco.com/security/center/content"
        "/CiscoSecurityAdvisory/cisco-sa-apache-log4j-qRuKNEbd",
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
        {"system_name": "GitHub Advisory", "text": "GHSA-1234-1234-1234"},
        {"system_name": "GitHub Advisory", "text": "GHSA-5432-5432-5432"},
        {"system_name": "Red Hat Security Advisory", "text": "RHSA-2023:5484"},
        {"system_name": "Red Hat Bugzilla ID", "text": "cve-2021-1234"},
    ]
    assert refs == [
        {
            "summary": "Red Hat Security Advisory",
            "url": "https://access.redhat.com/errata/RHSA-2023:5484",
        },
        {
            "summary": "Bugzilla",
            "url": "https://bugzilla.redhat.com/show_bug.cgi?id=2224245",
        },
        {
            "summary": "Bugzilla",
            "url": "https://bugzilla.redhat.com/show_bug.cgi?id=cve-2021-1234",
        },
        {"summary": "Other", "url": "https://example.com"},
        {
            "summary": "GitHub Issue",
            "url": "https://github.com/FasterXML/jackson-databind/issues/2816https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-apache-log4j-qRuKNEbd",
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
            "url": "https://github.com/user/repo/security/advisories/GHSA-5432-5432-5432",
        },
        {
            "summary": "CVE Record",
            "url": "https://nvd.nist.gov/vuln/detail/cve-2021-1234",
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
    res["cvss_v3"]["vector_string"] = ""
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
    ) == ("taffydb", {"known_affected": ["taffydb:<=2.7.3"]})


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
    result = []
    for o in occs:
        result.append(o.to_dict())
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
                    "text": "# TaffyDB can allow access to any data items in "
                    "the DB "
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
                "name": "Improperly Controlled Modification of Object "
                "Prototype Attributes",
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
                    "summary": "GitHub Advisory",
                    "url": "https://github.com/markdown-it/markdown-it"
                    "/security/advisories/GHSA-6vfc-qv3f-vr6c",
                },
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
