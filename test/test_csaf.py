import os.path


from depscan.lib.csaf import (add_vulnerabilities, cleanup_dict, cleanup_list,
                              format_references, get_acknowledgements,
                              get_products, get_ref_summary, import_csaf_toml,
                              import_root_component, parse_cvss, parse_cwe,
                              parse_revision_history, parse_toml,
                              verify_components_present, )


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
    advisories = [
        {
            "title": "testing",
            "url": "https://access.redhat.com/errata/RHSA-2023:5484",
        },
        {
            "title": "testing",
            "url": "https://bugzilla.redhat.com/show_bug.cgi?id=2224245",
        },
        {
            "title": "testing",
            "url": "https://nvd.nist.gov/vuln/detail/cve-2021-1234",
        },
        {
            "title": "testing",
            "url": "https://github.com/advisories/GHSA-1234-1234-1234",
        },
        {
            "title": "testing",
            "url": (
                "https://github.com/user/repo/security/advisories/GHSA"
                "-5432-5432-5432"
            ),
        },
        {"title": "testing", "url": "https://github.com/user/repo/pull/123"},
        {"title": "testing", "url": "https://github.com/user/repo/commit/123"},
        {"title": "testing", "url": "https://example.com"},
        {"title": "testing", "url": "https://github.com/user/repo/release"},
        {"title": "testing", "url": "https://github.com/user/repo"},
        {
            "title": "testing",
            "url": "https://bugzilla.redhat.com/show_bug.cgi?id=cve-2021-1234",
        },
        {
            "title": "testing",
            "url": "https://github.com/FasterXML/jackson-databind/issues/2816",
        },
        {
            "title": "testing",
            "url": (
                "https://sec.cloudapps.cisco.com/security/center/content"
                "/CiscoSecurityAdvisory/cisco-sa-apache-log4j-qRuKNEbd"
            ),
        },
        {
            "title": "testing",
            "url": "https://bitbucket.org/snakeyaml/snakeyaml/issues/525",
        },
        {
            "title": "testing",
            "url": (
                "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=4707"
            ),
        },
    ]

    [ids, refs] = format_references(advisories)
    # For consistency in tests
    ids = sorted(ids, key=lambda x: x["text"])
    refs = sorted(refs, key=lambda x: x["url"])
    assert ids == [
        {"system_name": "Red Hat Bugzilla ID", "text": "2224245"},
        {
            "system_name": "GitHub Issue [FasterXML/jackson-databind]",
            "text": "2816",
        },
        {"system_name": "Chromium Issue [oss-fuzz]", "text": "4707"},
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
            "url": "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=4707",
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
            "url": (
                "https://github.com/user/repo/security/advisories/GHSA"
                "-5432-5432-5432"
            ),
        },
        {
            "summary": "CVE Record",
            "url": "https://nvd.nist.gov/vuln/detail/cve-2021-1234",
        },
        {
            "summary": "Cisco Advisory",
            "url": (
                "https://sec.cloudapps.cisco.com/security/center/content"
                "/CiscoSecurityAdvisory/cisco-sa-apache-log4j-qRuKNEbd"
            ),
        },
    ]


def test_parse_cwe():
    assert parse_cwe([20, 668]) == (
        {"id": "20", "name": "Improper Input Validation"},
        [
            {
                "title": "Additional CWE: 668",
                "audience": "developers",
                "category": "other",
                "text": "Exposure of Resource to Wrong Sphere",
            }
        ],
    )
    assert parse_cwe([1333]) == (
        {
            "id": "1333",
            "name": "Inefficient Regular Expression Complexity",
        },
        [],
    )
    assert parse_cwe([]) == (None, [])
    assert parse_cwe([1010101]) == (
        {"id": "1010101", "name": "UNABLE TO LOCATE CWE NAME"},
        [],
    )


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
    assert parse_cvss([{
        "vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]) == {
        'attackComplexity': 'LOW',
        'attackVector': 'NETWORK',
        'availabilityImpact': 'HIGH',
        'baseScore': 9.8,
        'baseSeverity': 'CRITICAL',
        'confidentialityImpact': 'HIGH',
        'environmentalScore': 9.8,
        'environmentalSeverity': 'CRITICAL',
        'integrityImpact': 'HIGH',
        'modifiedAttackComplexity': 'LOW',
        'modifiedAttackVector': 'NETWORK',
        'modifiedAvailabilityImpact': 'HIGH',
        'modifiedConfidentialityImpact': 'HIGH',
        'modifiedIntegrityImpact': 'HIGH',
        'modifiedPrivilegesRequired': 'NONE',
        'modifiedScope': 'UNCHANGED',
        'modifiedUserInteraction': 'NONE',
        'privilegesRequired': 'NONE',
        'scope': 'UNCHANGED',
        'temporalScore': 9.8,
        'temporalSeverity': 'CRITICAL',
        'userInteraction': 'NONE',
        'vectorString': 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        'version': '3.0'
    }
    assert parse_cvss([{}]) == {}


def test_get_products():
    assert get_products([], []) == ([], {})
    affects = [
        {
            "ref": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9"
                   ".6?type=jar",
            "versions": [
                {"version": "2.9.6", "status": "affected"},
                {"version": "2.9.8", "status": "unaffected"},
            ]
        },
        {
            "ref": "pkg:maven/org.apache.httpcomponents/httpclient@4.5.5?type"
                   "=jar",
            "versions": [
                {"version": "4.5.5", "status": "affected"},
                {"version": "4.5.13", "status": "unaffected"},
            ]
        },
        {
            "ref": "pkg:pypi/setuptools@65.5.0",
            "versions": [
                {"version": "65.5.0", "status": "affected"},
            ]
        },
        {
            "ref": "pkg:golang/golang.org/x/net@v0.15.0",
            "versions": [{"version": "0.15.0", "status": "affected"}, ],
        },
            ]
    props = [
        {"name": "affectedVersionRange",
         "value": "com.fasterxml.jackson.core/jackson-databind@>=2.9.0-<2.9.8"},
        {"name": "affectedVersionRange",
         "value": "org.apache.httpcomponents/httpclient@>=4.5.0-<4.5.13"},
        {"name": "affectedVersionRange", "value": "setuptools@>=65.5.0"},
    ]
    [products, product_status] = get_products(affects, props)
    products.sort()
    assert products == [
        'com.fasterxml.jackson.core/jackson-databind@2.9.6',
        'com.fasterxml.jackson.core/jackson-databind@>=2.9.0-<2.9.8',
        'golang.org/x/net@v0.15.0',
        'org.apache.httpcomponents/httpclient@4.5.5',
        'org.apache.httpcomponents/httpclient@>=4.5.0-<4.5.13',
        'setuptools@65.5.0',
        'setuptools@>=65.5.0'
    ]
    assert product_status == {
        'fixed': ['com.fasterxml.jackson.core/jackson-databind@2.9.8',
           'org.apache.httpcomponents/httpclient@4.5.13'],
        'known_affected': [
            'com.fasterxml.jackson.core/jackson-databind@2.9.6',
            'org.apache.httpcomponents/httpclient@4.5.5',
            'setuptools@65.5.0',
            'golang.org/x/net@v0.15.0',
            'com.fasterxml.jackson.core/jackson-databind@>=2.9.0-<2.9.8',
            'org.apache.httpcomponents/httpclient@>=4.5.0-<4.5.13',
            'setuptools@>=65.5.0'
        ]}


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
                    "purl": (
                        "pkg:maven/com.example/vuln-spring@0.0.1-SNAPSHOT"
                        "?type=jar"
                    )
                },
            }
        ]
    }

    assert ref == [
        {
            "summary": "website",
            "url": (
                "https://projects.spring.io/spring-boot/#/spring"
                "-boot-starter-parent/vuln-spring"
            ),
        },
        {
            "summary": "vcs",
            "url": (
                "https://github.com/spring-projects/spring-boot"
                "/spring-boot-starter-parent/vuln-spring"
            ),
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
        "vulnerabilities": [],
    }
    metadata = {
        "depscan_version": "5.0.2",
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
            "text": (
                "Depscan reachable code only covers the "
                "project source code, not the code of "
                "dependencies. A dependency may execute "
                "vulnerable code when called even if it is "
                "not in the project's source code. Regard the "
                "Depscan-set flag of "
                "'code_not_in_execute_path' with this in "
                "mind."
            ),
        }
    ]
    assert template["product_tree"] == {
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
    assert new_metadata["tracking"] == {
        "current_release_date": "2023-11-12T06:51:08",
        "id": "",
        "initial_release_date": "2023-11-12T06:51:08",
        "status": "draft",
        "version": "1",
    }


def test_add_vulnerabilities():
    template = {
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
    pkg_vulnerabilities = [
        {
            "bom-ref": "CVE-2020-10673/pkg:maven/com.fasterxml.jackson.core"
                       "/jackson-databind@2.9.6?type=jar",
            "id": "CVE-2020-10673",
            "published": "2020-03-18T22:15:00",
            "updated": "2023-11-07T03:14:00",
            "source": {
                "name": "NVD",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2020-10673",
            },
            "ratings": [
                {
                    "score": 8.8,
                    "severity": "high",
                    "method": "CVSSv31",
                    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
                }
            ],
            "cwes": [668, 520, 521],
            "description": (
                "FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the"
                " interaction between serialization gadgets and typing, related"
                " to com.caucho.config.types.ResourceRef (aka caucho-quercus)."
            ),
            "recommendation": "Update to 2.12.7.1 or later",
            "advisories": [
                {
                    "title": "GitHub Issue",
                    "url": "https://github.com/FasterXML/jackson-databind"
                           "/issues/2660",
                },
                {
                    "title": "Mailing List",
                    "url": "https://lists.debian.org/debian-lts-announce/2020"
                           "/03/msg00027.html",
                },
                {
                    "title": "vendor",
                    "url": (
                        "https://www.oracle.com/security-alerts/cpuoct2021.html"
                    ),
                },
            ],
            "affects": [
                {
                    "ref": "pkg:maven/com.fasterxml.jackson.core/jackson"
                           "-databind@2.9.6?type=jar",
                    "versions": [
                        {"version": "2.9.6", "status": "affected"},
                        {"version": "2.12.7.1", "status": "unaffected"},
                    ],
                }
            ],
            "properties": [
                {
                    "name": "depscan:insights",
                    "value": "Direct dependency\\nVendor Confirmed",
                },
                {"name": "depscan:prioritized", "value": "true"},
                {
                    "name": "affected_version_range",
                    "value": ">=2.9.0-<2.9.10.4",
                },
            ],
        },
        {
            "bom-ref": "CVE-2021-20190/pkg:maven/com.fasterxml.jackson.core"
                       "/jackson-databind@2.9.6?type=jar",
            "id": "CVE-2021-20190",
            "published": "2021-01-19T17:15:00",
            "updated": "2023-11-07T03:28:00",
            "source": {
                "name": "NVD",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-20190",
            },
            "ratings": [
                {
                    "score": 8.1,
                    "severity": "high",
                    "method": "CVSSv31",
                    "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
                }
            ],
            "cwes": [502],
            "description": (
                "A flaw was found in jackson-databind before 2.9.10.7."
                " FasterXML mishandles the interaction between serialization"
                " gadgets and typing. The highest threat from this"
                " vulnerability is to data confidentiality and integrity as"
                " well as system availability."
            ),
            "recommendation": "Update to 2.12.7.1 or later",
            "advisories": [
                {
                    "title": "GitHub Issue",
                    "url": "https://github.com/FasterXML/jackson-databind"
                           "/issues/2854",
                },
                {
                    "title": "vendor",
                    "url": "https://www.oracle.com//security-alerts"
                           "/cpujul2021.html",
                },
                {
                    "title": "Mailing List",
                    "url": "https://lists.debian.org/debian-lts-announce/2021"
                           "/04/msg00025.html",
                },
            ],
            "affects": [
                {
                    "ref": "pkg:maven/com.fasterxml.jackson.core/jackson"
                           "-databind@2.9.6?type=jar",
                    "versions": [
                        {"version": "2.9.6", "status": "affected"},
                        {"version": "2.12.7.1", "status": "unaffected"},
                    ],
                }
            ],
            "properties": [
                {
                    "name": "depscan:insights",
                    "value": "Direct dependency\\nVendor Confirmed",
                },
                {"name": "depscan:prioritized", "value": "true"},
                {
                    "name": "affected_version_range",
                    "value": ">=2.7.0-<2.9.10.7",
                },
            ],
        },
    ]
    new_results = add_vulnerabilities(template, pkg_vulnerabilities)
    assert new_results.get("vulnerabilities") == [
        {
            "acknowledgements": {
                "organization": "NVD",
                "urls": ["https://nvd.nist.gov/vuln/detail/CVE-2020-10673"],
            },
            "cve": "CVE-2020-10673",
            "cwe": {
                "id": "668",
                "name": "Exposure of Resource to Wrong Sphere",
            },
            "discovery_date": "2020-03-18T22:15:00",
            "ids": [
                {
                    "system_name": "GitHub Issue [FasterXML/jackson-databind]",
                    "text": "2660",
                }
            ],
            "notes": [
                {
                    "audience": "developers",
                    "category": "other",
                    "text": ".NET Misconfiguration: Use of Impersonation",
                    "title": "Additional CWE: 520",
                },
                {
                    "audience": "developers",
                    "category": "other",
                    "text": "Weak Password Requirements",
                    "title": "Additional CWE: 521",
                },
                {
                    "category": "general",
                    "details": "Vulnerability Description",
                    "text": (
                        "FasterXML jackson-databind 2.x before 2.9.10.4"
                        " mishandles the interaction between serialization"
                        " gadgets and typing, related to"
                        " com.caucho.config.types.ResourceRef (aka"
                        " caucho-quercus)."
                    ),
                },
            ],
            "product_status": {
                "fixed": [
                    "com.fasterxml.jackson.core/jackson-databind@2.12.7.1"
                ],
                "known_affected": [
                    "com.fasterxml.jackson.core/jackson-databind@2.9.6"
                ],
            },
            "references": [
                {
                    "summary": "Mailing List Announcement",
                    "url": "https://lists.debian.org/debian-lts-announce/2020"
                           "/03/msg00027.html",
                },
                {
                    "summary": "Oracle Security Alert",
                    "url": (
                        "https://www.oracle.com/security-alerts/cpuoct2021.html"
                    ),
                },
                {
                    "summary": "GitHub Issue",
                    "url": "https://github.com/FasterXML/jackson-databind"
                           "/issues/2660",
                },
            ],
            "scores": [
                {'cvss_v3': {
                    'attackComplexity': 'LOW',
                    'attackVector': 'NETWORK',
                    'availabilityImpact': 'HIGH',
                    'baseScore': 8.8,
                    'baseSeverity': 'HIGH',
                    'confidentialityImpact': 'HIGH',
                    'environmentalScore': 8.8,
                    'environmentalSeverity': 'HIGH',
                    'integrityImpact': 'HIGH',
                    'modifiedAttackComplexity': 'LOW',
                    'modifiedAttackVector': 'NETWORK',
                    'modifiedAvailabilityImpact': 'HIGH',
                    'modifiedConfidentialityImpact': 'HIGH',
                    'modifiedIntegrityImpact': 'HIGH',
                    'modifiedPrivilegesRequired': 'NONE',
                    'modifiedScope': 'UNCHANGED',
                    'modifiedUserInteraction': 'REQUIRED',
                    'privilegesRequired': 'NONE',
                    'scope': 'UNCHANGED',
                    'temporalScore': 8.8,
                    'temporalSeverity': 'HIGH',
                    'userInteraction': 'REQUIRED',
                    'vectorString': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H'
                                    '/A:H',
                    'version': '3.1'
                },
                    "products": [
                        "com.fasterxml.jackson.core/jackson-databind@2.9.6"
                    ],
                }
            ],
        },
        {
            "acknowledgements": {
                "organization": "NVD",
                "urls": ["https://nvd.nist.gov/vuln/detail/CVE-2021-20190"],
            },
            "cve": "CVE-2021-20190",
            "cwe": {"id": "502", "name": "Deserialization of Untrusted Data"},
            "discovery_date": "2021-01-19T17:15:00",
            "ids": [
                {
                    "system_name": "GitHub Issue [FasterXML/jackson-databind]",
                    "text": "2854",
                }
            ],
            "notes": [
                {
                    "category": "general",
                    "details": "Vulnerability Description",
                    "text": (
                        "A flaw was found in jackson-databind before "
                        "2.9.10.7. FasterXML mishandles the interaction "
                        "between serialization gadgets and typing. The "
                        "highest threat from this vulnerability is to "
                        "data confidentiality and integrity as well as "
                        "system availability."
                    ),
                }
            ],
            "product_status": {
                "fixed": [
                    "com.fasterxml.jackson.core/jackson-databind@2.12.7.1"
                ],
                "known_affected": [
                    "com.fasterxml.jackson.core/jackson-databind@2.9.6"
                ],
            },
            "references": [
                {
                    "summary": "Other",
                    "url": (
                        "https://www.oracle.com//security-alerts"
                        "/cpujul2021.html"
                    ),
                },
                {
                    "summary": "Mailing List Announcement",
                    "url": (
                        "https://lists.debian.org/debian-lts-announce/2021"
                        "/04/msg00025.html"
                    ),
                },
                {
                    "summary": "GitHub Issue",
                    "url": (
                        "https://github.com/FasterXML/jackson-databind"
                        "/issues/2854"
                    ),
                },
            ],
            "scores": [
                {
                    'cvss_v3': {
                        'attackComplexity': 'HIGH',
                        'attackVector': 'NETWORK',
                        'availabilityImpact': 'HIGH',
                        'baseScore': 8.1,
                        'baseSeverity': 'HIGH',
                        'confidentialityImpact': 'HIGH',
                        'environmentalScore': 8.1,
                        'environmentalSeverity': 'HIGH',
                        'integrityImpact': 'HIGH',
                        'modifiedAttackComplexity': 'HIGH',
                        'modifiedAttackVector': 'NETWORK',
                        'modifiedAvailabilityImpact': 'HIGH',
                        'modifiedConfidentialityImpact': 'HIGH',
                        'modifiedIntegrityImpact': 'HIGH',
                        'modifiedPrivilegesRequired': 'NONE',
                        'modifiedScope': 'UNCHANGED',
                        'modifiedUserInteraction': 'NONE',
                        'privilegesRequired': 'NONE',
                        'scope': 'UNCHANGED',
                        'temporalScore': 8.1,
                        'temporalSeverity': 'HIGH',
                        'userInteraction': 'NONE',
                        'vectorString': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H'
                                        '/I:H/A:H',
                        'version': '3.1'
                    },
                    "products": [
                        "com.fasterxml.jackson.core/jackson-databind@2.9.6"
                    ],
                }
            ],
        },
    ]
    new_results = add_vulnerabilities(template, [])
    assert new_results.get("vulnerabilities") == []


def test_get_acknowledgements():
    source = {
        "name": "NVD",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-20190",
    }
    assert get_acknowledgements(source) == {
        "organization": "NVD",
        "urls": ["https://nvd.nist.gov/vuln/detail/CVE-2021-20190"],
    }
    source = {"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-20190"}
    assert get_acknowledgements(source) == {}

