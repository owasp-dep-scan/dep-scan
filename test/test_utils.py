import os

from depscan.lib import utils


def test_cleanup_license_string():
    data = utils.cleanup_license_string("MIT")
    assert data == "MIT"
    data = utils.cleanup_license_string("MIT/GPL-3.0")
    assert data == "MIT OR GPL-3.0"
    data = utils.cleanup_license_string("MIT / GPL-3.0")
    assert data == "MIT OR GPL-3.0"
    data = utils.cleanup_license_string("MIT & GPL-3.0")
    assert data == "MIT OR GPL-3.0"
    data = utils.cleanup_license_string("MIT&GPL-3.0")
    assert data == "MIT OR GPL-3.0"
    data = utils.cleanup_license_string("(MIT)")
    assert data == "MIT"
    data = utils.cleanup_license_string("(MIT OR GPL-2.0")
    assert data == "MIT OR GPL-2.0"


def test_max_version():
    ret = utils.max_version("1.0.0")
    assert ret == "1.0.0"
    ret = utils.max_version(["1.0.0", "1.0.1", "2.0.0"])
    assert ret == "2.0.0"
    ret = utils.max_version(["1.1.0", "2.1.1", "2.0.0"])
    assert ret == "2.1.1"
    ret = utils.max_version(
        ["2.9.10.1", "2.9.10.4", "2.9.10", "2.8.11.5", "2.8.11", "2.8.11.2"]
    )
    assert ret == "2.9.10.4"
    ret = utils.max_version(["2.9.10", "2.9.10.4"])
    assert ret == "2.9.10.4"


def test_get_pkg_vendor_name():
    vendor, name = utils.get_pkg_vendor_name({"vendor": "angular", "name": "cdk"})
    assert vendor == "angular"
    assert name == "cdk"

    vendor, name = utils.get_pkg_vendor_name(
        {"vendor": "", "purl": "pkg:npm/parse5@5.1.0", "name": "parse5"}
    )
    assert vendor == "npm"
    assert name == "parse5"


def test_get_pkgs_by_scope():
    scoped_pkgs = utils.get_pkgs_by_scope([{"vendor": "angular", "name": "cdk"}])
    assert not scoped_pkgs

    scoped_pkgs = utils.get_pkgs_by_scope(
        [
            {"vendor": "angular", "name": "cdk"},
            {
                "vendor": "",
                "purl": "pkg:npm/parse5@5.1.0",
                "name": "parse5",
                "scope": "required",
            },
        ],
    )
    assert scoped_pkgs == {"required": ["pkg:npm/parse5@5.1.0"]}

    scoped_pkgs = utils.get_pkgs_by_scope(
        [
            {"vendor": "angular", "name": "cdk"},
            {
                "vendor": "",
                "purl": "pkg:npm/parse5@5.1.0",
                "name": "parse5",
                "scope": "required",
            },
            {"vendor": "angular-devkit", "name": "build-webpack", "scope": "optional"},
        ],
    )
    assert scoped_pkgs == {
        "required": ["pkg:npm/parse5@5.1.0"],
        "optional": ["angular-devkit:build-webpack"],
    }


def test_is_exe():
    assert not utils.is_exe(os.path.join(__file__))
    if os.path.exists("/bin/ls"):
        assert utils.is_exe("/bin/ls")

def test_template_report():
    utils.render_template_report(
        jsonl_report_file=os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "data",
            "depscan-java.json",
        ),
        summary={
            "UNSPECIFIED": 0,
            "LOW": 3,
            "MEDIUM": 5,
            "HIGH": 2,
            "CRITICAL": 1,
        },
        template_file=os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "data",
            "report-template.j2",
        ),
        result_file="rendered.report"
    )
    with open("rendered.report", "r", encoding="utf-8") as report_file:
        rendered_report = report_file.read()

    assert rendered_report == """\
there are 13 vulns in here:

* CVE-2018-5968 - com.fasterxml.jackson.core:jackson-databind
* CVE-2018-12022 - com.fasterxml.jackson.core:jackson-databind
* CVE-2018-12023 - com.fasterxml.jackson.core:jackson-databind
* CVE-2019-17267 - com.fasterxml.jackson.core:jackson-databind
* CVE-2020-9547 - com.fasterxml.jackson.core:jackson-databind
* CVE-2020-10673 - com.fasterxml.jackson.core:jackson-databind
* CVE-2020-9548 - com.fasterxml.jackson.core:jackson-databind
* CVE-2019-14892 - com.fasterxml.jackson.core:jackson-databind
* CVE-2020-8840 - com.fasterxml.jackson.core:jackson-databind
* CVE-2019-20330 - com.fasterxml.jackson.core:jackson-databind
* CVE-2019-10172 - org.codehaus.jackson:jackson-mapper-asl
* CVE-2019-17531 - com.fasterxml.jackson.core:jackson-databind
* CVE-2019-16943 - com.fasterxml.jackson.core:jackson-databind
That's 3 of low severity,
5 medium, 2 high,
1 critical and 0 unspecified ones."""
    os.remove("rendered.report")
