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

def test_template_report_from_vdr():
    utils.render_template_report(
        vdr_file=os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "data",
            "jinja-report.vdr.json",
        ),
        bom_file=os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "data",
            "jinja-report.bom.json",
        ),
        pkg_vulnerabilities=[],
        pkg_group_rows=[],
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
Report for io.github.heubeck:examiner:1.11.26
Component count: 228
* BIT-apisix-2023-44487/pkg:maven/io.netty/netty-codec-http2@4.1.94.Final?type=jar - Update to 4.1.100.Final or later
* CVE-2023-4043/pkg:maven/org.eclipse.parsson/parsson@1.1.2?type=jar - Update to 1.1.4 or later
"""
    os.remove("rendered.report")

def test_template_report_from_bom():
    utils.render_template_report(
        vdr_file=os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "data",
            "no-vdr-here",
        ),
        bom_file=os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "data",
            "jinja-report.bom.json",
        ),
        pkg_vulnerabilities=[],
        pkg_group_rows=[],
        summary={
            "UNSPECIFIED": 0,
            "LOW": 0,
            "MEDIUM": 0,
            "HIGH": 0,
            "CRITICAL": 0,
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
Report for io.github.heubeck:examiner:1.11.27
Component count: 230
🏆 No vulnerabilities found 🎉
"""
    os.remove("rendered.report")
