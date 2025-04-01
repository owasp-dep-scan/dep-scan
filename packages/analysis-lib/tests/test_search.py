from analysis_lib import search


def test_get_pkg_vendor_name():
    vendor, name = search.get_pkg_vendor_name({"vendor": "angular", "name": "cdk"})
    assert vendor == "angular"
    assert name == "cdk"

    vendor, name = search.get_pkg_vendor_name(
        {"vendor": "", "purl": "pkg:npm/parse5@5.1.0", "name": "parse5"}
    )
    assert vendor == "npm"
    assert name == "parse5"


def test_get_pkgs_by_scope():
    scoped_pkgs = search.get_pkgs_by_scope([{"vendor": "angular", "name": "cdk"}])
    assert not scoped_pkgs

    scoped_pkgs = search.get_pkgs_by_scope(
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

    scoped_pkgs = search.get_pkgs_by_scope(
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
