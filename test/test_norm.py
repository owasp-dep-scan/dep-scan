from depscan.lib.normalize import create_pkg_variations, normalize_pkg


def test_pkg_norm():
    assert normalize_pkg({"vendor": "foo", "name": "bar"}) == {
        "vendor": "foo",
        "name": "bar",
    }

    assert normalize_pkg({"vendor": "org.apache.struts", "name": "struts2-core"}) == {
        "vendor": "apache",
        "name": "struts",
    }


def test_pkg_variations():
    pkg_list = create_pkg_variations(
        {"vendor": "fasterxml", "name": "jackson-databind", "version": "1.0.0"}
    )
    assert len(pkg_list) > 1
    pkg_list = create_pkg_variations(
        {
            "vendor": "com.fasterxml.jackson.core",
            "name": "jackson-databind",
            "version": "1.0.0",
        }
    )
    assert len(pkg_list) > 1
    pkg_list = create_pkg_variations(
        {"vendor": "commons-io", "name": "commons-io", "version": "1.0.0",}
    )
    assert len(pkg_list) == 1
