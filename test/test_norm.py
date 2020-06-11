from depscan.lib.normalize import normalize_pkg


def test_pkg_norm():
    assert normalize_pkg({"vendor": "foo", "name": "bar"}) == {
        "vendor": "foo",
        "name": "bar",
    }

    assert normalize_pkg({"vendor": "org.apache.struts", "name": "struts2-core"}) == {
        "vendor": "apache",
        "name": "struts",
    }
