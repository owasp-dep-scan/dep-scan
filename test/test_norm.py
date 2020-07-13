from depscan.lib.normalize import create_pkg_variations


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
    pkg_list = create_pkg_variations(
        {"vendor": "org.eclipse.foo", "name": "bar", "version": "1.0.0",}
    )
    assert len(pkg_list) > 1
    pkg_list = create_pkg_variations(
        {
            "vendor": "com.fasterxml.jackson.core",
            "name": "jackson-annotations",
            "version": "1.0.0",
        }
    )
    assert len(pkg_list) > 1
