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
        {"vendor": "commons-io", "name": "commons-io", "version": "1.0.0"}
    )
    assert len(pkg_list) > 1
    pkg_list = create_pkg_variations(
        {"vendor": "org.eclipse.foo", "name": "bar", "version": "1.0.0"}
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
    pkg_list = create_pkg_variations(
        {
            "vendor": "io.undertow",
            "name": "undertow-core",
            "version": "2.0.27.Final",
        }
    )
    assert len(pkg_list) > 1
    pkg_list = create_pkg_variations(
        {
            "vendor": "io.undertow",
            "name": "undertow-core",
            "version": "2.0.27.Final",
        }
    )
    assert len(pkg_list) > 1
    pkg_list = create_pkg_variations(
        {
            "vendor": "org.apache.logging.log4j",
            "name": "log4j-api",
            "version": "2.12.1",
        }
    )
    assert len(pkg_list) > 1
    pkg_list = create_pkg_variations(
        {
            "vendor": "org.springframework.batch",
            "name": "spring-batch",
            "version": "2.0.27.Final",
        }
    )
    assert len(pkg_list) > 1
    pkg_list = create_pkg_variations(
        {
            "vendor": "commons-fileupload",
            "name": "commons-fileupload",
            "version": "1.3.2",
        }
    )
    assert len(pkg_list) > 1
    pkg_list = create_pkg_variations(
        {
            "vendor": "github.com/go-sql-driver",
            "name": "mysql",
            "version": "v1.4.1",
        }
    )
    assert len(pkg_list) > 1
    pkg_list = create_pkg_variations(
        {
            "vendor": "golang.org/x/crypto",
            "name": "ssh",
            "version": "0.0.0-20200220183623-bac4c82f6975",
        }
    )
    assert pkg_list
    pkg_list = create_pkg_variations(
        {
            "vendor": "github.com/mitchellh",
            "name": "cli",
            "version": "6.14.1",
        }
    )
    assert pkg_list
    pkg_list = create_pkg_variations(
        {
            "vendor": "github.com/jacobsa",
            "name": "crypto",
            "version": "6.14.1",
        }
    )
    assert pkg_list
    pkg_list = create_pkg_variations(
        {
            "vendor": "org.hibernate",
            "name": "hibernate-core",
            "version": "5.4.18.Final",
        }
    )
    assert pkg_list
    pkg_list = create_pkg_variations(
        {
            "vendor": "org.springframework.security",
            "name": "spring-security-crypto",
            "version": "5.3.3.RELEASE",
        }
    )
    assert pkg_list
    pkg_list = create_pkg_variations(
        {
            "vendor": "deb",
            "name": "gnome-accessibility-themes",
            "version": "3.28-1ubuntu3",
        }
    )
    assert pkg_list
