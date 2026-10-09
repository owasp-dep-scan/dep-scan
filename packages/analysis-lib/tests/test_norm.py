from analysis_lib.normalize import create_pkg_variations


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
    assert len(pkg_list) == 1
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


def test_gem_platform_marker_alias():
    """A gem purl with a platform suffix must yield a platform-stripped alias.

    Regression test: create_pkg_variations used to reference
    config.RUBY_PLATFORM_MARKERS before it existed in analysis_lib.config, so
    every gem purl took the silent AttributeError fallback and the alias was
    never produced.
    """
    pkg_list = create_pkg_variations(
        {
            "purl": "pkg:gem/rails@7.0.0-x86_64-linux",
            "name": "rails",
            "version": "7.0.0-x86_64-linux",
        }
    )
    stripped = [p for p in pkg_list if p.get("version") == "7.0.0"]
    assert stripped, f"expected a platform-stripped alias in {pkg_list}"
    assert stripped[0]["name"] == "rails"
    # The junk vendor alias from the old exception fallback must be gone.
    assert all("@" not in (p.get("vendor") or "") for p in pkg_list)


def test_dealias_packages_with_vendor():
    """dealias_packages must handle dict-shaped package_issue entries.

    Regression test: the vendor branch used attribute access
    (package_issue.affected_location.vendor) on a dict and raised
    AttributeError for any result with a vendor. A non-empty pkg_aliases is
    required so the loop body (where the crash lived) actually runs.
    """
    from analysis_lib.normalize import dealias_packages

    pkg_list = [
        {
            "matched_by": "pkg:pypi/django@4.0",
            "package_issue": {"affected_location": {"vendor": "python", "package": "django"}},
        }
    ]
    dealias_dict = dealias_packages(
        pkg_list,
        pkg_aliases={"django-alias": ["python:django:4.0"]},
        purl_aliases={},
    )
    assert dealias_dict == {"python:django:4.0": "django-alias"}


def test_dedup_with_vendor():
    """dedup must build vendor:package keys from dict-shaped results.

    Regression test: same attribute-access crash as dealias_packages; two
    vendor+package duplicates must collapse to one entry.
    """
    from analysis_lib.normalize import dedup

    def occurrence(vid):
        return {
            "id": vid,
            "package_issue": {"affected_location": {"vendor": "python", "package": "django"}},
        }

    ret_list = dedup("pyproject", [occurrence("CVE-2021-1"), occurrence("CVE-2021-1")])
    assert len(ret_list) == 1
