from analysis_lib.config import SAFE_ENDPOINT_REACHABLE_PURLS
from analysis_lib.endpoints import is_endpoint_filterable, strip_version


def test_strip_version_drops_only_the_version():
    assert strip_version("pkg:npm/express@4.22.2") == "pkg:npm/express"
    # A scoped npm name keeps its encoded @ and loses only the version.
    assert strip_version("pkg:npm/%40babel/core@7.0.0") == "pkg:npm/%40babel/core"
    # Qualifiers and subpath follow the version, so they go with it.
    assert strip_version("pkg:maven/a/b@1.0?type=jar#sub") == "pkg:maven/a/b"
    assert strip_version("pkg:pypi/rich") == "pkg:pypi/rich"


def test_is_endpoint_filterable_matches_the_safe_prefixes():
    assert "pkg:maven/org.apache.ant/" in SAFE_ENDPOINT_REACHABLE_PURLS
    assert is_endpoint_filterable("pkg:maven/org.apache.ant/ant@1.10.14")
    assert is_endpoint_filterable("pkg:maven/org.apache.maven/maven-core@3.9.0")
    assert not is_endpoint_filterable("pkg:maven/org.springframework/spring-web@6.1.0")
    assert not is_endpoint_filterable("pkg:npm/express@4.22.2")
