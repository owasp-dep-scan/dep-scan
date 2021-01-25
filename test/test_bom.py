import os
import tempfile

import pytest
from vdb.lib import db as dbLib

from depscan.lib.bom import get_pkg_list, parse_bom_ref
from depscan.lib.utils import search_pkgs


@pytest.fixture
def test_db():
    with tempfile.NamedTemporaryFile(delete=False) as fp:
        with tempfile.NamedTemporaryFile(delete=False) as indexfp:
            return dbLib.get(db_file=fp.name, index_file=indexfp.name)


def test_get_pkg():
    test_bom = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "bom.xml"
    )
    pkg_list = get_pkg_list(test_bom)
    assert len(pkg_list) == 157
    for pkg in pkg_list:
        assert pkg["vendor"] != "maven"
        assert " " not in pkg["name"]
        assert pkg["version"]
    test_py_bom = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "bom-py.xml"
    )
    pkg_list = get_pkg_list(test_py_bom)
    assert len(pkg_list) == 31
    for pkg in pkg_list:
        assert pkg["vendor"] == "pypi"
        assert " " not in pkg["name"]
        assert pkg["version"]
    test_dn_bom = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "bom-dotnet.xml"
    )
    pkg_list = get_pkg_list(test_dn_bom)
    assert len(pkg_list) == 38
    for pkg in pkg_list:
        assert pkg["vendor"]
        assert " " not in pkg["name"]
        assert pkg["version"]

    test_dn_bom = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "bom-dotnet2.xml"
    )
    pkg_list = get_pkg_list(test_dn_bom)
    assert len(pkg_list) == 6
    for pkg in pkg_list:
        assert pkg["vendor"]
        assert " " not in pkg["name"]
        assert pkg["version"]


def test_parse():
    assert parse_bom_ref("pkg:maven/org.projectlombok/lombok@1.18.4?type=jar") == {
        "vendor": "org.projectlombok",
        "name": "lombok",
        "version": "1.18.4",
        "licenses": None,
    }

    assert parse_bom_ref("pkg:maven/org.projectlombok/lombok@1.18.4") == {
        "vendor": "org.projectlombok",
        "name": "lombok",
        "version": "1.18.4",
        "licenses": None,
    }

    assert parse_bom_ref("pkg:pypi/atomicwrites@1.3.0") == {
        "vendor": "pypi",
        "name": "atomicwrites",
        "version": "1.3.0",
        "licenses": None,
    }

    assert parse_bom_ref("pkg:npm/body-parser@1.18.3") == {
        "vendor": "npm",
        "name": "body-parser",
        "version": "1.18.3",
        "licenses": None,
    }

    assert parse_bom_ref("pkg:npm/@appthreat/cdxgen@1.10.0") == {
        "vendor": "@appthreat",
        "name": "cdxgen",
        "version": "1.10.0",
        "licenses": None,
    }
    assert parse_bom_ref("pkg:golang/cloud.google.com/go@v0.34.0") == {
        "vendor": "cloud.google.com",
        "name": "go",
        "version": "0.34.0",
        "licenses": None,
    }
    assert parse_bom_ref("pkg:golang/cloud.google.com/go/bigquery@v1.0.1") == {
        "vendor": "go",
        "name": "bigquery",
        "version": "1.0.1",
        "licenses": None,
    }
    assert parse_bom_ref(
        "pkg:golang/github.com%2FAzure%2Fazure-amqp-common-go/v2@v2.1.0"
    ) == {
        "vendor": "azure-amqp-common-go",
        "name": "v2",
        "version": "2.1.0",
        "licenses": None,
    }
    assert parse_bom_ref(
        "pkg:golang/github.com%2FAzure/go-autorest@v13.0.0%2Bincompatible"
    ) == {
        "vendor": "Azure",
        "name": "go-autorest",
        "version": "13.0.0+incompatible",
        "licenses": None,
    }
    assert parse_bom_ref(
        "pkg:golang/github.com%2Fdocker/docker@v0.7.3-0.20190327010347-be7ac8be2ae0"
    ) == {
        "vendor": "docker",
        "name": "docker",
        "version": "0.7.3-0.20190327010347-be7ac8be2ae0",
        "licenses": None,
    }


def test_search(test_db):
    test_bom = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "bom.xml"
    )
    pkg_list = get_pkg_list(test_bom)
    search_res, pkg_aliases = search_pkgs(test_db, "java", pkg_list)
    assert not len(search_res)


def test_go_search(test_db):
    test_bom = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "bom-go.xml"
    )
    pkg_list = get_pkg_list(test_bom)
    search_res, pkg_aliases = search_pkgs(test_db, "golang", pkg_list)
    assert not len(search_res)


def test_search_webgoat(test_db):
    test_bom = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "bom-webgoat.xml"
    )
    pkg_list = get_pkg_list(test_bom)
    search_res, pkg_aliases = search_pkgs(test_db, "java", pkg_list)
    assert not len(search_res)


def test_search_webgoat_json(test_db):
    test_bom = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "bom.json"
    )
    pkg_list = get_pkg_list(test_bom)
    assert len(pkg_list) == 157
    search_res, pkg_aliases = search_pkgs(test_db, "java", pkg_list)
    assert not len(search_res)
