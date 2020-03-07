import os
import tempfile

import pytest
import vdb.lib.db as dbLib

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
        assert pkg["name"]
        assert pkg["version"]
    test_py_bom = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "bom-py.xml"
    )
    pkg_list = get_pkg_list(test_py_bom)
    assert len(pkg_list) == 31
    for pkg in pkg_list:
        assert pkg["vendor"] == "pypi"
        assert pkg["name"]
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


def test_search(test_db):
    test_bom = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "bom.xml"
    )
    pkg_list = get_pkg_list(test_bom)
    search_res = search_pkgs(test_db, pkg_list)
    assert not len(search_res)
