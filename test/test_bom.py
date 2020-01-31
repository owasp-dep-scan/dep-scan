import os


from depscan.lib.bom import get_pkg_list, parse_bom_ref
from depscan.lib.utils import search_pkgs
import vulndb.lib.db as dbLib


def test_get_pkg():
    test_bom = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "bom.xml"
    )
    pkg_list = get_pkg_list(test_bom)
    assert len(pkg_list) == 157
    for pkg in pkg_list:
        assert pkg["group"]
        assert pkg["name"]
        assert pkg["version"]
    test_py_bom = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "bom-py.xml"
    )
    pkg_list = get_pkg_list(test_py_bom)
    assert len(pkg_list) == 31
    for pkg in pkg_list:
        assert not pkg["group"]
        assert pkg["name"]
        assert pkg["version"]


def test_parse():
    assert parse_bom_ref("pkg:maven/org.projectlombok/lombok@1.18.4?type=jar") == {
        "group": "org.projectlombok",
        "name": "lombok",
        "version": "1.18.4",
    }

    assert parse_bom_ref("pkg:maven/org.projectlombok/lombok@1.18.4") == {
        "group": "org.projectlombok",
        "name": "lombok",
        "version": "1.18.4",
    }

    assert parse_bom_ref("pkg:pypi/atomicwrites@1.3.0") == {
        "group": "",
        "name": "atomicwrites",
        "version": "1.3.0",
    }


def test_search():
    test_bom = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "bom.xml"
    )
    pkg_list = get_pkg_list(test_bom)
    db = dbLib.get()
    search_res = search_pkgs(db, pkg_list)
    assert len(search_res)
