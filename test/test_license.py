import os

import pytest

from depscan.lib.bom import get_pkg_list
from depscan.lib.license import build_license_data, bulk_lookup


@pytest.fixture
def test_license_data():
    licenses_dir = os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        "..",
        "vendor",
        "choosealicense.com",
        "_licenses",
    )
    return build_license_data(licenses_dir)


def test_lookup(test_license_data):
    test_bom = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "bom.xml"
    )
    pkg_list = get_pkg_list(test_bom)
    pkg_lic_dict = bulk_lookup(test_license_data, pkg_list)
    assert pkg_lic_dict

    test_bom = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "bom-dotnet.xml"
    )
    pkg_list = get_pkg_list(test_bom)
    pkg_lic_dict = bulk_lookup(test_license_data, pkg_list)
    assert pkg_lic_dict
    violations_list = []
    for pkg, ll in pkg_lic_dict.items():
        for lic in ll:
            if lic["condition_flag"]:
                violations_list.append(lic)
    assert len(violations_list) == 2
