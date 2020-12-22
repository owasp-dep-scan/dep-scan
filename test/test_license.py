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
    assert len(violations_list) == 1


def test_dual_license(test_license_data):
    pkg_lic_dict = bulk_lookup(
        test_license_data,
        [
            {
                "vendor": "npm",
                "name": "jszip",
                "version": "3.2.2",
                "licenses": ["(MIT OR GPL-3.0)"],
            }
        ],
    )
    assert pkg_lic_dict == {
        "npm:jszip@3.2.2": [
            {
                "title": "MIT License",
                "spdx-id": "MIT",
                "featured": True,
                "hidden": False,
                "description": "A short and simple permissive license with conditions only requiring preservation of copyright and license notices. Licensed works, modifications, and larger works may be distributed under different terms and without source code.",
                "how": "Create a text file (typically named LICENSE or LICENSE.txt) in the root of your source code and copy the text of the license into the file. Replace [year] with the current year and [fullname] with the name (or names) of the copyright holders.",
                "using": {
                    "Babel": "https://github.com/babel/babel/blob/master/LICENSE",
                    ".NET Core": "https://github.com/dotnet/runtime/blob/master/LICENSE.TXT",
                    "Rails": "https://github.com/rails/rails/blob/master/MIT-LICENSE",
                },
                "permissions": [
                    "commercial-use",
                    "modifications",
                    "distribution",
                    "private-use",
                ],
                "conditions": ["include-copyright"],
                "limitations": ["liability", "warranty"],
                "condition_flag": False,
            }
        ]
    }
    test_bom = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "bom-node2.xml"
    )
    pkg_list = get_pkg_list(test_bom)
    pkg_lic_dict = bulk_lookup(test_license_data, pkg_list)
    assert pkg_lic_dict
