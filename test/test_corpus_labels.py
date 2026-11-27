"""The label derivation script, tested on a truth fixture written by hand.

The fixture below is not copied from the private oracle output; it is a
cut-down document with the same shape, written for these assertions.
"""

import json
import os

import pytest

from contrib.corpus import derive_labels

TRUTH = {
    "root": "/fixture/project",
    "language": "python",
    "files": ["app.py", "util.py"],
    "skipped": [],
    "usages": [
        {
            "file": "app.py",
            "line": 1,
            "col": 0,
            "module": "click",
            "pkg": "click",
            "builtin": False,
            "member": "",
            "kind": "import",
            "via": "binding",
            "certain": True,
        },
        {
            "file": "app.py",
            "line": 7,
            "col": 1,
            "module": "click",
            "pkg": "click",
            "builtin": False,
            "member": "command",
            "kind": "decorator",
            "via": "binding",
            "certain": True,
        },
        {
            "file": "util.py",
            "line": 3,
            "col": 4,
            "module": "yaml",
            "pkg": "yaml",
            "builtin": False,
            "member": "safe_load",
            "kind": "call",
            "via": "binding",
            "certain": True,
        },
        {
            "file": "util.py",
            "line": 9,
            "col": 0,
            "module": "notarealpkg",
            "pkg": "notarealpkg",
            "builtin": False,
            "member": "",
            "kind": "import",
            "via": "binding",
            "certain": True,
        },
        {
            "file": "app.py",
            "line": 12,
            "col": 0,
            "module": "flask_sqlalchemy",
            "pkg": "flask_sqlalchemy",
            "builtin": False,
            "member": "",
            "kind": "import",
            "via": "binding",
            "certain": True,
        },
        {
            "file": "util.py",
            "line": 10,
            "col": 4,
            "module": "notarealpkg",
            "pkg": "notarealpkg",
            "builtin": False,
            "member": "thing",
            "kind": "call",
            "via": "binding",
            "certain": True,
        },
        {
            "file": "app.py",
            "line": 2,
            "col": 0,
            "module": "pathlib",
            "pkg": "pathlib",
            "builtin": True,
            "member": "Path",
            "kind": "import",
            "via": "binding",
            "certain": True,
        },
        {
            "file": "app.py",
            "line": 5,
            "col": 10,
            "module": "click",
            "pkg": "click",
            "builtin": False,
            "member": "",
            "kind": "call",
            "via": "binding",
            "certain": False,
        },
    ],
}

BOM = {
    "components": [
        {"purl": "pkg:pypi/click@8.5.1", "bom-ref": "c1"},
        {"purl": "pkg:pypi/pyyaml@6.0.4", "bom-ref": "c2"},
        {"purl": "pkg:pypi/Flask_SQLAlchemy@3.1.1", "bom-ref": "c3"},
        {"purl": "pkg:pypi/unused-dep@1.0.0", "bom-ref": "c4"},
    ],
    "metadata": {"component": {"bom-ref": "root", "type": "application"}},
    "dependencies": [
        {"ref": "root", "dependsOn": ["c1", "c2", "c3", "c4"]},
        {"ref": "c1", "dependsOn": []},
    ],
}


def test_python_labels_map_imports_to_distributions():
    document = derive_labels.derive("py-fixture", TRUTH, BOM)
    reach = document["reachability"]
    used = {entry["purl"]: entry["occurrences"] for entry in reach["used"]}
    # click maps by name; yaml maps through the import table; the folded
    # distribution name of the BOM component maps the sqlalchemy import.
    assert "pkg:pypi/click" in used
    assert "pkg:pypi/pyyaml" in used
    assert "pkg:pypi/flask-sqlalchemy" in used
    assert used["pkg:pypi/click"] == 2
    # The uncertain row adds nothing.
    assert used["pkg:pypi/click"] != 3


def test_unmapped_import_name_is_reported_with_a_count():
    document = derive_labels.derive("py-fixture", TRUTH, BOM)
    reach = document["reachability"]
    assert reach["unmapped"] == {"notarealpkg": 2}
    assert reach["counts"]["unmapped"] == 1


def test_builtins_and_uncertain_rows_never_become_labels():
    document = derive_labels.derive("py-fixture", TRUTH, BOM)
    reach = document["reachability"]
    used = {entry["purl"] for entry in reach["used"]}
    assert "pkg:pypi/pathlib" not in used
    assert "pathlib" not in reach["unmapped"]


def test_direct_dependency_without_use_is_unused():
    document = derive_labels.derive("py-fixture", TRUTH, BOM)
    reach = document["reachability"]
    unused = [entry["purl"] for entry in reach["unused"]]
    assert unused == ["pkg:pypi/unused-dep"]
    assert reach["counts"]["unused"] == 1


def test_bom_without_dependency_graph_declares_nothing_unused():
    bom = {**BOM, "dependencies": []}
    document = derive_labels.derive("py-fixture", TRUTH, bom)
    assert document["reachability"]["unused"] == []


def test_npm_scoped_names_map_to_the_bom_spelling():
    truth = {
        "files": ["a.js"],
        "usages": [
            {
                "file": "a.js",
                "line": 1,
                "col": 0,
                "module": "@babel/core",
                "pkg": "@babel/core",
                "kind": "import",
                "certain": True,
            },
            {
                "file": "a.js",
                "line": 2,
                "col": 0,
                "module": "fs",
                "pkg": "fs",
                "kind": "import",
                "certain": True,
            },
        ],
    }
    bom = {
        "components": [{"purl": "pkg:npm/%40babel/core@7.0.0", "bom-ref": "c1"}],
        "metadata": {"component": {"bom-ref": "root"}},
        "dependencies": [{"ref": "root", "dependsOn": ["c1"]}],
    }
    document = derive_labels.derive("js-fixture", truth, bom)
    reach = document["reachability"]
    used = {entry["purl"] for entry in reach["used"]}
    assert "pkg:npm/%40babel/core" in used
    # The Node builtin is reported, never silently dropped.
    assert reach["unmapped"] == {"fs": 1}


def test_java_group_artifact_maps_to_maven_purl():
    truth = {
        "language": "java",
        "files": ["A.java"],
        "usages": [
            {
                "file": "A.java",
                "line": 1,
                "col": 7,
                "module": "org.springframework.boot.SpringApplication",
                "pkg": "org.springframework.boot:spring-boot",
                "builtin": False,
                "kind": "call",
                "certain": True,
            }
        ],
    }
    bom = {
        "components": [
            {"purl": "pkg:maven/org.springframework.boot/spring-boot@3.4.0"}
        ],
        "metadata": {"component": {"bom-ref": "root"}},
        "dependencies": [],
    }
    document = derive_labels.derive("java-fixture", truth, bom)
    reach = document["reachability"]
    assert [entry["purl"] for entry in reach["used"]] == [
        "pkg:maven/org.springframework.boot/spring-boot"
    ]


def test_unknown_language_is_refused():
    with pytest.raises(ValueError):
        derive_labels.derive("c-fixture", TRUTH, BOM)


def test_derived_document_validates_against_the_labels_schema():
    import jsonschema

    here = os.path.dirname(os.path.abspath(__file__))
    schema_path = os.path.join(
        here, "..", "contrib", "corpus", "depscan-labels.schema.json"
    )
    with open(schema_path, encoding="utf-8") as fp:
        schema = json.load(fp)
    document = derive_labels.derive("py-fixture", TRUTH, BOM)
    jsonschema.validate(document, schema)
