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


@pytest.fixture
def py_project(tmp_path):
    """The project tree the truth was taken from: its requirements declare
    click and Flask-SQLAlchemy (yaml maps through the import table)."""
    project = tmp_path / "project"
    project.mkdir()
    (project / "requirements.txt").write_text(
        "click>=8\nFlask_SQLAlchemy==3.1.1  # the ORM\npyyaml\n", encoding="utf-8"
    )
    (project / "requirements-dev.txt").write_text("unused-dep\n", encoding="utf-8")
    return str(project)


def test_python_labels_map_imports_to_distributions(py_project):
    document = derive_labels.derive("py-fixture", TRUTH, BOM, project=py_project)
    reach = document["reachability"]
    used = {entry["purl"]: entry["occurrences"] for entry in reach["used"]}
    # click maps through the declared requirements; yaml through the import
    # table; the folded name of the declared Flask_SQLAlchemy maps the
    # flask_sqlalchemy import.
    assert "pkg:pypi/click" in used
    assert "pkg:pypi/pyyaml" in used
    assert "pkg:pypi/flask-sqlalchemy" in used
    assert used["pkg:pypi/click"] == 2
    # The uncertain row adds nothing.
    assert used["pkg:pypi/click"] != 3


def test_unmapped_import_name_is_reported_with_a_count(py_project):
    document = derive_labels.derive("py-fixture", TRUTH, BOM, project=py_project)
    reach = document["reachability"]
    assert reach["unmapped"] == {"notarealpkg": 2}
    assert reach["counts"]["unmapped"] == 1


def test_builtins_and_uncertain_rows_never_become_labels(py_project):
    document = derive_labels.derive("py-fixture", TRUTH, BOM, project=py_project)
    reach = document["reachability"]
    used = {entry["purl"] for entry in reach["used"]}
    assert "pkg:pypi/pathlib" not in used
    assert "pathlib" not in reach["unmapped"]


def test_direct_dependency_without_use_is_unused(py_project):
    document = derive_labels.derive("py-fixture", TRUTH, BOM, project=py_project)
    reach = document["reachability"]
    unused = [entry["purl"] for entry in reach["unused"]]
    assert unused == ["pkg:pypi/unused-dep"]
    assert reach["counts"]["unused"] == 1


def test_bom_without_dependency_graph_declares_nothing_unused():
    truth = {"usages": [_row("org.example:used", "A.java")]}
    bom = {
        "metadata": {"component": {"bom-ref": "root"}},
        "components": [{"purl": "pkg:maven/org.example/other@1.0", "bom-ref": "c1"}],
        "dependencies": [],
    }
    assert derive_labels.derive("java-fixture", truth, bom)["reachability"]["unused"] == []
    bom["dependencies"] = [{"ref": "root", "dependsOn": ["c1"]}]
    reach = derive_labels.derive("java-fixture", truth, bom)["reachability"]
    assert reach["unused"] == [{"purl": "pkg:maven/org.example/other"}]


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
    # The Node builtin is no package: dropped like a row the typed truth
    # flags as builtin, so it never counts as a recall miss.
    assert reach["unmapped"] == {}


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
        "components": [{"purl": "pkg:maven/org.springframework.boot/spring-boot@3.4.0"}],
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
    schema_path = os.path.join(here, "..", "contrib", "corpus", "depscan-labels.schema.json")
    with open(schema_path, encoding="utf-8") as fp:
        schema = json.load(fp)
    document = derive_labels.derive("py-fixture", TRUTH, BOM)
    jsonschema.validate(document, schema)


def _row(pkg, file_name="app.py"):
    return {"file": file_name, "line": 1, "module": pkg, "pkg": pkg, "certain": True}


def test_npm_use_of_a_package_the_bom_lacks_stays_a_label():
    # The BOM only answers directness: a package cdxgen failed to inventory
    # must still be a used label, so the scorer can count the miss.
    truth = {"usages": [_row("left-pad", "a.js"), _row("lodash", "a.js")]}
    bom = {"components": [{"purl": "pkg:npm/lodash@4.17.21", "bom-ref": "c1"}]}
    reach = derive_labels.derive("js-fixture", truth, bom)["reachability"]
    assert [e["purl"] for e in reach["used"]] == ["pkg:npm/left-pad", "pkg:npm/lodash"]
    assert reach["unmapped"] == {}


def test_python_import_the_project_does_not_declare_is_unmapped_not_used(tmp_path):
    # vulpy imports "lib", which no requirement declares and no directory
    # holds; a BOM component guessed from the import must not make it a label.
    (tmp_path / "requirements.txt").write_text("flask\n", encoding="utf-8")
    truth = {"usages": [_row("lib", "good/mod_welcome1.py"), _row("flask")]}
    bom = {"components": [{"purl": "pkg:pypi/lib@1.0", "bom-ref": "c1"}]}
    reach = derive_labels.derive("py-fixture", truth, bom, project=str(tmp_path))["reachability"]
    assert [e["purl"] for e in reach["used"]] == ["pkg:pypi/flask"]
    assert reach["unmapped"] == {"lib": 1}


def test_project_local_modules_are_counted_apart(tmp_path):
    (tmp_path / "good").mkdir()
    (tmp_path / "good" / "lib").mkdir()
    (tmp_path / "good" / "lib" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "frontend" / "src" / "app").mkdir(parents=True)
    (tmp_path / "frontend" / "tsconfig.json").write_text("{}", encoding="utf-8")
    truth = {"usages": [_row("lib", "good/mod_welcome1.py"), _row("lib", "good/x.py")]}
    reach = derive_labels.derive("py-fixture", truth, {}, project=str(tmp_path))["reachability"]
    assert reach["used"] == []
    assert reach["local"] == {"lib": 2}
    assert reach["counts"]["local"] == 1
    # An npm path alias that is a directory of the tree is local, while a
    # declared package with the same name as a directory stays a package.
    (tmp_path / "config").mkdir()
    (tmp_path / "package.json").write_text('{"dependencies": {"config": "^3"}}', encoding="utf-8")
    truth = {"usages": [_row("src", "frontend/src/app/x.ts"), _row("config", "server.ts")]}
    reach = derive_labels.derive("js-fixture", truth, {}, project=str(tmp_path))["reachability"]
    assert [e["purl"] for e in reach["used"]] == ["pkg:npm/config"]
    assert reach["local"] == {"src": 1}


def test_top_level_names_of_installed_distributions_map_imports(tmp_path):
    dist = tmp_path / "site" / "python_memcached-1.62.dist-info"
    dist.mkdir(parents=True)
    (dist / "top_level.txt").write_text("memcache_impl\n", encoding="utf-8")
    truth = {"usages": [_row("memcache_impl")]}
    reach = derive_labels.derive("py-fixture", truth, {}, site_packages=[str(tmp_path / "site")])[
        "reachability"
    ]
    assert [e["purl"] for e in reach["used"]] == ["pkg:pypi/python-memcached"]


def test_refresh_keeps_hand_findings_and_refuses_hand_reachability(tmp_path, capsys):
    truth_path = tmp_path / "truth.json"
    truth_path.write_text(json.dumps({"usages": [_row("lodash", "a.js")]}), encoding="utf-8")
    bom_path = tmp_path / "bom.json"
    bom_path.write_text("{}", encoding="utf-8")
    out = tmp_path / "labels.json"
    findings = {"source": "hand", "expected": []}
    joins = {"two-producers": {"source": "hand", "package": "pkg:npm/x", "citation": "a:1"}}
    out.write_text(
        json.dumps({"item": "js-fixture", "findings": findings, "joins": joins}),
        encoding="utf-8",
    )
    argv = ["--truth", str(truth_path), "--bom", str(bom_path), "--item", "js-fixture"]
    argv += ["--out", str(out)]
    assert derive_labels.main(argv) == 0
    written = json.loads(out.read_text(encoding="utf-8"))
    assert written["findings"] == findings
    assert written["joins"] == joins
    assert written["reachability"]["source"] == "oracle"
    hand = {"source": "hand", "used": [{"purl": "pkg:npm/express", "citation": "a.js:1"}]}
    out.write_text(json.dumps({"item": "js-fixture", "reachability": hand}), encoding="utf-8")
    assert derive_labels.main(argv) == 2
    assert "--force" in capsys.readouterr().err
    assert json.loads(out.read_text(encoding="utf-8"))["reachability"] == hand
    assert derive_labels.main(argv + ["--force"]) == 0


def test_hand_label_citations_name_a_file_and_line():
    import glob
    import re

    cites = re.compile(r"[\w./@-]+:\d+")
    here = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "contrib", "corpus")
    missing = []
    for path in sorted(glob.glob(os.path.join(here, "labels", "*.json"))):
        with open(path, encoding="utf-8") as fp:
            labels = json.load(fp)
        cited = []
        reach = labels.get("reachability") or {}
        if reach.get("source") == "hand":
            cited += reach.get("used") or []
        findings = labels.get("findings") or {}
        if findings.get("source") == "hand":
            cited += findings.get("expected") or []
        for section in (labels.get("joins") or {}).values():
            if section.get("source") != "hand":
                continue
            entries = section.get("routes") or section.get("packages")
            cited += (
                entries if entries is not None else ([section] if "package" in section else [])
            )
        for entry in cited:
            if not cites.search(entry.get("citation", "")):
                missing.append((os.path.basename(path), entry.get("purl") or entry.get("path")))
    assert missing == []


def test_python_distributions_come_from_requirement_dirs_and_lock_files(tmp_path):
    (tmp_path / "requirements" / "extras").mkdir(parents=True)
    (tmp_path / "requirements" / "extras" / "redis.txt").write_text("redis>=5\n", encoding="utf-8")
    (tmp_path / "uv.lock").write_text(
        'version = 1\n[[package]]\nname = "SQLAlchemy"\nversion = "2.0.0"\n', encoding="utf-8"
    )
    truth = {"usages": [_row("redis"), _row("sqlalchemy"), _row("cPickle"), _row("urlparse")]}
    reach = derive_labels.derive("py-fixture", truth, {}, project=str(tmp_path))["reachability"]
    assert [e["purl"] for e in reach["used"]] == ["pkg:pypi/redis", "pkg:pypi/sqlalchemy"]
    # Python 2 modules name no distribution: dropped, not counted unmapped.
    assert reach["unmapped"] == {}


def test_a_bare_javascript_import_is_not_local_beside_its_importer(tmp_path):
    # outline imports the history package from app/utils/*.ts, beside its
    # own app/utils/history.ts; a bare specifier never resolves there.
    (tmp_path / "app" / "utils").mkdir(parents=True)
    (tmp_path / "app" / "utils" / "history.ts").write_text("", encoding="utf-8")
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    truth = {"usages": [_row("history", "app/utils/routing.ts")]}
    reach = derive_labels.derive("js-fixture", truth, {}, project=str(tmp_path))["reachability"]
    assert [e["purl"] for e in reach["used"]] == ["pkg:npm/history"]
    assert reach["local"] == {}


def test_import_table_maps_names_that_differ_from_their_distribution():
    truth = {
        "usages": [
            _row("watson"),
            _row("split_settings"),
            _row("argon2"),
            _row("_billiard"),
            _row("couchbase_core"),
        ]
    }
    reach = derive_labels.derive("py-fixture", truth, {})["reachability"]
    assert [e["purl"] for e in reach["used"]] == [
        "pkg:pypi/argon2-cffi",
        "pkg:pypi/billiard",
        "pkg:pypi/couchbase",
        "pkg:pypi/django-split-settings",
        "pkg:pypi/django-watson",
    ]


def test_an_imported_but_undeclared_package_is_never_unused(tmp_path):
    # vulpy imports passlib without declaring it; the BOM lists passlib as a
    # direct dependency, and the truth's use must keep it out of unused even
    # though the name stays unmapped.
    truth = {"usages": [_row("passlib")]}
    bom = {
        "metadata": {"component": {"bom-ref": "root"}},
        "components": [{"purl": "pkg:pypi/passlib@1.7.4", "bom-ref": "c1"}],
        "dependencies": [{"ref": "root", "dependsOn": ["c1"]}],
    }
    reach = derive_labels.derive("py-fixture", truth, bom, project=str(tmp_path))["reachability"]
    assert reach["unmapped"] == {"passlib": 1}
    assert reach["unused"] == []


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_python_directness_comes_from_the_manifests_never_the_bom(tmp_path):
    # A BOM made in the wrong environment lists dep-scan's own workspace and
    # the project itself as direct dependencies; none of that is a label.
    _write(tmp_path / "pyproject.toml", '[project]\nname = "MyApp"\ndependencies = ["flask"]\n')
    _write(tmp_path / "requirements-dev.txt", "-e .\nmyapp\npytest\n")
    _write(tmp_path / "myapp" / "__init__.py", "")
    truth = {"usages": [_row("flask"), _row("myapp", "tests/test_app.py")]}
    bom = {
        "metadata": {"component": {"bom-ref": "root"}},
        "components": [
            {"purl": "pkg:pypi/owasp-depscan@7.0.0", "bom-ref": "c1"},
            {"purl": "pkg:pypi/myapp@1.0", "bom-ref": "c2"},
        ],
        "dependencies": [{"ref": "root", "dependsOn": ["c1", "c2"]}],
    }
    reach = derive_labels.derive("py-fixture", truth, bom, project=str(tmp_path))["reachability"]
    assert [e["purl"] for e in reach["used"]] == ["pkg:pypi/flask"]
    assert reach["unused"] == [{"purl": "pkg:pypi/pytest"}]
    assert reach["local"] == {"myapp": 1}


def test_the_projects_own_distribution_is_never_a_label(tmp_path):
    # An import of the project's own distribution that the tree does not
    # hold at an import root (a src layout under another directory name).
    _write(tmp_path / "setup.cfg", "[metadata]\nname = httpie\n")
    truth = {"usages": [_row("httpie")]}
    reach = derive_labels.derive("py-fixture", truth, {}, project=str(tmp_path))["reachability"]
    assert reach["used"] == []
    assert reach["unmapped"] == {}
    assert reach["local"] == {"httpie": 1}


def test_an_undeclared_import_known_to_the_environment_is_a_used_label(tmp_path):
    # six and urllib3 are installed but undeclared; pymongo is imported both
    # as bson (the import table) and as pymongo, and counts once.
    _write(tmp_path / "requirements.txt", "requests\n")
    lock = tmp_path / "env.txt"
    _write(lock, "# via requests\nrequests==2.32.3\nsix==1.16.0\nurllib3==2.2.0 \\\n")
    site = tmp_path / "site"
    (site / "colorama-0.4.6.dist-info").mkdir(parents=True)
    truth = {
        "usages": [
            _row("requests"),
            _row("six"),
            _row("urllib3"),
            _row("colorama"),
            _row("bson"),
            _row("pymongo"),
            _row("pymongo"),
            _row("IPython"),
        ]
    }
    reach = derive_labels.derive(
        "py-fixture",
        truth,
        {},
        project=str(tmp_path / "missing-tree"),
        site_packages=[str(site)],
        lock_files=[str(lock)],
    )["reachability"]
    used = {e["purl"]: e["occurrences"] for e in reach["used"]}
    assert used == {
        "pkg:pypi/colorama": 1,
        "pkg:pypi/pymongo": 3,
        "pkg:pypi/requests": 1,
        "pkg:pypi/six": 1,
        "pkg:pypi/urllib3": 1,
    }
    # A name no declaration, lock or environment knows stays unmapped.
    assert reach["unmapped"] == {"IPython": 1}


def test_a_declared_variant_claims_its_import_name(tmp_path):
    _write(
        tmp_path / "requirements.txt",
        "psycopg2-binary==2.9\nopencv-python-headless\nbeautifulsoup4\n",
    )
    truth = {"usages": [_row("psycopg2"), _row("cv2"), _row("bs4")]}
    reach = derive_labels.derive("py-fixture", truth, {}, project=str(tmp_path))["reachability"]
    assert [e["purl"] for e in reach["used"]] == [
        "pkg:pypi/beautifulsoup4",
        "pkg:pypi/opencv-python-headless",
        "pkg:pypi/psycopg2-binary",
    ]
    assert reach["unused"] == []
    assert reach["unmapped"] == {}


def test_the_uv_lock_root_package_is_the_project_not_a_dependency(tmp_path):
    _write(tmp_path / "app" / "__init__.py", "")
    _write(
        tmp_path / "uv.lock",
        "version = 1\n"
        '[[package]]\nname = "app"\nversion = "0.1.0"\nsource = { editable = "." }\n'
        'dependencies = [{ name = "fastapi" }]\n'
        '[package.optional-dependencies]\nmail = [{ name = "emails" }]\n'
        '[package.dev-dependencies]\ndev = [{ name = "pytest" }]\n'
        '[[package]]\nname = "fastapi"\nversion = "0.115.0"\n'
        'source = { registry = "https://pypi.org/simple" }\n'
        '[[package]]\nname = "starlette"\nversion = "0.40.0"\n'
        'source = { registry = "https://pypi.org/simple" }\n',
    )
    truth = {"usages": [_row("app", "app/main.py"), _row("fastapi", "app/main.py")]}
    reach = derive_labels.derive("py-fixture", truth, {}, project=str(tmp_path))["reachability"]
    assert [e["purl"] for e in reach["used"]] == ["pkg:pypi/fastapi"]
    assert reach["local"] == {"app": 1}
    # The root's dependencies are direct; the locked transitive is not.
    assert reach["unused"] == [{"purl": "pkg:pypi/emails"}, {"purl": "pkg:pypi/pytest"}]


def test_the_project_local_check_runs_before_the_declared_lookup(tmp_path):
    # utils is both a declared distribution and a package of the tree: the
    # tree's package wins. redis.py inside a package does not shadow the
    # redis distribution its own "import redis" names.
    _write(tmp_path / "requirements.txt", "utils\nredis\n")
    _write(tmp_path / "utils" / "__init__.py", "")
    _write(tmp_path / "proj" / "__init__.py", "")
    _write(tmp_path / "proj" / "backends" / "__init__.py", "")
    _write(tmp_path / "proj" / "backends" / "redis.py", "import redis\n")
    _write(tmp_path / "docs" / "redis" / "index.rst", "")
    truth = {"usages": [_row("utils", "proj/app.py"), _row("redis", "proj/backends/redis.py")]}
    reach = derive_labels.derive("py-fixture", truth, {}, project=str(tmp_path))["reachability"]
    assert [e["purl"] for e in reach["used"]] == ["pkg:pypi/redis"]
    assert reach["local"] == {"utils": 1}
    assert reach["unused"] == []


def test_a_reviewed_missing_module_is_neither_a_label_nor_a_miss(tmp_path):
    import jsonschema

    _write(tmp_path / "project" / "requirements.txt", "flask\n")
    truth_path = tmp_path / "truth.json"
    truth_path.write_text(
        json.dumps({"usages": [_row("lib", "good/mod.py"), _row("flask"), _row("passlib")]}),
        encoding="utf-8",
    )
    out = tmp_path / "labels.json"
    argv = ["--truth", str(truth_path), "--item", "py-fixture", "--out", str(out)]
    argv += ["--project", str(tmp_path / "project")]
    reason = "good/mod.py:4 imports lib.posts1, which the tree does not hold"
    assert derive_labels.main(argv + ["--missing-module", f"lib={reason}"]) == 0
    reach = json.loads(out.read_text(encoding="utf-8"))["reachability"]
    assert reach["missingModules"] == {"lib": {"occurrences": 1, "reason": reason}}
    assert reach["counts"]["missingModule"] == 1
    assert reach["unmapped"] == {"passlib": 1}
    # The reviewed reason survives a refresh without the option.
    assert derive_labels.main(argv) == 0
    document = json.loads(out.read_text(encoding="utf-8"))
    assert document["reachability"]["missingModules"]["lib"]["reason"] == reason
    here = os.path.dirname(os.path.abspath(__file__))
    with open(
        os.path.join(here, "..", "contrib", "corpus", "depscan-labels.schema.json"),
        encoding="utf-8",
    ) as fp:
        jsonschema.validate(document, json.load(fp))
    assert derive_labels.main(argv + ["--missing-module", "lib"]) == 2


def test_a_setup_py_name_constant_names_the_projects_own_distribution(tmp_path):
    # celery's setup.py says NAME = 'celery' and setup(name=NAME); an example
    # project in the tree declares celery as its dependency.
    _write(
        tmp_path / "setup.py", "NAME = 'celery'\nsetup(name=NAME, install_requires=['kombu'])\n"
    )
    _write(
        tmp_path / "examples" / "app" / "setup.py",
        "setup(name='example-tasks', install_requires=['celery>=5'])\n",
    )
    truth = {"usages": [_row("kombu")]}
    reach = derive_labels.derive("py-fixture", truth, {}, project=str(tmp_path))["reachability"]
    assert [e["purl"] for e in reach["used"]] == ["pkg:pypi/kombu"]
    assert reach["unused"] == []
