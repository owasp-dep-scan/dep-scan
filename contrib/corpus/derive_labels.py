#!/usr/bin/env python3
"""Derive package-level reachability labels from the callsites ground truth.

The oracle output of the callsites work names a file, a line and a package for
every certain use of a dependency in a project's own code. This script reduces
one project's oracle output to package level: a package is ``used`` when the
truth holds at least one certain use of it, and ``unused`` when the project
declares it as a direct dependency and the truth holds no use of it at all.
The rows themselves (files, lines, members) never leave the private harness;
the label file carries purls, occurrence counts and the names the mapping
could not turn into a purl, each with its count.

Usage:
    python contrib/corpus/derive_labels.py \
        --truth truth/py-vulpy.json --project ~/corpus/py-vulpy \
        --lock env/py-vulpy.txt --item py-vulpy \
        --out contrib/corpus/labels/py-vulpy.json

A truth package name becomes a purl without consulting the scan's output, so
a package dep-scan fails to inventory still shows up as a recall miss:

- npm, Maven, Composer and gem purls follow from the name (Maven's
  ``group:artifact``, Composer's ``vendor/name``). An npm name the project's
  package.json files do not declare, and which is a directory or module at
  a base a path alias resolves from (a parent directory of the importing
  file holding a package.json, tsconfig.json or jsconfig.json, such as
  Juice Shop's ``src``), is project-local. Node builtins are dropped.
- A Python import name that is a package or module of the project tree is
  project-local, whatever distribution shares its name. Any other name maps
  through the import names of the distributions the project declares
  (``DISTRIBUTION_IMPORTS`` holds the variants, such as psycopg2-binary for
  ``psycopg2``), then ``IMPORT_DISTRIBUTIONS``, then the ``top_level.txt``
  of the distributions installed under ``--site-packages``, then a
  distribution of the same folded name that the project declares, that its
  lock files (uv.lock, poetry.lock, pdm.lock, Pipfile.lock) install, or
  that its environment holds (``--lock`` files written outside the tree and
  ``--site-packages``). The project's own distribution is never a label,
  and an import named like a distribution another import already maps to
  joins that label. Python 2 modules and interpreter internals the truth
  does not flag as builtin are dropped.

Project-local names are listed under ``local`` with their counts and are not
labels. A reviewed name given with ``--missing-module`` (a module the project
imports that neither its tree nor any distribution holds) is listed under
``missingModules`` with its reason and is no label and no miss. Names still
unmapped are listed under ``unmapped`` with their counts; the scorer counts
each one as a used package no analyser can match, a recall miss reported
apart as ``unmappedUsed``.

Directness, for the ``unused`` labels, comes from the project's own files
for Python (its requirements files, pyproject.toml, setup.cfg, setup.py,
Pipfile and uv.lock's root package) and JavaScript (package.json), never
from a scan; for the other languages the BOM (``--bom``) answers it.

Exits 2 when the inputs cannot be read, the item's language is not covered,
or the label file's reachability section was written by hand (refreshing it
would drop the hand labels; ``--force`` overrides).
"""

from __future__ import annotations

import argparse
import configparser
import json
import os
import re
import sys
import tomllib

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from contrib.corpus.score import label_key, load_json  # noqa: E402
from vdb.lib.utils import parse_purl  # noqa: E402

#: Language of a corpus item, from the item id's prefix.
LANGUAGES = {
    "js-": "npm",
    "py-": "pypi",
    "java-": "maven",
    "php-": "composer",
    "rb-": "gem",
}

#: Python import names that are not their distribution's name, lower-cased
#: import name to the distribution name on the index.
IMPORT_DISTRIBUTIONS = {
    "_billiard": "billiard",
    "argon2": "argon2-cffi",
    "bs4": "beautifulsoup4",
    "bson": "pymongo",
    "crispy_forms": "django-crispy-forms",
    "crum": "django-crum",
    "couchbase_core": "couchbase",
    "cv2": "opencv-python",
    "dateutil": "python-dateutil",
    "debug_toolbar": "django-debug-toolbar",
    "django_filters": "django-filter",
    "dotenv": "python-dotenv",
    "easy_thumbnails": "easy-thumbnails",
    "environ": "django-environ",
    "extra_views": "django-extra-views",
    "fieldsignals": "django-fieldsignals",
    "git": "gitpython",
    "haystack": "django-haystack",
    "imagekit": "django-imagekit",
    "jwt": "pyjwt",
    "memcache": "python-memcached",
    "multiselectfield": "django-multiselectfield",
    "mysqldb": "mysqlclient",
    "openssl": "pyopenssl",
    "packageurl": "packageurl-python",
    "pghistory": "django-pghistory",
    "pgtrigger": "django-pgtrigger",
    "phonenumber_field": "django-phonenumber-field",
    "pil": "pillow",
    "polymorphic": "django-polymorphic",
    "rest_framework": "djangorestframework",
    "sklearn": "scikit-learn",
    "sorl": "sorl-thumbnail",
    "split_settings": "django-split-settings",
    "tagulous": "django-tagulous",
    "treebeard": "django-treebeard",
    "vcr_unittest": "vcrpy-unittest",
    "watson": "django-watson",
    "yaml": "pyyaml",
}

#: Import names of distributions that ship under another distribution's
#: import name: a binary build or a variant of one project. A declared
#: variant claims the import before the import table's choice, so a project
#: that declares psycopg2-binary has its ``psycopg2`` imports labelled as
#: psycopg2-binary, never as an unused psycopg2-binary beside a missed
#: psycopg2.
DISTRIBUTION_IMPORTS = {
    "opencv-contrib-python": ("cv2",),
    "opencv-contrib-python-headless": ("cv2",),
    "opencv-python-headless": ("cv2",),
    "pillow-simd": ("pil",),
    "psycopg-binary": ("psycopg",),
    "psycopg2-binary": ("psycopg2",),
    "pycryptodome": ("crypto",),
    "pycryptodomex": ("cryptodome",),
    "python-jose": ("jose",),
    "python-magic": ("magic",),
    "python-magic-bin": ("magic",),
    "tensorflow-cpu": ("tensorflow",),
}

#: Node's own modules. The untyped JavaScript truth records a package per use
#: and does not flag the builtins, so they are dropped here like the rows the
#: typed truth flags as builtin.
NODE_BUILTINS = frozenset(
    """
    assert async_hooks buffer child_process cluster console constants crypto
    dgram diagnostics_channel dns domain events fs http http2 https inspector
    module net os path perf_hooks process punycode querystring readline repl
    stream string_decoder sys timers tls trace_events tty url util v8 vm wasi
    worker_threads zlib
    """.split()
)

#: A valid npm package name, scoped or not.
NPM_NAME = re.compile(r"^(@[a-z0-9-~][a-z0-9-._~]*/)?[a-z0-9-~][a-z0-9-._~]*$")

#: A gem name.
GEM_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

#: The start of a requirement line: the distribution name.
REQUIREMENT_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")

#: The project files whose declared or locked distributions name the
#: Python packages a project installs, beside its requirements files.
PYTHON_MANIFESTS = frozenset(
    ("pyproject.toml", "setup.cfg", "setup.py", "Pipfile", "Pipfile.lock")
    + ("uv.lock", "poetry.lock", "pdm.lock")
)

#: Python 2 standard modules and interpreter internals that the Python truth
#: does not flag as builtin. Like a builtin row they name no distribution,
#: so they are dropped rather than counted as unmapped.
PYTHON_NOT_DISTRIBUTIONS = frozenset(
    """
    ConfigParser HTMLParser Queue StringIO __builtin__ __pypy__ _dummy_thread
    cPickle cStringIO cookielib dummy_thread httplib thread urllib2 urlparse
    """.split()
)

#: The files that make a directory the base an import alias resolves from:
#: a bare JavaScript import such as ``src/app`` names a directory there.
JS_PROJECT_BASES = ("package.json", "tsconfig.json", "jsconfig.json")

#: Directories the declared-dependency and project-local lookups skip.
SKIPPED_DIRS = frozenset({".git", "node_modules", ".venv", "venv", "site-packages", "__pycache__"})

SOURCE_SUFFIXES = (".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".vue", ".svelte")


def language_of(item_id: str) -> str:
    """The ecosystem of a corpus item id, or an empty string."""
    return next((eco for prefix, eco in LANGUAGES.items() if item_id.startswith(prefix)), "")


def certain_packages(truth: dict) -> dict:
    """Every package with a certain use, as {name: (count, files)}.

    A row counts when the oracle marked it certain (rows without the flag are
    certain: the JavaScript oracle records no flag), names a package, and is
    not a use of a language builtin. The files stay in memory for the
    project-local check and never reach the label file.
    """
    packages: dict = {}
    for row in truth.get("usages") or []:
        if not isinstance(row, dict) or row.get("certain") is False or row.get("builtin"):
            continue
        package = row.get("pkg")
        if isinstance(package, str) and package:
            count, files = packages.get(package, (0, set()))
            packages[package] = (count + 1, files | {str(row.get("file") or "")})
    return packages


def fold_name(name: str) -> str:
    """The PEP 503 form of a Python distribution name."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _walk(project: str, wanted):
    """The files under a project whose path ``wanted`` accepts, skipping
    SKIPPED_DIRS and hidden directories."""
    for base, dirs, files in os.walk(project):
        dirs[:] = [d for d in dirs if d not in SKIPPED_DIRS and not d.startswith(".")]
        for name in files:
            if wanted(os.path.join(base, name)):
                yield os.path.join(base, name)


def _requirement_lines(text: str):
    """The distribution specs of a requirements-format file: one per line,
    comments, options, includes and URL or VCS lines skipped, an
    ``#egg=`` name kept."""
    for line in text.splitlines():
        line = line.split("#egg=", 1)[1] if "#egg=" in line else line.split("#", 1)[0]
        if line.strip() and not line.lstrip().startswith(("-", "git+", "http")):
            yield line


def python_manifests(project: str):
    """What a Python project's own files say, as three sets of folded
    distribution names: ``direct``, the dependencies its requirements files,
    pyproject.toml, setup.cfg, setup.py, Pipfile and uv.lock's root package
    declare; ``locked``, every other distribution a lock file (uv.lock,
    poetry.lock, pdm.lock, Pipfile.lock) installs; and ``own``, the
    project's own distributions (a pyproject.toml, setup.cfg or setup.py
    name, and a uv.lock package whose source is the tree itself), which are
    never dependencies."""
    direct: set = set()
    locked: set = set()
    own: set = set()

    def name_of(spec):
        match = REQUIREMENT_NAME.match(str(spec))
        if match and match.group(1).lower() != "python":
            return fold_name(match.group(1))
        return None

    def add(target, spec):
        name = name_of(spec)
        if name:
            target.add(name)

    def is_requirements(path):
        name = os.path.basename(path)
        in_requirements_dir = "requirements" in os.path.relpath(path, project).split(os.sep)[:-1]
        return (
            name.endswith((".txt", ".in"))
            and "constraint" not in name
            and (name.startswith("requirements") or in_requirements_dir)
        )

    def is_manifest(path):
        return is_requirements(path) or os.path.basename(path) in PYTHON_MANIFESTS

    for path in _walk(project, is_manifest) if project else ():
        name = os.path.basename(path)
        try:
            with open(path, encoding="utf-8", errors="replace") as fp:
                text = fp.read()
        except OSError:
            continue
        if is_requirements(path):
            for line in _requirement_lines(text):
                add(direct, line)
        elif name == "Pipfile.lock":
            try:
                doc = json.loads(text)
            except ValueError:
                continue
            for section in ("default", "develop"):
                for spec in doc.get(section) or {}:
                    add(locked, spec)
        elif name in ("pyproject.toml", "Pipfile", "uv.lock", "poetry.lock", "pdm.lock"):
            try:
                doc = tomllib.loads(text)
            except tomllib.TOMLDecodeError:
                continue
            for package in doc.get("package") or []:
                if not isinstance(package, dict) or not package.get("name"):
                    continue
                source = package.get("source") if isinstance(package.get("source"), dict) else {}
                if name != "uv.lock" or not set(source) & {"editable", "virtual", "directory"}:
                    add(locked, package["name"])
                    continue
                # uv.lock lists the project itself, with its source in the
                # tree; its dependencies are the project's direct ones.
                add(own, package["name"])
                specs = list(package.get("dependencies") or [])
                for key in ("optional-dependencies", "dev-dependencies"):
                    for group in (package.get(key) or {}).values():
                        specs += list(group or [])
                for spec in specs:
                    add(direct, spec.get("name") if isinstance(spec, dict) else spec)
            project_table = doc.get("project") or {}
            poetry = (doc.get("tool") or {}).get("poetry") or {}
            for table in (project_table, poetry):
                if table.get("name"):
                    add(own, table["name"])
            specs = list(project_table.get("dependencies") or [])
            for group in (project_table.get("optional-dependencies") or {}).values():
                specs += list(group or [])
            for group in (doc.get("dependency-groups") or {}).values():
                specs += [s for s in group or [] if isinstance(s, str)]
            tables = [poetry.get("dependencies"), poetry.get("dev-dependencies")]
            tables += [g.get("dependencies") for g in (poetry.get("group") or {}).values()]
            tables += [doc.get("packages"), doc.get("dev-packages")]
            for table in tables:
                specs += list((table or {}).keys())
            for spec in specs:
                add(direct, spec)
        elif name == "setup.cfg":
            parser = configparser.ConfigParser(interpolation=None)
            try:
                parser.read_string(text)
            except configparser.Error:
                continue
            add(own, parser.get("metadata", "name", fallback=""))
            values = [parser.get("options", "install_requires", fallback="")]
            if parser.has_section("options.extras_require"):
                values += [value for _, value in parser.items("options.extras_require")]
            for value in values:
                for line in value.splitlines():
                    add(direct, line)
        else:
            match = re.search(r"\bname\s*=\s*['\"]([A-Za-z0-9._-]+)['\"]", text)
            if match:
                add(own, match.group(1))
            for block in re.findall(r"(?:install|tests)_requires\s*=\s*\[(.*?)\]", text, re.S):
                for spec in re.findall(r"['\"]([^'\"]+)['\"]", block):
                    add(direct, spec)
    return direct - own, locked - own - direct, own


def python_declared(project: str) -> set:
    """The folded distribution names a Python project's own manifests
    declare as direct dependencies; :func:`python_manifests` lists the
    files."""
    return python_manifests(project)[0]


def environment_distributions(lock_files, site_packages) -> set:
    """The folded names of the distributions a project's environment holds:
    every ``name==version`` line of the given requirements-format lock
    files (``uv pip compile`` output, say), and every distribution installed
    under the given site-packages directories."""
    names = set()
    for path in lock_files or []:
        try:
            with open(path, encoding="utf-8", errors="replace") as fp:
                text = fp.read()
        except OSError:
            continue
        for line in _requirement_lines(text):
            match = REQUIREMENT_NAME.match(line)
            if match:
                names.add(fold_name(match.group(1)))
    for directory in site_packages or []:
        try:
            entries = os.listdir(directory)
        except OSError:
            continue
        names |= {
            fold_name(entry.rsplit(".", 1)[0].split("-", 1)[0])
            for entry in entries
            if entry.endswith((".dist-info", ".egg-info"))
        }
    return names


def top_level_names(site_packages: list) -> dict:
    """Import name to folded distribution name, from the ``top_level.txt``
    of every distribution installed under the given directories."""
    names: dict = {}
    for directory in site_packages or []:
        try:
            entries = sorted(os.listdir(directory))
        except OSError:
            continue
        for entry in entries:
            if not entry.endswith((".dist-info", ".egg-info")):
                continue
            distribution = fold_name(entry.rsplit(".", 1)[0].split("-", 1)[0])
            try:
                with open(os.path.join(directory, entry, "top_level.txt"), encoding="utf-8") as fp:
                    for line in fp:
                        if line.strip():
                            names.setdefault(line.strip().lower(), distribution)
            except OSError:
                continue
    return names


def _python_roots(project: str, files) -> set:
    """The directories a Python import of the project resolves against: the
    project root, ``src``, and for each importing file the first directory
    above it that is not a package (no ``__init__.py``), which is the
    directory a script runs from or the root its package is imported from.
    A module beside its importer inside a package is not on that path, so
    ``import redis`` in ``celery/backends/redis.py`` names the distribution,
    not the module itself."""
    roots = {project, os.path.join(project, "src")}
    for file_name in files:
        directory = os.path.dirname(os.path.join(project, file_name))
        while directory.startswith(project) and os.path.isfile(
            os.path.join(directory, "__init__.py")
        ):
            directory = os.path.dirname(directory)
        if directory.startswith(project):
            roots.add(directory)
    return roots


def _is_python_package(path: str) -> bool:
    """Whether a directory is a Python package: it holds ``__init__.py`` or,
    as a namespace package, at least one module."""
    try:
        return any(name.endswith((".py", ".pyi")) for name in os.listdir(path))
    except OSError:
        return False


def is_project_local(project: str, name: str, files, javascript: bool = False) -> bool:
    """Whether ``name`` is a directory or module inside the project tree.

    A Python import resolves against the roots :func:`_python_roots`
    lists, and only a package directory or a module file there counts. A
    bare JavaScript import never resolves against the importing file's own
    directory, only against a base a path alias points at, so for
    JavaScript only the importer's parents that hold a package.json,
    tsconfig.json or jsconfig.json count, and any directory or source file
    there does.
    """
    if not project:
        return False
    head = name.split("/", 1)[0].split(".", 1)[0]
    if not javascript:
        return any(
            _is_python_package(os.path.join(directory, head))
            or any(os.path.isfile(os.path.join(directory, head + s)) for s in (".py", ".pyi"))
            for directory in _python_roots(project, files)
        )
    candidates = {project}
    for file_name in files:
        directory = os.path.dirname(os.path.join(project, file_name))
        while directory.startswith(project):
            if any(os.path.isfile(os.path.join(directory, base)) for base in JS_PROJECT_BASES):
                candidates.add(directory)
            parent = os.path.dirname(directory)
            if parent == directory:
                break
            directory = parent
    return any(
        os.path.isdir(os.path.join(directory, head))
        or any(os.path.isfile(os.path.join(directory, head + s)) for s in SOURCE_SUFFIXES)
        for directory in candidates
    )


def npm_declared(project: str) -> set:
    """Every name the project's package.json files declare."""
    names = set()
    for path in _walk(project, lambda p: os.path.basename(p) == "package.json") if project else ():
        document = load_json(path)
        for section in (
            "dependencies",
            "devDependencies",
            "peerDependencies",
            "optionalDependencies",
        ):
            values = document.get(section) if isinstance(document, dict) else None
            if isinstance(values, dict):
                names |= set(values)
    return names


def npm_purl(name: str) -> str:
    """A purl for an npm name, scoped names included, in cdxgen's spelling."""
    return f"pkg:npm/%40{name[1:]}" if name.startswith("@") else f"pkg:npm/{name}"


def import_names(distribution: str) -> set:
    """The lower-cased import names a distribution is known to provide:
    its own name with underscores, the import table's names for it and
    DISTRIBUTION_IMPORTS."""
    names = {distribution.replace("-", "_")}
    names |= {imp for imp, dist in IMPORT_DISTRIBUTIONS.items() if fold_name(dist) == distribution}
    return names | set(DISTRIBUTION_IMPORTS.get(distribution, ()))


class Mapper:
    """Turns one project's truth package names into purls."""

    def __init__(self, ecosystem: str, project: str = "", site_packages=None, lock_files=None):
        self.ecosystem = ecosystem
        self.project = os.path.abspath(project) if project else ""
        self.npm_declared = npm_declared(self.project) if ecosystem == "npm" else set()
        direct, locked, own = (
            python_manifests(self.project) if ecosystem == "pypi" else (set(), set(), set())
        )
        self.python_declared = direct
        self.python_own = own
        self.python_known = (
            locked | environment_distributions(lock_files, site_packages)
            if ecosystem == "pypi"
            else set()
        )
        self.top_level = top_level_names(site_packages) if ecosystem == "pypi" else {}
        self.declared_imports: dict = {}
        for distribution in sorted(direct):
            for name in import_names(distribution):
                self.declared_imports.setdefault(name, distribution)

    def purl(self, package: str, files=()):
        """The purl of a truth package, or "local", or None (unmapped)."""
        if self.ecosystem == "npm":
            if package in self.npm_declared:
                return npm_purl(package)
            if is_project_local(self.project, package, files, javascript=True):
                return "local"
            return npm_purl(package) if NPM_NAME.match(package) else None
        if self.ecosystem in ("maven", "composer"):
            parts = package.split(":" if self.ecosystem == "maven" else "/", 1)
            if len(parts) == 2 and all(parts):
                return f"pkg:{self.ecosystem}/{parts[0]}/{parts[1]}"
            return None
        if self.ecosystem == "gem":
            return f"pkg:gem/{package}" if GEM_NAME.match(package) else None
        # A module of the tree shadows any distribution of the same name, so
        # the project-local check comes first.
        if is_project_local(self.project, package, files):
            return "local"
        lower = package.lower()
        if any(lower in import_names(own) for own in self.python_own):
            return "local"
        distribution = (
            self.declared_imports.get(lower)
            or IMPORT_DISTRIBUTIONS.get(lower)
            or self.top_level.get(lower)
        )
        if not distribution and fold_name(package) in self.python_declared | self.python_known:
            distribution = package
        if not distribution:
            return None
        # The project's own distribution is never one of its dependencies.
        return (
            "local"
            if fold_name(distribution) in self.python_own
            else (f"pkg:pypi/{fold_name(distribution)}")
        )


def bom_direct_purls(bom: dict) -> set:
    """The purls the BOM's dependency graph lists under the root component
    and every application component: the direct dependencies."""
    ref_to_purl = {}
    roots = set()
    metadata_component = (bom.get("metadata") or {}).get("component") or {}
    for component in [*(bom.get("components") or []), metadata_component]:
        if not isinstance(component, dict) or not component.get("bom-ref"):
            continue
        if isinstance(component.get("purl"), str):
            ref_to_purl[component["bom-ref"]] = component["purl"]
        if component.get("type") == "application" or component is metadata_component:
            roots.add(component["bom-ref"])
    return {
        ref_to_purl[ref]
        for entry in bom.get("dependencies") or []
        if isinstance(entry, dict) and entry.get("ref") in roots
        for ref in entry.get("dependsOn") or []
        if ref in ref_to_purl
    }


def version_less(purl: str) -> str:
    """A purl without version, qualifiers or subpath, in the label spelling:
    a scoped npm name keeps cdxgen's encoded ``%40`` and a PyPI name is
    folded."""
    parsed = parse_purl(purl) or {}
    ptype = str(parsed.get("type") or "").lower()
    namespace, name = parsed.get("namespace") or "", parsed.get("name") or ""
    if ptype == "pypi":
        name = fold_name(name)
    if ptype == "npm" and namespace.startswith("@"):
        namespace = "%40" + namespace[1:]
    return f"pkg:{ptype}/{namespace}/{name}" if namespace else f"pkg:{ptype}/{name}"


def derive(
    item_id: str,
    truth: dict,
    bom: dict,
    manifest_path: str = "",
    project: str = "",
    site_packages=None,
    lock_files=None,
    missing_modules=None,
) -> dict:
    """The label document for one item, or raise ValueError when the item's
    language is one the oracle does not cover.

    ``missing_modules`` maps a truth package name to the reviewed reason it
    is a module the project imports but neither its tree nor any
    distribution holds; such a name is listed under ``missingModules`` and
    is neither a label nor a miss."""
    ecosystem = language_of(item_id)
    if not ecosystem:
        raise ValueError(
            f"Item '{item_id}' has no language the callsites truth covers "
            "(js-, py-, java-, php- or rb- prefixed)."
        )
    mapper = Mapper(ecosystem, project, site_packages, lock_files)
    packages = certain_packages(truth)
    missing_modules = missing_modules or {}
    used: dict = {}
    unmapped: dict = {}
    local: dict = {}
    missing: dict = {}
    for package, (count, files) in sorted(packages.items()):
        if ecosystem == "npm" and (package in NODE_BUILTINS or package.startswith("node:")):
            continue
        if ecosystem == "pypi" and package in PYTHON_NOT_DISTRIBUTIONS:
            continue
        purl = mapper.purl(package, files)
        if purl is None and package in missing_modules:
            missing[package] = {"occurrences": count, "reason": missing_modules[package]}
        elif purl is None:
            unmapped[package] = count
        elif purl == "local":
            local[package] = count
        else:
            used[purl] = used.get(purl, 0) + count
    if ecosystem == "pypi":
        # An undeclared import named like a distribution another import
        # already maps to (pymongo beside bson) is that distribution: its
        # uses join the label instead of counting as a second, unmapped one.
        for package in list(unmapped):
            purl = f"pkg:pypi/{fold_name(package)}"
            if purl in used:
                used[purl] += unmapped.pop(package)
    if ecosystem == "npm" and manifest_path:
        # cdxgen's npm graph lists the whole resolved tree under the root,
        # so the manifest answers which dependencies are direct.
        document = load_json(manifest_path)
        declared = set()
        for section in ("dependencies", "devDependencies"):
            values = document.get(section) if isinstance(document, dict) else None
            declared |= set(values) if isinstance(values, dict) else set()
        direct = {npm_purl(name) for name in declared}
    elif ecosystem == "pypi":
        # The project's own manifests answer directness; a BOM of the scan
        # may hold the environment cdxgen ran in.
        direct = {f"pkg:pypi/{name}" for name in mapper.python_declared}
    else:
        direct = {version_less(purl) for purl in bom_direct_purls(bom)}
    # A direct dependency is unused only when the truth holds no use of it.
    # An import the mapping could not place still names its package when
    # the names fold equal.
    used_keys = {label_key(purl) for purl in used}
    if ecosystem == "pypi":
        used_keys |= {label_key(f"pkg:pypi/{fold_name(name)}") for name in packages}
    unused = sorted(purl for purl in direct if label_key(purl) not in used_keys)
    reachability = {
        "source": "oracle",
        "derivedFrom": (
            "Package-level reduction of the callsites oracle output for "
            "this project at its pinned commit: a package is used when "
            "the truth holds a certain use of it in the project's own "
            "files, with the purl taken from the package name and not "
            "from any scan, and unused when the project's manifests (for "
            "Python and JavaScript) or the BOM (for the other languages) "
            "declare it as a direct dependency and the truth holds no "
            "use of it. No truth row is carried."
        ),
        "used": [{"purl": purl, "occurrences": count} for purl, count in sorted(used.items())],
        "unused": [{"purl": purl} for purl in unused],
        "unmapped": dict(sorted(unmapped.items())),
        "local": dict(sorted(local.items())),
    }
    if missing:
        reachability["missingModules"] = dict(sorted(missing.items()))
    reachability["counts"] = {
        "used": len(used),
        "unused": len(unused),
        "unmapped": len(unmapped),
        "local": len(local),
        "certainUses": sum(count for count, _ in packages.values()),
    }
    if missing:
        reachability["counts"]["missingModule"] = len(missing)
    return {"item": item_id, "reachability": reachability}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--truth", required=True, help="The project's truth JSON.")
    parser.add_argument(
        "--bom",
        default="",
        help="The scan's BOM, read for the direct dependencies of a Java, PHP or Ruby item only.",
    )
    parser.add_argument("--item", required=True, help="The corpus item id.")
    parser.add_argument(
        "--project",
        default="",
        help="The project's clone at the pinned commit, for its declared dependencies "
        "and its project-local modules.",
    )
    parser.add_argument(
        "--package-manifest",
        default="",
        help="The project's package.json (default: the one at --project's root), "
        "which answers directness for a JavaScript item.",
    )
    parser.add_argument(
        "--site-packages",
        action="append",
        default=[],
        help="A site-packages directory of the project's environment, whose "
        "distributions' top_level.txt map Python import names; repeatable.",
    )
    parser.add_argument(
        "--lock",
        action="append",
        default=[],
        help="A requirements-format lock file of the project's environment made outside "
        "the tree (uv pip compile output, say); its distributions map undeclared Python "
        "imports and never count as direct; repeatable.",
    )
    parser.add_argument(
        "--missing-module",
        action="append",
        default=[],
        metavar="NAME=REASON",
        help="A Python import that names a module neither the tree nor any distribution "
        "holds, with the reviewed reason; repeatable. The label file keeps earlier ones.",
    )
    parser.add_argument("--out", required=True, help="Label file to write.")
    parser.add_argument(
        "--force",
        action="store_true",
        help="Replace a reachability section that was not derived from the oracle.",
    )
    args = parser.parse_args(argv)
    truth = load_json(args.truth)
    bom = load_json(args.bom) if args.bom else {}
    if not isinstance(truth, dict) or not isinstance(bom, dict):
        print(f"Cannot read the truth '{args.truth}' or the BOM '{args.bom}'.", file=sys.stderr)
        return 2
    project = os.path.expanduser(args.project)
    manifest_path = os.path.expanduser(args.package_manifest) or (
        os.path.join(project, "package.json") if project else ""
    )
    # The derivation owns the oracle reachability section only. Hand-written
    # findings and joins survive the rewrite, as do the reviewed missing
    # modules, and a hand-written reachability section is refused unless
    # --force says to replace it.
    existing = load_json(args.out)
    reachability = (existing.get("reachability") or {}) if isinstance(existing, dict) else {}
    if reachability.get("source") not in (None, "oracle") and not args.force:
        print(
            f"The reachability section of '{args.out}' has source "
            f"'{reachability.get('source')}'; refreshing it from the oracle would drop "
            "those labels. Pass --force to replace it.",
            file=sys.stderr,
        )
        return 2
    missing_modules = {
        name: entry.get("reason", "")
        for name, entry in (reachability.get("missingModules") or {}).items()
        if isinstance(entry, dict)
    }
    for spec in args.missing_module:
        name, sep, reason = spec.partition("=")
        if not sep or not name.strip() or not reason.strip():
            print(f"--missing-module needs NAME=REASON, not '{spec}'.", file=sys.stderr)
            return 2
        missing_modules[name.strip()] = reason.strip()
    try:
        document = derive(
            args.item,
            truth,
            bom,
            manifest_path,
            project,
            [os.path.expanduser(p) for p in args.site_packages],
            [os.path.expanduser(p) for p in args.lock],
            missing_modules,
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if isinstance(existing, dict):
        for section in ("findings", "joins"):
            if section in existing:
                document[section] = existing[section]
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fp:
        json.dump(document, fp, indent=2, ensure_ascii=False)
        fp.write("\n")
    counts = document["reachability"]["counts"]
    print(
        f"{args.item}: used {counts['used']}, unused {counts['unused']}, unmapped "
        f"{counts['unmapped']}, local {counts['local']}, missing modules "
        f"{counts.get('missingModule', 0)} of {counts['certainUses']} certain uses"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
