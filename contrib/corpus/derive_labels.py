#!/usr/bin/env python3
"""Derive package-level reachability labels from the callsites ground truth.

The oracle output of the callsites work names a file, a line and a package for
every certain use of a dependency in a project's own code. This script reduces
one project's oracle output to package level: a package is ``used`` when the
truth holds at least one certain use of it, and ``unused`` when the project's
BOM declares it as a direct dependency and the truth holds no use of it at
all. The rows themselves (files, lines, members) never leave the private
harness; the label file carries purls, occurrence counts and the names the
mapping could not turn into a purl, each with its count.

Usage:
    python contrib/corpus/derive_labels.py \
        --truth truth/py-vulpy.json --bom sbom-python.cdx.json \
        --item py-vulpy --out contrib/corpus/labels/py-vulpy.json

The BOM is the scan directory's ``sbom-<type>.cdx.json`` of the same project
at the same pinned commit; it is what the labels are checked against, and its
components and dependency graph are how import names become distribution purls
and how direct dependencies are known.

Exits non-zero when the truth or the BOM cannot be read. An unmappable
package name is not an error: it is reported in the label file's ``unmapped``
object with its count, and the scorer counts every such label as a miss
waiting for a better mapping.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ANALYSIS_SRC = os.path.join(_HERE, "..", "..", "packages", "analysis-lib", "src")
if os.path.isdir(_ANALYSIS_SRC):
    sys.path.insert(0, os.path.abspath(_ANALYSIS_SRC))

from vdb.lib.utils import parse_purl  # noqa: E402

#: Language of a corpus item, from the item id's prefix.
LANGUAGES = {
    "js-": "npm",
    "py-": "pypi",
    "java-": "maven",
    "php-": "composer",
    "rb-": "gem",
}

#: Common Python import names that are not the distribution name, lower-cased
#: import name to the distribution name on the index. The mapping to a BOM
#: component tries the table first and then the case and separator fold, so a
#: project's own odd naming only needs a row here when no BOM component
#: matches either way.
IMPORT_DISTRIBUTIONS = {
    "bs4": "beautifulsoup4",
    "cv2": "opencv-python",
    "dateutil": "python-dateutil",
    "dotenv": "python-dotenv",
    "git": "gitpython",
    "jwt": "pyjwt",
    "openssl": "pyopenssl",
    "pil": "pillow",
    "sklearn": "scikit-learn",
    "yaml": "pyyaml",
}

#: Node's own modules. The untyped JavaScript truth records a package per use,
#: and a use of a Node builtin names the builtin, which no BOM component
#: matches; they are reported as unmapped like any other name, so the list
#: only keeps them out of the package mapping, not out of the label file.
NODE_BUILTINS = frozenset(
    """
    assert async_hooks buffer child_process cluster console constants crypto
    dgram diagnostics_channel dns domain events fs http http2 https inspector
    module net os path perf_hooks process punycode querystring readline repl
    stream string_decoder sys timers tls trace_events tty url util v8 vm wasi
    worker_threads zlib
    """.split()
)


def language_of(item_id: str) -> str:
    """The ecosystem of a corpus item id, or an empty string."""
    for prefix, ecosystem in LANGUAGES.items():
        if item_id.startswith(prefix):
            return ecosystem
    return ""


def certain_packages(truth: dict) -> dict:
    """Count the certain uses of every package in a truth document.

    A row counts when the oracle marked it certain (rows without the flag are
    certain: the JavaScript oracle records no flag), names a package, and is
    not a use of a language builtin.
    """
    counts: dict = {}
    for row in truth.get("usages") or []:
        if not isinstance(row, dict):
            continue
        if row.get("certain") is False or row.get("builtin"):
            continue
        package = row.get("pkg")
        if not isinstance(package, str) or not package:
            continue
        counts[package] = counts.get(package, 0) + 1
    return counts


def component_identities(bom: dict) -> set:
    """The version-less comparable identities of a BOM's components."""
    identities = set()
    for component in bom.get("components") or []:
        purl = component.get("purl")
        if isinstance(purl, str) and purl:
            identity = purl_identity(purl)
            if identity:
                identities.add(identity)
    return identities


def purl_identity(purl: str):
    """A purl reduced to (type, namespace, name), or None."""
    parsed = parse_purl(purl)
    if not parsed:
        return None
    namespace = parsed.get("namespace")
    return (
        str(parsed.get("type") or "").lower(),
        namespace or "",
        parsed.get("name") or "",
    )


def identity_purl(identity) -> str:
    """The label purl of a version-less identity, in the BOM's spelling."""
    ptype, namespace, name = identity
    if namespace:
        if ptype == "npm" and namespace.startswith("@"):
            namespace = "%40" + namespace[1:]
        return f"pkg:{ptype}/{namespace}/{name}"
    return f"pkg:{ptype}/{name}"


def npm_purl(name: str) -> str:
    """A purl for an npm name, scoped names included, in cdxgen's spelling."""
    if name.startswith("@"):
        return f"pkg:npm/%40{name[1:]}"
    return f"pkg:npm/{name}"


def fold_name(name: str) -> str:
    """The fold that makes ``Flask_SQLAlchemy`` and ``flask-sqlalchemy``
    compare equal."""
    return re.sub(r"[-_.]+", "-", name).lower()


def map_python_package(package: str, by_fold: dict):
    """Map a Python import name to a distribution identity from the BOM.

    The import name can differ from the distribution name, so the fold of the
    import name and the fold of the well-known import's distribution are
    looked up in the BOM's folded names. ``None`` means the name mapped to
    nothing the BOM declares.
    """
    for candidate in (
        fold_name(package),
        fold_name(IMPORT_DISTRIBUTIONS.get(fold_name(package), "")),
    ):
        if candidate and candidate in by_fold:
            return by_fold[candidate]
    return None


def direct_dependency_identities(bom: dict) -> set:
    """The identities a BOM declares as direct dependencies.

    Direct is the dependency graph's answer: everything the root component
    and every application component depends on, so a workspace's sub-projects
    count too. The graph's refs are bom-refs, so each is resolved through the
    component it names. A BOM without a dependency graph declares nothing,
    and the label file then holds no ``unused`` labels.
    """
    direct = set()
    ref_to_purl = {}
    application_refs = set()
    for component in bom.get("components") or []:
        if not isinstance(component, dict) or not component.get("bom-ref"):
            continue
        ref = component["bom-ref"]
        purl = component.get("purl")
        if isinstance(purl, str) and purl:
            ref_to_purl[ref] = purl
        if component.get("type") == "application":
            application_refs.add(ref)
    metadata_component = (bom.get("metadata") or {}).get("component") or {}
    roots = application_refs
    if metadata_component.get("bom-ref"):
        roots = roots | {metadata_component["bom-ref"]}
        metadata_purl = metadata_component.get("purl")
        if isinstance(metadata_purl, str) and metadata_purl:
            ref_to_purl[metadata_component["bom-ref"]] = metadata_purl
    for entry in bom.get("dependencies") or []:
        if not isinstance(entry, dict) or entry.get("ref") not in roots:
            continue
        for ref in entry.get("dependsOn") or []:
            identity = purl_identity(ref_to_purl.get(ref, ""))
            if identity:
                direct.add(identity)
    return direct


def derive(item_id: str, truth: dict, bom: dict) -> dict:
    """The label document for one item, or raise ValueError when the item's
    language is one the oracle does not cover."""
    ecosystem = language_of(item_id)
    if not ecosystem:
        raise ValueError(
            f"Item '{item_id}' has no language the callsites truth covers "
            "(js-, py-, java-, php- or rb- prefixed)."
        )
    counts = certain_packages(truth)
    identities = component_identities(bom)
    if ecosystem == "pypi":
        by_fold = {fold_name(identity[2]): identity for identity in identities}
    used = {}
    unmapped = {}
    for package, count in sorted(counts.items()):
        identity = None
        if ecosystem == "npm":
            if package in NODE_BUILTINS:
                unmapped[package] = count
                continue
            identity = purl_identity(npm_purl(package))
        elif ecosystem == "maven":
            parts = package.split(":", 1)
            identity = (
                ("maven", parts[0], parts[1]) if len(parts) == 2 else None
            )
        elif ecosystem == "composer":
            parts = package.split("/", 1)
            identity = (
                ("composer", parts[0], parts[1]) if len(parts) == 2 else None
            )
        elif ecosystem == "gem":
            identity = ("gem", "", package)
        else:
            identity = map_python_package(package, by_fold)
        if identity is None or identity not in identities:
            unmapped[package] = count
            continue
        used[identity] = used.get(identity, 0) + count
    used_list = [
        {"purl": identity_purl(identity), "occurrences": count}
        for identity, count in sorted(used.items())
    ]
    direct = direct_dependency_identities(bom)
    unused_list = [
        {"purl": identity_purl(identity)}
        for identity in sorted(direct - set(used))
    ]
    document = {
        "item": item_id,
        "reachability": {
            "source": "oracle",
            "derivedFrom": (
                "Package-level reduction of the callsites oracle output for "
                "this project at its pinned commit: a package is used when "
                "the truth holds a certain use of it in the project's own "
                "files, and unused when the BOM declares it as a direct "
                "dependency and the truth holds no use of it. No truth row "
                "is carried."
            ),
            "used": used_list,
            "unused": unused_list,
            "unmapped": dict(sorted(unmapped.items())),
            "counts": {
                "used": len(used_list),
                "unused": len(unused_list),
                "unmapped": len(unmapped),
                "certainUses": sum(counts.values()),
            },
        },
    }
    return document


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--truth", required=True, help="The project's truth JSON.")
    parser.add_argument("--bom", required=True, help="The scan's sbom-<type>.cdx.json.")
    parser.add_argument("--item", required=True, help="The corpus item id.")
    parser.add_argument("--out", required=True, help="Label file to write.")
    args = parser.parse_args()
    try:
        with open(args.truth, encoding="utf-8") as fp:
            truth = json.load(fp)
        with open(args.bom, encoding="utf-8") as fp:
            bom = json.load(fp)
    except (OSError, ValueError) as exc:
        print(f"Cannot read the inputs: {exc}", file=sys.stderr)
        return 2
    try:
        document = derive(args.item, truth, bom)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    out_dir = os.path.dirname(os.path.abspath(args.out))
    os.makedirs(out_dir, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fp:
        json.dump(document, fp, indent=2, ensure_ascii=False)
        fp.write("\n")
    counts = document["reachability"]["counts"]
    print(
        f"{args.item}: used {counts['used']}, unused {counts['unused']}, "
        f"unmapped {counts['unmapped']} of {counts['certainUses']} certain uses"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
