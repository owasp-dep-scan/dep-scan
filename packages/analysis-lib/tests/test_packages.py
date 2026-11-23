"""The component filter the package loader applies to one BOM document.

``bom_components`` is that filter on its own, so a caller that needs the
components a document contributes without loading a file sees exactly the
set ``get_pkg_list`` keeps. The tests pin the filter's decisions and that
``get_pkg_list`` is the same walk plus its enrichment, on the same fixture
documents the loader reads.
"""

import json

import pytest

from analysis_lib.packages import bom_components, get_pkg_list

#: One document holding every component position and type the filter
#: decides about: a kept top-level library, a skipped top-level ``data``
#: component, a kept and a skipped component nested below a kept one, and
#: the kept and skipped components of ``metadata.component``.
FILTER_BOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "metadata": {
        "component": {
            "type": "application",
            "name": "app",
            "bom-ref": "app",
            "components": [
                {"type": "library", "name": "meta-lib", "bom-ref": "meta-lib"},
                {"type": "application", "name": "meta-app", "bom-ref": "meta-app"},
                {"type": "data", "name": "meta-data", "bom-ref": "meta-data"},
            ],
        }
    },
    "components": [
        {"type": "library", "name": "lib", "bom-ref": "lib"},
        {"type": "data", "name": "data", "bom-ref": "data"},
        {
            "type": "library",
            "name": "parent",
            "bom-ref": "parent",
            "components": [
                {"type": "library", "name": "nested-lib", "bom-ref": "nested-lib"},
                {"type": "application", "name": "nested-app", "bom-ref": "nested-app"},
                {"type": "data", "name": "nested-data", "bom-ref": "nested-data"},
            ],
        },
    ],
}


def test_bom_components_keeps_the_loaded_positions_only():
    kept = [component["name"] for component in bom_components(FILTER_BOM)]
    assert kept == ["meta-lib", "lib", "parent", "nested-lib"]


def test_get_pkg_list_enriches_exactly_the_kept_components(tmp_path):
    """The loader's package list is ``bom_components`` plus the vendor,
    license and URL fields, in the same order."""
    bom_file = tmp_path / "sbom.cdx.json"
    bom_file.write_text(json.dumps(FILTER_BOM))
    pkgs, lifecycles = get_pkg_list(str(bom_file))
    assert lifecycles == []
    kept = list(bom_components(FILTER_BOM))
    assert pkgs == [
        {**component, "vendor": component.get("group") or "", "licenses": [], "url": ""}
        for component in kept
    ]
    assert [pkg["name"] for pkg in pkgs] == ["meta-lib", "lib", "parent", "nested-lib"]


@pytest.mark.parametrize(
    "document",
    [
        "not json text",
        None,
        [],
        {},
        {"metadata": None},
        {"metadata": {"component": None}},
        {"metadata": {"component": {}}},
        {"components": None},
        {"components": {}},
        {"components": [None, "lib"]},
    ],
    ids=[
        "text",
        "none",
        "list",
        "empty",
        "null-metadata",
        "null-root",
        "empty-root",
        "null-components",
        "object-components",
        "null-entries",
    ],
)
def test_bom_components_keeps_nothing_of_a_hostile_document(document):
    """A document that is not a JSON object, or whose component lists are
    null, of the wrong type or hold non-objects, keeps nothing instead of
    raising: the adapter hands such a document to the walk when a BOM file
    holds text the parser refused."""
    assert list(bom_components(document)) == []


def test_bom_components_skips_bad_metadata_entries():
    """Non-object entries inside ``metadata.component.components`` keep the
    walk alive; the objects around them still load."""
    document = {
        "metadata": {"component": {"components": [None, {"type": "library", "name": "m"}]}}
    }
    assert [component["name"] for component in bom_components(document)] == ["m"]


def test_the_directory_readers_skip_a_report_the_bom_glob_picks_up(tmp_path):
    """The BOM file list is a name glob, and a license or risk report whose
    name contains \"bom\" reaches it as a JSON array; the loaders skip it
    instead of reading it as a BOM document."""
    from analysis_lib.packages import retrieve_bom_dependency_tree, retrieve_oci_properties

    report = tmp_path / "license-bom.json"
    report.write_text(json.dumps([{"Package": "demo", "License Id": "MIT"}]), encoding="utf-8")
    assert get_pkg_list(str(report)) == ([], [])
    assert retrieve_bom_dependency_tree(None, str(tmp_path)) == []
    assert retrieve_oci_properties(None, str(tmp_path)) == {}
