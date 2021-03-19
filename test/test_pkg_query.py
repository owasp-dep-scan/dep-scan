import json
import os

import pytest

from depscan.lib.bom import get_pkg_list
from depscan.lib import config as config
from depscan.lib.pkg_query import (
    npm_metadata,
    pypi_metadata,
    get_category_score,
    calculate_risk_score,
    npm_pkg_risk,
    pypi_pkg_risk,
)


def test_risk_scores():
    cat_score = get_category_score(2, 100, 2)
    assert cat_score > 0.4
    cat_score = get_category_score(1000, config.mod_create_min_seconds_max, 1)
    assert cat_score > 0.3
    cat_score = get_category_score(120, config.latest_now_min_seconds_max, 0.5)
    assert cat_score > 0.1


def test_calculate_risk_score():
    # Test for min versions
    one_score = calculate_risk_score(
        {"pkg_min_versions_risk": True, "pkg_min_versions_value": 1}
    )
    assert one_score > 0
    two_score = calculate_risk_score(
        {"pkg_min_versions_risk": True, "pkg_min_versions_value": 2}
    )
    assert two_score < one_score
    # Deprecated package risk
    dep_score = calculate_risk_score({"pkg_deprecated_risk": True})
    assert dep_score > one_score
    dep_score = calculate_risk_score(
        {
            "pkg_deprecated_risk": True,
            "pkg_min_versions_risk": True,
            "pkg_min_versions_value": 1,
        }
    )
    assert dep_score > one_score
    # Min maintainers risk
    m_score = calculate_risk_score(
        {
            "pkg_min_maintainers_risk": True,
            "pkg_min_maintainers_value": 1,
            "pkg_min_versions_risk": True,
            "pkg_min_versions_value": 1,
        }
    )
    assert m_score > two_score
    # Recent package
    l1_score = calculate_risk_score(
        {
            "pkg_min_versions_risk": True,
            "pkg_min_versions_value": 1,
            "created_now_quarantine_seconds_risk": True,
            "latest_now_max_seconds_risk": True,
            "latest_now_max_seconds_value": 1000,
        }
    )
    # Recent package with less maintainers (risky)
    l2_score = calculate_risk_score(
        {
            "pkg_min_maintainers_risk": True,
            "pkg_min_maintainers_value": 1,
            "pkg_min_versions_risk": True,
            "pkg_min_versions_value": 1,
            "created_now_quarantine_seconds_risk": True,
            "latest_now_max_seconds_risk": True,
            "latest_now_max_seconds_value": 1000,
        }
    )
    assert l2_score > l1_score
    assert l2_score > 0.5
    # Also has script section
    l3_score = calculate_risk_score(
        {
            "pkg_min_maintainers_risk": True,
            "pkg_min_maintainers_value": 1,
            "pkg_min_versions_risk": True,
            "pkg_min_versions_value": 1,
            "created_now_quarantine_seconds_risk": True,
            "latest_now_max_seconds_risk": True,
            "latest_now_max_seconds_value": 1000,
            "pkg_install_scripts_risk": True,
            "pkg_install_scripts_value": 1,
        }
    )
    assert l3_score > l2_score

    # Old package with scripts but past quarantine
    l4_score = calculate_risk_score(
        {
            "pkg_min_maintainers_risk": True,
            "pkg_min_maintainers_value": 1,
            "pkg_min_versions_risk": True,
            "created_now_quarantine_seconds_risk": False,
            "created_now_quarantine_seconds_value": 2 * 365 * 60 * 60,
            "pkg_min_versions_value": 1,
            "pkg_install_scripts_risk": True,
            "pkg_install_scripts_value": 1,
        }
    )
    assert l4_score < l3_score

    # Quite old package
    o_score = calculate_risk_score(
        {
            "latest_now_max_seconds_risk": True,
            "latest_now_max_seconds_value": 10 * 365 * 60 * 60,
            "pkg_node_version_risk": True,
            "pkg_node_version_value": 1,
        }
    )
    assert o_score < 0.2
    od_score = calculate_risk_score(
        {
            "latest_now_max_seconds_risk": True,
            "latest_now_max_seconds_value": 10 * 365 * 60 * 60,
            "pkg_node_version_risk": True,
            "pkg_node_version_value": 1,
            "pkg_deprecated_risk": True,
        }
    )
    assert od_score > o_score


@pytest.mark.skip(reason="This downloads and tests with live data")
def test_query_metadata():
    test_bom = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "bom-node.xml"
    )
    pkg_list = get_pkg_list(test_bom)
    metadata_dict = npm_metadata({}, pkg_list, None)
    assert metadata_dict


@pytest.mark.skip(reason="This downloads and tests with live data")
def test_query_metadata1():
    test_bom = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "bom-goof.json"
    )
    pkg_list = get_pkg_list(test_bom)
    metadata_dict = npm_metadata({}, pkg_list, "snyk")
    assert metadata_dict


def test_npm_confusion_risks():
    test_deprecated_pkg = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "cdxgen-metadata.json"
    )
    with open(test_deprecated_pkg) as fp:
        pkg_metadata = json.load(fp)
        risk_metrics = npm_pkg_risk(pkg_metadata, True, None)
        assert risk_metrics["pkg_private_on_public_registry_risk"]
        assert not risk_metrics["pkg_min_versions_risk"]


def test_npm_risks():
    test_deprecated_pkg = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "bcrypt-metadata.json"
    )
    with open(test_deprecated_pkg) as fp:
        pkg_metadata = json.load(fp)
        risk_metrics = npm_pkg_risk(pkg_metadata, False, None)
        assert risk_metrics["pkg_deprecated_risk"]
        assert not risk_metrics["pkg_min_versions_risk"]
        assert risk_metrics["latest_now_max_seconds_risk"]

    ebp_pkg = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "ebparser-metadata.json"
    )
    with open(ebp_pkg) as fp:
        pkg_metadata = json.load(fp)
        risk_metrics = npm_pkg_risk(pkg_metadata, False, None)
        assert risk_metrics["pkg_node_version_risk"]
        assert not risk_metrics["pkg_deprecated_risk"]
        assert not risk_metrics["pkg_min_versions_risk"]


def test_pypi_confusion_risks():
    test_pkg = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "django-metadata.json"
    )
    with open(test_pkg) as fp:
        pkg_metadata = json.load(fp)
        risk_metrics = pypi_pkg_risk(pkg_metadata, False, None)
        assert risk_metrics == {
            "pkg_deprecated_risk": False,
            "pkg_min_versions_risk": False,
            "created_now_quarantine_seconds_risk": False,
            "latest_now_max_seconds_risk": False,
            "mod_create_min_seconds_risk": False,
            "pkg_min_maintainers_risk": False,
            "pkg_private_on_public_registry_risk": False,
            "risk_score": 0.0,
        }
    test_pkg = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "astroid-metadata.json"
    )
    with open(test_pkg) as fp:
        pkg_metadata = json.load(fp)
        risk_metrics = pypi_pkg_risk(pkg_metadata, False, None)
        assert risk_metrics == {
            "pkg_deprecated_risk": False,
            "pkg_min_versions_risk": False,
            "created_now_quarantine_seconds_risk": False,
            "latest_now_max_seconds_risk": False,
            "mod_create_min_seconds_risk": False,
            "pkg_min_maintainers_risk": False,
            "pkg_private_on_public_registry_risk": False,
            "risk_score": 0.0,
        }
    test_pkg = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "mongo-dash-metadata.json"
    )
    with open(test_pkg) as fp:
        pkg_metadata = json.load(fp)
        risk_metrics = pypi_pkg_risk(pkg_metadata, False, None)
        assert risk_metrics
        assert risk_metrics["pkg_min_versions_risk"]


def test_query_metadata2():
    test_bom = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "bom-py.xml"
    )
    pkg_list = get_pkg_list(test_bom)
    metadata_dict = pypi_metadata({}, pkg_list, None)
    assert metadata_dict
