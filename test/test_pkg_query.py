import json
import os
import time
from unittest.mock import MagicMock, patch

import pytest

from depscan.lib import config as config
from depscan.lib.bom import get_pkg_list
from depscan.lib.package_query.pkg_query import (
    calculate_risk_score,
    get_category_score,
)
from depscan.lib.package_query.metadata import npm_metadata, pypi_metadata, metadata_from_registry
from depscan.lib.package_query.pypi_pkg import pypi_pkg_risk
from depscan.lib.package_query.npm_pkg import npm_pkg_risk


def test_risk_scores():
    cat_score = get_category_score(2, 100, 2)
    assert cat_score > 0.4
    cat_score = get_category_score(1000, config.mod_create_min_seconds_max, 1)
    assert cat_score > 0.3
    cat_score = get_category_score(120, config.latest_now_min_seconds_max, 0.5)
    assert cat_score > 0.1


def test_calculate_risk_score():
    # Test for min versions
    one_score = calculate_risk_score({"pkg_min_versions_risk": True, "pkg_min_versions_value": 1})
    assert one_score > 0
    two_score = calculate_risk_score({"pkg_min_versions_risk": True, "pkg_min_versions_value": 2})
    assert two_score < one_score
    # Deprecated package risk
    dep_score = calculate_risk_score({"pkg_deprecated_risk": True, "pkg_deprecated_value": 1})
    assert dep_score > 0
    dep_score = calculate_risk_score(
        {
            "pkg_deprecated_risk": True,
            "pkg_deprecated_value": 1,
            "pkg_version_deprecated_risk": False,
            "pkg_version_missing_risk": False,
            "pkg_min_versions_risk": True,
            "pkg_min_versions_value": 1,
        }
    )
    assert dep_score > 0
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
    assert l2_score > 0.3
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
            "pkg_version_deprecated_risk": False,
            "pkg_version_missing_risk": False,
        }
    )
    assert od_score > o_score


@pytest.mark.skip(reason="This downloads and tests with live data")
def test_query_metadata():
    test_bom = os.path.join(os.path.dirname(os.path.realpath(__file__)), "data", "bom-node.xml")
    pkg_list = get_pkg_list(test_bom)
    metadata_dict = npm_metadata({}, pkg_list, None)
    assert metadata_dict


@pytest.mark.skip(reason="This downloads and tests with live data")
def test_query_metadata1():
    test_bom = os.path.join(os.path.dirname(os.path.realpath(__file__)), "data", "bom-goof.json")
    pkg_list = get_pkg_list(test_bom)
    metadata_dict = npm_metadata({}, pkg_list, "snyk")
    assert metadata_dict


def test_npm_confusion_risks():
    test_deprecated_pkg = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "cdxgen-metadata.json"
    )
    with open(test_deprecated_pkg, encoding="utf-8") as fp:
        pkg_metadata = json.load(fp)
        risk_metrics = npm_pkg_risk(pkg_metadata, True, None, None)
        assert risk_metrics["pkg_private_on_public_registry_risk"]
        assert not risk_metrics["pkg_min_versions_risk"]


def test_npm_risks():
    test_deprecated_pkg = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "bcrypt-metadata.json"
    )
    with open(test_deprecated_pkg, encoding="utf-8") as fp:
        pkg_metadata = json.load(fp)
        risk_metrics = npm_pkg_risk(pkg_metadata, False, None, None)
        assert risk_metrics["pkg_deprecated_risk"]
        assert not risk_metrics["pkg_min_versions_risk"]
        assert risk_metrics["latest_now_max_seconds_risk"]

    ebp_pkg = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "ebparser-metadata.json"
    )
    with open(ebp_pkg, encoding="utf-8") as fp:
        pkg_metadata = json.load(fp)
        risk_metrics = npm_pkg_risk(pkg_metadata, False, None, None)
        assert risk_metrics["pkg_node_version_risk"]
        assert not risk_metrics["pkg_deprecated_risk"]
        assert not risk_metrics["pkg_version_deprecated_risk"]
        assert not risk_metrics["pkg_version_missing_risk"]
        assert not risk_metrics["pkg_min_versions_risk"]

    fsevents_pkg = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "npm-fsevents-metadata.json"
    )
    with open(fsevents_pkg, encoding="utf-8") as fp:
        pkg_metadata = json.load(fp)
        risk_metrics = npm_pkg_risk(pkg_metadata, False, None, {"version": "1.2.10"})
        assert risk_metrics["pkg_includes_binary_risk"]
        assert not risk_metrics["pkg_deprecated_risk"]
        assert risk_metrics["pkg_version_deprecated_risk"]
        assert not risk_metrics["pkg_version_missing_risk"]
        assert not risk_metrics["pkg_min_versions_risk"]

    sqlite_pkg = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "npm-sqlite3-metadata.json"
    )
    with open(sqlite_pkg, encoding="utf-8") as fp:
        pkg_metadata = json.load(fp)
        risk_metrics = npm_pkg_risk(pkg_metadata, False, None, {"version": "5.0.2"})
        assert risk_metrics["pkg_includes_binary_risk"]
        assert not risk_metrics["pkg_deprecated_risk"]
        assert not risk_metrics["pkg_version_deprecated_risk"]
        assert not risk_metrics["pkg_version_missing_risk"]
        assert not risk_metrics["pkg_min_versions_risk"]
        assert risk_metrics["pkg_includes_binary_info"]

        risk_metrics = npm_pkg_risk(pkg_metadata, False, None, {"version": "5.0.3"})
        assert risk_metrics["pkg_includes_binary_risk"]
        assert not risk_metrics["pkg_deprecated_risk"]
        assert not risk_metrics["pkg_version_deprecated_risk"]
        assert not risk_metrics["pkg_version_missing_risk"]
        assert not risk_metrics["pkg_min_versions_risk"]
        assert risk_metrics["pkg_includes_binary_info"]

        risk_metrics = npm_pkg_risk(pkg_metadata, False, None, {"version": "5.1.7"})
        assert risk_metrics["pkg_includes_binary_risk"]
        assert not risk_metrics["pkg_deprecated_risk"]
        assert not risk_metrics["pkg_version_deprecated_risk"]
        assert not risk_metrics["pkg_version_missing_risk"]
        assert not risk_metrics["pkg_min_versions_risk"]
        assert risk_metrics["pkg_includes_binary_info"]

        risk_metrics = npm_pkg_risk(pkg_metadata, False, None, {"version": "5.1.7-rc.0"})
        assert risk_metrics["pkg_includes_binary_risk"]
        assert not risk_metrics["pkg_deprecated_risk"]
        assert not risk_metrics["pkg_version_deprecated_risk"]
        assert not risk_metrics["pkg_version_missing_risk"]
        assert not risk_metrics["pkg_min_versions_risk"]
        assert risk_metrics["pkg_includes_binary_info"]

    biome_pkg = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "npm-biome-metadata.json"
    )
    with open(biome_pkg, encoding="utf-8") as fp:
        pkg_metadata = json.load(fp)
        risk_metrics = npm_pkg_risk(pkg_metadata, False, None, {"version": "1.8.1"})
        assert risk_metrics["pkg_includes_binary_risk"]
        assert not risk_metrics["pkg_deprecated_risk"]
        assert not risk_metrics["pkg_version_deprecated_risk"]
        assert not risk_metrics["pkg_version_missing_risk"]
        assert not risk_metrics["pkg_min_versions_risk"]
        assert risk_metrics["pkg_attested_check"]
        assert (
            risk_metrics["pkg_attested_info"]
            == "SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA"
        )

    biomec_pkg = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "npm-biome-cli-metadata.json"
    )
    with open(biomec_pkg, encoding="utf-8") as fp:
        pkg_metadata = json.load(fp)
        risk_metrics = npm_pkg_risk(pkg_metadata, False, None, {"version": "1.8.1"})
        assert risk_metrics["pkg_includes_binary_risk"]
        assert not risk_metrics["pkg_deprecated_risk"]
        assert not risk_metrics["pkg_version_deprecated_risk"]
        assert not risk_metrics["pkg_version_missing_risk"]
        assert not risk_metrics["pkg_min_versions_risk"]
        assert risk_metrics["pkg_attested_check"]
        assert (
            risk_metrics["pkg_attested_info"]
            == "SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA"
        )

        risk_metrics = npm_pkg_risk(pkg_metadata, False, None, {"version": "1.8.0"})
        assert risk_metrics["pkg_includes_binary_risk"]
        assert not risk_metrics["pkg_deprecated_risk"]
        assert not risk_metrics["pkg_version_deprecated_risk"]
        assert not risk_metrics["pkg_version_missing_risk"]
        assert not risk_metrics["pkg_min_versions_risk"]
        assert risk_metrics["pkg_attested_check"]
        assert (
            risk_metrics["pkg_attested_info"]
            == "SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA"
        )


def test_pypi_confusion_risks():
    test_pkg = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "django-metadata.json"
    )
    with open(test_pkg) as fp:
        pkg_metadata = json.load(fp)
        risk_metrics = pypi_pkg_risk(pkg_metadata, False, None, None)
        assert risk_metrics == {
            "pkg_deprecated_risk": False,
            "pkg_version_deprecated_risk": False,
            "pkg_version_missing_risk": False,
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
        risk_metrics = pypi_pkg_risk(pkg_metadata, False, None, None)
        assert risk_metrics == {
            "pkg_deprecated_risk": False,
            "pkg_version_deprecated_risk": False,
            "pkg_version_missing_risk": False,
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
        risk_metrics = pypi_pkg_risk(pkg_metadata, False, None, None)
        assert risk_metrics
        assert risk_metrics["pkg_min_versions_risk"]


def test_query_metadata2():
    test_bom = os.path.join(os.path.dirname(os.path.realpath(__file__)), "data", "bom-py.xml")
    pkg_list = get_pkg_list(test_bom)
    metadata_dict = pypi_metadata({}, pkg_list, None)
    assert metadata_dict


# ---------------------------------------------------------------------------
# T3 — parallel registry audit
# ---------------------------------------------------------------------------


def _make_mock_response(json_data, status_code=200):
    r = MagicMock()
    r.status_code = status_code
    r.json.return_value = json_data
    return r


def _make_mock_client(delay=0):
    """Return a mock HTTP client whose .get returns canned npm metadata."""
    npm_meta = {
        "name": "lodash",
        "versions": {"4.17.20": {}},
        "dist-tags": {"latest": "4.17.21"},
        "time": {"created": "2012-04-25T15:20:00.000Z", "modified": "2021-05-07T00:00:00.000Z"},
        "maintainers": [{"name": "jd", "email": "x@y.com"}],
        "license": "MIT",
    }

    client = MagicMock()

    def _get(url, **kwargs):
        if delay:
            time.sleep(delay)
        return _make_mock_response(npm_meta)

    client.get.side_effect = _get
    # metadata_from_registry uses `with httpx.Client() as client:`
    client.__enter__.return_value = client
    client.__exit__.return_value = False
    return client


def test_parallel_metadata_preserves_result_shape():
    """The parallel audit returns the same dict shape as the serial path."""
    pkg_list = [
        {"name": f"pkg-{i}", "vendor": "", "scope": "required", "purl": f"pkg:npm/pkg-{i}@1.0.0"}
        for i in range(12)
    ]
    with patch(
        "depscan.lib.package_query.metadata.httpx.Client",
        return_value=_make_mock_client(),
    ):
        result = metadata_from_registry("npm", {}, pkg_list)
    assert len(result) == 12
    for key, entry in result.items():
        assert set(entry.keys()) == {
            "scope",
            "purl",
            "pkg_metadata",
            "risk_metrics",
            "is_private_pkg",
        }
        assert entry["scope"] == "required"


def test_parallel_metadata_circuit_breaker():
    """The circuit breaker trips and returns {} after max_request_failures."""
    pkg_list = [{"name": f"fail-{i}", "vendor": "", "scope": "required"} for i in range(20)]
    client = MagicMock()
    client.get.side_effect = ConnectionError("boom")
    client.__enter__.return_value = client
    client.__exit__.return_value = False
    with patch(
        "depscan.lib.package_query.metadata.httpx.Client",
        return_value=client,
    ):
        result = metadata_from_registry("npm", {}, pkg_list)
    assert result == {}


def test_parallel_metadata_is_faster_than_serial():
    """Demonstrate wall-clock drop: 20 packages * 50ms each.
    Serial ≈ 1000ms; parallel (10 workers) ≈ 100ms."""
    pkg_list = [
        {"name": f"pkg-{i}", "vendor": "", "scope": "required", "purl": f"pkg:npm/pkg-{i}@1.0.0"}
        for i in range(20)
    ]
    mock_client = _make_mock_client(delay=0.05)
    with patch(
        "depscan.lib.package_query.metadata.httpx.Client",
        return_value=mock_client,
    ):
        t0 = time.perf_counter()
        result = metadata_from_registry("npm", {}, pkg_list)
        elapsed = time.perf_counter() - t0
    assert len(result) == 20
    # 20 requests * 50ms = 1.0s serial. With 10 workers → ~0.1s.
    # Assert well under the serial bound (leave generous headroom).
    assert elapsed < 0.6, f"Parallel audit took {elapsed:.2f}s, expected < 0.6s"
