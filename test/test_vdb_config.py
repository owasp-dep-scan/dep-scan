"""Tests for the flavor selection and image resolution helpers."""

import pytest

from depscan.lib.config import (
    VDB_FLAVORS,
    VDB_LEGACY_FLAVOR_MAP,
    resolve_vdb_flavor,
    resolve_vdb_image_url,
    vdb_shards_marker,
)
from vdb.lib.db_cmd import FULL_DB_FLAVORS


def test_flavor_list_matches_vdb():
    """depscan offers exactly the flavors vdb publishes, from vdb's own list."""
    assert (
        VDB_FLAVORS
        == FULL_DB_FLAVORS
        == (
            "full",
            "app-only",
            "app-extended",
            "app-10y",
            "app-10y-extended",
        )
    )


# ---------------------------------------------------------------------------
# The legacy option mapping, one test per row of the table
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "kwargs, flavor",
    [
        ({"scope": "app+os", "time": "default", "extended": False}, "full"),
        ({"scope": "app", "time": "default", "extended": False}, "app-only"),
        ({"scope": "app", "time": "default", "extended": True}, "app-extended"),
        ({"scope": "app", "time": "10y", "extended": False}, "app-10y"),
        ({"scope": "app", "time": "10y", "extended": True}, "app-10y-extended"),
    ],
)
def test_legacy_flavor_map_rows(kwargs, flavor):
    """Every row of VDB_LEGACY_FLAVOR_MAP resolves to its flavor, and the
    table holds exactly the tested rows."""
    assert resolve_vdb_flavor(**kwargs) == flavor
    assert VDB_LEGACY_FLAVOR_MAP[(kwargs["scope"], kwargs["time"], kwargs["extended"])] == flavor


def test_legacy_map_has_no_other_rows():
    assert len(VDB_LEGACY_FLAVOR_MAP) == 5


def test_legacy_defaults_resolve_to_full():
    assert resolve_vdb_flavor() == "full"


@pytest.mark.parametrize(
    "kwargs",
    [
        # A two-year window has no v7 flavor in any scope.
        {"scope": "app", "time": "2y", "extended": False},
        {"scope": "app", "time": "2y", "extended": True},
        {"scope": "app+os", "time": "2y", "extended": False},
        # App+OS has no 10-year or extended variant: those flavors are
        # app-scope only.
        {"scope": "app+os", "time": "10y", "extended": False},
        {"scope": "app+os", "time": "10y", "extended": True},
        {"scope": "app+os", "time": "default", "extended": True},
    ],
)
def test_combinations_without_a_flavor_are_rejected(kwargs):
    """The rejection names the flavors instead of silently mapping the
    selection onto a bigger or smaller database."""
    with pytest.raises(
        ValueError,
        match="Published flavors: full, app-only, app-extended, app-10y, app-10y-extended",
    ):
        resolve_vdb_flavor(**kwargs)


def test_invalid_scope_rejected():
    with pytest.raises(ValueError, match="Invalid scope"):
        resolve_vdb_flavor(scope="os")


def test_invalid_time_rejected():
    with pytest.raises(ValueError, match="Invalid time"):
        resolve_vdb_flavor(time="5y")


# ---------------------------------------------------------------------------
# Image URLs, resolved by vdb
# ---------------------------------------------------------------------------


def test_full_flavor_uses_vdb_default_url():
    """vdb resolves 'full' from VDB_DATABASE_URL, so env overrides keep working."""
    url = resolve_vdb_image_url(flavor="full")
    assert url == "ghcr.io/appthreat/vdb7-full:v7.0.x-xz"


def test_app_only_flavor_uses_vdb_app_url(monkeypatch):
    monkeypatch.delenv("VDB_DATABASE_URL", raising=False)
    monkeypatch.delenv("VDB_APP_ONLY_DATABASE_URL", raising=False)
    import vdb.lib.config as vdb_config

    monkeypatch.setattr(vdb_config, "VDB_DATABASE_URL", "ghcr.io/appthreat/vdb7-full:v7.0.x-xz")
    monkeypatch.setattr(
        vdb_config, "VDB_APP_ONLY_DATABASE_URL", "ghcr.io/appthreat/vdb7-app-only:v7.0.x-xz"
    )
    assert resolve_vdb_image_url(flavor="app-only") == "ghcr.io/appthreat/vdb7-app-only:v7.0.x-xz"


def test_non_env_flavor_follows_vdb_database_url_registry(monkeypatch):
    """The derived flavors inherit registry and tag from VDB_DATABASE_URL, so
    a mirror override applies to every flavor."""
    import vdb.lib.config as vdb_config

    monkeypatch.setattr(vdb_config, "VDB_DATABASE_URL", "mirror.example.com/vdb7-full:v7-xz")
    assert resolve_vdb_image_url(flavor="app-10y") == "mirror.example.com/vdb7-app-10y:v7-xz"


def test_zst_compression_swaps_the_tag_suffix():
    assert resolve_vdb_image_url(flavor="full", compression="zst").endswith(":v7.0.x-zst")
    assert resolve_vdb_image_url(flavor="full", compression="xz").endswith(":v7.0.x-xz")


def test_image_override_wins_verbatim():
    assert (
        resolve_vdb_image_url(flavor="full", image="registry.example.com/vdb:v1")
        == "registry.example.com/vdb:v1"
    )


def test_invalid_flavor_rejected():
    with pytest.raises(ValueError, match="Invalid flavor"):
        resolve_vdb_image_url(flavor="app-2y")


def test_invalid_compression_rejected():
    with pytest.raises(ValueError, match="Invalid compression"):
        resolve_vdb_image_url(flavor="full", compression="gz")


# ---------------------------------------------------------------------------
# Shard-set marker
# ---------------------------------------------------------------------------


def test_shards_marker_is_sorted_and_prefixed():
    assert vdb_shards_marker(["npm", "pypi"]) == "shards:npm,pypi"
    assert vdb_shards_marker(["pypi", "npm"]) == "shards:npm,pypi"
