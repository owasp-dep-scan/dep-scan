"""Exhaustive tests for resolve_vdb_image and vdb_image_size."""

import pytest

from depscan.lib.config import (
    VDB_IMAGE_TAG,
    resolve_vdb_image,
    vdb_image_size,
)

REG = "ghcr.io/appthreat"
TAG = "v7.0.x"


# ---------------------------------------------------------------------------
# The five published flavors, in both compressions
# ---------------------------------------------------------------------------

FLAVOR_CASES = [
    # (kwargs, expected_flavor)
    ({"scope": "app+os", "time": "default", "extended": False}, "full"),
    ({"scope": "app", "time": "default", "extended": False}, "app-only"),
    ({"scope": "app", "time": "default", "extended": True}, "app-extended"),
    ({"scope": "app", "time": "10y", "extended": False}, "app-10y"),
    ({"scope": "app", "time": "10y", "extended": True}, "app-10y-extended"),
]

ALL_VALID = [
    (dict(kwargs, compression=compression), flavor)
    for kwargs, flavor in FLAVOR_CASES
    for compression in ("xz", "zst")
]


@pytest.mark.parametrize("kwargs, flavor", ALL_VALID)
def test_resolve_vdb_image_valid(kwargs, flavor):
    compression = kwargs["compression"]
    expected = f"{REG}/vdb7-{flavor}:{TAG}-{compression}"
    assert resolve_vdb_image(**kwargs) == expected


# ---------------------------------------------------------------------------
# Default args: zero-flag default is the full app+OS flavor, xz
# ---------------------------------------------------------------------------


def test_resolve_vdb_image_defaults():
    assert resolve_vdb_image() == f"{REG}/vdb7-full:{TAG}-xz"


def test_default_time_adds_no_segment():
    # app, default -> app-only (no time infix in the flavor name)
    assert resolve_vdb_image(scope="app", time="default") == f"{REG}/vdb7-app-only:{TAG}-xz"


def test_non_default_time_adds_segment():
    assert resolve_vdb_image(scope="app", time="10y") == f"{REG}/vdb7-app-10y:{TAG}-xz"


def test_compression_selects_the_tag_suffix():
    assert resolve_vdb_image(scope="app", compression="zst") == f"{REG}/vdb7-app-only:{TAG}-zst"


# ---------------------------------------------------------------------------
# Distro images: v7 publishes none
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("distro", ["alpine", "debian", "redhat", "alma", "rocky", "ubuntu"])
def test_resolve_distro_images_are_rejected(distro):
    with pytest.raises(ValueError, match="no per-distro complete database"):
        resolve_vdb_image(distro=distro)


def test_reject_unknown_distro_name():
    with pytest.raises(ValueError, match="Invalid distro"):
        resolve_vdb_image(distro="fedora")


# ---------------------------------------------------------------------------
# Tag override
# ---------------------------------------------------------------------------


def test_tag_override():
    url = resolve_vdb_image(tag="v7")
    assert url == f"{REG}/vdb7-full:v7-xz"


def test_vdb_image_tag_default():
    assert VDB_IMAGE_TAG == "v7.0.x"


# ---------------------------------------------------------------------------
# Rejected combinations: no v7 flavor exists, and the message names the flavors
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "kwargs",
    [
        # A two-year window has no v7 flavor in any scope.
        {"scope": "app", "time": "2y"},
        {"scope": "app", "time": "2y", "extended": True},
        {"scope": "app+os", "time": "2y"},
        # App+OS has no 10-year or extended variant: those flavors are
        # app-scope only.
        {"scope": "app+os", "time": "10y"},
        {"scope": "app+os", "time": "10y", "extended": True},
        {"scope": "app+os", "time": "default", "extended": True},
    ],
)
def test_reject_combinations_without_a_flavor(kwargs):
    with pytest.raises(
        ValueError,
        match="Published flavors: full, app-only, app-extended, app-10y, app-10y-extended",
    ):
        resolve_vdb_image(**kwargs)


def test_reject_invalid_scope():
    with pytest.raises(ValueError, match="Invalid scope"):
        resolve_vdb_image(scope="os")


def test_reject_invalid_time():
    with pytest.raises(ValueError, match="Invalid time"):
        resolve_vdb_image(time="5y")


def test_reject_invalid_compression():
    with pytest.raises(ValueError, match="Invalid compression"):
        resolve_vdb_image(compression="gz")


# ---------------------------------------------------------------------------
# vdb_image_size: the table keeps the v6-era figures; v7 names answer unknown
# ---------------------------------------------------------------------------


def test_vdb_image_size_full_ref():
    assert vdb_image_size(f"{REG}/vdbxz:v6.7.x") == "42.36 GiB"


def test_vdb_image_size_repo_only():
    assert vdb_image_size("vdbxz-app-2y") == "2.05 GiB"


def test_vdb_image_size_unknown():
    assert vdb_image_size("vdbxz-does-not-exist") == "unknown"


def test_vdb_image_size_unknown_for_v7_flavors():
    # No v7 numbers are in the table yet; the coarse warning stays quiet
    # rather than inventing a figure.
    assert vdb_image_size(f"{REG}/vdb7-full:{TAG}-xz") == "unknown"
    assert vdb_image_size(f"{REG}/vdb7-app-only:{TAG}-zst") == "unknown"


def test_vdb_image_size_normalizes_extended():
    # Uncompressed data size is identical for standard and extended tiers.
    assert vdb_image_size(f"{REG}/vdbxz-extended:v6.7.x") == "42.36 GiB"
    assert vdb_image_size("vdbxz-app-extended") == "2.96 GiB"
    assert vdb_image_size("vdbxz-app-10y-extended") == "3.52 GiB"


def test_vdb_image_size_normalizes_zst():
    # zst images have the same uncompressed data size as their xz counterparts.
    assert vdb_image_size(f"{REG}/vdbzst:v6.7.x") == "42.36 GiB"
    assert vdb_image_size("vdbzst-app") == "2.96 GiB"
    assert vdb_image_size("vdbzst-ubuntu") == "31.78 GiB"
    assert vdb_image_size("vdbzst-app-10y-extended") == "3.52 GiB"
