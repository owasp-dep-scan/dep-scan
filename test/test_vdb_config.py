"""Exhaustive tests for resolve_vdb_image and vdb_image_size (T7 Change A)."""

import pytest

from depscan.lib.config import (
    VDB_IMAGE_TAG,
    resolve_vdb_image,
    vdb_image_size,
)

REG = "ghcr.io/appthreat"
TAG = "v6.7.x"


# ---------------------------------------------------------------------------
# App/OS matrix -- every cell in both compressions
# ---------------------------------------------------------------------------

APPOS_CASES = [
    # (kwargs, expected_repo)
    # App scope
    ({"scope": "app", "time": "2y", "extended": False, "compression": "xz"}, "vdbxz-app-2y"),
    (
        {"scope": "app", "time": "2y", "extended": True, "compression": "xz"},
        "vdbxz-app-2y-extended",
    ),
    ({"scope": "app", "time": "default", "extended": False, "compression": "xz"}, "vdbxz-app"),
    (
        {"scope": "app", "time": "default", "extended": True, "compression": "xz"},
        "vdbxz-app-extended",
    ),
    ({"scope": "app", "time": "10y", "extended": False, "compression": "xz"}, "vdbxz-app-10y"),
    (
        {"scope": "app", "time": "10y", "extended": True, "compression": "xz"},
        "vdbxz-app-10y-extended",
    ),
    # App+OS scope (no 2y)
    ({"scope": "app+os", "time": "default", "extended": False, "compression": "xz"}, "vdbxz"),
    (
        {"scope": "app+os", "time": "default", "extended": True, "compression": "xz"},
        "vdbxz-extended",
    ),
    ({"scope": "app+os", "time": "10y", "extended": False, "compression": "xz"}, "vdbxz-10y"),
    (
        {"scope": "app+os", "time": "10y", "extended": True, "compression": "xz"},
        "vdbxz-10y-extended",
    ),
]

# zst variants: swap vdbxz -> vdbzst
APP_ZST_CASES = [
    ({"scope": "app", "time": "2y", "extended": False, "compression": "zst"}, "vdbzst-app-2y"),
    (
        {"scope": "app", "time": "2y", "extended": True, "compression": "zst"},
        "vdbzst-app-2y-extended",
    ),
    ({"scope": "app", "time": "default", "extended": False, "compression": "zst"}, "vdbzst-app"),
    (
        {"scope": "app", "time": "default", "extended": True, "compression": "zst"},
        "vdbzst-app-extended",
    ),
    ({"scope": "app", "time": "10y", "extended": False, "compression": "zst"}, "vdbzst-app-10y"),
    (
        {"scope": "app", "time": "10y", "extended": True, "compression": "zst"},
        "vdbzst-app-10y-extended",
    ),
    ({"scope": "app+os", "time": "default", "extended": False, "compression": "zst"}, "vdbzst"),
    (
        {"scope": "app+os", "time": "default", "extended": True, "compression": "zst"},
        "vdbzst-extended",
    ),
    ({"scope": "app+os", "time": "10y", "extended": False, "compression": "zst"}, "vdbzst-10y"),
    (
        {"scope": "app+os", "time": "10y", "extended": True, "compression": "zst"},
        "vdbzst-10y-extended",
    ),
]

ALL_VALID = APPOS_CASES + APP_ZST_CASES


@pytest.mark.parametrize("kwargs, repo", ALL_VALID)
def test_resolve_vdb_image_valid(kwargs, repo):
    expected = f"{REG}/{repo}:{TAG}"
    assert resolve_vdb_image(**kwargs) == expected


# ---------------------------------------------------------------------------
# Default args: zero-flag default is App+OS default standard xz
# ---------------------------------------------------------------------------


def test_resolve_vdb_image_defaults():
    assert resolve_vdb_image() == f"{REG}/vdbxz:{TAG}"


# ---------------------------------------------------------------------------
# default-no-segment rule
# ---------------------------------------------------------------------------


def test_default_time_adds_no_segment():
    # app, default -> vdbxz-app (no time infix)
    assert resolve_vdb_image(scope="app", time="default") == f"{REG}/vdbxz-app:{TAG}"


def test_non_default_time_adds_segment():
    assert resolve_vdb_image(scope="app", time="2y") == f"{REG}/vdbxz-app-2y:{TAG}"
    assert resolve_vdb_image(scope="app", time="10y") == f"{REG}/vdbxz-app-10y:{TAG}"


# ---------------------------------------------------------------------------
# App+OS -app drop
# ---------------------------------------------------------------------------


def test_app_os_drops_app_infix():
    assert resolve_vdb_image(scope="app+os") == f"{REG}/vdbxz:{TAG}"
    assert resolve_vdb_image(scope="app+os", extended=True) == f"{REG}/vdbxz-extended:{TAG}"


# ---------------------------------------------------------------------------
# Distro images -- all six, both compressions
# ---------------------------------------------------------------------------

DISTROS = ["alpine", "debian", "redhat", "alma", "rocky", "ubuntu"]


@pytest.mark.parametrize("distro", DISTROS)
@pytest.mark.parametrize("compression", ["xz", "zst"])
def test_resolve_distro_images(distro, compression):
    prefix = "vdbxz" if compression == "xz" else "vdbzst"
    expected = f"{REG}/{prefix}-{distro}:{TAG}"
    assert resolve_vdb_image(distro=distro, compression=compression) == expected


def test_resolve_distro_default_compression_is_xz():
    assert resolve_vdb_image(distro="ubuntu") == f"{REG}/vdbxz-ubuntu:{TAG}"


# ---------------------------------------------------------------------------
# Tag override
# ---------------------------------------------------------------------------


def test_tag_override():
    url = resolve_vdb_image(tag="stable")
    assert url.endswith(":stable")


def test_vdb_image_tag_default():
    assert VDB_IMAGE_TAG == "v6.7.x"


# ---------------------------------------------------------------------------
# Rejected combinations
# ---------------------------------------------------------------------------


def test_reject_app_os_2y():
    with pytest.raises(ValueError, match="App\\+OS has no 2y"):
        resolve_vdb_image(scope="app+os", time="2y")


def test_reject_distro_with_scope():
    with pytest.raises(ValueError, match="mutually exclusive"):
        resolve_vdb_image(distro="ubuntu", scope="app")


def test_reject_distro_with_time():
    with pytest.raises(ValueError, match="mutually exclusive"):
        resolve_vdb_image(distro="ubuntu", time="10y")


def test_reject_distro_with_extended():
    with pytest.raises(ValueError, match="mutually exclusive"):
        resolve_vdb_image(distro="ubuntu", extended=True)


def test_reject_invalid_scope():
    with pytest.raises(ValueError, match="Invalid scope"):
        resolve_vdb_image(scope="os")


def test_reject_invalid_time():
    with pytest.raises(ValueError, match="Invalid time"):
        resolve_vdb_image(time="5y")


def test_reject_invalid_compression():
    with pytest.raises(ValueError, match="Invalid compression"):
        resolve_vdb_image(compression="gz")


def test_reject_invalid_distro():
    with pytest.raises(ValueError, match="Invalid distro"):
        resolve_vdb_image(distro="fedora")


# ---------------------------------------------------------------------------
# Spot checks from the plan
# ---------------------------------------------------------------------------


def test_spot_checks():
    assert (
        resolve_vdb_image(scope="app", time="2y", extended=True)
        == f"{REG}/vdbxz-app-2y-extended:{TAG}"
    )
    assert resolve_vdb_image(scope="app+os", time="default") == f"{REG}/vdbxz:{TAG}"
    assert (
        resolve_vdb_image(scope="app+os", time="10y", extended=True)
        == f"{REG}/vdbxz-10y-extended:{TAG}"
    )
    assert resolve_vdb_image(scope="app", compression="zst") == f"{REG}/vdbzst-app:{TAG}"
    assert resolve_vdb_image(distro="ubuntu") == f"{REG}/vdbxz-ubuntu:{TAG}"


# ---------------------------------------------------------------------------
# vdb_image_size
# ---------------------------------------------------------------------------


def test_vdb_image_size_full_ref():
    assert vdb_image_size(f"{REG}/vdbxz:{TAG}") == "42.36 GiB"


def test_vdb_image_size_repo_only():
    assert vdb_image_size("vdbxz-app-2y") == "2.05 GiB"


def test_vdb_image_size_unknown():
    assert vdb_image_size("vdbxz-does-not-exist") == "unknown"


def test_vdb_image_size_distro():
    assert vdb_image_size(f"{REG}/vdbxz-ubuntu:{TAG}") == "31.78 GiB"


def test_vdb_image_size_normalizes_extended():
    # Uncompressed data size is identical for standard and extended tiers.
    assert vdb_image_size(f"{REG}/vdbxz-extended:{TAG}") == "42.36 GiB"
    assert vdb_image_size("vdbxz-app-extended") == "2.96 GiB"
    assert vdb_image_size("vdbxz-app-10y-extended") == "3.52 GiB"


def test_vdb_image_size_normalizes_zst():
    # zst images have the same uncompressed data size as their xz counterparts.
    assert vdb_image_size(f"{REG}/vdbzst:{TAG}") == "42.36 GiB"
    assert vdb_image_size("vdbzst-app") == "2.96 GiB"
    assert vdb_image_size("vdbzst-ubuntu") == "31.78 GiB"
    assert vdb_image_size("vdbzst-app-10y-extended") == "3.52 GiB"
