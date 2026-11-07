#!/usr/bin/env python3
"""
Version-consistency gate for depscan SEA builds.

Asserts that all sources of truth for the depscan version (and the bundled
cdxgen version) agree before any platform workflow spends build minutes on
PyInstaller or downloads the cdxgen SEA.

Sources checked:
  1. pyproject.toml              :: [project] version  (e.g. "6.3.0")
  2. build/assets/file_version_info.txt  :: filevers/prodvers tuple + FileVersion string
  3. build/assets/Info.plist     :: CFBundleVersion
  4. git tag (on tag push only)  :: refs/tags/v6.3.0  -> 6.3.0
  5. CDXGEN_SEA_VERSION env var  :: must equal CDXGEN_IMAGE_VERSION default
                                    in packages/xbom-lib/src/xbom_lib/cdxgen.py,
                                    ignoring a leading "v" (the SEA release
                                    tag is "v12.9.1", the image tag "12.9.1")

Exits 0 on full agreement, 1 on any mismatch. Prints a clear diff-style
report so the operator knows exactly what to update.

Usage:
    python3 build/sea-hooks/verify_versions.py

    # On a tag push, the workflow also exports GITHUB_REF so the script
    # can assert the tag matches:
    GITHUB_REF=refs/tags/v6.3.0 python3 build/sea-hooks/verify_versions.py
"""

from __future__ import annotations

import os
import plistlib
import re
import sys
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

PYPROJECT_PATH = REPO_ROOT / "pyproject.toml"
FILE_VERSION_INFO_PATH = REPO_ROOT / "build" / "assets" / "file_version_info.txt"
INFO_PLIST_PATH = REPO_ROOT / "build" / "assets" / "Info.plist"
CDXGEN_PY_PATH = REPO_ROOT / "packages" / "xbom-lib" / "src" / "xbom_lib" / "cdxgen.py"


def _read_pyproject_version() -> str:
    with PYPROJECT_PATH.open("rb") as f:
        data = tomllib.load(f)
    version = data.get("project", {}).get("version")
    if not version:
        raise AssertionError(f"No [project].version in {PYPROJECT_PATH}")
    return str(version)


def _read_file_version_info_version() -> str:
    text = FILE_VERSION_INFO_PATH.read_text(encoding="utf-8")
    # filevers=(6,3,0,0)  -> 6.3.0
    m = re.search(r"filevers\s*=\s*\((\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\)", text)
    if not m:
        raise AssertionError(
            f"Could not find filevers tuple in {FILE_VERSION_INFO_PATH}"
        )
    major, minor, patch, _build = m.groups()
    return f"{major}.{minor}.{patch}"


def _read_info_plist_version() -> str:
    with INFO_PLIST_PATH.open("rb") as f:
        data = plistlib.load(f)
    version = data.get("CFBundleVersion")
    if not version:
        raise AssertionError(f"No CFBundleVersion in {INFO_PLIST_PATH}")
    return str(version)


def _read_cdxgen_image_version_default() -> str:
    """Return the default value of CDXGEN_IMAGE_VERSION from xbom_lib/cdxgen.py.

    The line looks like:
        CDXGEN_IMAGE_VERSION = os.getenv("CDXGEN_IMAGE_VERSION", "12.9.1")
    We extract the second argument to os.getenv.
    """
    text = CDXGEN_PY_PATH.read_text(encoding="utf-8")
    m = re.search(
        r'CDXGEN_IMAGE_VERSION\s*=\s*os\.getenv\(\s*"CDXGEN_IMAGE_VERSION"\s*,\s*"([^"]+)"\s*\)',
        text,
    )
    if not m:
        raise AssertionError(
            f"Could not find CDXGEN_IMAGE_VERSION default in {CDXGEN_PY_PATH}"
        )
    return m.group(1)


def _strip_v(version: str) -> str:
    """Drop a leading "v" so a git tag and a container image tag compare equal."""
    return version[1:] if version.startswith("v") else version


def _read_git_tag() -> str | None:
    """If running under a tag push, return the bare tag name (e.g. 'v6.3.0')."""
    ref = os.environ.get("GITHUB_REF", "")
    if not ref.startswith("refs/tags/"):
        return None
    return ref[len("refs/tags/") :]


def main() -> int:
    errors: list[str] = []

    pyproject_version = _read_pyproject_version()
    file_version_info_version = _read_file_version_info_version()
    info_plist_version = _read_info_plist_version()
    cdxgen_image_version = _read_cdxgen_image_version_default()
    cdxgen_sea_version = os.environ.get("CDXGEN_SEA_VERSION", "")
    git_tag = _read_git_tag()

    print("=" * 72)
    print("depscan SEA version-consistency report")
    print("=" * 72)
    print(f"  pyproject.toml [project].version       : {pyproject_version}")
    print(f"  build/assets/file_version_info.txt     : {file_version_info_version}")
    print(f"  build/assets/Info.plist CFBundleVersion: {info_plist_version}")
    if git_tag:
        print(f"  git tag (GITHUB_REF)                   : {git_tag}")
    else:
        print("  git tag (GITHUB_REF)                   : (not a tag push)")
    print(
        f"  CDXGEN_IMAGE_VERSION default (xbom_lib) : {cdxgen_image_version}"
    )
    print(
        f"  CDXGEN_SEA_VERSION env (workflow)       : "
        f"{cdxgen_sea_version or '(not set)'}"
    )
    print("-" * 72)

    # Check 1: all depscan version sources agree
    depscan_sources = {
        "pyproject.toml": pyproject_version,
        "file_version_info.txt": file_version_info_version,
        "Info.plist": info_plist_version,
    }
    unique_depscan_versions = set(depscan_sources.values())
    if len(unique_depscan_versions) > 1:
        errors.append(
            "depscan version mismatch across sources:\n"
            + "\n".join(
                f"    {src}: {ver}" for src, ver in depscan_sources.items()
            )
        )

    # Check 2: on tag push, the bare tag (minus optional 'v' prefix) matches
    if git_tag:
        tag_version = git_tag[1:] if git_tag.startswith("v") else git_tag
        if tag_version != pyproject_version:
            errors.append(
                f"git tag {git_tag!r} (parsed version {tag_version!r}) does not "
                f"match pyproject.toml version {pyproject_version!r}"
            )

    # Check 3: cdxgen publishes exact image versions as bare "X.Y.Z" tags; a
    # "vX.Y.Z" image tag does not exist, so such a default could not be pulled.
    if not re.fullmatch(r"\d+\.\d+\.\d+", cdxgen_image_version):
        errors.append(
            f"CDXGEN_IMAGE_VERSION default {cdxgen_image_version!r} in "
            "packages/xbom-lib/src/xbom_lib/cdxgen.py must be a bare X.Y.Z "
            "version such as '12.9.1', which is how cdxgen tags its images"
        )

    # Check 4: CDXGEN_SEA_VERSION (workflow) matches CDXGEN_IMAGE_VERSION
    # (source). The workflow env var is the source of truth for which cdxgen
    # SEA binary gets downloaded; xbom_lib is the source of truth for which
    # cdxgen container image gets used at runtime. They MUST agree, otherwise
    # the bundled cdxgen and the fallback container would be different
    # versions. The SEA is downloaded from the "v12.9.1" release while the
    # images are tagged "12.9.1", so the comparison ignores a leading "v".
    if cdxgen_sea_version:
        if _strip_v(cdxgen_sea_version) != _strip_v(cdxgen_image_version):
            errors.append(
                f"CDXGEN_SEA_VERSION {cdxgen_sea_version!r} (workflow env) does "
                f"not match CDXGEN_IMAGE_VERSION default {cdxgen_image_version!r} "
                f"in packages/xbom-lib/src/xbom_lib/cdxgen.py"
            )

    if errors:
        print("RESULT: FAIL")
        for err in errors:
            print(f"  ERROR: {err}")
        print()
        print(
            "Fix the mismatches above before building. Common fixes:\n"
            "  - bump pyproject.toml version + run 'uv lock'\n"
            "  - update build/assets/file_version_info.txt filevers/prodvers\n"
            "  - update build/assets/Info.plist CFBundleVersion\n"
            "  - update CDXGEN_SEA_VERSION in .github/workflows/sea-*.yml\n"
            "  - update CDXGEN_IMAGE_VERSION default in xbom_lib/cdxgen.py"
        )
        return 1

    print("RESULT: PASS  (all depscan + cdxgen versions agree)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
