"""Tests for depscan.cli helpers."""

import argparse
import os

import pytest

from depscan import cli
from depscan.cli_options import (
    DEFAULT_SPEC_VERSION,
    build_parser,
    validate_spec_version,
)


def test_validate_spec_version_accepts_supported():
    assert validate_spec_version("1.6") == "1.6"
    assert validate_spec_version("1.7") == "1.7"
    assert validate_spec_version(1.5) == "1.5"
    assert validate_spec_version("2.0") == "2.0"
    assert validate_spec_version(2) == "2.0"


@pytest.mark.parametrize("bad", ["1.10", "1.3", "3.0", "abc", "", None])
def test_validate_spec_version_rejects_unsupported(bad):
    with pytest.raises(argparse.ArgumentTypeError):
        validate_spec_version(bad)


def test_spec_version_defaults_to_1_6(monkeypatch):
    monkeypatch.delenv("CDX_SPEC_VERSION", raising=False)
    parser = build_parser()
    args = parser.parse_args([])
    assert args.spec_version == DEFAULT_SPEC_VERSION == "1.6"


def test_spec_version_cli_override():
    parser = build_parser()
    args = parser.parse_args(["--spec-version", "1.7"])
    assert args.spec_version == "1.7"


def test_spec_version_cli_rejects_bad(capsys):
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--spec-version", "9.9"])


def test_download_vdb_succeeds_first_attempt(monkeypatch):
    calls = []
    monkeypatch.setattr(cli, "download_image", lambda url, d: calls.append(url) or ["ok"])
    monkeypatch.setattr(cli.time, "sleep", lambda s: None)
    result = cli.download_vdb_with_retries("oras://x", "/tmp/d", attempts=3)
    assert result == ["ok"]
    assert len(calls) == 1


def test_download_vdb_retries_then_succeeds(monkeypatch):
    calls = []

    def flaky(url, d):
        calls.append(url)
        if len(calls) < 3:
            raise ConnectionError("Connection broken: IncompleteRead")
        return ["ok"]

    monkeypatch.setattr(cli, "download_image", flaky)
    monkeypatch.setattr(cli.time, "sleep", lambda s: None)
    result = cli.download_vdb_with_retries("oras://x", "/tmp/d", attempts=3)
    assert result == ["ok"]
    assert len(calls) == 3


def test_download_vdb_reraises_after_exhausting_attempts(monkeypatch):
    calls = []

    def always_fail(url, d):
        calls.append(url)
        raise ConnectionError("Connection broken")

    monkeypatch.setattr(cli, "download_image", always_fail)
    monkeypatch.setattr(cli.time, "sleep", lambda s: None)
    with pytest.raises(ConnectionError):
        cli.download_vdb_with_retries("oras://x", "/tmp/d", attempts=3)
    assert len(calls) == 3


def test_positive_int_env(monkeypatch):
    monkeypatch.setenv("DS_TEST_RETRIES", "7")
    assert cli._positive_int_env("DS_TEST_RETRIES", 3) == 7
    monkeypatch.setenv("DS_TEST_RETRIES", "0")
    assert cli._positive_int_env("DS_TEST_RETRIES", 3) == 3
    monkeypatch.setenv("DS_TEST_RETRIES", "notanint")
    assert cli._positive_int_env("DS_TEST_RETRIES", 3) == 3
    monkeypatch.delenv("DS_TEST_RETRIES", raising=False)
    assert cli._positive_int_env("DS_TEST_RETRIES", 3) == 3


# ---------------------------------------------------------------------------
# Change C: variant marker + forced re-download on mismatch
# ---------------------------------------------------------------------------


def test_vdb_download_needed_stale(monkeypatch):
    """needs_update=True should trigger download regardless of marker."""
    monkeypatch.setattr(cli.db_lib, "needs_update", lambda **kw: True)
    monkeypatch.setattr(cli, "read_vdb_image_marker", lambda d: "ghcr.io/appthreat/vdbxz:v6.7.x")
    should, reason = cli.vdb_download_needed("ghcr.io/appthreat/vdbxz:v6.7.x", "/tmp/d")
    assert should is True
    assert reason == "stale"


def test_vdb_download_needed_variant_change_forces_redownload(monkeypatch):
    """A variant mismatch forces re-download even when the DB is fresh."""
    monkeypatch.setattr(cli.db_lib, "needs_update", lambda **kw: False)
    monkeypatch.setattr(cli, "read_vdb_image_marker", lambda d: "ghcr.io/appthreat/vdbxz:v6.7.x")
    should, reason = cli.vdb_download_needed("ghcr.io/appthreat/vdbxz-extended:v6.7.x", "/tmp/d")
    assert should is True
    assert reason == "variant-change"


def test_vdb_download_needed_no_download_when_fresh_and_same_variant(monkeypatch):
    """Fresh DB with same variant should not trigger download."""
    monkeypatch.setattr(cli.db_lib, "needs_update", lambda **kw: False)
    monkeypatch.setattr(cli, "read_vdb_image_marker", lambda d: "ghcr.io/appthreat/vdbxz:v6.7.x")
    should, reason = cli.vdb_download_needed("ghcr.io/appthreat/vdbxz:v6.7.x", "/tmp/d")
    assert should is False
    assert reason is None


def test_vdb_download_needed_no_marker_does_not_force(monkeypatch):
    """No marker at all (first run or pre-feature) should rely on needs_update only."""
    monkeypatch.setattr(cli.db_lib, "needs_update", lambda **kw: False)
    monkeypatch.setattr(cli, "read_vdb_image_marker", lambda d: None)
    should, reason = cli.vdb_download_needed("ghcr.io/appthreat/vdbxz:v6.7.x", "/tmp/d")
    assert should is False
    assert reason is None


# ---------------------------------------------------------------------------
# Change D: scan-time resolver + auto-extended for --severity
# ---------------------------------------------------------------------------


def _make_args(severity=None, deep_scan=False, src_dir_image=".", bom_dir=None, **vdb):
    """Build a lightweight args namespace for resolve_scan_vdb_image tests.

    ``vdb`` accepts the vdb-selection options (vdb_scope, vdb_time,
    vdb_extended, vdb_compression, vdb_distro, vdb_image); unset ones default to
    None so the resolver falls back to its defaults / env, matching how tomlparse
    leaves unset config keys.
    """
    import argparse

    fields = {
        "severity": severity,
        "deep_scan": deep_scan,
        "src_dir_image": src_dir_image,
        "bom_dir": bom_dir,
        "vdb_scope": None,
        "vdb_time": None,
        "vdb_extended": None,
        "vdb_compression": None,
        "vdb_distro": None,
        "vdb_image": None,
    }
    fields.update(vdb)
    return argparse.Namespace(**fields)


def test_resolve_scan_default_no_severity(monkeypatch):
    """No severity, no env vars -> default app+os standard xz."""
    monkeypatch.delenv("VDB_DATABASE_URL", raising=False)
    monkeypatch.delenv("USE_VDB_10Y", raising=False)
    monkeypatch.delenv("VDB_INCLUDE_METADATA", raising=False)
    args = _make_args()
    url, pinned = cli.resolve_scan_vdb_image(args)
    assert url == "ghcr.io/appthreat/vdbxz:v6.7.x"
    assert pinned is False
    assert os.getenv("VDB_INCLUDE_METADATA") is None


def test_resolve_scan_severity_auto_extended(monkeypatch):
    """--severity with no explicit pin -> extended image + VDB_INCLUDE_METADATA."""
    monkeypatch.delenv("VDB_DATABASE_URL", raising=False)
    monkeypatch.delenv("USE_VDB_10Y", raising=False)
    monkeypatch.delenv("VDB_INCLUDE_METADATA", raising=False)
    args = _make_args(severity="high")
    url, pinned = cli.resolve_scan_vdb_image(args)
    assert url == "ghcr.io/appthreat/vdbxz-extended:v6.7.x"
    assert pinned is False
    assert os.getenv("VDB_INCLUDE_METADATA") == "true"


def test_resolve_scan_explicit_url_not_overridden(monkeypatch):
    """VDB_DATABASE_URL pin is respected verbatim even with --severity."""
    monkeypatch.setenv("VDB_DATABASE_URL", "ghcr.io/appthreat/vdbxz-app:v6.7.x")
    monkeypatch.delenv("VDB_INCLUDE_METADATA", raising=False)
    args = _make_args(severity="high")
    url, pinned = cli.resolve_scan_vdb_image(args)
    assert url == "ghcr.io/appthreat/vdbxz-app:v6.7.x"
    assert pinned is True
    # VDB_INCLUDE_METADATA should NOT be set by depscan for a pinned image
    assert os.getenv("VDB_INCLUDE_METADATA") is None


def test_resolve_scan_use_vdb_10y(monkeypatch):
    """USE_VDB_10Y maps to time=10y."""
    monkeypatch.delenv("VDB_DATABASE_URL", raising=False)
    monkeypatch.setenv("USE_VDB_10Y", "true")
    monkeypatch.delenv("VDB_INCLUDE_METADATA", raising=False)
    args = _make_args()
    url, pinned = cli.resolve_scan_vdb_image(args)
    assert url == "ghcr.io/appthreat/vdbxz-10y:v6.7.x"
    assert pinned is False


def test_resolve_scan_use_vdb_10y_with_severity(monkeypatch):
    """USE_VDB_10Y + --severity -> 10y extended."""
    monkeypatch.delenv("VDB_DATABASE_URL", raising=False)
    monkeypatch.setenv("USE_VDB_10Y", "true")
    monkeypatch.delenv("VDB_INCLUDE_METADATA", raising=False)
    args = _make_args(severity="critical")
    url, pinned = cli.resolve_scan_vdb_image(args)
    assert url == "ghcr.io/appthreat/vdbxz-10y-extended:v6.7.x"
    assert pinned is False
    assert os.getenv("VDB_INCLUDE_METADATA") == "true"


# --- vdb-selection options persisted via CLI/config (tomlparse) -----------


def _clean_vdb_env(monkeypatch):
    monkeypatch.delenv("VDB_DATABASE_URL", raising=False)
    monkeypatch.delenv("USE_VDB_10Y", raising=False)
    monkeypatch.delenv("VDB_INCLUDE_METADATA", raising=False)


def test_resolve_scan_config_scope_app(monkeypatch):
    """A persisted vdb_scope=app resolves the app-only image."""
    _clean_vdb_env(monkeypatch)
    url, pinned = cli.resolve_scan_vdb_image(_make_args(vdb_scope="app"))
    assert url == "ghcr.io/appthreat/vdbxz-app:v6.7.x"
    assert pinned is False


def test_resolve_scan_config_extended_and_compression(monkeypatch):
    """Persisted vdb_extended + vdb_compression compose, and extended sets metadata."""
    _clean_vdb_env(monkeypatch)
    url, pinned = cli.resolve_scan_vdb_image(
        _make_args(vdb_scope="app", vdb_extended=True, vdb_compression="zst")
    )
    assert url == "ghcr.io/appthreat/vdbzst-app-extended:v6.7.x"
    assert os.getenv("VDB_INCLUDE_METADATA") == "true"


def test_resolve_scan_config_time_overrides_use_vdb_10y(monkeypatch):
    """An explicit vdb_time wins over USE_VDB_10Y."""
    _clean_vdb_env(monkeypatch)
    monkeypatch.setenv("USE_VDB_10Y", "true")
    url, _ = cli.resolve_scan_vdb_image(_make_args(vdb_time="2y", vdb_scope="app"))
    assert url == "ghcr.io/appthreat/vdbxz-app-2y:v6.7.x"


def test_resolve_scan_config_distro(monkeypatch):
    """A persisted vdb_distro resolves the distro-only image."""
    _clean_vdb_env(monkeypatch)
    url, pinned = cli.resolve_scan_vdb_image(_make_args(vdb_distro="ubuntu"))
    assert url == "ghcr.io/appthreat/vdbxz-ubuntu:v6.7.x"
    assert pinned is False


def test_resolve_scan_vdb_image_pin_verbatim(monkeypatch):
    """--vdb-image (or config vdb_image) is used verbatim and marked pinned."""
    _clean_vdb_env(monkeypatch)
    url, pinned = cli.resolve_scan_vdb_image(
        _make_args(vdb_image="ghcr.io/me/custom:1", vdb_scope="app")
    )
    assert url == "ghcr.io/me/custom:1"
    assert pinned is True


def test_resolve_scan_env_pin_beats_config(monkeypatch):
    """VDB_DATABASE_URL env pin wins over persisted vdb_scope."""
    _clean_vdb_env(monkeypatch)
    monkeypatch.setenv("VDB_DATABASE_URL", "ghcr.io/appthreat/vdbxz-extended:v6.7.x")
    url, pinned = cli.resolve_scan_vdb_image(_make_args(vdb_scope="app"))
    assert url == "ghcr.io/appthreat/vdbxz-extended:v6.7.x"
    assert pinned is True
