"""Tests for the CLI parser and the database setup helpers."""

import argparse
import ast
import os
from pathlib import Path

import pytest

from depscan.cli_options import (
    DEFAULT_SPEC_VERSION,
    build_parser,
    validate_spec_version,
)
from depscan.lib import vdb_setup


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
    """The download goes through vdb's refresh_full_image with the resolved
    image URL (positive control: one call, the right argument)."""
    from vdb.lib import db_cmd

    calls = []
    monkeypatch.setattr(
        db_cmd, "refresh_full_image", lambda image_url: calls.append(image_url) or {"ok": True}
    )
    monkeypatch.setattr(vdb_setup.time, "sleep", lambda s: None)
    result = vdb_setup.download_vdb_with_retries(
        "ghcr.io/appthreat/vdb7-full:v7.0.x-xz", attempts=3
    )
    assert result == {"ok": True}
    assert calls == ["ghcr.io/appthreat/vdb7-full:v7.0.x-xz"]


def test_download_vdb_retries_then_succeeds(monkeypatch):
    from vdb.lib import db_cmd

    calls = []

    def flaky(image_url):
        calls.append(image_url)
        if len(calls) < 3:
            raise ConnectionError("Connection broken: IncompleteRead")
        return {"ok": True}

    monkeypatch.setattr(db_cmd, "refresh_full_image", flaky)
    monkeypatch.setattr(vdb_setup.time, "sleep", lambda s: None)
    result = vdb_setup.download_vdb_with_retries("oras://x", attempts=3)
    assert result == {"ok": True}
    assert len(calls) == 3


def test_download_vdb_reraises_after_exhausting_attempts(monkeypatch):
    from vdb.lib import db_cmd

    calls = []

    def always_fail(image_url):
        calls.append(image_url)
        raise ConnectionError("Connection broken")

    monkeypatch.setattr(db_cmd, "refresh_full_image", always_fail)
    monkeypatch.setattr(vdb_setup.time, "sleep", lambda s: None)
    with pytest.raises(ConnectionError):
        vdb_setup.download_vdb_with_retries("oras://x", attempts=3)
    assert len(calls) == 3


def test_positive_int_env(monkeypatch):
    monkeypatch.setenv("DS_TEST_RETRIES", "7")
    assert vdb_setup._positive_int_env("DS_TEST_RETRIES", 3) == 7
    monkeypatch.setenv("DS_TEST_RETRIES", "0")
    assert vdb_setup._positive_int_env("DS_TEST_RETRIES", 3) == 3
    monkeypatch.setenv("DS_TEST_RETRIES", "notanint")
    assert vdb_setup._positive_int_env("DS_TEST_RETRIES", 3) == 3
    monkeypatch.delenv("DS_TEST_RETRIES", raising=False)
    assert vdb_setup._positive_int_env("DS_TEST_RETRIES", 3) == 3


# ---------------------------------------------------------------------------
# Empty or unreadable database: the scan must stop, never report zero findings
# ---------------------------------------------------------------------------


@pytest.fixture
def vdb_home(tmp_path, monkeypatch):
    """An isolated VDB_HOME; vdb's config captured the import-time paths, so
    they are patched alongside the environment.

    The directory is resolved because vdb opens its databases with
    SQLITE_OPEN_NOFOLLOW, which refuses a path that crosses a symlinked
    directory (macOS keeps its temp dirs behind the /var -> /private/var
    symlink).
    """
    home = tmp_path.resolve() / "vdb-home"
    home.mkdir()
    # Widen vdb's console so the directory path is not wrapped mid-token.
    monkeypatch.setenv("COLUMNS", "4096")
    monkeypatch.setenv("VDB_HOME", str(home))
    monkeypatch.setattr(vdb_setup.config, "DATA_DIR", str(home))
    monkeypatch.setattr(vdb_setup.config, "VDB_BIN_FILE", str(home / "data.vdb7"))
    monkeypatch.setattr(vdb_setup.config, "VDB_BIN_INDEX", str(home / "data.index.vdb7"))
    yield home
    vdb_setup.db_lib.reset_connections()


def test_ensure_vdb_usable_stops_on_missing_database(vdb_home, capsys):
    """An unbuilt VDB_HOME must fail the scan with the directory named and a
    way to get a database, not answer with zero findings."""
    with pytest.raises(vdb_setup.VdbUnusableError):
        vdb_setup.ensure_vdb_usable()
    out = " ".join(capsys.readouterr().out.split())
    assert str(vdb_home) in out
    assert "vdb db refresh full" in out


def test_ensure_vdb_usable_stops_on_v6_only_database(vdb_home, capsys):
    """vdb 7 does not read .vdb6 files, so a directory holding only v6
    artifacts is an empty database and the scan stops; vdb's guard names the
    legacy files."""
    (vdb_home / "data.vdb6").write_text("")
    (vdb_home / "data.index.vdb6").write_text("")
    with pytest.raises(vdb_setup.VdbUnusableError):
        vdb_setup.ensure_vdb_usable()
    out = " ".join(capsys.readouterr().out.split())
    assert str(vdb_home) in out
    assert "Found v6 database files (data.vdb6, data.index.vdb6)" in out


def test_ensure_vdb_usable_stops_on_zero_row_database(vdb_home, capsys):
    """A schema-valid v7 database with no rows answers nothing; the scan must
    stop instead of looking like a clean result."""
    vdb_setup.db_lib.get()  # create the v7 files with their schema
    assert (vdb_home / "data.vdb7").is_file()
    assert vdb_setup.db_lib.stats() == (0, 0)
    vdb_setup.db_lib.reset_connections()
    with pytest.raises(vdb_setup.VdbUnusableError):
        vdb_setup.ensure_vdb_usable()
    out = " ".join(capsys.readouterr().out.split())
    assert str(vdb_home) in out
    assert "is empty" in out


def test_ensure_vdb_usable_passes_with_rows(vdb_home):
    """Positive control: one index row is a usable database and the guard
    returns without exiting."""
    _, index_conn = vdb_setup.db_lib.get()
    index_conn.execute(
        "INSERT INTO cve_index(cve_id, type, namespace, name, vers, purl_prefix) "
        "VALUES('CVE-2024-1', 'pypi', '', 'requests', 'vers:pypi/>=2.0', 'pkg:pypi/requests')"
    )
    assert vdb_setup.db_lib.stats()[1] == 1
    vdb_setup.db_lib.reset_connections()
    # No SystemExit: the guard returns None on a usable database.
    assert vdb_setup.ensure_vdb_usable() is None


def test_vdb_download_needed_stale(monkeypatch):
    """needs_update=True should trigger download regardless of marker."""
    monkeypatch.setattr(vdb_setup.db_lib, "needs_update", lambda **kw: True)
    monkeypatch.setattr(
        vdb_setup, "read_vdb_image_marker", lambda d: "ghcr.io/appthreat/vdbxz:v6.7.x"
    )
    should, reason = vdb_setup.vdb_download_needed("ghcr.io/appthreat/vdbxz:v6.7.x", "/tmp/d")
    assert should is True
    assert reason == "stale"


def test_vdb_download_needed_variant_change_forces_redownload(monkeypatch):
    """A variant mismatch forces re-download even when the DB is fresh."""
    monkeypatch.setattr(vdb_setup.db_lib, "needs_update", lambda **kw: False)
    monkeypatch.setattr(
        vdb_setup, "read_vdb_image_marker", lambda d: "ghcr.io/appthreat/vdbxz:v6.7.x"
    )
    should, reason = vdb_setup.vdb_download_needed(
        "ghcr.io/appthreat/vdbxz-extended:v6.7.x", "/tmp/d"
    )
    assert should is True
    assert reason == "variant-change"


def test_vdb_download_needed_no_download_when_fresh_and_same_variant(monkeypatch):
    """Fresh DB with same variant should not trigger download."""
    monkeypatch.setattr(vdb_setup.db_lib, "needs_update", lambda **kw: False)
    monkeypatch.setattr(
        vdb_setup, "read_vdb_image_marker", lambda d: "ghcr.io/appthreat/vdbxz:v6.7.x"
    )
    should, reason = vdb_setup.vdb_download_needed("ghcr.io/appthreat/vdbxz:v6.7.x", "/tmp/d")
    assert should is False
    assert reason is None


def test_vdb_download_needed_no_marker_does_not_force(monkeypatch):
    """No marker at all (first run or pre-feature) should rely on needs_update only."""
    monkeypatch.setattr(vdb_setup.db_lib, "needs_update", lambda **kw: False)
    monkeypatch.setattr(vdb_setup, "read_vdb_image_marker", lambda d: None)
    should, reason = vdb_setup.vdb_download_needed("ghcr.io/appthreat/vdbxz:v6.7.x", "/tmp/d")
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
        "vdb_flavor": None,
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
    url, pinned, flavor = vdb_setup.resolve_scan_vdb_image(args)
    assert url == "ghcr.io/appthreat/vdb7-full:v7.0.x-xz"
    assert pinned is False
    assert flavor == "full"
    assert os.getenv("VDB_INCLUDE_METADATA") is None


def test_resolve_scan_severity_auto_extended(monkeypatch):
    """--severity with no explicit pin -> extended image + VDB_INCLUDE_METADATA."""
    monkeypatch.delenv("VDB_DATABASE_URL", raising=False)
    monkeypatch.delenv("USE_VDB_10Y", raising=False)
    monkeypatch.delenv("VDB_INCLUDE_METADATA", raising=False)
    args = _make_args(severity="high")
    url, pinned, flavor = vdb_setup.resolve_scan_vdb_image(args)
    # The metadata flavor is app-scope only, so --severity selects app-extended.
    assert url == "ghcr.io/appthreat/vdb7-app-extended:v7.0.x-xz"
    assert pinned is False
    assert flavor == "app-extended"
    assert os.getenv("VDB_INCLUDE_METADATA") == "true"


def test_resolve_scan_explicit_url_not_overridden(monkeypatch):
    """VDB_DATABASE_URL pin is respected verbatim even with --severity."""
    monkeypatch.setenv("VDB_DATABASE_URL", "ghcr.io/appthreat/vdb7-app-only:v7.0.x-xz")
    monkeypatch.delenv("VDB_INCLUDE_METADATA", raising=False)
    args = _make_args(severity="high")
    url, pinned, flavor = vdb_setup.resolve_scan_vdb_image(args)
    assert url == "ghcr.io/appthreat/vdb7-app-only:v7.0.x-xz"
    assert pinned is True
    assert flavor is None
    # VDB_INCLUDE_METADATA should NOT be set by depscan for a pinned image
    assert os.getenv("VDB_INCLUDE_METADATA") is None


def test_resolve_scan_use_vdb_10y(monkeypatch):
    """USE_VDB_10Y maps to time=10y."""
    monkeypatch.delenv("VDB_DATABASE_URL", raising=False)
    monkeypatch.setenv("USE_VDB_10Y", "true")
    monkeypatch.delenv("VDB_INCLUDE_METADATA", raising=False)
    args = _make_args()
    url, pinned, flavor = vdb_setup.resolve_scan_vdb_image(args)
    # The 10-year flavor is app-scope only, so USE_VDB_10Y selects app-10y.
    assert url == "ghcr.io/appthreat/vdb7-app-10y:v7.0.x-xz"
    assert pinned is False
    assert flavor == "app-10y"


def test_resolve_scan_use_vdb_10y_with_severity(monkeypatch):
    """USE_VDB_10Y + --severity -> 10y extended."""
    monkeypatch.delenv("VDB_DATABASE_URL", raising=False)
    monkeypatch.setenv("USE_VDB_10Y", "true")
    monkeypatch.delenv("VDB_INCLUDE_METADATA", raising=False)
    args = _make_args(severity="critical")
    url, pinned, flavor = vdb_setup.resolve_scan_vdb_image(args)
    # USE_VDB_10Y is not an explicit flavor choice, so --severity still adds
    # the metadata tables.
    assert url == "ghcr.io/appthreat/vdb7-app-10y-extended:v7.0.x-xz"
    assert pinned is False
    assert flavor == "app-10y-extended"
    assert os.getenv("VDB_INCLUDE_METADATA") == "true"


# --- vdb-selection options persisted via CLI/config (tomlparse) -----------


def _clean_vdb_env(monkeypatch):
    monkeypatch.delenv("VDB_DATABASE_URL", raising=False)
    monkeypatch.delenv("USE_VDB_10Y", raising=False)
    monkeypatch.delenv("VDB_INCLUDE_METADATA", raising=False)


def test_resolve_scan_config_scope_app(monkeypatch):
    """A persisted vdb_scope=app resolves the app-only image."""
    _clean_vdb_env(monkeypatch)
    url, pinned, flavor = vdb_setup.resolve_scan_vdb_image(_make_args(vdb_scope="app"))
    assert url == "ghcr.io/appthreat/vdb7-app-only:v7.0.x-xz"
    assert pinned is False
    assert flavor == "app-only"


def test_resolve_scan_config_extended_and_compression(monkeypatch):
    """Persisted vdb_extended + vdb_compression compose, and extended sets metadata."""
    _clean_vdb_env(monkeypatch)
    url, pinned, flavor = vdb_setup.resolve_scan_vdb_image(
        _make_args(vdb_scope="app", vdb_extended=True, vdb_compression="zst")
    )
    assert url == "ghcr.io/appthreat/vdb7-app-extended:v7.0.x-zst"
    assert flavor == "app-extended"
    assert os.getenv("VDB_INCLUDE_METADATA") == "true"


def test_resolve_scan_config_time_overrides_use_vdb_10y(monkeypatch):
    """An explicit vdb_time wins over USE_VDB_10Y: with vdb_time=default the
    resolver picks the full flavor, not the 10-year one the env var selects."""
    _clean_vdb_env(monkeypatch)
    monkeypatch.setenv("USE_VDB_10Y", "true")
    url, _, flavor = vdb_setup.resolve_scan_vdb_image(_make_args(vdb_time="default"))
    assert url == "ghcr.io/appthreat/vdb7-full:v7.0.x-xz"
    assert flavor == "full"


def test_resolve_scan_config_distro(monkeypatch):
    """A persisted vdb_distro is rejected: v7 publishes no per-distro
    complete database, and the error names the flavors."""
    import pytest

    _clean_vdb_env(monkeypatch)
    with pytest.raises(ValueError, match="no per-distro complete database"):
        vdb_setup.resolve_scan_vdb_image(_make_args(vdb_distro="ubuntu"))


def test_resolve_scan_vdb_image_pin_verbatim(monkeypatch):
    """--vdb-image (or config vdb_image) is used verbatim and marked pinned."""
    _clean_vdb_env(monkeypatch)
    url, pinned, flavor = vdb_setup.resolve_scan_vdb_image(
        _make_args(vdb_image="ghcr.io/me/custom:1", vdb_scope="app")
    )
    assert url == "ghcr.io/me/custom:1"
    assert pinned is True
    assert flavor is None


def test_resolve_scan_env_pin_beats_config(monkeypatch):
    """VDB_DATABASE_URL env pin wins over persisted vdb_scope."""
    _clean_vdb_env(monkeypatch)
    monkeypatch.setenv("VDB_DATABASE_URL", "ghcr.io/appthreat/vdb7-app-extended:v7.0.x-xz")
    url, pinned, flavor = vdb_setup.resolve_scan_vdb_image(_make_args(vdb_scope="app"))
    assert url == "ghcr.io/appthreat/vdb7-app-extended:v7.0.x-xz"
    assert pinned is True
    assert flavor is None


# ---------------------------------------------------------------------------
# Deprecated --vdb-* options warn once and name the flavor
# ---------------------------------------------------------------------------


def test_each_deprecated_option_warns_naming_the_flavor(monkeypatch, caplog):
    """One warning per deprecated option, each naming the flavor the whole
    selection resolved to."""
    _clean_vdb_env(monkeypatch)
    with caplog.at_level("WARNING"):
        url, _pinned, flavor = vdb_setup.resolve_scan_vdb_image(
            _make_args(vdb_scope="app", vdb_time="10y", vdb_extended=True)
        )
    assert flavor == "app-10y-extended"
    warnings = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
    assert len(warnings) == 3
    assert all("app-10y-extended" in w for w in warnings)
    assert any("--vdb-scope" in w for w in warnings)
    assert any("--vdb-time" in w for w in warnings)
    assert any("--vdb-extended" in w for w in warnings)
    assert all("--vdb-flavor" in w for w in warnings)


def test_use_vdb_10y_env_warns_naming_the_flavor(monkeypatch, caplog):
    _clean_vdb_env(monkeypatch)
    monkeypatch.setenv("USE_VDB_10Y", "true")
    with caplog.at_level("WARNING"):
        _url, _pinned, flavor = vdb_setup.resolve_scan_vdb_image(_make_args())
    assert flavor == "app-10y"
    warnings = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
    assert len(warnings) == 1
    assert "USE_VDB_10Y" in warnings[0]
    assert "'app-10y'" in warnings[0]


def test_vdb_flavor_direct_no_warning(monkeypatch, caplog):
    _clean_vdb_env(monkeypatch)
    with caplog.at_level("WARNING"):
        url, _pinned, flavor = vdb_setup.resolve_scan_vdb_image(_make_args(vdb_flavor="app-only"))
    assert (url, flavor) == ("ghcr.io/appthreat/vdb7-app-only:v7.0.x-xz", "app-only")
    assert not [r for r in caplog.records if r.levelname == "WARNING"]


def test_vdb_flavor_rejects_deprecated_mix(monkeypatch):
    import pytest

    _clean_vdb_env(monkeypatch)
    with pytest.raises(ValueError, match="cannot be combined"):
        vdb_setup.resolve_scan_vdb_image(_make_args(vdb_flavor="app-only", vdb_scope="app"))


def test_severity_does_not_override_explicit_flavor(monkeypatch, caplog):
    """A flavor the user chose explicitly is never narrowed by --severity; the
    depscan-side severity floor still applies."""
    _clean_vdb_env(monkeypatch)
    with caplog.at_level("INFO"):
        url, _pinned, flavor = vdb_setup.resolve_scan_vdb_image(
            _make_args(vdb_flavor="full", severity="high")
        )
    assert flavor == "full"
    assert os.getenv("VDB_INCLUDE_METADATA") is None
    infos = [r.getMessage() for r in caplog.records]
    assert any("severity floor is still applied" in w for w in infos)


# ---------------------------------------------------------------------------
# No function in depscan/cli.py may exceed 80 lines
# ---------------------------------------------------------------------------


def _function_lengths(source):
    """Map every function name in *source* to its length in lines, counted
    from its ``def`` line to its last line."""
    lengths = {}
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            lengths[node.name] = (node.end_lineno or node.lineno) - node.lineno + 1
    return lengths


def test_function_length_counter_reports_an_81_line_function():
    """Positive control for the counter: a function that is exactly 81 lines
    long is reported as 81, so the limit test below would fail on it."""
    body = "\n".join(f"    x = {i}" for i in range(80))
    lengths = _function_lengths(f"def too_long():\n{body}\n")
    assert lengths["too_long"] == 81


def test_no_cli_function_exceeds_80_lines():
    """run_depscan orchestrates the pipeline stages; the stages themselves
    live in depscan.lib.pipeline. Nothing in the CLI module may grow past 80
    lines again."""
    cli_source = (Path(__file__).parent.parent / "depscan" / "cli.py").read_text()
    offenders = {
        name: length for name, length in _function_lengths(cli_source).items() if length > 80
    }
    assert not offenders, f"functions longer than 80 lines: {offenders}"
