"""Tests for the depscan-vdb command."""

import pytest

from depscan.vdb_cli import (
    _build_parser,
    _flavor_from_image,
    _resolve_flavor_from_args,
    cmd_download,
    cmd_info,
    cmd_path,
    main,
)


def test_parser_has_subcommands():
    parser = _build_parser()
    args = parser.parse_args(["download"])
    assert args.command == "download"
    args = parser.parse_args(["info"])
    assert args.command == "info"
    args = parser.parse_args(["path"])
    assert args.command == "path"


def test_download_defaults():
    parser = _build_parser()
    args = parser.parse_args(["download"])
    assert args.flavor is None
    assert args.shards is None
    assert args.scope is None
    assert args.time is None
    assert args.extended is False
    assert args.compression == "xz"
    assert args.distro is None
    assert args.image is None


# ---------------------------------------------------------------------------
# Flavor selection: --flavor, deprecated aliases, rejections
# ---------------------------------------------------------------------------


def test_flavor_from_image_extracts_repo_suffix():
    assert _flavor_from_image("ghcr.io/appthreat/vdb7-app-only:v7.0.x-xz") == "app-only"
    assert (
        _flavor_from_image("ghcr.io/appthreat/vdb7-app-10y-extended:v7.0.x-xz")
        == "app-10y-extended"
    )
    assert _flavor_from_image("registry.example.com/vdb:v1") is None


def test_resolve_flavor_direct():
    parser = _build_parser()
    args = parser.parse_args(["download", "--flavor", "app-only"])
    flavor, legacy = _resolve_flavor_from_args(args)
    assert flavor == "app-only"
    assert legacy == []


def test_resolve_default_is_full():
    parser = _build_parser()
    args = parser.parse_args(["download"])
    flavor, legacy = _resolve_flavor_from_args(args)
    assert flavor == "full"
    assert legacy == []


def test_deprecated_aliases_resolve_and_warn(capsys):
    """Each deprecated alias prints one warning naming the flavor it maps to."""
    parser = _build_parser()
    args = parser.parse_args(["download", "--scope", "app", "--time", "10y", "--extended"])
    flavor, legacy = _resolve_flavor_from_args(args)
    assert flavor == "app-10y-extended"
    assert legacy == ["--scope", "--time", "--extended"]
    err = capsys.readouterr().err
    # One warning per deprecated alias, each naming the resolved flavor.
    assert err.count("deprecated") == 3
    assert err.count("'app-10y-extended'") == 3


def test_flavor_rejects_deprecated_aliases():
    parser = _build_parser()
    args = parser.parse_args(["download", "--flavor", "app-only", "--scope", "app"])
    with pytest.raises(ValueError, match="cannot be combined"):
        _resolve_flavor_from_args(args)


def test_distro_is_rejected():
    parser = _build_parser()
    args = parser.parse_args(["download", "--distro", "ubuntu"])
    with pytest.raises(ValueError, match="no per-distro complete database"):
        _resolve_flavor_from_args(args)


def test_two_year_window_is_rejected():
    parser = _build_parser()
    args = parser.parse_args(["download", "--scope", "app", "--time", "2y"])
    with pytest.raises(ValueError, match="Published flavors"):
        _resolve_flavor_from_args(args)


# ---------------------------------------------------------------------------
# download: stubbed vdb refresh with positive controls
# ---------------------------------------------------------------------------


@pytest.fixture
def vdb_home(tmp_path, monkeypatch):
    home = tmp_path.resolve() / "vdb-home"
    home.mkdir()
    import vdb.lib.config as vdb_config

    monkeypatch.setenv("VDB_HOME", str(home))
    monkeypatch.setattr(vdb_config, "DATA_DIR", str(home))
    monkeypatch.setattr(vdb_config, "VDB_BIN_FILE", str(home / "data.vdb7"))
    monkeypatch.setattr(vdb_config, "VDB_BIN_INDEX", str(home / "data.index.vdb7"))
    monkeypatch.setattr(vdb_config, "VDB_SHARDS_DIR", str(home / "shards"))
    yield home


def test_download_flavor_calls_refresh_with_resolved_image(vdb_home, monkeypatch):
    """The flavor download goes through vdb's refresh with the resolved URL,
    and the marker records that URL."""
    from depscan.lib.config import read_vdb_image_marker

    calls = []

    def fake_refresh(url, attempts=None):
        calls.append(url)
        return {"image": url, "meta": {}}

    from depscan import cli

    monkeypatch.setattr(cli, "download_vdb_with_retries", fake_refresh)
    parser = _build_parser()
    args = parser.parse_args(["download", "--flavor", "app-only"])
    assert cmd_download(args) == 0
    # Positive control: vdb's refresh ran once, with the flavor's URL.
    assert calls == ["ghcr.io/appthreat/vdb7-app-only:v7.0.x-xz"]
    assert read_vdb_image_marker(str(vdb_home)) == "ghcr.io/appthreat/vdb7-app-only:v7.0.x-xz"


def test_download_zst_compression_passed_through(vdb_home, monkeypatch):
    calls = []

    def fake_refresh(url, attempts=None):
        calls.append(url)
        return {"image": url, "meta": {}}

    from depscan import cli

    monkeypatch.setattr(cli, "download_vdb_with_retries", fake_refresh)
    parser = _build_parser()
    args = parser.parse_args(["download", "--flavor", "full", "--compression", "zst"])
    assert cmd_download(args) == 0
    assert calls == ["ghcr.io/appthreat/vdb7-full:v7.0.x-zst"]


def test_download_image_override_verbatim(vdb_home, monkeypatch):
    calls = []

    def fake_refresh(url, attempts=None):
        calls.append(url)
        return {"image": url, "meta": {}}

    from depscan import cli

    monkeypatch.setattr(cli, "download_vdb_with_retries", fake_refresh)
    parser = _build_parser()
    args = parser.parse_args(["download", "--image", "registry.example.com/vdb:v1"])
    assert cmd_download(args) == 0
    assert calls == ["registry.example.com/vdb:v1"]


def test_download_shards_calls_refresh_shards_with_names(vdb_home, monkeypatch):
    """A shard-set download refreshes exactly the canonical shards for the
    requested purl types into the store, and records the shard marker."""
    from depscan.lib.config import read_vdb_image_marker

    calls = []

    def fake_refresh_shards(shard_names, store_dir=None, attempts=None):
        calls.append((list(shard_names), store_dir))
        return list(shard_names)

    from depscan import cli

    monkeypatch.setattr(cli, "refresh_shards_with_retries", fake_refresh_shards)
    parser = _build_parser()
    args = parser.parse_args(["download", "--shards", "pypi", "npm"])
    assert cmd_download(args) == 0
    # Positive control: the purl types were canonicalised and refreshed into
    # the shard store next to the database home.
    assert calls == [(["pypi", "npm"], str(vdb_home / "shards"))]
    assert read_vdb_image_marker(str(vdb_home)) == "shards:npm,pypi"


def test_download_shards_rejects_flavor_combo(vdb_home):
    parser = _build_parser()
    args = parser.parse_args(["download", "--shards", "pypi", "--flavor", "full"])
    assert cmd_download(args) == 1


def test_download_rejected_combination_exits_one(vdb_home, capsys):
    parser = _build_parser()
    args = parser.parse_args(["download", "--distro", "ubuntu"])
    assert cmd_download(args) == 1
    assert "no per-distro complete database" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# info: vdb's store status, partial stores and stale shards not hidden
# ---------------------------------------------------------------------------


def test_cmd_path(vdb_home, capsys):
    rc = cmd_path(None)
    assert rc == 0
    assert str(vdb_home) in capsys.readouterr().out


def test_cmd_info_shows_flavor_partial_store_and_stale_shard(vdb_home, monkeypatch, capsys):
    from depscan.lib.config import write_vdb_image_marker

    write_vdb_image_marker("ghcr.io/appthreat/vdb7-full:v7.0.x-xz", str(vdb_home))
    monkeypatch.setattr(
        "depscan.vdb_cli.db_lib.get_db_file_metadata",
        lambda: {
            "created_utc": "2026-11-14T10:00:00+00:00",
            "cve_data_count": 100,
            "cve_index_count": 99,
            "completeness": "partial",
        },
    )
    monkeypatch.setattr("depscan.vdb_cli.db_lib.needs_update", lambda **kw: False)

    def fake_store_status(store_dir=None):
        return {
            "store_dir": str(vdb_home / "shards"),
            "shards": [
                {
                    "name": "pypi",
                    "build_id": "b1",
                    "created_utc": "2026-11-14T10:00:00+00:00",
                    "age_days": 0.1,
                    "stale": False,
                    "types": ["pypi"],
                    "type_count": 1,
                },
                {
                    "name": "deb",
                    "build_id": "b0",
                    "created_utc": "2026-10-01T10:00:00+00:00",
                    "age_days": 44.0,
                    "stale": True,
                    "types": ["deb"],
                    "type_count": 1,
                },
            ],
            "build_ids": ["b0", "b1"],
            "mixed_builds": True,
            "missing_group_shards": ["rpm", "apk", "app", "cpe"],
            "coverage": "partial (missing: apk, app, cpe, rpm)",
        }

    monkeypatch.setattr("depscan.vdb_cli.db_cmd.store_status", fake_store_status)
    rc = cmd_info(None)
    assert rc == 0
    out = capsys.readouterr().out
    # Flavor from the marker, build time, rows.
    assert "vdb7-full:v7.0.x-xz (full)" in out
    assert "2026-11-14T10:00:00+00:00" in out
    assert "100 data / 99 index" in out
    # A shard installed as the main database is named as such.
    assert "shard installed as the main database (partial)" in out
    # A stale shard and a partial store are printed, never hidden.
    assert "STALE (much older than its siblings)" in out
    assert "partial (missing: apk, app, cpe, rpm)" in out
    assert "(mixed builds)" in out


def test_cmd_info_empty_store_and_no_database(vdb_home, monkeypatch, capsys):
    monkeypatch.setattr("depscan.vdb_cli.db_lib.get_db_file_metadata", lambda: None)

    def fake_store_status(store_dir=None):
        return {"store_dir": str(vdb_home / "shards"), "shards": []}

    monkeypatch.setattr("depscan.vdb_cli.db_cmd.store_status", fake_store_status)
    rc = cmd_info(None)
    assert rc == 0
    out = capsys.readouterr().out
    assert "no database found" in out
    assert "empty" in out


def test_cmd_info_shows_shard_set_marker(vdb_home, monkeypatch, capsys):
    from depscan.lib.config import write_vdb_image_marker

    write_vdb_image_marker("shards:npm,pypi", str(vdb_home))
    monkeypatch.setattr("depscan.vdb_cli.db_lib.get_db_file_metadata", lambda: None)

    def fake_store_status(store_dir=None):
        return {"store_dir": str(vdb_home / "shards"), "shards": []}

    monkeypatch.setattr("depscan.vdb_cli.db_cmd.store_status", fake_store_status)
    assert cmd_info(None) == 0
    assert "shards npm,pypi" in capsys.readouterr().out


def test_main_defaults_to_download(monkeypatch):
    """Running depscan-vdb with no subcommand should default to download."""
    called = []

    def fake_cmd_download(args):
        called.append("download")
        return 0

    monkeypatch.setattr("depscan.vdb_cli.cmd_download", fake_cmd_download)
    monkeypatch.setattr("sys.argv", ["depscan-vdb"])
    rc = main()
    assert rc == 0
    assert called == ["download"]


def test_main_download_with_flags(monkeypatch):
    called = []

    def fake_cmd_download(args):
        called.append(args.flavor)
        return 0

    monkeypatch.setattr("depscan.vdb_cli.cmd_download", fake_cmd_download)
    monkeypatch.setattr("sys.argv", ["depscan-vdb", "--flavor", "app-only"])
    rc = main()
    assert rc == 0
    assert called == ["app-only"]
