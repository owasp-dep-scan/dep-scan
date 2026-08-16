"""Tests for the depscan-vdb command (T7 Change B)."""

from depscan.vdb_cli import (
    _build_parser,
    _resolve_image_from_args,
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
    assert args.scope == "app+os"
    assert args.time == "default"
    assert args.extended is False
    assert args.compression == "xz"
    assert args.distro is None
    assert args.image is None


def test_resolve_default_download_image():
    parser = _build_parser()
    args = parser.parse_args(["download"])
    assert _resolve_image_from_args(args) == "ghcr.io/appthreat/vdbxz:v6.7.x"


def test_resolve_distro_ubuntu():
    parser = _build_parser()
    args = parser.parse_args(["download", "--distro", "ubuntu"])
    assert _resolve_image_from_args(args) == "ghcr.io/appthreat/vdbxz-ubuntu:v6.7.x"


def test_resolve_app_extended():
    parser = _build_parser()
    args = parser.parse_args(["download", "--scope", "app", "--extended"])
    assert _resolve_image_from_args(args) == "ghcr.io/appthreat/vdbxz-app-extended:v6.7.x"


def test_resolve_image_override_verbatim():
    parser = _build_parser()
    args = parser.parse_args(["download", "--image", "registry.example.com/vdb:v1"])
    assert _resolve_image_from_args(args) == "registry.example.com/vdb:v1"


def test_download_writes_marker(tmp_path, monkeypatch):
    """download should call download_vdb_with_retries and write the marker."""
    calls = []

    def fake_download(url, data_dir, **kw):
        calls.append((url, data_dir))
        return ["ok"]

    # Patch the lazy import target in depscan.cli
    from depscan import cli

    monkeypatch.setattr(cli, "download_vdb_with_retries", fake_download)
    monkeypatch.setattr("depscan.vdb_cli._ORAS_AVAILABLE", True)

    parser = _build_parser()
    args = parser.parse_args(["download", "--distro", "ubuntu"])
    # Redirect DATA_DIR to tmp_path
    from vdb.lib import config as vdb_config

    monkeypatch.setattr(vdb_config, "DATA_DIR", str(tmp_path))

    rc = cmd_download(args)
    assert rc == 0
    assert len(calls) == 1
    assert calls[0][0] == "ghcr.io/appthreat/vdbxz-ubuntu:v6.7.x"
    # Marker should be written
    from depscan.lib.config import read_vdb_image_marker

    marker = read_vdb_image_marker(str(tmp_path))
    assert marker == "ghcr.io/appthreat/vdbxz-ubuntu:v6.7.x"


def test_download_no_oras_reports_error(tmp_path, monkeypatch):
    monkeypatch.setattr("depscan.vdb_cli._ORAS_AVAILABLE", False)
    from vdb.lib import config as vdb_config

    monkeypatch.setattr(vdb_config, "DATA_DIR", str(tmp_path))
    parser = _build_parser()
    args = parser.parse_args(["download"])
    rc = cmd_download(args)
    assert rc == 1


def test_cmd_path(tmp_path, monkeypatch, capsys):
    from vdb.lib import config as vdb_config

    monkeypatch.setattr(vdb_config, "DATA_DIR", str(tmp_path))
    rc = cmd_path(None)
    assert rc == 0
    captured = capsys.readouterr()
    assert str(tmp_path) in captured.out


def test_cmd_info_no_db(tmp_path, monkeypatch, capsys):
    from vdb.lib import config as vdb_config

    monkeypatch.setattr(vdb_config, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr("depscan.vdb_cli.db_lib.get_db_file_metadata", lambda: None)
    monkeypatch.setattr("depscan.vdb_cli.db_lib.needs_update", lambda **kw: False)
    rc = cmd_info(None)
    assert rc == 0
    captured = capsys.readouterr()
    assert "VDB_HOME" in captured.out
    assert "no database" in captured.out.lower() or "(none recorded)" in captured.out


def test_cmd_info_with_marker(tmp_path, monkeypatch, capsys):
    from vdb.lib import config as vdb_config
    from depscan.lib.config import write_vdb_image_marker

    monkeypatch.setattr(vdb_config, "DATA_DIR", str(tmp_path))
    write_vdb_image_marker("ghcr.io/appthreat/vdbxz-app:v6.7.x", str(tmp_path))
    monkeypatch.setattr(
        "depscan.vdb_cli.db_lib.get_db_file_metadata",
        lambda: {"created_utc": "2025-01-01T00:00:00+00:00"},
    )
    monkeypatch.setattr("depscan.vdb_cli.db_lib.needs_update", lambda **kw: True)
    monkeypatch.setattr("depscan.vdb_cli.db_lib.metadata_rows_count", lambda: 0)
    rc = cmd_info(None)
    assert rc == 0
    captured = capsys.readouterr()
    assert "vdbxz-app" in captured.out
    assert "stale" in captured.out


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


def test_main_path(monkeypatch):
    monkeypatch.setattr("sys.argv", ["depscan-vdb", "path"])
    # cmd_path just prints DATA_DIR; ensure no crash
    rc = main()
    assert rc == 0


def test_main_download_with_flags(monkeypatch):
    """depscan-vdb --scope app should default to download with the flag."""
    called = []

    def fake_cmd_download(args):
        called.append(args.scope)
        return 0

    monkeypatch.setattr("depscan.vdb_cli.cmd_download", fake_cmd_download)
    monkeypatch.setattr("sys.argv", ["depscan-vdb", "--scope", "app"])
    rc = main()
    assert rc == 0
    assert called == ["app"]
