"""Tests of the ``depscan vdb`` output contract.

The verb accepts ``--format`` before and after its subcommand with the
subcommand's position winning when both are given, every path in its json
documents carries the absolute, normalised, slash-separated form, and a
failure writes the error document on stdout next to the message on stderr.
Most runs go through ``depscan.cli.main``, the front end the ``depscan``
command uses, with the database home pointed at a temporary directory and
vdb's download stubbed.
"""

import json
import os
import sys

import pytest

import vdb.lib.config as vdb_config

from depscan import cli, vdb_cli
from depscan.commands.output import json_path
from depscan.lib.config import (
    VDB_IMAGE_MARKER_FILE,
    read_vdb_image_marker,
    write_vdb_image_marker,
)


def run_depscan(monkeypatch, argv):
    """Run the ``depscan`` front end with ``argv``; the exit code."""
    monkeypatch.setattr(sys, "argv", ["depscan", *argv])
    with pytest.raises(SystemExit) as excinfo:
        cli.main()
    return excinfo.value.code


@pytest.fixture
def vdb_home(tmp_path, monkeypatch):
    """A vdb home configured through a dot segment, so every path field in a
    json document has a non-normalised form to normalise. The dot segment's
    directory is real, so paths through it still open."""
    home = tmp_path / "vdb-home"
    home.mkdir()
    (tmp_path / "unnormalised").mkdir()
    dotted = os.path.join(str(tmp_path), "unnormalised", os.pardir, "vdb-home")
    monkeypatch.setenv("VDB_HOME", dotted)
    monkeypatch.setattr(vdb_config, "DATA_DIR", dotted)
    monkeypatch.setattr(vdb_config, "VDB_BIN_FILE", os.path.join(dotted, "data.vdb7"))
    monkeypatch.setattr(vdb_config, "VDB_BIN_INDEX", os.path.join(dotted, "data.index.vdb7"))
    monkeypatch.setattr(vdb_config, "VDB_SHARDS_DIR", os.path.join(dotted, "shards"))
    return home


@pytest.fixture
def empty_store(vdb_home, monkeypatch):
    """No local database and an empty shard store, stubbed at vdb."""
    monkeypatch.setattr("depscan.vdb_cli.db_lib.get_db_file_metadata", lambda: None)

    def fake_store_status(store_dir=None):
        return {"store_dir": vdb_config.VDB_SHARDS_DIR, "shards": []}

    monkeypatch.setattr("depscan.vdb_cli.db_cmd.store_status", fake_store_status)


# --- the format positions ----------------------------------------------------------


def test_format_before_the_subcommand_prints_one_document(
    vdb_home, empty_store, monkeypatch, capsys
):
    assert run_depscan(monkeypatch, ["vdb", "--format", "json", "info"]) == 0
    captured = capsys.readouterr()
    document = json.loads(captured.out)
    assert document["vdbHome"] == json_path(str(vdb_home))


def test_format_after_the_subcommand_prints_one_document(
    vdb_home, empty_store, monkeypatch, capsys
):
    assert run_depscan(monkeypatch, ["vdb", "info", "--format", "json"]) == 0
    captured = capsys.readouterr()
    document = json.loads(captured.out)
    assert os.path.isabs(document["vdbHome"])
    assert document["vdbHome"] == json_path(str(vdb_home))
    assert "/unnormalised/" not in document["vdbHome"]


def test_the_subcommand_position_wins_when_both_are_given(
    vdb_home, empty_store, monkeypatch, capsys
):
    assert run_depscan(monkeypatch, ["vdb", "--format", "text", "info", "--format", "json"]) == 0
    document = json.loads(capsys.readouterr().out)
    assert document["vdbHome"] == json_path(str(vdb_home))


def test_a_late_text_format_wins_back_text(vdb_home, empty_store, monkeypatch, capsys):
    assert run_depscan(monkeypatch, ["vdb", "--format", "json", "info", "--format", "text"]) == 0
    captured = capsys.readouterr()
    assert captured.out.startswith("VDB_HOME:")
    with pytest.raises(ValueError):
        json.loads(captured.out)


def test_the_raw_front_end_accepts_format_before_the_subcommand(
    vdb_home, empty_store, capsys
):
    assert vdb_cli.main(["--format", "json", "info"]) == 0
    document = json.loads(capsys.readouterr().out)
    assert document["vdbHome"] == json_path(str(vdb_home))


def test_the_raw_front_end_still_defaults_to_download_behind_a_format(monkeypatch, capsys):
    called = []

    def fake_download(args):
        called.append(getattr(args, "format", "text"))
        return 0

    monkeypatch.setattr(vdb_cli, "cmd_download", fake_download)
    assert vdb_cli.main(["--format", "json"]) == 0
    assert called == ["json"]


# --- the paths ---------------------------------------------------------------------


def test_path_prints_the_normalised_absolute_home(vdb_home, monkeypatch, capsys):
    assert run_depscan(monkeypatch, ["vdb", "path", "--format", "json"]) == 0
    document = json.loads(capsys.readouterr().out)
    assert os.path.isabs(document["path"])
    assert document["path"] == json_path(str(vdb_home))
    assert "/unnormalised/" not in document["path"]


def test_info_paths_are_normalised_and_the_marker_value_stays_verbatim(
    vdb_home, empty_store, monkeypatch, capsys
):
    write_vdb_image_marker("ghcr.io/appthreat/vdb7-full:v7.0.x-xz", vdb_config.DATA_DIR)
    assert run_depscan(monkeypatch, ["vdb", "info", "--format", "json"]) == 0
    captured = capsys.readouterr()
    document = json.loads(captured.out)
    # The stub left no database file behind, which is the positive control
    # that the info document came from this fixture's store.
    assert document["mainDb"] is None
    assert document["vdbHome"] == json_path(str(vdb_home))
    assert document["shardStore"]["storeDir"] == json_path(vdb_config.VDB_SHARDS_DIR)
    # The recorded image reference is not a filesystem path and stays verbatim.
    assert document["marker"] == "ghcr.io/appthreat/vdb7-full:v7.0.x-xz"


def test_text_info_keeps_the_plain_lines(vdb_home, empty_store, monkeypatch, capsys):
    assert run_depscan(monkeypatch, ["vdb", "info"]) == 0
    captured = capsys.readouterr()
    assert captured.out.startswith("VDB_HOME:")
    with pytest.raises(ValueError):
        json.loads(captured.out)


# --- the download documents ----------------------------------------------------------


def test_download_prints_the_absolute_marker_path(vdb_home, monkeypatch, capsys):
    from depscan.lib import vdb_setup

    calls = []

    def fake_refresh(url, attempts=None):
        calls.append(url)
        return {"image": url, "meta": {}}

    monkeypatch.setattr(vdb_setup, "download_vdb_with_retries", fake_refresh)
    argv = ["vdb", "download", "--flavor", "app-only", "--format", "json"]
    assert run_depscan(monkeypatch, argv) == 0
    captured = capsys.readouterr()
    document = json.loads(captured.out)
    # Positive control: vdb's refresh ran once, with the flavor's URL.
    assert calls == ["ghcr.io/appthreat/vdb7-app-only:v7.0.x-xz"]
    assert document["image"] == "ghcr.io/appthreat/vdb7-app-only:v7.0.x-xz"
    marker_path = os.path.join(str(vdb_home), VDB_IMAGE_MARKER_FILE)
    assert document["marker"] == json_path(marker_path)
    assert os.path.isabs(document["marker"])
    assert "/unnormalised/" not in document["marker"]


def test_download_shards_print_the_absolute_marker_path(vdb_home, monkeypatch, capsys):
    from depscan.lib import vdb_setup

    calls = []

    def fake_refresh_shards(shard_names, store_dir=None, attempts=None):
        calls.append(list(shard_names))
        return list(shard_names)

    monkeypatch.setattr(vdb_setup, "refresh_shards_with_retries", fake_refresh_shards)
    argv = ["vdb", "download", "--shards", "pypi", "npm", "--format", "json"]
    assert run_depscan(monkeypatch, argv) == 0
    document = json.loads(capsys.readouterr().out)
    # Positive controls: the purl types were canonicalised and refreshed, and
    # the shard-set marker was written into the database home.
    assert calls == [["pypi", "npm"]]
    assert read_vdb_image_marker(str(vdb_home)) == "shards:npm,pypi"
    assert document["shards"] == ["pypi", "npm"]
    marker_path = os.path.join(str(vdb_home), VDB_IMAGE_MARKER_FILE)
    assert document["marker"] == json_path(marker_path)


# --- the failures ---------------------------------------------------------------------


def test_a_rejected_distro_prints_the_error_document(vdb_home, monkeypatch, capsys):
    argv = ["vdb", "download", "--distro", "ubuntu", "--format", "json"]
    assert run_depscan(monkeypatch, argv) == 1
    captured = capsys.readouterr()
    document = json.loads(captured.out)
    assert document["error"]["exitCode"] == 1
    assert document["error"]["verb"] == "vdb"
    assert "no per-distro complete database" in document["error"]["message"]
    assert "details" not in document["error"]
    # The same message on stderr as text.
    assert captured.err.strip() == document["error"]["message"]


def test_a_rejected_flavor_alias_combination_prints_the_error_document(
    vdb_home, monkeypatch, capsys
):
    argv = ["vdb", "download", "--flavor", "app-only", "--scope", "app", "--format", "json"]
    assert run_depscan(monkeypatch, argv) == 1
    document = json.loads(capsys.readouterr().out)
    assert document["error"]["exitCode"] == 1
    assert document["error"]["verb"] == "vdb"
    assert "cannot be combined" in document["error"]["message"]


def test_a_failed_flavor_download_prints_the_error_document(vdb_home, monkeypatch, capsys):
    from depscan.lib import vdb_setup

    def failing_refresh(url, attempts=None):
        raise RuntimeError("connection reset by peer")

    monkeypatch.setattr(vdb_setup, "download_vdb_with_retries", failing_refresh)
    assert run_depscan(monkeypatch, ["vdb", "download", "--flavor", "full", "--format", "json"]) == 1
    captured = capsys.readouterr()
    document = json.loads(captured.out)
    assert document["error"]["exitCode"] == 1
    assert document["error"]["verb"] == "vdb"
    assert "ghcr.io/appthreat/vdb7-full" in document["error"]["message"]
    assert "connection reset by peer" in document["error"]["message"]
    assert "connection reset by peer" in captured.err
    # A failed download records no variant marker.
    assert read_vdb_image_marker(str(vdb_home)) is None


def test_a_failed_shard_refresh_prints_the_error_document(vdb_home, monkeypatch, capsys):
    from depscan.lib import vdb_setup

    def failing_refresh(shard_names, store_dir=None, attempts=None):
        raise RuntimeError("shard store unreachable")

    monkeypatch.setattr(vdb_setup, "refresh_shards_with_retries", failing_refresh)
    argv = ["vdb", "download", "--shards", "pypi", "--format", "json"]
    assert run_depscan(monkeypatch, argv) == 1
    document = json.loads(capsys.readouterr().out)
    assert document["error"]["exitCode"] == 1
    assert document["error"]["verb"] == "vdb"
    assert "pypi" in document["error"]["message"]
    assert "shard store unreachable" in document["error"]["message"]
    assert read_vdb_image_marker(str(vdb_home)) is None


def test_an_unexpected_info_error_prints_the_error_document(vdb_home, monkeypatch, capsys):
    def exploding_store_status(store_dir=None):
        raise RuntimeError("store exploded")

    monkeypatch.setattr("depscan.vdb_cli.db_lib.get_db_file_metadata", lambda: None)
    monkeypatch.setattr("depscan.vdb_cli.db_cmd.store_status", exploding_store_status)
    assert run_depscan(monkeypatch, ["vdb", "info", "--format", "json"]) == 1
    captured = capsys.readouterr()
    document = json.loads(captured.out)
    assert document["error"]["exitCode"] == 1
    assert document["error"]["verb"] == "vdb"
    assert "store exploded" in document["error"]["message"]
    assert "store exploded" in captured.err


def test_an_unexpected_info_error_in_text_mode_stays_quiet_on_stdout(
    vdb_home, monkeypatch, caplog, capsys
):
    def exploding_store_status(store_dir=None):
        raise RuntimeError("store exploded")

    monkeypatch.setattr("depscan.vdb_cli.db_lib.get_db_file_metadata", lambda: None)
    monkeypatch.setattr("depscan.vdb_cli.db_cmd.store_status", exploding_store_status)
    assert run_depscan(monkeypatch, ["vdb", "info"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "store exploded" in caplog.text


def test_vdb_progress_prints_stay_off_stdout_in_json(vdb_home, monkeypatch, capsys):
    """vdb's refresh reports its progress on stdout; in json format stdout
    carries exactly one document, so the progress joins stderr."""
    from depscan.lib import vdb_setup

    def chatty_refresh(url, attempts=None):
        # vdb's refresh_full_image prints this line on stdout.
        print(f"Downloading vdb image {url} into the store (staged)")
        return {"image": url, "meta": {}}

    monkeypatch.setattr(vdb_setup, "download_vdb_with_retries", chatty_refresh)
    assert run_depscan(monkeypatch, ["vdb", "download", "--flavor", "full", "--format", "json"]) == 0
    captured = capsys.readouterr()
    document = json.loads(captured.out)
    # Positive control: the refresh ran and its progress reached stderr.
    assert "Downloading vdb image" in captured.err
    assert document["image"] == "ghcr.io/appthreat/vdb7-full:v7.0.x-xz"


# --- the usage errors -----------------------------------------------------------------


def test_a_usage_error_inside_a_subcommand_writes_the_document(monkeypatch, capsys):
    assert (
        run_depscan(monkeypatch, ["vdb", "download", "--flavor", "bogus", "--format", "json"])
        == 2
    )
    captured = capsys.readouterr()
    document = json.loads(captured.out)
    assert document["error"]["exitCode"] == 2
    assert document["error"]["verb"] == "vdb"
    assert "invalid choice: 'bogus'" in document["error"]["message"]
    # argparse's own usage and message stay on stderr.
    assert "usage: depscan vdb download" in captured.err
    assert "invalid choice: 'bogus'" in captured.err


def test_a_usage_error_inside_a_subcommand_stays_text_without_json(monkeypatch, capsys):
    assert run_depscan(monkeypatch, ["vdb", "download", "--flavor", "bogus"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "usage: depscan vdb download" in captured.err


def test_unrecognized_arguments_write_the_document_from_the_top_level(monkeypatch, capsys):
    assert run_depscan(monkeypatch, ["vdb", "download", "--bogus", "--format", "json"]) == 2
    captured = capsys.readouterr()
    document = json.loads(captured.out)
    assert document["error"]["exitCode"] == 2
    assert document["error"]["verb"] == "vdb"
    assert "--bogus" in document["error"]["message"]
    # The extras surface at the top level, whose usage names the verbs.
    assert "usage: depscan" in captured.err


# --- a download that fails for real -----------------------------------------------------


def test_a_real_unreachable_image_prints_the_error_document(vdb_home, monkeypatch, capsys):
    """The unstubbed download failure path, against an image reference no
    registry serves; vdb's retry backoff is skipped for the run."""
    monkeypatch.setattr("depscan.lib.vdb_setup.time.sleep", lambda seconds: None)
    argv = ["vdb", "download", "--image", "registry.invalid/vdb:nope", "--format", "json"]
    assert run_depscan(monkeypatch, argv) == 1
    captured = capsys.readouterr()
    document = json.loads(captured.out)
    assert document["error"]["exitCode"] == 1
    assert document["error"]["verb"] == "vdb"
    assert "registry.invalid/vdb:nope" in document["error"]["message"]
    assert read_vdb_image_marker(str(vdb_home)) is None
