"""The suite never works in the user's real vulnerability database directory."""

import os

from vdb.lib import config as vdb_config

from depscan.lib.config import read_vdb_image_marker, write_vdb_image_marker
from test import conftest


def test_every_test_runs_against_its_own_data_directory():
    assert vdb_config.DATA_DIR != conftest._REAL_VDB_DIR
    assert os.environ["VDB_HOME"] == vdb_config.DATA_DIR
    for derived in (
        vdb_config.VDB_BIN_FILE,
        vdb_config.VDB_BIN_INDEX,
        vdb_config.VDB_METADATA_FILE,
        vdb_config.VDB_SHARDS_DIR,
    ):
        assert derived.startswith(vdb_config.DATA_DIR)


def test_the_image_marker_is_written_to_the_temporary_directory():
    before = conftest._snapshot(conftest._REAL_VDB_DIR)
    write_vdb_image_marker("oras://vdb-img", vdb_config.DATA_DIR)
    assert read_vdb_image_marker(vdb_config.DATA_DIR) == "oras://vdb-img"
    assert conftest._snapshot(conftest._REAL_VDB_DIR) == before


def test_the_snapshot_sees_a_changed_marker_and_a_new_file(tmp_path):
    marker = tmp_path / ".depscan-vdb-image"
    marker.write_text("one")
    before = conftest._snapshot(str(tmp_path))
    assert before == conftest._snapshot(str(tmp_path))
    marker.write_text("two")
    assert conftest._snapshot(str(tmp_path)) != before
    marker.write_text("one")
    (tmp_path / ".incoming-vdb-1").mkdir()
    assert conftest._snapshot(str(tmp_path)) != before
    assert conftest._snapshot(str(tmp_path / "missing")) is None
