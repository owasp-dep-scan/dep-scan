import os

import pytest

from vdb.lib import config as _vdb_config

# The data directory vdb resolved at import: the user's real database. No
# test may write below it; every test runs against a temporary one instead,
# and the guard below fails the run when the real one changed.
_REAL_VDB_DIR = _vdb_config.DATA_DIR


def _snapshot(directory):
    """Name, size and mtime of every entry directly in ``directory``, and the
    text of the small marker files, or None when it does not exist."""
    if not os.path.isdir(directory):
        return None
    entries = {}
    for entry in sorted(os.scandir(directory), key=lambda e: e.name):
        stat = entry.stat(follow_symlinks=False)
        content = None
        if entry.is_file(follow_symlinks=False) and stat.st_size < 4096:
            with open(entry.path, encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        entries[entry.name] = (stat.st_size, stat.st_mtime_ns, content)
    return entries


_REAL_VDB_SNAPSHOT = _snapshot(_REAL_VDB_DIR)


def pytest_sessionfinish(session, exitstatus):
    """Fail the run when a test changed the real vulnerability database
    directory (a marker file, a download staging directory, a data file)."""
    after = _snapshot(_REAL_VDB_DIR)
    if after == _REAL_VDB_SNAPSHOT:
        return
    changed = sorted(
        name
        for name in set(after or {}) | set(_REAL_VDB_SNAPSHOT or {})
        if (after or {}).get(name) != (_REAL_VDB_SNAPSHOT or {}).get(name)
    )
    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    message = f"tests changed the real vdb directory {_REAL_VDB_DIR}: {', '.join(changed)}"
    if reporter is not None:
        reporter.write_line(message, red=True)
    session.exitstatus = 1


# vdb's published defaults. vdb reads VDB_DATABASE_URL and
# VDB_APP_ONLY_DATABASE_URL once at import, so clearing the environment alone
# does not undo a value the CI job set.
_VDB_DEFAULT_URL = "ghcr.io/appthreat/vdb7-full:v7.0.x-xz"
_VDB_DEFAULT_APP_ONLY_URL = "ghcr.io/appthreat/vdb7-app-only:v7.0.x-xz"


@pytest.fixture(autouse=True)
def _isolate_vdb_selection(monkeypatch):
    """Keep the database selection a test sees independent of the caller's
    environment. CI jobs pin VDB_DATABASE_URL to a small image for their real
    scans; tests that need a pin set one themselves."""
    from vdb.lib import config as vdb_config

    for name in (
        "VDB_DATABASE_URL",
        "VDB_APP_ONLY_DATABASE_URL",
        "USE_VDB_10Y",
        "VDB_USE_SHARDS",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(vdb_config, "VDB_DATABASE_URL", _VDB_DEFAULT_URL)
    monkeypatch.setattr(vdb_config, "VDB_APP_ONLY_DATABASE_URL", _VDB_DEFAULT_APP_ONLY_URL)


@pytest.fixture(autouse=True)
def _restore_fetch_license():
    """Undo the FETCH_LICENSE value a scan's setup writes into os.environ.

    The license stage turns itself on by setting the variable for cdxgen, and
    ``monkeypatch.delenv(..., raising=False)`` records nothing when it was
    unset, so without this a license test turns the license stage on for
    every scan run after it."""
    import os

    saved = os.environ.get("FETCH_LICENSE")
    yield
    if saved is None:
        os.environ.pop("FETCH_LICENSE", None)
    else:
        os.environ["FETCH_LICENSE"] = saved


@pytest.fixture(autouse=True)
def _isolate_vdb_data_dir(monkeypatch, tmp_path_factory):
    """Point every vdb and dep-scan data location at a per-test directory.

    vdb binds the data, cache and shard directories at import from VDB_HOME,
    VDB_CACHE and VDB_SHARDS_DIR and derives its database file names from
    them, so the module attributes and the environment are both moved. A test
    that wants a particular directory sets it itself, after this fixture."""
    from vdb.lib import config as vdb_config

    home = str(tmp_path_factory.mktemp("vdb-home"))
    cache = str(tmp_path_factory.mktemp("vdb-cache"))
    monkeypatch.setenv("VDB_HOME", home)
    monkeypatch.setenv("VDB_CACHE", cache)
    monkeypatch.delenv("VDB_SHARDS_DIR", raising=False)
    monkeypatch.setattr(vdb_config, "DATA_DIR", home)
    monkeypatch.setattr(vdb_config, "CACHE_DIR", cache)
    monkeypatch.setattr(vdb_config, "VDB_BIN_FILE", os.path.join(home, "data.vdb7"))
    monkeypatch.setattr(vdb_config, "VDB_BIN_INDEX", os.path.join(home, "data.index.vdb7"))
    monkeypatch.setattr(vdb_config, "VDB_METADATA_FILE", os.path.join(home, "vdb.meta"))
    monkeypatch.setattr(vdb_config, "VDB_SHARDS_DIR", os.path.join(home, "shards"))
