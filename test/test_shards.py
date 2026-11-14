"""Tests for opt-in shard mode (VDB_USE_SHARDS) and download interruption.

vdb owns the placement (``db_cmd.refresh_shards``, atomic per shard) and the
coverage answer (``shard_store.coverage_for_types``); these tests stub those
boundaries and prove depscan calls them with the right arguments, never
unpacks into the database directory itself, and never enables mid-scan
fetching.
"""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from depscan import cli


@pytest.fixture
def vdb_home(tmp_path, monkeypatch):
    """An isolated database home with its own shard store; vdb's config
    captured the import-time paths, so they are patched alongside the env.

    The directory is resolved because vdb opens its databases with
    SQLITE_OPEN_NOFOLLOW, which refuses a path that crosses a symlinked
    directory (macOS keeps its temp dirs behind /var -> /private/var).
    """
    home = tmp_path.resolve() / "vdb-home"
    home.mkdir()
    store = home / "shards"
    store.mkdir()
    monkeypatch.setenv("VDB_HOME", str(home))
    monkeypatch.setattr(cli.config, "DATA_DIR", str(home))
    monkeypatch.setattr(cli.config, "VDB_BIN_FILE", str(home / "data.vdb7"))
    monkeypatch.setattr(cli.config, "VDB_BIN_INDEX", str(home / "data.index.vdb7"))
    monkeypatch.setattr(cli.config, "VDB_SHARDS_DIR", str(store))
    yield home
    cli.db_lib.reset_connections()


# ---------------------------------------------------------------------------
# VDB_AUTO_FETCH stays off: a scan never downloads mid-run
# ---------------------------------------------------------------------------


def test_depscan_never_enables_vdb_auto_fetch():
    """Tripwire: no depscan source may touch VDB_AUTO_FETCH, because a scan
    reaching for the network mid-run is a behaviour users must opt into at
    the vdb level, never one depscan enables for them. Relaxing this test
    means changing that decision deliberately."""
    import depscan

    package_root = Path(depscan.__file__).parent
    offenders = []
    for path in package_root.rglob("*.py"):
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            code = line.split("#", 1)[0]
            if "VDB_AUTO_FETCH" in code:
                offenders.append(f"{path.relative_to(package_root.parent)}:{lineno}")
    assert offenders == []


def test_shard_setup_does_not_enable_auto_fetch(vdb_home, monkeypatch):
    """Running the shard-mode setup must leave the environment untouched."""
    monkeypatch.setattr(cli, "refresh_shards_with_retries", lambda names, store_dir=None: names)
    monkeypatch.setattr(
        cli,
        "report_shard_coverage",
        lambda types, store_dir=None: SimpleNamespace(
            uncovered_types=frozenset(), stale_shards=()
        ),
    )
    monkeypatch.setattr(cli, "connect_shard_as_main", lambda shard_dir, store_dir: None)
    monkeypatch.setattr(cli, "shards_refresh_needed", lambda marker, store_dir=None: (True, "x"))
    cli.setup_shards_for_scan(["pypi"])
    assert os_environ_truthy("VDB_AUTO_FETCH") is False


def os_environ_truthy(name):
    import os

    return os.environ.get(name, "") in ("true", "1")


# ---------------------------------------------------------------------------
# collect_purl_types: when the scan's types are known before matching
# ---------------------------------------------------------------------------


def _args(**kwargs):
    import argparse

    fields = {
        "search_purl": None,
        "bom": None,
        "bom_dir": None,
    }
    fields.update(kwargs)
    return argparse.Namespace(**fields)


def test_collect_purl_types_from_single_purl():
    assert cli.collect_purl_types(_args(search_purl="pkg:pypi/requests@2.32.1"), ".") == ["pypi"]


def test_collect_purl_types_dedupes_and_lowercases(tmp_path):
    bom = tmp_path / "bom.json"
    bom.write_text(
        json.dumps(
            {
                "components": [
                    {"purl": "pkg:NPM/lodash@4.17.21"},
                    {"purl": "pkg:npm/express@4.0.0"},
                    {"purl": "pkg:pypi/flask@3.0"},
                    {"name": "no-purl-here"},
                ]
            }
        )
    )
    assert cli.collect_purl_types(_args(bom=str(bom)), ".") == ["npm", "pypi"]


def test_collect_purl_types_empty_without_known_types(tmp_path):
    """When depscan generates the BOM itself, the types are not known before
    matching and shard mode cannot apply."""
    assert cli.collect_purl_types(_args(), str(tmp_path)) == []
    assert cli.collect_purl_types(_args(bom=str(tmp_path / "missing.json")), ".") == []


# ---------------------------------------------------------------------------
# setup_shards_for_scan: stubbed vdb refresh with positive controls
# ---------------------------------------------------------------------------


def test_setup_shards_refreshes_canonical_shards(vdb_home, monkeypatch):
    """The refresh asks vdb for exactly the canonical shards of the scan's
    purl types, into the store beside the database home, and records the
    shard-set marker."""
    refresh_calls = []
    connect_calls = []
    coverage_calls = []

    monkeypatch.setattr(cli, "shards_refresh_needed", lambda marker, store_dir=None: (True, "x"))

    def fake_refresh(shard_names, store_dir=None, attempts=None):
        refresh_calls.append((list(shard_names), store_dir))
        return list(shard_names)

    def fake_connect(shard_dir, store_dir):
        connect_calls.append((shard_dir, store_dir))

    def fake_coverage(purl_types, store_dir=None):
        coverage_calls.append((sorted(purl_types), store_dir))
        return SimpleNamespace(uncovered_types=frozenset(), stale_shards=())

    monkeypatch.setattr(cli, "refresh_shards_with_retries", fake_refresh)
    monkeypatch.setattr(cli, "connect_shard_as_main", fake_connect)
    monkeypatch.setattr(cli, "report_shard_coverage", fake_coverage)

    connected = cli.setup_shards_for_scan(["pypi", "npm"])
    store = str(vdb_home / "shards")
    # Positive controls: the canonical shard list reached vdb's refresh, the
    # first shard was connected as the main database, and coverage was
    # reported for the requested types.
    assert refresh_calls == [(["pypi", "npm"], store)]
    assert connect_calls == [(f"{store}/pypi", store)]
    assert coverage_calls == [(["npm", "pypi"], store)]
    assert connected == ["pypi", "npm"]
    from depscan.lib.config import read_vdb_image_marker

    assert read_vdb_image_marker(str(vdb_home)) == "shards:npm,pypi"


def test_setup_shards_skips_refresh_when_fresh(vdb_home, monkeypatch):
    """A matching marker and fresh shards mean no refresh; the store is only
    connected and coverage-reported."""
    from depscan.lib.config import write_vdb_image_marker

    write_vdb_image_marker("shards:pypi", str(vdb_home))
    monkeypatch.setattr(cli, "shards_refresh_needed", lambda marker, store_dir=None: (False, None))
    refresh_calls = []
    monkeypatch.setattr(
        cli, "refresh_shards_with_retries", lambda *a, **k: refresh_calls.append(a)
    )
    monkeypatch.setattr(cli, "connect_shard_as_main", lambda shard_dir, store_dir: None)
    monkeypatch.setattr(
        cli,
        "report_shard_coverage",
        lambda types, store_dir=None: SimpleNamespace(
            uncovered_types=frozenset(), stale_shards=()
        ),
    )
    assert cli.setup_shards_for_scan(["pypi"]) == ["pypi"]
    assert refresh_calls == []


def test_setup_shards_exits_when_nothing_lands(vdb_home, monkeypatch):
    monkeypatch.setattr(cli, "shards_refresh_needed", lambda marker, store_dir=None: (True, "x"))
    monkeypatch.setattr(cli, "refresh_shards_with_retries", lambda names, store_dir=None: [])
    with pytest.raises(SystemExit) as exc:
        cli.setup_shards_for_scan(["pypi"])
    assert exc.value.code == 1


def test_unknown_purl_type_maps_to_the_cpe_shard(vdb_home, monkeypatch):
    """Types without their own shard resolve to the cpe complement shard in
    vdb's table, so they are fetched rather than assumed uncovered."""
    refresh_calls = []
    monkeypatch.setattr(cli, "shards_refresh_needed", lambda marker, store_dir=None: (True, "x"))
    monkeypatch.setattr(
        cli,
        "refresh_shards_with_retries",
        lambda names, store_dir=None: refresh_calls.append(list(names)) or list(names),
    )
    monkeypatch.setattr(cli, "connect_shard_as_main", lambda shard_dir, store_dir: None)
    monkeypatch.setattr(
        cli,
        "report_shard_coverage",
        lambda types, store_dir=None: SimpleNamespace(
            uncovered_types=frozenset(), stale_shards=()
        ),
    )
    cli.setup_shards_for_scan(["notarealtype"])
    assert refresh_calls == [["cpe"]]


def test_shards_refresh_needed_policy(vdb_home, monkeypatch):
    """The store is the truth: a subset of already-fetched fresh shards needs
    no refresh; a missing or over-age shard does."""
    store = str(vdb_home / "shards")

    def status_with(shards):
        return {"shards": shards}

    fresh_pair = [
        {"name": "npm", "age_days": 0.5},
        {"name": "pypi", "age_days": 0.5},
    ]
    stale = [{"name": "pypi", "age_days": 3.0}]
    unknown_age = [{"name": "pypi", "age_days": None}]

    monkeypatch.setattr(cli.db_lib, "needs_update", lambda **kw: False)
    # A store already holding fresh shards serves a subset without refreshing.
    monkeypatch.setattr(
        "vdb.lib.db_cmd.store_status", lambda store_dir=None: status_with(fresh_pair)
    )
    needed, reason = cli.shards_refresh_needed(["pypi"], store_dir=store)
    assert needed is False and reason is None
    # A shard missing from the store refreshes, naming it.
    needed, reason = cli.shards_refresh_needed(["pypi", "npm", "golang"], store_dir=store)
    assert needed is True and reason == "missing shards: golang"
    # A shard older than the window refreshes.
    monkeypatch.setattr("vdb.lib.db_cmd.store_status", lambda store_dir=None: status_with(stale))
    needed, reason = cli.shards_refresh_needed(["pypi"], store_dir=store)
    assert needed is True and reason == "stale"
    # So does a shard whose age cannot be determined.
    monkeypatch.setattr(
        "vdb.lib.db_cmd.store_status", lambda store_dir=None: status_with(unknown_age)
    )
    needed, reason = cli.shards_refresh_needed(["pypi"], store_dir=store)
    assert needed is True and reason == "stale"
    # An empty store refreshes too (everything is missing).
    monkeypatch.setattr("vdb.lib.db_cmd.store_status", lambda store_dir=None: {"shards": []})
    needed, reason = cli.shards_refresh_needed(["pypi"], store_dir=store)
    assert needed is True and reason == "missing shards: pypi"


# ---------------------------------------------------------------------------
# Coverage reporting: uncovered types warn, are never clean
# ---------------------------------------------------------------------------


def test_report_shard_coverage_warns_for_uncovered_types(vdb_home, monkeypatch, caplog):
    """The warning names the uncovered types; the answer comes from vdb's
    coverage_for_types, never a local table."""
    from vdb.lib import shard_store

    calls = []

    def fake_coverage(purl_types, store_dir=None):
        calls.append((sorted(purl_types), store_dir))
        return (
            SimpleNamespace(uncovered_types=frozenset({"swift", "pub"}), stale_shards=("deb",)),
            [],
        )

    monkeypatch.setattr(shard_store, "coverage_for_types", fake_coverage)
    with caplog.at_level("WARNING"):
        coverage = cli.report_shard_coverage(["swift", "pub", "pypi"], store_dir="store-x")
    assert coverage.uncovered_types == frozenset({"swift", "pub"})
    # Positive control: vdb's coverage was asked about exactly these types.
    assert calls == [(["pub", "pypi", "swift"], "store-x")]
    messages = " ".join(record.getMessage() for record in caplog.records)
    assert "pub, swift" in messages
    assert "NOT assessed" in messages
    assert "shard deb is much older than its siblings" in messages


# ---------------------------------------------------------------------------
# connect_shard_as_main: the fan-out layout
# ---------------------------------------------------------------------------


def test_connect_shard_as_main_points_everything_at_the_shard(vdb_home, monkeypatch, tmp_path):
    resets = []
    monkeypatch.setattr(cli.db_lib, "reset_connections", lambda: resets.append("db"))
    import vdb.lib.shard_store as shard_store

    monkeypatch.setattr(shard_store, "reset", lambda: resets.append("store"))
    shard_dir = str(tmp_path.resolve() / "shards" / "pypi")
    store_dir = str(tmp_path.resolve() / "shards")
    cli.connect_shard_as_main(shard_dir, store_dir)
    assert cli.config.DATA_DIR == shard_dir
    assert cli.config.VDB_BIN_FILE == f"{shard_dir}/data.vdb7"
    assert cli.config.VDB_BIN_INDEX == f"{shard_dir}/data.index.vdb7"
    assert cli.config.VDB_SHARDS_DIR == store_dir
    import os

    assert os.environ["VDB_HOME"] == shard_dir
    assert os.environ["VDB_SHARDS_DIR"] == store_dir
    assert resets == ["db", "store"]


# ---------------------------------------------------------------------------
# Interrupted download: the previous database stays usable
# ---------------------------------------------------------------------------


def _build_one_row_database(home):
    cli.db_lib.reset_connections()
    _, index_conn = cli.db_lib.get()
    index_conn.execute(
        "INSERT INTO cve_index(cve_id, type, namespace, name, vers, purl_prefix) "
        "VALUES('CVE-2024-1', 'pypi', '', 'requests', 'vers:pypi/>=2.0', 'pkg:pypi/requests')"
    )
    cli.db_lib.reset_connections()


def test_interrupted_refresh_leaves_previous_database_usable(vdb_home, monkeypatch):
    """A download that dies mid-stream after staging files must leave the
    previous database in place and readable, because vdb swaps atomically and
    depscan never unpacks into the database directory itself."""
    import hashlib

    from vdb.lib import orasclient
    from vdb.lib.db_cmd import VdbDbCommandError

    _build_one_row_database(vdb_home)

    def digest(path):
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()

    before = {name: digest(vdb_home / name) for name in ("data.vdb7", "data.index.vdb7")}
    fetch_calls = []

    def exploding_download(url, outdir):
        # Simulate a partial download: bytes land in vdb's staging directory,
        # then the connection dies.
        fetch_calls.append(url)
        Path(outdir, "data.vdb7").write_bytes(b"partial download, not a database")
        raise ConnectionError("simulated interruption mid-download")

    monkeypatch.setattr(orasclient, "download_image", exploding_download)
    monkeypatch.setattr(cli.time, "sleep", lambda s: None)
    with pytest.raises(VdbDbCommandError, match="left untouched"):
        cli.download_vdb_with_retries("ghcr.io/appthreat/vdb7-app-only:v7.0.x-xz", attempts=1)
    # Positive control: the stubbed fetch ran, so the failure path is the one
    # under test.
    assert fetch_calls == ["ghcr.io/appthreat/vdb7-app-only:v7.0.x-xz"]
    # The previous files are byte-for-byte unchanged...
    assert {name: digest(vdb_home / name) for name in before} == before
    # ...no new database file was swapped in (vdb stages under .incoming-vdb-*
    # directories and sweeps them on the next refresh, so only the staging
    # directory of this failed attempt may appear beside the database)...
    assert not (vdb_home / "vdb.meta").exists()
    # ...and the database still opens and answers.
    _, index_conn = cli.db_lib.get(read_only=True)
    row = index_conn.execute("SELECT count(*) FROM cve_index").fetchone()
    assert row is not None and row[0] == 1
    cli.db_lib.reset_connections()


def test_interrupted_shard_refresh_leaves_previous_shard_usable(vdb_home, monkeypatch):
    """A shard refresh that fails must not damage the shards already in the
    store: vdb places each shard with an atomic directory rename."""
    from vdb.lib import shard_store
    from vdb.lib.shard_store import ShardFetchError

    store = vdb_home / "shards"
    existing = store / "pypi"
    existing.mkdir()
    (existing / "marker").write_text("previous complete artifact")

    def failing_fetch(names, **kwargs):
        raise ShardFetchError("simulated fetch failure")

    monkeypatch.setattr(shard_store, "fetch_shards", failing_fetch)
    monkeypatch.setattr(cli.time, "sleep", lambda s: None)
    with pytest.raises(ShardFetchError):
        cli.refresh_shards_with_retries(["npm", "pypi"], store_dir=str(store), attempts=1)
    assert (existing / "marker").read_text() == "previous complete artifact"
