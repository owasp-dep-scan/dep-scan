import pytest

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
