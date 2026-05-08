import io
import json
import os
import tempfile
from pathlib import Path

import pytest
from quart.testing import QuartClient
from server_lib import ServerOptions
from server_lib import simple as simple_module
from server_lib.simple import app, run_server
from werkzeug.datastructures import FileStorage


@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["MAX_CONTENT_LENGTH"] = None
    for config_key in (
        "ALLOWED_HOSTS",
        "ALLOWED_PATHS",
        "API_KEY",
        "ALLOW_PRIVATE_URLS",
        "ALLOW_UNAUTHENTICATED_BIND",
        "MAX_BOM_FILE_SIZE",
        "create_bom",
    ):
        app.config.pop(config_key, None)
    app.config["MAX_CONTENT_LENGTH"] = None
    return app.test_client()


@pytest.fixture
def allowed_dirs():
    with tempfile.TemporaryDirectory() as safe_dir:
        sub_dir = Path(safe_dir) / "sub"
        sub_dir.mkdir()
        yield str(safe_dir), str(sub_dir)


@pytest.mark.asyncio
async def test_host_allowlist_blocks_disallowed(client: QuartClient):
    app.config["ALLOWED_HOSTS"] = ["127.0.0.1"]
    response = await client.get(
        "/scan?type=python&path=/tmp",
        headers={"X-Test-Remote-Addr": "192.168.1.10"},
    )
    assert response.status_code == 403
    data = await response.get_json()
    assert "Host not allowed" in data["message"]


@pytest.mark.asyncio
async def test_host_allowlist_allows_localhost(client: QuartClient):
    app.config["ALLOWED_HOSTS"] = ["127.0.0.1"]
    response = await client.get(
        "/scan?type=python&path=/tmp",
        headers={"X-Test-Remote-Addr": "127.0.0.1"},
    )
    assert response.status_code != 403


@pytest.mark.asyncio
async def test_path_allowlist_blocks_disallowed_path(client: QuartClient, allowed_dirs):
    safe_dir, _ = allowed_dirs
    app.config["ALLOWED_PATHS"] = [safe_dir]
    response = await client.get(
        "/scan?type=python&path=/etc/passwd",
        headers={"X-Test-Remote-Addr": "127.0.0.1"},
    )
    assert response.status_code == 403
    data = await response.get_json()
    assert "Path not allowed" in data["message"]


@pytest.mark.asyncio
async def test_path_allowlist_allows_subdir(client: QuartClient, allowed_dirs):
    safe_dir, sub_dir = allowed_dirs
    app.config["ALLOWED_PATHS"] = [safe_dir]
    response = await client.get(
        f"/scan?type=python&path={sub_dir}",
        headers={"X-Test-Remote-Addr": "127.0.0.1"},
    )
    assert response.status_code != 403


@pytest.mark.asyncio
async def test_path_allowlist_prevents_traversal(client: QuartClient, allowed_dirs):
    safe_dir, _ = allowed_dirs
    app.config["ALLOWED_PATHS"] = [safe_dir]
    malicious_path = os.path.join(safe_dir, "..", "..", "etc", "passwd")
    response = await client.get(
        f"/scan?type=python&path={malicious_path}",
        headers={"X-Test-Remote-Addr": "127.0.0.1"},
    )
    assert response.status_code == 403
    data = await response.get_json()
    assert "Path not allowed" in data["message"]


@pytest.mark.asyncio
async def test_path_allowlist_blocks_prefix_bypass(client: QuartClient, tmp_path):
    safe_dir = tmp_path / "data"
    safe_dir.mkdir()
    attacker_dir = tmp_path / "database"
    attacker_dir.mkdir()
    app.config["ALLOWED_PATHS"] = [str(safe_dir)]
    response = await client.get(
        f"/scan?type=python&path={attacker_dir}",
        headers={"X-Test-Remote-Addr": "127.0.0.1"},
    )
    assert response.status_code == 403
    data = await response.get_json()
    assert "Path not allowed" in data["message"]


def test_path_allowlist_skips_invalid_entries(monkeypatch, tmp_path):
    allowed_dir = tmp_path / "allowed"
    allowed_dir.mkdir()
    target_dir = allowed_dir / "subdir"
    target_dir.mkdir()

    real_commonpath = simple_module.os.path.commonpath

    def flaky_commonpath(paths):
        if paths[1] == "/invalid":
            raise ValueError("bad allowlist entry")
        return real_commonpath(paths)

    monkeypatch.setattr(simple_module.os.path, "commonpath", flaky_commonpath)

    assert simple_module._is_allowed_scan_path(str(target_dir), ["/invalid", str(allowed_dir)])


@pytest.mark.asyncio
async def test_path_from_json_body_enforced(client: QuartClient, allowed_dirs):
    safe_dir, _ = allowed_dirs
    app.config["ALLOWED_PATHS"] = [safe_dir]
    response = await client.post(
        "/scan",
        json={"type": "python", "path": "/tmp/evil"},
        headers={"X-Test-Remote-Addr": "127.0.0.1"},
    )
    assert response.status_code == 403
    data = await response.get_json()
    assert "Path not allowed" in data["message"]


@pytest.mark.asyncio
async def test_security_headers(client: QuartClient):
    response = await client.get("/")
    headers = response.headers
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "SAMEORIGIN"
    assert headers.get("X-XSS-Protection") == "1; mode=block"
    assert headers.get("Strict-Transport-Security") is None
    response_scan = await client.get("/scan", headers={"X-Test-Remote-Addr": "127.0.0.1"})
    headers_scan = response_scan.headers
    assert headers_scan.get("X-Content-Type-Options") == "nosniff"
    assert headers_scan.get("X-Frame-Options") == "SAMEORIGIN"
    assert headers_scan.get("X-XSS-Protection") == "1; mode=block"
    assert headers_scan.get("Strict-Transport-Security") is None


@pytest.mark.asyncio
async def test_no_allowlist_means_no_enforcement(client: QuartClient):
    app.config.pop("ALLOWED_HOSTS", None)
    app.config.pop("ALLOWED_PATHS", None)
    response1 = await client.get(
        "/scan?type=python&path=/any/path",
        headers={"X-Test-Remote-Addr": "192.168.99.99"},
    )
    assert response1.status_code != 403
    response2 = await client.get(
        "/scan?type=python&path=/any/path",
        headers={"X-Test-Remote-Addr": "127.0.0.1"},
    )
    assert response2.status_code != 403


@pytest.mark.asyncio
async def test_private_url_scan_is_blocked_by_default(client: QuartClient):
    response = await client.post(
        "/scan",
        json={"type": "python", "url": "http://127.0.0.1/internal/repo"},
        headers={"X-Test-Remote-Addr": "127.0.0.1"},
    )
    assert response.status_code == 400
    data = await response.get_json()
    assert "restricted address" in data["message"]


@pytest.mark.asyncio
async def test_private_url_scan_can_be_explicitly_allowed(client: QuartClient):
    app.config["ALLOW_PRIVATE_URLS"] = True
    response = await client.post(
        "/scan",
        json={"type": "python", "url": "http://127.0.0.1/internal/repo"},
        headers={"X-Test-Remote-Addr": "127.0.0.1"},
    )
    assert response.status_code == 400
    data = await response.get_json()
    assert "cdxgen server is required" in data["message"]


@pytest.mark.asyncio
async def test_scan_rejects_non_object_json_body_without_crashing(client: QuartClient):
    response = await client.post(
        "/scan?type=python",
        json=["unexpected"],
        headers={"X-Test-Remote-Addr": "127.0.0.1"},
    )
    assert response.status_code == 400
    data = await response.get_json()
    assert "path or url or a bom file upload is required" in data["message"]


@pytest.mark.asyncio
async def test_path_allowlist_ignores_non_object_json_body(client: QuartClient, allowed_dirs):
    safe_dir, _ = allowed_dirs
    app.config["ALLOWED_PATHS"] = [safe_dir]
    response = await client.post(
        "/scan?type=python",
        json=["path"],
        headers={"X-Test-Remote-Addr": "127.0.0.1"},
    )
    assert response.status_code == 400
    data = await response.get_json()
    assert "path or url or a bom file upload is required" in data["message"]


@pytest.mark.asyncio
async def test_uploaded_bom_rejects_invalid_utf8(client: QuartClient):
    response = await client.post(
        "/scan?type=python",
        files={
            "file": FileStorage(
                stream=io.BytesIO(b"\xff\xfe\x00\x01"),
                filename="sample.bom.json",
                content_type="application/json",
            )
        },
        headers={"X-Test-Remote-Addr": "127.0.0.1"},
    )
    assert response.status_code == 400
    data = await response.get_json()
    assert "valid UTF-8 JSON" in data["message"]


@pytest.mark.asyncio
async def test_uploaded_bom_size_limit_is_enforced(client: QuartClient):
    app.config["MAX_BOM_FILE_SIZE"] = 32
    response = await client.post(
        "/scan?type=python",
        files={
            "file": FileStorage(
                stream=io.BytesIO(b"{" + (b"a" * 128) + b"}"),
                filename="sample.bom.json",
                content_type="application/json",
            )
        },
        headers={"X-Test-Remote-Addr": "127.0.0.1"},
    )
    assert response.status_code == 400
    data = await response.get_json()
    assert "configured size limit" in data["message"]


def test_read_upload_with_limit_uses_bounded_reads():
    class TrackingStream(io.BytesIO):
        def __init__(self, payload):
            super().__init__(payload)
            self.read_sizes = []

        def read(self, size=-1):
            self.read_sizes.append(size)
            if size == -1:
                raise AssertionError("upload stream should not be read without a size limit")
            return super().read(size)

    stream = TrackingStream(b"{" + (b"a" * 128) + b"}")
    upload = FileStorage(
        stream=stream,
        filename="sample.bom.json",
        content_type="application/json",
    )

    upload_content, upload_error = simple_module._read_upload_with_limit(upload, 32)

    assert upload_content is None
    assert "configured size limit" in upload_error
    assert stream.read_sizes
    assert all(size != -1 for size in stream.read_sizes)
    assert max(stream.read_sizes) <= 33


def test_read_upload_with_limit_rejects_declared_size_before_reading():
    app.config["MAX_BOM_FILE_SIZE"] = 64

    class FailIfReadStream(io.BytesIO):
        def read(self, size=-1):
            raise AssertionError(
                "stream should not be read when declared size already exceeds limit"
            )

    upload = FileStorage(
        stream=FailIfReadStream(b'{"bomFormat":"CycloneDX"}'),
        filename="sample.bom.json",
        content_type="application/json",
        content_length=128,
    )

    upload_content, upload_error = simple_module._read_upload_with_limit(upload, 64)

    assert upload_content is None
    assert "configured size limit" in upload_error


@pytest.mark.asyncio
async def test_api_key_authentication_is_enforced(client: QuartClient):
    app.config["API_KEY"] = "super-secret"
    response = await client.get("/", headers={"X-Test-Remote-Addr": "127.0.0.1"})
    assert response.status_code == 401
    data = await response.get_json()
    assert "Authentication required" in data["message"]


@pytest.mark.asyncio
async def test_scan_existing_bom_path(client: QuartClient, tmp_path, monkeypatch):
    bom_path = tmp_path / "sample.bom.json"
    bom_path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "version": 1,
                "components": [],
            }
        ),
        encoding="utf-8",
    )

    class DummyAnalyzer:
        def __init__(self, vdr_options):
            self.vdr_options = vdr_options

        def process(self):
            return type(
                "DummyResult",
                (),
                {"success": True, "pkg_vulnerabilities": []},
            )()

    monkeypatch.setattr("server_lib.simple.get_pkg_list", lambda _: ([], None))
    monkeypatch.setattr("server_lib.simple.VDRAnalyzer", DummyAnalyzer)

    response = await client.get(
        f"/scan?type=python&path={bom_path}",
        headers={"X-Test-Remote-Addr": "127.0.0.1"},
    )
    assert response.status_code == 200
    data = await response.get_json()
    assert data["bomFormat"] == "CycloneDX"


@pytest.mark.asyncio
async def test_scan_existing_bom_path_with_invalid_max_content_length(
    client: QuartClient, tmp_path, monkeypatch
):
    bom_path = tmp_path / "sample.bom.json"
    bom_path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "version": 1,
                "components": [],
            }
        ),
        encoding="utf-8",
    )

    class DummyAnalyzer:
        def __init__(self, vdr_options):
            self.vdr_options = vdr_options

        def process(self):
            return type(
                "DummyResult",
                (),
                {"success": True, "pkg_vulnerabilities": []},
            )()

    app.config["MAX_CONTENT_LENGTH"] = "not-an-integer"
    monkeypatch.setattr("server_lib.simple.get_pkg_list", lambda _: ([], None))
    monkeypatch.setattr("server_lib.simple.VDRAnalyzer", DummyAnalyzer)

    response = await client.get(
        f"/scan?type=python&path={bom_path}",
        headers={"X-Test-Remote-Addr": "127.0.0.1"},
    )
    assert response.status_code == 200
    data = await response.get_json()
    assert data["bomFormat"] == "CycloneDX"


def test_run_server_refuses_non_local_bind_without_auth(monkeypatch):
    called = {"run": False}

    def fake_run(**_kwargs):
        called["run"] = True

    monkeypatch.setattr(app, "run", fake_run)
    app.config["API_KEY"] = None
    app.config["ALLOW_UNAUTHENTICATED_BIND"] = False

    result = run_server(ServerOptions(server_host="0.0.0.0", server_port=7070))

    assert result is False
    assert called["run"] is False


@pytest.mark.asyncio
async def test_index_endpoint(client: QuartClient):
    response = await client.get("/")
    assert response.status_code == 200
    data = await response.get_json()
    assert data == {}
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
