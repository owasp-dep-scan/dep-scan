import os
import tempfile
from pathlib import Path

import pytest
from quart.testing import QuartClient

from server_lib.simple import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
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
async def test_no_allowlist_means_no_enforcement(client: QuartClient):
    app.config.pop("ALLOWED_HOSTS", None)
    app.config.pop("ALLOWED_PATHS", None)
    response = await client.get(
        "/scan?type=python&path=/any/path",
        headers={"X-Test-Remote-Addr": "192.168.99.99"},
    )
    assert response.status_code != 403


@pytest.mark.asyncio
async def test_security_headers(client: QuartClient):
    response = await client.get("/")
    headers = response.headers
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "SAMEORIGIN"
    assert headers.get("X-XSS-Protection") == "1; mode=block"
    assert (
        headers.get("Strict-Transport-Security")
        == "max-age=31536000; includeSubDomains"
    )
    response_scan = await client.get(
        "/scan", headers={"X-Test-Remote-Addr": "127.0.0.1"}
    )
    headers_scan = response_scan.headers
    assert headers_scan.get("X-Content-Type-Options") == "nosniff"
    assert headers_scan.get("X-Frame-Options") == "SAMEORIGIN"
    assert headers_scan.get("X-XSS-Protection") == "1; mode=block"
    assert (
        headers_scan.get("Strict-Transport-Security")
        == "max-age=31536000; includeSubDomains"
    )


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
async def test_index_endpoint(client: QuartClient):
    response = await client.get("/")
    assert response.status_code == 200
    data = await response.get_json()
    assert data == {}
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
