from unittest.mock import patch

import httpx

from depscan.lib import github

url = "https://api.github.com/"


def _mock_response(status_code=200, headers=None, json_body=None):
    return httpx.Response(
        status_code=status_code,
        headers=headers,
        json=json_body,
        request=httpx.Request("GET", url),
    )


def test_can_authenticate_success():
    headers = {
        "content-type": "application/json",
        "X-OAuth-Scopes": "admin:org, admin:repo_hook, repo, user",
        "X-Accepted-OAuth-Scopes": "repo",
    }

    with patch(
        "depscan.lib.github.httpx.get",
        return_value=_mock_response(headers=headers),
    ):
        github_client = github.GitHub("test-token")
        result = github_client.can_authenticate()

    assert result


def test_can_authenticate_unauthentiated():
    headers = {"content-type": "application/json"}

    with patch(
        "depscan.lib.github.httpx.get",
        return_value=_mock_response(
            status_code=401,
            headers=headers,
            json_body={"message": "Bad credentials"},
        ),
    ):
        github_client = github.GitHub("test-token")
        result = github_client.can_authenticate()

    assert not result


def test_get_token_scopes_success():
    headers = {
        "content-type": "application/json",
        "X-OAuth-Scopes": "admin:org, admin:repo_hook, repo, user",
        "X-Accepted-OAuth-Scopes": "repo",
    }

    with patch(
        "depscan.lib.github.httpx.get",
        return_value=_mock_response(headers=headers),
    ):
        github_client = github.GitHub("test-token")
        result = github_client.get_token_scopes()

    assert (
        len(result) == 4
        and result.index("admin:org") >= 0
        and result.index("admin:repo_hook") >= 0
        and result.index("repo") >= 0
        and result.index("user") >= 0
    )


def test_get_token_scopes_none():
    headers = {
        "content-type": "application/json",
    }

    with patch(
        "depscan.lib.github.httpx.get",
        return_value=_mock_response(headers=headers),
    ):
        github_client = github.GitHub("test-token")
        result = github_client.get_token_scopes()

    assert result == []


def test_get_token_scopes_empty():
    headers = {"content-type": "application/json", "x-oauth-scopes": ""}

    with patch(
        "depscan.lib.github.httpx.get",
        return_value=_mock_response(headers=headers),
    ):
        github_client = github.GitHub("test-token")
        result = github_client.get_token_scopes()

    assert result == []
