import httpretty

from depscan.lib import github

url = "https://api.github.com/"


def test_can_authenticate_success():
    httpretty.enable()
    httpretty.reset()

    headers = {
        "content-type": "application/json",
        "X-OAuth-Scopes": "admin:org, admin:repo_hook, repo, user",
        "X-Accepted-OAuth-Scopes": "repo",
    }

    httpretty.register_uri(method=httpretty.GET, uri=url, adding_headers=headers)

    github_client = github.GitHub("test-token")
    result = github_client.can_authenticate()

    httpretty.disable()

    assert result


def test_can_authenticate_unauthentiated():
    httpretty.enable()
    httpretty.reset()

    headers = {"content-type": "application/json"}

    httpretty.register_uri(
        method=httpretty.GET,
        uri=url,
        body='{"message":"Bad credentials"}',
        adding_headers=headers,
        status=401,
    )

    github_client = github.GitHub("test-token")
    result = github_client.can_authenticate()

    httpretty.disable()

    assert not result


def test_get_token_scopes_success():
    httpretty.enable()
    httpretty.reset()

    headers = {
        "content-type": "application/json",
        "X-OAuth-Scopes": "admin:org, admin:repo_hook, repo, user",
        "X-Accepted-OAuth-Scopes": "repo",
    }

    httpretty.register_uri(method=httpretty.GET, uri=url, adding_headers=headers)

    github_client = github.GitHub("test-token")
    result = github_client.get_token_scopes()

    httpretty.disable()

    assert (
        len(result) == 4
        and result.index("admin:org") >= 0
        and result.index("admin:repo_hook") >= 0
        and result.index("repo") >= 0
        and result.index("user") >= 0
    )


def test_get_token_scopes_none():
    httpretty.enable()
    httpretty.reset()

    headers = {
        "content-type": "application/json",
    }

    httpretty.register_uri(method=httpretty.GET, uri=url, adding_headers=headers)

    github_client = github.GitHub("test-token")
    result = github_client.get_token_scopes()

    httpretty.disable()

    assert result == []


def test_get_token_scopes_empty():
    httpretty.enable()
    httpretty.reset()

    headers = {"content-type": "application/json", "x-oauth-scopes": ""}

    httpretty.register_uri(method=httpretty.GET, uri=url, adding_headers=headers)

    github_client = github.GitHub("test-token")
    result = github_client.get_token_scopes()

    httpretty.disable()

    assert result == []
