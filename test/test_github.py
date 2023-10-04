from depscan.lib import github
import httpretty
import os


user_url = 'https://api.github.com/user'
user_success_response_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), "data", "github-response-user-success.json")
with open(user_success_response_file) as file:
    user_success_json = file.read()


def test_authenticate_success():
    httpretty.enable()
    httpretty.reset()
    
    headers = {
        'content-type': 'application/json',
        'X-OAuth-Scopes': 'admin:org, admin:repo_hook, repo, user',
        'X-Accepted-OAuth-Scopes': 'repo'
    }

    httpretty.register_uri(
        method=httpretty.GET,
        uri=user_url,
        body=user_success_json,
        adding_headers=headers
    )
    
    github_client = github.GitHub('test-token')
    result = github_client.authenticate()

    httpretty.disable()

    assert result == True


def test_authenticate_unauthentiated():
    httpretty.enable()
    httpretty.reset()
    
    headers = {
        'content-type': 'application/json'
    }

    httpretty.register_uri(
        method=httpretty.GET,
        uri=user_url,
        body='{"message":"Bad credentials"}',
        adding_headers=headers,
        status=401
    )
    
    github_client = github.GitHub('test-token')
    result = github_client.authenticate()

    httpretty.disable()

    assert result == False


def test_get_token_scopes_success():
    httpretty.enable()
    httpretty.reset()

    headers = {
        'content-type': 'application/json',
        'X-OAuth-Scopes': 'admin:org, admin:repo_hook, repo, user',
        'X-Accepted-OAuth-Scopes': 'repo'
    }

    httpretty.register_uri(
        method=httpretty.GET,
        uri=user_url,
        body=user_success_json,
        adding_headers=headers
    )
    
    github_client = github.GitHub('test-token')
    result = github_client.get_token_scopes()

    httpretty.disable()

    assert len(result) == 4 and result.index('admin:org') >= 0 and result.index('admin:repo_hook') >= 0 and result.index('repo') >= 0 and result.index('user') >= 0


def test_get_token_scopes_none():
    httpretty.enable()
    httpretty.reset()

    headers = {
        'content-type': 'application/json',
    }

    httpretty.register_uri(
        method=httpretty.GET,
        uri=user_url,
        body=user_success_json,
        adding_headers=headers
    )
    
    github_client = github.GitHub('test-token')
    result = github_client.get_token_scopes()

    httpretty.disable()

    assert result is None


def test_get_token_scopes_empty():
    httpretty.enable()
    httpretty.reset()

    headers = {
        'content-type': 'application/json',
        'x-oauth-scopes': ''
    }

    httpretty.register_uri(
        method=httpretty.GET,
        uri=user_url,
        body=user_success_json,
        adding_headers=headers
    )
    
    github_client = github.GitHub('test-token')
    result = github_client.get_token_scopes()

    httpretty.disable()

    assert result is None