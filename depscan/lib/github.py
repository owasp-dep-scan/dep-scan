import os

import httpx
from github import Auth, Github

from depscan.lib import config


class GitHub:
    # The GitHub instance object from the PyGithub library
    github = None
    github_token = None

    def __init__(self, github_token: str):
        self.github = Github(auth=Auth.Token(github_token))
        self.github_token = github_token

    def can_authenticate(self):
        """
        Calls the GitHub API to determine if the token is valid

        :return: Flag indicating whether authentication was successful or not
        """
        headers = {"Authorization": f"token {self.github_token}"}
        try:
            httpx.get(
                url=os.getenv("GITHUB_API_URL", "https://api.github.com"),
                headers=headers,
                follow_redirects=True,
                timeout=config.request_timeout_sec,
            ).raise_for_status()
            return True
        except httpx.HTTPStatusError:
            return False

    def get_token_scopes(self):
        """
        Provides the scopes associated to the access token provided in the environment variable
        Only classic personal access tokens will result in scopes returned from the GitHub API

        :return: List of token scopes
        """
        headers = {"Authorization": f"token {self.github_token}"}

        response = httpx.get(
            url=os.getenv("GITHUB_API_URL", "https://api.github.com"),
            headers=headers,
            follow_redirects=True,
            timeout=config.request_timeout_sec,
        )
        oauth_scopes = response.headers.get("x-oauth-scopes")
        if oauth_scopes:
            return oauth_scopes.split(", ")
        return []
