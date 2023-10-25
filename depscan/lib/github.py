from github import Github, Auth
from depscan.lib import config
import httpx


class GitHub:
    # The GitHub instance object from the PyGithub library
    github = None
    github_token = None


    def __init__(self, github_token: str) -> None:
        self.github = Github(auth=Auth.Token(github_token))
        self.github_token = github_token


    def can_authenticate(self) -> bool:
        """
        Calls the GitHub API to determine if the token is valid

        :return: Flag indicating whether authentication was successful or not
        """
        headers = {"Authorization": f"token {self.github_token}"}

        response = httpx.get(
            url='https://api.github.com/',
            headers=headers,
            follow_redirects=True,
            timeout=config.request_timeout_sec
        )

        if response.status_code == 401:
            return False
        else:
            return True


    def get_token_scopes(self) -> list:
        """
        Provides the scopes associated to the access token provided in the environment variable
        Only classic personal access tokens will result in scopes returned from the GitHub API

        :return: List of token scopes
        """
        headers = {"Authorization": f"token {self.github_token}"}

        response = httpx.get(
            url='https://api.github.com/',
            headers=headers,
            follow_redirects=True,
            timeout=config.request_timeout_sec
        )

        oauth_scopes = response.headers.get('x-oauth-scopes')

        if not oauth_scopes is None:
            if oauth_scopes == '':
                return None
            else:
                return oauth_scopes.split(', ')

        return None