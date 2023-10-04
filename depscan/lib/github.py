from github import BadCredentialsException, Github, Auth, GithubException
from dataclasses import dataclass


class GitHub:
    # The GitHub instance object from the PyGithub library
    github = None


    def __init__(self, github_token: str) -> None:
        self.github = Github(auth=Auth.Token(github_token))


    def authenticate(self) -> bool:
        """
        Authenticates to the GitHub API

        :return: Flag indicating whether authentication was successful or not
        """
        try:
            # Call the GitHub API to authenticate
            self.github.get_user().name
        except (BadCredentialsException, GithubException):
            return False
        return True


    def get_token_scopes(self) -> list:
        """
        Provides the scopes associated to the access token provided in the environment variable

        :return: List of token scopes
        """
        if self.github.oauth_scopes is None:
            self.authenticate()

        # Case when a classic token has no scopes assigned
        if not self.github.oauth_scopes is None and len(self.github.oauth_scopes) == 1 and self.github.oauth_scopes[0] == '':
            return None

        return self.github.oauth_scopes