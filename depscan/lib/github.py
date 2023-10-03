from github import BadCredentialsException, Github, Auth
from dataclasses import dataclass



# Data class to represent a required GitHub personal access token scope for depscan
@dataclass
class RequiredTokenScope:
    # Required token scope
    scope: str
    # If the required scope can be inherited from a parent scope, it is represented here
    # Note that situation usually means that depscan will have the necessary permissions to function, but it will likely have more privilege than necessary
    # For example, if a token has write:packages scope, then it inherits read:packages scope by default: 
    #              > write:packages (Parent)
    #              >>>> read:packages (Child)
    scope_parent: str = None



class GitHub:
    # The GitHub personal access token required scopes for depscan
    DEPSCAN_REQUIRED_TOKEN_SCOPES = [
        RequiredTokenScope("read:packages", "write:packages")
    ]

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
        except(BadCredentialsException):
            return False
        
        return True


    def get_token_scopes(self) -> list[str]:
        """
        Provides the scopes associated to the access token provided in the environment variable

        :return: List of token scopes
        """
        if self.github.oauth_scopes is None:
            self.authenticate()

        return self.github.oauth_scopes


    def token_has_required_scopes(self) -> bool:
        """
        Determines if the token has the minimum required scopes for depscan to operate

        :return: Flag indicating whether the token has the required scopes
        """
        token_scopes = self.get_token_scopes()

        # Check that all required scopes are granted to the provided GitHub personal access token
        # If they are not present in the token scopes list, a ValueError will be thrown from index()
        for required_scope in self.DEPSCAN_REQUIRED_TOKEN_SCOPES:
            try:
                token_scopes.index(required_scope.scope)
            except(ValueError):
                if required_scope.scope_parent is None:
                    return False
                
                try:
                    # The required scope is not explicitly present on the token
                    # Check to see if the scope is implicitly present through inheritance from a parent scope
                    token_scopes.index(required_scope.scope_parent)
                except(ValueError):
                    return False

        return True
    

    def get_token_extra_scopes(self) -> list[str]:
        """
        Lists the token scopes greater than what is required for depscan to operate

        :return: List of the extra scopes
        """
        token_scopes = self.get_token_scopes()

        # Remove all required matching scopes from local copy of token scopes
        # If any token scopes remain, the token has too many permissions, likely from additional scopes beyond the required scope
        # This could also mean that the extra scope granted is a parent scope with greater privilege than is required for depscan
        # If they are not present in the token scopes list, a ValueError will be thrown from remove()
        for required_scope in self.DEPSCAN_REQUIRED_TOKEN_SCOPES:
            try:
                token_scopes.remove(required_scope.scope)
            except(ValueError):
                pass

        return token_scopes