import contextlib
import os

from rich.panel import Panel
from vdb.lib.gha import GitHubSource
from depscan.lib import github

from depscan.lib.logger import console, LOG

LOGO = """
██████╗ ███████╗██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗
██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║
██║  ██║█████╗  ██████╔╝███████╗██║     ███████║██╔██╗ ██║
██║  ██║██╔══╝  ██╔═══╝ ╚════██║██║     ██╔══██║██║╚██╗██║
██████╔╝███████╗██║     ███████║╚██████╗██║  ██║██║ ╚████║
╚═════╝ ╚══════╝╚═╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
"""

def sponsor_message(args):
    """
    Prints out the sponsor message for dep-scan.
    Please consider supporting dep-scan.
    """
    if (
        os.getenv("CI")
        and not os.getenv("GITHUB_REPOSITORY", "").lower().startswith("owasp")
        and not args.no_banner
        and os.getenv("INPUT_THANK_YOU", "")
                != "I have sponsored OWASP-dep-scan."
    ):
        console.print(
            Panel(
                "OWASP foundation relies on donations to fund our projects.\nPlease donate at: https://owasp.org/donate/?reponame=www-project-dep-scan&title=OWASP+depscan",
                title="Donate to the OWASP Foundation",
                expand=False,
            )
        )

def print_banner(args):
    """
    If no banner argument is used don't printing the banner
    """

    if not args.no_banner:
        with contextlib.suppress(UnicodeEncodeError):
            print(LOGO)


def caching_message(args, bom_file):
    LOG.debug("Scanning using the bom file %s", bom_file)
    if not args.bom:
        LOG.info(
            "To improve performance, cache the bom file and invoke "
            "depscan with --bom %s instead of -i",
            bom_file,
        )

def github_client_message(sources_list):
    github_token = os.environ.get("GITHUB_TOKEN")
    if github_token and os.getenv("CI"):
        try:
            github_client = github.GitHub(github_token)

            if not github_client.can_authenticate():
                LOG.info(
                    "The GitHub personal access token supplied appears to "
                    "be invalid or expired. Please see: "
                    "https://github.com/owasp-dep-scan/dep-scan#github"
                    "-security-advisory"
                )
            else:
                sources_list.insert(0, GitHubSource())
                scopes = github_client.get_token_scopes()
                if scopes:
                    LOG.warning(
                        "The GitHub personal access token was granted "
                        "more permissions than is necessary for depscan "
                        "to operate, including the scopes of: %s. It is "
                        "recommended to use a dedicated token with only "
                        "the minimum scope necesary for depscan to "
                        "operate. Please see: "
                        "https://github.com/owasp-dep-scan/dep-scan"
                        "#github-security-advisory",
                        ", ".join(scopes),
                    )
        except Exception:
            pass
