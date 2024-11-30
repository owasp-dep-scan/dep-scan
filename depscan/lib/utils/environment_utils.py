import os
import sys

from rich.panel import Panel

from depscan.lib.csaf import write_toml
from depscan.lib.logger import LOG, DEBUG, console


def setup_debug(args):
    """
    If --debug is passed in arguments then start debug mode
    """
    if args.enable_debug:
        os.environ["AT_DEBUG_MODE"] = "debug"
        LOG.setLevel(DEBUG)

def get_src_dir(args):
    """
    Sets the appropriate `src_dir` for the project.
    If using `.` as the dir, then changes it to `os.getcwd()`.
    TODO: check it out maybe the else statement is misplaced
    """
    src_dir = args.src_dir_image
    if not src_dir or src_dir == ".":
        if src_dir == "." or args.search_purl:
            src_dir = os.getcwd()
        # Try to infer from the bom file
        elif args.bom and os.path.exists(args.bom):
            src_dir = os.path.dirname(os.path.realpath(args.bom))
        else:
            src_dir = os.getcwd()
    return src_dir

def csaf_toml_check(args, src_dir):
    """
    If csaf argument is provided but csaf template environment variable is not set then exits after display warning.
    """
    if args.csaf:
        toml_file_path = os.getenv(
            "DEPSCAN_CSAF_TEMPLATE", os.path.join(src_dir, "csaf.toml")
        )
        if not os.path.exists(toml_file_path):
            LOG.info("CSAF toml not found, creating template in %s", src_dir)
            write_toml(toml_file_path)
            LOG.info(
                "Please fill out the toml with your details and rerun depscan."
            )
            LOG.info(
                "Check out our CSAF documentation for an explanation of "
                "this feature. https://github.com/owasp-dep-scan/dep-scan"
                "/blob/master/contrib/CSAF_README.md"
            )
            LOG.info(
                "If you're just checking out how our generator works, "
                "feel free to skip filling out the toml and just rerun "
                "depscan."
            )
            sys.exit(0)

def create_dirs(reports_dir):
    """
    Create dirs required for storing report files
    """
    if reports_dir and not os.path.exists(reports_dir):
        os.makedirs(reports_dir, exist_ok=True)

def setup_license(args, project_types_list):
    """
    Adds FETCH_LICENSE environment variable and print a banner
    """
    if "license" in project_types_list or "license" in args.profile:
        os.environ["FETCH_LICENSE"] = "true"
        project_types_list.remove("license")
        console.print(
            Panel(
                "License audit is enabled for this scan. This would increase "
                "the time by up to 10 minutes.",
                title="License Audit",
                expand=False,
            )
        )
