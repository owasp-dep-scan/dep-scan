import argparse
import shutil
import os

def build_blint_args(argument_string: str) -> argparse.Namespace:
    """
    Constructs command line arguments for the blint tool
    """
    parser = argparse.ArgumentParser(
        prog="blint",
        description="Binary linter and SBOM generator.",
    )
    parser.add_argument(
        "-i",
        "--src",
        dest="src_dir_image",
        action="extend",
        nargs="+",
        help="Source directories, container images or binary files. Defaults "
             "to current directory.",
    )
    parser.add_argument(
        "-o",
        "--reports",
        dest="reports_dir",
        default=os.path.join(os.getcwd(), "reports"),
        help="Reports directory. Defaults to reports.",
    )
    parser.add_argument(
        "--no-error",
        action="store_true",
        default=False,
        dest="noerror",
        help="Continue on error to prevent build from breaking.",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        default=False,
        dest="no_banner",
        help="Do not display banner.",
    )
    parser.add_argument(
        "--no-reviews",
        action="store_true",
        default=False,
        dest="no_reviews",
        help="Do not perform method reviews.",
    )
    parser.add_argument(
        "--suggest-fuzzable",
        action="store_true",
        default=False,
        dest="suggest_fuzzable",
        help="Suggest functions and symbols for fuzzing based on a dictionary.",
    )
    # sbom commmand
    subparsers = parser.add_subparsers(
        title="sub-commands",
        description="Additional sub-commands",
        dest="subcommand_name",
    )
    sbom_parser = subparsers.add_parser(
        "sbom", help="Command to generate SBOM for supported binaries."
    )
    sbom_parser.add_argument(
        "-i",
        "--src",
        dest="src_dir_image",
        action="extend",
        nargs="+",
        help="Source directories, container images or binary files. Defaults "
             "to current directory.",
    )
    sbom_parser.add_argument(
        "-o",
        "--output-file",
        dest="sbom_output",
        help="SBOM output file. Defaults to bom-post-build.cdx.json in current directory.",
    )
    sbom_parser.add_argument(
        "--deep",
        action="store_true",
        default=False,
        dest="deep_mode",
        help="Enable deep mode to collect more used symbols and modules "
             "aggressively. Slow operation.",
    )
    sbom_parser.add_argument(
        "--stdout",
        action="store_true",
        default=False,
        dest="stdout_mode",
        help="Print the SBOM to stdout instead of a file.",
    )
    sbom_parser.add_argument(
        "--exports-prefix",
        default=[],
        action="extend",
        nargs="+",
        dest="exports_prefix",
        help="prefixes for the exports to be included in the SBOM.",
    )
    sbom_parser.add_argument(
        "--bom-src",
        dest="src_dir_boms",
        action="extend",
        nargs="+",
        help="Directories containing pre-build and build BOMs. Use to improve the precision.",
    )

    return parser.parse_args(argument_string.split())

def rename_cdxgen_file(creation_status, bom_file):
    if creation_status:
        new_bom_file = bom_file + ".cdx"
        shutil.move(bom_file, new_bom_file)
        return new_bom_file
    return None