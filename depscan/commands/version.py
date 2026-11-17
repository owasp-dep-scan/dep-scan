"""The ``depscan version`` verb."""

import argparse
import json

from depscan import get_version
from depscan.lib import doctor as doctor_lib


def register(subparsers) -> None:
    parser = subparsers.add_parser(
        "version",
        help="Print the dep-scan version, with tool versions as JSON.",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="text for people, json for scripts (default: text)",
    )


def run(args: argparse.Namespace) -> int:
    if args.format == "json":
        # Collecting the doctor report probes every tool, so it runs only
        # when the tool versions were asked for.
        report = doctor_lib.doctor()
        document = {
            "version": get_version(),
            "tools": {tool.name: tool.version for tool in report.tools},
        }
        print(json.dumps(document, indent=2))
        return 0
    print(f"depscan {get_version()}")
    return 0
