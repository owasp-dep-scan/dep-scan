"""The ``depscan schema`` verb: print the published finding schemas."""

import argparse
import json
import sys

from analysis_lib.findings.schemas import load_schema, schema_names


def register(subparsers) -> None:
    parser = subparsers.add_parser(
        "schema",
        help="Print the published finding schemas.",
    )
    parser.add_argument(
        "name",
        nargs="?",
        help="Print this schema document; without it, list the schema names.",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="text for people, json for scripts (default: text)",
    )


def run(args: argparse.Namespace) -> int:
    if not args.name:
        names = schema_names()
        if args.format == "json":
            print(json.dumps({"schemas": names}, indent=2))
        else:
            for name in names:
                print(name)
        return 0
    try:
        document = load_schema(args.name)
    except ValueError as exc:
        print(f"depscan schema: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(document, indent=2))
    return 0
