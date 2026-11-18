"""The ``depscan schema`` verb: print the published finding schemas.

Without a name the verb lists every published schema, as bare names in text
format and as one object with each schema's name, ``$id`` and title in json
format. With a name it prints that schema document. An unknown name is a
usage error: exit 2 with the message on stderr, and, in json format, the
error document on stdout like any verb.
"""

import argparse
import json
import sys

from analysis_lib.findings.schemas import load_schema, schema_names, schema_summaries
from depscan.commands.output import EXIT_USAGE, print_error_document


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
        if args.format == "json":
            print(json.dumps({"schemas": schema_summaries()}, indent=2))
        else:
            for name in schema_names():
                print(name)
        return 0
    try:
        document = load_schema(args.name)
    except ValueError as exc:
        message = f"depscan schema: {exc}"
        if args.format == "json":
            print_error_document(EXIT_USAGE, "schema", message)
        else:
            print(message, file=sys.stderr)
        return EXIT_USAGE
    print(json.dumps(document, indent=2))
    return 0
