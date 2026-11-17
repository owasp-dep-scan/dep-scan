"""The ``depscan help`` verb: the top-level help or one verb's help."""

import argparse


def register(subparsers) -> None:
    # VERBS is imported at call time because the registry imports this module
    # while it is still defining itself.
    from depscan.commands import VERBS

    parser = subparsers.add_parser(
        "help",
        help="Show the top-level help, or one verb's help.",
    )
    parser.add_argument(
        "topic",
        nargs="?",
        choices=VERBS,
        metavar="verb",
        help="the verb to describe (default: the top-level help)",
    )


def run(args: argparse.Namespace) -> int:
    from depscan.commands import build_parser

    parser = build_parser()
    if getattr(args, "topic", None):
        try:
            parser.parse_args([args.topic, "--help"])
        except SystemExit as exc:
            return int(exc.code or 0)
    parser.print_help()
    return 0
