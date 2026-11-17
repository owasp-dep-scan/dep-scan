"""The ``depscan help`` verb: the top-level help or one verb's help."""

import argparse
import json


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
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="text for people, json for scripts (default: text)",
    )


def _help_text(parser: argparse.ArgumentParser, topic: str) -> str:
    """The help text of ``topic``'s subparser, or the top-level help."""
    if topic:
        for action in parser._actions:
            if isinstance(action, argparse._SubParsersAction) and topic in action.choices:
                return action.choices[topic].format_help()
    return parser.format_help()


def run(args: argparse.Namespace) -> int:
    from depscan.commands import build_parser

    topic = getattr(args, "topic", "") or ""
    text = _help_text(build_parser(), topic)
    if args.format == "json":
        print(json.dumps({"help": text}))
        return 0
    print(text, end="")
    return 0
