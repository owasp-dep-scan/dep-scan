#!/usr/bin/env python3 -W ignore::DeprecationWarning
# -*- coding: utf-8 -*-
"""The ``depscan`` entry point: verb dispatch with a v6 rejection path.

The v7 command line is verb first (``depscan scan``, ``depscan serve``,
``depscan vdb`` and so on); the registry in :mod:`depscan.commands` builds
the parser and runs the chosen verb. Two command lines are handled before
the registry sees them:

* ``depscan -h``/``--help`` prints the v7 help and exits 0.
* Any other command line that starts with an option is a v6 invocation,
  which v7 no longer runs. It is translated to its v7 equivalent, the
  translation and a link to the migration guide are printed on stderr, and
  the process exits 2.
"""

import os
import sys

from depscan.commands import build_parser, run
from depscan.commands import translate
from depscan.commands.output import (
    EXIT_USAGE,
    argv_requests_json,
    argv_verb,
    error_document,
    print_json_document,
)

if sys.platform == "win32" and os.environ.get("PYTHONIOENCODING") is None:
    sys.stdin.reconfigure(encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

MIGRATION_GUIDE = "https://depscan.readthedocs.io/upgrade/migrate-v6-to-v7/"

_V6_PREFIX = "depscan: this is a dep-scan 6 command line, which dep-scan 7 no longer runs."


def _print_v6_rejection(translated):
    """Explain a rejected v6 invocation on stderr."""
    print(_V6_PREFIX, file=sys.stderr)
    if translated:
        print(f"The equivalent v7 command is: {translated}", file=sys.stderr)
    else:
        print(
            "Re-run the command with a verb, for example: depscan scan --help",
            file=sys.stderr,
        )
    print(f"See the migration guide: {MIGRATION_GUIDE}", file=sys.stderr)


def main():
    argv = sys.argv[1:]
    if argv and argv[0] in ("-h", "--help"):
        # Argparse prints the v7 help and exits 0.
        build_parser().parse_args(argv)
        return
    if argv and argv[0].startswith("-"):
        translated = translate.translate(argv)
        if argv_requests_json(argv):
            details = {"migrationGuide": MIGRATION_GUIDE}
            if translated:
                details["translated"] = translated
            print_json_document(
                error_document(
                    EXIT_USAGE, argv_verb(argv), _V6_PREFIX[len("depscan: ") :], details
                )
            )
        _print_v6_rejection(translated)
        sys.exit(EXIT_USAGE)
    args = build_parser().parse_args(argv)
    sys.exit(run(args) or 0)


if __name__ == "__main__":
    main()
