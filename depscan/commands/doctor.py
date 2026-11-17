"""The ``depscan doctor`` verb: a forward to the doctor command.

The implementation, including the report and the ``--require`` gate, lives in
:func:`depscan.lib.doctor.run_doctor_command`; this module only registers the
same options on the verb's subparser so the top-level parser accepts them,
then hands the command line through unchanged.
"""

import argparse

from depscan.lib import doctor as doctor_lib


def register(subparsers) -> None:
    parser = subparsers.add_parser(
        "doctor",
        help="Report the tools, data and capabilities a scan can use here.",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="text for people, json for scripts (default: text)",
    )
    parser.add_argument(
        "--require",
        action="append",
        default=[],
        metavar="CAPABILITY",
        help=(
            "exit with code 4 unless these capabilities are available; "
            "comma-separated or repeated, for example "
            "--require vulnerabilities,reachability:go"
        ),
    )


def run(args: argparse.Namespace) -> int:
    argv = ["--format", args.format]
    for value in args.require:
        argv += ["--require", value]
    return doctor_lib.run_doctor_command(argv)
