"""The ``depscan report`` verb: a forward to the report command.

The implementation lives in :mod:`depscan.lib.report`; this module registers
its arguments on the verb's subparser and runs the parsed command.
"""

from depscan.lib import report as report_lib


def register(subparsers) -> None:
    parser = subparsers.add_parser(
        "report",
        help="Render the console tables and explanations of a saved scan.",
    )
    report_lib.register_arguments(parser)


def run(args) -> int:
    return report_lib.run_report_args(args)
