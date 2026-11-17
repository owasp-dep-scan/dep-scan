"""The ``depscan vdb`` verb: a forward to the vdb command.

The implementation lives in :mod:`depscan.vdb_cli`; this module registers its
arguments on the verb's subparser and dispatches the parsed command.
"""

from depscan import vdb_cli


def register(subparsers) -> None:
    parser = subparsers.add_parser(
        "vdb",
        help="Download and inspect the vdb vulnerability database.",
    )
    vdb_cli.register_arguments(parser)


def run(args) -> int:
    return vdb_cli.dispatch(args)
