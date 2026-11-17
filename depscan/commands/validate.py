"""The ``depscan validate`` verb: a forward to the validate command.

The implementation lives in :mod:`depscan.validate_cli`; this module
registers its arguments on the verb's subparser and runs the parsed command.
"""

from depscan import validate_cli


def register(subparsers) -> None:
    parser = subparsers.add_parser(
        "validate",
        help="Validate CSAF VEX or CycloneDX VDR/VEX documents against their schema.",
    )
    validate_cli.register_arguments(parser)


def run(args) -> int:
    return validate_cli.run_validation(args)
