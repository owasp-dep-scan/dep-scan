"""The verb registry: the top-level parser and the dispatch table.

Every verb is one module in this package exposing ``register(subparsers)``,
which adds its subparser, and ``run(args) -> int``, which executes it and
returns the process exit code. :func:`build_parser` wires the verbs into the
top-level parser in :data:`VERBS` order, so ``depscan --help`` lists them in
that order and an unknown verb is argparse's own invalid-choice error.

The parsers are :class:`ErrorDocumentParser`, so a usage error argparse
finds before a verb runs writes the error document on stdout when the
command line asked for json anywhere, and keeps argparse's usage and
message on stderr, exiting 2, in every case.
"""

import argparse
import sys

from depscan.commands.output import (
    EXIT_USAGE,
    argv_requests_json,
    argv_verb,
    error_document,
    print_json_document,
)

from depscan.commands import (
    config as config_verb,
    doctor as doctor_verb,
    report as report_verb,
    scan as scan_verb,
    schema as schema_verb,
    serve as serve_verb,
    validate as validate_verb,
    vdb as vdb_verb,
    version as version_verb,
)
from depscan.commands import help as help_verb

#: The verb names, in the order the registry registers and lists them.
VERBS = (
    "scan",
    "report",
    "vdb",
    "doctor",
    "schema",
    "config",
    "serve",
    "validate",
    "version",
    "help",
)

_VERB_MODULES = {
    "scan": scan_verb,
    "report": report_verb,
    "vdb": vdb_verb,
    "doctor": doctor_verb,
    "schema": schema_verb,
    "config": config_verb,
    "serve": serve_verb,
    "validate": validate_verb,
    "version": version_verb,
    "help": help_verb,
}


class ErrorDocumentParser(argparse.ArgumentParser):
    """An argument parser whose usage errors carry the error document.

    When the command line asked for json anywhere (``--format json`` as two
    tokens or ``--format=json`` as one), :meth:`error` writes the error
    document on stdout before argparse prints its usage and message on
    stderr and exits 2. A command line without ``--format``, as every
    dep-scan 6 invocation is, stays text only.
    """

    def error(self, message):
        argv = sys.argv[1:]
        if argv_requests_json(argv):
            print_json_document(error_document(EXIT_USAGE, argv_verb(argv), message))
        super().error(message)


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level ``depscan`` parser with every verb registered."""
    parser = ErrorDocumentParser(
        prog="depscan",
        description="Fully open-source security and license audit for "
        "application dependencies and container images based on "
        "known vulnerabilities and advisories.",
        epilog="Visit https://github.com/owasp-dep-scan/dep-scan to learn more",
    )
    subparsers = parser.add_subparsers(
        dest="verb", required=True, parser_class=ErrorDocumentParser
    )
    for name in VERBS:
        _VERB_MODULES[name].register(subparsers)
    return parser


def run(args: argparse.Namespace) -> int:
    """Dispatch a parsed command line to its verb; the process exit code."""
    verb = getattr(args, "verb", "")
    module = _VERB_MODULES.get(verb)
    if module is None:
        return 2
    return module.run(args)
