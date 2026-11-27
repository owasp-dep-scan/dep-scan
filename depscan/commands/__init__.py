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
    EXIT_FAILURE,
    EXIT_USAGE,
    argv_requests_json,
    argv_verb,
    error_document,
    plain_text,
    print_error_document,
    print_json_document,
)

from depscan.commands import (
    config as config_verb,
    doctor as doctor_verb,
    mcp as mcp_verb,
    report as report_verb,
    scan as scan_verb,
    schema as schema_verb,
    serve as serve_verb,
    triage as triage_verb,
    validate as validate_verb,
    vdb as vdb_verb,
    version as version_verb,
)
from depscan.commands import help as help_verb

#: The verb names, in the order the registry registers and lists them.
VERBS = (
    "scan",
    "report",
    "triage",
    "vdb",
    "doctor",
    "schema",
    "config",
    "serve",
    "mcp",
    "validate",
    "version",
    "help",
)

_VERB_MODULES = {
    "scan": scan_verb,
    "report": report_verb,
    "triage": triage_verb,
    "vdb": vdb_verb,
    "doctor": doctor_verb,
    "schema": schema_verb,
    "config": config_verb,
    "serve": serve_verb,
    "mcp": mcp_verb,
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

    def print_help(self, file=None):
        """Print the help, as the help verb's document when json was asked for.

        ``-h`` and ``--help`` print the help on stdout and exit 0; with
        ``--format json`` anywhere on the command line stdout still carries
        one JSON document, the same ``{"help": ...}`` that ``depscan help``
        prints.
        """
        if file is None and argv_requests_json(sys.argv[1:]):
            print_json_document({"help": plain_text(self.format_help())})
            return
        super().print_help(file)


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
    if getattr(args, "format", None) != "json":
        return module.run(args)
    # In json format stdout carries one document whatever happens, so an
    # error no verb expected still ends as the error document.
    try:
        return module.run(args)
    except Exception as exc:  # noqa: BLE001 - the failure becomes the error document
        message = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
        print_error_document(EXIT_FAILURE, verb, message)
        return EXIT_FAILURE
