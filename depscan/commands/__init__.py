"""The verb registry: the top-level parser and the dispatch table.

Every verb is one module in this package exposing ``register(subparsers)``,
which adds its subparser, and ``run(args) -> int``, which executes it and
returns the process exit code. :func:`build_parser` wires the verbs into the
top-level parser in :data:`VERBS` order, so ``depscan --help`` lists them in
that order and an unknown verb is argparse's own invalid-choice error.
"""

import argparse

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


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level ``depscan`` parser with every verb registered."""
    parser = argparse.ArgumentParser(
        prog="depscan",
        description="Fully open-source security and license audit for "
        "application dependencies and container images based on "
        "known vulnerabilities and advisories.",
        epilog="Visit https://github.com/owasp-dep-scan/dep-scan to learn more",
    )
    subparsers = parser.add_subparsers(dest="verb", required=True)
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
