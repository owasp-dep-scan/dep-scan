#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""``depscan validate``: validate VEX/VDR documents against their schema.

Validates one or more documents produced by dep-scan *or any other tool*:

* **CSAF VEX** -- against the bundled CSAF JSON Schema (with an RFC 3339
  ``date-time`` check) plus the CSAF §6.1 mandatory semantic tests.
* **CycloneDX VDR/VEX** -- against the bundled CycloneDX schema matching the
  document's ``specVersion``.

The document format is auto-detected per file; ``--input-format`` forces one.
All validation is offline. Exit status is 1 when any document is invalid.

The module serves two front ends: the ``depscan validate`` verb, whose
subparser carries :func:`register_arguments`, and :func:`main`, which parses
a raw argv. ``--format`` selects the output, like on every verb: ``json``
prints one ``{"results": [...]}`` document on stdout, one entry per file,
whether the documents are valid or not; ``text`` (the default) prints the
text lines. An invalid document is a result, not an error of the verb.
"""

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional

from analysis_lib.validation import (
    FORMAT_CSAF,
    FORMAT_CYCLONEDX,
    validate_document,
)

from depscan import get_version
from depscan.commands.output import (
    EXIT_FAILURE,
    json_path,
    print_error_document,
    print_json_document,
)
from depscan.lib.logger import LOG

#: The ``--format`` choices: the output formats every verb selects between.
OUTPUT_FORMAT_CHOICES = ("text", "json")

#: The ``--input-format`` choices: the document formats, auto-detected by
#: default.
INPUT_FORMAT_CHOICES = ("auto", FORMAT_CSAF, FORMAT_CYCLONEDX)


def register_arguments(parser: argparse.ArgumentParser) -> None:
    """Add the validate options to ``parser``."""
    parser.add_argument("files", nargs="+", help="one or more JSON documents to validate")
    parser.add_argument(
        "--format",
        choices=OUTPUT_FORMAT_CHOICES,
        default="text",
        help="text prints one line per file, json prints the results as one "
        "JSON document (default: text)",
    )
    parser.add_argument(
        "--input-format",
        choices=INPUT_FORMAT_CHOICES,
        default="auto",
        help="document format (default: auto-detect per file)",
    )
    parser.add_argument(
        "--csaf-version",
        choices=["2.0", "2.1"],
        default=None,
        help="force a CSAF schema version (default: read from the document)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="only print a summary line per file, not each error",
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="depscan validate",
        description=(
            "Validate CSAF VEX or CycloneDX VDR/VEX documents (auto-detected) "
            "against their schema and, for CSAF, the CSAF §6.1 semantic tests."
        ),
    )
    register_arguments(parser)
    parser.add_argument("--version", action="version", version=f"%(prog)s {get_version()}")
    return parser


def _validate_file(
    path: str, doc_format: str, csaf_version, quiet: bool, json_output: bool
) -> Dict[str, Any]:
    """Validate a single file; return its result entry.

    The entry's ``valid`` flag says whether the document passed; text lines
    are printed only when the output is text. ``file`` carries the absolute,
    slash-separated form of the path, as every path in a json document does
    outside the manifest and the findings.
    """
    if os.path.isdir(path):
        message = "is a directory, not a JSON file"
        if not json_output:
            print(f"[INVALID] {path}: {message}")
        return {"file": json_path(path), "format": None, "valid": False, "errors": [message]}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError, RecursionError) as exc:
        # RecursionError: json gives up on a document nested too deeply.
        message = f"could not read JSON ({exc})"
        if not json_output:
            print(f"[INVALID] {path}: {message}")
        return {"file": json_path(path), "format": None, "valid": False, "errors": [message]}

    detected, errors = validate_document(doc, doc_format, csaf_version)
    label = detected or "unknown"
    if errors:
        if not json_output:
            print(f"[INVALID] {path} ({label}): {len(errors)} error(s)")
            if not quiet:
                for err in errors:
                    print(f"    {err}")
        return {"file": json_path(path), "format": label, "valid": False, "errors": list(errors)}
    if not json_output:
        print(f"[VALID]   {path} ({label})")
    return {"file": json_path(path), "format": label, "valid": True, "errors": []}


def run_validation(args) -> int:
    """Validate every file named by the parsed arguments; the exit code.

    An invalid document, a document that cannot be read and a file that is
    no JSON at all are results, not errors: the run reports them in the
    document (or the text lines) and exits 1. The error document is
    reserved for a failure that stops the verb as a whole.
    """
    json_output = args.format == "json"
    try:
        entries = []
        for path in args.files:
            entry = _validate_file(
                path, args.input_format, args.csaf_version, args.quiet, json_output
            )
            entries.append(entry)
    except Exception as exc:
        return _unexpected_failure(json_output, exc)
    if json_output:
        print_json_document({"results": entries})
    return 0 if all(entry["valid"] for entry in entries) else 1


def _unexpected_failure(json_output: bool, exc: Exception) -> int:
    """Report a validate run that stopped with an unexpected error.

    The message goes on stderr as text with its traceback; in json format
    the error document follows on stdout, so the stream never carries
    nothing. The exit code is 1, the "could not run" code of the exit table.
    """
    message = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
    LOG.exception("The validation stopped with an unexpected error: %s", message)
    if json_output:
        print_error_document(EXIT_FAILURE, "validate", message)
    return EXIT_FAILURE


def main(argv: Optional[List[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    return run_validation(args)


if __name__ == "__main__":
    sys.exit(main())
