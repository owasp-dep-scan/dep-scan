#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""``depscan validate``: validate VEX/VDR documents against their schema.

Validates one or more documents produced by dep-scan *or any other tool*:

* **CSAF VEX** -- against the bundled CSAF JSON Schema (with an RFC 3339
  ``date-time`` check) plus the CSAF §6.1 mandatory semantic tests.
* **CycloneDX VDR/VEX** -- against the bundled CycloneDX schema matching the
  document's ``specVersion``.

The format is auto-detected per file; use ``--format`` to force one. All
validation is offline. Exit status is non-zero when any document is invalid.

The module serves two front ends: the ``depscan validate`` verb, whose
subparser carries :func:`register_arguments`, and :func:`main`, which parses
a raw argv. ``--format json`` prints one JSON document with an entry per
file; ``--format auto`` (the default) leaves the document format
auto-detected and prints the text lines.
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

#: The ``--format`` choices: the document formats plus the output format.
FORMAT_CHOICES = ["auto", FORMAT_CSAF, FORMAT_CYCLONEDX, "json"]


def register_arguments(parser: argparse.ArgumentParser) -> None:
    """Add the validate options to ``parser``."""
    parser.add_argument("files", nargs="+", help="one or more JSON documents to validate")
    parser.add_argument(
        "--format",
        choices=FORMAT_CHOICES,
        default="auto",
        help="document format (default: auto-detect per file); 'json' prints "
        "the results as one JSON document instead of text lines",
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
    are printed only when the output is text.
    """
    if os.path.isdir(path):
        message = "is a directory, not a JSON file"
        if not json_output:
            print(f"[INVALID] {path}: {message}")
        return {"file": path, "format": None, "valid": False, "errors": [message]}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        message = f"could not read JSON ({exc})"
        if not json_output:
            print(f"[INVALID] {path}: {message}")
        return {"file": path, "format": None, "valid": False, "errors": [message]}

    detected, errors = validate_document(doc, doc_format, csaf_version)
    label = detected or "unknown"
    if errors:
        if not json_output:
            print(f"[INVALID] {path} ({label}): {len(errors)} error(s)")
            if not quiet:
                for err in errors:
                    print(f"    {err}")
        return {"file": path, "format": label, "valid": False, "errors": list(errors)}
    if not json_output:
        print(f"[VALID]   {path} ({label})")
    return {"file": path, "format": label, "valid": True, "errors": []}


def run_validation(args) -> int:
    """Validate every file named by the parsed arguments; the exit code."""
    json_output = args.format == "json"
    # 'json' is an output format: the document format stays auto-detected.
    doc_format = "auto" if args.format in ("auto", "json") else args.format
    all_valid = True
    entries = []
    for path in args.files:
        entry = _validate_file(path, doc_format, args.csaf_version, args.quiet, json_output)
        entries.append(entry)
        if not entry["valid"]:
            all_valid = False
    if json_output:
        print(json.dumps(entries, indent=2))
    return 0 if all_valid else 1


def main(argv: Optional[List[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    return run_validation(args)


if __name__ == "__main__":
    sys.exit(main())
