#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""depscan-validate: validate VEX/VDR documents against their schema.

Validates one or more documents produced by dep-scan *or any other tool*:

* **CSAF VEX** -- against the bundled CSAF JSON Schema (with an RFC 3339
  ``date-time`` check) plus the CSAF §6.1 mandatory semantic tests.
* **CycloneDX VDR/VEX** -- against the bundled CycloneDX schema matching the
  document's ``specVersion``.

The format is auto-detected per file; use ``--format`` to force one. All
validation is offline. Exit status is non-zero when any document is invalid.
"""

import argparse
import json
import os
import sys
from typing import List, Optional

from analysis_lib.validation import (
    FORMAT_CSAF,
    FORMAT_CYCLONEDX,
    validate_document,
)

from depscan import get_version


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="depscan-validate",
        description=(
            "Validate CSAF VEX or CycloneDX VDR/VEX documents (auto-detected) "
            "against their schema and, for CSAF, the CSAF §6.1 semantic tests."
        ),
    )
    parser.add_argument("files", nargs="+", help="one or more JSON documents to validate")
    parser.add_argument(
        "--format",
        choices=["auto", FORMAT_CSAF, FORMAT_CYCLONEDX],
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
    parser.add_argument("--version", action="version", version=f"%(prog)s {get_version()}")
    return parser


def _validate_file(path: str, doc_format: str, csaf_version, quiet: bool) -> bool:
    """Validate a single file; return True when valid."""
    if os.path.isdir(path):
        print(f"[INVALID] {path}: is a directory, not a JSON file")
        return False
    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[INVALID] {path}: could not read JSON ({exc})")
        return False

    detected, errors = validate_document(doc, doc_format, csaf_version)
    label = detected or "unknown"
    if errors:
        print(f"[INVALID] {path} ({label}): {len(errors)} error(s)")
        if not quiet:
            for err in errors:
                print(f"    {err}")
        return False
    print(f"[VALID]   {path} ({label})")
    return True


def main(argv: Optional[List[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    all_valid = True
    for path in args.files:
        if not _validate_file(path, args.format, args.csaf_version, args.quiet):
            all_valid = False
    return 0 if all_valid else 1


if __name__ == "__main__":
    sys.exit(main())
