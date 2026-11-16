#!/usr/bin/env python3 -W ignore::DeprecationWarning
# -*- coding: utf-8 -*-

import os
import sys

from depscan import api
from depscan.cli_options import build_parser
from depscan.lib import doctor as doctor_lib
from depscan.lib import pipeline

if sys.platform == "win32" and os.environ.get("PYTHONIOENCODING") is None:
    sys.stdin.reconfigure(encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")


def build_args():
    """
    Constructs command line arguments for the depscan tool
    """
    parser = build_parser()
    return parser.parse_args()


def run_depscan(args):
    """
    Detects the project type, performs various scans and audits,
    and generates reports based on the results.

    The scan itself runs through :func:`depscan.api.scan`; this function
    starts server mode (which is not a scan) and turns a scan that stopped
    early into the exit code the scan has always used.
    """
    if args.server_mode:
        ctx = pipeline.build_context(args)
        pipeline.configure_output(ctx)
        try:
            return pipeline.start_server_mode(ctx)
        except pipeline.ScanStageError:
            # The database stage already logged why the server cannot start.
            sys.exit(1)
    try:
        api.scan(args)
    except api.ScanError:
        # The stage already logged why the scan stops; this keeps the exit
        # code the scan has always used for these conditions.
        sys.exit(1)


def main():
    # The full subcommand layout lands later; for now ``doctor`` is the one
    # verb handled before the v6-style parser, which sees every other
    # invocation unchanged.
    if len(sys.argv) > 1 and sys.argv[1] == "doctor":
        sys.exit(doctor_lib.run_doctor_command(sys.argv[2:]))
    cli_args = build_args()
    run_depscan(cli_args)


if __name__ == "__main__":
    main()
