#!/usr/bin/env python3 -W ignore::DeprecationWarning
# -*- coding: utf-8 -*-

import os
import sys

from depscan import api
from depscan.cli_options import build_parser
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
        return pipeline.start_server_mode(ctx)
    try:
        api.scan(args)
    except api.ScanError:
        # The stage already logged why the scan stops; this keeps the exit
        # code the scan has always used for these conditions.
        sys.exit(1)


def main():
    cli_args = build_args()
    run_depscan(cli_args)


if __name__ == "__main__":
    main()
