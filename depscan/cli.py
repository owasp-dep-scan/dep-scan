#!/usr/bin/env python3 -W ignore::DeprecationWarning
# -*- coding: utf-8 -*-

import os
import sys

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

    The work itself lives in the stage functions in
    :mod:`depscan.lib.pipeline`; this function builds the scan context, calls
    the stages in order and turns a stage's decision to stop into the exit
    code the scan has always used. Server mode starts the server and returns
    before any scan stage runs.
    """
    ctx = pipeline.build_context(args)
    pipeline.configure_output(ctx)
    if args.server_mode:
        return pipeline.start_server_mode(ctx)
    try:
        # We have everything needed to start the composition analysis. There are many approaches to implementing an SCA tool.
        # Our style of analysis is comparable to that of an intelligent Hubble telescope or a rover—examining the same subject through multiple optics, colors, and depths to gain a deeper understanding.
        # We begin by iterating over the project types provided or assumed.
        pipeline.stage_setup(ctx)
        pipeline.stage_database(ctx)
        pipeline.finalize_setup(ctx)
        for project_type in ctx.project_types:
            scan = pipeline.TypeScan(project_type=project_type)
            if not pipeline.stage_inventory(ctx, scan):
                continue
            ctx.scans.append(scan)
            pipeline.stage_analysis_licenses(ctx, scan)
            pipeline.stage_analysis_risk(ctx, scan)
            pipeline.announce_scan_targets(ctx, scan)
            pipeline.stage_enrichment(ctx, scan)
            pipeline.stage_matching(ctx, scan)
            pipeline.stage_analysis_vdr(ctx, scan)
            pipeline.stage_render_explain(ctx, scan)
        pipeline.stage_render_reports(ctx)
    except pipeline.ScanStageError:
        # The stage already logged why the scan stops; this keeps the exit
        # code the scan has always used for these conditions.
        sys.exit(1)


def main():
    cli_args = build_args()
    run_depscan(cli_args)


if __name__ == "__main__":
    main()
