"""Run dosai over a .NET project and keep its raw reports next to the BOM.

atom writes no reachables slice for C#; dep-scan's .NET reachability comes
from dosai, which ``depscan scan`` runs after cdxgen. generate.sh calls this
script for every dotnet type, so the published data carries the raw dosai
reports under ``analysis/dosai/`` and a BOM directory scan reads them through
the dosai adapter, the way a source scan's persisted reports are read.

Usage: python native_reachability.py BOM_FILE SRC_DIR

It needs a Python with dep-scan installed (``uv run --no-sync python`` in a
dep-scan checkout) and a .NET runtime dosai can run on.
"""

import os
import sys


def main(argv):
    if len(argv) != 2:
        print("Usage: native_reachability.py BOM_FILE SRC_DIR", file=sys.stderr)
        return 2
    bom_file, src_dir = argv
    from depscan.lib.bom import run_dosai_reachability

    options = {"project_type": ["dotnet"], "reachability_analyzer": "SemanticReachability"}
    result = run_dosai_reachability(bom_file, src_dir, options)
    if result is None or result.status != "completed":
        reason = getattr(result, "reason", None) or "dosai was not assessed"
        print(f"dosai produced no reachability evidence for {src_dir}: {reason}", file=sys.stderr)
        return 1
    analysis_dir = os.path.join(os.path.dirname(bom_file), "analysis", "dosai")
    written = [
        name
        for name in ("dotnet-dataflows.json", "dotnet-methods.json")
        if os.path.isfile(os.path.join(analysis_dir, name))
    ]
    if not written:
        print(f"dosai completed but no raw report was left under {analysis_dir}", file=sys.stderr)
        return 1
    print(f"dosai raw reports written under {analysis_dir}: {', '.join(written)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
