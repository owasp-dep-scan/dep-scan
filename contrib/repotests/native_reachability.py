"""Write the dosai reachables slice of a .NET project next to its BOM.

atom writes no reachables slice for C#; dep-scan's .NET reachability comes
from dosai, which ``depscan scan`` runs after cdxgen. generate.sh calls this
script for every dotnet type, so the published data carries the same
``dotnet-reachables.slices.json`` a source scan would produce and the repo
tests can scan it as a BOM directory.

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
    if not run_dosai_reachability(bom_file, src_dir, options):
        print(f"dosai wrote no reachables slice for {src_dir}", file=sys.stderr)
        return 1
    slice_file = os.path.join(os.path.dirname(bom_file), "dotnet-reachables.slices.json")
    if not os.path.isfile(slice_file):
        print(f"dosai reported success but {slice_file} is missing", file=sys.stderr)
        return 1
    print(f"dosai reachables slice written to {slice_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
