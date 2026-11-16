#!/usr/bin/env python3
"""Write the generation.json provenance record of one generated project.

Read by the publish job to annotate the OCI artifact and by validate.py lock
to write testdata.lock.json. Called by generate.sh once every project type
ran successfully, so the record exists only for complete generations.

Usage: write_provenance.py OUT_DIR --name NAME --git URL --commit SHA
       --types-json '["rust","js"]' --cdxgen-args-json '["--profile","research"]'
       --cdxgen-version 13.8.0 --npm-prefix DIR
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone


def npm_package_version(prefix, package):
    try:
        with open(os.path.join(prefix, "node_modules", package, "package.json")) as fp:
            return json.load(fp).get("version", "unknown")
    except OSError:
        return "not-installed"


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("out_dir")
    parser.add_argument("--name", required=True)
    parser.add_argument("--git", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--types-json", required=True)
    parser.add_argument("--cdxgen-args-json", required=True)
    parser.add_argument("--cdxgen-version", required=True)
    parser.add_argument("--npm-prefix", required=True)
    parser.add_argument(
        "--generated",
        help="Generation timestamp (UTC, ISO 8601). Defaults to now.",
    )
    args = parser.parse_args()

    entry = {
        "name": args.name,
        "git": args.git,
        "commit": args.commit,
        "types": json.loads(args.types_json),
        "cdxgenArgs": json.loads(args.cdxgen_args_json),
        "cdxgenVersion": args.cdxgen_version,
        "atomVersion": npm_package_version(args.npm_prefix, "@appthreat/atom"),
        "cdxgenPluginsVersion": npm_package_version(
            args.npm_prefix, "@cdxgen/cdxgen-plugins-bin"
        ),
        "generated": args.generated
        or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    entry["tag"] = "{}-cdxgen{}-{}".format(
        entry["name"], entry["cdxgenVersion"], entry["generated"][:10].replace("-", "")
    )
    out = os.path.join(args.out_dir, "generation.json")
    with open(out, "w", encoding="utf-8") as fp:
        json.dump(entry, fp, indent=2, sort_keys=True)
        fp.write("\n")
    print(f"Provenance written to {out} (tag {entry['tag']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
