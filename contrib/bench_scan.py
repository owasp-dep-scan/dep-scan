#!/usr/bin/env python3
"""
Minimal wall-clock benchmark for depscan's vulnerability search (roadmap T1).

Measures the serial per-package search path vs the batched vdb search path
(find_vulns_batched) on a large golden BOM fixture. Requires a populated vdb
database — run ``depscan`` once first or set VDB_DATABASE_DIR.

Usage::

    uv run python contrib/bench_scan.py [--fixture contrib/bench_fixtures/large-bom.json]
    uv run python contrib/bench_scan.py --generate   # (re)generate the fixture

This is a contribution script, not a test — it does not assert speedups, it
prints measured wall-clock numbers.
"""

import argparse
import json
import os
import sys
import time

# Ensure the workspace packages are importable when running the script directly.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "packages", "analysis-lib", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "packages", "analysis-lib"))

from analysis_lib.search import find_vulns  # noqa: E402
from analysis_lib.utils import get_pkg_list  # noqa: E402

DEFAULT_FIXTURE = os.path.join(
    os.path.dirname(__file__), "bench_fixtures", "large-bom.json"
)

# Well-known packages likely present in vdb. Repeated with distinct versions to
# reach ≥300 components.
SEED_PACKAGES = [
    ("npm", "lodash", "4.17.20"),
    ("npm", "express", "4.17.1"),
    ("npm", "axios", "0.21.1"),
    ("npm", "minimist", "1.2.5"),
    ("npm", "yargs-parser", "13.1.2"),
    ("npm", "handlebars", "4.7.6"),
    ("npm", "marked", "1.2.7"),
    ("npm", "validator", "13.5.2"),
    ("npm", "moment", "2.29.1"),
    ("npm", "qs", "6.9.6"),
    ("npm", "request", "2.88.2"),
    ("npm", "debug", "2.6.9"),
    ("npm", "ws", "7.4.3"),
    ("npm", "ini", "1.3.5"),
    ("npm", "chalk", "2.4.2"),
    ("npm", "glob", "7.1.6"),
    ("npm", "browserslist", "4.16.1"),
    ("npm", "postcss", "8.2.4"),
    ("npm", "normalize-url", "4.5.0"),
    ("npm", "ssri", "6.0.1"),
    ("npm", "tar", "4.4.13"),
    ("npm", "shell-quote", "1.7.2"),
    ("npm", "lodash-es", "4.17.15"),
    ("npm", "underscore", "1.12.0"),
    ("npm", "async", "2.6.3"),
    ("npm", "minimatch", "3.0.4"),
    ("npm", "growl", "1.10.5"),
    ("npm", "semver", "5.7.1"),
    ("npm", "mime", "1.6.0"),
    ("npm", "fresh", "0.5.2"),
    ("npm", "trim-newlines", "3.0.0"),
    ("npm", "mem", "4.3.0"),
    ("npm", "y18n", "4.0.0"),
    ("npm", "color-string", "1.5.3"),
    ("npm", "is-svg", "3.0.0"),
    ("npm", "dompurify", "2.2.6"),
    ("npm", "snarkdown", "1.2.2"),
    ("npm", "jest", "26.6.3"),
    ("npm", "webpack", "4.46.0"),
    ("npm", "elliptic", "6.5.3"),
    ("npm", "diff", "3.5.0"),
    ("npm", "node-forge", "0.10.0"),
    ("npm", "https-proxy-agent", "2.2.4"),
    ("npm", "bl", "2.2.1"),
    ("npm", "pngjs", "3.4.0"),
    ("npm", "jquery", "3.5.1"),
    ("npm", "path-parse", "1.0.6"),
    ("npm", "hosted-git-info", "2.8.9"),
    ("npm", "url-parse", "1.5.1"),
    ("npm", "ua-parser-js", "0.7.28"),
]


def generate_fixture(path, min_components=320):
    """Generate a CycloneDX BOM JSON by repeating seed packages with new versions."""
    components = []
    idx = 0
    while len(components) < min_components:
        for ecosystem, name, version in SEED_PACKAGES:
            suffix = idx // len(SEED_PACKAGES)
            v = f"{version}.{suffix}" if suffix else version
            if ecosystem == "npm" and "/" not in name:
                purl = f"pkg:npm/{name}@{v}"
            else:
                purl = f"pkg:{ecosystem}/{name}@{v}"
            components.append(
                {
                    "type": "library",
                    "name": name,
                    "version": v,
                    "purl": purl,
                    "bom-ref": purl,
                }
            )
            idx += 1
            if len(components) >= min_components:
                break
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "components": components,
    }
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(bom, f, indent=2)
    return bom


def load_pkg_list(fixture_path):
    pkg_list, _ = get_pkg_list(fixture_path)
    return pkg_list


def timed_find_vulns(pkg_list, batched, runs=1):
    """Run find_vulns N times and return (median_seconds, results_from_last_run)."""
    old_env = os.environ.get("DEPSCAN_BATCH_SEARCH", "")
    os.environ["DEPSCAN_BATCH_SEARCH"] = "true" if batched else "false"
    try:
        times = []
        results = None
        for _ in range(runs):
            t0 = time.perf_counter()
            results, _, _ = find_vulns(None, pkg_list)
            elapsed = time.perf_counter() - t0
            times.append(elapsed)
        times.sort()
        median = times[len(times) // 2]
        return median, results
    finally:
        os.environ["DEPSCAN_BATCH_SEARCH"] = old_env


def main():
    parser = argparse.ArgumentParser(description="Benchmark depscan search paths")
    parser.add_argument("--fixture", default=DEFAULT_FIXTURE, help="Path to golden BOM fixture")
    parser.add_argument("--generate", action="store_true", help="(Re)generate the fixture")
    parser.add_argument("--runs", type=int, default=1, help="Number of runs per path")
    args = parser.parse_args()

    if args.generate or not os.path.exists(args.fixture):
        print(f"Generating fixture at {args.fixture} ...")
        bom = generate_fixture(args.fixture)
        print(f"  {len(bom['components'])} components")

    pkg_list = load_pkg_list(args.fixture)
    print(f"Loaded {len(pkg_list)} packages from {args.fixture}")

    # Verify vdb is available
    try:
        from vdb.lib import db

        db_conn, index_conn = db.get(read_only=True)
        count = index_conn.execute("SELECT count(*) FROM cve_index").fetchone()
        print(f"vdb index rows: {count[0] if count else 0}")
    except Exception as e:
        print(f"ERROR: vdb not available — {e}")
        print("Run depscan once first to download the database.")
        return 1

    print(f"\n--- Serial path (DEPSCAN_BATCH_SEARCH=false) [{args.runs} run(s)] ---")
    serial_time, serial_results = timed_find_vulns(pkg_list, batched=False, runs=args.runs)
    print(f"  wall-clock: {serial_time:.3f}s")
    print(f"  results:    {len(serial_results)}")

    print(f"\n--- Batched path (DEPSCAN_BATCH_SEARCH=true) [{args.runs} run(s)] ---")
    batched_time, batched_results = timed_find_vulns(pkg_list, batched=True, runs=args.runs)
    print(f"  wall-clock: {batched_time:.3f}s")
    print(f"  results:    {len(batched_results)}")

    # Output parity check (compare CVE id + matched_by sets)
    def result_key(r):
        return (r.get("cve_id"), r.get("matched_by"))

    serial_keys = {result_key(r) for r in serial_results}
    batched_keys = {result_key(r) for r in batched_results}
    only_serial = serial_keys - batched_keys
    only_batched = batched_keys - serial_keys
    print(f"\nOutput parity: serial={len(serial_keys)} batched={len(batched_keys)}")
    if only_serial:
        print(f"  ONLY in serial ({len(only_serial)}): {sorted(only_serial)[:5]} ...")
    if only_batched:
        print(f"  ONLY in batched ({len(only_batched)}): {sorted(only_batched)[:5]} ...")
    if not only_serial and not only_batched:
        print("  EXACT MATCH")

    if serial_time > 0:
        print(f"\nSpeedup: {serial_time / batched_time:.2f}x" if batched_time > 0 else "")
    return 0


if __name__ == "__main__":
    sys.exit(main())
