#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""depscan-vdb: download and inspect the vdb vulnerability database.

The heavy lifting belongs to vdb's ``vdb db`` command: the full-database
flavors are downloaded through its staged, validated and atomically swapped
refresh, type shards through its atomic per-shard placement, and the local
state report comes from its store status. This command adds dep-scan's
variant selection (the legacy ``--scope``/``--time``/``--extended`` aliases
mapped onto the five published flavors), its download retries, its
``VDB_AGE_HOURS`` freshness policy and its variant marker.
"""

import argparse
import sys

from vdb.lib import config as vdb_config
from vdb.lib import db as db_lib
from vdb.lib import db_cmd

from depscan import get_version
from depscan.lib.config import (
    VDB_AGE_HOURS,
    VDB_FLAVORS,
    VDB_SHARDS_MARKER_PREFIX,
    read_vdb_image_marker,
    resolve_vdb_flavor,
    resolve_vdb_image_url,
    vdb_image_marker_path,
    vdb_shards_marker,
    write_vdb_image_marker,
)
from depscan.lib.logger import LOG


def _flavor_from_image(image):
    """The flavor name of a vdb 7 image reference, when it carries one."""
    repo = image.split("/")[-1].split(":")[0]
    if repo.startswith("vdb7-"):
        flavor = repo[len("vdb7-") :]
        if flavor in VDB_FLAVORS:
            return flavor
    return None


def _build_parser():
    parser = argparse.ArgumentParser(
        prog="depscan-vdb",
        description=(
            "Download and inspect the published vdb vulnerability database "
            "flavors and type shards."
        ),
        epilog="Visit https://github.com/owasp-dep-scan/dep-scan to learn more",
    )
    subparsers = parser.add_subparsers(dest="command")

    # --- download (default) ------------------------------------------------
    dl = subparsers.add_parser(
        "download",
        help="Download a database flavor or a set of type shards into the local store.",
    )
    dl.add_argument(
        "--flavor",
        choices=VDB_FLAVORS,
        default=None,
        help="Which published database flavor to download: full (app+OS), "
        "app-only, app-extended (metadata tables), app-10y (NVD 2016+), "
        "app-10y-extended. Default: full.",
    )
    dl.add_argument(
        "--shards",
        nargs="+",
        default=None,
        metavar="SHARD",
        help="Fetch type shards (shard names or purl types such as npm, pypi) "
        "into the shard store instead of a complete database.",
    )
    dl.add_argument(
        "--scope",
        choices=("app", "app+os"),
        default=None,
        help="Deprecated alias for --flavor. 'app' resolves to app-only (or a "
        "10y/extended flavor with the other aliases), 'app+os' to full.",
    )
    dl.add_argument(
        "--time",
        choices=("2y", "default", "10y"),
        default=None,
        help="Deprecated alias for --flavor. '10y' selects a 10-year flavor; "
        "'2y' has no v7 equivalent and is rejected.",
    )
    dl.add_argument(
        "--extended",
        action="store_true",
        default=False,
        help="Deprecated alias selecting the metadata flavor (app-extended or app-10y-extended).",
    )
    dl.add_argument(
        "--compression",
        choices=("xz", "zst"),
        default="xz",
        help="Compression format. 'xz' always works; 'zst' needs a zstd "
        "decompressor. Default: xz.",
    )
    dl.add_argument(
        "--distro",
        choices=("alpine", "debian", "redhat", "alma", "rocky", "ubuntu"),
        default=None,
        help="Rejected: vdb 7 publishes no per-distro complete database.",
    )
    dl.add_argument(
        "--image",
        default=None,
        help="Override the image URL verbatim (bypasses the flavor resolver).",
    )

    # --- info --------------------------------------------------------------
    subparsers.add_parser(
        "info",
        help="Print information about the local database and shard store.",
    )

    # --- path --------------------------------------------------------------
    subparsers.add_parser(
        "path",
        help="Print the VDB_HOME directory.",
    )

    parser.add_argument(
        "-v",
        "--version",
        help="Display the version",
        action="version",
        version="%(prog)s " + get_version(),
    )
    return parser


def _resolve_flavor_from_args(args):
    """Resolve the flavor from --flavor or the deprecated aliases.

    Each deprecated alias in use prints one warning naming the flavor the
    selection resolved to. Combinations with no published flavor raise.
    """
    if args.distro:
        raise ValueError(
            "vdb 7 publishes no per-distro complete database. Published "
            f"flavors: {', '.join(VDB_FLAVORS)}."
        )
    legacy_flags = [
        flag
        for flag, value in (
            ("--scope", args.scope),
            ("--time", args.time),
            ("--extended", args.extended),
        )
        if value
    ]
    if args.flavor and legacy_flags:
        raise ValueError("--flavor cannot be combined with the deprecated aliases.")
    if args.flavor:
        return args.flavor, []
    flavor = resolve_vdb_flavor(
        scope=args.scope or "app+os",
        time=args.time or "default",
        extended=args.extended,
    )
    for flag in legacy_flags:
        print(
            f"warning: {flag} is deprecated; downloading the '{flavor}' flavor. "
            f"Pass --flavor {flavor} to select it directly.",
            file=sys.stderr,
        )
    return flavor, legacy_flags


def cmd_download(args):
    """Download the selected database flavor or shard set and write the marker."""
    from depscan.cli import download_vdb_with_retries, refresh_shards_with_retries

    data_dir = vdb_config.DATA_DIR
    if args.shards:
        if args.flavor or args.image:
            print(
                "error: --shards cannot be combined with --flavor or --image.",
                file=sys.stderr,
            )
            return 1
        from vdb.lib.shard_store import canonical_shard_for_type

        # Shard names or purl types (npm, pypi, ...), like `vdb db refresh`.
        shard_names = []
        for shard in args.shards:
            name = canonical_shard_for_type(shard)
            if name not in shard_names:
                shard_names.append(name)
        LOG.info(
            "Refreshing vdb shard(s) %s into %s",
            ", ".join(shard_names),
            vdb_config.VDB_SHARDS_DIR,
        )
        placed = (
            refresh_shards_with_retries(shard_names, store_dir=vdb_config.VDB_SHARDS_DIR) or []
        )
        write_vdb_image_marker(vdb_shards_marker(shard_names), data_dir)
        LOG.info(
            "Refreshed shard(s): %s. Marker written to %s",
            ", ".join(placed),
            vdb_image_marker_path(data_dir),
        )
        return 0

    try:
        flavor, _legacy = _resolve_flavor_from_args(args)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    image_url = resolve_vdb_image_url(
        flavor=flavor, compression=args.compression, image=args.image
    )
    LOG.info("vdb image: %s", image_url)
    LOG.info("Target directory: %s", data_dir)
    download_vdb_with_retries(image_url)
    write_vdb_image_marker(image_url, data_dir)
    LOG.info("Download complete. Variant marker written to %s", vdb_image_marker_path(data_dir))
    return 0


def cmd_info(args):
    """Print the local database and shard store state.

    Built on vdb's own reporting (``db_cmd.store_status`` and the main
    database metadata); a partial store or a stale shard is printed as such,
    never hidden.
    """
    data_dir = vdb_config.DATA_DIR
    marker = read_vdb_image_marker(data_dir)
    print(f"VDB_HOME: {data_dir}")
    if marker:
        if marker.startswith(VDB_SHARDS_MARKER_PREFIX):
            print(f"Last refresh:      shards {marker[len(VDB_SHARDS_MARKER_PREFIX) :]}")
        else:
            flavor = _flavor_from_image(marker)
            print(f"Last pulled image: {marker}" + (f" ({flavor})" if flavor else ""))
    else:
        print("Last pulled image: (none recorded)")
    db_lib.reset_connections()
    db_meta = db_lib.get_db_file_metadata() or {}
    if db_meta.get("created_utc"):
        stale = db_lib.needs_update(days=0, hours=VDB_AGE_HOURS, default_status=False)
        state = "stale (re-download recommended)" if stale else "fresh"
        print(
            f"Main DB built:     {db_meta.get('created_utc')} ({state}, threshold: {VDB_AGE_HOURS}h)"
        )
        completeness = db_meta.get("completeness", "full")
        if completeness == "partial":
            print("Main DB type:      shard installed as the main database (partial)")
        print(
            f"Main DB rows:      {db_meta.get('cve_data_count', '?')} data / "
            f"{db_meta.get('cve_index_count', '?')} index"
        )
    else:
        print("Main DB built:     (no database found)")
    meta_rows = db_lib.metadata_rows_count() if db_meta.get("created_utc") else 0
    print(f"Metadata rows:     {meta_rows}" + (" (extended flavor)" if meta_rows else ""))
    store = db_cmd.store_status()
    print(f"Shard store:       {store.get('store_dir')}")
    shards = store.get("shards") or []
    if not shards:
        print("Shard store:       empty")
    for shard in shards:
        state = "STALE (much older than its siblings)" if shard["stale"] else "ok"
        print(
            f"  shard {shard['name']}: build {shard['build_id']}, "
            f"built {shard.get('created_utc') or '?'}, "
            f"{_fmt_age(shard.get('age_days'))} old, "
            f"{shard['type_count']} type(s) ({', '.join(shard['types'])}) - {state}"
        )
    if shards:
        mix = " (mixed builds)" if store.get("mixed_builds") else ""
        print(f"Store coverage:    {store.get('coverage')}{mix}")
        if store.get("missing_group_shards"):
            print(
                "note: purl types with no local shard are reported as coverage "
                "gaps at search time, never silently skipped."
            )
    return 0


def _fmt_age(age_days):
    if age_days is None:
        return "unknown age"
    if age_days < 1 / 24:
        return "<1h"
    if age_days < 1:
        return f"{age_days * 24:.1f}h"
    return f"{age_days:.1f}d"


def cmd_path(args):
    """Print the VDB_HOME directory."""
    print(vdb_config.DATA_DIR)
    return 0


def main():
    """Entry point for the depscan-vdb console script."""
    known_subcommands = ("download", "info", "path")
    raw_args = sys.argv[1:]
    # Default to "download" when no subcommand is given.
    if not raw_args or (raw_args[0].startswith("-") and raw_args[0] not in ("-h", "--help")):
        raw_args = ["download"] + raw_args
    parser = _build_parser()
    args = parser.parse_args(raw_args)
    if args.command == "info":
        return cmd_info(args)
    if args.command == "path":
        return cmd_path(args)
    return cmd_download(args)


if __name__ == "__main__":
    sys.exit(main() or 0)
