#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""``depscan vdb``: download and inspect the vdb vulnerability database.

The heavy lifting belongs to vdb's ``vdb db`` command: the full-database
flavors are downloaded through its staged, validated and atomically swapped
refresh, type shards through its atomic per-shard placement, and the local
state report comes from its store status. This command adds dep-scan's
variant selection (the legacy ``--scope``/``--time``/``--extended`` aliases
mapped onto the five published flavors), its download retries, its
``VDB_AGE_HOURS`` freshness policy and its variant marker.

The module serves two front ends: the ``depscan vdb`` verb, whose subparser
carries :func:`register_arguments`, and :func:`main`, which parses a raw
argv and defaults to the ``download`` subcommand when none was given.
"""

import argparse
import json
import sys
from typing import Any, Dict, List, Optional

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


def _add_format_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="text for people, json for scripts (default: text)",
    )


def register_arguments(parser: argparse.ArgumentParser) -> None:
    """Add the vdb subcommands and options to ``parser``."""
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
    _add_format_argument(dl)

    # --- info --------------------------------------------------------------
    info = subparsers.add_parser(
        "info",
        help="Print information about the local database and shard store.",
    )
    _add_format_argument(info)

    # --- path --------------------------------------------------------------
    path = subparsers.add_parser(
        "path",
        help="Print the VDB_HOME directory.",
    )
    _add_format_argument(path)

    parser.add_argument(
        "-v",
        "--version",
        help="Display the version",
        action="version",
        version="%(prog)s " + get_version(),
    )


def _build_parser():
    parser = argparse.ArgumentParser(
        prog="depscan vdb",
        description=(
            "Download and inspect the published vdb vulnerability database "
            "flavors and type shards."
        ),
        epilog="Visit https://github.com/owasp-dep-scan/dep-scan to learn more",
    )
    register_arguments(parser)
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
    from depscan.lib.vdb_setup import download_vdb_with_retries

    data_dir = vdb_config.DATA_DIR
    if args.shards:
        return _download_shards(args, data_dir)

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
    if getattr(args, "format", "text") == "json":
        print(json.dumps({"image": image_url, "marker": vdb_image_marker_path(data_dir)}))
    return 0


def _download_shards(args, data_dir):
    """Fetch the requested type shards and write the shard-set marker."""
    from vdb.lib.shard_store import canonical_shard_for_type

    from depscan.lib.vdb_setup import refresh_shards_with_retries

    if args.flavor or args.image:
        print(
            "error: --shards cannot be combined with --flavor or --image.",
            file=sys.stderr,
        )
        return 1
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
    placed = refresh_shards_with_retries(shard_names, store_dir=vdb_config.VDB_SHARDS_DIR) or []
    write_vdb_image_marker(vdb_shards_marker(shard_names), data_dir)
    LOG.info(
        "Refreshed shard(s): %s. Marker written to %s",
        ", ".join(placed),
        vdb_image_marker_path(data_dir),
    )
    if getattr(args, "format", "text") == "json":
        print(json.dumps({"shards": shard_names, "marker": vdb_image_marker_path(data_dir)}))
    return 0


def _collect_info() -> Dict[str, Any]:
    """Read the local database and shard store state as one document.

    Built on vdb's own reporting (``db_cmd.store_status`` and the main
    database metadata); a partial store or a stale shard is recorded as such,
    never hidden.
    """
    data_dir = vdb_config.DATA_DIR
    marker = read_vdb_image_marker(data_dir)
    document: Dict[str, Any] = {
        "vdbHome": data_dir,
        "marker": marker,
        "markerKind": None,
        "flavor": None,
    }
    if marker:
        if marker.startswith(VDB_SHARDS_MARKER_PREFIX):
            document["markerKind"] = "shards"
        else:
            document["markerKind"] = "image"
            document["flavor"] = _flavor_from_image(marker)
    db_lib.reset_connections()
    db_meta = db_lib.get_db_file_metadata() or {}
    document["mainDb"] = _main_db_entry(db_meta)
    meta_rows = db_lib.metadata_rows_count() if db_meta.get("created_utc") else 0
    document["metadataRows"] = meta_rows
    document["extendedFlavor"] = bool(meta_rows)
    document["shardStore"] = _shard_store_entry(db_cmd.store_status())
    return document


def _main_db_entry(db_meta: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The main database entry, or None when no database was found."""
    if not db_meta.get("created_utc"):
        return None
    stale = db_lib.needs_update(days=0, hours=VDB_AGE_HOURS, default_status=False)
    return {
        "builtUtc": db_meta.get("created_utc"),
        "stale": bool(stale),
        "maxAgeHours": VDB_AGE_HOURS,
        "completeness": db_meta.get("completeness", "full"),
        "dataRows": db_meta.get("cve_data_count", "?"),
        "indexRows": db_meta.get("cve_index_count", "?"),
    }


def _shard_store_entry(store: Dict[str, Any]) -> Dict[str, Any]:
    """The shard store entry, with one record per installed shard."""
    shards = []
    for shard in store.get("shards") or []:
        shards.append(
            {
                "name": shard["name"],
                "buildId": shard["build_id"],
                "builtUtc": shard.get("created_utc"),
                "ageDays": shard.get("age_days"),
                "typeCount": shard["type_count"],
                "types": list(shard["types"]),
                "stale": bool(shard["stale"]),
            }
        )
    return {
        "storeDir": store.get("store_dir"),
        "shards": shards,
        "coverage": store.get("coverage"),
        "mixedBuilds": bool(store.get("mixed_builds")),
        "missingGroupShards": list(store.get("missing_group_shards") or []),
    }


def _render_info_text(document: Dict[str, Any]) -> List[str]:
    """The text rendering of the info document, one line per row."""
    lines = [f"VDB_HOME: {document['vdbHome']}"]
    marker = document["marker"]
    if marker:
        if document["markerKind"] == "shards":
            lines.append(f"Last refresh:      shards {marker[len(VDB_SHARDS_MARKER_PREFIX) :]}")
        else:
            flavor = document["flavor"]
            lines.append(f"Last pulled image: {marker}" + (f" ({flavor})" if flavor else ""))
    else:
        lines.append("Last pulled image: (none recorded)")
    main_db = document["mainDb"]
    if main_db:
        state = "stale (re-download recommended)" if main_db["stale"] else "fresh"
        lines.append(
            f"Main DB built:     {main_db['builtUtc']} ({state}, "
            f"threshold: {main_db['maxAgeHours']}h)"
        )
        if main_db["completeness"] == "partial":
            lines.append("Main DB type:      shard installed as the main database (partial)")
        lines.append(
            f"Main DB rows:      {main_db['dataRows']} data / {main_db['indexRows']} index"
        )
    else:
        lines.append("Main DB built:     (no database found)")
    meta_rows = document["metadataRows"]
    lines.append(f"Metadata rows:     {meta_rows}" + (" (extended flavor)" if meta_rows else ""))
    store = document["shardStore"]
    lines.append(f"Shard store:       {store['storeDir']}")
    shards = store["shards"]
    if not shards:
        lines.append("Shard store:       empty")
    for shard in shards:
        state = "STALE (much older than its siblings)" if shard["stale"] else "ok"
        lines.append(
            f"  shard {shard['name']}: build {shard['buildId']}, "
            f"built {shard['builtUtc'] or '?'}, "
            f"{_fmt_age(shard['ageDays'])} old, "
            f"{shard['typeCount']} type(s) ({', '.join(shard['types'])}) - {state}"
        )
    if shards:
        mix = " (mixed builds)" if store["mixedBuilds"] else ""
        lines.append(f"Store coverage:    {store['coverage']}{mix}")
        if store["missingGroupShards"]:
            lines.append(
                "note: purl types with no local shard are reported as coverage "
                "gaps at search time, never silently skipped."
            )
    return lines


def cmd_info(args):
    """Print the local database and shard store state."""
    document = _collect_info()
    if getattr(args, "format", "text") == "json":
        print(json.dumps(document, indent=2))
        return 0
    for line in _render_info_text(document):
        print(line)
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
    if getattr(args, "format", "text") == "json":
        print(json.dumps({"path": vdb_config.DATA_DIR}))
        return 0
    print(vdb_config.DATA_DIR)
    return 0


def dispatch(args) -> int:
    """Run the parsed subcommand; returns the process exit code."""
    if args.command == "info":
        return cmd_info(args)
    if args.command == "path":
        return cmd_path(args)
    return cmd_download(args)


def main(argv=None):
    """Entry point of the vdb command; ``argv`` defaults to ``sys.argv``."""
    raw_args = list(sys.argv[1:] if argv is None else argv)
    # Default to "download" when no subcommand is given.
    if not raw_args or (raw_args[0].startswith("-") and raw_args[0] not in ("-h", "--help")):
        raw_args = ["download"] + raw_args
    args = _build_parser().parse_args(raw_args)
    return dispatch(args)


if __name__ == "__main__":
    sys.exit(main() or 0)
