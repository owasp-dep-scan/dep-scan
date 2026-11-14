#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""depscan-vdb: select, download, and inspect vdb vulnerability database images.

This is the dedicated vdb management command added in T7. It lets users pick
any published vdb image variant (scope, time window, extended tier, compression,
distro) without hand-editing ``VDB_DATABASE_URL``. The scan path reuses the
same resolver; this command is for explicit, out-of-band downloads and
inspection.
"""

import argparse
import sys

from vdb.lib import config as vdb_config
from vdb.lib import db as db_lib

from depscan import get_version
from depscan.lib.config import (
    VDB_AGE_HOURS,
    read_vdb_image_marker,
    resolve_vdb_image,
    vdb_image_marker_path,
    vdb_image_size,
    write_vdb_image_marker,
)
from depscan.lib.logger import LOG

_ORAS_AVAILABLE = False
try:
    from vdb.lib.orasclient import download_image  # noqa: F401

    _ORAS_AVAILABLE = True
except ImportError:
    pass


def _build_parser():
    parser = argparse.ArgumentParser(
        prog="depscan-vdb",
        description=(
            "Select, download, and inspect any published vdb vulnerability "
            "database image (scope, time, extended tier, compression, distro)."
        ),
        epilog="Visit https://github.com/owasp-dep-scan/dep-scan to learn more",
    )
    subparsers = parser.add_subparsers(dest="command")

    # --- download (default) ------------------------------------------------
    dl = subparsers.add_parser(
        "download",
        help="Download a vdb image into VDB_HOME (default action).",
    )
    dl.add_argument(
        "--scope",
        choices=("app", "app+os"),
        default="app+os",
        help="Database scope. 'app' carries only application vulnerabilities; "
        "'app+os' adds OS distro data. Default: app+os.",
    )
    dl.add_argument(
        "--time",
        choices=("2y", "default", "10y"),
        default="default",
        help="Time window. '2y' covers 2024+, 'default' covers 2020+, "
        "'10y' covers 2016+. Default: default.",
    )
    dl.add_argument(
        "--extended",
        action="store_true",
        default=False,
        help="Download the extended variant with metadata tables populated "
        "(needed for severity, text, alias, reference, symbol, and date search).",
    )
    dl.add_argument(
        "--compression",
        choices=("xz", "zst"),
        default="xz",
        help="Compression format. 'xz' (tar.xz) is smaller; 'zst' (zstd) is "
        "faster to decompress. Default: xz.",
    )
    dl.add_argument(
        "--distro",
        choices=("alpine", "debian", "redhat", "alma", "rocky", "ubuntu"),
        default=None,
        help="Download a distro-only database. Mutually exclusive with "
        "--scope, --time, and --extended.",
    )
    dl.add_argument(
        "--image",
        default=None,
        help="Override the image URL verbatim (bypasses the resolver).",
    )

    # --- info --------------------------------------------------------------
    subparsers.add_parser(
        "info",
        help="Print information about the locally cached vdb.",
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


def _resolve_image_from_args(args):
    """Resolve the image ref from parsed download args."""
    if args.image:
        return args.image
    return resolve_vdb_image(
        scope=args.scope,
        time=args.time,
        extended=args.extended,
        compression=args.compression,
        distro=args.distro,
    )


def cmd_download(args):
    """Download the selected vdb image and write the variant marker."""
    from depscan.cli import download_vdb_with_retries

    image_url = _resolve_image_from_args(args)
    size = vdb_image_size(image_url)
    data_dir = vdb_config.DATA_DIR
    LOG.info("vdb image: %s (approx %s uncompressed)", image_url, size)
    LOG.info("Target directory: %s", data_dir)
    if not _ORAS_AVAILABLE:
        LOG.error(
            "oras support is not installed. Reinstall with "
            "`pip install owasp-depscan[all]` or "
            "`pip install appthreat-vulnerability-db[oras]`."
        )
        return 1
    download_vdb_with_retries(image_url, data_dir)
    write_vdb_image_marker(image_url, data_dir)
    LOG.info("Download complete. Variant marker written to %s", vdb_image_marker_path(data_dir))
    return 0


def cmd_info(args):
    """Print details about the locally cached vdb."""
    data_dir = vdb_config.DATA_DIR
    marker = read_vdb_image_marker(data_dir)
    db_meta = db_lib.get_db_file_metadata()
    print(f"VDB_HOME: {data_dir}")
    if marker:
        print(f"Last pulled image: {marker}")
        print(f"Approximate size:  {vdb_image_size(marker)} uncompressed")
    else:
        print("Last pulled image: (none recorded)")
    if db_meta and db_meta.get("created_utc"):
        created = db_meta["created_utc"]
        print(f"Created (UTC):     {created}")
        stale = db_lib.needs_update(
            days=0,
            hours=VDB_AGE_HOURS,
            default_status=False,
        )
        status = "stale (re-download recommended)" if stale else "fresh"
        print(f"Freshness:         {status} (threshold: {VDB_AGE_HOURS}h)")
    else:
        print("Created (UTC):     (no database found)")
        print("Freshness:         no local database")
    # Metadata rows (extended check)
    meta_count = 0
    try:
        db_lib.get(read_only=True)
        meta_count = db_lib.metadata_rows_count()
    except Exception:  # noqa: BLE001
        pass
    extended_label = "yes" if meta_count and meta_count > 0 else "no"
    print(f"Extended metadata: {extended_label}" + (f" ({meta_count} rows)" if meta_count else ""))
    return 0


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
