"""The ``depscan serve`` verb: run dep-scan as a server."""

import argparse
import json

from depscan import api
from depscan.lib import pipeline

#: The dests of this verb's own options that never reach scan_options.
_NON_SCAN_DESTS = ("verb", "format")


def register(subparsers) -> None:
    parser = subparsers.add_parser(
        "serve",
        help="Run depscan as a server.",
    )
    _add_server_options(parser)
    _add_database_options(parser)


def _add_server_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--server-host",
        default=argparse.SUPPRESS,
        dest="server_host",
        help="depscan server host",
    )
    parser.add_argument(
        "--server-port",
        default=argparse.SUPPRESS,
        dest="server_port",
        help="depscan server port",
    )
    parser.add_argument(
        "--server-allowed-hosts",
        nargs="*",
        default=argparse.SUPPRESS,
        dest="server_allowed_hosts",
        help="List of allowed hostnames or IPs that can access the server (e.g., 'localhost 192.168.1.10'). If unspecified, no host allowlist is enforced.",
    )
    parser.add_argument(
        "--server-allowed-paths",
        nargs="*",
        default=argparse.SUPPRESS,
        dest="server_allowed_paths",
        help="List of allowed filesystem paths that can be scanned by the server. Restricts `path` parameter in /scan requests.",
    )
    parser.add_argument(
        "--cdxgen-server",
        default=argparse.SUPPRESS,
        dest="cdxgen_server",
        help="cdxgen server url. Eg: http://cdxgen:9090",
    )
    parser.add_argument(
        "--custom-data",
        default=argparse.SUPPRESS,
        dest="custom_data",
        help="Path to directory containing custom vulnerability data (JSON/YAML/TOML) to override/augment results.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        default=argparse.SUPPRESS,
        dest="enable_debug",
        help="Run depscan in debug mode.",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="text for people, json for scripts (default: text)",
    )


def _add_database_options(parser: argparse.ArgumentParser) -> None:
    vdb_group = parser.add_argument_group(
        "vulnerability database selection",
        "Select which published vdb database the server downloads when it "
        "starts. An explicit VDB_DATABASE_URL env pin always wins. The "
        "`depscan vdb download` command shares the same options for "
        "pre-fetching.",
    )
    vdb_group.add_argument(
        "--vdb-flavor",
        choices=("full", "app-only", "app-extended", "app-10y", "app-10y-extended"),
        default=argparse.SUPPRESS,
        dest="vdb_flavor",
        help="Which published database flavor to use: 'full' (app+OS), "
        "'app-only' (application ecosystems, NVD 2020+), 'app-extended' "
        "(adds metadata tables for severity, text, alias, reference, symbol "
        "and date search), 'app-10y' (NVD 2016+), 'app-10y-extended' "
        "(both). Default: full.",
    )
    vdb_group.add_argument(
        "--vdb-scope",
        choices=("app", "app+os"),
        default=argparse.SUPPRESS,
        dest="vdb_scope",
        help="Deprecated alias for --vdb-flavor: 'app' maps to app-only (or "
        "app-extended/app-10y/app-10y-extended with the other deprecated "
        "options), 'app+os' to full. Default: app+os.",
    )
    vdb_group.add_argument(
        "--vdb-time",
        choices=("2y", "default", "10y"),
        default=argparse.SUPPRESS,
        dest="vdb_time",
        help="Deprecated alias for --vdb-flavor: '10y' selects a 10-year "
        "flavor; '2y' has no v7 equivalent and is rejected. Default: default.",
    )
    vdb_group.add_argument(
        "--vdb-extended",
        action="store_true",
        default=argparse.SUPPRESS,
        dest="vdb_extended",
        help="Deprecated alias selecting the metadata flavor (app-extended or "
        "app-10y-extended), needed for severity, text, alias, reference, "
        "symbol, and date search. Auto-selected when --severity is set.",
    )
    vdb_group.add_argument(
        "--vdb-compression",
        choices=("xz", "zst"),
        default=argparse.SUPPRESS,
        dest="vdb_compression",
        help="Compression format. 'xz' (tar.xz) always works; 'zst' (zstd) is "
        "faster to decompress but needs a zstd decompressor. Default: xz.",
    )
    vdb_group.add_argument(
        "--vdb-distro",
        choices=("alpine", "debian", "redhat", "alma", "rocky", "ubuntu"),
        default=argparse.SUPPRESS,
        dest="vdb_distro",
        help="Rejected: vdb 7 publishes no per-distro complete database. Pass "
        "--vdb-flavor full and scan the distro packages, or fetch type shards "
        "with `depscan vdb download`.",
    )
    vdb_group.add_argument(
        "--vdb-image",
        default=argparse.SUPPRESS,
        dest="vdb_image",
        help="Override the vdb image URL verbatim (bypasses the resolver). "
        "Equivalent to setting VDB_DATABASE_URL.",
    )


def run(args: argparse.Namespace) -> int:
    overrides = {
        dest: value
        for dest, value in vars(args).items()
        if dest not in _NON_SCAN_DESTS
    }
    options = api.scan_options(server_mode=True, **overrides)
    ctx = pipeline.build_context(options)
    pipeline.configure_output(ctx)
    if args.format == "json":
        # The database stage runs (and reports its problems on stderr) inside
        # start_server_mode, before the server blocks; this line is the only
        # stdout content.
        print(json.dumps({"serve": f"{options.server_host}:{options.server_port}"}))
    try:
        started = pipeline.start_server_mode(ctx)
    except pipeline.ScanStageError:
        # The database stage already logged why the server cannot start.
        return 1
    if started is False:
        # The server packages are missing or the bind was refused; the reason
        # is already logged. A requested capability that cannot run exits 4.
        return 4
    return 0
