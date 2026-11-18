"""The ``depscan serve`` verb: run dep-scan as a server."""

import argparse
import sys
from typing import Dict

from depscan import api
from depscan.commands.output import (
    stdout_on_stderr,
    EXIT_FAILURE,
    EXIT_REQUIREMENT_NOT_MET,
    print_error_document,
    print_json_document,
)
from depscan.commands.scan import add_vdb_options
from depscan.lib import pipeline
from depscan.lib.logger import LOG

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
    add_vdb_options(
        parser,
        "Select which published vdb database the server downloads when it "
        "starts. An explicit VDB_DATABASE_URL env pin always wins. The "
        "`depscan vdb download` command shares the same options for "
        "pre-fetching.",
    )


def _serving_document(options) -> Dict:
    """The document that names the running server.

    ``host`` and ``port`` are the configured values; ``url`` shows the
    wildcard and IPv6-any hosts as 127.0.0.1, the address a caller on the
    same machine can reach.
    """
    host = options.server_host
    port = options.server_port
    shown = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    return {"serving": {"host": host, "port": port, "url": f"http://{shown}:{port}"}}


def run(args: argparse.Namespace) -> int:
    """Run the server; the process exit code.

    In json format stdout carries exactly one document: the ``serving``
    document once the server's listening socket accepts connections, or the
    error document when the server cannot start. The server's startup
    banners, its request logs and everything else the run prints go to
    stderr, in every format. A database that cannot be prepared exits 1, a
    server whose packages or requirements are missing exits 4, and any other
    start failure exits 1.
    """
    json_output = args.format == "json"
    overrides = {dest: value for dest, value in vars(args).items() if dest not in _NON_SCAN_DESTS}
    options = api.scan_options(server_mode=True, **overrides)
    ctx = pipeline.build_context(options)
    pipeline.configure_output(ctx)
    saved_stdout = sys.stdout
    started_hook = None
    if json_output:
        document = _serving_document(options)

        def started_hook():
            print_json_document(document, saved_stdout)
            saved_stdout.flush()

    try:
        # The server's startup banners and any stray print land next to its
        # request logs on stderr, so stdout carries at most one document.
        with stdout_on_stderr():
            pipeline.start_server_mode(ctx, started_hook=started_hook)
    except pipeline.ScanStageError as exc:
        # The database stage already logged why the server cannot start;
        # json adds the document and the message line the contract asks for.
        if json_output:
            print_error_document(EXIT_FAILURE, "serve", str(exc), stream=saved_stdout)
        return EXIT_FAILURE
    except pipeline.ServerRequirementError as exc:
        if json_output:
            print_error_document(
                EXIT_REQUIREMENT_NOT_MET,
                "serve",
                str(exc),
                {"capability": "server", "reason": str(exc)},
                stream=saved_stdout,
            )
        else:
            LOG.error("%s", exc)
        return EXIT_REQUIREMENT_NOT_MET
    except Exception as exc:  # noqa: BLE001 - the failure becomes the error document
        message = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
        LOG.exception("The server stopped with an unexpected error: %s", message)
        if json_output:
            print_error_document(EXIT_FAILURE, "serve", message, stream=saved_stdout)
        return EXIT_FAILURE
    return 0
