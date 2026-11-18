"""The ``depscan mcp`` verb: run the MCP server over stdio.

stdout is the protocol channel for the whole session and carries nothing
else; the SDK's ``stdio_server()`` captures the transport first and only
then the run loop moves ``sys.stdout`` to stderr, so logs and stray output
from dep-scan and its libraries reach the client's log sink instead of the
wire. The verb has no ``--format`` option for the same reason: there is no
second output document.

The ``mcp`` SDK enters only through the run path's loader, so a machine
without the ``mcp`` extra imports this module, prints one message on stderr
naming the extra, and exits 4.
"""

import argparse
import asyncio
import sys

from depscan.commands.output import EXIT_FAILURE, EXIT_REQUIREMENT_NOT_MET, EXIT_USAGE
from depscan.lib.logger import LOG
from depscan.mcp_server import confinement
from depscan.mcp_server.server import load_mcp_sdk, serve

#: The extra that provides the SDK, named by the exit-4 message.
MCP_EXTRA = "owasp-depscan[mcp]"


def register(subparsers) -> None:
    parser = subparsers.add_parser(
        "mcp",
        help="Run the MCP server over stdio for agents and MCP clients.",
    )
    parser.add_argument(
        "--allow-dir",
        action="append",
        default=[],
        dest="allow_dirs",
        metavar="DIR",
        help=(
            "A directory the server may read scan data from; repeatable. "
            "With none given, the server's working directory is the only "
            "allowed root. Roots the MCP client announces add to these."
        ),
    )
    parser.add_argument(
        "--allow-scans",
        action="store_true",
        default=False,
        help=(
            "Let the run_scan tool execute a real dep-scan scan, never a "
            "dry run, for targets inside the allowed roots. The tool's own "
            "arguments cannot turn this on; only the person who starts the "
            "server can."
        ),
    )


def run(args: argparse.Namespace) -> int:
    """Run the MCP server over stdio; the process exit code.

    Exits 4 with the message on stderr naming ``owasp-depscan[mcp]`` when
    the ``mcp`` extra is not installed. A root given to ``--allow-dir``
    that is not an existing directory refuses to start (exit 2), because a
    root that confines nothing would promise more than it allows. Any other
    failure of the running server exits 1.
    """
    try:
        sdk = load_mcp_sdk()
    except ImportError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_REQUIREMENT_NOT_MET
    try:
        startup_roots = confinement.startup_roots(args.allow_dirs)
    except confinement.PathOutsideRootsError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_USAGE
    LOG.info(
        "Starting the MCP server over stdio; allowed roots: %s%s",
        ", ".join(startup_roots),
        "; real scans allowed" if args.allow_scans else "; scans are dry runs",
    )
    try:
        return asyncio.run(serve(sdk, tuple(startup_roots), allow_scans=args.allow_scans))
    except Exception as exc:  # noqa: BLE001 - a stopped server reports and exits 1
        message = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
        LOG.error("The MCP server stopped with an error: %s", message)
        return EXIT_FAILURE
