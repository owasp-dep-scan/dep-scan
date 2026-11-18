"""The MCP server: SDK loading, construction, handlers and the run loop.

Importing this module never imports the ``mcp`` SDK: the SDK enters through
:func:`load_mcp_sdk`, which only the verb's run path calls, so a machine
without the ``mcp`` extra imports everything and exits 4 with the install
message instead of crashing on an import.

The handler functions delegate to :mod:`depscan.mcp_server.tools` (the ten
tools, paging and the spill) and :mod:`depscan.mcp_server.resources`
(resources and prompts). Those modules are imported inside
:func:`build_server`, the construction path, so this module stays importable
on its own and the tool and resource layers load only when a server is
actually built. The contract the two modules fulfil, each a handler of the
same name and signature the MCP request expects:

- ``tools.handle_list_tools(ctx, params)`` -> ``ListToolsResult``
- ``tools.handle_call_tool(ctx, params)`` -> ``CallToolResult``
- ``resources.handle_list_resources(ctx, params)`` -> ``ListResourcesResult``
- ``resources.handle_list_resource_templates(ctx, params)`` ->
  ``ListResourceTemplatesResult``
- ``resources.handle_read_resource(ctx, params)`` -> ``ReadResourceResult``
- ``resources.handle_list_prompts(ctx, params)`` -> ``ListPromptsResult``
- ``resources.handle_get_prompt(ctx, params)`` -> ``GetPromptResult``

Both modules read the startup configuration from the lifespan state this
module puts on the request context: ``startup_roots``, the tuple of allowed
roots fixed when the server started, and ``allow_scans``, whether real runs
are permitted at all. Helpers here give them the client's roots
(:func:`client_roots`) and the merged, effective roots
(:func:`effective_roots_for`).

stdout discipline: stdout is the protocol channel. The SDK's
``stdio_server()`` captures the transport the moment it is entered - it
checks ``sys.stdout``'s file descriptor at entry and serves the wire from a
private duplicate of fd 1, falling back to ``sys.stdout.buffer`` in place
where descriptors cannot be duplicated. Swapping ``sys.stdout`` before that
entry would therefore hand the fallback path stderr's buffer and send the
protocol itself to stderr. The order is fixed: build the server, enter
``stdio_server()``, and only then move ``sys.stdout`` to stderr for the rest
of the session (:func:`depscan.commands.output.stdout_on_stderr`), so dep-scan's
console, which pins no stream and follows ``sys.stdout`` at write time, and
any library print land next to the logs on stderr and never on the wire.
"""

import os
import sys
from contextlib import asynccontextmanager
from importlib.metadata import PackageNotFoundError, version as pkg_version
from typing import Any, AsyncIterator, Dict, Tuple
from urllib.parse import urlparse
from urllib.request import url2pathname

from depscan.mcp_server import confinement

#: The server name clients see.
SERVER_NAME = "dep-scan"

#: How long one roots/list request may take before the call goes on with
#: the --allow-dir roots alone.
ROOTS_TIMEOUT_SECONDS = 10

try:
    SERVER_VERSION = pkg_version("owasp-depscan")
except PackageNotFoundError:
    SERVER_VERSION = "7.0.0"

SERVER_INSTRUCTIONS = """
This MCP server exposes a dep-scan scan directory as structured security
data for agents.

Use it to:
- summarize a scan directory's manifest, findings and coverage
- list, filter and page findings and BOM components
- read one finding, explain it, and diff two scan directories
- report the doctor's tools and capabilities and the vulnerability
  database state
- run a dep-scan scan (a dry run by default; a real run needs the server
  started with --allow-scans)

Every path a tool takes must resolve inside the allowed roots: the
--allow-dir directories the server was started with plus the roots this
client announced. Results larger than 32 KB page or spill to a JSON file
inside the scan directory. The server reads scan results; run_scan is the
only tool that scans, and it never runs a project's install or build steps
and always runs cdxgen in secure mode.
"""


class SdkMissingError(ImportError):
    """The ``mcp`` SDK this server is written against is not installed.

    The verb turns this into exit 4 with the install message naming the
    extra; the loader raises it through the real import, so the test for the
    missing extra exercises the same import a running server performs.
    """


def load_mcp_sdk() -> Any:
    """Import the ``mcp`` SDK the server is written against.

    Returns the pieces the server needs as one namespace; raises
    :class:`SdkMissingError`, an ``ImportError``, when the ``mcp`` extra is
    not installed. Kept to one small function so the missing-extra path is
    the real import path, exercised as it runs.
    """
    try:
        import mcp.server
        import mcp.server.stdio
        import mcp.types
        from mcp.server import Server
        from mcp.server.context import ServerRequestContext
    except ImportError as exc:
        raise SdkMissingError(
            "the mcp package is not installed; run `pip install "
            "owasp-depscan[mcp]` to enable the depscan mcp command"
        ) from exc
    return {
        "server_module": mcp.server,
        "stdio": mcp.server.stdio,
        "types": mcp.types,
        "Server": Server,
        "ServerRequestContext": ServerRequestContext,
    }


async def client_roots(ctx: Any) -> Tuple[str, ...]:
    """The roots the client announced, as local directory paths.

    Asks the client session for its roots; a client that does not support
    them, or announces none, yields an empty tuple. Each root arrives as a
    ``file://`` URI and is converted to a local path the way this platform
    spells it.
    """
    import anyio  # an mcp dependency; imported here like the SDK itself

    roots = []
    session = ctx.session
    capabilities = getattr(getattr(session, "client_params", None), "capabilities", None)
    if getattr(capabilities, "roots", None) is None:
        # A client that did not declare the roots capability never answers
        # roots/list; asking would hang the call.
        return ()
    try:
        with anyio.fail_after(ROOTS_TIMEOUT_SECONDS):
            result = await session.list_roots()
    except Exception as exc:  # noqa: BLE001 - no answer means no client roots
        print(
            f"depscan mcp: the client's roots/list request failed ({type(exc).__name__}); "
            "confining this call to the --allow-dir roots",
            file=sys.stderr,
        )
        return ()
    for root in result.roots or []:
        parsed = urlparse(str(root.uri))
        if parsed.scheme not in ("", "file"):
            continue
        path = url2pathname(parsed.path)
        if path and os.path.isdir(path):
            roots.append(os.path.realpath(path))
    return tuple(roots)


async def effective_roots_for(ctx: Any, startup_roots: Tuple[str, ...]) -> Tuple[str, ...]:
    """The roots one request is confined by: startup roots plus client roots.

    The client's roots add to the ``--allow-dir`` roots, they never replace
    them: the directory the person who started the server allowed stays
    allowed, and a client that announces a wider root widens what this
    session may read and, with ``--allow-scans``, where it may scan.
    """
    return confinement.effective_roots(startup_roots, await client_roots(ctx))


def build_server(sdk: Dict[str, Any], startup_roots: Tuple[str, ...], allow_scans: bool = False):
    """Construct the MCP server with its handlers.

    ``startup_roots`` and ``allow_scans`` reach the handlers through the
    lifespan state, so the server object itself carries no mutable global.
    The tool and resource modules are imported here, in the construction
    path: importing :mod:`depscan.mcp_server.server` never needs them.
    """
    from depscan.mcp_server import resources  # pyrefly: ignore missing-import
    from depscan.mcp_server import tools  # pyrefly: ignore missing-import

    types = sdk["types"]
    server_class = sdk["Server"]

    @asynccontextmanager
    async def server_lifespan(server) -> AsyncIterator[Dict[str, Any]]:
        yield {"startup_roots": tuple(startup_roots), "allow_scans": bool(allow_scans)}

    async def handle_list_tools(ctx, params):
        return await tools.handle_list_tools(ctx, params)

    async def handle_call_tool(ctx, params):
        try:
            return await tools.handle_call_tool(ctx, params)
        except Exception as exc:  # noqa: BLE001 - a tool failure is an isError result
            # Tool failures become isError results the client can show the
            # model, never a protocol-level break that would end the session.
            return types.CallToolResult(
                content=[
                    types.TextContent(type="text", text=f"{type(exc).__name__}: {exc}")
                ],
                is_error=True,
            )

    async def handle_list_resources(ctx, params):
        return await resources.handle_list_resources(ctx, params)

    async def handle_list_resource_templates(ctx, params):
        return await resources.handle_list_resource_templates(ctx, params)

    async def handle_read_resource(ctx, params):
        return await resources.handle_read_resource(ctx, params)

    async def handle_list_prompts(ctx, params):
        return await resources.handle_list_prompts(ctx, params)

    async def handle_get_prompt(ctx, params):
        return await resources.handle_get_prompt(ctx, params)

    return server_class(
        SERVER_NAME,
        version=SERVER_VERSION,
        instructions=SERVER_INSTRUCTIONS,
        lifespan=server_lifespan,
        on_list_tools=handle_list_tools,
        on_call_tool=handle_call_tool,
        on_list_resources=handle_list_resources,
        on_list_resource_templates=handle_list_resource_templates,
        on_read_resource=handle_read_resource,
        on_list_prompts=handle_list_prompts,
        on_get_prompt=handle_get_prompt,
    )


async def serve(sdk: Dict[str, Any], startup_roots: Tuple[str, ...], allow_scans: bool = False) -> int:
    """Run the server over stdio until the session ends; the exit code.

    The order is the stdout discipline the module docstring fixes: build
    the server, enter ``stdio_server()`` so the SDK captures the transport
    while ``sys.stdout`` is still the real stdout, then swap ``sys.stdout``
    to stderr for the rest of the session. ``stdout_on_stderr`` enters here
    rather than at module level because importing it means importing the
    verb registry, whose modules import this one back.
    """
    from depscan.commands.output import stdout_on_stderr

    server = build_server(sdk, startup_roots, allow_scans)
    async with sdk["stdio"].stdio_server() as (read_stream, write_stream):
        with stdout_on_stderr():
            await server.run(
                read_stream,
                write_stream,
                server.create_initialization_options(),
            )
    return 0
