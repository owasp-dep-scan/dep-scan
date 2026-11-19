"""The ``depscan mcp`` server package: construction, confinement and, in
their own modules, the tools and resources.

Importing this package never imports the ``mcp`` SDK: the SDK enters only
through :func:`depscan.mcp_server.server.load_mcp_sdk`, inside the verb's
run path, so a missing ``mcp`` extra is a clean exit 4 naming the extra and
not a crashed import. The verb module is :mod:`depscan.commands.mcp`.
"""
