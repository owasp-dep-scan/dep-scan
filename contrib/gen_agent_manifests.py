#!/usr/bin/env python3
"""gen_agent_manifests.py: write the shared fields of every coding-agent
manifest from pyproject.toml and contrib/agent_manifests_template.json.

The version comes from pyproject.toml. dep-scan publishes PEP 440 versions
(``7.0.0.dev0``) while the agent clients expect a semver string, so
:func:`pep440_to_semver` converts the version: the release part is kept,
a ``devN`` segment becomes ``-devN``, an ``aN``/``bN``/``rcN`` (PEP 440 also
allows ``cN``) segment becomes ``-aN``/``-bN``/``-rcN``, and ``postN``
segments are dropped because semver has no post-release. ``7.0.0.dev0``
therefore lands in every manifest as ``7.0.0-dev0``.

The description, author, homepage, repository and keywords come from the
template. Fields that only one client reads (``userConfig``,
``documentationUrl``, ``supportUrl``, ``privacyPolicyUrl`` and ``icon`` in
the Claude Code manifest) are left as they are in the file. The two MCP
server configurations (``.mcp.json`` for Claude Code and ``mcp.json`` for
Codex) are written from one constant so they cannot drift apart. Output is
byte-stable: two-space indent, fixed key order and a trailing newline, so a
second run changes nothing.

Usage:
    python -m contrib.gen_agent_manifests           # write the files
    python -m contrib.gen_agent_manifests --check   # exit 1 and name files that differ

Exit codes:
    0: files written, or all up to date with --check
    1: --check found files that differ from the generated output
    2: internal error
"""

import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = REPO_ROOT / "contrib" / "agent_manifests_template.json"
AGENT_PLUGINS_SCHEMA_URL = "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"
PLUGIN_NAME = "depscan"
PLUGIN_DIR = "./agent-plugin"

#: The MCP server configuration the plugin ships. Claude Code reads it from
#: ``.mcp.json`` at the plugin root and Codex from ``mcp.json``; both files
#: carry the same object, and neither may pass --allow-scans.
MCP_CONFIG = {"mcpServers": {"depscan": {"command": "depscan", "args": ["mcp"]}}}

_VERSION_RE = re.compile(
    r"^(?P<release>\d+(?:\.\d+)*)(?:\.?(?P<pre>a|b|c|rc|dev)\.?(?P<prenum>\d+))?(?:\.post\d+)*(?:\+.*)?$"
)


def pep440_to_semver(version: str) -> str:
    """Convert a PEP 440 version to the semver form the clients expect.

    ``7.0.0`` stays ``7.0.0``; ``7.0.0.dev0`` becomes ``7.0.0-dev0``;
    ``7.0.0rc1`` becomes ``7.0.0-rc1``. Post-release and local segments are
    dropped. A version the regex cannot read is returned unchanged, so a
    future versioning change surfaces as a schema or review problem rather
    than a crash.
    """
    match = _VERSION_RE.match(version.strip())
    if not match:
        return version
    semver = match.group("release")
    if match.group("pre"):
        semver += f"-{match.group('pre')}{match.group('prenum') or ''}"
    return semver


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def with_order(order, values, existing=None):
    """Put the keys in ``order`` first, then any other keys in their old order."""
    result = {}
    existing = existing or {}
    for key in order:
        if values.get(key) is not None:
            result[key] = values[key]
    for key, value in existing.items():
        if key not in result:
            result[key] = value
    return result


def read_existing(path: Path):
    return read_json(path) if path.exists() else {}


def shared_fields() -> dict:
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    version_match = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.MULTILINE)
    if not version_match:
        raise RuntimeError("pyproject.toml has no version")
    pep440_version = version_match.group(1)
    template = read_json(TEMPLATE)
    return {
        "version": pep440_to_semver(pep440_version),
        "description": template["description"],
        "author": template["author"],
        "homepage": template["homepage"],
        "repository": template["repository"],
        "keywords": template["keywords"],
        "marketplace": template["marketplace"],
        "codex": template["codex"],
    }


PLUGIN_FIELDS = [
    "description",
    "version",
    "author",
    "homepage",
    "repository",
    "keywords",
]

# Each target names the file it owns and builds its content from the shared
# fields and whatever is already in the file.
TARGETS = [
    {
        "file": "agent-plugin/.claude-plugin/plugin.json",
        "build": lambda shared, existing: with_order(
            ["name", *PLUGIN_FIELDS], {"name": PLUGIN_NAME, **shared}, existing
        ),
    },
    {
        # The Agent Plugins schema is closed, so nothing but the schema fields
        # is written, plus the extensions block below. Codex discovers
        # hooks/hooks.json by default, and plugins with lifecycle hooks are
        # not eligible for its public plugin directory, so the manifest
        # declares an empty hooks list.
        # https://developers.openai.com/codex/plugins/build
        "file": "agent-plugin/plugin.json",
        "build": lambda shared, existing: with_order(
            ["$schema", "name", *PLUGIN_FIELDS, "extensions"],
            {
                "$schema": AGENT_PLUGINS_SCHEMA_URL,
                "name": PLUGIN_NAME,
                **shared,
                "extensions": {"com.openai": {"hooks": []}},
            },
        ),
    },
    {
        "file": ".claude-plugin/marketplace.json",
        "build": lambda shared, existing: update_marketplace(shared, existing),
    },
    {
        # Codex reads .agents/plugins/marketplace.json and resolves
        # source.path against the repository root. The portable plugin.json
        # in agent-plugin/ is what it loads. Every Codex entry needs a policy
        # and a category.
        # https://developers.openai.com/codex/plugins/build#marketplace-metadata
        "file": ".agents/plugins/marketplace.json",
        "build": lambda shared, existing: {
            "name": shared["marketplace"]["name"],
            "interface": {"displayName": shared["marketplace"]["displayName"]},
            "plugins": [
                {
                    "name": PLUGIN_NAME,
                    "source": {"source": "local", "path": PLUGIN_DIR},
                    "policy": {
                        "installation": shared["codex"]["installation"],
                        "authentication": shared["codex"]["authentication"],
                    },
                    "category": shared["codex"]["category"],
                }
            ],
        },
    },
    {
        # Cursor imports a repository that has .cursor-plugin/marketplace.json
        # at its root. `source` is a bare directory name, not a ./ path. The
        # plugin directory holds a root Agent Plugins plugin.json, which
        # Cursor loads.
        # https://cursor.com/docs/reference/plugins.md
        "file": ".cursor-plugin/marketplace.json",
        "build": lambda shared, existing: {
            "name": shared["marketplace"]["name"],
            "owner": {
                "name": shared["author"]["name"],
                "email": shared["author"]["email"],
            },
            "metadata": {
                "description": shared["description"],
                "version": shared["version"],
            },
            "plugins": [
                {
                    "name": PLUGIN_NAME,
                    "source": PLUGIN_DIR.replace("./", ""),
                    "description": shared["description"],
                    "version": shared["version"],
                    "author": {
                        "name": shared["author"]["name"],
                        "email": shared["author"]["email"],
                    },
                    "homepage": shared["homepage"],
                    "repository": shared["repository"],
                    "keywords": shared["keywords"],
                    "category": shared["marketplace"]["category"],
                }
            ],
        },
    },
    {
        # Gemini CLI installs an extension from a directory that holds
        # gemini-extension.json and a skills/ folder, so the file sits in the
        # plugin directory next to skills/.
        # https://github.com/google-gemini/gemini-cli/blob/main/docs/extensions/reference.md
        "file": "agent-plugin/gemini-extension.json",
        "build": lambda shared, existing: {
            "name": PLUGIN_NAME,
            "version": shared["version"],
            "description": shared["description"],
        },
    },
    {
        "file": "agent-plugin/.mcp.json",
        "build": lambda shared, existing: MCP_CONFIG,
    },
    {
        "file": "agent-plugin/mcp.json",
        "build": lambda shared, existing: MCP_CONFIG,
    },
]


def update_marketplace(shared, existing):
    """Update the plugin entry of the Claude marketplace, keeping its shape.

    The entry may carry fields the generator does not own (displayName,
    category); assigning by key keeps each of them where it already is.
    """
    marketplace = json.loads(json.dumps(existing))
    entry = next(
        (
            plugin
            for plugin in marketplace.get("plugins", [])
            if plugin.get("name") == PLUGIN_NAME
        ),
        None,
    )
    if entry is None:
        raise RuntimeError(
            f'.claude-plugin/marketplace.json has no "{PLUGIN_NAME}" plugin'
        )
    for key in ("description", "homepage", "repository"):
        entry[key] = shared[key]
    return marketplace


def serialize(value) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False) + "\n"


def render_all():
    shared = shared_fields()
    rendered = []
    for target in TARGETS:
        path = REPO_ROOT / target["file"]
        content = serialize(target["build"](shared, read_existing(path)))
        current = path.read_text(encoding="utf-8") if path.exists() else None
        rendered.append({"file": target["file"], "content": content, "current": current})
    return rendered


def stale_manifests():
    return [
        item["file"]
        for item in render_all()
        if item["content"] != item["current"]
    ]


def main() -> int:
    try:
        return run(sys.argv[1:])
    except Exception as err:  # noqa: BLE001 - the CLI reports and exits 2
        print(err, file=sys.stderr)
        return 2


def run(argv: list[str]) -> int:
    check_only = "--check" in argv
    if check_only:
        stale = stale_manifests()
        if stale:
            print(
                "These manifests differ from the generated output; run "
                "`python -m contrib.gen_agent_manifests`:",
                file=sys.stderr,
            )
            for file in stale:
                print(f"  {file}", file=sys.stderr)
            return 1
        print("Agent manifests are up to date.")
        return 0
    wrote = False
    for item in render_all():
        if item["content"] != item["current"]:
            path = REPO_ROOT / item["file"]
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(item["content"], encoding="utf-8")
            print(f"wrote {item['file']}")
            wrote = True
    if not wrote:
        print("Agent manifests are already up to date.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
