#!/usr/bin/env python3
"""SessionStart hook: warn once when the dep-scan CLI is missing from PATH,
is older than this plugin, or lacks the mcp extra the plugin's server
needs. It never installs anything, never scans, and never executes
depscan: the version and the mcp module are read from the distribution
metadata next to the binary, so the check stays fast and has no side
effects. A dep-scan whose version cannot be read this way (a wrapper
script, a shim) is accepted silently.

The command runs in exec form (python3 on PATH, this script as the
argument). If the interpreter itself is missing, Claude Code reports a
non-blocking one-line status and the session proceeds; this script never
needs to handle that case.
"""

import json
import glob
import os
import re
import sys

PLUGIN_MANIFEST = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", ".claude-plugin", "plugin.json"
)

WINDOWS_SUFFIXES = (".exe", ".cmd", ".ps1", ".bat", "")

#: PEP 440 pre-release kinds in their order, lowest first. The plugin
#: manifest carries the semver form (-dev0), the installed distribution
#: carries the PEP 440 form (.dev0); both parse through PRE_ORDER.
PRE_ORDER = {"dev": 0, "a": 1, "alpha": 1, "b": 2, "beta": 2, "c": 3, "rc": 3}
FINAL = 4


def find_on_path(command, env=None):
    """The command's path on PATH, with the Windows script suffixes."""
    env = env if env is not None else os.environ
    dirs = (env.get("PATH") or env.get("Path") or "").split(os.pathsep)
    suffixes = WINDOWS_SUFFIXES if os.name == "nt" else ("",)
    for directory in dirs:
        if not directory:
            continue
        for suffix in suffixes:
            candidate = os.path.join(directory, command + suffix)
            if os.path.isfile(candidate):
                return candidate
    return None


def parse_version(version):
    """A version string as ((major, minor, patch), pre_order, pre_number).

    Reads both the plugin manifest's semver form (7.0.0-dev0) and the
    distribution's PEP 440 form (7.0.0.dev0). A version the parser cannot
    read returns None and the caller stays silent.
    """
    match = re.match(
        r"^(\d+)\.(\d+)\.(\d+)(?:[.-]?(dev|a|alpha|b|beta|c|rc)\.?(\d+))?",
        (version or "").strip(),
    )
    if not match:
        return None
    numbers = (int(match.group(1)), int(match.group(2)), int(match.group(3)))
    if match.group(4):
        pre = PRE_ORDER[match.group(4)]
        pre_number = int(match.group(5) or 0)
    else:
        pre = FINAL
        pre_number = 0
    return (numbers, pre, pre_number)


def is_older(installed, expected):
    """Whether the installed version is older than the expected one."""
    parsed_installed = parse_version(installed)
    parsed_expected = parse_version(expected)
    if not parsed_installed or not parsed_expected:
        return False
    return parsed_installed < parsed_expected


def site_packages_of(binary):
    """The site-packages directory the console script belongs to, if any.

    pip and uv lay the package out as <env>/bin/depscan with the packages
    under <env>/lib/pythonX.Y/site-packages; a Windows venv keeps them in
    Lib\\site-packages next to Scripts. The walk starts at the script's
    directory and looks at those layouts under each ancestor, because the
    depth of the pythonX.Y level varies.
    """
    real = os.path.realpath(binary)
    current = os.path.dirname(real)
    patterns = (
        os.path.join("lib", "python*", "site-packages"),
        os.path.join("lib", "site-packages"),
        os.path.join("Lib", "site-packages"),
    )
    for _ in range(4):
        for relative in patterns:
            matches = sorted(glob.glob(os.path.join(current, relative)))
            if matches:
                return matches[0]
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return None


def read_installed_version(binary):
    """The dep-scan version from the distribution metadata near the binary."""
    packages = site_packages_of(binary)
    if not packages:
        return None
    try:
        entries = sorted(os.listdir(packages))
    except OSError:
        return None
    for entry in entries:
        match = re.match(r"^owasp_depscan-(.+)\.dist-info$", entry)
        if match:
            return match.group(1)
    return None


def has_mcp_module(binary):
    """Whether the mcp extra is importable in the distribution's environment."""
    packages = site_packages_of(binary)
    if not packages:
        return True
    return os.path.isdir(os.path.join(packages, "mcp"))


def plugin_version():
    """The plugin's own version from its manifest."""
    try:
        with open(PLUGIN_MANIFEST, encoding="utf-8") as handle:
            return json.load(handle).get("version")
    except (OSError, ValueError):
        return None


def check(plugin_version_value, env=None, platform=None):
    """The warning for this machine, or None when everything is in place."""
    binary = find_on_path("depscan", env)
    if not binary:
        return {
            "systemMessage": (
                "The dep-scan plugin needs the depscan CLI, which is not on PATH. "
                "Install it with `pip install owasp-depscan`, `pipx install "
                "owasp-depscan` or `uv tool install owasp-depscan`, or use the "
                "ghcr.io/owasp-dep-scan/dep-scan image."
            ),
            "hookSpecificOutput": {
                "hookEventName": "SessionStart",
                "additionalContext": (
                    "The depscan CLI is not on PATH. Before running any dep-scan "
                    "command for a dep-scan skill, tell the user it is missing. "
                    "Do not install it yourself."
                ),
            },
        }
    installed = read_installed_version(binary)
    if installed and plugin_version_value and is_older(installed, plugin_version_value):
        return {
            "systemMessage": (
                "depscan {0} is older than the dep-scan plugin ({1}). Some skill "
                "instructions may use options it lacks. Update with `pip install "
                "--upgrade owasp-depscan` (or the tool that installed it)."
            ).format(installed, plugin_version_value),
            "hookSpecificOutput": {
                "hookEventName": "SessionStart",
                "additionalContext": (
                    "The installed depscan CLI is version {0}, older than the "
                    "plugin's {1}. If a command fails with an unknown option, say "
                    "so instead of working around it."
                ).format(installed, plugin_version_value),
            },
        }
    if not has_mcp_module(binary):
        return {
            "systemMessage": (
                "The dep-scan plugin's MCP server needs the mcp extra, which the "
                "depscan installation here does not have. The server will exit 4 "
                "until the extra is installed with `pip install "
                "'owasp-depscan[mcp]'`."
            ),
            "hookSpecificOutput": {
                "hookEventName": "SessionStart",
                "additionalContext": (
                    "The depscan CLI on PATH lacks the mcp extra its configured "
                    "MCP server needs. Tell the user the MCP tools will not start "
                    "until they install 'owasp-depscan[mcp]'. Do not install it "
                    "yourself."
                ),
            },
        }
    return None


def main():
    result = check(plugin_version())
    if result:
        sys.stdout.write(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
