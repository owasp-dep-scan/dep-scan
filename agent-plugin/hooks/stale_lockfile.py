#!/usr/bin/env python3
"""PostToolUse hook for Write and Edit: when Claude changes a lockfile or a
dependency manifest, remind it that any dep-scan scan from earlier in the
session no longer matches the project. Off unless the user turns on the
plugin's "lockfile_reminder" option, which Claude Code passes to hook
processes as CLAUDE_PLUGIN_OPTION_LOCKFILE_REMINDER. It reminds once per
file per session, using a small marker file in the plugin's data
directory. It never installs, never scans and never prints file contents.
"""

import json
import os
import re
import sys

EXACT = frozenset(
    (
        "Cargo.lock",
        "Cargo.toml",
        "Gemfile",
        "Gemfile.lock",
        "Package.resolved",
        "Package.swift",
        "Pipfile",
        "Pipfile.lock",
        "build.gradle",
        "build.gradle.kts",
        "bun.lock",
        "bun.lockb",
        "composer.json",
        "composer.lock",
        "conan.lock",
        "conanfile.txt",
        "go.mod",
        "go.sum",
        "gradle.lockfile",
        "mix.lock",
        "package-lock.json",
        "package.json",
        "packages.lock.json",
        "pdm.lock",
        "pixi.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "pom.xml",
        "pubspec.lock",
        "pubspec.yaml",
        "pyproject.toml",
        "uv.lock",
        "vcpkg.json",
        "yarn.lock",
    )
)
PATTERNS = (re.compile(r"^requirements.*\.txt$"), re.compile(r"\.(?:cs|fs|vb)proj$"))


def is_dependency_file(file_path):
    """Whether the edited file is a lockfile or a dependency manifest."""
    base = os.path.basename(file_path or "")
    return base in EXACT or any(pattern.search(base) for pattern in PATTERNS)


def enabled(env=None):
    env = env if env is not None else os.environ
    return str(env.get("CLAUDE_PLUGIN_OPTION_LOCKFILE_REMINDER", "")).lower() in (
        "true",
        "1",
    )


def first_time(data_dir, session_id, file_path):
    """True the first time a file is seen in a session."""
    if not data_dir or not session_id:
        return True
    directory = os.path.join(data_dir, "stale-lockfile")
    safe = re.sub(r"[^A-Za-z0-9_-]", "_", session_id)
    marker = os.path.join(directory, safe + ".json")
    seen = []
    try:
        with open(marker, encoding="utf-8") as handle:
            seen = json.load(handle)
    except (OSError, ValueError):
        seen = []
    if file_path in seen:
        return False
    try:
        os.makedirs(directory, exist_ok=True)
        with open(marker, "w", encoding="utf-8") as handle:
            json.dump(seen + [file_path], handle)
    except OSError:
        pass
    return True


def remind(payload, env=None):
    """The reminder for this edit, or None when there is nothing to say."""
    env = env if env is not None else os.environ
    file_path = (payload or {}).get("tool_input", {}).get("file_path")
    if not enabled(env) or not is_dependency_file(file_path):
        return None
    if not first_time(env.get("CLAUDE_PLUGIN_DATA"), payload.get("session_id"), file_path):
        return None
    return {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": (
                "{0} changed, so any dep-scan scan from earlier in this session "
                "no longer matches the project. Mention this to the user when you "
                "finish, and offer to re-run the scan."
            ).format(os.path.basename(file_path)),
        }
    }


def main():
    try:
        payload = json.loads(sys.stdin.read())
    except ValueError:
        return 0
    result = remind(payload if isinstance(payload, dict) else {})
    if result:
        sys.stdout.write(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
