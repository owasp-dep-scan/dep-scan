"""The plugin's hooks, driven the way hooks.json launches them.

Every hook behaviour has a unit test through the real script entry point,
with the environment faked: a hidden depscan is a PATH, HOME, APPDATA and
USERPROFILE pointed at empty directories, a fake install is a tmp
environment with a bin script and a site-packages tree, and every "silent"
case has a positive control in the same harness that proves the output
path works.
"""

import json
import os
import subprocess
import sys

import pytest

HOOKS_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "agent-plugin", "hooks"
)
CHECK_SCRIPT = os.path.join(HOOKS_DIR, "check_depscan.py")
STALE_SCRIPT = os.path.join(HOOKS_DIR, "stale_lockfile.py")
PLUGIN_VERSION = "7.0.0-dev0"

#: The environment of a machine where depscan cannot be found at all.
HIDDEN_ENV = {
    "PATH": "",
    "HOME": "",
    "APPDATA": "",
    "USERPROFILE": "",
}


def _make_fake_install(tmp_path, version="7.0.0.dev0", with_mcp=False):
    """A fake environment with a depscan console script and its metadata.

    Laid out the way pip, uv and pipx lay it out: <env>/bin/depscan next to
    <env>/lib/pythonX.Y/site-packages/owasp_depscan-<version>.dist-info.
    """
    env_dir = tmp_path / "fake-env"
    bin_dir = env_dir / "bin"
    bin_dir.mkdir(parents=True)
    script = bin_dir / "depscan"
    script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    script.chmod(0o755)
    packages = env_dir / "lib" / "python3.14" / "site-packages"
    packages.mkdir(parents=True)
    dist_info = packages / f"owasp_depscan-{version}.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text("Name: owasp-depscan\n", encoding="utf-8")
    if with_mcp:
        (packages / "mcp").mkdir()
    return env_dir


def _env_with(fake_env, **overrides):
    env = dict(os.environ)
    env["PATH"] = str(fake_env / "bin")
    for key in ("APPDATA", "USERPROFILE"):
        env[key] = ""
    env.update(overrides)
    return env


def _run_hook(script, payload=None, env=None):
    """Run a hook the way hooks.json does: exec form, JSON on stdin."""
    proc = subprocess.run(
        [sys.executable, script],
        input=json.dumps(payload) if payload is not None else "",
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    return proc


def _parse_hook_output(proc):
    if not proc.stdout.strip():
        return None
    return json.loads(proc.stdout)


def test_missing_depscan_warns_and_does_not_install(tmp_path):
    """A machine without depscan gets one warning naming the installs."""
    env = dict(HIDDEN_ENV)
    env.update({"SYSTEMROOT": os.environ.get("SYSTEMROOT", "")})
    result = _parse_hook_output(_run_hook(CHECK_SCRIPT, env=env))
    assert result is not None
    assert "not on PATH" in result["systemMessage"]
    assert "pip install owasp-depscan" in result["systemMessage"]
    context = result["hookSpecificOutput"]["additionalContext"]
    assert "Do not install it yourself" in context
    assert result["hookSpecificOutput"]["hookEventName"] == "SessionStart"


def test_present_depscan_is_silent(tmp_path):
    """A current install with the mcp extra produces no output at all."""
    fake_env = _make_fake_install(tmp_path, version="9.9.9.dev9", with_mcp=True)
    result = _parse_hook_output(_run_hook(CHECK_SCRIPT, env=_env_with(fake_env)))
    assert result is None


def test_older_depscan_warns(tmp_path):
    """An install below the plugin version is named with both versions."""
    fake_env = _make_fake_install(tmp_path, version="6.9.9")
    result = _parse_hook_output(_run_hook(CHECK_SCRIPT, env=_env_with(fake_env)))
    assert result is not None
    assert "6.9.9 is older than the dep-scan plugin" in result["systemMessage"]
    assert PLUGIN_VERSION in result["systemMessage"]


def test_equal_version_is_silent(tmp_path):
    """The dev pre-release of the same release is not older than the plugin."""
    fake_env = _make_fake_install(tmp_path, version="7.0.0.dev0", with_mcp=True)
    result = _parse_hook_output(_run_hook(CHECK_SCRIPT, env=_env_with(fake_env)))
    assert result is None


def test_missing_mcp_module_warns(tmp_path):
    """A current install without the mcp extra warns about the server's exit."""
    fake_env = _make_fake_install(tmp_path, version="9.9.9", with_mcp=False)
    result = _parse_hook_output(_run_hook(CHECK_SCRIPT, env=_env_with(fake_env)))
    assert result is not None
    assert "mcp extra" in result["systemMessage"]
    assert "exit 4" in result["systemMessage"]


def test_version_parser_reads_both_forms():
    """The semver manifest form and the PEP 440 installed form compare."""
    sys.path.insert(0, HOOKS_DIR)
    try:
        import check_depscan

        assert check_depscan.parse_version("7.0.0-dev0") == check_depscan.parse_version(
            "7.0.0.dev0"
        )
        assert check_depscan.is_older("6.9.9", "7.0.0-dev0")
        assert not check_depscan.is_older("7.0.0", "7.0.0-dev0")
        assert check_depscan.is_older("7.0.0.dev0", "7.0.0")
        assert not check_depscan.is_older("8.0.0.dev1", "7.0.0-dev0")
        assert not check_depscan.is_older("garbage", "7.0.0-dev0")
    finally:
        sys.path.pop(0)
        sys.modules.pop("check_depscan", None)


def test_reminder_off_by_default(tmp_path):
    """Without the opt-in setting a lockfile edit produces no output.

    Positive control: the same harness with the setting on warns, which
    proves the silence comes from the setting and not from the harness.
    """
    payload = {
        "session_id": "sess-test",
        "tool_name": "Edit",
        "tool_input": {"file_path": "/home/dev/work/app/uv.lock"},
    }
    env = dict(os.environ)
    env.pop("CLAUDE_PLUGIN_OPTION_LOCKFILE_REMINDER", None)
    env["CLAUDE_PLUGIN_DATA"] = str(tmp_path)
    assert _parse_hook_output(_run_hook(STALE_SCRIPT, payload, env=env)) is None
    env["CLAUDE_PLUGIN_OPTION_LOCKFILE_REMINDER"] = "true"
    result = _parse_hook_output(_run_hook(STALE_SCRIPT, payload, env=env))
    assert result is not None
    assert "uv.lock changed" in result["hookSpecificOutput"]["additionalContext"]


def test_reminder_warns_once_per_file(tmp_path):
    """The reminder fires once per file per session, then stays silent."""
    payload = {
        "session_id": "sess-once",
        "tool_name": "Write",
        "tool_input": {"file_path": "/home/dev/work/app/package-lock.json"},
    }
    env = dict(os.environ)
    env["CLAUDE_PLUGIN_OPTION_LOCKFILE_REMINDER"] = "true"
    env["CLAUDE_PLUGIN_DATA"] = str(tmp_path)
    first = _parse_hook_output(_run_hook(STALE_SCRIPT, payload, env=env))
    assert first is not None
    second = _parse_hook_output(_run_hook(STALE_SCRIPT, payload, env=env))
    assert second is None


def test_reminder_ignores_unrelated_files(tmp_path):
    """An edit to a non-manifest file produces no output.

    Positive control: package.json in the same harness warns.
    """
    env = dict(os.environ)
    env["CLAUDE_PLUGIN_OPTION_LOCKFILE_REMINDER"] = "true"
    env["CLAUDE_PLUGIN_DATA"] = str(tmp_path)
    readme_payload = {
        "session_id": "sess-unrelated",
        "tool_name": "Edit",
        "tool_input": {"file_path": "/home/dev/work/app/README.md"},
    }
    assert _parse_hook_output(_run_hook(STALE_SCRIPT, readme_payload, env=env)) is None
    manifest_payload = {
        "session_id": "sess-unrelated",
        "tool_name": "Edit",
        "tool_input": {"file_path": "/home/dev/work/app/package.json"},
    }
    result = _parse_hook_output(_run_hook(STALE_SCRIPT, manifest_payload, env=env))
    assert result is not None


@pytest.mark.parametrize(
    "name",
    [
        "requirements.txt",
        "requirements-prod.txt",
        "src/App.csproj",
        "poetry.lock",
        "go.sum",
        "Pipfile",
    ],
)
def test_dependency_file_predicate_covers_the_ecosystems(tmp_path, name):
    """The manifest patterns cover the ecosystems dep-scan reads."""
    sys.path.insert(0, HOOKS_DIR)
    try:
        import stale_lockfile

        assert stale_lockfile.is_dependency_file(name)
        assert not stale_lockfile.is_dependency_file("notes.txt")
    finally:
        sys.path.pop(0)
        sys.modules.pop("stale_lockfile", None)


def test_invalid_stdin_is_silent(tmp_path):
    """A payload the hook cannot parse exits 0 with no output."""
    proc = subprocess.run(
        [sys.executable, STALE_SCRIPT],
        input="not json at all",
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0
    assert proc.stdout.strip() == ""
