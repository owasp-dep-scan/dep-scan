"""The generated agent manifests match the template and the pyproject version.

The six client manifests and the two MCP configurations are written by
``contrib/gen_agent_manifests.py``; this module keeps the committed files
equal to what the generator produces, keeps generation byte-stable, and
checks the PEP 440 to semver conversion the manifests carry.
"""

import json
import sys

import pytest

from contrib import gen_agent_manifests as gen


def test_pep440_to_semver_mapping():
    """The conversion the manifests carry, stated example by example."""
    assert gen.pep440_to_semver("7.0.0") == "7.0.0"
    assert gen.pep440_to_semver("7.0.0.dev0") == "7.0.0-dev0"
    assert gen.pep440_to_semver("7.1.0.dev5") == "7.1.0-dev5"
    assert gen.pep440_to_semver("7.0.0rc1") == "7.0.0-rc1"
    assert gen.pep440_to_semver("7.0.0c2") == "7.0.0-c2"
    assert gen.pep440_to_semver("7.0.0.post1") == "7.0.0"
    assert gen.pep440_to_semver("not-a-version") == "not-a-version"


def test_committed_manifests_match_the_generator():
    """The repository's committed manifests are what the generator writes."""
    assert gen.stale_manifests() == []


def test_mcp_configurations_are_identical_and_conservative():
    """The Claude Code and Codex MCP files carry the same conservative object."""
    claude = json.loads(
        (gen.REPO_ROOT / "agent-plugin" / ".mcp.json").read_text(encoding="utf-8")
    )
    codex = json.loads(
        (gen.REPO_ROOT / "agent-plugin" / "mcp.json").read_text(encoding="utf-8")
    )
    assert claude == codex == gen.MCP_CONFIG
    assert "allow-scans" not in json.dumps(claude)
    assert claude["mcpServers"]["depscan"]["args"] == ["mcp"]


def _make_tree(tmp_path):
    """A repository copy with everything the generator reads and writes."""
    for item in gen.TARGETS:
        source = gen.REPO_ROOT / item["file"]
        target = tmp_path / item["file"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
    for name in ("pyproject.toml", "contrib/agent_manifests_template.json"):
        source = gen.REPO_ROOT / name
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
    return tmp_path


def test_generation_is_byte_stable(tmp_path, capsys):
    """A second run over the same tree writes nothing."""
    tree = _make_tree(tmp_path)
    original_root = gen.REPO_ROOT
    gen.REPO_ROOT = tree
    try:
        gen.main()
        first = {item["file"]: (tree / item["file"]).read_bytes() for item in gen.TARGETS}
        gen.main()
        capsys.readouterr()
        second = {item["file"]: (tree / item["file"]).read_bytes() for item in gen.TARGETS}
        assert first == second
    finally:
        gen.REPO_ROOT = original_root


def test_check_names_the_drifted_file(tmp_path, capsys, monkeypatch):
    """--check exits 1 and names the file a later edit changed."""
    tree = _make_tree(tmp_path)
    manifest = tree / "agent-plugin" / "gemini-extension.json"
    document = json.loads(manifest.read_text(encoding="utf-8"))
    document["version"] = "0.0.0"
    manifest.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8", newline="\n")
    original_root = gen.REPO_ROOT
    gen.REPO_ROOT = tree
    monkeypatch.setattr(sys, "argv", ["gen_agent_manifests.py", "--check"])
    try:
        assert gen.main() == 1
    finally:
        gen.REPO_ROOT = original_root
    captured = capsys.readouterr()
    assert "agent-plugin/gemini-extension.json" in captured.err


def test_check_exits_two_when_the_version_is_missing(tmp_path, capsys, monkeypatch):
    """A pyproject.toml without a version is an internal error, not drift."""
    tree = _make_tree(tmp_path)
    pyproject = tree / "pyproject.toml"
    pyproject.write_text(
        '[project]\nname = "owasp-depscan"\ndependencies = []\n', encoding="utf-8"
    )
    original_root = gen.REPO_ROOT
    gen.REPO_ROOT = tree
    monkeypatch.setattr(sys, "argv", ["gen_agent_manifests.py", "--check"])
    try:
        assert gen.main() == 2
    finally:
        gen.REPO_ROOT = original_root


@pytest.mark.parametrize(
    "manifest_file,field",
    [
        ("agent-plugin/.claude-plugin/plugin.json", "version"),
        ("agent-plugin/plugin.json", "description"),
        ("agent-plugin/gemini-extension.json", "name"),
    ],
)
def test_a_changed_shared_field_is_drift(tmp_path, manifest_file, field):
    """Editing a field the generator owns makes the file stale by name."""
    tree = _make_tree(tmp_path)
    original_root = gen.REPO_ROOT
    gen.REPO_ROOT = tree
    try:
        assert gen.stale_manifests() == []
        manifest = tree / manifest_file
        document = json.loads(manifest.read_text(encoding="utf-8"))
        document[field] = "drifted-value"
        manifest.write_text(
            json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        assert gen.stale_manifests() == [manifest_file]
    finally:
        gen.REPO_ROOT = original_root
