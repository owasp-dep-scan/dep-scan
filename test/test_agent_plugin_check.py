"""The structural checks of contrib/check_agent_plugin.py, one violation at a time.

Every check fires on a repository copy built to violate exactly that check,
so a checker change that stops checking is visible, and the exit codes and
the --json mode behave like cdxgen's checker.
"""

import json
import shutil
import sys

import pytest

from contrib import check_agent_plugin as check

#: Everything the checker reads, copied into each temporary repository copy.
TREE_MEMBERS = (
    "contrib/schemas",
    "contrib/gen_agent_manifests.py",
    "contrib/agent_manifests_template.json",
    "pyproject.toml",
    ".claude-plugin",
    ".agents",
    ".cursor-plugin",
    "agent-plugin",
)


def _make_tree(tmp_path):
    for member in TREE_MEMBERS:
        source = check.REPO_ROOT / member
        target = tmp_path / member
        if source.is_dir():
            shutil.copytree(source, target)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
    return tmp_path


def _problems(tree):
    return check.collect_problems(tree)


def _read(tree, relative, as_text=False):
    """A tree file's text, or its parsed JSON document by default."""
    path = tree / relative
    if as_text:
        return path.read_text(encoding="utf-8")
    return json.loads(path.read_text(encoding="utf-8"))


def _write(tree, relative, value):
    path = tree / relative
    path.write_text(value, encoding="utf-8")


def _write_json(tree, relative, document):
    _write(tree, relative, json.dumps(document, indent=2, ensure_ascii=False) + "\n")


def _skill_tree(tmp_path, name="depscan-scan"):
    """A tree whose plugin carries one clean skill, for the per-check tests."""
    tree = _make_tree(tmp_path)
    skill_dir = tree / "agent-plugin" / "skills" / name
    skill_dir.mkdir(parents=True)
    _write(
        tree,
        f"agent-plugin/skills/{name}/SKILL.md",
        "---\n"
        f"name: {name}\n"
        "description: Scan a project with dep-scan and report what to fix first.\n"
        "---\n"
        "# Scan\n\n"
        "Read [safety](../../reference/safety.md) first.\n",
    )
    reference = tree / "agent-plugin" / "reference"
    reference.mkdir()
    _write(tree, "agent-plugin/reference/safety.md", "# Safety\n")
    return tree


def test_clean_tree_has_no_problems(tmp_path):
    """A copy with one clean skill and no introduced violation passes."""
    assert _problems(_skill_tree(tmp_path)) == []


def test_bad_skill_name(tmp_path):
    """A frontmatter name that differs from its directory is named."""
    tree = _skill_tree(tmp_path, "depscan-scan")
    path = tree / "agent-plugin" / "skills" / "depscan-scan" / "SKILL.md"
    _write(tree, "agent-plugin/skills/depscan-scan/SKILL.md", path.read_text(encoding="utf-8").replace("name: depscan-scan", "name: depscan-scan-2"))
    problems = _problems(tree)
    assert any("does not match its directory" in p["problem"] for p in problems)
    assert all(not p["file"].startswith(str(tree)) for p in problems)


def test_unskillish_directory_name(tmp_path):
    """A directory outside the Agent Skills name rule is named."""
    tree = _skill_tree(tmp_path, "depscan-scan")
    source = tree / "agent-plugin" / "skills" / "depscan-scan"
    target = tree / "agent-plugin" / "skills" / "Depscan Scan"
    shutil.move(str(source), str(target))
    problems = _problems(tree)
    assert any("lowercase letters, digits and single hyphens" in p["problem"] for p in problems)


def test_over_long_description(tmp_path):
    """A description over the 1024-character limit is named with its size."""
    tree = _skill_tree(tmp_path)
    path = tree / "agent-plugin" / "skills" / "depscan-scan" / "SKILL.md"
    long_description = "x" * 1100
    _write(
        tree,
        "agent-plugin/skills/depscan-scan/SKILL.md",
        path.read_text(encoding="utf-8").replace(
            "description: Scan a project with dep-scan and report what to fix first.",
            f"description: {long_description}",
        ),
    )
    problems = _problems(tree)
    assert any("over the 1024 limit" in p["problem"] for p in problems)


def test_duplicate_frontmatter_key(tmp_path):
    """A frontmatter key defined twice is a parse error, not a last-one-wins."""
    tree = _skill_tree(tmp_path)
    _write(
        tree,
        "agent-plugin/skills/depscan-scan/SKILL.md",
        "---\n"
        "name: depscan-scan\n"
        "name: depscan-scan-2\n"
        "description: Duplicate names must be reported.\n"
        "---\n",
    )
    problems = _problems(tree)
    assert any("invalid YAML frontmatter" in p["problem"] and "duplicate" in p["problem"] for p in problems)


def test_broken_relative_link(tmp_path):
    """A relative Markdown link that resolves to nothing is named."""
    tree = _skill_tree(tmp_path)
    path = tree / "agent-plugin" / "skills" / "depscan-scan" / "SKILL.md"
    _write(
        tree,
        "agent-plugin/skills/depscan-scan/SKILL.md",
        path.read_text(encoding="utf-8").replace(
            "(../../reference/safety.md)", "(../../reference/safety-guide.md)"
        ),
    )
    problems = _problems(tree)
    assert any("link target not found: ../../reference/safety-guide.md" in p["problem"] for p in problems)


def test_version_mismatch(tmp_path):
    """A manifest version that differs from pyproject's is named on both sides."""
    tree = _make_tree(tmp_path)
    manifest = tree / "agent-plugin" / ".claude-plugin" / "plugin.json"
    document = _read(tree, "agent-plugin/.claude-plugin/plugin.json")
    document["version"] = "9.9.9"
    _write_json(tree, "agent-plugin/.claude-plugin/plugin.json", document)
    problems = _problems(tree)
    assert any("release versions differ" in p["problem"] for p in problems)
    mismatch = next(p for p in problems if "release versions differ" in p["problem"])
    assert "pyproject.toml=7.0.0-dev0" in mismatch["problem"]
    assert "9.9.9" in mismatch["problem"]


def test_stale_manifest(tmp_path):
    """A manifest edited away from the generated output is named as stale."""
    tree = _make_tree(tmp_path)
    manifest = tree / "agent-plugin" / "gemini-extension.json"
    document = _read(tree, "agent-plugin/gemini-extension.json")
    document["description"] = "manually edited"
    _write_json(tree, "agent-plugin/gemini-extension.json", document)
    problems = _problems(tree)
    assert any(
        p["file"] == "agent-plugin/gemini-extension.json" and "differs from the generated output" in p["problem"]
        for p in problems
    )


def test_agent_plugins_schema_violation(tmp_path):
    """An unknown property in the Agent Plugins manifest fails the vendored schema."""
    tree = _make_tree(tmp_path)
    document = _read(tree, "agent-plugin/plugin.json")
    document["unexpected"] = True
    _write_json(tree, "agent-plugin/plugin.json", document)
    problems = _problems(tree)
    assert any("schema:" in p["problem"] for p in problems)


def test_hook_script_missing(tmp_path):
    """A hooks.json entry pointing at a file that does not exist is named."""
    tree = _make_tree(tmp_path)
    hooks_dir = tree / "agent-plugin" / "hooks"
    hooks_dir.mkdir()
    _write_json(
        tree,
        "agent-plugin/hooks/hooks.json",
        {
            "hooks": {
                "SessionStart": [
                    {
                        "matcher": "startup",
                        "hooks": [
                            {
                                "type": "command",
                                "command": "python3",
                                "args": ["${CLAUDE_PLUGIN_ROOT}/hooks/missing.py"],
                                "timeout": 10,
                            }
                        ],
                    }
                ]
            }
        },
    )
    problems = _problems(tree)
    assert any("hook script not found: hooks/missing.py" in p["problem"] for p in problems)


def test_agent_needs_name_and_description(tmp_path):
    """An agent file without a name or description is named."""
    tree = _make_tree(tmp_path)
    agents = tree / "agent-plugin" / "agents"
    agents.mkdir(exist_ok=True)
    _write(tree, "agent-plugin/agents/anonymous.md", "---\nname: anonymous\n---\n")
    problems = _problems(tree)
    assert any("agent needs a name and a description" in p["problem"] for p in problems)


def test_mcp_configs_must_stay_identical(tmp_path):
    """An edit to one of the two MCP configurations is named."""
    tree = _make_tree(tmp_path)
    document = _read(tree, "agent-plugin/.mcp.json")
    document["mcpServers"]["depscan"]["args"] = ["mcp", "--allow-scans"]
    _write_json(tree, "agent-plugin/.mcp.json", document)
    problems = _problems(tree)
    assert any("must be identical" in p["problem"] for p in problems)
    assert any("allow-scans" in p["problem"] for p in problems)


def test_mcp_config_may_not_grant_scans(tmp_path):
    """--allow-scans in both files is its own problem, not only a mismatch."""
    tree = _make_tree(tmp_path)
    for name in (".mcp.json", "mcp.json"):
        document = _read(tree, f"agent-plugin/{name}")
        document["mcpServers"]["depscan"]["args"] = ["mcp", "--allow-scans"]
        _write_json(tree, f"agent-plugin/{name}", document)
    problems = _problems(tree)
    assert any("allow-scans" in p["problem"] for p in problems)


def test_codex_marketplace_needs_policy_and_category(tmp_path):
    """A Codex marketplace entry without policy or category is named."""
    tree = _make_tree(tmp_path)
    document = _read(tree, ".agents/plugins/marketplace.json")
    del document["plugins"][0]["policy"]
    _write_json(tree, ".agents/plugins/marketplace.json", document)
    problems = _problems(tree)
    assert any("missing policy.installation" in p["problem"] for p in problems)


def test_exit_codes_and_json_mode(tmp_path, capsys, monkeypatch):
    """Exit 1 with problems, 0 without, and --json prints the problem list."""
    tree = _skill_tree(tmp_path)
    path = tree / "agent-plugin" / "skills" / "depscan-scan" / "SKILL.md"
    _write(
        tree,
        "agent-plugin/skills/depscan-scan/SKILL.md",
        path.read_text(encoding="utf-8").replace(
            "(../../reference/safety.md)", "(../../reference/missing.md)"
        ),
    )
    original_root = check.REPO_ROOT
    monkeypatch.setattr(sys, "argv", ["check_agent_plugin.py", "--json"])
    monkeypatch.setattr(check, "REPO_ROOT", tree)
    try:
        assert check.main() == 1
        report = json.loads(capsys.readouterr().out)
        assert report["total"] == len(report["problems"]) >= 1
        assert report["problems"][0]["file"].startswith("agent-plugin")
    finally:
        check.REPO_ROOT = original_root


def test_exit_two_when_the_marketplace_is_missing(tmp_path, monkeypatch):
    """An unreadable marketplace is an internal error, not a problem list."""
    tree = _make_tree(tmp_path)
    (tree / ".claude-plugin" / "marketplace.json").unlink()
    original_root = check.REPO_ROOT
    monkeypatch.setattr(sys, "argv", ["check_agent_plugin.py"])
    monkeypatch.setattr(check, "REPO_ROOT", tree)
    try:
        assert check.main() == 2
    finally:
        check.REPO_ROOT = original_root


def test_real_repository_checker_is_wireable(capsys, monkeypatch):
    """The checker runs over the real repository and reports its state.

    While the plugin's pieces are still landing the checker names what is
    missing; the whole-repository exit-0 assertion lives in
    test_agent_plugin_plugin.py, which runs once the plugin is complete.
    """
    monkeypatch.setattr(sys, "argv", ["check_agent_plugin.py", "--json"])
    assert check.main() in (0, 1)
    report = json.loads(capsys.readouterr().out)
    assert report["total"] == len(report["problems"])


@pytest.mark.parametrize(
    "problem_maker,expected",
    [
        (lambda t: _write_json(t, "agent-plugin/plugin.json", {"$schema": "broken"}), "schema:"),
    ],
    ids=["schema-of-broken-json-shape"],
)
def test_parametrised_violations(tmp_path, problem_maker, expected):
    """A violation introduced into a copied tree is reported by name."""
    tree = _make_tree(tmp_path)
    problem_maker(tree)
    problems = _problems(tree)
    assert any(expected in p["problem"] for p in problems)
