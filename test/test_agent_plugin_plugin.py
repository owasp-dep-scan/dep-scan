"""The plugin pieces hold together on the real repository.

The per-piece tests build temporary trees; this module runs the generator's
drift check and the structural checker over the checkout as committed, so
the pytest suite itself fails when a skill edit leaves a manifest stale or
breaks a check. Unlike the temporary-tree tests, this one passes only when
the plugin is complete, which is what makes it the merge-time guard.
"""

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _run_module(module):
    proc = subprocess.run(
        [sys.executable, "-m", module],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        timeout=120,
    )
    return proc


def test_generated_manifests_are_not_stale():
    """The committed manifests equal what the generator writes."""
    proc = _run_module("contrib.gen_agent_manifests")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "up to date" in proc.stdout


def test_structural_checks_pass_on_the_repository():
    """The checker finds no problems in the plugin as committed."""
    proc = _run_module("contrib.check_agent_plugin")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "checks passed" in proc.stdout


def test_the_plugin_carries_every_published_skill():
    """The skill set the docs and evals describe is what ships.

    A skill renamed or removed without its eval cases and docs following
    leaves the plugin promising something it does not carry.
    """
    skills_dir = REPO_ROOT / "agent-plugin" / "skills"
    shipped = sorted(entry.name for entry in skills_dir.iterdir() if entry.is_dir())
    assert shipped == [
        "depscan-attack-surface",
        "depscan-binary",
        "depscan-change-risk",
        "depscan-container-image",
        "depscan-coverage-loop",
        "depscan-crypto",
        "depscan-memory-safety",
        "depscan-mobile-app",
        "depscan-reachability-proof",
        "depscan-scan",
        "depscan-supply-chain",
        "depscan-triage",
        "depscan-vdb",
        "depscan-vex-compliance",
    ]
    evals_dir = REPO_ROOT / "agent-plugin" / "evals"
    eval_names = {entry.name for entry in evals_dir.iterdir() if entry.is_dir()}
    for skill in shipped:
        skill_dir = skills_dir / skill
        frontmatter = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
        if "disable-model-invocation: true" in frontmatter:
            assert f"not-invoked-{skill}" in eval_names, skill
        else:
            assert f"select-{skill}" in eval_names, skill
