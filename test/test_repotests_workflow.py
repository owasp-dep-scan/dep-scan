"""Structural checks for the repository-test workflow.

The repo tests live in one workflow file whose job names, matrix entries and
check names branch protection depends on, and whose generated-input cache
keys decide whether a pull request regenerates the cdxgen and atom outputs.
These tests pin the structure those properties need; they read the workflow
file and assert nothing about how long any step runs.
"""

import re
from pathlib import Path

import yaml

WORKFLOW_FILE = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "repotests.yml"

#: The jobs branch protection requires, with the matrix entries each must keep.
EXPECTED_JOBS = {
    "os-repo-tests": {
        "os": ["ubuntu-24.04", "ubuntu-24.04-arm", "windows-latest"],
        "python-version": ["3.14"],
    },
    "os-semantics-tests": {
        "python-version": ["3.14"],
    },
}

#: Step names that existed before the generated-input caches were introduced.
#: Branch protection and log readers refer to some of them, so none may be
#: renamed or removed. Steps may be added.
EXPECTED_STEP_NAMES = {
    "os-repo-tests": [
        "Trim CI agent",
        "Install depscan",
        "Get repo test data",
        "repotests java-sec-code",
        "Upload java-sec-code reports",
        "Remove java-sec-code reports",
        "repotests dotnet-podcasts",
        "repotests vulnerable-aws-koa-app",
        "repotests signal-android",
        "repotests kafka-4.0.0",
        "repotests spring-petclinic",
        "repotests cdxgen",
        "repotests signal-desktop",
        "repotests forgejo",
        "repotests rustpad",
        "repotests django-defectdojo",
        "repotests depscan",
        "repotests phpmyadmin",
        "repotests openssl-3.5.0",
        "repotests open5gs-2.7.5",
        "repotests curl-8.13.0",
    ],
    "os-semantics-tests": [
        "Install uv",
        "Install depscan",
        "semantic analysis self",
        "Get repo test data",
        "semantic analysis over pinned data",
        "semantic analysis dejacode",
    ],
}

#: The external projects the workflow checks out, with the repository each
#: step must pin. A pinned full commit keeps the cache key stable; a branch
#: ref would move the key without anyone changing it.
PINNED_CHECKOUTS = {
    "hoolicorp/java-sec-code",
    "HooliCorp/vulnerable-aws-koa-app",
    "microsoft/dotnet-podcasts",
    "aboutcode-org/dejacode",
}

#: The generated-input cache variants, one entry each.
CACHE_VARIANTS = {
    "java-sec-code",
    "java-sec-code1",
    "java-sec-code2",
    "dotnet-podcasts",
    "dotnet-podcasts1",
    "dotnet-podcasts2",
    "vulnerable-aws-koa-app",
    "dejacode",
    "self",
}

#: What the miss-path copy step may write into a cache directory: what
#: cdxgen and atom wrote into the reports directory, never dep-scan's own
#: outputs.
ALLOWED_COPY_PATTERNS = {
    "*.cdx.json",
    "*slices*.json",
    "*openapi*.json",
    "*.introspection.json",
    "generation.json",
}

CACHE_ACTION_SHA = "55cc8345863c7cc4c66a329aec7e433d2d1c52a9"
SKIP_RESTORE_CONDITION = "github.event_name != 'schedule' && inputs.regenerate != true"


def load_workflow():
    with WORKFLOW_FILE.open(encoding="utf-8") as fp:
        return yaml.safe_load(fp)


def steps_of(job):
    return job.get("steps") or []


def named_steps(job):
    return {step["name"]: step for step in steps_of(job) if step.get("name")}


def test_workflow_file_exists():
    assert WORKFLOW_FILE.is_file(), WORKFLOW_FILE


def test_jobs_and_matrix_entries_are_unchanged():
    workflow = load_workflow()
    jobs = workflow.get("jobs") or {}
    assert set(jobs) == set(EXPECTED_JOBS), sorted(jobs)
    for job_name, expected in EXPECTED_JOBS.items():
        matrix = jobs[job_name]["strategy"]["matrix"]
        for dimension, values in expected.items():
            assert matrix[dimension] == values, (job_name, dimension, matrix[dimension])


def test_existing_step_names_survive():
    workflow = load_workflow()
    for job_name, names in EXPECTED_STEP_NAMES.items():
        present = set(named_steps(workflow["jobs"][job_name]))
        missing = [name for name in names if name not in present]
        assert not missing, (job_name, missing)


def test_weekly_schedule_and_regenerate_input_exist():
    triggers = load_workflow()[True] if True in load_workflow() else load_workflow().get("on")
    assert triggers, "the workflow declares no triggers"
    schedule = triggers.get("schedule") or []
    assert any(entry.get("cron") == "0 5 * * 1" for entry in schedule), schedule
    dispatch = triggers.get("workflow_dispatch") or {}
    regenerate = (dispatch.get("inputs") or {}).get("regenerate")
    assert regenerate, "workflow_dispatch declares no regenerate input"
    assert regenerate.get("type") == "boolean"
    assert regenerate.get("default") is False or regenerate.get("default") == "false"
    # The workflow must not gain a push trigger: the 2.5-hour matrix would
    # then run on every merge.
    assert "push" not in triggers


def test_every_restore_step_skips_on_schedule_and_regenerate():
    workflow = load_workflow()
    checked = 0
    for job_name, job in workflow["jobs"].items():
        for step in steps_of(job):
            if str(step.get("uses", "")).startswith("actions/cache/restore"):
                condition = step.get("if") or ""
                assert "github.event_name != 'schedule'" in condition, (job_name, step.get("name"))
                assert "inputs.regenerate != true" in condition, (job_name, step.get("name"))
                checked += 1
    assert checked >= 9, f"expected the nine restore steps, found {checked}"


def test_every_cache_key_names_everything_that_changes_the_inputs():
    workflow = load_workflow()
    seen_variants = set()
    checked = 0
    for job_name, job in workflow["jobs"].items():
        for step in steps_of(job):
            uses = str(step.get("uses", ""))
            key = (step.get("with") or {}).get("key") or ""
            if not (uses.startswith("actions/cache/restore") or uses.startswith("actions/cache/save")):
                continue
            # Only the generated-input entries; the repotests-data action
            # keeps its own repotests-data- keys.
            if not key.startswith("repotests-gen-"):
                continue
            checked += 1
            variant = key.split("-${{")[0]
            variant = variant[len("repotests-gen-"):].split("-${{")[0]
            seen_variants.add(variant)
            # The runner OS and architecture.
            assert "${{ runner.os }}" in key, (job_name, step.get("name"))
            assert "${{ runner.arch }}" in key, (job_name, step.get("name"))
            # The tool versions, resolved before the restore.
            assert "-cdxgen${{ steps.cache-versions.outputs.cdxgen-version }}-atom" in key, (
                job_name,
                step.get("name"),
            )
            assert "${{ steps.cache-versions.outputs.atom-version }}-" in key, (
                job_name,
                step.get("name"),
            )
            # The dep-scan files that build the cdxgen command line.
            assert "${{ steps.cache-versions.outputs.command-line-files }}" in key, (
                job_name,
                step.get("name"),
            )
            # The scanned project's commit: a pinned 40-hex SHA, or the self
            # checkout's dependency-manifest hash.
            project_part = key.split("-atom${{")[1]
            project_part = project_part.split("-", 1)[1]
            has_pinned_sha = re.search(r"([0-9a-f]{40})-\$\{\{", project_part)
            has_self_hash = "${{ steps.cache-versions.outputs.self-project-files }}" in project_part
            assert has_pinned_sha or has_self_hash, (job_name, step.get("name"), project_part)
    assert checked >= 18, f"expected nine restore and nine save steps, found {checked}"
    assert seen_variants == CACHE_VARIANTS, sorted(seen_variants)


def test_self_cache_keys_on_the_dependency_manifests():
    workflow = load_workflow()
    versions_step = named_steps(workflow["jobs"]["os-semantics-tests"])[
        "Resolve generated-input cache versions"
    ]
    self_hash = versions_step["env"]["SELF_PROJECT_FILES_HASH"]
    assert "hashFiles('uv.lock', '**/pyproject.toml')" in self_hash, self_hash
    # No per-Python-file hash: an ordinary code change must reuse the slices.
    assert "hashFiles('**/*.py')" not in self_hash


def test_command_line_hash_covers_the_cdxgen_invocation_files():
    for job_name in ("os-repo-tests", "os-semantics-tests"):
        job = load_workflow()["jobs"][job_name]
        env = named_steps(job)["Resolve generated-input cache versions"]["env"]
        command = env["COMMAND_LINE_FILES_HASH"]
        for required in (
            "packages/xbom-lib/src/xbom_lib/cdxgen.py",
            "packages/xbom-lib/src/xbom_lib/process.py",
            "depscan/lib/bom.py",
            "depscan/lib/pipeline.py",
            "depscan/lib/config.py",
            "depscan/cli_options.py",
            "depscan/commands/scan.py",
        ):
            assert required in command, (job_name, required)


def test_hit_path_rescans_as_a_bom_directory_with_the_same_options():
    workflow = load_workflow()
    miss_names = {
        "os-repo-tests": [
            "repotests java-sec-code",
            "repotests dotnet-podcasts",
            "repotests vulnerable-aws-koa-app",
        ],
        "os-semantics-tests": ["semantic analysis self", "semantic analysis dejacode"],
    }
    for job_name, names in miss_names.items():
        steps = named_steps(workflow["jobs"][job_name])
        for name in names:
            hit = steps[f"{name} (cached bom-dir)"]
            run = hit["run"]
            assert "--target-kind bom-dir" in run, (job_name, name)
            # The miss path keeps the analyzer and explain options of the
            # original step, and the hit path must mirror exactly those.
            miss_run = steps[name]["run"]
            for flag in ("--reachability-analyzer", "--explain"):
                miss_has = flag in miss_run
                hit_has = flag in run
                assert miss_has == hit_has, (job_name, name, flag)
            for analyzer in ("FrameworkReachability", "SemanticReachability"):
                assert (analyzer in miss_run) == (analyzer in run), (job_name, name, analyzer)


def test_save_steps_run_only_after_a_restore_miss():
    workflow = load_workflow()
    checked = 0
    for job_name, job in workflow["jobs"].items():
        for step in steps_of(job):
            uses = str(step.get("uses", ""))
            key = (step.get("with") or {}).get("key") or ""
            if uses.startswith("actions/cache/save") and key.startswith("repotests-gen-"):
                condition = step.get("if") or ""
                assert "outputs.cache-matched-key == ''" in condition, (job_name, step.get("name"))
                checked += 1
    assert checked == 9, f"expected nine generated-input save steps, found {checked}"


def test_cache_actions_are_pinned_by_sha():
    workflow = load_workflow()
    for job_name, job in workflow["jobs"].items():
        for step in steps_of(job):
            uses = str(step.get("uses", ""))
            if uses.startswith("actions/cache"):
                assert CACHE_ACTION_SHA in uses, (job_name, step.get("name"))


def test_external_checkouts_are_pinned_to_full_commits():
    workflow = load_workflow()
    found = {}
    for job_name, job in workflow["jobs"].items():
        for step in steps_of(job):
            with_ = step.get("with") or {}
            repository = with_.get("repository")
            if repository in PINNED_CHECKOUTS:
                ref = str(with_.get("ref") or "")
                assert re.fullmatch(r"[0-9a-f]{40}", ref), (job_name, repository, ref)
                found[repository] = ref
    assert set(found) == PINNED_CHECKOUTS, sorted(found)


def test_miss_path_caches_only_cdxgen_and_atom_outputs():
    workflow = load_workflow()
    copy_steps = 0
    for job_name, job in workflow["jobs"].items():
        for step in steps_of(job):
            run = step.get("run") or ""
            if "repotests-gen" not in run or "find " not in run:
                continue
            patterns = set(re.findall(r"-name '([^']+)'", run))
            assert patterns, (job_name, step.get("name"))
            assert patterns <= ALLOWED_COPY_PATTERNS, (job_name, step.get("name"), patterns - ALLOWED_COPY_PATTERNS)
            assert {"*.cdx.json", "*slices*.json"} <= patterns, (job_name, step.get("name"))
            copy_steps += 1
    # Seven miss-path copy steps: three java-sec-code variants share one step,
    # three dotnet-podcasts variants share one step, the koa app, the self
    # scan and dejacode have one each.
    assert copy_steps == 5, f"expected five miss-path copy steps, found {copy_steps}"


def test_no_cache_step_writes_dep_scan_outputs():
    workflow = load_workflow()
    for job_name, job in workflow["jobs"].items():
        for step in steps_of(job):
            uses = str(step.get("uses", ""))
            key = (step.get("with") or {}).get("key") or ""
            path = (step.get("with") or {}).get("path") or ""
            if not (uses.startswith("actions/cache") and key.startswith("repotests-gen-")):
                continue
            assert "depscan_reports" not in path, (job_name, step.get("name"), path)
            assert "vdr" not in path.lower(), (job_name, step.get("name"), path)


def test_size_logging_step_runs_du():
    for job_name in ("os-repo-tests", "os-semantics-tests"):
        job = load_workflow()["jobs"][job_name]
        steps = named_steps(job)
        size_step = steps["Log generated-input cache sizes"]
        assert size_step.get("if") == "always()", job_name
        assert "du -sk" in size_step["run"], job_name
