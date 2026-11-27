"""The join-eval workflow runs the scorer the way the corpus docs say."""

import os

import yaml

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
WORKFLOW = os.path.join(REPO_ROOT, ".github", "workflows", "join-eval.yml")


def _workflow():
    with open(WORKFLOW, encoding="utf-8") as fp:
        return yaml.safe_load(fp)


def _run_lines(job):
    return "\n".join(step.get("run", "") for step in job["steps"])


def test_path_filter_covers_the_code_the_scorer_runs():
    # PyYAML reads the "on" key as True.
    paths = _workflow()[True]["pull_request"]["paths"]
    for path in (
        "depscan/lib/**",
        "depscan/commands/**",
        "packages/analysis-lib/**",
        "packages/xbom-lib/**",
        "contrib/corpus/**",
        "pyproject.toml",
        "uv.lock",
        ".github/workflows/join-eval.yml",
    ):
        assert path in paths


def test_scans_stay_out_of_the_checkout_and_no_timeout_is_passed():
    for job in _workflow()["jobs"].values():
        score_steps = [s for s in job["steps"] if "score.py" in s.get("run", "")]
        assert len(score_steps) == 1
        step = score_steps[0]
        assert step["env"]["CORPUS"] == "${{ runner.temp }}"
        assert '--scans-root "$CORPUS/corpus-scans"' in step["run"]
        assert "--timeout" not in step["run"]
        assert "sandbox" not in _run_lines(job)


def test_pull_requests_use_the_small_database_and_the_full_job_has_dotnet():
    jobs = _workflow()["jobs"]
    assert jobs["subset"]["env"]["VDB_DATABASE_URL"].startswith("ghcr.io/appthreat/vdb7-app-2y:")
    assert jobs["full"]["env"]["VDB_DATABASE_URL"].startswith("ghcr.io/appthreat/vdb7-full-10y:")
    dotnet = [s for s in jobs["full"]["steps"] if "setup-dotnet" in s.get("uses", "")]
    assert dotnet and dotnet[0]["with"]["dotnet-version"].startswith("11.")
    # The repo-test pull goes through the repository's composite action,
    # which pulls by digest.
    for job in jobs.values():
        assert any(s.get("uses") == "./.github/actions/repotests-data" for s in job["steps"])


CORPUS = os.path.join(REPO_ROOT, "contrib", "corpus")


def _json(*parts):
    import json

    with open(os.path.join(CORPUS, *parts), encoding="utf-8") as fp:
        return json.load(fp)


def test_the_job_installs_the_cdxgen_the_floors_were_recorded_with():
    version = _json("floors.json")["tools"]["cdxgen"]
    for job in _workflow()["jobs"].values():
        assert f"@cdxgen/cdxgen@{version}" in _run_lines(job)


def test_floors_hold_on_the_recorded_run_and_name_subset_items_only():
    from contrib.corpus import score as corpus_score

    floors = _json("floors.json")
    recorded = _json("results", "score-ci.json")
    assert recorded["commit"] == floors["commit"]
    assert corpus_score.check_floors(floors, recorded) == []
    subset = {i["name"] for i in _json("depscan.corpus.json")["items"] if i.get("subset") == "ci"}
    assert {floor["item"] for floor in floors["floors"]} <= subset


def test_recorded_scores_validate_against_the_score_schema():
    import jsonschema

    schema = _json("depscan-score.schema.json")
    for name in ("score-ci.json", "score-full.json"):
        jsonschema.validate(_json("results", name), schema)
