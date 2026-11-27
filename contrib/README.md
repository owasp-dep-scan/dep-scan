# Contributed tools and fixtures

This folder holds the scripts, fixtures and research material that support dep-scan's development and its neighbourhood of tools. Nothing here is part of the installed package; review a script before running it. Everything that documents dep-scan's behaviour moved to [the documentation site](https://depscan.readthedocs.io); the entries below are the tools themselves.

## Maintained with dep-scan

- `gen_agent_manifests.py` and `check_agent_plugin.py` generate and check the agent-plugin manifests; run as `python -m contrib.gen_agent_manifests` and `python -m contrib.check_agent_plugin`, and enforced in the test suite and CI.
- `bench_scan.py` times the matching stage of a scan over the fixtures in `bench_fixtures/`, through `analysis_lib` directly.
- `repotests/` holds the project manifest, fixtures and scripts behind the real-repository CI workflows, including the provenance and validation steps.
- `corpus/` holds the labelled corpus the scorer measures dep-scan against: the manifest (`depscan.corpus.json`) with its published schemas, one label file per item, the derivation script for the oracle labels (`derive_labels.py`), the input resolution (`inputs.py`), the committed fixtures, the floors the pull-request subset enforces (`floors.json`) and the recorded runs those floors and the docs table come from (`results/`). The `Join eval` workflow runs `corpus/score.py` on pull requests that change analysis paths, the scorer or the tool pins, and over the whole corpus weekly; the docs site's Measuring dep-scan page explains how to run it.
- `report-templates/` holds example Jinja templates for `--report-template`.
- `reachability_eval.py` scores dep-scan's reachability against the corpus labels (recall and precision of `direct_purls` and the reached purls, per project and per analyser) through the corpus scorer's own functions; `--check-snapshot` (or `--snapshot`, `--check`, or a repository argument) keeps the older comparison against `reachability_eval.baseline.json` for a refactor that must not change output.
- `CSAF_README.md` points at the CSAF VEX documentation; `csaf.toml` is the commented example the CSAF guide references.
- `dependency-track/` runs Dependency-Track beside dep-scan with docker compose; `lima/` starts an Ubuntu VM for scanning under Linux from a macOS host.
- `schemas/` and the CycloneDX JSON Schema copies here back the offline validation.

## CI helpers

- `free_disk_space.sh` frees disk space on GitHub's hosted runners before the image and repository tests.
