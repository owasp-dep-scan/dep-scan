# Contributed tools and fixtures

This folder holds the scripts, fixtures and research material that support dep-scan's development and its neighbourhood of tools. Nothing here is part of the installed package; review a script before running it. Everything that documents dep-scan's behaviour moved to [the documentation site](https://depscan.readthedocs.io); the entries below are the tools themselves.

## Maintained with dep-scan

- `gen_agent_manifests.py` and `check_agent_plugin.py` generate and check the agent-plugin manifests; run as `python -m contrib.gen_agent_manifests` and `python -m contrib.check_agent_plugin`, and enforced in the test suite and CI.
- `bench_scan.py` times the matching stage of a scan over the fixtures in `bench_fixtures/`, through `analysis_lib` directly.
- `repotests/` holds the project manifest, fixtures and scripts behind the real-repository CI workflows, including the provenance and validation steps.
- `report-templates/` holds example Jinja templates for `--report-template`.
- `npm-watch.py` walks npm registry metadata through `depscan.lib.package_query` to exercise the package risk scoring at scale.
- `pkg-state-research/` and `npm-binaries/` collect registry and binary data for research runs; each has its own requirements file.
- `reachability_eval.py` compares the reached sets computed from a reports directory's atom `reachables` slices against its baseline snapshot (`reachability_eval.baseline.json`), and cross-references the VDR. It reads the files dep-scan 7 writes, and its notes about atom 2.5-era slices predate atom 4.
- `CSAF_README.md` points at the CSAF VEX documentation; `csaf.toml` is the commented example the CSAF guide references.
- `dependency-track/` runs Dependency-Track beside dep-scan with docker compose; `lima/` starts an Ubuntu VM for scanning under Linux from a macOS host.
- `schemas/` and the CycloneDX JSON Schema copies here back the offline validation.

## Older tools, kept for reference

- `trivy-compare.py` parses dep-scan's `depscan-<type>.json` as newline-delimited JSON, the shape dep-scan 6 wrote; dep-scan 7 writes one JSON array per file, so the script needs that change before it compares again.
- `depscanGPT/README.md` carries prompt material for a ChatGPT-based assistant that reads dep-scan's reports; its advice predates the scan directory and the MCP server, both of which are better interfaces for an assistant today.
- `dep-scan-gui.png` and `GUI_README.md` describe the retired web GUI.
- `free_disk_space.sh` is a CI helper, not a dep-scan tool.
