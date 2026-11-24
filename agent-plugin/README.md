# OWASP dep-scan plugin for coding agents

The dep-scan plugin gives a coding agent the fourteen dep-scan skills: scanning source projects and container images, triaging findings, refreshing the vulnerability database, closing coverage gaps, and producing VEX and CSAF documents. It also carries three agents that do not modify the project (triage, binary review and exposure analysis) and the configuration that connects dep-scan's MCP server. The skills tell the agent which command and flags to use, and they carry the safety rules in [`reference/safety.md`](reference/safety.md): untrusted projects stay untrusted, absolute paths, no installs or build scripts of the scanned project, secrets are never quoted, and a clean result must be earned from the scan manifest.

The plugin ships instructions, not the tool, so install dep-scan too (`pip install owasp-depscan`, or one of the other methods in the [project README](https://github.com/owasp-dep-scan/dep-scan#readme)). The skills are plain [Agent Skills](https://agentskills.io/specification), and the folder carries a root `plugin.json` in the [Agent Plugins](https://agent-plugins.org) format, so it serves every client below.

## Contents

- `skills/`, one skill per job. The dep-scan skills cover only what dep-scan's code delivers today; where a check still exits 4 because dep-scan does not implement it (binary, memory safety, mobile, crypto), the toolchain skill runs the sibling tool directly and says so at each step. `depscan-vdb` and `depscan-coverage-loop` change state (a download, an install), so they set `disable-model-invocation` and run only when the user asks.
- `agents/vuln-triager.md` reads an existing scan directory and returns what to fix first; it never scans, never refreshes the database, and never records a triage decision, because the MCP server has no `record_triage` tool in this version. `agents/binary-reviewer.md` reviews binaries, drivers, installers and app artifacts; `agents/exposure-analyst.md` answers exposure and reachability questions from the engines' reports. None of the three modifies the project; their tool list includes Bash, so this rests on their instructions, and the reports they produce go to `/tmp`.
- `hooks/`, two standard-library Python scripts that warn and never act: a `SessionStart` check that warns when the `depscan` CLI is missing, older than the plugin, or missing the `mcp` extra, and an opt-in reminder that the last scan is stale after a lockfile edit.
- `.mcp.json` and `mcp.json`, the same conservative MCP server configuration (`depscan mcp`, never `--allow-scans`) for Claude Code and Codex, the two clients that read one from a plugin today.
- `reference/safety.md` (the shared rules every skill links to), `reference/commands.md` (the dep-scan verbs with the documents each writes, and the sibling-tool commands) and `reference/tools.md` (how each sibling tool is found and versioned).
- `evals/`, the plugin's eval cases: one selection case per model-invocable skill, one not-invoked case per state-changing skill, one case per safety rule and two evidence cases. Run them with `claude plugin eval ./agent-plugin --threshold 0.8`; each case also runs once without the plugin, so the report shows what the plugin adds.

## Install per client

The full instructions, including the tested status of each client, are in [the documentation page](https://depscan.readthedocs.io/agent-plugin). The short forms:

- Claude Code: `claude plugin marketplace add owasp-dep-scan/dep-scan` then `claude plugin install depscan@depscan-plugins`.
- Codex: `codex plugin marketplace add owasp-dep-scan/dep-scan` then `codex plugin add depscan@depscan-plugins`.
- opencode: point the `skills` setting in `opencode.json` at this folder's `skills/` as `{"paths": [".../agent-plugin/skills"]}`; `opencode debug skill` lists the fourteen skills.
- ZCode: `zcode plugins marketplace add owasp-dep-scan/dep-scan` then `zcode plugins install depscan@depscan-plugins`; ZCode needs `.zcode-plugin/plugin.json`, which this folder carries.
- Cursor, Gemini CLI, Kiro, Copilot CLI: each reads the manifest format it documents (`.cursor-plugin/marketplace.json`, `gemini-extension.json`, the Agent Plugins `plugin.json`); these clients are not yet tested.

Only Claude Code has the agents and the `userConfig` options, and only Claude Code and ZCode run the hooks; on every other client the skills read `${user_config.KEY}` as plain text and fall back to their defaults.

## Plugin settings

The settings hold no keys or tokens: `lockfile_reminder` (the opt-in stale-scan hook), `vdb_home` (the database directory, as `VDB_HOME`), `vdb_flavor` (full, full-extended, full-2y, full-2y-extended, full-10y, full-10y-extended, app-only, app-extended, app-2y, app-2y-extended, app-10y, app-10y-extended), `cdxgen_cmd` (how dep-scan starts cdxgen; dep-scan needs cdxgen 13.8.0 or newer), and `runtime` (the local CLI or the ghcr.io/owasp-dep-scan/dep-scan image).

## Privacy

The plugin sends nothing anywhere. It contains instructions, two Python hook scripts the client runs locally, and a configuration that starts `depscan mcp` on your machine. The tools it runs are the user's own dep-scan and its sibling tools, reading the user's own projects. A scan does use the network: it downloads the vulnerability database when the local one is missing, older than 48 hours or of another flavor (`--profile offline` prevents it), pulls the `ghcr.io/cdxgen/cdxgen` image for a source scan when no usable local cdxgen exists, `docker` is on `PATH` and the engine is left on `auto`, and lets golem fetch Go modules unless `--go-analyzer-network offline` is passed. The skills tell the agent to say which of these will happen before a scan.

## The cdxgen plugin is the companion for BOM generation

dep-scan's skills start from a scan or a scan directory. For generating the BOM itself, the [cdxgen plugin](https://github.com/cdxgen/cdxgen/tree/master/agent-plugin) is the companion: its `sbom-generate`, `container-sbom` and `sbom-fidelity-loop` skills cover the generation side, and dep-scan's skills name them instead of repeating cdxgen's commands. cdxgen has no MCP server, so everything there runs as a command line.

## Development

`python -m contrib.gen_agent_manifests` regenerates every client manifest from `contrib/agent_manifests_template.json` and the version in `pyproject.toml`; `python -m contrib.check_agent_plugin` runs the structural checks the Claude validator does not make (skill names and directories, description lengths, strict frontmatter, relative links, versions, hooks and agents, the two MCP files, drift). `python -m pytest test/test_agent_plugin_manifests.py test/test_agent_plugin_check.py test/test_agent_plugin_commands.py test/test_agent_plugin_tool_commands.py test/test_agent_plugin_hooks.py test/test_agent_plugin_plugin.py` runs the whole set, and the `Agent plugin` workflow runs all of it with `claude plugin validate --strict` in CI.
