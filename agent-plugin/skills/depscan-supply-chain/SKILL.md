---
name: depscan-supply-chain
description: 'Audits how software is built and delivered rather than which CVEs it carries: dep-scan''s supply-chain check and risk audit, cdx-audit''s rule packs (package-integrity, dependency-source, ci-permission, build-fidelity, mcp-server, the ai-* packs and the extension packs) run directly on a BOM, malicious-package matching from the vulnerability database, AI and MCP inventory through cdxgen''s ai-bom skill, and provenance and trusted publishing. Use when asked about install scripts, CI workflow risk, dependency confusion, AI or MCP supply chain, or whether a package is known malicious.'
---

# Audit the supply chain

Use this skill when the question is about how the software is built and
delivered rather than which advisories match. dep-scan's own supply-chain
check runs the package risk audit on the npm, PyPI and Cargo packages a
scan finds; cdx-audit's
rule packs are run directly because dep-scan does not run them yet, and
each step below says so. The rules in
[reference/safety.md](../../reference/safety.md) apply; in particular
cdx-audit's predictive mode clones upstream repositories, which needs the
user's consent, and the step says so before it runs.

## Plugin settings

| Setting | Value | When not set |
| --- | --- | --- |
| Vulnerability database directory | `${user_config.vdb_home}` | dep-scan's own default |
| Vulnerability database flavor | `${user_config.vdb_flavor}` | the dep-scan default |
| cdxgen command | `${user_config.cdxgen_cmd}` | the `cdxgen` on `PATH` |

## Step 1: dep-scan's own supply-chain view

```bash
depscan scan /absolute/path/to/project --checks supply-chain --format json -o /absolute/path/to/reports
```

The risk audit reads the npm, PyPI and Cargo packages of the scan,
whatever the project type, and looks each one up in its public registry,
so it needs the network. When the scan carries none of those packages the
manifest's risk stage is `not-assessed` with that reason, which is not
clean; a `skipped` stage means the check was not requested. Malicious packages (`MAL-` advisories)
match through the vulnerability database when the database carries them;
`depscan vdb info --format json` shows the flavor and whether it does.

## Step 2: cdx-audit on a BOM

This runs cdx-audit directly because dep-scan does not run the rule packs
yet. cdx-audit ships with cdxgen.

```bash
CDXGEN_SECURE_MODE=true cdxgen --no-install-deps \
  -o /absolute/path/to/bom.json /absolute/path/to/project
cdx-audit --bom /absolute/path/to/bom.json --direct-bom-audit \
  --report json -o /absolute/path/to/audit.json
```

Always pass `--direct-bom-audit`: without it, cdx-audit runs its
predictive mode, which is the default. The predictive mode clones the
upstream repositories of the BOM's packages to compare what you ship
against what upstream publishes. It is the stronger audit, and it runs
network clones of third-party code, so it needs the user's consent in the
conversation, with the clone count stated first.

The report carries `auditMode` and, per input, the findings with rule ids
and severity. In direct mode every category applies unless
`--categories` narrows it. Exit code 3 means a target reached
`--fail-severity` (default `high`); it is a result, not a failure to
retry.

The categories that matter, by question: install scripts and integrity
(`package-integrity`), where a dependency comes from
(`dependency-source`), CI workflow permissions and untrusted input
(`ci-permission`), build reproducibility (`build-fidelity`), MCP server
configurations (`mcp-server`), agent and model inventory (`ai-agent`,
`ai-governance`, `ai-oversight`, `ai-provenance`), language evidence
(`golem-security`, `go-security`, `cargo-security`, `php-security`,
`scala-security`), cryptography (`cbom-security`), and browser or editor
extensions (`vscode-extension`, `chrome-extension`).

## Step 3: AI and MCP inventory

For the model, server and skill inventory itself, use cdxgen's `ai-bom`
skill (this plugin names it rather than repeating its guidance). The two
project types it starts from:

```bash
CDXGEN_SECURE_MODE=true cdxgen -t mcp --no-install-deps \
  -o /absolute/path/to/mcp-bom.json /absolute/path/to/project
CDXGEN_SECURE_MODE=true cdxgen -t ai-skill --no-install-deps \
  -o /absolute/path/to/skills-bom.json /absolute/path/to/project
```

Then `cdx-audit --bom <file> --direct-bom-audit --categories
mcp-server,ai-agent --report json` audits what they found.

## Provenance and trusted publishing

Where the registry records npm provenance or PyPI attestations, cdxgen's
evidence properties carry them; report per ecosystem how many components
had provenance, had none, or could not be checked. A missing attestation
is a finding about the supply chain's transparency, not proof of
tampering.

## What this proves and what it does not

The audit proves what the rules matched in the BOM and CI files the run
read. It does not prove the pipeline is safe: a category that had no
findings on an ecosystem cdx-audit does not cover is not assessed, and
predictive results are a hypothesis about upstream, not a statement about
the artifact you were given. Name rule ids, and say which categories ran.

## After the audit

- Refresh the database the malware match used: ask the user to run
  `/depscan:depscan-vdb`
- Produce a disclosure from the findings: `depscan-vex-compliance`
