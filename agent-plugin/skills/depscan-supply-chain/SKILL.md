---
name: depscan-supply-chain
description: 'Audits how software is built and delivered rather than which CVEs it carries: dep-scan''s supply-chain check and risk audit, cdx-audit''s rule packs (ci-permission, dependency-source, package-integrity, build-fidelity, mcp-server, ai-* and the extension packs) run directly on a BOM, malicious-package matching from the vulnerability database, AI and MCP inventory through cdxgen''s ai-bom skill, and provenance and trusted publishing. Use when asked about install scripts, CI workflow risk, dependency confusion, AI or MCP supply chain, or whether a package is known malicious.'
---

# Audit the supply chain

Use this skill when the question is about how the software is built and
delivered rather than which advisories match. dep-scan's own supply-chain
check runs the risk audit for the project types it supports; cdx-audit's
rule packs are reached directly because dep-scan does not run them yet,
and each step below says so. The rules in
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

On the project types the risk audit supports this reports the risk audit
findings; on others the manifest's risk stage reads `skipped: the risk
audit was not requested for this type`, which is not assessed, not clean.
Malicious packages (`MAL-` advisories) match through the vulnerability
database at every version when the database carries them; `depscan vdb
info --format json` shows whether it does.

## Step 2: cdx-audit on a BOM

This runs cdx-audit directly because dep-scan does not run the rule packs
yet.

```bash
cdxgen -o /absolute/path/to/bom.json --no-install-deps /absolute/path/to/project
cdx-audit --bom /absolute/path/to/bom.json --direct-bom-audit --report json
```

The results document carries the findings with rule ids and severity from
the packs that apply to the BOM's ecosystems. The predictive mode
(`--no-direct-bom-audit`) clones upstream repositories to compare what
you ship against what upstream publishes: it is the stronger audit, and
it needs the user's consent in the conversation because it runs network
clones of third-party code. Exit code 3 means at least one target met or
exceeded `--fail-severity`.

The packs that matter, by question: install scripts and integrity
(`package-integrity`), where a dependency comes from
(`dependency-source`), CI workflow permissions and untrusted input
(`ci-permission`), build reproducibility (`build-fidelity`), MCP server
configurations (`mcp-server`), agent and model inventory (`ai-agent`,
`ai-provenance`, `ai-governance`, `ai-security`), and browser or editor
extensions (`vscode-extension`, `chrome-extension`).

## Step 3: AI and MCP inventory

For the model, server and skill inventory itself, use cdxgen's `ai-bom`
skill (this plugin names it rather than repeating cdxgen's commands):

```bash
cdxgen -t ai -o /absolute/path/to/ai-bom.json --no-install-deps /absolute/path/to/project
```

## Provenance and trusted publishing

Where the registry records npm provenance or PyPI attestations, cdxgen's
evidence properties carry them; report per ecosystem how many components
had provenance, had none, or could not be checked. A missing attestation
is a finding about the supply chain's transparency, not proof of
tampering.

## What this proves and what it does not

The audit proves what the rules matched in the BOM and CI files the run
read. It does not prove the pipeline is safe: a rule pack that had no
findings on an ecosystem cdx-audit does not cover is not assessed, and
predictive results are a hypothesis about upstream, not a statement about
the artifact you were given. Name rule ids, and say which packs ran.

## After the audit

- Refresh the database the malware match used — `depscan-vdb`
- Produce a disclosure from the findings — `depscan-vex-compliance`
