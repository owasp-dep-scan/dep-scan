---
name: depscan-supply-chain
description: 'Audits how software is built and delivered rather than which CVEs it carries: dep-scan''s supply-chain check runs cdxgen''s cdx-audit (the package-integrity and dependency-source rule packs, cargo-security for Cargo crates, container-risk, rootfs-hardening and cbom-security added for container images, the dependency-confusion check through --private-ns, and the predictive upstream audit under the deep and research profiles), malicious-package matching from the vulnerability database, and cdx-audit run directly for the ci-permission, mcp-server and ai-* packs and AI and MCP inventory through cdxgen''s ai-bom skill. Use when asked about install scripts, CI workflow risk, dependency confusion, AI or MCP supply chain, or whether a package is known malicious.'
---

# Audit the supply chain

Use this skill when the question is about how the software is built and
delivered rather than which advisories match. dep-scan's supply-chain check
runs cdxgen's `cdx-audit` over the scan's BOM: the direct audit always, and
the predictive upstream audit under the `deep` and `research` profiles. The
findings carry cdxgen's rule ids, severities and the components they name;
the rules in [reference/safety.md](../../reference/safety.md) apply, and the
predictive mode's upstream clones need the user's consent in the
conversation before `--profile deep` or `--profile research` is used.

## Plugin settings

| Setting | Value | When not set |
| --- | --- | --- |
| Vulnerability database directory | `${user_config.vdb_home}` | dep-scan's own default |
| Vulnerability database flavor | `${user_config.vdb_flavor}` | the dep-scan default |
| cdxgen command | `${user_config.cdxgen_cmd}` | the `cdxgen` on `PATH` |

## Step 1: dep-scan's supply-chain check

```bash
CDXGEN_SECURE_MODE=true depscan scan /absolute/path/to/project --checks supply-chain --format json -o /absolute/path/to/reports
```

`CDXGEN_SECURE_MODE=true` stays on every scan of a local project the user
has not vouched for (the same rule as the scan skill), and a tree whose
container files or fixture corpora are not product content carries their
`--cdxgen-args --exclude` trees, or the inventory spends its budget reading
them.

The check needs cdxgen 13.10.0 or newer (`depscan doctor` reports it as the
`cdx-audit` tool). The direct audit first looks the BOM's npm, PyPI and
Cargo components up in their registries, one request per package, because
its rules for deprecated or yanked packages, missing versions and package
age read what only a registry states; say so before running it on a network
the user regards as restricted. The predictive audit under `deep` or
`research` resolves and clones the upstream repositories of the required
dependencies under a target cap of 25 and a 30-minute budget, which is the
consent step above. Under the `offline` profile the audit runs with
`--offline` and makes no network request at all.

Whatever the audit could not assess is stated and never folded into a clean
result: a target the predictive audit skipped or failed, an exhausted target
cap, a spent budget, a registry lookup that did not run, and each component
no registry answered for. Each is a coverage reason on the findings of that
audit and a not-assessed reason on the manifest's `risk` stage. An offline
scan always carries the reason that the registry rules assessed none of the
scan's packages: read the `notAssessed` list before calling a scan clean.

The packs dep-scan runs are `package-integrity` and `dependency-source`,
plus `cargo-security` when the BOM carries Cargo crates; a container image
adds `container-risk`, `rootfs-hardening` and `cbom-security` to them. The
CI, MCP and AI packs are not among them: Step 2 runs cdx-audit directly for
those questions.

The audit's findings are `supply-chain` findings in `depscan.findings.json`
(a `cbom-security` rule becomes a `crypto` finding, a `rootfs-hardening`
rule a `binary-hardening` finding), with cdxgen's rule id as the rule and
cdx-audit's severity; select on `.producer.name == "cdx-audit"` to read all
of them. The scan prints them as the Supply-Chain Audit Results table. The
raw report stays in the scan directory as `cdx-audit-<type>.json`, one per
BOM in a BOM directory scan. When the scan carries no BOM to audit, the
manifest's risk stage says so as not-assessed, which is not clean; a
`skipped` stage means the check was not requested. Under `--profile deep`
or `--profile research` on a machine whose cdx-audit is missing or too old,
the manifest carries a not-assessed `check-supply-chain` entry instead of
a risk stage that ran: report it as not assessed, not as clean. Malicious packages
(`MAL-` advisories) match through the vulnerability database in the matching
stage; `depscan vdb info --format json` shows the flavor and whether it
carries them.

Dependency confusion: pass `--private-ns` with the private namespace or
name prefixes the organisation registers. Each matching package name is
looked up on the public npm registry, the Python Package Index or crates.io.
A name the public registry holds is reported by cdx-audit's INT-017 to
INT-019 rules, for npm scopes and for PyPI and Cargo names; a private
package that is not published publicly is the intended state and is not
reported. Under the `offline` profile the public registry is not asked, so
the check assesses none of the matching packages and the manifest says so.

## Step 2: narrower questions straight on a BOM

For a question a saved BOM can answer without a full scan, run cdx-audit the
way dep-scan does:

```bash
CDXGEN_SECURE_MODE=true cdxgen --no-install-deps \
  -o /absolute/path/to/bom.json /absolute/path/to/project
cdx-audit --bom /absolute/path/to/bom.json --direct-bom-audit \
  --report json -o /absolute/path/to/audit.json
```

Always pass `--direct-bom-audit`: without it, cdx-audit runs its predictive
mode, which clones the upstream repositories of the BOM's packages and needs
the user's consent in the conversation, with the clone count stated first.
Exit code 3 means a target reached `--fail-severity` (default `high`); it is
a result, not a failure to retry. `--offline` plans the queue and reports
every target as skipped when the user asked for no network.

The categories that matter, by question: install scripts and integrity
(`package-integrity`), where a dependency comes from (`dependency-source`),
CI workflow permissions and untrusted input (`ci-permission`),
build reproducibility (`build-fidelity`), MCP server configurations
(`mcp-server`), agent and model inventory (`ai-agent`, `ai-governance`,
`ai-oversight`, `ai-provenance`), language evidence (`golem-security`,
`go-security`, `cargo-security`, `php-security`, `scala-security`),
cryptography (`cbom-security`), and browser or editor extensions
(`vscode-extension`, `chrome-extension`).

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
evidence properties carry them; report per ecosystem how many components had
provenance, had none, or could not be checked. A missing attestation is a
finding about the supply chain's transparency, not proof of tampering.

## What this proves and what it does not

The audit proves what the rules matched in the BOM the scan read, and in
predictive mode what the upstream repositories showed at the time of the
run. It does not prove the pipeline is safe: a category that had no findings
on an ecosystem cdx-audit does not cover is not assessed, and predictive
results are a hypothesis about upstream, not a statement about the artifact
you were given. Name rule ids, and say which categories ran and which
targets the coverage caveats name.

## After the audit

- Refresh the database the malware match used: ask the user to run
  `/depscan:depscan-vdb`
- Produce a disclosure from the findings: `depscan-vex-compliance`
