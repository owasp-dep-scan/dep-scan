---
name: depscan-scan
description: Scans a source repository or directory with OWASP dep-scan and reports what to fix first, with the vulnerability and license checks, scan profiles, the scan manifest's coverage stages, and the exit codes an agent branches on. Use when asked to scan a project for vulnerabilities, check dependencies for CVEs, run dep-scan in CI, read a dep-scan manifest or findings document, or when a scan came back empty and the result needs checking before it is called clean. Load it before writing any depscan command, even when the user only wants to see the command.
---

# Scan a project with dep-scan

Use this skill for the common case: a user wants to know what is vulnerable
in a repository or directory. For container images and rootfs directories
use `depscan-container-image`; to read an existing scan back and explain its
findings use `depscan-triage`; when the environment is missing tools or data,
suggest that the user run `/depscan:depscan-coverage-loop`.

The rules in [reference/safety.md](../../reference/safety.md) apply to every
command this skill produces, including commands that are only shown to the
user. In particular: absolute paths, never run the scanned project's build
scripts or installs, and a clean result must be earned from the manifest.

## Plugin settings

Claude Code replaces the `${user_config.*}` values in this table with the
options the user set for the plugin. Other clients show the text as written.
A value counts as set only when it is not empty and does not start with `${`;
otherwise ignore it and follow the "When not set" column. The settings hold
no keys or tokens.

| Setting | Value | When not set |
| --- | --- | --- |
| Vulnerability database directory | `${user_config.vdb_home}` | dep-scan's own default |
| Vulnerability database flavor | `${user_config.vdb_flavor}` | dep-scan's own default |
| cdxgen command | `${user_config.cdxgen_cmd}` | the `cdxgen` on `PATH` (dep-scan needs 13.8.0 or newer) |
| Preferred runtime | `${user_config.runtime}` | the `depscan` on `PATH` |

A set database directory is exported as `VDB_HOME`; a set flavor is passed
as `--vdb-flavor` (a flavor other than the local one triggers a download,
see Step 1); a set cdxgen command is exported as `CDXGEN_CMD`, which the
default `auto` engine then uses before it considers the cdxgen container
image.

## Core syntax

```bash
CDXGEN_SECURE_MODE=true depscan scan /absolute/path/to/project --format json -o /absolute/path/to/reports
```

The target is optional and defaults to the current directory, but always
pass it explicitly; `-o` names the reports directory the scan manifest,
findings document and BOM land in. `--format json` makes the verb write one
JSON document to stdout: `{"scans": [entry, ...]}`, one entry per target,
each with `target`, `kind`, `scanDir`, `manifest` and `findings`. Logs and
tables go to stderr. `CDXGEN_SECURE_MODE=true` keeps cdxgen from running
package managers or builds; dep-scan sets it by itself only for git URLs
and purls, so keep it for any local project the user has not vouched for.

## Step 1: check what the scan will fetch, then run it

```bash
depscan vdb info --format json
depscan config show --format json
```

A scan downloads the vulnerability database by itself when it is missing,
older than 48 hours, or of a different flavor (`full` is gigabytes). When
`vdb info` shows that a download would follow, tell the user before
scanning, or add `--profile offline` to scan against the database as it is.
`config show` prints the effective options and where each came from. A
source scan also lets golem fetch Go modules unless
`--go-analyzer-network offline` is passed, and when no usable local cdxgen
exists (neither `CDXGEN_CMD` nor a cdxgen on `PATH` at the minimum version)
and `docker` is on `PATH`, the `auto` engine pulls the
`ghcr.io/cdxgen/cdxgen` image; say which applies. A source scan of a tree
that carries Dockerfiles or compose files reads every image they name: it
pulls the ones the daemon lacks and extracts their layers, which on a
container-heavy tree can consume the whole cdxgen time budget (30 minutes
by default, `CDXGEN_TIMEOUT_MS` to raise it). Look for container files
before scanning a large tree. When they are CI or build material rather
than the product, exclude their folders, for example
`--cdxgen-args "--exclude 'ci/**' --exclude 'test/**'"`, one `--exclude`
per tree with the pattern anchored at the scanned root. dep-scan applies
the same patterns to its own walks (the binary review and the golem, rusi,
kosi and dosai runs it makes; a language tool that cannot take exclusions
starts on the one project folder the patterns leave, or is reported as not
assessed), so one set keeps a tree out of every stage (see [reference/safety.md](../../reference/safety.md)).

```bash
CDXGEN_SECURE_MODE=true depscan scan /absolute/path/to/project --format json -o /absolute/path/to/reports
```

Exit codes to branch on:

- 0: the scan ran. Read the manifest before calling the result clean.
- 1: the scan could not run (unusable database, missing target). The stderr
  names the cause.
- 2: a usage error; the error document on stdout names the problem, a
  decisions file the schema refuses included.
- 3: an expectation with `action = "fail"` in the project's decisions file
  (or a `--fail-on` you passed) matched a finding. The scan ran; report the
  expectations that failed from `depscan.expectations.json` and never edit
  the decisions file to make the gate pass.
- 4: a requested capability cannot run on this machine, or a `[[require]]`
  entry of the decisions file found its capability not assessed. Do not
  retry with different flags to make it disappear; report what the machine
  lacks or what was not assessed, and suggest
  `/depscan:depscan-coverage-loop` to the user.

In CI, add `--fail-on-error`: without it a failed inventory degrades to
exit 0 with an empty result. `--debug` adds the debug log (for cdxgen too)
when a run goes wrong.

## Step 2: read the manifest before calling it clean

A scan that exits 0 with an empty findings list is not a clean project
until the manifest agrees. Check the `manifest.stages` entries first:

```bash
depscan report /absolute/path/to/reports --format json
```

Any stage whose status is not `completed` (`failed`, `skipped`,
`not-assessed`), and any stage missing after one that stopped the run,
means part of the analysis did not run; report "not assessed" with the
stage's reason rather than a clean result. `depscan doctor --format json` shows the same state
machine-wide. The verbs this skill does not show, `depscan version` (the
dep-scan version and every tool's version) among them, are listed in
[reference/commands.md](../../reference/commands.md) with the document each
writes.

## Choosing checks and profiles

```bash
# Vulnerabilities and license analysis only
depscan scan /absolute/path/to/project --checks vulnerabilities,license --format json -o /absolute/path/to/reports

# The CI profile: vulnerabilities and reachability, no explanations
depscan scan /absolute/path/to/project --profile ci --fail-on-error --format json -o /absolute/path/to/reports

# Every check that can run here; the others are recorded as not assessed
depscan scan /absolute/path/to/project --checks all --format json -o /absolute/path/to/reports
```

An explicitly named check, and every check a `--profile` implies, is gated:
if one cannot run on this machine the verb exits 4 before any scan work
(`--profile ci` exits 4 without a cdxgen of 13.8.0 or newer). `all` never
gates; checks that cannot run become not-assessed entries in the manifest.

| Checks value | What it adds |
| --- | --- |
| `vulnerabilities` | Always runs. |
| `license` | License analysis. |
| `reachability` | Reachability enrichment; needs cdxgen 13.8.0 or newer. |
| `supply-chain` | The supply-chain audit through cdxgen's cdx-audit (cdxgen 13.9.0 or newer). |
| `binary`, `memory-safety`, `mobile`, `code`, `crypto` | Present as names, but several are not implemented in this version and exit 4 with the reason. Probe with `depscan doctor` before promising one. |
| `all` | Every check; the ones that cannot run are recorded, not refused. |

Other options worth knowing: `--exclude-type <type>` drops a detected
project type, `--severity <level>` limits the reported findings,
`--private-ns <prefix>` names the private package namespaces the dependency-confusion check watches, `--malware-only`
looks for known malicious packages only, and several targets can be passed
in one run.

Profiles: `quick` (vulnerabilities only), `ci`, `deep` (adds license and
supply-chain with semantic reachability), `research` (deep plus cdxgen's
research BOM profile), `offline` (no database download, no remote cdxgen).
An explicit `--checks` list defines the whole optional set.

## What this proves and what it does not

A completed scan proves that the matched packages carry the recorded
vulnerabilities as of the database date. It does not prove code is
reachable, that a finding is exploitable, or that a skipped stage found
nothing. Findings carry a `coverage.state`; say which findings were
assessed when summarising, and never upgrade "not assessed" into clean.
For a readable explanation of a finished scan use `depscan-triage`.

## After the scan

Offer the natural next step rather than stopping at the findings file:

- Explain and rank what to fix first: `depscan-triage`
- Check or refresh the database: suggest `/depscan:depscan-vdb`
- Fix the environment a stage that did not complete names: suggest `/depscan:depscan-coverage-loop`
- Produce a CSAF VEX or check a VDR document: `depscan-vex-compliance`
