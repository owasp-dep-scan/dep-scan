---
name: depscan-scan
description: Scans a source repository or directory with OWASP dep-scan and reports what to fix first, with the vulnerability and license checks, scan profiles, the scan manifest's coverage stages, and the exit codes an agent branches on. Use when asked to scan a project for vulnerabilities, check dependencies for CVEs, run dep-scan in CI, read a dep-scan manifest or findings document, or when a scan came back empty and the result needs checking before it is called clean. Load it before writing any depscan command, even when the user only wants to see the command.
---

# Scan a project with dep-scan

Use this skill for the common case: a user wants to know what is vulnerable
in a repository or directory. For container images and rootfs directories
use `depscan-container-image`; to read an existing scan back and explain its
findings use `depscan-triage`; when the environment is missing tools or data
use `depscan-coverage-loop`.

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
as `--vdb-flavor`; a set cdxgen command is exported as `CDXGEN_CMD`.

## Core syntax

```bash
depscan scan /absolute/path/to/project --format json -o /absolute/path/to/reports
```

The target is optional and defaults to the current directory, but always
pass it explicitly; `-o` names the reports directory the scan manifest,
findings document and BOM land in. `--format json` makes the verb write one
JSON document to stdout: `{"scans": [entry, ...]}`, one entry per target,
each with `target`, `kind`, `scanDir`, `manifest` and `findings`. Logs and
tables go to stderr.

## Step 1: run the scan

```bash
depscan scan /absolute/path/to/project --format json -o /absolute/path/to/reports
```

Exit codes to branch on:

- 0: the scan ran. Read the manifest before calling the result clean.
- 1: the scan could not run (unusable database, missing target). The stderr
  names the cause.
- 2: a usage error; the error document on stdout names the problem.
- 4: a requested capability cannot run on this machine. Do not retry with
  different flags to make it disappear; report what the machine lacks, and
  offer `depscan-coverage-loop`.

## Step 2: read the manifest before calling it clean

A scan that exits 0 with an empty findings list is not a clean project
until the manifest agrees. Check the `manifest.stages` entries first:

```bash
depscan report /absolute/path/to/reports --format json
```

A stage with `"status": "failed"` or `"skipped"` and a reason means part of
the analysis did not run; report "not assessed" with that reason rather
than a clean result. `depscan doctor --format json` shows the same state
machine-wide.

## Choosing checks and profiles

```bash
# Vulnerabilities and license analysis only
depscan scan /absolute/path/to/project --checks vulnerabilities,license --format json -o /absolute/path/to/reports

# The CI profile: vulnerabilities and reachability, no explanations
depscan scan /absolute/path/to/project --profile ci --format json -o /absolute/path/to/reports
```

| Checks value | What it adds |
| --- | --- |
| `vulnerabilities` | Always runs. |
| `license` | License analysis. |
| `reachability` | Reachability enrichment; needs cdxgen 13.8.0 or newer. |
| `supply-chain` | The supply-chain risk audit, for the project types it supports. |
| `binary`, `memory-safety`, `mobile`, `code`, `crypto` | Present as names, but several are not implemented in this version and exit 4 with the reason. Probe with `depscan doctor` before promising one. |

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
- Check the database is current: `depscan-vdb`
- Fix the environment a failed or skipped stage names: `depscan-coverage-loop`
- Produce a CSAF VEX or check a VDR document: `depscan-vex-compliance`
