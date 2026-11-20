---
name: depscan-triage
description: Explains the findings of an existing dep-scan scan directory, ranks what to fix first, and answers questions about severity, reachability state and coverage, without changing any file or recording any triage decision. Use when asked to explain, triage, summarise or prioritise dep-scan findings, to answer "which of these CVEs matter", or to read a dep-scan manifest. Load it before discussing scan results with the user.
---

# Explain and rank dep-scan findings

Use this skill to make sense of a scan that already exists. To produce a
scan use `depscan-scan` or `depscan-container-image`.

You read a scan directory and report what to fix first. You record no
triage decisions: dep-scan has no way to store them in this version, so a
"decided" or "dismissed" claim would be fiction. The rules in
[reference/safety.md](../../reference/safety.md) apply, in particular
never claiming `not_affected` or "not reachable" beyond what the evidence
says, and reporting "not assessed" as unknown rather than clean.

## Plugin settings

| Setting | Value | When not set |
| --- | --- | --- |
| Vulnerability database directory | `${user_config.vdb_home}` | dep-scan's own default |

## Reading a scan directory

```bash
depscan report /absolute/path/to/scan-dir --format json
```

The document carries `scanDir`, `manifest` and `findings`. Exit codes: 0
read, 1 could not run, 2 usage error. Every path in a findings summary you
give the user comes from the document, never from memory of a previous
scan.

With the explanation of the analysis:

```bash
depscan report /absolute/path/to/scan-dir --format json --explain
```

The explanation is rendered for the whole scan in this version; read it as
the scan's context around each finding, not as a per-finding text. It is
built from the slices and OpenAPI files in the scan directory, so a scan
that ran without reachability (`--profile quick`, a skipped or failed
reachability stage) has nothing to explain, and the output says so.

## The MCP server

When Claude Code offers the plugin's MCP tools, the same data is available
over `depscan mcp`: `scan_summary`, `list_findings` (filters: category,
severity, purl, cwe, rule, reachable), `get_finding`, `explain_finding`,
`coverage`, `list_components`, `diff_scans`, `doctor`, `vdb_status` and
`run_scan` (a dry run by default). List results are paged: when a result
carries `nextCursor`, pass it back as `cursor` until it is absent before
counting or ranking, and a result too large for the reply is written to a
spill file in the scan directory whose path the result names. The server exits 4 when the `mcp` extra
is missing; installing `owasp-depscan[mcp]` into the environment the server
launches from is a state change, so ask the user first, and never pass
`--allow-scans`.

The server reads only its working directory and the roots the client
announces; the plugin's configuration passes no `--allow-dir`. A scan
directory outside those roots is refused, so fall back to
`depscan report <scan-dir> --format json` rather than widening the server.
The `reachable` filter of `list_findings` reads each finding's
`exploitability.axes.reach`. A scan with reachability records `likely`
for a package in an analyzer's reached set, `unknown` for one absent from
a non-empty reached set, and `not_assessed` when no analyzer covered the
type; `exploitability.sources.reach` names the analyzers. `reachable=true`
returns the `likely` findings. The `grade` filter takes an array and
matches a finding whose `exploitability.grade` is one of the listed
grades, so `grade=["high"]` is the fastest page of the worst-graded
findings; a grade is never inferred from severity. dep-scan writes no `unlikely` or `refuted` value,
so `reachable=false` returns nothing, and an empty page from either value
is never "nothing is reachable".

## How to triage

1. Read the manifest's `stages` first. Any stage whose status is not
   `completed`, or a stage missing after one that stopped the run, means
   the categories it would have produced are **not assessed**; report them
   as unknown rather than clean, with the stage's reason.
2. Group the findings by severity, then by category. For each finding read
   `coverage.state`: `assessed` means the matcher evaluated it against the
   database; anything else was not evaluated.
3. Rank what to fix first by severity, reachability state where the scan
   recorded one, and whether a fixed version exists. Say what each ranking
   rests on.
4. Answer reachability questions with what the scan records (the
   reachability slices and the explanation with `--explain`). Absence of a
   reachability entry is not evidence of "not reachable"; say the scan did
   not assess it.
5. Never mark a finding `not_affected`, never record a decision, and never
   quote a secret the findings or BOM carry. Name the component instead.

## What this proves and what it does not

The report proves what the scan recorded as of its date. It does not prove
a finding is exploitable in the user's deployment, and a clean category is
only as good as the stages behind it. When the user wants a scan rerun
after fixes, compare the old and new directories with the MCP `diff_scans`
tool or a fresh `depscan scan` into a new reports directory.

## After triage

- Fix the environment a stage's failure names: suggest `/depscan:depscan-coverage-loop`
- Produce a CSAF VEX document from the scan: `depscan-vex-compliance`
