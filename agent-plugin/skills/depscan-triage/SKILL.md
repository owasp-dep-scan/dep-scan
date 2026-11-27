---
name: depscan-triage
description: Explains the findings of an existing dep-scan scan directory, ranks what to fix first, and answers questions about severity, reachability state and coverage. When asked to record a triage decision, it proposes one into the decisions file for a person to approve; it never approves its own proposal. Use when asked to explain, triage, summarise or prioritise dep-scan findings, to answer "which of these CVEs matter", to read a dep-scan manifest, or to record a triage decision. Load it before discussing scan results with the user.
---

# Explain and rank dep-scan findings

Use this skill to make sense of a scan that already exists. To produce a
scan use `depscan-scan` or `depscan-container-image`.

You read a scan directory and report what to fix first. You can propose a
triage decision, and a person approves it; you never approve your own
proposal, and a decision you made up without the review step is fiction.
The rules in [reference/safety.md](../../reference/safety.md) apply, in
particular never claiming `not_affected` or "not reachable" beyond what the
evidence says, and reporting "not assessed" as unknown rather than clean.

## Plugin settings

| Setting | Value | When not set |
| --- | --- | --- |
| Vulnerability database directory | `${user_config.vdb_home}` | dep-scan's own default |

## Reading a scan directory

```bash
depscan report /absolute/path/to/scan-dir --format json
```

The document carries `scanDir`, `manifest` and `findings`, and
`expectations` when decisions apply: the report re-evaluates the decisions
file, the VEX documents and the `--fail-on` expressions the scan recorded,
with the files resolved against the scan directory, and its `warnings` say
when a recorded file cannot be found, changed since the scan, or was
replaced by a file the environment or configuration names. When a recorded
file is gone, `expectations` and the exit code are the gate result the scan
saved; when that is gone too, the report exits 1 because the recorded gate
cannot be evaluated. Exit codes: 0 read, 1 could not run, 2 usage error, 3 a fail-action expectation matched, 4 a
`[[require]]` entry found its capability not assessed; 3 and 4 are the
user's gate, not a failure of the report. Every path in a findings summary
you give the user comes from the document, never from memory of a previous
scan.

With the explanation of the analysis:

```bash
depscan report /absolute/path/to/scan-dir --format json --explain
```

The explanation is rendered for the whole scan in this version; read it as
the scan's context around each finding, not as a per-finding text. It is
built from the slices and OpenAPI files in the scan directory, so a scan
that ran without reachability (`--profile quick`, a skipped or failed
reachability stage) has nothing to explain and no explanation appears;
report the explanation as not assessed, not as an all-clear.

## The MCP server

When Claude Code offers the plugin's MCP tools, the same data is available
over `depscan mcp`: `scan_summary`, `list_findings` (filters: category,
severity, purl, cwe, rule, reachable), `get_finding`, `explain_finding`,
`coverage`, `list_components`, `diff_scans`, `doctor`, `vdb_status`,
`run_scan` (a dry run by default), `get_decisions` (the triage entries of a
scan with their handles and status, the last gate result, and warnings
when the recorded file is missing or changed) and `propose_triage` (writes
a proposal; the server must have been started with `--allow-propose`). List results are paged: when a result
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
grades, so `grade=["critical", "high"]` is the fastest page of the
worst-graded findings (the bundled table grades no higher than `high`, a
replacement table can); a grade is never inferred from severity. dep-scan writes no `unlikely` or `refuted` value,
so `reachable=false` returns nothing, and an empty page from either value
is never "nothing is reachable".

## How to propose a triage decision

When the user asks you to record a decision about a finding:

1. Name the finding by its `dsf1:` id from `list_findings` or `get_finding`,
   and say in one sentence what the evidence shows.
2. Write the proposal with `propose_triage`, with `scan_dir` naming the
   scan, `proposed_by` naming you and your session, the state the evidence
   supports, and the detail carrying the reasoning and the evidence ids. A
   `not_affected` proposal names its justification. The tool takes no file
   path: it writes into the decisions file `depscan report` would read for
   that scan, found relative to the scan directory, and never changes a
   decision a person made; it adds the proposal beside it. The server refuses the call without the `--allow-propose` grant,
   and you never ask the user to add the grant for a single proposal
   without saying what it widens.
3. Tell the user the proposal waits for them, with the `handle` the result
   carries: `depscan triage review --approve <handle> --approver <their
   name>` approves it, and `depscan triage review --reject <handle>
   --approver <their name>` removes it; `depscan triage review` alone lists
   the pending proposals. Until a person approves it the proposal changes
   no gate, no report and no exit code.
4. Never write an author or an approver name other than through the
   review step, and never claim a decision is recorded when the tool was
   refused or the write failed.

## How to triage

1. Read the manifest's `stages` first. Any stage whose status is not
   `completed`, or a stage missing after one that stopped the run, means
   the categories it would have produced are **not assessed**; report them
   as unknown rather than clean, with the stage's reason.
2. Group the findings by severity, then by category. For each finding read
   `coverage.state`: `assessed` means the matcher evaluated it against the
   database; anything else was not evaluated.
3. Rank what to fix first by severity, reachability state where the scan
   recorded one, and whether a fixed version exists: each finding's
   `fix.fixed_versions` carries it, and the VDR the scan wrote
   (`<bom>.vdr.json`, such as `sbom-docker.vdr.json`) repeats it in each
   vulnerability's `recommendation` string. The VDR's `ratings` arrays can
   hold empty objects, so read severities from the findings document. Say
   what each ranking rests on.
4. Answer reachability questions with what the scan records (the
   reachability slices and the explanation with `--explain`). Absence of a
   reachability entry is not evidence of "not reachable"; say the scan did
   not assess it.
5. Attribute every "fix this" item to where the component really comes
   from before calling it the user's own: a universal or container scan
   mixes the project's manifest-born components with image-born ones, and
   the SBOM's `internal:SrcFile` property is a weak guide (a stamp such as
   `pnpm-lock.yaml` can land on an image RPM). Confirm attribution by
   finding the exact version in the project's own manifest or lockfile
   (the purl and version must both match); a version the lockfile does not
   pin came from an image or fixture, and a lockfile bump will not clear
   it. Count the noise bucket from the findings themselves, not from a
   category name, and re-check every count and total you state against a
   query you can show.
6. Never mark a finding `not_affected` on your own authority: the state
   reaches the user only through a proposal the review step approves. Never
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
