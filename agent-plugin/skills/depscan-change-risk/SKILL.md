---
name: depscan-change-risk
description: 'Reports what changed between two dep-scan scans, builds or source revisions and whether it made things worse: the MCP diff_scans tool or a fresh scan pair for findings, dosai diff for .NET data-flow deltas, atom-tools drift for flow-level risk deltas with a pass or fail gate, and blint diff for binary hardening regressions. Use for pull-request and release questions such as "did this change add exposure", "what new findings did this introduce", or "did the new build lose hardening".'
---

# Answer what a change did to risk

Use this skill when there are two of something: two scan directories, two
engine reports, two binaries. The question is always "worse, better, or
unchanged, and where". The rules in
[reference/safety.md](../../reference/safety.md) apply; a risk delta that
rests on a stage that did not run is reported as not assessed, never as
"no change".

## Plugin settings

| Setting | Value | When not set |
| --- | --- | --- |
| Vulnerability database directory | `${user_config.vdb_home}` | dep-scan's own default |
| cdxgen command | `${user_config.cdxgen_cmd}` | the `cdxgen` on `PATH` |

## Scan findings: dep-scan first

When Claude Code offers the plugin's MCP tools, `diff_scans` compares two
scan directories and returns the added, fixed and changed vulnerability
pairs:

```
diff_scans(old_scan_dir=<old>, new_scan_dir=<new>)
```

Without the MCP server, produce two scans and compare the documents:

```bash
CDXGEN_SECURE_MODE=true depscan scan /absolute/path/to/old-revision --format json -o /tmp/old-reports
CDXGEN_SECURE_MODE=true depscan scan /absolute/path/to/new-revision --format json -o /tmp/new-reports
```

Bound both sides the same way before launching. When a tree holds container
files, fixture corpora or other non-product trees, pass the same
`--cdxgen-args "--exclude ..."` set to both scans (patterns anchor at each
scanned root), and name that scope before the first command runs: two
inventories of different material answer a different question than the one
asked, and a source scan reads and pulls every image its Dockerfiles name
(see [reference/safety.md](../../reference/safety.md)).

Read both manifests' `stages` first: a stage that is anything but
`completed` on one side makes the delta for its categories not assessed.
Then check what each side's inventory covered: compare the two BOMs'
component counts and purl-type mix and the introspection summary beside
each BOM (its `overall` names the tier reached). A verdict such as
"better" or "unchanged" says which components it covers, not only which
directories were excluded. Then diff the findings by id: added ids are new findings, missing ids are
fixed ones, and shared ids with a changed severity or coverage changed
state.

## .NET data-flow deltas: dosai

This runs dosai directly because dep-scan has no data-flow diff yet.

```bash
dosai dataflows --path /absolute/path/to/old --o /tmp/dosai-old.json
dosai dataflows --path /absolute/path/to/new --o /tmp/dosai-new.json
dosai diff --old /tmp/dosai-old.json --new /tmp/dosai-new.json \
  --o /tmp/dosai-diff.json
```

The diff carries `AddedEntryPoints`, `RemovedEntryPoints`, `AddedSlices`,
`RemovedSlices`, `AddedWeaknesses`, `RemovedWeaknesses`, `AddedPackages`,
`RemovedPackages`, `OldStatistics`, `NewStatistics` and a `RiskDelta`
whose `NewAnonymousEndpoints`, `NewHighSeveritySlices` and
`NewlyReachablePackages` are the headline numbers. Added entry points are
exposure changes even when no weakness accompanies them. Both inputs need
the same dosai version: compare the `Metadata` of the two dataflows files,
because the diff document does not repeat it. dosai's `--restore`/`--build`
run MSBuild: consent, and never on an untrusted project.

## Flow-level risk deltas across engines: atom-tools drift

This runs atom-tools directly because dep-scan has no cross-engine drift
view yet. Both sides must be reports from the same engine (dosai
dataflows, golem, rusi, kosi or atom reachables), produced with the same
options.

```bash
atom-tools drift --old /tmp/golem-old.json --new /tmp/golem-new.json \
  -o /tmp/drift.json -f json --fail-on new-high
```

The drift document carries `AddedFlows`, `RemovedFlows`, `MovedFlows`,
`WitnessChangedFlows`, `AddedEntryPoints`, `AddedPackages`,
`NewSinkCategories` and a `RiskDelta`; `coverage.regressed` says whether
the new report covers less than the old one. With `--fail-on`, exit 2
means a gate tripped, and the console line names which and why. A gate
the engine cannot evaluate also trips. In atom-tools 1.0.x the drift
`RiskDelta.NewAnonymousEndpoints` is `null` ("not computed") for every
engine, because the unified model carries no exposure tier, so
`--fail-on new-anonymous-endpoint` always exits 2. Do not pass that gate;
read `AddedEntryPoints` (each with `method`, `path`, `kind` and `file`)
for new exposure, take authentication from `depscan-attack-surface` or
from `dosai diff`'s own `RiskDelta`, and report any gate the console says
"cannot be evaluated" as not assessed, never as a regression or a pass.

## Binaries and builds: blint diff

`blint diff` compares two builds' hardening, findings, reviews,
dependencies and identity. It ships in blint 4.0.0 and newer, which
dep-scan's `ext` extra installs; a blint 3.2.x found elsewhere does not
have it, so check `blint --help` for `diff` first.

```bash
blint diff /absolute/path/to/old-binary /absolute/path/to/new-binary --json \
  > /tmp/blint-diff.json
```

The document carries `summary`, `hardening`, `findings`, `reviews`,
`dependencies`, `imports`, `symbols` and `identity` deltas. Add
`--disassemble` for the function-level delta (added, removed or changed
by content hash), which needs `blint[extended]`. With only blint 3.2.x
available, say the binary hardening delta is not assessable here rather
than substituting a weaker check.

## What this proves and what it does not

A delta proves a difference between exactly the two artifacts you gave it.
It does not prove the new revision is safe: new findings say what got
worse, "no new findings" says nothing about categories whose stages did
not run, and a flow delta is only as good as the root sets both sides
used. Name the two artifacts, the engine versions, and the root sets in
the answer.

## After the delta

- Prove the reach of a finding the delta added: `depscan-reachability-proof`
- Show the new build's surface: `depscan-attack-surface`
