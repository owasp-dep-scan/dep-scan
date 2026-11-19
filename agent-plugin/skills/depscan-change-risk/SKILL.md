---
name: depscan-change-risk
description: 'Reports what changed between two dep-scan scans, builds or source revisions and whether it made things worse: the MCP diff_scans tool or a fresh scan pair for findings, dosai diff for .NET data-flow deltas, blint diff for binary hardening regressions, and atom-tools drift for flow-level risk deltas. Use for pull-request and release questions such as "did this change add exposure", "what new findings did this introduce", or "did the new build lose hardening".'
---

# Answer what a change did to risk

Use this skill when there are two of something: two scan directories, two
dosai reports, two binaries. The question is always "worse, better, or
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
depscan scan /absolute/path/to/old-revision --format json -o /tmp/old-reports
depscan scan /absolute/path/to/new-revision --format json -o /tmp/new-reports
```

Read both manifests' `stages` first: a stage that failed on one side makes
the delta for its categories not assessed. Then diff the findings by id:
added ids are new findings, missing ids are fixed ones, and shared ids
with a changed severity or coverage changed state.

## .NET data-flow deltas: dosai

This runs dosai directly because dep-scan has no data-flow diff yet.

```bash
dosai dataflows --path /absolute/path/to/old --o /tmp/dosai-old.json
dosai dataflows --path /absolute/path/to/new --o /tmp/dosai-new.json
dosai diff --old /tmp/dosai-old.json --new /tmp/dosai-new.json \
  --o /tmp/dosai-diff.json
```

The document carries `AddedEntryPoints`, `RemovedEntryPoints`,
`AddedPackages`, `AddedSlices`, `AddedWeaknesses` and the statistics of
both sides. Added entry points are exposure changes even when no
weakness accompanies them. Both runs need the same dosai version; a
version mismatch makes the delta unreliable, and the diff document's
`Metadata` records what ran. dosai's `--restore`/`--build` run MSBuild:
consent, and never on an untrusted project.

## Flow-level risk deltas across engines: atom-tools drift

This runs atom-tools directly because dep-scan has no cross-engine drift
view yet.

```bash
atom-tools drift --old /tmp/golem-old.json --new /tmp/golem-new.json \
  -o /tmp/drift.json -f json
```

Both sides must come from the same engine (the command refuses mixed
engines). The drift document carries `AddedFlows`, `RemovedFlows`,
`MovedFlows`, `AddedEntryPoints` and a `RiskDelta` with the tier changes;
`NewAnonymousEndpoints` is the headline number for a pull request.

## Binaries and builds: blint diff

blint's `diff` subcommand compares two builds' metadata, hardening and
findings. It exists in blint master but not yet in a released blint
(the releases this plugin's tools carry stop at `sbom`,
`callgraph-match`, `canonicalize` and `db`); check `blint --help` first
and, when the subcommand is missing, say the binary hardening delta is
not assessable with the installed blint rather than substituting a
weaker check.

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
