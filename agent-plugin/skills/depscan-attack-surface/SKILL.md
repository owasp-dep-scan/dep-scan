---
name: depscan-attack-surface
description: 'Maps what an application exposes: it joins entry points, authentication state and trust zones from dosai, golem and rusi through atom-tools into one attack-surface view, and answers which anonymous endpoints reach which vulnerable packages. Use when asked what is exposed, what the attack surface is, which endpoints are anonymous, or what a finding can reach from outside.'
---

# Map the attack surface

Use this skill to answer "what is exposed". It needs a source project and,
for the vulnerable-package join, a dep-scan scan of the same project. The
tools are reached directly because dep-scan does not surface
attack-surface tiers or trust zones yet; each step says so, and moves to
the dep-scan path when a later version wires them up.

The rules in [reference/safety.md](../../reference/safety.md) apply. Two
steps here can run project code (dosai's `--restore`/`--build`, atom's
`--fetch-deps`); neither is needed for the default path, and both need the
user's consent when they are.

## Plugin settings

| Setting | Value | When not set |
| --- | --- | --- |
| cdxgen command | `${user_config.cdxgen_cmd}` | the `cdxgen` on `PATH` |

## Step 1: collect the engine reports

Per language, one report each; skip a language the project does not have
and say so.

```bash
# Go
golem analyze -callgraph cha -dataflow security -o /tmp/golem.json \
  /absolute/path/to/project

# Rust
rusi analyze --dir /absolute/path/to/project -o /tmp/rusi.json

# .NET (needs the .NET runtime the release targets)
dosai dataflows --path /absolute/path/to/project \
  --o /tmp/dosai-dataflows.json
dosai methods --path /absolute/path/to/project --o /tmp/dosai-methods.json
```

## Step 2: normalise into one flow model

This runs atom-tools directly because dep-scan does not expose the
engines' endpoints and flows in one view yet.

```bash
atom-tools ingest -i /tmp/golem.json,/tmp/rusi.json,/tmp/dosai-dataflows.json \
  -o /tmp/unified-flows.json
```

The unified document carries `flows`, `endpoints` and `packages` with the
engine named per entry in `provenance`. Engines can be mixed freely; an
engine whose report is missing contributes nothing, and the summary says
which engines were absent rather than implying a complete surface.

## Step 3: group by exposure tier

```bash
atom-tools attack-surface -i /tmp/unified-flows.json \
  -o /tmp/attack-surface.json -f json
```

The document carries `tiers` ordered from most exposed (`anonymous-http`)
down, with the entry points in each tier. A diagnostic such as "no call
graph in the supplied golem report(s); reach is not computed" is part of
the answer: the tier exists, the reach behind it was not computed. For a
.NET view with trust zones, read `dosai-methods.json`'s `Services` (trust
zones) and `EntryPoints`; dosai's `--classify-data` adds data
classifications.

## Step 4: join to the vulnerable packages

Read the dep-scan scan directory of the same project
(`depscan report <scan-dir> --format json`), then answer the question that
matters: which anonymous endpoints reach which vulnerable purls. The
unified document's flows carry package identities where the engine
records them; where a flow's package column is empty, the join is
`not_assessed` for that entry point.

Proxy-derived sources and trusted-proxy configuration: golem and rusi
report a `trusted-proxy-config` signal when they see spoofable client-IP
handling; treat it as an exposure finding of its own.

## What this proves and what it does not

The surface map proves what the analysed languages and the run's root sets
exposed. It does not prove completeness: a language the engines do not
cover, a route registered dynamically, or a call graph built with a
smaller root set all shrink the picture. State which engines ran, which
did not, and the tier of every entry point you name; "no anonymous
endpoints" is only ever the conclusion for the languages and roots you
actually analysed.

## After the surface map

- Prove a specific finding's reach: `depscan-reachability-proof`
- Compare the surface before and after a change: `depscan-change-risk`
