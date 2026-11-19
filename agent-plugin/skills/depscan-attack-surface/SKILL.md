---
name: depscan-attack-surface
description: 'Maps what an application exposes: it groups the entry points, authentication state and trust zones that dosai, golem, rusi and kosi report into exposure tiers with atom-tools, and answers which anonymous endpoints reach which vulnerable packages. Use when asked what is exposed, what the attack surface is, which endpoints are anonymous, or what a finding can reach from outside.'
---

# Map the attack surface

Use this skill to answer "what is exposed". It needs a source project and,
for the vulnerable-package join, a dep-scan scan of the same project. The
tools are run directly because dep-scan does not report attack-surface
tiers or trust zones yet; each step says so, and moves to the dep-scan
path when a later version reports them.

The rules in [reference/safety.md](../../reference/safety.md) apply. Steps
that run project code (dosai's `--restore`/`--build`, golem with cgo on,
the rusi `compiler` backend, atom's `--fetch-deps`) are not needed here,
and each needs the user's consent when it is.

## Step 1: collect the engine reports

Per language, one report each; skip a language the project does not have
and say so. Write everything under a directory you created for this run.

```bash
mkdir -p /tmp/surface
# Go
CGO_ENABLED=0 GOFLAGS=-mod=readonly golem analyze -dir /absolute/path/to/project \
  -callgraph cha -roots handlers -dataflow security -out /tmp/surface/golem.json

# Rust
rusi analyze --dir /absolute/path/to/project --out /tmp/surface/rusi.json

# Kotlin and JVM
kosi analyze --dir /absolute/path/to/project --backend resolved \
  --roots handlers --dataflow security --out /tmp/surface/kosi.json

# .NET (needs the .NET runtime the release targets)
dosai dataflows --path /absolute/path/to/project \
  --o /tmp/surface/dosai-dataflows.json
dosai methods --path /absolute/path/to/project \
  --o /tmp/surface/dosai-methods.json
```

golem reads the project from `-dir`, never from a positional path, and
writes with `-out`. [reference/tools.md](../../reference/tools.md) says
where each tool is found.

## Step 2: group by exposure tier

This runs atom-tools directly because dep-scan does not report exposure
tiers yet. Pass the engine reports themselves: the tiers come from dosai's
`AttackSurface` array and from each engine's call graph, which the unified
document of `atom-tools ingest` does not carry.

```bash
atom-tools attack-surface \
  -i /tmp/surface/golem.json,/tmp/surface/rusi.json,/tmp/surface/kosi.json,/tmp/surface/dosai-dataflows.json \
  -o /tmp/surface/attack-surface.json -f json
```

Read the document in this order:

- `summary.headline` and `summary.anonymousReach` give the answer in one
  line ("0 of 2 anonymous entry points reach at least one high-risk
  sink"), with `byTier` and `byEngine` counts.
- `tiers[]`, in `tierOrder` from `anonymous-http` down to `unknown-auth`,
  each with its `Exposure`, `EntryPointCount` and `EntryPoints` (`Route`,
  `HttpMethod`, `File`, `LineNumber`, `Engine` and a `Reach` object).
- `coverage` per engine: how many endpoints were anchored in the call
  graph and how many flows were attached.
- `diagnostics`: an endpoint that could not be anchored reports
  `seed-not-found`, and an engine with no call graph reports reach as not
  computed. Both are gaps, not "reaches nothing".

Only dosai classifies authentication. golem, rusi and kosi entry points
land in `unknown-auth`, which is a gap in the data, not a verdict that
they are protected. For .NET trust zones, read `dosai-methods.json`'s
`Services` (with the request and response data classifications dosai adds
by default) and `EntryPoints`.

## Step 3: join to the vulnerable packages

Read the dep-scan scan directory of the same project
(`depscan report <scan-dir> --format json`), then answer the question that
matters: which anonymous entry points reach which vulnerable purls. An
entry point's `Reach.purls` lists the packages its reach touches; where it
is empty because reach was not computed, the join is `not_assessed` for
that entry point. To see the flows themselves across engines, `atom-tools
ingest -i <the same reports> -o /tmp/surface/unified-flows.json` writes one
document with `flows`, `endpoints` and `packages`.

To find the one function whose fix cuts the most flows, run the chokepoint
metric over a call-graph report:

```bash
atom-tools graph -i /tmp/surface/golem.json --metric chokepoints \
  -f json -o /tmp/surface/chokepoints.json
```

Proxy-derived sources: golem, rusi and kosi report a
`trusted-proxy-config` signal when they see spoofable client-IP handling;
treat it as an exposure finding of its own.

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
