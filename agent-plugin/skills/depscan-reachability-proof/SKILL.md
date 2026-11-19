---
name: depscan-reachability-proof
description: 'Proves or disproves that a vulnerable package or function is reachable, per language, by running the sibling analyzers directly: golem with an explicit root set and witness paths for Go, rusi for Rust, dosai exploit chains and reachability for .NET, and atom reachables and callsites where an atom file exists. Use when the user asks whether a finding is actually exploitable, to prove a CVE is reachable from an entry point, or to separate dead code from live exposure. Every reach claim names its analyzer and root set, and anything not measured is reported as not assessed.'
---

# Prove reachability for a finding

Use this skill when the question is "is this finding reachable here", after
a scan exists. dep-scan's own reachability enrichment runs through
`depscan scan --profile ci` or `--checks reachability`; the analyzers below
are reached directly because dep-scan does not surface their witness paths,
root sets or exploit chains yet, and each step below says so. When a later
dep-scan version wires an output up, the skill changes to the dep-scan path.

The rules in [reference/safety.md](../../reference/safety.md) apply, in
particular: a reach claim names its analyzer and root set; "not reachable"
is never stated unless the evidence covers the vulnerable function and the
deployed entry points; and the summary uses the finding schema's
exploitability axes (presence, reach, exposure, barrier, pressure), marking
every axis you did not measure as `not_assessed`.

## Plugin settings

| Setting | Value | When not set |
| --- | --- | --- |
| cdxgen command | `${user_config.cdxgen_cmd}` | the `cdxgen` on `PATH` (dep-scan needs 13.8.0 or newer) |

## Finding the analyzers

`depscan doctor --format json` lists each analyzer with its version. golem
and rusi are on `PATH` when dep-scan was installed with its tool extras;
dosai needs the .NET runtime its release targets; atom ships with the
tool extras. When a tool is missing, the analysis it would provide stays
`not_assessed`; say so, and never install a tool without the user's
consent. [reference/tools.md](../../reference/tools.md) carries the lookup
details.

## Go: golem with an explicit root set

This runs golem directly because dep-scan does not surface witness paths
or root sets yet.

```bash
printf 'ssh.Dial\n' > /tmp/symbols.txt
golem analyze -callgraph rta -roots main -dataflow security \
  -reachable-symbols /tmp/symbols.txt -o /tmp/golem.json \
  /absolute/path/to/project
```

Go's flag parser stops at the first positional argument, so every flag
goes before the path. The root set is the claim's scope: `-roots main`
means reachable from `main`; `-roots handlers` means reachable from
`http.Handler` implementations; `-roots all` widens the claim. The report
names the mode in `options.callGraphMode` and `options.dataFlowMode`; read
them before quoting anything. In `callGraph.reachableSymbols.nodes`, each
node carries `reachableFromRoots`, `minDepth` and `rootIds`: that is the
witness. `securitySignals` entries carry a category, severity and
confidence; `dataFlow` slices carry `sanitizerNodeIds`, which is negative
evidence, not proof of absence.

If the diagnostics say `RTA requires at least one reachable root function`,
the chosen root set found no roots: report that, and do not present an
empty graph as "nothing is reachable".

## Rust: rusi

This runs rusi directly because dep-scan does not surface its unsafe-code
signals or crypto findings yet.

```bash
rusi analyze --dir /absolute/path/to/project --backend stable \
  -o /tmp/rusi.json
```

`security_signals` carry `category` (unsafe-code, native-interop,
trusted-proxy-config and friends), severity, confidence, purl and file
position. The `compiler` backend runs the Rust compiler on the project,
which executes project code: it needs the user's consent in the
conversation, and the skill says so at the step. `rusi cryptos --dir <dir>`
produces the crypto report separately.

## .NET: dosai

This runs dosai directly because dep-scan does not surface exploit chains,
attack-surface tiers or trust zones yet.

```bash
dosai dataflows --path /absolute/path/to/project \
  --o /tmp/dosai-dataflows.json
```

`ExploitChains` are the strongest evidence: a chain from a route to a sink
through the vulnerable package. `AttackSurface` groups entry points by
exposure tier; `SanitizedFlows` is negative evidence (a sanitizer on the
path), never proof the finding cannot fire; `PackageReachability` joins
packages to flows. dosai's `--restore` or `--build` options run MSBuild on
the project: never pass them to an untrusted project, and on a trusted one
say at the step that they build project code. On a machine whose .NET
runtime is newer than the release targets, dosai needs
`DOTNET_ROLL_FORWARD=LatestMajor`; record that you set it.

## Corroboration from atom

```bash
atom reachables -l <language> --sink-tag memory-safety \
  -o /tmp/app.atom --slice-outfile /tmp/reachables.json \
  /absolute/path/to/project
```

An empty reachables list with no tagged sources is `not_assessed`, not
"unreachable": the fixtures that produce empty lists usually lack entry
points. `atom callsites` and `atom usages` add per-package use facts.
atom's `--fetch-deps` runs project tooling and needs consent; do not pass
it by default.

## Kotlin and JVM: a stated gap

kosi analyses Kotlin, JVM and Android and cdxgen runs it, but dep-scan has
no converter for its report and cdxgen deletes the report after parsing
(cdxgen#4806). Kotlin reachability is therefore `not_assessed` in this
version; say exactly that rather than guessing from the BOM.

## What this proves and what it does not

A witness path from a named root set proves reach from that root set under
that analyzer's call-graph approximation (rta is an approximation, not a
concrete trace). Sanitizers, authentication and binary hardening are
barriers, not refutations. A summary states, per finding: presence (the
package is in the BOM), reach (the witness or its absence as not
assessed), exposure (the entry point and its tier), barrier (sanitizers
seen), and pressure (what the database knows). Every axis you did not
measure is `not_assessed`, and an unmeasured axis caps the claim.
