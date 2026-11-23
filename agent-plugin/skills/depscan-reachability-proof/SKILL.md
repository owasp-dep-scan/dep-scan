---
name: depscan-reachability-proof
description: 'Proves or disproves that a vulnerable package or function is reachable, per language, by running the sibling analyzers directly: golem with an explicit root set and witness paths for Go, kosi for Kotlin and JVM, rusi for Rust, dosai exploit chains and reachability for .NET, and atom reachables and callsites for the languages atom reads. Use when the user asks whether a finding is actually exploitable, to prove a CVE is reachable from an entry point, or to separate dead code from live exposure. Every reach claim names its analyzer and root set, and anything not measured is reported as not assessed.'
---

# Prove reachability for a finding

Use this skill when the question is "is this finding reachable here", after
a scan exists. dep-scan's own reachability enrichment runs through
`depscan scan --profile ci` or `--checks reachability`, and its outputs
come first: the scan's evidence store (`evidence.jsonl`, whose records
carry each producer's own flows, witness paths and caveats), the raw
reports (the `*-semantics.slices.json` cdxgen persisted for rusi, golem
and dosai, or `analysis/<tool>/` when dep-scan ran the tool itself, which
is always the case for kosi), and each finding's
`exploitability.axes.reach`. The analyzers below are run directly only for
what a scan does not record, and each step says what that is.

The rules in [reference/safety.md](../../reference/safety.md) apply, in
particular: a reach claim names its analyzer and root set; "not reachable"
is never stated unless the evidence covers the vulnerable function and the
deployed entry points; and the summary uses the finding schema's
exploitability axes (presence, reach, exposure, barrier), marking
every axis you did not measure as `not_assessed`.

## Finding the analyzers

golem, kosi and rusi ship in `@cdxgen/cdxgen-plugins-bin-<platform>`, not
with dep-scan; dosai is its own release; atom is the `@appthreat/atom` npm
package. `depscan doctor --format json` lists the ones dep-scan found, and
[reference/tools.md](../../reference/tools.md) gives the lookup order and
the minimum versions. When a tool is missing, the analysis it would provide
stays `not_assessed`; say so, and never install a tool without the user's
consent.

Write every output under a directory you created for this run (the
examples use `/tmp/reach`), with absolute paths.

## Go: golem with an explicit root set

dep-scan does not choose golem's root set: the report it reads records
the root set in `callGraph.roots`, and dep-scan's own run leaves golem's
default in place. The golem adapter carries the callee node's
`reachableFromRoots`, `minDepth` and `rootIds` into each call-graph edge
record (the raw report is `go-semantics.slices.json` when cdxgen wrote
it, or `analysis/golem/golem.json` when dep-scan ran golem). It does not
ask for witness paths to a vulnerable symbol, because golem runs before
the advisories are matched, so this step runs golem directly with the
symbol named and, when the claim needs it, an explicit `-roots` set.

```bash
mkdir -p /tmp/reach
printf 'golang.org/x/crypto/ssh.Dial\n' > /tmp/reach/symbols.txt
CGO_ENABLED=0 GOFLAGS=-mod=readonly golem analyze -dir /absolute/path/to/project \
  -callgraph rta -roots main -reachable-symbols /tmp/reach/symbols.txt \
  -dependency-detail full -include-stdlib -out /tmp/reach/golem.json
```

golem reads the project from `-dir` and ignores positional arguments; a
command without `-dir` analyses the current directory and can return an
empty, valid-looking report. Write the report with `-out` (golem has no
`-o`). The environment prefix keeps cgo off and the module graph read-only,
which is what dep-scan itself does; add `GOPROXY=off GOTOOLCHAIN=local`
when the machine must stay offline. Turning cgo on (`CGO_ENABLED=1`) runs
the host C compiler with flags the project chooses: it needs the user's
consent, stated at the step.

The symbols file holds one pattern per line, matched case-insensitively as
a substring of node ids and labels. `-include-stdlib` keeps standard
library functions in the graph and `-dependency-detail full` keeps the
interior of dependencies; without them, a vulnerable function in the
standard library or deep inside a module has no node to reach, and an empty
answer under the defaults is `not_assessed`, not "not reachable".

The root set is the claim's scope: `-roots main` means reachable from
`main`; `-roots handlers` means reachable from HTTP handlers; `-roots
exported` is the right set for a library module; `-roots all` widens the
claim. The report names the run in `options.callGraphMode` and
`callGraph.roots`; read them before quoting anything. Then:

- `callGraph.reachability.paths[]` is the witness: `symbol`, the `nodeIds`
  from a root to the symbol, the `edgeIds` with file and line, and
  `depth`. `-max-paths-per-symbol` (default 3) caps the paths per symbol.
- `callGraph.reachability.nodes[]` is liveness: `nodeId`,
  `reachableFromRoots`, `minDepth` and `rootIds` for every node in the
  graph.
- A symbol with no node at all was not reached from the chosen roots under
  rta. That is evidence for this root set only, with the analyzer's limits
  (reflection, plugins, code loaded at run time).

`securitySignals` entries carry a category, severity and confidence;
`dataFlow` slices carry `sanitizerNodeIds`, which is barrier evidence, not
proof of absence. If the diagnostics say `RTA requires at least one
reachable root function`, the chosen root set found no roots: report that,
and do not present an empty graph as "nothing is reachable".

## Kotlin and JVM: kosi

For Kotlin and Android scans dep-scan runs kosi's `syntax`
backend itself (it reads source only and starts no build) and reads the
report into evidence records, with the raw report in
`analysis/kosi/kosi.json`. Its API endpoints become `entry-point` records
that name no package, so they never count as reach. The syntax tier has
library usages joined to explicit imports (a wildcard import or an
import that matches more than one artifact attributes nothing), and no
call graph or data flow, so this step runs the `resolved` backend
directly for root sets and witness paths.
Per-node `rootScopes` there are kosi's scope names (`main`, `handlers`),
not node ids.

```bash
kosi analyze --dir /absolute/path/to/project --backend resolved \
  --roots main --dataflow security \
  --reachable-symbols /tmp/reach/kosi-witness.json --out /tmp/reach/kosi.json
```

For kosi, `--reachable-symbols` names the file it writes: the shortest
witness paths for every reached symbol (`symbols[].canonicalName`,
`nodeId`, `paths[].root` and `paths[].edges`). It needs the resolved
backend; the syntax backend has no call graph. `callGraph.reachability[]`
carries `nodeId`, `reached`, `distance` and `roots` per node. Use `--roots
handlers` for services and `--roots android` for apps. The resolved
backend builds its classpath from explicit jars, a `classpath.txt`, `libs/`
directories or an offline scan of `~/.gradle` and `~/.m2`
(`stats.classpath` names the one used); it does not run Gradle. Calls into
a library missing from that classpath stay unresolved, and the summary
says so.

## Rust: rusi

dep-scan's rusi records carry rusi's data-flow slices, its call-graph
edges into dependency crates, its API endpoints, and its `usages[]` as
`callsite` records, which the engine never counts as reach. This runs
rusi directly because dep-scan does not report its unsafe-code signals or
crypto findings yet.

```bash
rusi analyze --dir /absolute/path/to/project --backend stable \
  --out /tmp/reach/rusi.json
```

`security_signals` carry `category` (unsafe-code, native-interop,
ffi-wrapper, trusted-proxy-config and others), severity, confidence, purl
and file position. rusi has no root-based liveness, so its call graph is
reach evidence only through a data flow's witness. `--deps` (with
`--dataflow security-deps`) resolves calls into dependency crates instead
of stopping at the boundary. The `compiler` backend runs the Rust compiler
and the crate's build scripts, which executes project code: it needs the
user's consent in the conversation, stated at the step.

## .NET: dosai

dep-scan keeps dosai's exploit chains, attack-surface tiers, sanitized
flows and service trust zones as evidence records: `exploit-chain`
records carry the chains with their entry point, exposure and hop count,
`entry-point` records carry the attack-surface tier and `trustZone` of
each service, and `sanitizer` records carry the sanitized flows and
`sanitizersNearby` (the raw report is the `*-semantics.slices.json` cdxgen
persisted, or `analysis/dosai/dotnet-dataflows.json` and
`dotnet-methods.json` when dep-scan ran dosai). dosai emits no slice
for a trace it sanitized, so a nearby sanitizer is context, not a reason
to discount the slice; quote its category (an HTML encoder does not
sanitize a SQL or command sink). Read those first; run dosai directly
only when no scan exists or for `agent-context`.

```bash
dosai dataflows --path /absolute/path/to/project \
  --o /tmp/reach/dosai-dataflows.json
dosai agent-context --path /absolute/path/to/project \
  --o /tmp/reach/dosai-agent.json
```

`ExploitChains` are the strongest evidence: a chain from a route to a sink
through the vulnerable package. `AttackSurface` groups entry points by
exposure tier; `SanitizedFlows` is barrier evidence (a sanitizer on the
path), never proof the finding cannot fire; `PackageReachability` joins
packages to flows. `agent-context` is the compact version for a long
investigation: `EntryPoints`, `HighRiskSlices`, `ReachablePackages`,
`AttackSurface` and `SuggestedNextCommands`. dosai's `--restore` or
`--build` options run MSBuild on the project: never pass them to an
untrusted project, and on a trusted one say at the step that they build
project code. On a machine whose .NET runtime is newer than the one the
release targets, dosai needs `DOTNET_ROLL_FORWARD=LatestMajor`; record that
you set it.

## atom: reachables and callsites

atom covers Java, JavaScript and TypeScript, Python, PHP, Ruby and C/C++.

```bash
atom reachables -l <language> --no-build-tools --profile appsec \
  --bom-file /absolute/path/to/bom.json \
  -o /tmp/reach/app.atom --slice-outfile /tmp/reach/reachables.json \
  /absolute/path/to/project
atom callsites -l <language> --no-build-tools \
  --bom-file /absolute/path/to/bom.json \
  -o /tmp/reach/app.atom --reuse-atom \
  --slice-outfile /tmp/reach/callsites.json /absolute/path/to/project
```

`--bom-file` takes the BOM dep-scan's scan wrote, so reachables and
callsites carry package purls. `--profile appsec` drops flows a sanitizer
already covers. `--no-build-tools` keeps atom from running Maven, Gradle,
delombok or sbt; `--fetch-deps` and the build tools run project tooling
and need consent. An empty reachables list with no tagged sources is
`not_assessed`, not "unreachable": the projects that produce empty lists
usually lack recognised entry points. callsites lists every place the
application calls into each package, which is presence of use, not reach
from an entry point.

## What this proves and what it does not

A witness path from a named root set proves reach from that root set under
that analyzer's call-graph approximation (rta and cha are approximations,
not concrete traces). Sanitizers, authentication and binary hardening are
barriers, not refutations. A summary states, per finding: presence (`likely`
when the package is in the BOM, `proven` on a cdxgen occurrence or callstack
record in `evidence.jsonl` or a reached value; BOM directory and lifecycle
scans grade presence without those records), reach (the witness, which
names the id of the evidence record that carries the path, or not
assessed), exposure
(the entry point and its tier), and barrier (sanitizers or authentication
seen). Every axis you did not measure is `not_assessed`, and an
unmeasured axis caps the claim.
