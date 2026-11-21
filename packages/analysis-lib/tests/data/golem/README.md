# golem recordings

Raw golem 4.3.1 reports kept as adapter test input. Each file is the JSON
golem printed, with two trims applied so the recording carries no local
paths and no repeated bulk. The tests in `test_evidence_golem.py` read them.

## How they were made

golem 4.3.1, printed by the binary itself (`golem --version`) from the npm
package `@cdxgen/cdxgen-plugins-bin-darwin-arm64` 4.3.1 installed at
`~/sandbox/depscan-perf/tools/node_modules/` (file
`.../plugins/golem/golem-darwin-arm64`). The binaries in the
`cdxgen-plugins-bin` checkout and on PATH are other versions and were not
used. The repos are the ones the repository carries at
`test/data/golem/repos`, copied into a temporary recording directory
(`/var/tmp/p17-golem-rusi-recording/golem`) so the recording root was never
the checkout; `reachable-app` and `unreachable-app` were copied beside
`vuln-lib`, which their `go.mod` replace directives point at. Each run
mirrors the flags dep-scan's fallback runner passes
(`xbom_lib.golem._build_golem_args`):

```bash
CGO_ENABLED=0 GOFLAGS=-mod=readonly GOPROXY=off GOTOOLCHAIN=local \
golem analyze --dir <recording-root>/<repo> --format json --callgraph static \
  --out <recording-root>/golem-<repo>.json --include-all-flows --dataflow all \
  --dataflow-callgraph static --dataflow-pattern-packs all \
  --dataflow-max-slices 1000 --dataflow-workers 4 --max-procs 4 \
  --dataflow-large-repo-functions 1000 --dataflow-max-function-instructions 200 \
  --dataflow-max-trace-nodes 64 --dataflow-max-trace-edges 128 \
  --dataflow-skip-generated --dataflow-skip-tests
```

`golem-real-cve-app.json` was recorded with `GOFLAGS=-mod=vendor` instead,
because the repo vendors its two dependencies. `reachable-app` and
`unreachable-app` resolve `vuln-lib` through the local replace directive, so
their runs needed no module downloads.

- `golem-reachable-app.json`: run over `reachable-app`. One dataflow slice
  rooted at the HTTP handler, two call-graph edges into `vuln-lib`, one
  usage, two HTTP endpoints.
- `golem-real-cve-app.json`: run over `real-cve-app` (vendored gorilla/mux,
  satori/go.uuid). Ten unrooted dataflow slices and 155 call-graph edges,
  almost all dependency-internal.
- `golem-unreachable-app.json`: run over `unreachable-app`. No dependencies,
  two HTTP endpoints.

## What was cut

- Every absolute path under the temporary recording root was rewritten to
  `/src/...` (golem embeds the analysed directory in node ids, positions,
  module dirs, the runtime working dir and endpoint ids).
- `golem-real-cve-app.json` only: of the 155 call-graph edges, the 97
  vendored-mux-internal edges and the go.uuid-internal edges were cut except
  two kept as shape representatives (one mux-internal, one go.uuid-internal),
  alongside the app-driven edges into `go.uuid.init` and `go.uuid.NewV4` and
  the blank-import edge into `mux.init`; the call-graph nodes only those cut
  edges referenced were cut, together with their root-reachability entries;
  and of the 10 unrooted dataflow slices the first 2 were kept, with the
  dataflow nodes and edges only they name. `callGraph.stats` and
  `dataFlow.stats` still carry what golem printed about the full run, and
  nothing else was changed: every kept object is what golem printed, modulo
  the path rewrite.

The golem reports carry no usernames or hostnames.
