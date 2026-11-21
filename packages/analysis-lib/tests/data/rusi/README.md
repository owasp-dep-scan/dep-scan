# rusi recordings

Raw rusi 4.3.1 reports kept as adapter test input. Each file is the JSON
rusi printed, with the built-in dataflow pattern pack cut out (reference
material the analysis results do not depend on) and the recording root
rewritten to `/src`. The tests in `test_evidence_rusi.py` read them.

## How they were made

rusi 4.3.1, printed by the binary itself (`rusi --version`) from the npm
package `@cdxgen/cdxgen-plugins-bin-darwin-arm64` 4.3.1 installed at
`~/sandbox/depscan-perf/tools/node_modules/` (file
`.../plugins/rusi/rusi-darwin-arm64`). The rusi 2.5.1 on PATH was not used.
The repos are the ones the repository carries at `test/data/rusi/repos`,
copied into a temporary recording directory
(`/var/tmp/p17-golem-rusi-recording/rusi`) so the recording root was never
the checkout:

```bash
rusi analyze --dir <recording-root>/<repo> --backend stable --callgraph static \
  --dataflow security-deps --out <recording-root>/rusi-<repo>.json
```

These are the backend, call-graph and data-flow settings dep-scan's fallback
runner passes by default (`xbom_lib.rusi`).

- `rusi-reachable-app.json`: run over `reachable-app`. One dataflow slice
  (`file-to-sql-query`) from `std::fs::read_to_string` into `fetch_one`,
  five call-graph edges (four stdlib, one `sqlx::query`), five usages, no
  HTTP endpoints.
- `rusi-rustsec-app.json`: run over `rustsec-app` (the RUSTSEC-2020-0071
  `time` 0.1 dependency). Six call-graph edges including one into
  `time::now`, no dataflow slices, five usages.
- `rusi-unreachable-app.json`: run over `unreachable-app`. One workspace
  declaration, no edges, no slices, no usages.

## What was cut

- Absolute paths under the temporary recording root (rusi writes them into
  `packages[].manifest_path`, `modules[].manifest_path`, `options.directory`
  and `runtime.working_directory`) were rewritten to `/src/...`.
- The `data_flow.patterns` object (rusi's built-in source/sink pattern pack)
  was replaced with a stub naming the cut; nothing else was touched.
- No entries were dropped from the call graph, dataflow, usages or
  endpoints sections.

The string `/var/tmp/tainted_file.txt` appears inside the
`rusi-reachable-app.json` call-graph edge receiver and the dataflow because
the scanned Rust source itself opens that path
(`fs::read_to_string("/var/tmp/tainted_file.txt")`). It is the program's own
literal, not a path on the recording machine, and rusi's evidence is kept as
given. The reports carry no usernames or hostnames.
