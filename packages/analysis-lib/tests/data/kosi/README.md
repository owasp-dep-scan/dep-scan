# kosi recordings

Two kosi 4.3.1 reports kept as adapter test input, one per analysis tier,
over the same small Kotlin project. The tests in `test_evidence_kosi.py`
read them.

## How they were made

kosi 4.3.1 is the `plugins/kosi/kosi-darwin-arm64` binary of the npm
package `@cdxgen/cdxgen-plugins-bin-darwin-arm64` 4.3.1, the package this
command installs:

```bash
npm install @cdxgen/cdxgen-plugins-bin-darwin-arm64@4.3.1
```

Both reports name it in their `tool` block (`version` 4.3.1, `commit`
`f9b7d7e667cb45ded678c12748ea296221c27ee3`). The analysed project, `kt2`, is
a one-file Kotlin JVM project (`src/main/kotlin/demo/App.kt`) whose only
dependency is `com.squareup.okhttp3:okhttp` 4.12.0; it is not carried in
this repository. The runs used the arguments dep-scan's runner passes
(`xbom_lib.kosi._build_kosi_args`), one per tier:

```bash
kosi analyze --dir <recording-root>/kt2 --backend resolved --out kosi-resolved-report.json \
  --callgraph static --dataflow security
kosi analyze --dir <recording-root>/kt2 --backend syntax --out kosi-syntax-report.json
```

The `options` block of each report records the settings kosi applied,
defaults included.

- `kosi-resolved-report.json`: the resolved tier. Two dataflow slices (one
  into okhttp's `Request.Builder.url`, one into `Runtime.exec`), a call
  graph of four workspace functions and three edges, 16 usages and two
  imports, no API endpoints, and one `taint-unnameable-invoke` diagnostic.
- `kosi-syntax-report.json`: the syntax tier. No call graph and no data
  flow (`callGraph` and `dataFlow` are `null`), the same 16 usages and two
  imports, and the three diagnostics that say the syntax tier resolves no
  calls, lowers no IR and parses without a classpath.

## Paths

`runtime.workingDirectory` reads `/src/kt2` in both reports, the only
absolute path in them; every other path (`filePath`, frame `file`,
positions) is relative to the project, as kosi writes it. The reports carry
no usernames or hostnames.
