# cdxgen recordings

Real cdxgen 13.9.0 BOMs and a build-introspection report, kept as adapter
test input. The tests in `test_evidence_cdxgen.py` read them:
`sbom-python.cdx.json` with its introspection report, and
`sbom-kotlin-kosi.cdx.json`, which carries the `cdx:kosi:*` properties
cdxgen writes from a kosi analysis (see the last section).

## How they were made

cdxgen 13.9.0 (master `af131a30`) ran over a small Flask application created
for the recording: a `pyproject.toml` naming defusedxml, flask and sqlparse,
one `app.py` with a route that parses XML and normalizes SQL, and a
virtualenv holding those packages installed from PyPI. The flags mirror what
the repository's repotests generation and the cdxgen runner pass
(`contrib/repotests/generate.sh` uses `--profile research`,
`xbom_lib.cdxgen` adds `--introspect --introspect-json` beside the BOM):

```bash
cdxgen -t python --profile research \
  --introspect --introspect-json sbom-python.cdx.json.introspection.json \
  -o sbom-python.cdx.json <project-dir>
```

The result carries 4 components with `evidence.occurrences` (locations,
lines, symbols and offsets), 4 with `evidence.callstack` frames, and one
SaaSBOM provenance annotation whose subject is the application purl.

The second annotation on the BOM comes from a second run over the same
project with the BOM audit and one always-firing custom rule:

```bash
cdxgen -t python --bom-audit --bom-audit-rules-dir <rules-dir> \
  -o audit-only.cdx.json <project-dir>
```

The rules directory held one YAML file:

```yaml
- id: REC-001
  name: "Recording fixture rule"
  description: "An always-firing rule used to record the bom-audit annotation shape."
  severity: low
  category: recording
  condition: "true"
  message: "The recording rule fired for this BOM."
```

cdxgen writes that finding as a document annotation whose subject is the BOM
serial number, with the `cdx:audit:*` facts rendered into the text as a
markdown table and no separate `properties` array. The same run also wrote
predictive audit annotations (one per audited package, subjects are purls,
`cdx:audit:target:purl` and its siblings in the text table); they exercise
the same subject-purl reading as the SaaSBOM annotation and were not kept.

cdxgen 13.9.0 drops the bom-audit annotations when `--profile research`
runs its evidence pass after the audit, so the audit ran as its own pass
and its annotation was copied in with the subject set to the kept BOM's
serial number. Nothing else on the annotation was changed.

## What was cut

- The `formulation` section (166 KB of workflow steps), the `dependencies`
  graph, `citations` and `services` sections: the adapter reads
  `metadata`, `components` and `annotations` only.
- Of the 12 components, five transitive Flask dependencies without any
  evidence (MarkupSafe, Jinja2, itsdangerous, click, blinker) were cut. The
  seven kept components are unchanged as recorded: the four carrying
  occurrences and callstacks, two without evidence, and the application.
- In the introspection report, `bom.path` was rewritten from the recording
  directory's absolute path to the bare file name. Nothing else was
  changed; every kept value is what cdxgen printed.

The recordings carry no other absolute paths, usernames or hostnames.

## The Kotlin recording with kosi properties

`sbom-kotlin-kosi.cdx.json` is a cdxgen 13.9.0 research-profile BOM over a
one-file Kotlin JVM project (`src/main/kotlin/demo/App.kt`, with
`com.squareup.okhttp3:okhttp` 4.12.0 as its only dependency) whose code
reads a line from standard input and passes it to okhttp's
`Request.Builder.url` and to `Runtime.exec`. The project was written for
the recording and is not carried here. cdxgen ran kosi 4.3.1 from
`@cdxgen/cdxgen-plugins-bin-darwin-arm64` 4.3.1, with Gradle 9.6.1 and the
okhttp jar already in the local Gradle cache:

```bash
cdxgen -t kotlin --profile research -o sbom-kotlin.cdx.json <project-dir>
```

The run-level `cdx:kosi:*` properties (the kosi and Kotlin versions, slice
and source coverage counts, the root's data-flow facts and the five
`cdx:kosi:diagnostic:*` counts) are on the root component, okhttp carries
`cdx:kosi:reachableFromRoots`, two occurrences and a two-frame callstack,
and the one service is the outbound okhttp call kosi found, described by
`cdx:kosi:service:*` properties. The run reported no `cdx:kosi:degraded`,
no `cdx:kosi:diagnosticErrors` and no API endpoint; the tests add those in
the shapes `lib/ecosystems/kosi.js` writes.

What was cut: every component except okhttp (27 Kotlin toolchain and
transitive jars without evidence), the `dependencies`, `formulation`,
`annotations` and `citations` sections and `metadata.properties`, okhttp's
`evidence.identity` and `cdx:gradle:GradleRootPath` property, and the root
component's `buildFile`, `projectDir` and `rootDir` properties: those were
the only values holding absolute paths of the recording machine. Every kept
value is what cdxgen printed.
