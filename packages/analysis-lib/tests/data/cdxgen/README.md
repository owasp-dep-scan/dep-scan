# cdxgen recordings

A real cdxgen 13.9.0 BOM and its build-introspection report, kept as adapter
test input. The tests in `test_evidence_cdxgen.py` read them.

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
A second run added `--bom-audit` (once plain, once with
`--bom-audit-categories ai-inventory`); cdxgen 13.9.0 attaches its audit
annotations to an internal copy and the written BOM carried none, so the
committed recording is the plain run and the bom-audit annotation shape is
covered by a test that injects it.

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
