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

The audit ran as its own pass for two reasons: the earlier attempts that
combined `--profile research` with `--bom-audit` produced BOM audit findings
(the rule fired, the table printed) but the evidence analysis that the
research profile runs afterwards rewrote the output BOM from an earlier
snapshot, so the written file lost the audit annotations; and a plain run
keeps them. The annotation's subject named that pass's serial number, so it
was rewritten to the serial number of the research run's BOM that the
fixture keeps, which is what cdxgen would have written had the rule fired
in that pass. Nothing else on the annotation was changed.

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
