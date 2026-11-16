# atom 4 slice fixtures

Recorded from a scan of dep-scan's own code at commit aba6104 (the `.git`
directory removed) with cdxgen 13.8.0 (`@cdxgen/cdxgen`, npm cache
`~/.cache/cdxgen-13.8.0`), which bundles atom 4.0.2 (chen 4.0.1, npm package
`@appthreat/atom` 4.0.2). The OpenAPI document was converted by atom-tools
1.0.5, which atom started from `--extract-endpoints`.

Command shape (paths shortened):

```
cdxgen -t python -o <reports>/sbom-python.cdx.json --profile research \
  --reachables-slices-file <reports>/python-reachables.slices.json \
  --usages-slices-file <reports>/python-usages.slices.json \
  --callsites-slices-file <reports>/python-callsites.slices.json \
  --introspect --introspect-json <reports>/sbom-python.cdx.json.introspection.json \
  <dep-scan clone>
```

with `ATOM_TOOLS_WORK_DIR=<reports>` and `ATOM_TOOLS_OPENAPI_FILENAME=
python-openapi.json` in the environment. The full run produced 295 reachable
flows. dep-scan reads the reachables slice and the OpenAPI document; the
usages slice goes only to cdxgen and atom-tools, so it is not kept here.

## How the files were cut

- `python-reachables.slices.json`: five whole flow objects kept verbatim out
  of the 295: two whose CALL/LITERAL nodes carry callee purls appended in
  their `tags` string (the atom 4 `withPurls` order, purls first and the
  semantic tag last), one whose IDENTIFIER node interleaves a purl, a
  semantic tag and a second purl, one plain flow, and one flow with no
  purls at all.
- `python-openapi.json`: the document envelope kept verbatim with eight
  whole path objects, including two whose `x-atom-usages` carries both
  `call` and `target`; atom-tools 1.x writes `target` line numbers as a
  list.
- `sbom-python.cdx.json`: the BOM cut down to the four components the kept
  flows reach (rich, custom-json-diff, quart at both versions). The
  components are verbatim except that `evidence.callstack` was dropped and
  `formulation`, `annotations`, `citations` and `services` were removed
  from the document; the metadata was cut back to its `tools` entry.

No absolute paths, usernames or hostnames remain in any of the files; file
names inside the slices are repository-relative paths of the scanned
dep-scan checkout.
