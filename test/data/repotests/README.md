# Trimmed projects from the pinned repotests data

These two directories come from the pinned repotests scan data that the
performance comparisons use. They keep the input files a BOM-directory scan
reads: the BOM, atom's own slices for the atom-only project, and dosai's raw
dataflows report for the .NET project.

- `dejacode/` was produced with cdxgen 13.8.0 and atom 4.0.2 over the
  dejacode project. It carries no language-tool raw report, so every reached
  purl comes from atom: the three `python-reachables.slices*` files.
- `dotnet-podcasts/` was produced with cdxgen 13.9.0 and dosai 5.0.0 over the
  dotnet-podcasts project. `csharp-data-flow.slices.json` is dosai's raw
  dataflows report, the cdxgen evinse name, schema 5.1.0.

## How the fixtures were trimmed

The pinned files carry machine-specific paths from the run that generated
them, and the usage slices are far larger than a test needs, so each file was
rewritten as follows:

- `sbom-python.cdx.json`: the `path+file:///home/runner/...` bom-refs of the
  embedded workspace crates were rewritten to `path+crates/...` form. The
  components themselves are unchanged.
- `python-reachables.slices*.json`: the first flows of each file plus every
  later flow that introduces a purl the file has not yet shown, capped at 20
  flows. Every distinct reached purl of the original file is still present.
- `python-usages.slices.json`: the first 40 `objectSlices` entries and the
  first 10 `userDefinedTypes`.
- `python-callsites.slices.json`: the first 40 `callsites` entries.
- `csharp-data-flow.slices.json`: `Metadata.InputPath` and
  `Metadata.InputFullPath` were replaced with the project name. Everything
  else is the recorded report.

No other content was changed. The stale converted
`dotnet-reachables.slices.json` of the pinned directory was left out: it is
not an input any more.
