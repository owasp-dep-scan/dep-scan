# Fixtures cut from the pinned repotests data

These two directories are small cuts of the repotests scan data that
`contrib/repotests/testdata.lock.json` pins. Each keeps the input files a BOM
directory scan reads, reduced to what the evidence wiring tests need, so the
tests run the real adapters and the real enrichment stage without the
multi-megabyte originals.

- `dejacode/` comes from the artifact the lock names for `dejacode`
  (`ghcr.io/owasp-dep-scan/depscan-testdata@sha256:0949977ae16f8b657db1290168f4c6999cd60308467c55a6a143ea4c631ace9d`),
  generated with cdxgen 13.8.0 and atom 4.0.2. It carries no language-tool
  report, so every reached purl comes from atom's reachables slices.
- `dotnet-podcasts/` comes from the artifact the lock names for
  `dotnet-podcasts`
  (`ghcr.io/owasp-dep-scan/depscan-testdata@sha256:48e23af58b2eb38b35bdafa9c86ed21302d88b8fa1c064775470c6e0b890c7a5`),
  generated with cdxgen 13.8.0 and dosai 5.0.0.
  `csharp-data-flow.slices.json` is dosai's raw dataflows report under the
  cdxgen evinse name; its `Metadata.SchemaVersion` is 5.1.0. The artifact's
  `dotnet-reachables.slices.json`, a converted slice no current scan reads,
  is left out.

Pull an artifact with `oras pull` and the digest above to recreate a cut.
Every file is rewritten as compact JSON on one line.

## How each file was cut

`dejacode/`:

- `python-reachables.slices.json`, `python-reachables.slices_1.json` and
  `python-reachables.slices_2.json`: for each purl a file's flows carry, in
  sorted order, the smallest flow (by its compact JSON size) that carries it
  is kept, unless a flow already kept carries that purl. The kept flows stay
  in file order and are unchanged. The three files keep 22 flows that reach
  the same 11 purls as the full files, and the atom adapter builds the same
  records for them as it does from the full files.
- `python-usages.slices.json`: the first 5 `objectSlices` entries and the
  first 2 `userDefinedTypes`.
- `python-callsites.slices.json`: the first 10 `callsites` entries.
- `sbom-python.cdx.json`: the components whose purl one of the kept flows
  carries, each reduced to `type`, `group`, `name`, `version`, `purl`,
  `bom-ref` and `scope`. The metadata keeps the timestamp, the tool names
  and versions, the root component and the lifecycle. Dependencies,
  formulation, annotations and every property are dropped; the formulation
  of the pinned BOM records the generating machine's paths.

`dotnet-podcasts/`:

- `csharp-data-flow.slices.json`: the sections the dosai adapter does not
  read (`Edges`, `MethodSummaries`, `Patterns`, `WeaknessCandidates` and
  `DangerousApiReachability`) are dropped, and `Nodes` keeps only the nodes
  a slice lists in `NodeIds`, `SourceId` or `SinkId`, or an exploit chain
  names as its source or sink node. `Metadata.InputPath` and
  `Metadata.InputFullPath` held the generating machine's checkout path and
  now hold the project name. Every other section is the recorded report,
  and the adapter builds the same 71 records from it as from the full report.
- `sbom-dotnet.cdx.json`: the components whose purl, without its version,
  appears in the cut report, reduced like the dejacode BOM's, with the same
  metadata.
