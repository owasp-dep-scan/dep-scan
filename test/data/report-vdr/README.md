# A saved scan cut for the report-verb rendering tests

This directory is a cut of a saved dep-scan scan directory, trimmed to what
the report rendering tests read: the VDR entry, the findings file and the
manifest that makes the directory load as a scan. The tests render it with
`depscan report` and assert on the table it prints.

## Where the scan came from

The scan is the `default` run over the cdx-proto checkout at commit
`cdb2fc91fd208d5249bc7bca5b3d13142da72080` (a dirty work tree), scanned with
dep-scan 7.0.0a2 as a universal source scan with the generic profile and the
`pcu` search order. The parsed options of that run survive in the manifest's
`options` object. The original directory lives outside this repository with
the other exercise scans.

## What was cut

- `sbom-universal.vdr.json` keeps the scan's one vulnerability entry
  (`CVE-2026-118764` on `pkg:npm/minimatch@10.2.6`) with the fields the
  rendering reads: the `affects` versions that carry the fix, the ratings,
  and the `depscan:insights` and exploitability properties. The long
  `detail`, the `references` and the `advisories` were dropped, and the
  document metadata was reduced to a timestamp.
- `depscan.findings.json` keeps the finding built from that entry, without
  its `references` array.
- `depscan.manifest.json` keeps the recorded stages, options and database
  state. The `inputs` path was rewritten to the relative `cdx-proto`, the
  `tools` list was reduced to the cdxgen entry, and `files` lists only the
  two files this cut ships, with digests recomputed over the trimmed bytes.
  The BOM the inventory stage names is not shipped; a load treats a missing
  inventory output as absent, which the report verb does not render.

Every file is compact JSON on one line. Nothing in the cut names an absolute
path, a user or a host.
