# A saved binary scan cut for the report-verb rendering tests

This directory is a cut of a saved dep-scan binary scan, trimmed to what
the binary review rendering tests read: the findings file with its one
binary-hardening finding, blint's coverage report and the manifest that
makes the directory load as a scan. The tests render it with
`depscan report` and assert on the table it prints.

## Where the scan came from

The scan is the `binary-golem` run of the exercise: dep-scan 7.0.0a2 over
the golem project's released `golem-darwin-arm64` binary (a Mach-O arm64
executable) as a binary source scan with the binary check on, reachability
off. The parsed options of that run survive in the manifest's `options`
object. The original directory lives outside this repository with the
other exercise scans.

## What was cut

- `depscan.findings.json` is the scan's own file, unchanged: it holds the
  one `binary-hardening` finding blint's `CHECK_UNUSED_DEPENDENCIES`
  check produced, about `libresolv.9.dylib` never being used.
- `analysis/blint/analysis-coverage.json` is blint's own coverage report,
  unchanged: one unit attempted and succeeded, none failed or skipped.
  The review's `findings.json` and `reviews.json` are not shipped; nothing
  the report verb renders reads them.
- `depscan.manifest.json` keeps the recorded stages, options and database
  state. The `inputs` path was rewritten to the relative
  `golem-darwin-arm64`, the `tools` list was reduced to the blint entry
  with its path dropped, and `files` lists only the two files this cut
  ships, with digests recomputed over the shipped bytes. The scan wrote no
  VDR (it found no vulnerabilities), which is why none is listed.

Nothing in the cut names an absolute path, a user or a host.
