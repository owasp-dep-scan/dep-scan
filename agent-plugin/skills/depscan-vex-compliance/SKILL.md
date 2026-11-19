---
name: depscan-vex-compliance
description: 'Produces and checks vulnerability disclosure documents from a dep-scan scan: the CSAF VEX document a scan exports with --csaf, the CycloneDX VDR a scan writes, and depscan validate''s schema verdict on either. Use when asked to produce a VEX or CSAF document, to check a VDR or CSAF file is valid, or when a compliance question needs a machine-readable disclosure. Load it before writing any VEX-producing depscan command.'
---

# VEX and CSAF documents from a dep-scan

Use this skill when the deliverable is a disclosure document rather than a
fix list. To produce the scan these documents come from, use
`depscan-scan` or `depscan-container-image`.

The rules in [reference/safety.md](../../reference/safety.md) apply, in
particular: a document states what the scan assessed, and you never edit a
statement to `not_affected` beyond what the evidence says.

## Plugin settings

| Setting | Value | When not set |
| --- | --- | --- |
| Vulnerability database directory | `${user_config.vdb_home}` | dep-scan's own default |

## Produce a CSAF VEX document

```bash
depscan scan /absolute/path/to/project --csaf --format json -o /absolute/path/to/reports
```

The scan writes `sbom-<type>.csaf.json` next to the BOM in the reports
directory (CSAF 2.1 by default; `--csaf-version 2.0` selects the older
version). The document's vulnerabilities carry the findings the scan
matched, and their product status comes from the scan's reachability
result:

| Reachability result | CSAF product status |
| --- | --- |
| The package is in the scan's reached set | `known_affected` |
| The reached set is not empty, and this package is not in it | `known_not_affected`, flag `vulnerable_code_not_in_execute_path` |
| The reached set is empty (no reachable flows, `--profile quick`, `--reachability-analyzer off`) | `under_investigation` |

So dep-scan does write `known_not_affected` by itself, on the basis "not in
the reached set of this analyzer". Before the document goes anywhere, read
`product_status.known_not_affected` in each vulnerability and tell the user
which packages it lists and what that rests on: the analyzer named in the
manifest, its root set, and the stages that completed. When the user wants
no reachability-based statements in the disclosure, re-run with
`--reachability-analyzer off`, which leaves every matched package
`under_investigation`.

A target without a BOM cannot carry the export: a purl scan with `--csaf`
exits 0 but skips the export with a stderr warning, because there is no BOM
to name the output and build the product tree from. Run `--csaf` against a
source, container or BOM target, never against a purl.

## Produce a CycloneDX VDR

Every completed scan of a source, container or BOM target writes the
CycloneDX VDR next to the BOM in the reports directory, named after it:
`sbom-<type>.vdr.json` (for example `sbom-docker.vdr.json`), or
`depscan-universal.vdr.json` for a BOM directory. A purl scan writes no
VDR.

## Validate a document

```bash
depscan validate /absolute/path/to/reports/sbom-universal.csaf.json --format json
depscan validate /absolute/path/to/reports/sbom-universal.vdr.json --format json
```

The results document carries one `{"file", "format", "valid", "errors"}`
entry per file. An invalid document is a result, not a verb failure: the
verb exits 1 when any document is invalid and the errors name the schema
violations. Fix the producing scan, never the document by hand; a
hand-edited disclosure no longer reflects the scan that produced it.

## Decision table

| The user needs | Command |
| --- | --- |
| A machine-readable disclosure of this scan | `depscan scan <project> --csaf --format json -o <reports>` |
| CSAF 2.0 instead of 2.1 | Add `--csaf-version 2.0` |
| The CycloneDX VDR of an existing scan | Read `sbom-<type>.vdr.json` from the scan directory, or `depscan report <scan-dir> --format json` |
| No reachability-based statements | Add `--reachability-analyzer off` |
| Is this CSAF or VDR file valid | `depscan validate <file> --format json` |

## What this proves and what it does not

A valid document proves its structure matches the CSAF or CycloneDX schema.
It does not prove the statements inside are true beyond the scan: each
status reflects what the scan assessed as of the database date, and a
`known_not_affected` from dep-scan means "not in the reached set", which is
as strong as the analyzer and root set behind it. Never edit a statement to
`not_affected` by hand; a `not_affected` claim needs evidence that covers
the vulnerable function and the deployed entry points, and saying plainly
what the evidence covers is the correct disclosure.

## After the document

- Explain the findings behind it: `depscan-triage`
- Check the database the statements rest on: suggest `/depscan:depscan-vdb`
