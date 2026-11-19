---
name: depscan-vex-compliance
description: 'Produces and checks vulnerability disclosure documents from a dep-scan scan: the CSAF VEX document a scan exports with --csaf, the CycloneDX VDR a scan writes, and depscan validate''s schema verdict on either. Use when asked to produce a VEX or CSAF document, to check a VDR or CSAF file is valid, or when a compliance question needs a machine-readable disclosure. Load it before writing any VEX-producing depscan command.'
---

# VEX and CSAF documents from a dep-scan

Use this skill when the deliverable is a disclosure document rather than a
fix list. To produce the scan these documents come from, use
`depscan-scan` or `depscan-container-image`.

The rules in [reference/safety.md](../../reference/safety.md) apply, in
particular: a document states what the scan assessed, and nothing in it is
ever upgraded to `not_affected` beyond what the evidence says.

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
matched.

A target without a BOM cannot carry the export: a purl scan with `--csaf`
exits 0 but skips the export with a stderr warning, because there is no BOM
to name the output and build the product tree from. Run `--csaf` against a
source, container or BOM target, never against a purl.

## Produce a CycloneDX VDR

Every completed scan writes `depscan.vdr.json` in the reports directory:
the CycloneDX VDR with the scan's findings and their coverage state.

## Validate a document

```bash
depscan validate /absolute/path/to/reports/sbom-universal.csaf.json --format json
depscan validate /absolute/path/to/reports/depscan.vdr.json --format json
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
| The CycloneDX VDR of an existing scan | Read `depscan.vdr.json` from the scan directory, or `depscan report <scan-dir> --format json` |
| Is this CSAF or VDR file valid | `depscan validate <file> --format json` |

## What this proves and what it does not

A valid document proves its structure matches the CSAF or CycloneDX schema.
It does not prove the statements inside are true beyond the scan: the
`analysis_state` of each vulnerability reflects what the scan assessed as
of the database date. Never edit a statement to `not_affected`; the
evidence a `not_affected` claim needs (reachability of the vulnerable
function from the deployed entry points) is more than dep-scan's scan
output carries, and saying so plainly is the correct disclosure.

## After the document

- Explain the findings behind it — `depscan-triage`
- Refresh the database the statements rest on — `depscan-vdb`
