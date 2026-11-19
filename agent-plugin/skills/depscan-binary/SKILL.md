---
name: depscan-binary
description: 'Reviews executables, installers and drivers with blint: the security review with hardening and behaviour rules, per-architecture metadata, component identification, and Windows driver and Authenticode analysis. Use when asked to analyse a binary, check a driver, review an installer, inspect an ELF or Mach-O, or answer whether a binary is safe to ship. Component identification at scale needs blintdb, which is a tens-of-gigabytes download and only runs with the user''s consent.'
---

# Review a binary with blint

Use this skill for artifacts, not source: executables, installers, drivers,
firmware-adjacent binaries. For an Android or iOS app use
`depscan-mobile-app`; for a whole container image use
`depscan-container-image` first and this skill for its unpackaged
binaries.

blint is reached directly because dep-scan's binary check needs a binary
target and reports the BOM only, not blint's findings. The rules in
[reference/safety.md](../../reference/safety.md) apply: a binary from an
untrusted source is still untrusted input; never execute it, and never
run its installer.

## Plugin settings

| Setting | Value | When not set |
| --- | --- | --- |
| Vulnerability database directory | `${user_config.vdb_home}` | dep-scan's own default |

## The security review

```bash
mkdir -p /absolute/path/to/blint-reports
blint -i /absolute/path/to/binary -o /absolute/path/to/blint-reports --no-banner
```

Outputs in the reports directory: `findings.json` (hardening and behaviour
findings with rule ids, e.g. missing PIE or NX), `reviews.json` (behaviour
reviews: dynamic code loading, weak crypto, embedded secret shapes), the
binary's `-metadata.json` (format, sections, linked libraries, signatures
on Windows), `fuzzables.json` (functions that take attacker-controlled
input shapes), and `analysis-coverage.json` (what blint could and could
not analyse). Review `analysis-coverage.json` before summarising: what
blint left out is not assessed, and the summary says so.

Add `--disassemble` for function-level call graphs; it needs the extended
install (`blint[extended]`) and takes longer. Add `--suggest-fuzzable` to
rank fuzzable functions.

## What each artifact kind delivers

| Artifact | blint gives | Detection-only |
| --- | --- | --- |
| ELF, Mach-O, PE (+.NET), WASM | hardening findings, behaviour reviews, metadata, exports, embedded runtimes | packed or obfuscated binaries: the packer is named, its payload is not unpacked |
| Windows drivers | vulnerable-driver list matches, HVCI and IOCTL handler review | |
| Authenticode-signed files | signature and chain analysis | |
| MSI, MSIX, CAB, ClickOnce, nupkg, VBA | contents and macro review | NSIS and Inno installers: detection only, not full review |
| Apple .ipa/.app/.framework | entitlements, provisioning, privacy manifest (see `depscan-mobile-app`) | FairPlay-encrypted IPAs |

## Component identification

`blint sbom -i <binary> -o <dir>` produces a CycloneDX BOM of the binary's
components, which `depscan scan --target-kind bom <bom-file>` matches
against the vulnerability database:

```bash
blint sbom -i /absolute/path/to/binary -o /absolute/path/to/blint-reports --no-banner
depscan scan --target-kind bom /absolute/path/to/blint-reports/sbom-binary-postbuild.cdx.json --format json -o /absolute/path/to/reports
```

Exact identification at scale uses blintdb:
`blint db --download` fetches the identification database, and it is tens
of gigabytes. State the size, and do not start it without the user's
consent; without blintdb, identification rests on exports, embedded
signatures and link metadata, and the summary says which method produced
each component.

For stripped ELF files, `blint canonicalize <name>` normalises C++/Rust
symbols and `blint callgraph-match` compares a stripped binary's call
graph against a source-built one (check `blint --help`; both need a blint
new enough to carry them).

## What this proves and what it does not

A blint review proves what the format and rules could see statically. It
does not prove a binary is safe to run: it cannot see what packing hides,
what a runtime loads dynamically, or what a driver does with hardware.
Hardening findings are barrier evidence; behaviour reviews are leads.
Name the rule ids in the answer and mark the coverage gaps not assessed.

## After the review

- Match the component BOM against advisories — the `depscan scan` above
- Compare two builds' hardening — `depscan-change-risk`
