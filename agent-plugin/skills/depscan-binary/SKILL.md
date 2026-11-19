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

blint is run directly because dep-scan's binary check reports the BOM
only, not blint's findings. The rules in
[reference/safety.md](../../reference/safety.md) apply: a binary from an
untrusted source is still untrusted input; never execute it, and never
run its installer.

## Plugin settings

| Setting | Value | When not set |
| --- | --- | --- |
| Vulnerability database directory | `${user_config.vdb_home}` | dep-scan's own default |

## Which blint

dep-scan's `ext` extra installs blint 3.2.x. blint 4.0.0 and newer add the
analysis coverage report, `capabilities`, `diff`, ELF link closure and a
parse cache. Read the version first
(`python -c "import importlib.metadata as m; print(m.version('blint'))"`
in the environment that runs blint) and use only what that version has.
On blint 4, `blint capabilities --json` prints the catalog of checks and
reviews the installed blint runs, which is the list to quote when the user
asks what was checked.

## The security review

```bash
mkdir -p /absolute/path/to/blint-reports
blint -i /absolute/path/to/binary -o /absolute/path/to/blint-reports --no-banner
```

Outputs in the reports directory: the binary's `<name>-metadata.json`
(format, sections, linked libraries, signatures on Windows),
`reviews.json` (behaviour reviews: dynamic code loading, weak crypto,
embedded secret shapes), `findings.json` when a hardening rule fired (for
example missing PIE or NX), and `blint-output.html`. A missing
`findings.json` means no hardening rule fired, not that none ran. Add
`--suggest-fuzzable` for `fuzzables.json`, and `--disassemble` for
function-level call graphs (it needs the extended install,
`blint[extended]`, and takes longer).

blint 4 also writes `analysis-coverage.json`: what blint could and could
not analyse. Read it before summarising; what blint left out is not
assessed. On blint 3.2.x there is no coverage report, so the coverage of
the review is unknown and the summary says so.

## What each artifact kind delivers

| Artifact | blint gives | Detection-only |
| --- | --- | --- |
| ELF, Mach-O, PE (+.NET), WASM | hardening findings, behaviour reviews, metadata, exports, embedded runtimes | packed or obfuscated binaries: the packer is named, its payload is not unpacked |
| Windows drivers | vulnerable-driver list matches, HVCI and IOCTL handler review | |
| Authenticode-signed files | signature and chain analysis | |
| MSI, MSIX, CAB, ClickOnce, nupkg, VBA | contents and macro review | NSIS and Inno installers: detection only, not full review |
| Apple .ipa/.app/.framework | entitlements, provisioning, privacy manifest (see `depscan-mobile-app`) | FairPlay-encrypted IPAs |

## Component identification

`blint sbom` produces a CycloneDX BOM of the binary's components, which
`depscan scan --target-kind bom <bom-file>` matches against the
vulnerability database. Global options such as `--no-banner` go before the
subcommand.

```bash
blint --no-banner sbom -i /absolute/path/to/binary \
  -o /absolute/path/to/blint-reports/binary.cdx.json
depscan scan --target-kind bom /absolute/path/to/blint-reports/binary.cdx.json --format json -o /absolute/path/to/reports
```

Exact identification at scale uses blintdb (`--use-blintdb`), and
`blint db --download` fetches it: tens of gigabytes. blint turns blintdb
on by itself when `blint.db` already exists under `BLINTDB_HOME`, and it
downloads the database when `--use-blintdb` or `USE_BLINTDB` is set and
the file is missing, or when `BLINTDB_REFRESH` is set. So never pass
`--use-blintdb` or set those variables unless the file exists or the user
agreed to the download, state the size, and do not start it without the
user's consent; without blintdb,
identification rests on exports, embedded signatures and link metadata,
and the summary says which method produced each component.

For stripped binaries, `blint canonicalize` normalises C++, Rust and Swift
symbols, and `blint callgraph-match` compares a stripped binary's call
graph against one built from source (`--profile precision`, `balanced`
or `recall`). Both are in blint 3.2.x and 4.

## Linked libraries on ELF (blint 4)

With blint 4, setting `BLINT_RESOLVE_LINK_CLOSURE=1` resolves each ELF's
needed libraries against a root filesystem (`BLINT_LINK_ROOT`, plus
`BLINT_LINK_SEARCH_PATH` for extra directories) and records the result in
the metadata's `link_closure`: missing libraries, the search paths used,
and unused or undeclared dependencies. blint 3.2.x ignores these variables.

## What this proves and what it does not

A blint review proves what the format and rules could see statically. It
does not prove a binary is safe to run: it cannot see what packing hides,
what a runtime loads dynamically, or what a driver does with hardware.
Hardening findings are barrier evidence; behaviour reviews are leads.
Name the rule ids in the answer and mark the coverage gaps not assessed.

## After the review

- Match the component BOM against advisories: the `depscan scan` above
- Compare two builds' hardening: `depscan-change-risk`
- Review a container's trust store: `depscan-container-image`
