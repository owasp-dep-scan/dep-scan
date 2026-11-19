# dep-scan command surface

dep-scan publishes eleven verbs. Every verb accepts `--format json` and
then writes exactly one JSON document to stdout; logs, progress and tables
go to stderr. Pick the right entry point before reaching for flags.

## Scanning and reading

| Command | Use for | Document in json format |
| --- | --- | --- |
| `depscan scan [target]` | Scan a source directory, container image, rootfs, BOM, BOM directory, purl or binary | `{"scans": [entry, ...]}`, one entry per target, each with `manifest` and `findings` |
| `depscan report <scan-dir>` | Read a saved scan directory back | `{"scanDir", "manifest", "findings"}` |
| `depscan validate <file>` | Validate a CSAF VEX or CycloneDX VDR/VEX document | `{"results": [{"file", "format", "valid", "errors"}]}` |

A scan entry whose `manifest.stages` carry a failed or skipped stage is not
a clean scan; see [safety.md](safety.md).

## The vulnerability database

| Command | Use for | Document |
| --- | --- | --- |
| `depscan vdb info` | The local database and shard store state, staleness included | the vdb info document |
| `depscan vdb path` | The `VDB_HOME` directory | `{"path": "..."}` |
| `depscan vdb download --flavor <flavor>` | Download a flavor: `full`, `app-only`, `app-extended`, `app-10y`, `app-10y-extended` | `{"image", "marker"}` |

Distro package matching (apk, deb, rpm) needs the `full` flavor;
app-only is enough for application packages. Downloads are consent-first;
see [safety.md](safety.md).

## Diagnosis

| Command | Use for | Document |
| --- | --- | --- |
| `depscan doctor` | The tools, data and capabilities dep-scan sees on this machine, with a status per capability | the doctor report |
| `depscan version` | The dep-scan version and every tool's version | `{"version", "tools"}` |
| `depscan schema [name]` | The published schemas, or one schema document | the listing or the schema |

## Agents and servers

| Command | Use for | Document |
| --- | --- | --- |
| `depscan mcp` | The MCP server over stdio (ten read tools and a dry-run scan tool) | no document: stdout is the protocol channel |
| `depscan serve` | dep-scan as an HTTP server | `{"serving": {"host", "port", "url"}}` |
| `depscan config show` | The effective scan options and where each came from | `{"options": {...}}` |
| `depscan help [verb]` | The help text as a document | `{"help": "..."}` |

`depscan mcp` without the `mcp` extra exits 4 with a message naming
`owasp-depscan[mcp]`; install the extra with
`pip install "owasp-depscan[mcp]"` (or the environment's package manager),
with the user's consent, and never pass `--allow-scans`.

## Options worth knowing

| Option | Effect |
| --- | --- |
| `--checks <list>` | Comma-separated subset of `vulnerabilities, reachability, license, supply-chain, binary, memory-safety, mobile, code, crypto`. An explicit list defines the whole optional set; vulnerabilities always runs. |
| `--profile <p>` | `quick`, `ci`, `deep`, `research` or `offline`; explicit options win over the profile. |
| `--target-kind <kind>` | Force the kind: `purl, git, container, bom, bom-dir, binary, android, ios, source, firmware` (ios and firmware are refused). |
| `-o, --reports-dir <dir>` | Where the scan writes its manifest, findings, BOM and reports. |
| `--explain` | Add the explanation of the analysis to the report and stderr. |
| `--csaf` | Export a CSAF VEX document next to the BOM (`<bom-base>.csaf.json`). |
| `--csaf-version {2.0,2.1}` | The CSAF version; default 2.1. |
| `--cdxgen-args "<args>"` | Extra arguments for the cdxgen run a scan performs. |
| `CDXGEN_CMD` | Environment variable naming the cdxgen command; dep-scan needs cdxgen 13.8.0 or newer. |
| `VDB_HOME` | Environment variable naming the vulnerability database directory. |

Exit codes: 0 success, 1 could not run, 2 usage error, 4 capability
unavailable. Findings never change the exit code. The full contract, the
error document and the paths rule are in
[the agents page](https://depscan.readthedocs.io/agents).

## The sibling tools

The skills reach these directly for what dep-scan does not surface yet;
[tools.md](tools.md) records how each is found and versioned, and what to
say when one is missing. Flag order matters for the Go tools: flags go
before the positional path.

| Tool | Command | Verified output |
| --- | --- | --- |
| `golem` | `golem analyze -callgraph rta -roots main -dataflow security -reachable-symbols <file> -o <out.json> <path>` | call graph with `reachableFromRoots`, `minDepth` and `rootIds`; `securitySignals`; `crypto.*`; `apiEndpoints` |
| `rusi` | `rusi analyze --dir <path> --backend stable -o <out.json>` | `security_signals` (unsafe-code, native-interop), purl and position |
| `rusi` | `rusi cryptos --dir <path> -o <out.json>` | the Rust crypto inventory |
| `dosai` | `dosai dataflows --path <path> --o <out.json>` | `ExploitChains`, `AttackSurface`, `SanitizedFlows`, `PackageReachability` |
| `dosai` | `dosai methods --path <path> --o <out.json>` | `Reachability`, `DeadCode`, `SecurityFindings`, `Services`, `EntryPoints` |
| `dosai` | `dosai crypto --path <path> --format cyclonedx --o <out.json>` | a CycloneDX CBOM |
| `dosai` | `dosai diff --old <a.json> --new <b.json> --o <diff.json>` | `AddedEntryPoints`, `AddedPackages`, `AddedWeaknesses`, statistics of both sides |
| `atom` | `atom memory-safety -l c --auto-defines --min-confidence medium --slice-outfile <f> <path>` | findings with rule id, CWE, confidence and flow (JSON; `--format sarif` for SARIF 2.1.0) |
| `atom` | `atom reachables -l <lang> --reuse-atom --sink-tag memory-safety --slice-outfile <f> <path>` | the defects entry points reach |
| `atom-tools` | `atom-tools ingest -i <reports> -o <unified.json>` | the unified flow model across engines |
| `atom-tools` | `atom-tools attack-surface -i <unified.json> -o <f> -f json` | exposure tiers with entry points |
| `atom-tools` | `atom-tools drift --old <a.json> --new <b.json> -o <f> -f json` | `AddedFlows`, `AddedEntryPoints`, `RiskDelta` |
| `atom-tools` | `atom-tools crypto-reach -i <engine report> -o <f>` | crypto joined to reach, per engine granularity |
| `blint` | `blint -i <artifact> -o <dir> --no-banner` | findings, reviews, metadata, coverage |
| `blint` | `blint sbom -i <artifact> -o <dir> --deep --no-banner` | the component BOM with per-ABI native libraries and the DEX callgraph |
| `blint` | `blint canonicalize --json <names>` | normalised symbols for stripped binaries |
| `blint` | `BLINT_RESOLVE_LINK_CLOSURE=1 BLINT_LINK_ROOT=<rootfs> blint -i <dir> -o <reports> --no-banner` | the NEEDED and imported libraries per binary in the metadata |
| `trustinspector` | `trustinspector-cdxgen-<platform> rootfs <dir>` | trust materials with hashes and trust domains |
| `trivy-cdxgen` | `trivy-cdxgen-<platform> rootfs --output <f.cdx> <dir>` | the OS-package BOM with installed files |
| `vdb` (v7 CLI) | `vdb --search-text <text>` / `--search-alias <id>` / `--search-symbol <s>` / `--list-malware` | advisory answers from the store |
| `vdb` (v7 CLI) | `vdb db status --json` | per-shard age, coverage and `needs_update` |
| `cdx-audit` | `cdx-audit --bom <bom.json> --direct-bom-audit --report json` | rule-pack findings with rule ids; exit 3 on fail severity |

Consent-gated shapes the skills name and this table deliberately omits:
dosai `--restore`/`--build`, the rusi `compiler` backend, atom
`--fetch-deps`, cdx-audit's predictive mode, `blint db --download` and
cdxgen's `tracebom` and `hbom --sensitive`. See
[safety.md](safety.md).
