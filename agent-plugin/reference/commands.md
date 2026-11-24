# dep-scan commands

dep-scan publishes eleven verbs. Every verb except `mcp` (and the `config`
group itself, whose `show` and `init` subcommands take it) accepts
`--format json` and then writes exactly one JSON document to stdout; logs,
progress and tables go to stderr. Pick the right entry point before
reaching for flags.

## Scanning and reading

| Command | Use for | Document in json format |
| --- | --- | --- |
| `depscan scan [target]` | Scan a source directory, container image, rootfs, BOM, BOM directory, purl or binary | `{"scans": [entry, ...]}`, one entry per target, each with `manifest` and `findings` |
| `depscan report <scan-dir>` | Read a saved scan directory back | `{"scanDir", "manifest", "findings"}` |
| `depscan validate <file>` | Validate a CSAF VEX or CycloneDX VDR/VEX document | `{"results": [{"file", "format", "valid", "errors"}]}` |

A scan entry with any stage in `manifest.stages` that is not `completed`
(failed, skipped or not-assessed), or with an expected stage missing, is
not a clean scan; see [safety.md](safety.md).

## The vulnerability database

| Command | Use for | Document |
| --- | --- | --- |
| `depscan vdb info` | The local database and shard store state, staleness included | the vdb info document |
| `depscan vdb path` | The `VDB_HOME` directory | `{"path": "..."}` |
| `depscan vdb download --flavor <flavor>` | Download a flavor: `full`, `full-extended`, `full-2y`, `full-2y-extended`, `full-10y`, `full-10y-extended`, `app-only`, `app-extended`, `app-2y`, `app-2y-extended`, `app-10y`, `app-10y-extended` | `{"image", "marker"}` |

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
| `depscan mcp` | The MCP server over stdio: ten tools, nine that read and a `run_scan` that only plans a scan unless the person starting the server passed `--allow-scans` | no document: stdout is the protocol channel; `--format` is refused |
| `depscan serve` | dep-scan as an HTTP server | `{"serving": {"host", "port", "url"}}` |
| `depscan config show` | The effective scan options and where each came from | `{"options": {...}}` |
| `depscan config init` | Write `./depscan.toml` with the effective scan options (a file write: ask first) | `{"written": "..."}` |
| `depscan help [verb]` | The help text as a document | `{"help": "..."}` |

`depscan mcp` without the `mcp` extra exits 4 with a message naming
`owasp-depscan[mcp]`; install the extra with
`pip install "owasp-depscan[mcp]"` (or the environment's package manager),
with the user's consent, and never pass `--allow-scans`.

## Options worth knowing

| Option | Effect |
| --- | --- |
| `--checks <list>` | `all`, or a comma-separated subset of `vulnerabilities, reachability, license, supply-chain, binary, memory-safety, mobile, code, crypto`. An explicit list defines the whole optional set; vulnerabilities always runs. A named check this machine cannot run stops the scan with exit 4 before any work; `all` never stops it and records each unavailable check as not assessed instead. |
| `--profile <p>` | `quick`, `ci`, `deep`, `research` or `offline`; explicit options win over the profile. A profile's checks are gated like named checks, so `--profile ci` exits 4 on a machine without cdxgen 13.8.0 or newer. |
| `--target-kind <kind>` | Force the kind: `purl, git, container, bom, bom-dir, binary, android, ios, source, firmware` (ios and firmware are refused). |
| `-o, --reports-dir <dir>` | Where the scan writes its manifest, findings, BOM and reports. |
| `--explain` | Add the explanation of the analysis to the report and stderr. |
| `--csaf` | Export a CSAF VEX document next to the BOM (`<bom-base>.csaf.json`). |
| `--csaf-version {2.0,2.1}` | The CSAF version; default 2.1. |
| `--cdxgen-args "<args>"` | Extra arguments for the cdxgen run a scan performs, shell-quoted as one string. `--exclude 'trees/**'` entries reach cdxgen's own walk (one `--exclude` per tree, patterns anchored at the scanned root) and keep non-product trees out of the BOM, and dep-scan applies them to its own binary-review and language-tool walks too; container files under an excluded tree add no image pulls. |
| `CDXGEN_CMD` | Environment variable naming the cdxgen command; dep-scan needs cdxgen 13.8.0 or newer. |
| `CDXGEN_TIMEOUT_MS` | Environment variable for cdxgen's own time budget; 30 minutes by default. A cdxgen failure names the budget that was in effect, and a scan whose inventory is slow (an image-pulling tree, for example) raises it rather than cutting the tree. |
| `VDB_HOME` | Environment variable naming the vulnerability database directory. |

Exit codes: 0 success, 1 could not run, 2 usage error, 4 capability
unavailable. Findings never change the exit code. The full contract, the
error document and the paths rule are in
[the agents page](https://depscan.readthedocs.io/agents).

## The sibling tools

The skills run these directly for what dep-scan does not report yet;
[tools.md](tools.md) records how each is found and versioned, and what to
say when one is missing. Every command below ran against a pinned test
corpus before it was published. golem reads the project from `-dir` and
ignores positional arguments; blint's global options go before its
subcommand.

| Tool | Command | Verified output |
| --- | --- | --- |
| `golem` | `CGO_ENABLED=0 GOFLAGS=-mod=readonly golem analyze -dir <path> -callgraph rta -roots main -reachable-symbols <file> -include-stdlib -out <out.json>` | `callGraph.reachability.nodes[]` (`reachableFromRoots`, `minDepth`, `rootIds`), witness paths in `callGraph.reachability.paths[]`, `securitySignals`, `apiEndpoints` |
| `golem` | `CGO_ENABLED=0 GOFLAGS=-mod=readonly golem analyze -dir <path> -dataflow crypto -out <out.json>` | `crypto.findings`, `libraries`, `operations`, `materials`, `protocols` |
| `kosi` | `kosi analyze --dir <path> --backend resolved --roots main --dataflow security --reachable-symbols <witness.json> --out <out.json>` | `callGraph.reachability[]` (`reached`, `distance`, `roots`); the witness file with paths per reached symbol |
| `rusi` | `rusi analyze --dir <path> --backend stable --out <out.json>` | `security_signals` (unsafe-code, native-interop), purl and position; `crypto` |
| `rusi` | `rusi cryptos --dir <path> --out <out.json>` | the Rust crypto report |
| `dosai` | `dosai dataflows --path <path> --o <out.json>` | `ExploitChains`, `AttackSurface`, `SanitizedFlows`, `PackageReachability`, `WeaknessCandidates` |
| `dosai` | `dosai methods --path <path> --o <out.json>` | `Reachability`, `DeadCode`, `SecurityFindings`, `Services`, `EntryPoints`, `AiComponents` |
| `dosai` | `dosai agent-context --path <path> --o <out.json>` | `Summary`, `EntryPoints`, `HighRiskSlices`, `ReachablePackages`, `SuggestedNextCommands` |
| `dosai` | `dosai crypto --path <path> --o <out.json>` (or `--format cyclonedx` for a CBOM) | `Assets`, `Operations`, `Materials`, `Protocols`, `Findings` |
| `dosai` | `dosai diff --old <a.json> --new <b.json> --o <diff.json>` | `Added*`/`Removed*` entry points, slices, weaknesses and packages, `RiskDelta` |
| `atom` | `atom memory-safety -l c --compile-commands <file> --min-confidence medium --no-build-tools --parse-report <f> -o <app.atom> --slice-outfile <f> <path>` | findings with `rule`, `cwe`, `confidence` and `flow` (JSON; `--format sarif` for SARIF 2.1.0) |
| `atom` | `atom reachables -l c --reuse-atom --no-build-tools --sink-tag memory-safety -o <the same app.atom> --slice-outfile <f> <path>` | the memory-safety defects entry points reach |
| `atom` | `atom reachables -l <lang> --no-build-tools --profile appsec --bom-file <bom> -o <app.atom> --slice-outfile <f> <path>` | reachable flows with package purls |
| `atom` | `atom callsites -l <lang> --no-build-tools --bom-file <bom> -o <app.atom> --reuse-atom --slice-outfile <f> <path>` | every call into each package, with file, line and purl |
| `atom-tools` | `atom-tools attack-surface -i <engine reports> -o <f> -f json` | `summary`, `tiers` in `tierOrder`, `coverage`, `diagnostics` |
| `atom-tools` | `atom-tools ingest -i <engine reports> -o <unified.json>` | the unified `flows`, `endpoints` and `packages` |
| `atom-tools` | `atom-tools drift --old <a.json> --new <b.json> -o <f> -f json --fail-on new-high` | `AddedFlows`, `AddedEntryPoints`, `RiskDelta`, `coverage`; exit 2 when a gate trips |
| `atom-tools` | `atom-tools graph -i <report> --metric chokepoints -f json -o <f>` | functions ranked by how many flows pass through them |
| `atom-tools` | `atom-tools crypto-reach -i <engine reports> -o <f>` | crypto joined to reach, per engine granularity |
| `blint` | `blint -i <artifact> -o <dir> --no-banner` | metadata, `reviews.json`, `findings.json` when a rule fired, `analysis-coverage.json` on blint 4 |
| `blint` | `blint --no-banner sbom -i <artifact> -o <bom.json> --deep` | the component BOM with per-ABI native libraries and the DEX call graph |
| `blint` | `blint canonicalize --json <names>` | normalised symbols for stripped binaries |
| `blint` (4.0+) | `blint diff <old> <new> --json` | hardening, findings, reviews and dependency deltas |
| `blint` (4.0+) | `blint capabilities --json` | the catalog of checks and reviews the installed blint runs |
| `blint` (4.0+) | `BLINT_RESOLVE_LINK_CLOSURE=1 BLINT_LINK_ROOT=<rootfs> blint -i <dir> -o <reports> --no-banner` | `link_closure` per ELF in the metadata |
| `trustinspector` | `trustinspector-cdxgen-<platform> rootfs <dir>` | trust materials with hashes and trust domains |
| `trivy-cdxgen` | `trivy-cdxgen-<platform> rootfs --output <f.cdx.json> <dir>` | the OS-package BOM with installed files |
| `vdb` | `vdb --search-text <text>` / `--search-alias <id>` / `--search-symbol <s>` | advisory answers from the store; empty on flavors without the extended metadata, which is not "nothing known" |
| `vdb` | `vdb db status --json` | per-shard age, coverage and `needs_update` |
| `cdx-audit` | `cdx-audit --bom <bom.json> --direct-bom-audit --report json -o <f>` | rule findings with rule ids; exit 3 at `--fail-severity` (default high) |

Consent-gated shapes the skills name and this table leaves out: dosai
`--restore`/`--build`, golem with `CGO_ENABLED=1`, the rusi `compiler`
backend, atom `--fetch-deps` and build tools, cdx-audit without
`--direct-bom-audit` (its predictive mode clones upstream), `blint db
--download`, and cdxgen's `tracebom` and `hbom --sensitive`. See
[safety.md](safety.md).
