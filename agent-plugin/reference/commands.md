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
