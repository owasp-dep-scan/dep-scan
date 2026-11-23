# Finding and versioning the toolchain tools

The skills run sibling tools directly for what dep-scan does not report
yet. Most of them ship inside `@cdxgen/cdxgen-plugins-bin-<platform>`, not
with dep-scan and not on `PATH`, and a missing tool is a reported state,
never a reason to install anything without the user's consent.

## Where each tool comes from

| Tool | Ships in | Command variable |
| --- | --- | --- |
| golem, rusi, kosi, trustinspector, trivy-cdxgen | `@cdxgen/cdxgen-plugins-bin-<platform>` (installed with cdxgen) | `GOLEM_CMD`, `RUSI_CMD`, `KOSI_CMD`, `TRUSTINSPECTOR_CMD`, `TRIVY_CMD` (read by cdxgen); dep-scan reads `DEPSCAN_GOLEM_BINARY` and `DEPSCAN_RUSI_BINARY` |
| dosai | its own release (a .NET tool) | `DOSAI_CMD` |
| atom | the `@appthreat/atom` npm package | none |
| atom-tools, blint | dep-scan's `ext` extra (atom-tools 1.0.x, blint 4.1.x) | none |
| cdxgen, cdx-audit | the `@cyclonedx/cdxgen` npm package | `CDXGEN_CMD` for cdxgen |
| vdb | vulnerability-db, a dependency of dep-scan | none |

## The lookup order

For each tool, resolve in this order and record which one answered:

1. The command variable, when the tool has one (table above).
2. The environment that runs `depscan`: atom-tools, blint and vdb sit in
   the same `bin` (or `Scripts`) directory as the `depscan` script.
3. `PATH`.
4. The plugins package directory:
   `<npm prefix>/lib/node_modules/@cdxgen/cdxgen-plugins-bin-<platform>/plugins/`
   (`npm root -g` prints the parent), where `<platform>` is
   `darwin-arm64`, `darwin-amd64`, `linux-amd64`, `linux-arm64`,
   `linux-arm64-musl` or `windows-amd64`. golem, rusi and kosi sit at
   `plugins/<tool>/<tool>-<platform>`; trustinspector and trivy sit at
   `plugins/trustinspector/trustinspector-cdxgen-<platform>` and
   `plugins/trivy/trivy-cdxgen-<platform>`.
5. `depscan doctor --format json`: the `tools` array lists the analyzers
   dep-scan found, with a version where it could read one, and each
   capability lists the tools it is `missing`.

## Reading a version

| Tool | Version |
| --- | --- |
| cdxgen | `"$CDXGEN_CMD" --version` (or `cdxgen --version`) |
| golem, rusi | `<binary> --version`, or the report's `tool.version` |
| kosi | `<binary> --version` (a JSON line with `version` and the backends it carries) |
| dosai | `dosai --version`; it fails when the .NET runtime the release targets is missing, and on a newer runtime `DOTNET_ROLL_FORWARD=LatestMajor` runs it (record that you set it) |
| atom | `atom --version`; the usage line of `atom --help` lists the commands, and `memory-safety` and `callsites` need atom 4.0.2 or newer |
| atom-tools | `atom-tools --version` |
| blint | `python -c "import importlib.metadata as m; print(m.version('blint'))"` in blint's environment (the CLI has no `--version`); `diff`, `capabilities`, `analysis-coverage.json` and ELF link closure need blint 4 |
| trustinspector | `trustinspector-cdxgen-<platform> version` |
| trivy-cdxgen | the plugins package version (`npm ls -g @cdxgen/cdxgen-plugins-bin-<platform>`) |
| vdb | `vdb db status --json` answers on vulnerability-db 7; a `vdb` without the `db` subcommand is the older 6.x line |

The report files carry the producer version too (`tool.version` in golem,
rusi and kosi reports; `Metadata` in dosai's), and a summary that names an
engine should name that version with it.

## When a tool is missing

Say what cannot be assessed. A missing golem means Go witness paths stay
`not_assessed`; a missing kosi means Kotlin and JVM reach stays
`not_assessed`; a missing dosai means .NET exploit chains, trust zones and
the CBOM stay `not_assessed`; a missing or too-old atom means
memory-safety findings and reachables stay `not_assessed`. Never install a
tool, download a database or upgrade a CLI without the user's consent,
and never report zero findings for a stage the missing tool would have
run.

## Windows notes

The plugins package for `windows-amd64` carries the same tools as `.exe`
binaries; dosai on Windows needs the matching .NET runtime for arm64 or
amd64. The lookup order and the consent rules are the same.
