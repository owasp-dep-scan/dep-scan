# Finding and versioning the toolchain tools

The skills reach sibling tools directly for what dep-scan does not surface
yet. Most of them ship inside `@cdxgen/cdxgen-plugins-bin-<platform>`, not
on `PATH`, and a missing tool is a reported state, never a reason to
install anything without the user's consent.

## The lookup order

For each tool, resolve in this order and record which one answered:

1. The environment variable, when the tool has one: `GOLEM_CMD`, `RUSI_CMD`,
   `DOSAI_CMD`, `TRIVY_CMD`, `OSQUERY_CMD`, `SOURCEKITTEN_CMD`,
   `TRUSTINSPECTOR_CMD`, `CDXRS_CMD`, `CDXUI_CMD`, and dep-scan's
   `CDXGEN_CMD` for cdxgen. kosi has no command variable; cdxgen finds it
   in the plugins directory and can disable it with `CDXGEN_KOSI_DISABLE`.
2. The `depscan` venv's `bin` directory: atom, atom-tools and blint are
   installed with dep-scan's tool extras, so the interpreter that runs
   `depscan` usually carries them.
3. The plugins package directory:
   `<prefix>/node_modules/@cdxgen/cdxgen-plugins-bin-<platform>/plugins/`,
   where `<platform>` is `darwin-arm64`, `darwin-amd64`, `linux-amd64`,
   `linux-arm64`, `linux-arm64-musl` or `windows-amd64`. The binaries sit
   in `plugins/<tool>/<tool>-cdxgen-<platform>`.
4. `depscan doctor --format json`: the `tools` array lists the analyzers
   dep-scan found, with a version where it could read one and null where
   it could not. This is also the check that says which capability each
   tool unlocks (`reachability` needs cdxgen 13.8.0 or newer, and so on).

## Reading a version

| Tool | Version |
| --- | --- |
| cdxgen | `"$CDXGEN_CMD" --version` (or `cdxgen --version`) |
| golem | `golem --version` (or the report's `tool.version`) |
| rusi | `rusi --version` (or the report's `tool.version`) |
| dosai | `dosai --version` fails without the .NET runtime its release targets; on a newer runtime set `DOTNET_ROLL_FORWARD=LatestMajor` first, and record that you set it |
| atom | `atom --version` (the npm 4.0.2 release lacks the `memory-safety` and `callsites` subcommands; a newer atom carries them) |
| atom-tools | `atom-tools --version` |
| blint | `python -c "import importlib.metadata as m; print(m.version('blint'))"` (the CLI has no `--version`) |
| trustinspector, trivy-cdxgen | `<binary> version` (trustinspector) or the plugins package version (`npm view @cdxgen/cdxgen-plugins-bin-<platform> version`) |
| vdb | the vulnerability-db 7 command line in the dep-scan environment (`vdb db status --json` answers); a `vdb` on `PATH` that accepts only flags is the older 6.x CLI |

The report files carry the producer version too (`tool.version` in golem,
rusi, dosai and atom-tools documents; `Metadata` in dosai's), and a
summary that names an engine should name that version with it.

## When a tool is missing

Say what cannot be assessed. A missing golem means Go witness paths stay
`not_assessed`; a missing dosai means .NET exploit chains, trust zones and
the CBOM stay `not_assessed`; a missing atom means memory-safety findings
and reachables stay `not_assessed`. Never install a tool, download a
database or upgrade a CLI without the user's consent, and never report
zero findings for a stage the missing tool would have run.

## Windows notes

The plugins package for `windows-amd64` carries the same tools as
`.exe` binaries; `dosai` on Windows needs the matching .NET runtime arm64
or amd64, and `atom`'s JVM build runs on any installed Java 17 or newer
(the jar-based atom platforms need Java 17; the native platforms need
none). The lookup order and the consent rules are the same.
