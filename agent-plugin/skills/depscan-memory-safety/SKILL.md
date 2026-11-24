---
name: depscan-memory-safety
description: 'Finds memory-safety defects in C and C++ with atom and its bundled chen engine under the 37-rule family set, with confidence levels, compile-command support, SARIF output, and reachability ranking; and inventories the unsafe boundaries other languages carry (golem cgo and native interop, rusi unsafe-code and FFI, blint JNI joins). Use when asked to find memory-safety defects, review native code, audit unsafe boundaries, or check whether a memory-safety defect is reachable.'
---

# Memory-safety analysis

Use this skill for native code. dep-scan's memory-safety check is not
implemented yet (a scan that asks for it exits 4 with the reason), so atom
is run directly; chen is atom's bundled AST engine, not a separate binary
to find (`atom --version` prints both versions). This is the same analyzer
dep-scan plans to use, and the skill moves to the dep-scan path when that
lands.

The rules in [reference/safety.md](../../reference/safety.md) apply, and
[reference/tools.md](../../reference/tools.md) says where atom is found.
atom reads the project; `--fetch-deps`, the build tools and a CMake
configure step would run project tooling and need the user's consent.
`--no-build-tools` below keeps them off.

## Which atom

The memory-safety and callsites commands are in `@appthreat/atom` 4.0.2
and newer. `atom --help` lists the commands in its usage line; an atom
without `memory-safety` there is too old, and the analysis stays not
assessed until the user chooses to upgrade it.

## The C and C++ analysis

```bash
mkdir -p /absolute/path/to/ms-reports
# With a compilation database the project already has
atom memory-safety -l c --compile-commands /absolute/path/to/project/compile_commands.json \
  --min-confidence medium --no-build-tools \
  --parse-report /absolute/path/to/ms-reports/parse-report.json \
  -o /absolute/path/to/ms-reports/ms-app.atom \
  --slice-outfile /absolute/path/to/ms-reports/findings.json \
  /absolute/path/to/project

# Without one (most projects have none): the macro census defines the
# build-option macros that hide #if code first
atom memory-safety -l c --auto-defines \
  --min-confidence medium --no-build-tools \
  --parse-report /absolute/path/to/ms-reports/parse-report.json \
  -o /absolute/path/to/ms-reports/ms-app.atom \
  --slice-outfile /absolute/path/to/ms-reports/findings.json \
  /absolute/path/to/project
```

Use `-l cpp` for C++. Results are much better with a
`compile_commands.json`, and `--auto-defines` changes what is analysed, so
say which of the two forms you ran. `--format sarif` writes SARIF
2.1.0 instead of JSON; `--memory-api-config <file>` declares the project's
in-house allocation wrappers; `--min-confidence` takes low, medium or high
(medium is the reviewed default; low is noisy).

The findings are a JSON list. Each carries a `rule` (`MS-BOUND-002`,
`MS-ALLOC-004` and others across the bounds, allocation-state, integer and
conversion, null, escape, format-string, initialisation, invalidation,
TOCTOU, division, shift, pointer and overlap families), a `cwe`, a
`severity`, a `confidence`, `file` and `line`, and a `flow`: the sequence
from the length argument or allocation to the memory operation. The
confidence is chen's, not yours to raise; quote it.

The `--parse-report` file lists every file the frontends left out or only
partly read; every file on it is not assessed for that file's defects,
and the summary says so.

## Rank by reach

```bash
atom reachables -l c --reuse-atom --no-build-tools --sink-tag memory-safety \
  -o /absolute/path/to/ms-reports/ms-app.atom \
  --slice-outfile /absolute/path/to/ms-reports/reachables.json \
  /absolute/path/to/project
```

The memory-safety tags exist only in the atom the memory-safety command
wrote, so `-o` must name that same file with `--reuse-atom`; a fresh atom
has no memory-safety tags and returns nothing. The reachables pass routes
from atom's default source tags to the memory-safety sinks, so the defects
an entry point reaches rank first. A library or fixture with no
recognised entry points returns an empty list: that is `not_assessed`,
not "unreachable".

## Unsafe boundaries elsewhere

Memory-safe languages still cross into unsafe code, and the engines report
exactly where:

```bash
CGO_ENABLED=0 GOFLAGS=-mod=readonly golem analyze -dir /absolute/path/to/go-project \
  -dataflow security -out /tmp/golem.json
rusi analyze --dir /absolute/path/to/rust-project --out /tmp/rusi.json
```

golem reads the project from `-dir` and ignores positional paths, and
neither golem nor rusi is on `PATH` by default:
[reference/tools.md](../../reference/tools.md) gives the lookup order for
both. With cgo off, packages that import "C" still appear with their `#cgo`
variables, flag names and risk categories, read from source rather than
compiled; the crossings in `nativeBoundary[]` need the cgo build
(`CGO_ENABLED=1`), which runs the host C compiler with flags the project
chooses and needs the user's consent, stated at the step. rusi reports
`unsafe-code`, `native-interop`, `ffi-wrapper` and `pointer-arithmetic`
signals with purl and position; blint's Android analysis joins DEX to the
native libraries it loads (see `depscan-mobile-app`). Inventory these per
component as boundary evidence, and treat a boundary as a place a
memory-safety defect can live, not as a defect.

## What this proves and what it does not

A finding proves chen's rule fired at a confidence on a parsed file. It
does not prove exploitability; the flow and the reach pass are evidence
towards that, and a finding located in a toolchain header belongs to
neither the app nor a component, so it is kept but left out of the
application's counts. Vendored directories cdxgen marked
(`cdx:vendored:path`) attribute to the vendored component's purl;
everything else is the application's.

## After the findings

- Prove the reach of one defect: `depscan-reachability-proof`
- Check the binary's hardening: `depscan-binary`
