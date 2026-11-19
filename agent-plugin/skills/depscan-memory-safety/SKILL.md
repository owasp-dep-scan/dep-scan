---
name: depscan-memory-safety
description: 'Finds memory-safety defects in C and C++ with atom and chen under the 37-rule family set, with confidence levels, compile-command support, SARIF output, and reachability ranking; and inventories the unsafe boundaries other languages carry (golem cgo and native boundary, rusi unsafe-code and FFI, SIMD build shapes, blint JNI joins). Use when asked to find memory-safety defects, review native code, audit unsafe boundaries, or check whether a memory-safety defect is reachable.'
---

# Memory-safety analysis

Use this skill for native code. dep-scan's memory-safety check is not
implemented yet (the scan verb exits 4 with the reason), so atom and chen
are run directly; this is the same analyzer dep-scan plans to wire up, and
the skill moves to the dep-scan path when that lands.

The rules in [reference/safety.md](../../reference/safety.md) apply. atom
and chen read the project; `--fetch-deps` and a CMake configure step would
run project tooling and need the user's consent. An atom built by another
command is never reused for memory-safety: the command reuses only an
atom a memory-safety build wrote, and reports that instead of zero
findings for anything else.

## Plugin settings

| Setting | Value | When not set |
| --- | --- | --- |
| Vulnerability database directory | `${user_config.vdb_home}` | dep-scan's own default |

## The C and C++ analysis

```bash
mkdir -p /absolute/path/to/ms-reports
atom memory-safety -l c --auto-defines --min-confidence medium \
  --parse-report -o /tmp/ms-app.atom \
  --slice-outfile /absolute/path/to/ms-reports/findings.json \
  /absolute/path/to/project
```

Use `-l cpp` for C++; `--compile-commands <file>` replaces `--auto-defines`
when a `compile_commands.json` exists, and results are much better with
one; `--format sarif` writes SARIF 2.1.0 instead of JSON; `--memory-api-config <file>`
declares the project's in-house allocation wrappers; `--min-confidence`
takes low, medium or high (medium is the reviewed default; low is noisy).

The findings carry a rule id (`MS-BOUND-002`, `MS-ALLOC-004` and friends
across the bounds, allocation-state, integer and conversion, null, escape,
format-string, initialisation, invalidation, TOCTOU, division, shift,
pointer and overlap families), a CWE, a severity, a confidence, and a
flow: the sequence from the length argument or allocation to the memory
operation. The confidence is chen's, not yours to raise; quote it.

## Rank by reach

```bash
atom reachables -l c --reuse-atom --sink-tag memory-safety \
  -o /tmp/reach-app.atom --slice-outfile /tmp/reachables.json \
  /absolute/path/to/project
```

Routes the memory-safety findings through the reachability pass so the
defects an entry point reaches rank first. Reachability needs entry
points: an empty result on a fixture without sources is `not_assessed`,
not "unreachable". The `--parse-report` file above lists the files atom
could not read; every file on it is not assessed for that file's defects,
and the summary says so.

## Unsafe boundaries elsewhere

Memory-safe languages still cross into unsafe territory, and the engines
report exactly where:

```bash
golem analyze -dataflow security -o /tmp/golem.json /absolute/path/to/go-project
rusi analyze --dir /absolute/path/to/rust-project -o /tmp/rusi.json
```

golem reports cgo and `native-interop` signals (and SIMD build shapes in
its build-shape deltas); rusi reports `unsafe-code`, `native-interop` and
`ffi-wrapper` signals with purl and position; blint's Android analysis
joins DEX to the native libraries it loads. Inventory these per component
as boundary evidence, and treat a boundary as a place a memory-safety
defect can live, not as a defect.

## What this proves and what it does not

A finding proves chen's rule fired at a confidence on a parsed file. It
does not prove exploitability; the flow and the reach pass are evidence
towards that, and a toolchain-header finding (chen's known path issue)
belongs to neither the app nor a component, so it is kept but excluded
from the application's counts. Vendored directories cdxgen marked
(`cdx:vendored:path`) attribute to the vendored component's purl;
everything else is the application's.

## After the findings

- Prove the reach of one defect — `depscan-reachability-proof`
- Check the binary's hardening — `depscan-binary`
