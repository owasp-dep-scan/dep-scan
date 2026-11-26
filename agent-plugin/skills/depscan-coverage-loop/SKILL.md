---
name: depscan-coverage-loop
description: Runs the dep-scan coverage loop, which scans, reads depscan doctor and the scan manifest's stages that did not complete, fixes the missing tool, database flavor or option each one names, and re-scans until coverage stops improving. Use when a scan came back empty or partly not assessed, when depscan doctor reports a missing tool or an unavailable capability, or when the user asks to make dep-scan coverage complete on this machine. Runs only when the user asks for it, because it installs dep-scan's own tools and data.
disable-model-invocation: true
---

# The dep-scan coverage loop

The user asked for this skill by name or asked to fix dep-scan's coverage
directly. The loop fixes the environment dep-scan runs in: it installs
dep-scan's own tools and data (a newer cdxgen, a database flavor, an
analyzer) and re-scans. It never installs the scanned project's
dependencies, never runs the project's build scripts, and never edits the
project. Each install is a state change: name what you will install and
why, and wait for the user's consent unless the instruction to run this
loop already covers it. The rules in
[reference/safety.md](../../reference/safety.md) apply, in particular that
a stage that did not run is reported as not assessed, never as clean.

## Plugin settings

| Setting | Value | When not set |
| --- | --- | --- |
| Vulnerability database directory | `${user_config.vdb_home}` | dep-scan's own default |
| cdxgen command | `${user_config.cdxgen_cmd}` | the `cdxgen` on `PATH` |
| Vulnerability database flavor | `${user_config.vdb_flavor}` | the dep-scan default |

## The loop

```text
for iteration in 1..5:
    read the machine's state with:
        depscan doctor --format json
    for each capability whose status is "unavailable":
        its "missing" list names requirements such as "tool:cdxgen" or
        "data:vdb"; look each tool up in "tools" by name and read its
        "reason" and "minVersion"; fix it under the consent rule above
    for each capability whose status is "not-implemented":
        report it with its "issue" link; there is nothing to fix here
    read the target's stages with:
        depscan scan /absolute/path/to/target --checks all --format json -o /absolute/path/to/reports
    for each manifest stage whose status is not "completed", and each
    stage missing after one that stopped the run:
        the stage's reason names what was missing; report it as not
        assessed, and fix it under the consent rule above
    if every stage that applies to the target is completed, and doctor
    reports no unavailable capability the user cares about:
        STOP - success: coverage complete for this target
    if this iteration changed nothing (same doctor state, same stages):
        STOP - stalled: report what is still missing and why
    if every remaining gap is not-implemented or not applicable:
        STOP - nothing further available on this machine
    if a fix needs the user's consent and they declined:
        STOP - blocked: report the fix that would have helped
STOP - budget exhausted; report the stages and capabilities still missing
```

`--checks all` runs every check that can run and records the others as not
assessed, instead of refusing with exit 4 the way a named check does.

## The fixes the reasons name

The reasons come from dep-scan's own output, and the fixes are theirs to
read, not guesses:

| dep-scan says | Fix |
| --- | --- |
| A `tools` entry for cdxgen with `version` below `minVersion` (13.8.0), or `reason` "not found on PATH" | Install a new enough cdxgen (`npm install -g @cdxgen/cdxgen@13.8.0` or newer), or install it into a prefix and export `CDXGEN_CMD` pointing at it. A prefix install is the reversible choice. The default `auto` engine uses `CDXGEN_CMD` or a new enough cdxgen on `PATH` before the container image, so the re-scan tests the local install. |
| A capability `unavailable` with `missing: ["tool:cdxgen"]` | The same cdxgen fix; reachability needs 13.8.0 or newer. |
| The database flavor lacks distro advisories (apk, deb, rpm) | `depscan vdb download --flavor full`, with the consent rule. |
| The risk stage `skipped` with `the supply-chain audit was not requested` | Not a defect: the supply-chain check was not asked for. Add `--checks supply-chain` only if the user wants it. |
| The risk stage `not-assessed` with "cdx-audit was not found" or a minimum named | Install cdxgen 13.9.0 or newer (`npm install -g @cdxgen/cdxgen`, with consent, into a prefix where a choice exists) or export `CDX_AUDIT_CMD`; the check runs cdx-audit. |
| The risk stage `not-assessed` because the scan produced no BOM to audit | Not fixable on this machine: the audit reads a BOM. Report it as not assessed. |
| The risk stage `completed` with `notAssessed` reasons about registry metadata | The audit ran but its registry rules did not assess every package: the lookup was offline (the `offline` profile makes no network request by design) or a registry did not answer for the named components. Re-scan online for the first; report the count for the second. Never present the scan as fully assessed. |
| A capability `not-implemented` | Nothing to fix on this machine; the capability is dep-scan's backlog. Report it with its `issue` link. |
| Any other tool whose `version` is null | Its `reason` names the tool and how dep-scan looks for it; install it with consent, or tell the user which analysis stays not assessed without it. |

Rules for executing a fix: one fix per gap per iteration, name the command
before running it, install into a prefix or the dep-scan environment
rather than system-wide where a choice exists, and never install, build or
run anything from the scanned project.

## Verify on the next iteration

Judge every fix by the next `depscan doctor --format json` and the next
scan manifest, never by the install command's exit code. A fix that leaves
the doctor state unchanged is recorded as no-change and not retried at the
same target.

## Deeper coverage signals

Three more signals tell the loop whether the analysis itself was complete,
beyond the stages:

- **cdxgen's fidelity tiers**: cdxgen's `sbom-fidelity-loop` skill grades
  each ecosystem (resolved, lockfile, manifest, heuristic, absent) and
  ranks fixes. The skill is not one of this plugin's: it ships in cdxgen's
  own agent plugin, inside the installed cdxgen package
  (`agent-plugin/skills/sbom-fidelity-loop/` next to the package's
  `bin/`), so read it there when cdxgen's plugin is at hand; otherwise the
  scan's own introspection sidecar (`<bom>.cdx.json.introspection.json`,
  its `overall` and `ecosystems` entries) is the nearest signal this
  plugin carries. A `manifest` tier on an ecosystem means the BOM carried
  direct dependencies only, which caps what the matching stage can see.
- **atom's `--parse-report`**: when a run produced one, the files it lists
  were not fully read, and their defects and usages are not assessed.
- **blint's `analysis-coverage.json`** (blint 4.0.0 or newer): for binary
  and app targets it names what blint could not analyse. A scan with the
  binary check writes it under `analysis/blint/`; with an older blint 3.2.x
  it is absent, and binary coverage is then unknown.

Each of these is a coverage fact about the run, not a defect in the
project; carry them into the final report as not-assessed entries with
their reason.

## What this proves and what it does not

A completed loop proves that, on this machine, the target's stages all ran
and the capabilities the user cares about are available. It does not prove
the findings are complete beyond the database's date, and a capability
that is "not implemented in this version" stays not assessed; say so in
the final report.

## After the loop

- Re-read the finished scan: `depscan-triage`
- Check the database the loop downloaded: suggest `/depscan:depscan-vdb`
