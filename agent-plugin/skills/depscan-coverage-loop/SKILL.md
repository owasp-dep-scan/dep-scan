---
name: depscan-coverage-loop
description: Runs the dep-scan coverage loop, which scans, reads depscan doctor and the scan manifest's failed and skipped stages, fixes the missing tool, database flavor or option each one names, and re-scans until coverage stops improving. Use when a scan came back empty or partly not assessed, when depscan doctor reports a missing tool or an unavailable capability, or when the user asks to make dep-scan coverage complete on this machine. Runs only when the user asks for it, because it installs dep-scan's own tools and data.
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
    for each capability whose status is unavailable:
        report the capability's reason; the reason names the tool and
        the version it needs; fix it under the consent rule above
    for each tool whose version is null or below the reason's minimum:
        report and fix it the same way
    read the target's stages with:
        depscan scan /absolute/path/to/target --format json -o /absolute/path/to/reports
    for each manifest stage whose status is failed or skipped:
        the stage's reason names what was missing; report it as not
        assessed, and fix it under the consent rule above
    if every stage that applies to the target is completed, and doctor
    reports no unavailable capability the user cares about:
        STOP - coverage complete for this target
    if this iteration changed nothing (same doctor state, same stages):
        STOP - stalled; report what is still missing and why
STOP - budget exhausted; report the stages and capabilities still missing
```

## The fixes the reasons name

The reasons come from dep-scan's own output, and the fixes are theirs to
read, not guesses:

| Reason says | Fix |
| --- | --- |
| `cdxgen 13.3.0 was found, but dep-scan needs 13.8.0 or newer` | Install a new enough cdxgen (`npm install -g @cdxgen/cdxgen@13.8.0` or newer), or install it into a prefix and export `CDXGEN_CMD` pointing at it. A prefix install is the reversible choice. |
| `capability reachability is unavailable: tool:cdxgen` | The same cdxgen fix; reachability needs 13.8.0 or newer. |
| The database flavor lacks distro advisories (apk, deb, rpm) | `depscan vdb download --flavor full`, with the consent rule. |
| `the risk audit was not requested for this type` | Not a defect: the stage does not apply to the target's type. Record it as not applicable, not as work. |
| `<check> is not implemented in this version` | Nothing to fix on this machine; the capability is dep-scan's backlog. Report the check as not implemented, with the reason's issue link. |
| A missing analyzer the doctor's `tools` list shows as version null | The reason names the tool; install it with consent or tell the user the analysis that stays not assessed without it. |

## Verify on the next iteration

Judge every fix by the next `depscan doctor --format json` and the next
scan manifest, never by the install command's exit code. A fix that leaves
the doctor state unchanged is recorded as no-change and not retried at the
same target.

## Deeper coverage signals

Three more signals tell the loop whether the analysis itself was complete,
beyond the stages:

- **cdxgen's fidelity tiers**: the loop may invoke cdxgen's
  `sbom-fidelity-loop` skill, which grades each ecosystem
  (resolved, lockfile, manifest, heuristic, absent) and ranks fixes; a
  `manifest` tier on an ecosystem means the BOM carried direct
  dependencies only, which caps what the matching stage can see.
- **atom's `--parse-report`**: when a run produced one, the files it lists
  were not fully read, and their defects and usages are not assessed.
- **blint's `analysis-coverage.json`**: for binary and app targets it
  names what blint could not analyse.

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
- Refresh the database the loop downloaded: `depscan-vdb`
