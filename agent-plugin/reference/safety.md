# dep-scan safety constraints for agents

These constraints apply to every dep-scan skill in this plugin. They exist
because dep-scan runs real analysis against a user's project and writes
reports the user will act on, and several failure modes are silent rather
than loud.

## Untrusted repositories stay untrusted

Assume every scanned project is hostile until the user says otherwise.

- Never run the scanned project's build scripts, test commands or
  package-manager installs. dep-scan reads manifests and lockfiles in
  secure mode and needs none of them.
- Keep cdxgen in secure mode (`CDXGEN_SECURE_MODE=true`) for source the
  user has not vouched for. Never run secure mode as root, and never grant
  `--allow-fs-read="*"` or `--allow-fs-write="*"`.
- Never pass `--allow-scans` to `depscan mcp`. The flag is the person who
  starts the server choosing to let its `run_scan` tool execute scans;
  an agent does not grant it, in the shipped `.mcp.json`, in a command
  line, or anywhere else, unless the user asked for scans in this
  conversation.

## Absolute paths, always

Use absolute paths for the scan target and for `-o`. Relative paths break
the report paths a later skill or the MCP server reads back, and the
result documents record the scan directory the run used.

## Parse output as a document, and branch on the exit code

With `--format json`, every verb writes exactly one JSON document to stdout
and keeps logs and tables on stderr. Parse the whole of stdout as one
document. The exit codes are:

| Code | Meaning |
| --- | --- |
| 0 | Success. Findings never change it; a clean scan also exits 0. |
| 1 | A scan or command that could not run (unusable database, missing target). |
| 2 | A usage error, including any dep-scan 6 command line. |
| 4 | A requested capability that cannot run here (a check whose analyzer is missing, a refused kind). |

Exit 4 with a capability the machine lacks is a fact to report, not a
failure to retry with different flags until it disappears.

## A clean result must be earned

A scan that exits 0 with no findings is not evidence of a clean project
until the manifest agrees. Read the scan manifest's `stages` entries: an
`inventory` stage that failed, a check skipped for the target type, or a
tool below its minimum version (an old cdxgen leaves a container scan
exit 0 with an empty findings list) all mean the result is **not
assessed**, and "not assessed" is reported as unknown rather than clean.
`depscan doctor --format json` reports the same state machine-wide, and
`depscan-coverage-loop` is the skill that fixes it.

## Never claim more than the evidence says

- Never claim a finding is `not_affected`, and never call a component
  "not reachable", unless the evidence in the scan covers the vulnerable
  function and the deployed entry points. Reachability output names the
  analyzer and its limits; quote them.
- Findings carry a `coverage.state`; findings whose state is `assessed`
  were matched, and everything else was not. Say which when summarising.

## Secrets are never quoted

Findings, BOMs and manifests can carry URLs with credentials, private
package indexes and tokens. Never repeat a secret, key or token in a
report, a summary or a command line, including one the user pasted. Name
the component and the property instead of pasting the value.

## State changes need the user's consent

Two skills change state, and both say so at the step:

- `depscan-vdb` downloads data (a flavor can be gigabytes) over the
  network. Ask before the first download of a session; do not re-download
  a fresh database silently.
- `depscan-coverage-loop` installs dep-scan's own tools and data (a newer
  cdxgen, the full database flavor, a missing analyzer). It never installs
  the scanned project's dependencies and never runs its build scripts, and
  it asks before each install that is not already covered by an explicit
  instruction from the user.

## Steps that run project code, clone upstream, or download data

The analysis skills reach the toolchain directly, and three shapes of step
go beyond reading the project. Each one states what it does at the step and
waits for the user's consent in the conversation:

- **Running project code.** dosai's `--restore`/`--build` run MSBuild on
  the project; the rusi `compiler` backend compiles the crate; atom's
  `--fetch-deps` runs project tooling; cdxgen's `tracebom` executes the
  program (sandboxed, still consent); golem's cgo analysis runs the host C
  compiler. Never pass these for an untrusted project, and on a trusted
  one name what will execute before doing it.
- **Cloning upstream.** cdx-audit's predictive mode clones third-party
  repositories over the network. The direct-bom-audit form needs no
  clones; the predictive form names the clones before it runs.
- **Large downloads and redaction.** `blint db --download` fetches tens of
  gigabytes; cdxgen's `hbom --sensitive` turns redaction off and its raw
  golem values (`go:generate` commands, environment values, keys) are
  never quoted regardless. Name the size or the redaction change, and wait.

## Reach claims name their root set

Reachability is always stated with its analyzer and root set (`golem -callgraph rta -roots main`), because the same code is reachable from one
root set and not another. "Not reachable" is never a `not_affected`
justification unless the evidence covers the vulnerable function and the
deployed entry points; an analyzer that did not run, a root set that found
no roots, or a report that a tool deleted all mean the axis is **not
assessed**, and "not assessed" is reported as unknown rather than clean.
