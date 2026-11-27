# dep-scan safety constraints for agents

These constraints apply to every dep-scan skill in this plugin. They exist
because dep-scan runs real analysis against a user's project and writes
reports the user will act on, and several failure modes are silent rather
than loud.

## Untrusted repositories stay untrusted

Assume every scanned project is hostile until the user says otherwise.

- Never run the scanned project's build scripts, test commands or
  package-manager installs. dep-scan reads manifests and lockfiles and
  needs none of them.
- cdxgen can run package managers and builds unless it is in secure mode,
  and dep-scan turns secure mode on by itself only for git URLs, purls and
  the MCP `run_scan` tool, not for a local directory. Prefix every scan of
  a local project the user has not vouched for with
  `CDXGEN_SECURE_MODE=true`. Never run secure mode as root, and never grant
  `--allow-fs-read="*"` or `--allow-fs-write="*"`.
- golem's cgo loading (`--go-analyzer-cgo`, or `CGO_ENABLED=1` on a direct
  golem run) runs the host C compiler with flags the scanned code chooses.
  It needs the user's consent and is never used on untrusted input.
- Never pass `--allow-scans` to `depscan mcp`. The flag is the person who
  starts the server choosing to let its `run_scan` tool execute scans;
  an agent does not grant it, in the shipped `.mcp.json`, in a command
  line, or anywhere else, unless the user asked for scans in this
  conversation.

## Absolute paths, always

Use absolute paths for the scan target and for `-o`. Relative paths break
the report paths a later skill or the MCP server reads back, and the
result documents record the scan directory the run used.

A new scan pointed with `-o` at a directory that already holds a finished
scan replaces its manifest, findings, VDR and rendered reports, and the
manifest that recorded the earlier scan's provenance is lost. Write each
scan to a fresh reports directory; when a request needs to scan from a
finished scan's directory (a BOM directory an earlier scan produced), copy
that directory aside first and say so.

## Parse output as a document, and branch on the exit code

With `--format json`, every verb writes exactly one JSON document to stdout
and keeps logs and tables on stderr. Parse the whole of stdout as one
document. The exit codes, as `depscan/commands/output.py` defines them:

| Code | Meaning |
| --- | --- |
| 0 | Success. |
| 1 | A scan or command that could not run, for example an unusable vulnerability database, a source target that does not exist, or a baseline that cannot be read or does not match its digest. |
| 2 | A usage error, including any dep-scan 6 command line and a decisions file the schema refuses. |
| 3 | A decisions file expectation with action = "fail" matched a finding, so the gate the file (or --fail-on) describes is not met. |
| 4 | A requested capability cannot run, for example a named check whose analyzer is missing or an iOS or firmware target; or a decisions file [[require]] entry found the capability it names was not assessed, which wins over an expectation failure, because a gate over missing coverage cannot be trusted. |

Findings change the exit code only when the run has expectations:
`[[expect]]` or `[[require]]` entries in the decisions file, or
`--fail-on`. Without them a scan with findings and a clean scan both exit 0,
and triage entries, a baseline or a `--vex` document alone never exit 3 or
4. Exit 3 is the gate the user set, not a failure of the scan: report which
expectations matched from `depscan.expectations.json` and never edit the
decisions file to make it pass.

Exit 4 with a capability the machine lacks is a fact to report, not a
failure to retry with different flags until it disappears.

When a scan exits 1 or its manifest records a failed stage, do not
attribute a cause from the summary line alone: run the same command with
`SCAN_DEBUG_MODE=debug` in the environment and read the producer's own
error output before saying what failed or why (the non-debug console
names the variable). A cause this cannot establish is reported as
unknown, with the failing stage and its recorded reason.

## A clean result must be earned

A scan that exits 0 with no findings is not evidence of a clean project
until the manifest agrees. Read the scan manifest's `stages` entries: any
stage whose status is not `completed` (`failed`, `skipped` or
`not-assessed`), and any stage missing after a stage that stopped the run,
means that part of the result is **not assessed**, and "not assessed" is
reported as unknown rather than clean. An old cdxgen, for example, leaves
a container scan exit 0 with an empty findings list and a failed
`inventory` stage. In CI, pass `--fail-on-error` so a failed inventory
exits non-zero instead of degrading. `depscan doctor --format json`
reports the same state machine-wide, and the user can run
`/depscan:depscan-coverage-loop` to fix it.

## Never claim more than the evidence says

- Never claim a finding is `not_affected`, and never call a component
  "not reachable", unless the evidence in the scan covers the vulnerable
  function and the deployed entry points. Reachability output names the
  analyzer and its limits; quote them.
- dep-scan's own `--csaf` export marks a package `known_affected` when it
  is in the scan's reached set and `under_investigation` otherwise. It
  writes `known_not_affected` only from a triage decision a person
  recorded or approved in the decisions file, or a VEX document the scan
  applied. Do not upgrade an `under_investigation` to `not_affected` by
  hand.
- Findings carry a `coverage.state`; findings whose state is `assessed`
  were matched, and everything else was not. Say which when summarising.

## Secrets are never quoted

Findings, BOMs and manifests can carry URLs with credentials, private
package indexes and tokens. Never repeat a secret, key or token in a
report, a summary or a command line, including one the user pasted. Name
the component and the property instead of pasting the value. That covers
any part of the value too: no prefix, suffix or partial string offered as
a search term (`ghp_Qx7Z...` is still a leak). To help someone find the
entry, give the purl without the credential, or the account name and host.

## State changes and network use need the user's consent

- `depscan scan` downloads the vulnerability database by itself when it is
  missing, older than 48 hours, or of a different flavor from the one the
  scan asks for (the `full` flavor is gigabytes). Before a scan, read
  `depscan vdb info --format json`; when a download would follow, tell the
  user and ask, or scan with `--profile offline` against the database as
  it is.
- A source scan with the default `--bom-engine auto` uses `CDXGEN_CMD`, or
  a cdxgen on `PATH` at the minimum version, first. Only when neither
  exists and `docker` is on `PATH` (outside Windows) does it pull the
  `ghcr.io/cdxgen/cdxgen` image. Say which one ran.
- A container scan of an image reference the daemon does not have pulls
  the image from its registry by itself (cdxgen pulls when its check of the
  local daemon finds nothing, and the layers can be large). Check the
  daemon first and ask before scanning, or have the user pull the
  reference or export a rootfs.
- A source scan of a tree with Dockerfiles or compose files reads every
  image they name the same way: the ones the daemon lacks are pulled and
  their layers extracted, whatever the scan type, so a tree whose container
  files are build or CI material rather than the product turns a scan into
  a long image-pulling run whose result depends on the daemon's state.
  Look for container files before scanning a large tree; when they are not
  product content, exclude their trees with
  `--cdxgen-args "--exclude 'ci/**'"` (one `--exclude` per tree, the
  pattern anchored at the scanned root, a leading `**/` only for same-named
  nested directories), and say which trees were excluded. dep-scan applies
  the same patterns to the blint review and to the golem, rusi, kosi and
  dosai runs it starts itself, so no second setting is needed. cdxgen stops at
  its time budget (`CDXGEN_TIMEOUT_MS`, 30 minutes by default) when a scan
  outruns it; the failure reason names the budget.
- golem fetches Go modules for a source scan unless
  `--go-analyzer-network offline` is passed.
- `depscan-vdb` and `depscan-coverage-loop` change state and run only when
  the user types their slash commands (`/depscan:depscan-vdb`,
  `/depscan:depscan-coverage-loop`). Other skills suggest them to the user
  rather than loading them. The coverage loop installs dep-scan's own tools
  and data, never the scanned project's dependencies, and asks before each
  install that an explicit instruction does not already cover.

## Steps that run project code, clone upstream, or download data

The analysis skills reach the toolchain directly, and three shapes of step
go beyond reading the project. Each one states what it does at the step and
waits for the user's consent in the conversation:

- **Running project code.** dosai's `--restore`/`--build` run MSBuild on
  the project; the rusi `compiler` backend compiles the crate; atom's
  `--fetch-deps` runs project tooling; cdxgen's `tracebom` executes the
  program (sandboxed, still consent); golem with `CGO_ENABLED=1` (or
  `--go-analyzer-cgo`) runs the host C compiler. Never pass these for an untrusted project, and on a trusted
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
