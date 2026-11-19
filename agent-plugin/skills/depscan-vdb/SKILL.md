---
name: depscan-vdb
description: Checks and refreshes the dep-scan vulnerability database with depscan vdb info, path and download. Use when the user asks to update, download or inspect the vulnerability database, when a scan reports an unusable or stale database, or when distro (apk, deb, rpm) matching needs the full flavor. Runs only when the user asks for it, because a download is a state change that can be gigabytes.
disable-model-invocation: true
---

# Check and refresh the vulnerability database

The user asked for this skill by name or asked for a database download or
refresh directly. A download writes into the user's `VDB_HOME` and can be
gigabytes; confirm the flavor with the user before the first download of a
session, and never re-download a fresh database silently. The rules in
[reference/safety.md](../../reference/safety.md) apply, in particular that
a missing or stale database is reported as not assessed, never as a clean
scan.

## Plugin settings

| Setting | Value | When not set |
| --- | --- | --- |
| Vulnerability database directory | `${user_config.vdb_home}` | dep-scan's own default |
| Vulnerability database flavor | `${user_config.vdb_flavor}` | the dep-scan default |

A set database directory is exported as `VDB_HOME` for every command in
this skill.

## Check the state

```bash
depscan vdb info --format json
```

The document carries the local flavor, the marker it was published from,
`mainDb` with `builtUtc`, `stale` and `completeness`, and the shard store
with per-type coverage. Exit 0 with a missing database is itself a finding:
report the database as absent rather than assuming scans will work.

```bash
depscan vdb path --format json
```

Prints `{"path": "..."}` with the `VDB_HOME` directory the commands use.

## Download a flavor

```bash
depscan vdb download --flavor app-only --format json
```

| Flavor | Carries |
| --- | --- |
| `full` | Application and OS advisories (apk, deb, rpm). Required for distro package matching, such as a container image scan. |
| `app-only` | Application ecosystem advisories. Enough for most source scans. |
| `app-extended` | app-only plus the extended metadata set. |
| `app-10y` | app-only with a ten-year window. |
| `app-10y-extended` | The ten-year window with the extended metadata set. |

Exit 0 after the download completed; exit 1 with the error document when
the download failed. A failed download is reported as such; a scan that
runs against the old database afterwards is not assessed for the advisories
the download would have added.

## Advisory search and the malware list

dep-scan's `vdb` verb reports the store state. The sibling `vdb` command
that ships with vulnerability-db (the dep-scan venv carries it; `depscan
doctor --format json` names the tools it found) answers advisory questions
directly from the store:

```bash
vdb --search-text "jwt"
vdb --search-alias CVE-2026-25645
vdb --search-symbol <function-or-symbol>
vdb --list-malware
```

The store's own coverage and staleness, per shard, with `needs_update`
flags:

```bash
vdb db status --json
```

A machine can carry an older `vdb` on `PATH` (the vulnerability-db 6
command line, flags only); the commands above are the vulnerability-db 7
command line in the dep-scan environment, so resolve `vdb` through the
same environment that runs dep-scan before using them.

Each search reads the store the same way a scan does, so a search against
a store with a coverage gap returns what the store has, and the result
tells you which store it read. `depscan vdb info --format json` remains
the freshness and completeness answer; the searches answer "what does the
store know about X". Run these read-only commands freely; they only read.

## What this proves and what it does not

`vdb info` proves the local database's date, flavor and completeness.
It does not prove a scan used it: a scan run with a different `VDB_HOME`
or a shard override reads whatever its environment names. Match the
database's state against the scan manifest's `database` entry when the
question is "did this scan see current advisories".

## After the download

- Re-run the scan that prompted this: `depscan-scan` or `depscan-container-image`
- Check what a scan could actually see here: `depscan-triage`
