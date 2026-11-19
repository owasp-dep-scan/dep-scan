---
name: depscan-container-image
description: Scans a container image reference, an exported rootfs directory or an image tarball with OWASP dep-scan and reports the CVEs in the image's packages. Use when asked to scan a docker or OCI image for vulnerabilities, audit an alpine, debian or redhat base image, check a rootfs, or when a container scan came back empty and the cdxgen version needs checking. Load it before writing any container depscan command.
---

# Scan a container image with dep-scan

Use this skill for images, rootfs directories and image tarballs. For source
repositories use `depscan-scan`; to read a finished container scan back use
`depscan-triage`.

The rules in [reference/safety.md](../../reference/safety.md) apply to every
command this skill produces. In particular: absolute paths, and a clean
result must be earned from the manifest, because an empty container scan is
usually a tooling problem rather than a clean image.

## Plugin settings

Claude Code replaces the `${user_config.*}` values in this table with the
options the user set for the plugin. Other clients show the text as written.
A value counts as set only when it is not empty and does not start with `${`;
otherwise ignore it and follow the "When not set" column.

| Setting | Value | When not set |
| --- | --- | --- |
| Vulnerability database directory | `${user_config.vdb_home}` | dep-scan's own default |
| cdxgen command | `${user_config.cdxgen_cmd}` | the `cdxgen` on `PATH` (dep-scan needs 13.8.0 or newer) |
| Preferred runtime | `${user_config.runtime}` | the `depscan` on `PATH` |

## Requirements to check first

Two things decide whether a container scan delivers:

1. **cdxgen 13.8.0 or newer.** An older cdxgen makes the scan exit 0 with
   an empty findings list and a manifest whose `inventory` stage failed;
   stderr names the required version and the `CDXGEN_CMD` fix. Check
   `depscan doctor --format json` (`tools[].name == "cdxgen"`) or trust the
   `depscan-coverage-loop` skill to repair it.
2. **The full database flavor.** Distro packages (apk, deb, rpm) match
   against the OS advisories, which the `app-only` flavor does not carry.
   `depscan vdb info --format json` reports the local flavor;
   `depscan-coverage-loop` or `depscan-vdb` downloads `full` with the
   user's consent.

## The commands

```bash
# An image reference, from a local daemon or a registry
depscan scan --target-kind container alpine:3.19 --format json -o /absolute/path/to/reports

# An exported rootfs directory (docker export)
depscan scan --target-kind container /absolute/path/to/rootfs --format json -o /absolute/path/to/reports
```

Both exit 0 when the inventory stage completed and write
`sbom-docker.cdx.json`, `depscan.findings.json`, `depscan.manifest.json`
and `depscan.vdr.json` into the reports directory. The findings list
carries one entry per vulnerable package with its purl
(`pkg:apk/alpine/...`, `pkg:deb/debian/...`, `pkg:rpm/...`), severity and
coverage state.

To export a rootfs from an image:

```bash
docker create --name depscan-rootfs alpine:3.19 true
docker export depscan-rootfs | tar -C /absolute/path/to/rootfs -xf -
docker rm depscan-rootfs
```

Run these container commands against a target the user named. Never export
or scan an image the user did not ask about.

## Decision table

| Situation | Command |
| --- | --- |
| An image reference the user named | `depscan scan --target-kind container <image> --format json -o <reports>` |
| A rootfs directory | `depscan scan --target-kind container <dir> --format json -o <reports>` |
| An image tarball on disk | `depscan scan --target-kind container <file.tar> --format json -o <reports>` |
| The scan exits 0 with no findings | Read `depscan.manifest.json` stages; `inventory` failed means not assessed, usually the cdxgen version |
| Distro CVEs are missing with a complete inventory | The database flavor is not `full`; see `depscan-vdb` |
| Which libraries are actually loaded, and by what | blint's link closure, below |
| What the image trusts, and which files came from packages | trustinspector and trivy-cdxgen, below |

## Link closure, trust material and installed-file provenance

Three deeper container questions are answered by the sibling tools
directly, because dep-scan does not surface them yet:

```bash
# Which shared libraries each executable declares and imports
# (env-only in this blint; never set BLINT_LINK_ROOT to the scan host)
BLINT_RESOLVE_LINK_CLOSURE=1 BLINT_LINK_ROOT=/absolute/path/to/rootfs \
  blint -i /absolute/path/to/rootfs/usr/bin -o /absolute/path/to/blint-reports --no-banner

# The certificates and trust material the image carries
trustinspector-cdxgen-<platform> rootfs /absolute/path/to/rootfs

# The OS-package inventory of the unpacked rootfs, with installed files
trivy-cdxgen-<platform> rootfs --output /tmp/trivy-rootfs.cdx /absolute/path/to/rootfs
```

The link closure lands in each binary's `-metadata.json`:
`dynamic_entries` carries the NEEDED libraries and `import_dependencies`
the resolved imports, which answers "is this vulnerable library actually
loaded by some executable, or installed but unused"; unused is not
`not_affected`, it is a weaker presence claim with this evidence. The
trust report carries the certificate material with its hashes and trust
domains; the hash list feeds a distrust review, and certificate contents
are never quoted. trivy-cdxgen's inventory includes the installed files
and trust state behind each OS package, which separates a real package
from a lookalike directory. The cdxgen audit packs `container-risk` and
`rootfs-hardening` apply to these BOMs through the cdx-audit step in
`depscan-supply-chain`.

## What this proves and what it does not

A completed container scan proves the packages the image ships carry the
recorded CVEs as of the database date. It does not prove the image is safe
to run, that a vulnerable package is reachable from the entrypoint, or that
unpackaged binaries are free of vulnerabilities: dep-scan matches packages,
and binaries without a package identity are inventoried without CVE
matching in this version. Say so when summarising.

## After the scan

- Explain and rank what to fix first — `depscan-triage`
- Download the `full` flavor for distro matching — `depscan-vdb`
- Fix a missing tool or flavor — `depscan-coverage-loop`
