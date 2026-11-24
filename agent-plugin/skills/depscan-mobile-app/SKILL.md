---
name: depscan-mobile-app
description: 'Analyses an Android APK, AAB or iOS IPA with blint: the deep component inventory, per-architecture native-library review, the JNI join between DEX and native code, entitlements and provisioning on iOS, and behavioural reviews. Use when asked what an app carries, which SDKs or trackers it bundles, whether its native libraries have CVEs, or what its entitlements allow. Manifest-level Android risks (exported components, debuggable, backup, cleartext) are stated as a gap, not guessed.'
---

# Analyse a mobile app with blint

Use this skill for app artifacts. The app's source repository, when one
exists, is scanned as a normal source project by `depscan-scan`.

blint is run directly because dep-scan's mobile check is not implemented
yet (a scan that asks for it exits 4 with the reason). The rules in
[reference/safety.md](../../reference/safety.md) apply: an app from an
untrusted source is untrusted input, and its embedded code is never
executed.

## Plugin settings

| Setting | Value | When not set |
| --- | --- | --- |
| Vulnerability database directory | `${user_config.vdb_home}` | dep-scan's own default |

## The deep inventory and review

Global options such as `--no-banner` go before the `sbom` subcommand.

```bash
mkdir -p /absolute/path/to/blint-reports
blint --no-banner sbom -i /absolute/path/to/app.apk \
  -o /absolute/path/to/blint-reports/app.cdx.json --deep
blint -i /absolute/path/to/app.apk -o /absolute/path/to/blint-reports --no-banner
```

The deep SBOM (`app.cdx.json`) carries the bundled SDK and library
components per architecture (`.aar` and `.so` entries with their ABI) and
tracker or service SDK identification; next to it, blint writes the DEX
call graph as `<bom-stem>-<apk-file-name>.dex-callgraph.json`, the BOM's
stem followed by the APK's own file name, so the exact name varies with
the APK (`app.cdx-app.apk.dex-callgraph.json` only for an APK named
`app.apk`). The review run writes
`reviews.json` (and `findings.json` when a hardening rule fired), whose
rule ids name the behaviour (dynamic code loading, reflection, native
command execution, weak cryptography, cleartext traffic) with evidence
positions, plus the app's `-metadata.json`. iOS IPA files add
entitlements, provisioning profiles, the privacy manifest and the
required-reason API review.

dep-scan's `ext` extra installs blint 4.1.x, which writes
`analysis-coverage.json` (read it first: what blint could not analyse is
not assessed) and `--android-abi` to restrict the native review to the
ABIs the user ships. On blint 3.2.x the review's coverage is unknown, and
the summary says so.

## Match the components against advisories

```bash
depscan scan --target-kind bom /absolute/path/to/blint-reports/app.cdx.json --format json -o /absolute/path/to/reports
```

The scan matches the app's bundled libraries against the database. Read
the manifest's `stages` first: any stage that is not `completed` means the
CVE answer for its part is not assessed, not clean.

## The JNI join

The DEX call graph document names the native libraries the bytecode loads
through JNI. When a vulnerable native library is both in the component
list and referenced from the DEX call graph, that is presence plus a load
path: report it with both facts. Without the DEX reference, the library is
present but not shown loaded.

## Known gaps, stated plainly

blint reads the Android manifest's package name, SDK levels, permissions
and features only. It has no exported-component, `debuggable`,
`allowBackup` or cleartext-traffic manifest rules today, so those risks
are not assessed by this skill; do not guess them from the manifest by
hand and present them as blint findings. Which SDK method the app's own
code calls is a reachability question, limited in obfuscated apps without
an R8 mapping file.

## What this proves and what it does not

The analysis proves what the app carries and what its bytecode and native
libraries do by blint's rules as of the installed version. It does not
prove the app is safe to ship, does not decrypt FairPlay-encrypted IPAs,
and does not assess the manifest risks listed above. Name rule ids and
ABIs in the answer, and mark the gaps not assessed.

## After the analysis

- Read and rank the findings: `depscan-triage`
- Review an embedded native library alone: `depscan-binary`
