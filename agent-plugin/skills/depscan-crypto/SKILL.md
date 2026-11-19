---
name: depscan-crypto
description: 'Builds the cryptographic inventory and its reachability across the toolchain: golem crypto findings (insecure TLS verification, literal key material), rusi cryptos, dosai crypto with its record-level reach and CBOM, atom-tools crypto-reach joining crypto assets to entry points, and trustinspector certificate and SPKI hashes for container trust. Use when asked what cryptography a project uses, whether weak algorithms are reachable, whether TLS verification is disabled anywhere, or how ready the code is for post-quantum migration.'
---

# The cryptographic inventory and its reach

Use this skill to answer "what crypto does this project use, and is any of
it weak or reachable". The engines are run directly because dep-scan does
not report their crypto findings yet; each step says so. The rules in
[reference/safety.md](../../reference/safety.md) apply, in particular
that raw key material and golem's environment values are never quoted.

## Plugin settings

| Setting | Value | When not set |
| --- | --- | --- |
| cdxgen command | `${user_config.cdxgen_cmd}` | the `cdxgen` on `PATH` |

## Per-language crypto evidence

```bash
mkdir -p /tmp/crypto
# Go: crypto findings, libraries, operations, materials, protocols
CGO_ENABLED=0 GOFLAGS=-mod=readonly golem analyze -dir /absolute/path/to/project \
  -dataflow crypto -out /tmp/crypto/golem.json

# Rust: the analyze report carries the crypto section; cryptos is the
# crypto-only report
rusi analyze --dir /absolute/path/to/project --out /tmp/crypto/rusi.json
rusi cryptos --dir /absolute/path/to/project --out /tmp/crypto/rusi-cryptos.json

# .NET: dosai's own crypto report, and the CycloneDX CBOM
dosai crypto --path /absolute/path/to/project --o /tmp/crypto/dosai-crypto.json
dosai crypto --path /absolute/path/to/project --format cyclonedx \
  --o /tmp/crypto/dosai-cbom.json
```

golem reads the project from `-dir`, never from a positional path. Its
report carries `crypto.findings` (rule ids such as
`GOLEM-CRYPTO-LITERAL-MATERIAL` and `GOLEM-CRYPTO-TLS-INSECURE-SKIP-VERIFY`,
the second also visible as a `tls-insecure` security signal), plus
`crypto.libraries`, `crypto.operations`, `crypto.materials` and
`crypto.protocols`. rusi's `crypto` section carries `libraries`,
`components`, `materials` and `findings`; its weak primitive findings
cover MD5 and SHA-1, it is not a TLS configuration verifier, and it does
not separate every weak hash
used as a checksum from one used for security, so a rusi run that names
nothing weak is not evidence that no weak cipher is used. dosai's crypto
report carries `Assets`, `Operations`, `Materials`, `Protocols`,
`Findings` and `CryptoDataFlows`; the CBOM is the same inventory as a
CycloneDX document. Never quote a material's value; name its type and
location.

For the CycloneDX CBOM of a broader codebase, cdxgen's `crypto-bom` skill
is the companion (this plugin names it rather than repeating its
guidance).

## Join crypto to reachability

This runs atom-tools directly because dep-scan does not report the join
yet. Pass the engine reports themselves, not the CBOM or a unified
document: crypto-reach reads dosai's crypto report, golem with
`-dataflow crypto` or `all`, and rusi analyze.

```bash
atom-tools crypto-reach \
  -i /tmp/crypto/golem.json,/tmp/crypto/rusi.json,/tmp/crypto/dosai-crypto.json \
  -o /tmp/crypto/crypto-reach.txt
```

The text report names, per engine, the join granularity (dosai is
record-level, rusi function-level, golem package-level at best), the
triage population (weak or legacy strength items and weak-crypto rule
hits) and a reach verdict per item. Counts are per engine and are never
summed across engines. `--weak-only` keeps only the triage population, and
`-f json` carries the whole inventory.

## Certificates and container trust

For what a container trusts rather than what its code uses, run
trustinspector from the plugins package (the binary is
`trustinspector-cdxgen-<platform>`; [reference/tools.md](../../reference/tools.md)
says where it is):

```bash
trustinspector-cdxgen-<platform> rootfs /absolute/path/to/rootfs > /tmp/crypto/trust.json
```

The report lists the trust materials with their hashes and trust domains;
the hash list is the input to a distrust review. `--embedded` also scans
binaries for embedded PEM certificates.

## Post-quantum readiness

State only what the data supports: the inventory names algorithms and
protocols, so a quantum-vulnerable algorithm that is inventory-identified
can be listed, with its locations and reach. Anything the engines did not
inventory (hardware, external services, languages no engine read) is not
assessed. Do not compute a "PQC score".

## What this proves and what it does not

The inventory proves which algorithms, protocols and materials the
analysed languages' code referenced, and the reach pass proves which of
them an entry point reaches at the stated granularity. It does not prove
key strength in operation, certificate validity at runtime, or
configuration outside the analysed files. Name rule ids, locations and
granularity in the answer.

## After the inventory

- Prove the reach of one weak primitive: `depscan-reachability-proof`
- Check the container's trust material: `depscan-container-image`
