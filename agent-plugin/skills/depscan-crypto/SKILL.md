---
name: depscan-crypto
description: 'Builds the cryptographic inventory and its reachability across the toolchain: golem crypto findings (insecure TLS verification, key material), rusi cryptos, dosai crypto CBOM, atom-tools crypto-reach joining crypto assets to entry points, and trustinspector certificate and SPKI hashes for container trust. Use when asked what cryptography a project uses, whether weak algorithms are reachable, whether TLS verification is disabled anywhere, or how ready the code is for post-quantum migration.'
---

# The cryptographic inventory and its reach

Use this skill to answer "what crypto does this project use, and is any of
it weak or reachable". The engines are reached directly because dep-scan
does not surface their crypto findings yet; each step says so. The rules
in [reference/safety.md](../../reference/safety.md) apply, in particular
that raw key material and golem's environment values are never quoted.

## Plugin settings

| Setting | Value | When not set |
| --- | --- | --- |
| cdxgen command | `${user_config.cdxgen_cmd}` | the `cdxgen` on `PATH` |

## Per-language crypto evidence

```bash
# Go: crypto findings, libraries, operations, materials, protocols
golem analyze -dataflow crypto -o /tmp/golem.json /absolute/path/to/project

# Rust: the cryptos report is a separate command
rusi cryptos --dir /absolute/path/to/project -o /tmp/rusi-cryptos.json

# .NET: a CycloneDX CBOM
dosai crypto --path /absolute/path/to/project --format cyclonedx \
  --o /tmp/dosai-cbom.json
```

golem's report carries `crypto.findings` (rule ids such as
`GOLEM-CRYPTO-LITERAL-MATERIAL` and the insecure-TLS-verification finding,
also visible as a `tls-insecure` security signal), plus
`crypto.libraries`, `crypto.operations`, `crypto.materials` and
`crypto.protocols`. rusi's cryptos report carries the Rust crypto
inventory. dosai's CBOM is a CycloneDX document of the cryptographic
assets. Never quote a material's value; name its type and location.

For the CycloneDX CBOM of a broader codebase, cdxgen's `crypto-bom` skill
is the companion (this plugin names it rather than repeating cdxgen's
commands).

## Join crypto to reachability

This runs atom-tools directly because dep-scan does not surface the join
yet.

```bash
atom-tools crypto-reach -i /tmp/golem.json -o /tmp/crypto-reach.txt
```

The output is a console report (one per engine input): it joins the
crypto inventory to entry-point reachability at the granularity each
engine supports and says which granularity that is. It refuses unified
documents on purpose: pass the engine's own report. The triage population
line names the weak or legacy strength items; the per-item entries name
the rule, the location and the reach.

## Certificates and container trust

For what a container trusts rather than what its code uses:

```bash
trustinspector-cdxgen rootfs /absolute/path/to/rootfs
```

Reports the trust materials with SHA-1 and SPKI hashes and their trust
domains; the hash list is the input to a distrust review.

## Post-quantum readiness

State only what the data supports: the inventory names algorithms and
protocols, so a quantum-vulnerable algorithm that is inventory-identified
can be listed, with its locations and reach. Anything the engines did not
inventory (hardware, external services) is not assessed. Do not compute a
"PQC score".

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
