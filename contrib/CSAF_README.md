# CSAF VEX generation

The operator and reference documentation for dep-scan's CSAF VEX output has
been promoted to the official documentation site:

**➡ [CSAF VEX guide for compliance](https://depscan.readthedocs.io/en/latest/output/vex-csaf-guide/)**
(source: [`documentation/docs/output/vex-csaf-guide.mdx`](../documentation/docs/output/vex-csaf-guide.mdx))

That guide is the single source of truth and covers:

- generating a document with `--csaf` / `--csaf-version` and the output-naming
  (VDR safety) guarantee;
- the reachability → CSAF `product_status` mapping that makes the VEX
  actionable;
- the `csaf.toml` metadata fields (publisher, tracking, notes, references);
- the two-layer validation pipeline — the bundled CSAF JSON Schema (with an
  RFC 3339 `date-time` check and offline CVSS `$ref` resolution) plus the
  CSAF §6.1 mandatory *semantic* tests implemented in
  `analysis_lib.vex.semantic`;
- CSAF 2.0 vs 2.1 differences.

The implementation lives under `packages/analysis-lib/src/analysis_lib/vex/`.
This directory still ships the bundled schema (`csaf_2.0_schema.json`) and the
starter `csaf.toml`.

To validate an existing CSAF VEX or CycloneDX VDR/VEX document (from dep-scan or
any other tool), use the bundled `depscan validate` command — it auto-detects the
format and runs fully offline:

```bash
depscan validate path/to/document.json
```

See [Validating VEX and VDR documents](https://depscan.readthedocs.io/en/latest/output/validate-command/).

## Questions? Comments? Suggestions?

Reach out on [Discord](https://discord.gg/DCNxzaeUpd) or start a discussion on
the [OWASP dep-scan repo](https://github.com/owasp-dep-scan/dep-scan).
