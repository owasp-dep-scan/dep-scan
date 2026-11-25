# dep-scan documentation site

The documentation site, built with [Docusaurus](https://docusaurus.io/) 3.7. The pages live in `docs/`, organized in reading order: Start, Understand the results, Scan your software, Run it in CI and with agents, Reference, Upgrade, Develop, and the lesson Tutorials.

## Build

```bash
npm ci
npm run build
```

The build treats broken links as errors (`onBrokenLinks` and `onBrokenMarkdownLinks` are `throw`), so a page that moves must carry its redirect in `docusaurus.config.ts`.

## Generated content

Several pages embed content the code generates, each between HTML-comment markers, with a test under `test/` that compares the region to the generator:

| Page | Markers | Generator |
| --- | --- | --- |
| `docs/reference/cli.mdx` | help blocks, exit-code table | the built argparse parsers; `depscan.commands.output.exit_code_table_markdown` |
| `docs/integrate/agents.mdx` | exit-code table | the same exit-code helper |
| `docs/integrate/ci.mdx` | exit-code table | the same exit-code helper |
| `docs/start/vulnerability-database.mdx` | flavor table, legacy flavor table | `depscan.lib.config.flavor_table_markdown`, `legacy_flavor_table_markdown` |
| `docs/reference/schemas.mdx` | schema table | `analysis_lib.findings.schemas.schema_table_markdown` |
| `docs/results/scan-directory.mdx` | manifest field tables | `depscan.lib.scan_directory.manifest_fields_markdown` |
| `docs/lessons/*.mdx` | whole page | `documentation/lessons/<name>/run.sh`, compared by `test/test_docs_lessons.py` |

The README's help block is generated the same way and checked by `test/test_docs_cli.py`. When such a test fails, regenerate the embedded block from the named helper; do not edit the expectation.
