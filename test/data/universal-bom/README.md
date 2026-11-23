# A universal-typed BOM that carries a golang purl

`sbom-universal-go.cdx.json` is a trimmed cut of the BOM a default scan of
the [safer-exec](https://github.com/cdxgen/safer-exec) repository wrote,
at commit `6f3556ec41d5205df7998f40ce1b2fd55fd77531` (with local
changes), with the command `depscan scan <checkout> --reports-dir
<reports>` (the universal project type, the default analyzer). The
original `sbom-universal.cdx.json` holds 1821 components; this cut keeps
the first component of three purl types (golang, npm and deb), reduced to
`type`, `name`, `version`, `purl` and `bom-ref`, which is what the
reachability tools' purl-type gate reads. The golang component is the one
that makes a universal scan a golem scan.
