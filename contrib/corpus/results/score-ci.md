# Corpus score

Generated 2026-11-27T20:01:39+00:00 at commit b3b7f85aee1a42c68be7d6248e188a049ddac482 with dep-scan 7.0.0a4.

| Item | State | Reachability recall/precision | Categories | Joins |
| --- | --- | --- | --- | --- |
| supply-chain-fixture-ci | scored |  | license: not assessed; supply-chain: not assessed |  |
| malware-fixture | scored |  | license: not assessed; malware: 1.0/1.0; supply-chain: not assessed |  |
| binary-hardening-fixture | scored |  | binary-hardening: 0.8571/1.0; license: not assessed; supply-chain: not assessed |  |
| lifecycle-fixture | scored | Framework direct 1.0/1.0; Framework reached 1.0/1.0; Semantic direct 1.0/1.0; Semantic reached 1.0/1.0 | license: not assessed; supply-chain: not assessed; vulnerability: -/- | lifecycle-phase: measured |
| monorepo-fixture | scored | Framework direct 1.0/1.0; Framework reached 1.0/1.0; Semantic direct 1.0/1.0; Semantic reached 1.0/1.0 | license: not assessed; supply-chain: not assessed | two-manifests: measured |
| java-sec-code-repotests | scored |  | license: not assessed; supply-chain: not assessed; vulnerability: 1.0/1.0 |  |

## Joins

| Join | Outcome |
| --- | --- |
| advisory-usage-reach | not labelled |
| route-package | not labelled |
| lifecycle-phase | measured |
| component-layer | not labelled |
| component-runtime | not labelled |
| two-producers | not labelled |
| two-manifests | measured |

## Categories dep-scan does not produce yet

- memory-safety: tracked by https://github.com/owasp-dep-scan/dep-scan/issues/613
- mobile: tracked by https://github.com/owasp-dep-scan/dep-scan/issues/625
- crypto: tracked by https://github.com/owasp-dep-scan/dep-scan/issues/630
- code: tracked by https://github.com/owasp-dep-scan/dep-scan/issues/605
