# Security Policy

## Reporting Security Issues

The OWASP dep-scan maintainers and community take security reports seriously. If you believe you have found a vulnerability in `dep-scan`, please report it privately through GitHub Security Advisories.

Use this private reporting link:

https://github.com/owasp-dep-scan/dep-scan/security/advisories/new

Please do not open a public GitHub issue for suspected security vulnerabilities. Public issues are appropriate for bugs, feature requests, and hardening suggestions that do not expose users to immediate risk. For anything that could affect server mode, release integrity, published packages, container images, or scan safety, use the private advisory flow first.

A good report usually includes:

- the affected version or commit
- the impacted component or file if known
- a clear description of the issue
- reproduction steps or a proof of concept
- expected behavior and observed behavior
- any constraints, assumptions, or exploit prerequisites
- your assessment of impact

If your finding involves a third-party dependency or external tool rather than `dep-scan` itself, please consider reporting it to the upstream maintainer as well. If the impact on `dep-scan` is still meaningful, you can report it privately here and explain the dependency relationship.

After the initial report, maintainers will triage the finding, may ask for more detail, and will coordinate remediation and disclosure as appropriate.

## Service Level Agreements (SLAs)

The following response targets are best-effort goals, not contractual guarantees.

| Severity                                                                                                                                               | Initial Response | Triage / Confirmation | Remediation Target | Disclosure                |
| ------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------- | --------------------- | ------------------ | ------------------------- |
| **Critical** such as remote code execution, release pipeline compromise, authentication bypass in server mode, or supply chain compromise              | 48 hours         | 5 business days       | 15 business days   | Coordinated with reporter |
| **High** such as path traversal in server mode, SSRF, private network access via URL scanning, or significant integrity failure in published artifacts | 5 business days  | 10 business days      | 30 business days   | Coordinated with reporter |
| **Medium** such as information disclosure, denial of service, validation bypass with limited impact, or security control regression                    | 10 business days | 15 business days      | 60 business days   | Next suitable release     |
| **Low** such as minor hardening gaps, verbose non-sensitive errors, or low-impact defense-in-depth improvements                                        | 15 business days | 30 business days      | Best effort        | Next suitable release     |

When remediation is available, maintainers may publish a GitHub Security Advisory and request a CVE where appropriate.

## What Counts as a Genuine Security Issue

### In scope

The following classes of issues are generally in scope for `dep-scan`.

- **Server mode vulnerabilities**. Examples include host or path allowlist bypass, path traversal, request smuggling through malformed inputs, file upload validation bypass, and failures in request size enforcement.
- **Server-side request forgery**. If the `/scan` endpoint, cdxgen-backed URL scanning path, or a related validation path can be used to reach unintended internal or restricted network targets, that is in scope.
- **Unsafe delegated execution**. If attacker-controlled input can cause `dep-scan` itself to execute unintended commands, invoke external tooling in a way that crosses the intended boundary, or bypass safeguards around cdxgen or blint integration, that is in scope.
- **Supply chain and release integrity issues**. This includes compromise or meaningful weakening of package publishing, GHCR image publishing, release artifact generation, workflow integrity, or downloaded tool verification in release automation.
- **Credential or secret leakage caused by dep-scan**. If `dep-scan` exposes tokens, secrets, credentials, or sensitive environment data in normal output, reports, logs, or published artifacts, that is in scope.
- **Vulnerability reporting integrity failures**. If a bug can materially misstate or suppress findings in a way that creates a security risk for users, especially across trusted inputs and default workflows, that may be in scope.
- **Unsafe disclosure in explanation output**. If a change or bug causes `dep-scan` to expose endpoint mappings, internal paths, or similar sensitive information beyond what a user explicitly asked it to generate, that is in scope.
- **Container and packaging hardening regressions**. If the official images or package defaults weaken execution safety in a meaningful way, that is in scope.

### Out of scope

The following are generally not considered `dep-scan` vulnerabilities on their own.

- **Vulnerabilities in the scanned project**. If `dep-scan` correctly reports a vulnerable dependency or risky package in the target project, that is a finding about the target, not about `dep-scan`.
- **Bugs in upstream build tools or registries without a demonstrated dep-scan impact**. Examples include vulnerabilities in npm, pip, Maven, Gradle, Cargo, Docker, Podman, GitHub, PyPI, npmjs, or crates.io when there is no clear exploit path through `dep-scan` itself.
- **Dependency CVEs with no demonstrated impact**. Automated reports that only state that a dependency has a CVE are not enough by themselves. Please explain reachability or impact on `dep-scan`.
- **Unsafe deployment choices outside dep-scan defaults**. For example, exposing server mode on an untrusted network with a weak or unchanged development API key, or mounting overly broad host paths into a container, is important operator guidance but not always a product vulnerability by itself.
- **Expected behavior of external build or package tools used during scanning**. `dep-scan` may interact with tools that process untrusted manifests, source trees, or package metadata. If the issue is solely that an upstream tool behaves as designed, report it upstream unless there is a clear `dep-scan`-specific bypass or unsafe delegation issue.
- **Debug or highly verbose operator-controlled output**. When users intentionally enable verbose, explanation, or debug-style behavior, some additional path and environment detail may appear. Reports should show why the observed output exceeds what that mode reasonably implies.
- **Social engineering, phishing, or local machine compromise**. If exploitation requires tricking a maintainer or compromising their workstation outside the repository trust boundary, that is outside normal product scope.
- **Scanner-only submissions with no reproduction or impact story**. We appreciate leads, but reports need enough context to evaluate exploitability and product impact.

### Grey areas

Some findings require case-by-case review.

- **Misleading analysis results**. Not every false positive or false negative is a security vulnerability, but some are serious if they can be triggered systematically and affect risk decisions or enforcement workflows.
- **Environment variable poisoning**. `dep-scan` uses many environment variables for configuration, tool selection, and workflow behavior. If a bypass meaningfully weakens trust boundaries beyond what an attacker with environment control would normally have, it may be in scope.
- **Template-related risk**. User-provided report templates are powerful. In local trusted use, that is expected. In more automated or hosted flows, the security impact depends on who controls the template and how it is executed.
- **Container escape or host interaction**. Generic runtime vulnerabilities belong with the runtime vendor. A `dep-scan`-specific escape path or dangerous container default may still be in scope.

## Shared Responsibility Model

`dep-scan` sits at the intersection of source analysis, external tool invocation, vulnerability intelligence, and CI/CD automation. Security responsibility is shared between the project, its users, and several upstream systems.

### What dep-scan is responsible for

| Area                                 | Responsibility                                                                                       | Key Controls                                                                                                                                             |
| ------------------------------------ | ---------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Own code safety**                  | Preventing injection, traversal, unsafe defaults, and unintended behavior in the `dep-scan` codebase | input validation, path allowlisting, safe BOM parsing, request size controls, cautious defaults in server mode                                           |
| **Server mode safety**               | Protecting the built-in HTTP server from hostile or malformed requests                               | API key support, non-local bind refusal by default, host and path allowlisting, remote URL scheme checks, restricted-address blocking, upload validation |
| **BOM generation boundary handling** | Keeping delegation to cdxgen and blint within expected control boundaries                            | structured subprocess arguments, generator selection rules, server URL separation, temp file management                                                  |
| **Workflow and release integrity**   | Keeping publishing and release automation trustworthy                                                | pinned action SHAs, least-privilege workflow permissions, trusted publishing to PyPI, digest verification for downloaded release tooling                 |
| **Artifact hygiene**                 | Avoiding accidental leakage through normal reports, outputs, or release assets                       | validation, explicit output modes, review of generated artifacts and workflows                                                                           |
| **Timely remediation**               | Addressing genuine product vulnerabilities in maintained versions                                    | private advisory intake, triage, fixes, and coordinated disclosure                                                                                       |

### What users are responsible for

| Area                       | Responsibility                                           | Guidance                                                                                                                                                             |
| -------------------------- | -------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Deployment safety**      | Running server mode in an appropriate trust environment  | Prefer local-only binds or protected internal networks. Set `DEPSCAN_SERVER_API_KEY` for non-local binds. Avoid placeholder development secrets in real deployments. |
| **Filesystem exposure**    | Controlling what host paths are mounted or made readable | Use narrow mounts in containers and consider `--server-allowed-paths` when exposing server mode.                                                                     |
| **Network egress control** | Limiting where scanning infrastructure can connect       | Use network policies, firewalls, or container isolation, especially when URL scanning or registry lookups are enabled.                                               |
| **Toolchain trust**        | Managing the risk of external build and analysis tools   | Keep cdxgen, Docker, package managers, and related tooling updated. Treat scans of untrusted projects as potentially high risk operations.                           |
| **Credential handling**    | Preventing accidental exposure of tokens or secrets      | Do not pass unnecessary secrets to scanning environments. Review CI logs and artifact retention for sensitive content.                                               |
| **Upgrade hygiene**        | Applying supported versions that include security fixes  | Stay on the latest maintained release line whenever possible.                                                                                                        |

### What upstream projects are responsible for

| Area                                                                                                                | Responsible Party                          |
| ------------------------------------------------------------------------------------------------------------------- | ------------------------------------------ |
| Vulnerabilities in package managers, registries, runtimes, or container engines                                     | The respective upstream maintainers        |
| Vulnerabilities in GitHub Actions runner infrastructure or GitHub platform controls                                 | GitHub                                     |
| Vulnerabilities in external analysis tools such as cdxgen, blint, npm, pip, Maven, Gradle, Cargo, Docker, or Podman | The respective upstream maintainers        |
| Malicious third-party packages or registries                                                                        | Registry operators and package maintainers |

## Security Features Reference

The following repository documents describe the current security posture and review model in more detail.

- [`README.md`](README.md)
- [`AGENTS.md`](AGENTS.md)
- [`SKILL.md`](SKILL.md)
- [`THREAT_MODEL.md`](THREAT_MODEL.md)
- [`documentation/docs/server-usage.mdx`](documentation/docs/server-usage.mdx)
- [`documentation/docs/env-var.mdx`](documentation/docs/env-var.mdx)

## Coordinated Disclosure Expectations

We ask reporters to avoid public disclosure until maintainers have had a reasonable chance to investigate and prepare a fix.

When possible, please keep exploit details private until one of the following happens:

- a fix has been released
- a mitigation has been documented
- maintainers confirm that the issue is not reproducible or not a product vulnerability
- a mutually agreed disclosure date is reached

If a report affects downstream users immediately and active exploitation appears likely, maintainers may prioritize mitigation guidance even before a full fix is available.

## Supported Versions

Security fixes are typically applied to the current maintained release line and forward-moving development work. Older unsupported releases may not receive backports.

| Version                         | Supported |
| ------------------------------- | --------- |
| Current maintained release line | ✅        |
| Current development branch      | ✅        |
| Older unsupported releases      | ❌        |

If you are unsure whether your version is still maintained, please report the issue privately and include the exact version, package source, and environment.
