# THREAT_MODEL.md

## Purpose and audience

This document is a working threat model for `dep-scan`. It is written for security researchers, maintainers, and AI agents that need to assess changes across the codebase, the server mode, the container images, and the GitHub workflows.

The goal is not to present a perfect formal model. The goal is to make review more accurate. This repository mixes local analysis, network lookups, external tool execution, server-side scanning, and release automation. That combination creates more security-relevant behavior than a typical Python package.

The language here is intentionally practical. It aims to help someone reviewing a pull request understand what matters, what is already protected, and where the sharp edges still are.

## What the system does

At a high level, `dep-scan` takes one of several possible inputs, turns that input into an SBOM if needed, enriches it with vulnerability and risk information, and writes reports or serves results over HTTP.

The product can work in at least four modes:

1. local CLI scan of a source tree, image, binary, or existing BOM
2. server mode that accepts scan requests over HTTP
3. reachability and explanation generation for richer reports
4. CI and release automation that builds, tests, and publishes packages and container images

The architecture is easier to reason about when shown as a flow.

```text
                     +----------------------+
                     |   Local user or CI   |
                     +----------+-----------+
                                |
                                v
                      +---------+---------+
                      |   depscan CLI     |
                      |   depscan/cli.py  |
                      +----+---------+----+
                           |         |
          needs BOM        |         | uses existing BOM / purl / bom dir
                           |         |
                           v         v
               +-----------+--+   +--+------------------+
               | BOM generation |   | Analysis + VDR     |
               | depscan/lib/   |   | analysis-lib,      |
               | bom.py         |   | reporting-lib      |
               +-----+----------+   +---------+----------+
                     |                            |
                     | delegates to               | fetches external data
                     v                            v
         +-----------+----------------+   +------+------------------+
         | cdxgen CLI / cdxgen server |   | VDB, GitHub, registries |
         | / image based cdxgen       |   | PyPI, npm, crates.io    |
         +-----------+----------------+   +------+------------------+
                     |                            |
                     +-------------+--------------+
                                   |
                                   v
                        +----------+-----------+
                        | Reports, VDR, CSAF,  |
                        | console output,      |
                        | explanation outputs  |
                        +----------------------+
```

Server mode adds another trust boundary.

```text
Client --> Quart server (/scan) --> input validation --> BOM generation and analysis --> JSON response
             |
             +--> path-based scan
             +--> URL-based scan via cdxgen server
             +--> uploaded BOM scan
```

Release automation is another system in its own right.

```text
Git push or tag
      |
      v
GitHub Actions workflows
      |
      +--> run tests on multiple OS and Python versions
      +--> build Python packages
      +--> build and push container images to GHCR
      +--> publish package to PyPI on tags
      +--> attach SBOMs and create releases
```

## Security objectives

The security story of `dep-scan` is broader than confidentiality alone.

The first objective is analysis integrity. Users need results that accurately reflect the scanned input and the underlying vulnerability sources.

The second objective is execution safety. The tool must not turn common scan inputs into easy paths for command injection, filesystem escape, SSRF, or privilege expansion.

The third objective is operator safety. Server mode and container usage should fail in a safe way when exposed to risky deployment patterns.

The fourth objective is release integrity. Published packages, container images, and release artifacts should come from trusted workflows with constrained authority.

The fifth objective is information hygiene. Reports, logs, explanation output, and CI artifacts should avoid leaking more data than necessary.

## Important assets

Several asset classes matter here.

The most obvious assets are published artifacts. Those include PyPI packages, GHCR container images, release assets, and attached SBOMs.

The next class is analysis output. VDR files, CSAF output, explanation reports, endpoint summaries, and reachability artifacts can influence remediation decisions and may contain sensitive implementation details.

Credentials and authority are another asset class. This includes GitHub tokens, trusted publishing identity, workflow `GITHUB_TOKEN` permissions, server API keys, and any credentials inherited by subprocesses or package managers.

There is also host-level risk. In server mode, `dep-scan` can read local files, process uploads, and ask cdxgen to inspect local paths or remote URLs. In Docker and CI, it can run external toolchains and download binaries.

Finally, there is the reputation asset. `dep-scan` is itself a security product. A compromised release pipeline or an exposed server mode would damage trust in the findings it produces.

## Trust boundaries

This repository has several trust boundaries that deserve explicit attention.

The boundary between operator-controlled local input and repository-controlled logic is the easiest one to see. A user points the tool at a path, image, or BOM. The tool then parses files, may execute external tooling, and may fetch network data.

The boundary between trusted operator and remote caller is introduced by server mode. That path is much more sensitive because HTTP requests can carry paths, URLs, uploaded files, and type selections.

The boundary between repository code and external services is present in package registry lookups, GitHub API requests, VDB downloads, cdxgen server calls, Hugging Face dataset downloads in workflows, and direct binary downloads in CI and container builds.

The boundary between pull request code and repository authority is present in GitHub Actions. Pull request workflows usually have read-only contents permission, but they still execute repository code, download third-party tools, and process artifacts. Release workflows cross into a stronger trust zone because they have write authority for packages, contents, and trusted publishing.

A final boundary exists between reports and downstream consumers. Reachability explanations and endpoint summaries may be consumed by humans, CI logs, dashboards, or other AI systems. That changes what counts as sensitive output.

## Threat actors and likely motivations

The most realistic attackers are not all the same.

One class is an external caller hitting a deployed `dep-scan` server. Their goal may be to read local files, scan internal services, exhaust resources, or pivot into the environment through a delegated tool such as cdxgen.

Another class is a malicious contributor or compromised dependency trying to change what gets built, tested, or published. Their goal may be to ship altered artifacts, exfiltrate workflow data, or establish persistence in CI.

A third class is a malicious sample repository or image being scanned. That input may try to trigger bugs in parsers, oversized processing, dangerous subprocess behavior, or unexpected tool downloads.

A fourth class is a passive observer who gains more data than intended through logs, reports, uploaded artifacts, endpoint summaries, or prompt-like explanation output.

Finally, there is the accidental attacker. Many practical security incidents come from a well-meaning operator binding the server to `0.0.0.0`, mounting a broad host path into a container, or leaving a development API key in place.

## Main attack surfaces

### 1. CLI inputs and local scan orchestration

The CLI accepts source paths, images, binary paths, BOM files, BOM directories, direct PURLs, custom report templates, custom vulnerability data, and many execution knobs. Those arguments influence:

- which files are read
- where reports are written
- which analyzers run
- which external services are contacted
- whether external tools are executed locally, over HTTP, or via container images

This surface is mostly operator-controlled, which lowers attacker leverage in a pure local workflow. The risk rises when the scanned content itself is untrusted or when the CLI is wrapped by automation that passes partially untrusted values.

The most important review question is whether a user-controlled value crosses into subprocess construction, network targets, report rendering, or filesystem writes without enough validation.

### 2. BOM generation backends

BOM generation is a major trust boundary. `depscan/lib/bom.py` delegates work to `xbom-lib`, and `packages/xbom-lib/src/xbom_lib/cdxgen.py` can use:

- local `cdxgen` CLI
- local fallback binaries
- cdxgen server over HTTP
- cdxgen container images
- `blint` for binary-oriented flows

This part of the system is powerful because it turns a broad range of inputs into machine-readable BOMs. It is also risky because it can execute external tools, depend on environment variables, and interact with source trees that may contain crafted manifests.

A practical threat here is not necessarily classic command injection. The code largely builds subprocess arguments as a list, which helps. The deeper risks are delegated execution, unsafe defaults in downstream tools, surprising network access, and a widening of trust when remote cdxgen server mode is involved.

`cdxgen_args` deserves special attention during review because it is intentionally flexible. Flexibility is useful for operators, but it also means a caller can influence downstream tool behavior in ways that may bypass normal expectations.

### 3. BOM parsing and report generation

`dep-scan` reads both JSON and XML BOMs. XML parsing uses `defusedxml`, which is an important existing mitigation against classic XML parser abuse.

Even so, malformed, oversized, or unexpected BOM content can still produce denial-of-service style behavior, misleading results, or confusing report output if not handled carefully.

Report generation also matters. A user-provided Jinja template is a powerful feature. In local CLI usage, that is usually a trusted operator choice. In any automated or service-based usage, it becomes a code execution and trust decision because template engines can be surprisingly expressive.

### 4. Registry and GitHub metadata lookups

The package risk audit path reaches out to PyPI, npm, and crates.io. GitHub token helpers call the GitHub API. These calls are not just incidental network traffic. They can affect risk scoring, package classification, and operator decisions.

The repository already includes some useful controls here. Timeouts are used. Registry base URLs are fixed in config. The metadata fetch path has a circuit breaker to stop after repeated failures.

The main risks are:

- over-trusting remote metadata
- handling failures in a way that silently changes security conclusions
- leaking credentials or scopes through logs
- allowing environment overrides or future refactors to shift from fixed hosts to user-controlled hosts

A strong reviewer should treat these integrations as security-relevant data sources, not just convenience enrichments.

### 5. Server mode

Server mode is the highest risk runtime surface in the product.

The request path in `packages/server-lib/src/server_lib/simple.py` accepts three very different scan modes.

A caller can submit a local path. That is a potential local file and directory exposure surface.

A caller can submit a remote URL. That is a potential SSRF and internal network discovery surface, especially because cdxgen may later act on the URL.

A caller can upload a BOM file. That is a parser and resource handling surface.

Recent hardening in the server code already adds meaningful protection. The server can require an API key. It refuses non-local binds by default unless authenticated or explicitly opted out. It supports allowed hosts and allowed paths. It validates URL schemes and blocks URLs that resolve to private, loopback, link-local, multicast, reserved, or unspecified addresses unless explicitly allowed. It enforces project type limits and BOM size limits. It validates uploaded BOM structure and format.

These are good controls, but server mode remains sensitive for two reasons.

First, it still delegates work to external analysis paths and optionally to cdxgen server mode. That means a validation gap can have a large blast radius.

Second, many operators deploy scanning services in environments that are more connected than they first realize. The product correctly warns that server mode is for trusted environments. Reviewers should preserve that posture.

### 6. Explanation and reachability outputs

The explanation path in `depscan/lib/explainer.py` is not just cosmetic. It can surface endpoint patterns, code hotspots, reachable flows, and prompt-like structured content derived from analysis results.

This creates a quiet but important disclosure surface.

In a private engineering environment, detailed reachability output is often exactly what users want.

In CI logs, uploaded artifacts, or any workflow that forwards this content into another AI system, it can reveal more of the internal application than expected. Endpoint names, file paths, and vulnerability-to-code mappings may all carry sensitivity.

The key question is not whether the content is secret in an absolute sense. The key question is whether the current audience and artifact retention model make that level of detail appropriate.

### 7. Container builds and runtime images

The Dockerfiles build a large multi-language tool environment with Java, Maven, Gradle, Go, Node.js, PHP, Composer, `uv`, `cdxgen`, and `atom-tools`.

This is understandable for a multi-ecosystem scanner, but it increases supply chain and build-time risk.

The good news is that the final image runs as a non-root `owasp` user and locks down `/opt` with read-only permissions after setup.

The less comfortable reality is that the build process downloads a wide range of tooling from external sources, including SDKMAN-managed runtimes, Go tarballs, npm packages, pip packages, and Composer bootstrap logic. Every one of those sources becomes part of the trusted build story.

A reviewer should treat the Dockerfiles as a supply chain program, not just an installation recipe.

### 8. GitHub Actions workflows

The workflow surface is large and deserves first-class threat modeling.

There are read-oriented assurance workflows like `pythonapp.yml`, `pre-commit.yml`, `dockertests.yml`, `gobintests.yml`, and `repotests.yml`.

There is a stronger authority release workflow in `pythonpublish.yml` which can build packages, push container images, attach SBOMs, and publish to PyPI on tags.

A few observations matter here.

Most actions are pinned by commit SHA. That is a strong control and worth preserving.

Pull request workflows use read-only contents permission. That lowers direct repository takeover risk.

At the same time, many workflows download and execute third-party tools or inspect third-party repositories and datasets. For example:

- npm global install of `@cyclonedx/cdxgen`
- `uv sync --all-extras --all-packages --dev`
- direct `curl` downloads of tools such as `nydus`
- `soar` binary installation in binary tests
- Hugging Face dataset downloads in repo tests
- checkout of external repositories for sample scans
- use of a self-hosted runner in part of `repotests.yml`

This does not mean the workflows are unsafe by default. It does mean they deserve ongoing scrutiny, especially where downloads happen at runtime and where self-hosted infrastructure is involved.

## Existing controls that materially help

The repository already includes several meaningful protections.

Action versions are pinned by commit SHA in workflows.

Release publishing uses trusted publishing for PyPI.

The release workflow now pins the expected SHA-256 for the downloaded `nydus` archive instead of trusting a co-hosted checksum file.

Server mode defaults are cautious. Non-local binds require an API key or an explicit opt-in. API key authentication supports both `X-API-Key` and bearer tokens. Path and host allowlisting are available. Private URL resolution is blocked by default. Request size and project type validation are present.

XML parsing uses `defusedxml`.

The metadata audit path uses timeouts and a circuit breaker.

The final runtime container uses a non-root user.

These controls reduce risk, but they are not a reason to relax review depth.

## Threats by category

### Integrity threats

The biggest integrity risks live in release workflows, container builds, and analysis inputs from third-party services.

A compromised package manager dependency, a malicious external sample repository used in tests, or an unsafe workflow change could alter published artifacts or test expectations.

Another integrity threat is silent result drift. If a refactor changes the fallback path between cdxgen CLI, cdxgen server, and image-based generation, users may get different BOMs without realizing the trust boundary changed.

Registry metadata and GitHub scope checks can also alter perceived risk posture. If failures are swallowed or defaults change, the user may think the analysis is more authoritative than it really is.

### Confidentiality threats

The highest confidentiality risks appear in server mode, explanation output, and workflow logs or artifacts.

A server misconfiguration could expose local files or internal source trees through path-based scanning.

A URL validation mistake could let an external caller probe private network space through cdxgen-backed URL scanning.

Detailed explanation output can reveal internal endpoints, file paths, and code hotspots. On a developer laptop that may be fine. In retained CI artifacts or downstream AI prompts, it may be too much.

Workflows that upload artifacts need review for accidental inclusion of sensitive files, especially when sample repos or generated reports are involved.

### Availability threats

Availability matters because `dep-scan` often runs in CI and can become part of a delivery gate.

Large inputs, expensive reachability analysis, oversized uploads, repeated network failures, and malicious source trees can all increase runtime cost.

Server mode adds classic denial-of-service opportunities through repeated requests, large uploads, expensive URL-based scans, or intentionally complex source trees.

The repository already includes some guards such as request body limits, project type limits, and a metadata circuit breaker. Reviewers should preserve or strengthen these when changing related code.

### Privilege and authority threats

This repository spans several privilege levels.

A local user running the CLI has their own machine authority. That is expected.

A server process may have access to local mounts, temp directories, and internal networks. That is more dangerous.

A GitHub Actions PR job usually has limited repo authority but still has the ability to run code and egress to the network.

A release workflow has package and contents write permissions and trusted publishing authority. That is the highest-value authority in the repository.

A threat model for `dep-scan` should always ask: what authority does this path run with, and who gets to influence it?

## Detailed review guidance by component

### `depscan/cli.py`

This file is the orchestration heart of the product. Review changes here for implicit behavior shifts.

Questions to ask:

- Does a new argument widen what can be read or written?
- Does the change alter which analyzer is selected automatically?
- Does the change move a workflow from local-only to remote-assisted behavior?
- Does the change increase what is logged or emitted in reports?

The CLI is where a small default change can quietly reshape the whole system.

### `depscan/lib/bom.py`

This file decides how BOM creation is performed and when to delegate to `blint` or cdxgen variants.

Questions to ask:

- Does the selected backend match the trust assumptions for the input?
- Could a path or image input cause unexpected external execution?
- Are temporary and output files created in predictable locations and cleaned up safely?

### `packages/xbom-lib/src/xbom_lib/cdxgen.py`

This is one of the most important integration files in the repository.

Questions to ask:

- Who controls `cdxgen_args` and environment-derived behavior?
- Is the subprocess argument list still structured safely?
- Are network timeouts and server headers reasonable?
- Has a change made image freshness or image trust looser than intended?
- Would a fallback path surprise an operator by changing execution locality?

### `packages/server-lib/src/server_lib/simple.py`

This is the highest-value application security review target.

Questions to ask:

- Are authentication checks guaranteed to run before sensitive work?
- Does host allowlisting behave correctly in both test and real deployment contexts?
- Does path allowlisting resolve symlinks and traversal attempts safely?
- Does remote URL validation block internal address classes consistently?
- Are request size and project type limits robust against misconfiguration?
- Are temporary files removed even on failure paths?
- Does any error message expose too much detail to the caller?

### `.github/workflows/pythonpublish.yml`

This is the release control plane.

Questions to ask:

- Has any permission been widened?
- Can a non-tag event publish artifacts unintentionally?
- Are all downloaded tools pinned or verified strongly enough?
- Could generated release assets include unexpected content?
- Are new build inputs coming from trusted or reviewable sources?

### Other workflows

`pythonapp.yml`, `dockertests.yml`, `gobintests.yml`, and `repotests.yml` are lower authority than the publish workflow, but they still matter.

Questions to ask:

- Do they run untrusted code from pull requests or external repos?
- Do they download tools or datasets without strong integrity checks?
- Do they use self-hosted infrastructure?
- Do they retain or upload artifacts that may contain sensitive output?

## Workflow-specific risks worth calling out

### Pull request workflows

The default permissions are relatively cautious, which is good.

The remaining risk is execution of untrusted proposed code plus runtime downloads. That combination can still threaten hosted runners, leak logs, or exploit a weakly isolated self-hosted runner.

The self-hosted portion of `repotests.yml` deserves special attention because self-hosted runners have a different risk profile from GitHub-hosted runners. Any workflow step that builds sample projects, downloads datasets, or runs deeper semantic analysis on a self-hosted runner should be reviewed with infrastructure impact in mind.

### Release workflow

The release workflow has write access and trusted publishing. That makes integrity the top concern.

If an attacker could influence what source is built on a tagged release, which images are pushed, or which artifacts are attached, they could create a supply chain incident that looks legitimate to users.

The current use of pinned action SHAs and digest verification for `nydus` helps. Reviewers should preserve that discipline when new external downloads are added.

## Data flow walkthroughs

### Local path scan

```text
Operator --> depscan CLI --> detect project type --> generate or load BOM --> analyze --> write reports
```

Main concerns:

- surprising subprocess behavior
- untrusted source tree tricks against downstream tooling
- output leakage into CI logs and artifacts

### Server path scan

```text
Remote caller --> /scan?path=... --> host/path checks --> BOM or existing file --> analyze --> response
```

Main concerns:

- path traversal
- local file exposure
- temp file handling
- resource exhaustion

### Server URL scan

```text
Remote caller --> /scan?url=... --> scheme and IP-class validation --> cdxgen server --> BOM --> analyze --> response
```

Main concerns:

- SSRF
- internal network probing
- delegated fetch behavior inside cdxgen
- expensive or repeated remote scans

### Release publish path

```text
Tag push --> pythonpublish.yml --> build packages --> publish to PyPI --> build images --> push to GHCR --> create release assets
```

Main concerns:

- artifact integrity
- workflow authority misuse
- downloaded build tool tampering
- accidental publication from the wrong event or source state

## Plausible abuse cases

A few concrete scenarios are worth keeping in mind during review.

An external caller finds a publicly reachable `dep-scan` server running with the default development API key from an unmodified `docker-compose.yml`. They submit path-based scans against mounted host directories and collect information about internal projects.

A pull request adds a convenient new workflow step that downloads a helper binary with `curl` but does not pin a digest or verify a signature. The workflow still looks reasonable in code review, but it weakens the release chain.

A future refactor allows the cdxgen server URL or registry base URLs to become user-controlled without the same validation currently used for scan URLs. That silently converts a product feature into an SSRF primitive.

A new explanation mode writes more endpoint detail into artifacts uploaded by CI. The feature is correct, but the artifact audience becomes much broader than the author expected.

A Dockerfile change adds a build-time fetch from a mutable latest-style URL. The runtime image still works, but reproducibility and provenance become much weaker.

## Residual risk and open questions

Even with the current hardening, some residual risk is inherent to the product's mission.

Scanning untrusted code is never the same as parsing a simple text file. Downstream build and analysis tooling may have their own attack surface.

Server mode remains appropriate only for trusted environments or carefully segmented deployments. The product now nudges operators in that direction, which is good, but deployment mistakes will still happen.

Workflow integrity is an ongoing maintenance issue. The current workflows are careful in several places, but any future introduction of new downloads, new write permissions, or broader self-hosted usage should trigger fresh review.

The explanation and reachability features create useful but potentially sensitive output. The right balance between value and disclosure depends heavily on where artifacts are stored and who can read them.

## What a reviewer should preserve

When changing the repository, reviewers and AI agents should try hard to preserve the following behaviors.

Server mode should stay safe by default, especially for non-local bind behavior, path constraints, URL validation, and body size limits.

Workflow permissions should stay as narrow as practical.

Direct downloads in workflows and Dockerfiles should remain pinned, verified, or both.

Action references should remain pinned by commit SHA unless there is a compelling reason not to.

Reports and explanation outputs should avoid accidental expansion of sensitive detail without a clear operator-facing reason.

## Practical review checklist for humans and AI agents

Use this checklist when assessing a change.

Start by asking what authority the changed code runs with.

Then ask what inputs influence it.

Then ask where those inputs end up. Filesystem, network, subprocess, logs, artifacts, and published outputs are the most important sinks.

Then look for limiting controls. In this repository, those usually mean allowlists, size limits, fixed hosts, pinned versions, digest verification, read-only workflow permissions, and safe defaults.

Finally, check whether tests and docs still describe the real behavior.

## Closing note

`dep-scan` is a security tool, but it is also a system that processes untrusted material, delegates to external tooling, and publishes artifacts with high trust value. The best reviews in this repository are the ones that keep all three truths in view at the same time.
