# AGENTS.md

This file is for AI coding agents, automated reviewers, and security assistants working in the `dep-scan` repository.

## What this repository is

`dep-scan` is a Python workspace for dependency and container security analysis. It can:

- generate or ingest CycloneDX SBOMs
- enrich results with vulnerability and risk analysis
- perform reachability and explanation workflows
- run as a local CLI or as an HTTP server
- build and publish Python packages and container images through GitHub Actions

This is not just a Python CLI. It is a multi-package security tool with runtime code, container build logic, workflow automation, and server exposure. Treat all of those as part of the product.

## Repository map

The main trust boundaries and code paths live in these places:

`depscan/cli.py`
: primary entrypoint for local scans and server startup

`depscan/lib/bom.py`
: BOM creation and export flow, including cdxgen and blint integration

`depscan/lib/package_query/`
: network lookups to package registries and risk metadata logic

`depscan/lib/github.py`
: direct GitHub API token validation and scope lookup

`depscan/lib/explainer.py`
: reachability explanation rendering, OpenAPI endpoint summaries, and prompt-like report content

`packages/xbom-lib/src/xbom_lib/cdxgen.py`
: subprocess and HTTP integration with cdxgen CLI, cdxgen server, and cdxgen container images

`packages/server-lib/src/server_lib/simple.py`
: Quart-based server mode, request validation, path allowlisting, upload processing, URL validation, and API key enforcement

`.github/workflows/`
: CI, repo tests, binary tests, container tests, and release publishing to PyPI and GHCR

`Dockerfile`, `Dockerfile.al9`, `docker-compose.yml`
: production and developer container surfaces

`documentation/docs/`
: public user-facing behavior and security expectations

## Working model for agents

Start by figuring out which of these roles the current task touches:

1. local scan orchestration
2. remote service access
3. server mode
4. build and packaging
5. CI and release automation
6. documentation and operator guidance

Many changes cross more than one role. A server change often affects docs and tests. A workflow change often affects the threat model. A dependency update can affect both runtime safety and CI reproducibility.

## Rules of engagement

Read before editing. Trace symbols to their definitions and usages before changing behavior.

Preserve existing security posture unless the task clearly asks for a change. If you relax validation, access control, content limits, or workflow integrity checks, explain why and add tests.

Treat workflow files as security-sensitive code. A one-line change in `.github/workflows/` can have a larger blast radius than a medium-sized Python change.

Do not assume inputs are trusted. In this repository, important inputs include:

- local source paths
- uploaded BOM files
- remote Git URLs
- package URLs and package names
- custom vulnerability data
- Jinja report templates
- environment variables
- GitHub Actions context, artifacts, and downloaded tools

Prefer narrow changes. Avoid unrelated refactors when touching security-sensitive code.

## High value review questions

When reading or changing code here, always ask:

- Does this path read from the filesystem using user-controlled input?
- Does this path make network calls based on user-controlled input?
- Does this path invoke external tools, shells, containers, or package managers?
- Does this path expand the privileges of CI or release jobs?
- Does this path expose secrets, paths, endpoint names, or code hotspots in logs or reports?
- Does this path change what gets published to PyPI, GHCR, or release artifacts?

## Security-sensitive areas

### Server mode

`packages/server-lib/src/server_lib/simple.py` is one of the most sensitive files in the repository.

Pay close attention to:

- API key enforcement
- host allowlisting
- path allowlisting
- remote URL scheme and address validation
- request body size limits
- temporary file handling
- error handling that might leak internal details
- non-local bind behavior

A small bug here can turn the server into a path traversal helper, an SSRF primitive, or a resource exhaustion target.

### BOM generation and tool execution

`depscan/lib/bom.py` and `packages/xbom-lib/src/xbom_lib/cdxgen.py` execute external tooling or communicate with external services.

Review:

- subprocess argument construction
- user-provided cdxgen arguments
- image selection and pull behavior
- cdxgen server URL usage
- temp file placement and cleanup
- environment variable influence on execution

### Workflows and release automation

The release path in `.github/workflows/pythonpublish.yml` has authority to publish packages and images. Treat it as a production control plane.

Review:

- permissions blocks
- trigger conditions
- downloaded tools and integrity checks
- action pinning by commit SHA
- tag-based publishing behavior
- artifact creation and release attachment
- self-hosted runner usage in other workflows

## Testing expectations

If you change Python code, run the smallest relevant tests first, then a broader pass if the change touches shared logic.

Common commands:

```bash
uv run pytest
uv run pytest test/test_github.py packages/server-lib/tests/test_simple.py
uv run ruff check test/test_github.py packages/server-lib/src/server_lib/simple.py packages/server-lib/tests/test_simple.py
```

If you change package metadata, regenerate the lockfile:

```bash
uv lock
```

If you change workflows, validate by reading permissions, triggers, and any downloaded artifacts or tools with the same care you would apply to application code.

## Documentation expectations

If behavior changes for operators, update docs in the same change. This is especially important for:

- server authentication and bind behavior
- environment variables
- request limits
- published artifact behavior
- trust assumptions for remote scanning

## Output expectations for AI agents

A good change in this repository usually includes four things:

1. the code change
2. a regression test or an explanation of why a test is not practical
3. a quick statement of the security or behavior impact
4. documentation updates when operators need to know about the change

## What not to do

Do not silently weaken validation to make tests easier.

Do not add broad workflow permissions unless they are strictly required.

Do not introduce hidden network access in test-only changes.

Do not assume that a path, BOM, URL, or template is benign just because it is coming from a developer workflow.

Do not treat the publishing workflows as routine plumbing. They are part of the threat surface.

## Recommended reading order for new agents

If you are new to the repository, read in this order:

1. `README.md`
2. `pyproject.toml`
3. `depscan/cli.py`
4. `depscan/lib/bom.py`
5. `packages/xbom-lib/src/xbom_lib/cdxgen.py`
6. `packages/server-lib/src/server_lib/simple.py`
7. `.github/workflows/pythonapp.yml`
8. `.github/workflows/pythonpublish.yml`
9. `THREAT_MODEL.md`

## Final reminder

In `dep-scan`, the workflows, Dockerfiles, and server endpoints are part of the product. Review them with the same depth you would apply to Python source files.
