# SKILL.md

This document describes the skill profile an AI agent should use when reviewing or modifying `dep-scan`.

## Core mindset

Work like a careful security engineer who also understands packaging, automation, and developer ergonomics.

The repository rewards agents that can switch between several modes of thinking:

- Python application review
- server-side input validation review
- subprocess and toolchain safety review
- supply chain and release engineering review
- documentation quality review

A weak agent treats this repository as a simple CLI. A strong agent recognizes that `dep-scan` is a security product whose workflows, containers, and default guidance matter as much as its Python code.

## What strong repository knowledge looks like

A skilled agent knows that `dep-scan` operates across several layers.

At the top level, `depscan/cli.py` orchestrates scans, report generation, and server startup.

BOM generation is delegated to code in `depscan/lib/bom.py` and `packages/xbom-lib/src/xbom_lib/cdxgen.py`. That means scan behavior is shaped by local tools, HTTP calls to cdxgen server mode, and container-image based execution.

Analysis and explanation logic lives in the Python workspace packages, especially `analysis-lib`, `reporting-lib`, and the reachability and explanation code.

Server mode lives in `packages/server-lib/src/server_lib/simple.py`, which is a separate attack surface with request parsing, file uploads, path handling, URL validation, and optional authentication.

The release and assurance story lives in `.github/workflows/`, Dockerfiles, and packaging metadata. That is not background noise. It is production code with authority.

## Skills an agent should actively apply

### 1. Trace external influence

For every change, identify where outside data enters the system. Typical examples are:

- CLI flags
- environment variables
- uploaded files
- local paths
- remote Git URLs
- package URLs
- registry responses
- GitHub API responses
- workflow inputs, artifacts, and downloaded binaries

The agent should follow those values forward until they hit one of these sinks:

- filesystem reads or writes
- subprocess execution
- network requests
- template rendering
- log output
- generated artifacts and release assets

### 2. Understand trust boundaries

This repository has multiple trust zones.

A local CLI scan is usually user-driven and trusted by the operator, but it can still point at untrusted source trees or archives.

Server mode is much more sensitive because the caller may be remote.

CI on pull requests usually runs untrusted proposed code with limited repository authority.

Release workflows run on trusted branches or tags and have package and contents write access.

A strong agent changes behavior with those trust zones in mind.

### 3. Review subprocess construction carefully

`dep-scan` delegates important work to other tools. Reviewers should look for:

- argument list construction
- use of `shell=True` or platform-specific shell execution
- user-controlled arguments being passed through unchecked
- environment variables that change tool behavior
- networked backends where a local-only assumption no longer holds

The right question is not just "does this command run?" but "who gets to shape what this command does?"

### 4. Read workflows as attack surface

A capable agent should be comfortable reviewing GitHub Actions with the same depth used for Python code.

That means checking:

- event triggers
- permissions blocks
- use of secrets and trusted publishing
- action pinning by commit SHA
- direct downloads with `curl`
- checksums, signatures, or pinned digests
- artifact upload and download chains
- external repository checkouts
- self-hosted runner exposure

In this repository, workflows test real sample repos, download datasets, fetch binaries, build containers, and publish artifacts. That deserves first-class review attention.

### 5. Understand output sensitivity

Some outputs are more sensitive than they look.

Reachability reports, endpoint summaries, and prompt-oriented explanation outputs can expose:

- internal endpoint names
- code hotspots
- file paths
- dependency names and versions
- potentially sensitive operational details

A strong agent evaluates whether a change increases accidental disclosure in logs, artifacts, or published outputs.

## Review heuristics by subsystem

### CLI and analysis flow

When reviewing `depscan/cli.py` and related logic, check whether a new argument changes:

- which files are read
- which network calls happen
- which report files are written
- which analyzers are selected automatically
- whether behavior differs between local use and CI

### Server mode

When reviewing `packages/server-lib/src/server_lib/simple.py`, treat each request field as adversarial.

Focus on:

- authentication
- authorization by host and path
- SSRF resistance
- body size limits
- file type validation
- temporary file lifecycle
- error behavior
- safe defaults for network exposure

### BOM generation

When reviewing `depscan/lib/bom.py` and `packages/xbom-lib/src/xbom_lib/cdxgen.py`, check:

- fallback behavior between local CLI, container image, and cdxgen server
- execution with untrusted source directories
- how optional `cdxgen_args` or environment variables alter behavior
- whether network access is implicit or explicit

### Package metadata and GitHub integrations

When reviewing registry and GitHub lookups, check:

- fixed vs user-controlled hosts
- timeout behavior
- retries and circuit breakers
- error handling that changes security posture
- token handling and scope interpretation

### Containers and release automation

When reviewing Dockerfiles and publish workflows, check:

- downloaded tool provenance
- package manager trust
- pinned versions
- final runtime user and filesystem permissions
- what exactly is being published, signed, or attached

## What a high quality agent output should include

A strong review or implementation response should usually contain:

A brief architecture-aware summary of the affected surface.

A clear statement of the trust boundary involved.

Any residual risk or assumption that remains after the change.

Evidence of validation. This usually means targeted tests, lint, or workflow reasoning grounded in the current files.

If the change affects operator behavior, the response should also mention the corresponding docs that were updated or should be updated.

## Common mistakes to avoid

Do not focus only on syntax and unit tests.

Do not miss workflow privilege changes because they live outside Python.

Do not assume that validation in the CLI automatically protects server mode.

Do not overlook the security effect of changing defaults.

Do not ignore release integrity just because package publishing is "ops". In this repository, it is part of the product trust model.

## Fast review playbook

When time is short, use this sequence.

First, identify the entrypoint and trust boundary.

Second, identify user-controlled inputs.

Third, identify execution sinks such as filesystem access, network access, subprocesses, and artifact publication.

Fourth, check whether there is a limiting control such as allowlisting, size limits, authentication, or pinned integrity data.

Fifth, check tests and docs.

This simple loop catches a surprising amount of real risk in `dep-scan`.

## Relationship to other repository docs

Read `AGENTS.md` for repository operating guidance.

Read `THREAT_MODEL.md` for the detailed security model, attack paths, and workflow review guidance.
