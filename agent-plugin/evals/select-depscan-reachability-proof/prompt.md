---
description: 'A reachability question should load depscan-reachability-proof, whose commands name their analyzer and root set.'
tags: [selection]
max_turns: 12
allowed_tools: [Read, Glob, Grep, Skill]
---

We ship a Go service and CVE-2026-25645 hits a package in our BOM. Is that code actually reachable from our main function, or is it dead weight? Show me how to prove it.
