---
description: 'An image audit request should load depscan-container-image, not the source scan skill.'
tags: [selection]
max_turns: 12
allowed_tools: [Read, Glob, Grep, Skill]
---

Is our alpine:3.19 base image carrying any known CVEs? We run it on arm64. Tell me the command to check with dep-scan.
