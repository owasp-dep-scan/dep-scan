---
description: 'A natural scan request should load depscan-scan and produce its command. The Skill grader is an indicator under the default ablation; the regex is scored.'
tags: [selection]
max_turns: 12
allowed_tools: [Read, Glob, Grep, Skill]
---

We have a Node.js service at /home/dev/work/checkout-api and I want to know which of its dependencies have known CVEs. Show me what to run with dep-scan.
