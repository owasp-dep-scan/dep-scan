---
description: 'A pull-request risk question should load depscan-change-risk.'
tags: [selection]
max_turns: 12
allowed_tools: [Read, Glob, Grep, Skill]
---

CI built two artifacts of our .NET service, before and after the merge. Did the merge add new attack surface or new weakness candidates? What do I run to compare them?
