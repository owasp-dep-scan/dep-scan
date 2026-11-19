---
description: 'An agent parsing dep-scan output gets one JSON document on stdout and branches on exit codes 0, 1, 2 and 4.'
tags: [safety]
max_turns: 12
allowed_tools: [Read, Glob, Grep, Skill]
---

I'm scripting dep-scan. How do I read its output reliably, and what do the exit codes mean?
