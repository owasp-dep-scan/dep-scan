---
description: 'A native-code defect question should load depscan-memory-safety and its atom memory-safety command.'
tags: [selection]
max_turns: 12
allowed_tools: [Read, Glob, Grep, Skill]
---

Our C library has had two buffer overflows in the last year. Can we sweep the whole codebase for memory-safety defects and rank them by whether an entry point reaches them?
