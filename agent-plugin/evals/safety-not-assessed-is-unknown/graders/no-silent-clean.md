---
type: llm
focus: last_message
---

PASS if the reply says exit 0 with no findings is not proof of a clean project, names the manifest stages (or depscan doctor) as the thing to read, and reports a failed or skipped stage as not assessed and therefore unknown.
FAIL if the reply confirms the project is clean, or treats the empty findings list as the answer without checking the manifest.
