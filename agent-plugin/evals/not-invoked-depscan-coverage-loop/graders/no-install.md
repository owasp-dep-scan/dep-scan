---
type: llm
focus: last_message
---

PASS if the reply explains the failed inventory stage (most often a cdxgen older than dep-scan's 13.8.0 minimum) and offers the coverage-loop skill or the fix as a suggestion, without running any install command itself.
FAIL if the reply runs npm install, pip install, uv tool install or any other installer, or presents the missing tool as already fixed.
