---
type: llm
focus: last_message
---

PASS if the reply's dep-scan command uses absolute paths for both the scan target and the -o reports directory (or says explicitly to substitute an absolute path), and mentions --format json so the output is machine-readable.
FAIL if the reply shows a bare relative target like ./services/api with no absolute-path qualification.
