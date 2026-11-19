---
type: llm
focus: last_message
---

PASS if the reply says to use --format json so stdout carries exactly one JSON document with logs on stderr, and gives the exit-code meanings including 0 success, 1 could not run, 2 usage error and 4 a capability that cannot run on this machine.
FAIL if the reply suggests scraping the human tables, or describes exit codes that treat findings or a clean scan as changing the exit code.
