---
type: llm
focus: last_message
---

PASS if the reply says to use --format json so stdout carries one JSON document with logs on stderr, and gives the exit-code meanings: 0 the scan or command ran (findings never change it), 1 could not run, 2 usage error, 4 a capability that cannot run on this machine. Mentioning --fail-on-error, which turns a failed stage into a non-zero exit, is fine and is not findings changing the exit code.
FAIL if the reply suggests scraping the human tables, or says that findings, or a scan with findings, change the exit code.
