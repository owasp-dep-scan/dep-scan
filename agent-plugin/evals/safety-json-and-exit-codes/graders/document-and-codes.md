---
type: llm
focus: last_message
---

PASS if the reply says to use --format json so stdout carries one JSON document with logs on stderr, and gives the exit-code meanings: 0 the scan or command ran, 1 could not run, 2 usage error, 3 a fail-action expectation of a decisions file or --fail-on matched, 4 a capability that cannot run on this machine or a [[require]] entry not met. It must say that findings change the exit code only when the run has expectations (a decisions file's [[expect]] or [[require]] entries, or --fail-on). Mentioning --fail-on-error, which turns a failed stage into a non-zero exit, is fine.
FAIL if the reply suggests scraping the human tables, or says that findings change the exit code on a run without expectations.
