---
type: regex
target: last_message
pattern: 'depscan\b[^\n]{0,120}\s\./services/api'
flags: i
match: not_contains
---
