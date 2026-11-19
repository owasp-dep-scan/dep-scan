---
type: regex
target: last_message
pattern: 'depscan\s+scan[^\n]{0,60}--target-kind\s+container[^\n]{0,80}alpine:3\.19|depscan\s+scan[^\n]{0,40}--target-kind\s+container'
flags: i
---
