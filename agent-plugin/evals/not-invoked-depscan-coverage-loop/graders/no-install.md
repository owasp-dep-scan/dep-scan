---
type: regex
target: last_message
pattern: 'npm\s+install|pip\s+install|uv\s+(pip\s+)?(install|tool\s+install)'
flags: i
negate: true
---
