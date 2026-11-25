#!/usr/bin/env bash
# Lesson 08: an agent answering a real question about a scan, through the
# MCP server.
#
# Saves a scan, starts `depscan mcp` over stdio, and drives it the way an
# MCP client does, with the MCP inspector's CLI mode: the summary, the
# findings filter for reached findings, and one finding read back.
#
# Needs: dep-scan with the mcp extra (pip install "owasp-depscan[mcp]"),
# Node.js with npx for the inspector, and an app-only database.
set -euo pipefail

WORK="${WORK:-/tmp/depscan-lesson-08}"
SCANS="$WORK/scans"
mkdir -p "$SCANS"

### Save a scan for the agent to read
depscan scan pkg:pypi/requests@2.31.0 --profile ci --no-banner -o "$SCANS/reports"

### List the tools an MCP client sees
npx -y @modelcontextprotocol/inspector --cli depscan mcp --allow-dir "$SCANS" \
  --method tools/list > "$SCANS/tools.json"
python3 -c "
import json
doc = json.load(open('$SCANS/tools.json'))
names = [t['name'] for t in doc['tools']]
print(f'tools: {len(names)}')
print('read tools:', ', '.join(sorted(names)))
"

### Ask for the summary
npx -y @modelcontextprotocol/inspector --cli depscan mcp --allow-dir "$SCANS" \
  --method tools/call --tool-name scan_summary \
  --tool-arg scan_dir="$SCANS/reports" > "$SCANS/summary.json"
python3 -c "
import json
doc = json.load(open('$SCANS/summary.json'))
state = json.loads(doc['content'][0]['text'])
print('findingCount:', state['findingCount'])
print('countsBySeverity:', json.dumps(state['countsBySeverity']))
"

### Ask for the medium-severity findings
npx -y @modelcontextprotocol/inspector --cli depscan mcp --allow-dir "$SCANS" \
  --method tools/call --tool-name list_findings \
  --tool-arg scan_dir="$SCANS/reports" --tool-arg severity=medium > "$SCANS/medium.json"
python3 -c "
import json
doc = json.load(open('$SCANS/medium.json'))
state = json.loads(doc['content'][0]['text'])
findings = state.get('findings', [])
print('medium findings:', len(findings))
for x in findings:
    axes = x.get('exploitability', {}).get('axes', {})
    print(' ', x['rule'], x['severity'], 'reach', axes.get('reach'))
"

### Read one finding back by its fingerprint
python3 -c "
import json
doc = json.load(open('$SCANS/medium.json'))
state = json.loads(doc['content'][0]['text'])
finding = state['findings'][0]
print(fingerprint := finding['id'])
" > "$SCANS/fingerprint.txt"
npx -y @modelcontextprotocol/inspector --cli depscan mcp --allow-dir "$SCANS" \
  --method tools/call --tool-name get_finding \
  --tool-arg scan_dir="$SCANS/reports" \
  --tool-arg finding_id="$(cat "$SCANS/fingerprint.txt")" > "$SCANS/finding.json"
python3 -c "
import json
doc = json.load(open('$SCANS/finding.json'))
state = json.loads(doc['content'][0]['text'])
print('read back:', state['rule'], 'fix', state.get('fix', {}).get('fixed_versions'))
"
