#!/usr/bin/env bash
# Lesson 07: CI gating with a profile, the exit codes and a findings gate.
#
# Runs the CI profile over a pinned package URL, shows the exit code and the
# JSON output contract, and gates on the findings file with a short Python
# step, reading the coverage block so an unassessed finding cannot pass as a
# clean one.
#
# Needs: dep-scan and an app-only vulnerability database. The scan itself is
# a package URL search, so it is fast and needs no project.
set -euo pipefail

WORK="${WORK:-/tmp/depscan-lesson-07}"
SCANS="$WORK/scans"
mkdir -p "$SCANS"

### Scan with the CI profile
set +e
depscan scan pkg:pypi/requests@2.31.0 --profile ci --vdb-flavor app-only \
  --format json --no-banner -o "$SCANS/reports" > "$SCANS/scan.json"
rc=$?
set -e
echo "scan exit code: $rc"

### The JSON contract: stdout is exactly one document
python3 - "$SCANS" <<'PY'
import json, sys
d = sys.argv[1]
doc = json.load(open(f"{d}/scan.json"))
entry = doc["scans"][0]
print(f"one document, scans: {len(doc['scans'])}")
print(f"target kind: {entry['kind']}")
print(f"findings in the entry: {len(entry['findings'])}")
PY

### Gate on the findings file, coverage included
python3 - "$SCANS/reports" <<'PY'
import json, sys
d = sys.argv[1]
f = json.load(open(f"{d}/depscan.findings.json"))
critical = [x for x in f["findings"]
            if x["severity"] == "critical" and x["coverage"]["state"] == "assessed"]
print(f"assessed critical findings: {len(critical)}")
allfindings = len(f["findings"])
not_assessed = [x for x in f["findings"] if x["coverage"]["state"] == "not_assessed"]
print(f"findings total: {allfindings}, not assessed: {len(not_assessed)}")
PY

### What a failing scan looks like
# A requested capability that cannot run exits 4; the error document is on
# stdout in json format.
set +e
depscan scan pkg:pypi/requests@2.31.0 --checks memory-safety --format json \
  --no-banner -o "$SCANS/refused" > "$SCANS/refused.json" 2>/dev/null
rc=$?
echo "refused scan exit code: $rc"
python3 -c "
import json
doc = json.load(open('$SCANS/refused.json'))
print('error verb:', doc['error']['verb'], 'exitCode:', doc['error']['exitCode'])
"
set -e
