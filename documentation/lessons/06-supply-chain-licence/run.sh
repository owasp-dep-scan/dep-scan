#!/usr/bin/env bash
# Lesson 06: a supply-chain and licence audit.
#
# Runs the supply-chain and licence checks over the same pinned Juice Shop
# commit as lesson 01, and reads the supply-chain findings, the audit's own
# report, the licence report and the manifest stages that record what ran.
#
# Needs: dep-scan, cdxgen 13.10.0 or newer (for the cdx-audit it ships),
# Node.js, and an app-only vulnerability database.
set -euo pipefail

WORK="${WORK:-/tmp/depscan-lesson-06}"
SRC="$WORK/juice-shop"
SCANS="$WORK/scans"
COMMIT=33518f5a0911e25d9df747b1e70fb7af279a755c
mkdir -p "$SCANS"

### Pin the project
if [ ! -d "$SRC/.git" ]; then
  git clone --quiet https://github.com/juice-shop/juice-shop.git "$SRC"
fi
git -C "$SRC" checkout --quiet $COMMIT
echo "project: juice-shop $COMMIT"

### Run the supply-chain and licence checks
depscan scan "$SRC" --checks supply-chain,license --vdb-flavor app-only --no-banner \
  --cdxgen-args "--exclude 'Dockerfile' --exclude 'docker-compose*.yml'" \
  -o "$SCANS/reports"

### What ran, in the manifest's own words
python3 - "$SCANS/reports" <<'PY'
import json, sys
d = sys.argv[1]
m = json.load(open(f"{d}/depscan.manifest.json"))
for s in m["stages"]:
    if s["name"] in ("licenses", "risk"):
        print(f"stage {s['name']}: {s['status']}")
PY

### Read the supply-chain findings
python3 - "$SCANS/reports" <<'PY'
import json, sys
d = sys.argv[1]
findings = json.load(open(f"{d}/depscan.findings.json"))["findings"]
supply = [f for f in findings if f["category"] == "supply-chain"]
print(f"supply-chain findings: {len(supply)}")
rules = {}
for f in supply:
    rules[f["rule"]] = rules.get(f["rule"], 0) + 1
top = sorted(rules.items(), key=lambda kv: (-kv[1], kv[0]))[:3]
print("most frequent rules: " + ", ".join(f"{rule} x{n}" for rule, n in top))
if supply:
    producer = supply[0]["producer"]
    print(f"producer: {producer['name']} {producer['version']}")
audit = json.load(open(f"{d}/cdx-audit-universal.json"))
mode = audit.get("auditMode", "predictive")
print(f"audit mode: {mode}, total findings: {audit['summary']['totalFindings']}")
PY

### Read the licence report
python3 - "$SCANS/reports" <<'PY'
import json, sys
d = sys.argv[1]
rows = json.load(open(f"{d}/license-universal.json"))
print(f"licence rows: {len(rows)}")
copyleft = [r for r in rows if "Same License" in r.get("License conditions", "")]
print(f"copyleft conditions flagged: {len(copyleft)}")
PY
