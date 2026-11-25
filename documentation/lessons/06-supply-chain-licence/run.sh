#!/usr/bin/env bash
# Lesson 06: a supply-chain and licence audit.
#
# Runs the supply-chain and licence checks over the same pinned Juice Shop
# commit as lesson 01, and reads the risk report, the licence report and the
# manifest stages that record what ran.
#
# Needs: dep-scan, cdxgen, Node.js, and an app-only vulnerability database.
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

### Read the risk report
# The report holds the packages the audit flagged: a risk score above the
# threshold (0.5 unless PKG_MAX_RISK_SCORE says otherwise), or a deprecated,
# missing, binary-carrying or private-on-public package. With nothing flagged,
# the file is not written at all.
python3 - "$SCANS/reports" <<'PY'
import json, os, sys
path = os.path.join(sys.argv[1], "depscan-risk-universal.json")
if not os.path.exists(path):
    print("flagged packages: 0 (no risk report written)")
else:
    rows = json.load(open(path))
    print(f"flagged packages: {len(rows)}")
    top = max(rows, key=lambda r: r["Risk Score"])
    print("row shape: Package, Used?, Risk Score, Identified Risks")
    print(f"highest score: {top['Risk Score']} ({len(top['Identified Risks'])} risks identified)")
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
