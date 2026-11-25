#!/usr/bin/env bash
# Lesson 01: a source repository with call-level reachability.
#
# Scans the OWASP Juice Shop project at a pinned commit with atom's
# reachability, follows one reached finding to its call site through the
# evidence store, and reads one not-assessed axis.
#
# Needs: dep-scan, cdxgen, Node.js, and an app-only vulnerability database
# (depscan vdb download --flavor app-only). The clone is cached in $WORK.
set -euo pipefail

WORK="${WORK:-/tmp/depscan-lesson-01}"
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

### Scan with atom reachability
# The typed scan (-t js) plus the research BOM profile is what makes cdxgen
# persist the atom slices the reachability analyzers read. The two exclude
# patterns keep the Dockerfile and the compose file out of a source scan.
depscan scan "$SRC" -t js --bom-profile research --vdb-flavor app-only --no-banner \
  --cdxgen-args "--exclude 'Dockerfile' --exclude 'docker-compose*.yml'" \
  -o "$SCANS/reports"

### What the scan proved
# The manifest's atom entry says the report was read, and the findings file
# holds the reach verdicts.
python3 - "$SCANS/reports" <<'PY'
import json, sys
d = sys.argv[1]
m = json.load(open(f"{d}/depscan.manifest.json"))
atom = [a for s in m["stages"] for a in s.get("analyzers", []) if a["name"] == "atom"][0]
print(f"atom analyzer status: {atom['status']}")
f = json.load(open(f"{d}/depscan.findings.json"))
reach = {}
for x in f["findings"]:
    r = x.get("exploitability", {}).get("axes", {}).get("reach", "not_assessed")
    reach[r] = reach.get(r, 0) + 1
print("reach verdicts:", ", ".join(f"{k}: {v}" for k, v in sorted(reach.items())))
reached = [x for x in f["findings"]
           if x.get("exploitability", {}).get("axes", {}).get("reach") in ("likely", "proven")]
# The lesson follows one finding; naming it keeps the walk-through stable.
x = [r for r in reached if r["rule"] == "CVE-2025-65945"][0]
print(f"reached finding: {x['rule']} on {x['components'][0]}")
print(f"grade: {x['exploitability']['grade']} (rule {x['exploitability']['rule']})")
print(f"witness: {x['exploitability'].get('witness')}")
PY

### Follow the witness into the evidence store
# The witness id names one record in evidence.jsonl; the record carries the
# call path atom traced and the file and line of each hop.
python3 - "$SCANS/reports" <<'PY'
import json, sys
d = sys.argv[1]
f = json.load(open(f"{d}/depscan.findings.json"))
reached = [x for x in f["findings"]
           if x.get("exploitability", {}).get("axes", {}).get("reach") in ("likely", "proven")]
witness = [r for r in reached if r["rule"] == "CVE-2025-65945"][0]["exploitability"]["witness"]
for line in open(f"{d}/evidence.jsonl"):
    r = json.loads(line)
    if r["id"] == witness:
        print(f"record: {r['kind']} from {r['producer']['name']} {r['producer']['version']}")
        hop = r["path"][0]
        print(f"first hop: {hop['file']}:{hop['line']} in {hop['method']}")
        break
PY

### Read one not-assessed axis
# Reach answers what atom traced. Exposure and barrier need dosai, which is
# a .NET analyzer; on this JavaScript project nobody looked, and the finding
# says so instead of implying a clean bill.
python3 - "$SCANS/reports" <<'PY'
import json, sys
d = sys.argv[1]
f = json.load(open(f"{d}/depscan.findings.json"))
reached = [x for x in f["findings"]
           if x.get("exploitability", {}).get("axes", {}).get("reach") in ("likely", "proven")]
x = [r for r in reached if r["rule"] == "CVE-2025-65945"][0]
axes = x["exploitability"]["axes"]
print("axes:", json.dumps(axes))
print("unassessed:", ", ".join(x["exploitability"]["unassessed"]))
PY
