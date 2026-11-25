#!/usr/bin/env bash
# Lesson 02: a Go service with call-graph reachability through golem.
#
# Scans a Go microservice project at a pinned commit, follows one reached
# finding to the call path golem traced, and reads the budget caveat that
# tempers the verdict.
#
# Needs: dep-scan, cdxgen, the Go toolchain, golem (from cdxgen-plugins-bin),
# and an app-only vulnerability database. The first run lets golem download
# the project's modules through the local Go environment.
set -euo pipefail

WORK="${WORK:-/tmp/depscan-lesson-02}"
SRC="$WORK/shop-golang-microservices"
SCANS="$WORK/scans"
COMMIT=76c34f1ab7e428f6106c5cf291570502df4ff257
mkdir -p "$SCANS"

### Pin the project
if [ ! -d "$SRC/.git" ]; then
  git clone --quiet https://github.com/meysamhadeli/shop-golang-microservices "$SRC"
fi
git -C "$SRC" checkout --quiet $COMMIT
echo "project: shop-golang-microservices $COMMIT"

### Scan with golem reachability
# The typed scan (-t go) starts golem directly; semantic reachability also
# attributes the reached services and endpoints.
depscan scan "$SRC" -t go --bom-profile research --vdb-flavor app-only \
  --reachability-analyzer SemanticReachability --no-banner \
  -o "$SCANS/reports"

### What the scan proved
python3 - "$SCANS/reports" <<'PY'
import json, sys
d = sys.argv[1]
m = json.load(open(f"{d}/depscan.manifest.json"))
golem = [a for s in m["stages"] for a in s.get("analyzers", []) if a["name"] == "golem"][0]
print(f"golem analyzer status: {golem['status']}")
f = json.load(open(f"{d}/depscan.findings.json"))
reached = [x for x in f["findings"]
           if x.get("exploitability", {}).get("axes", {}).get("reach") in ("likely", "proven")]
print(f"findings: {len(f['findings'])}, reached: {len(reached)}")
# The lesson follows the docker client finding; naming it keeps the
# walk-through stable.
x = [r for r in reached if r["rule"] == "GHSA-jq35-85cj-fj4p"][0]
print(f"reached finding: {x['rule']} on {x['components'][0]}")
print(f"grade: {x['exploitability']['grade']} (rule {x['exploitability']['rule']})")
print(f"presence: {x['exploitability']['axes']['presence']}, reach: {x['exploitability']['axes']['reach']}")
witness = x["exploitability"]["witness"]
for line in open(f"{d}/evidence.jsonl"):
    r = json.loads(line)
    if r["id"] == witness:
        hop = r["path"][0]
        print(f"witness kind: {r['kind']} from {r['producer']['name']} {r['producer']['version']}")
        print(f"first hop: {hop['method']}")
        for c in r.get("caveats", []):
            print(f"caveat: {c['kind']}: {c['detail']}")
        break
PY

### What stayed not assessed
# Exposure and barrier are dosai's to assess, and dosai is a .NET analyzer.
python3 - "$SCANS/reports" <<'PY'
import json, sys
d = sys.argv[1]
f = json.load(open(f"{d}/depscan.findings.json"))
reached = [x for x in f["findings"]
           if x.get("exploitability", {}).get("axes", {}).get("reach") in ("likely", "proven")]
x = [r for r in reached if r["rule"] == "GHSA-jq35-85cj-fj4p"][0]
print("unassessed:", ", ".join(x["exploitability"]["unassessed"]))
PY
