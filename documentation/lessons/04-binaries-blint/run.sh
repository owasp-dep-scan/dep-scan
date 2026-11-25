#!/usr/bin/env bash
# Lesson 04: a set of binaries with the binary check.
#
# Runs blint's binary review and hardening checks over the analyzer binaries
# the cdxgen plugins package ships, and reads the findings and the coverage
# line.
#
# Needs: dep-scan with the blint package (pip install "owasp-depscan[ext]"),
# and cdxgen installed, whose plugins directory holds the binaries this
# lesson reviews. No vulnerability database beyond the default download is
# needed.
set -euo pipefail

WORK="${WORK:-/tmp/depscan-lesson-04}"
SCANS="$WORK/scans"
mkdir -p "$SCANS"

### Find the binaries to review
# The plugin binaries that cdxgen resolves are the same set on every
# platform, pinned by the plugins package version doctor reports.
PLUGINS="$(depscan doctor --format json | python3 -c '
import json, sys
report = json.load(sys.stdin)
tool = next(t for t in report["tools"] if t["name"] == "cdxgen-plugins")
print(tool["path"])
')"
depscan doctor --format json | python3 -c '
import json, sys
report = json.load(sys.stdin)
tool = next(t for t in report["tools"] if t["name"] == "cdxgen-plugins")
print("plugin binaries:", tool["version"])
'

### Scan the directory as binaries
depscan scan "$PLUGINS" --target-kind binary --checks binary --no-banner \
  -o "$SCANS/binaries"

### Read the findings and the coverage line
python3 - "$SCANS/binaries" <<'PY'
import json, sys
d = sys.argv[1]
f = json.load(open(f"{d}/depscan.findings.json"))
cats = {}
for x in f["findings"]:
    cats[x["category"]] = cats.get(x["category"], 0) + 1
print("categories:", ", ".join(f"{k}: {v}" for k, v in sorted(cats.items())))
producers = sorted({f"{x['producer']['name']} {x['producer']['version']}"
                    for x in f["findings"] if x["category"] == "binary-hardening"})
print("hardening producer:", ", ".join(producers))
x = [r for r in f["findings"] if r["category"] == "binary-hardening"][0]
print(f"first hardening finding: {x['rule']} on {x['components'][0]}")
print(f"binary: {x['locations'][0]['binary']}")
cov = json.load(open(f"{d}/analysis/blint/analysis-coverage.json"))
print("coverage report read:", bool(cov))
PY
