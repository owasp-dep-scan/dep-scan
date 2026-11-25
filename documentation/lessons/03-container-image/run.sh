#!/usr/bin/env bash
# Lesson 03: a container image, its OS and application packages, and what an
# image scan cannot see.
#
# Scans the nginx:alpine image by digest with the full database flavor, then
# the redmine image, whose findings span the Debian OS layer and the bundled
# Rails gems.
#
# Needs: dep-scan, cdxgen, a container daemon (docker, podman or nerdctl),
# and the full vulnerability database (depscan vdb download --flavor full).
# The images are
# pulled by digest, so the bytes are pinned.
set -euo pipefail

WORK="${WORK:-/tmp/depscan-lesson-03}"
SCANS="$WORK/scans"
mkdir -p "$SCANS"

### Scan nginx:alpine by digest with the full flavor
# The digest pins the bytes. The full flavor carries the OS advisories an
# image scan needs; app-only would leave the apk packages matching nothing.
depscan scan nginx@sha256:7fc0fb4af7bf006aeb31aea88069976060f8f0a0a86b667126742cc17f4e31ae \
  --vdb-flavor full --no-banner -o "$SCANS/nginx"

### What the OS layer produced
python3 - "$SCANS/nginx" <<'PY'
import json, sys
d = sys.argv[1]
m = json.load(open(f"{d}/depscan.manifest.json"))
print(f"database flavor: {m['database']['flavorUsed']}")
print(f"inventory stage: {next(s['status'] for s in m['stages'] if s['name'] == 'inventory')}")
f = json.load(open(f"{d}/depscan.findings.json"))
print(f"findings: {len(f['findings'])}")
types = sorted({c.split(':')[1].split('/')[0] for x in f['findings'] for c in x['components']})
print("component types:", ", ".join(types))
PY

### Scan redmine, an application-on-an-OS image
depscan scan redmine@sha256:c3c9da0407e99b2a47af9e0af7b06bce1a3cfec16def1c14cd1fae61e3fa0770 \
  --vdb-flavor full --no-banner -o "$SCANS/redmine"

### The two layers in one report
python3 - "$SCANS/redmine" <<'PY'
import json, sys
d = sys.argv[1]
f = json.load(open(f"{d}/depscan.findings.json"))
print(f"findings: {len(f['findings'])}")
types = sorted({c.split(':')[1].split('/')[0] for x in f['findings'] for c in x['components']})
print("component types:", ", ".join(types))
PY
