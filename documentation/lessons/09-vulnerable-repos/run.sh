#!/usr/bin/env bash
# Lesson 09: what dep-scan proves on deliberately vulnerable projects, and
# what it cannot.
#
# Scans three well-known vulnerable applications at pinned commits: Juice
# Shop (Node), DVWA (PHP) and railsgoat (Ruby), and reads the findings and
# the reach verdicts: npm is a reachability ecosystem, PHP and Ruby are not,
# and the reports say so instead of implying it.
#
# Needs: dep-scan, cdxgen, Node.js, PHP and Ruby for their managers, and an
# app-only vulnerability database.
set -euo pipefail

WORK="${WORK:-/tmp/depscan-lesson-09}"
SCANS="$WORK/scans"
mkdir -p "$SCANS"

### Pin the three projects
clone() {
  local url="$1" commit="$2" dir="$3"
  if [ ! -d "$WORK/$dir/.git" ]; then
    git clone --quiet "$url" "$WORK/$dir"
  fi
  git -C "$WORK/$dir" checkout --quiet "$commit"
}
clone https://github.com/juice-shop/juice-shop.git 33518f5a0911e25d9df747b1e70fb7af279a755c juice-shop
clone https://github.com/digininja/DVWA.git 068d974487a297c155c48722f9fcf7180a83adc4 DVWA
clone https://github.com/OWASP/railsgoat.git f5951f13089d85c979de09e7da3c8c0fb982f94a railsgoat
echo "pinned: juice-shop, DVWA, railsgoat"

### Scan each project typed
# Typed scans keep the container files in these trees from turning a source
# scan into an image-pulling run.
depscan scan "$WORK/juice-shop" -t js --bom-profile research --no-banner \
  --cdxgen-args "--exclude 'Dockerfile' --exclude 'docker-compose*.yml'" \
  -o "$SCANS/juice-shop"
depscan scan "$WORK/DVWA" -t php --no-banner -o "$SCANS/dvwa"
depscan scan "$WORK/railsgoat" -t ruby --no-banner -o "$SCANS/railsgoat"

### What v7 proves, and what it cannot
python3 - "$SCANS" <<'PY'
import json, sys
scans = sys.argv[1]
for name in ("juice-shop", "dvwa", "railsgoat"):
    f = json.load(open(f"{scans}/{name}/depscan.findings.json"))
    reaches = {x.get("exploitability", {}).get("axes", {}).get("reach") for x in f["findings"]}
    assessed = all(r in ("likely", "proven", "unknown") for r in reaches)
    print(f"{name}: findings {len(f['findings'])}, reach assessed: {assessed}")
    if not assessed:
        print(f"{name}: reach verdict is not_assessed, with the analyzer gap named in the manifest")
PY
