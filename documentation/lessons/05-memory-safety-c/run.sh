#!/usr/bin/env bash
# Lesson 05: C and C++ memory safety.
#
# dep-scan's memory-safety check is not implemented in this version, and the
# lesson shows that refusal honestly, then runs the analyzer behind the
# planned check, atom memory-safety, over a pinned C project, and reads one
# finding with its flow.
#
# Needs: dep-scan, cdxgen (which bundles atom), and no vulnerability
# database for the refusal path.
set -euo pipefail

WORK="${WORK:-/tmp/depscan-lesson-05}"
SRC="$WORK/C23-examples"
COMMIT=46ecae4927f761ca434077bfd22270ae0360647a
mkdir -p "$WORK"

### Pin the project
if [ ! -d "$SRC/.git" ]; then
  git clone --quiet https://github.com/scivision/C23-examples "$SRC"
fi
git -C "$SRC" checkout --quiet $COMMIT
echo "project: C23-examples $COMMIT"

### The check refuses, honestly
# Naming the check stops the scan with exit 4 before any work runs.
set +e
depscan scan "$SRC" --checks memory-safety --no-banner -o "$WORK/scans/refusal"
echo "exit code: $?"
set -e

# --no-build-tools never runs the project's build system, --auto-defines
# defines the build-option macros a macro census finds, and the parse report
# names every file the front end left out, so an unparseable project is never
# reported as clean. --cache none keeps atom from writing into the tree.
OUT="$WORK/scans/atom-memsafety"
mkdir -p "$OUT"
# atom writes its findings JSON to slices.json in the working directory, so
# the run starts there.
(cd "$OUT" && atom memory-safety -l c "$SRC" --auto-defines --no-build-tools \
  --cache none --format json -o ms.atom --parse-report parse-report.json)

### Read one finding with its flow
python3 - "$OUT" <<'PY'
import json, sys
d = sys.argv[1]
findings = json.load(open(f"{d}/slices.json"))
print(f"memory-safety findings: {len(findings)}")
x = findings[0]
print(f"rule: {x['rule']} ({x['cwe']}), severity {x['severity']}, confidence {x['confidence']}")
print(f"location: {x['file']}:{x['line']}")
flow_roles = [step.get("role") for step in x["flow"]]
print("flow roles:", ", ".join(r for r in flow_roles if r))
report = json.load(open(f"{d}/parse-report.json"))
units = report.get("units", report)
print("parse report entries:", len(units))
PY
