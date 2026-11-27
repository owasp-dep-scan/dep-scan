#!/usr/bin/env bash
# Record the runtime trace of this fixture: a venv with pyyaml outside the
# fixture directory, then tracebom over one run of trace_target.py. The
# trace lands in analysis/tracebom/trace-bom.json, where a BOM-directory
# scan's tracebom adapter reads it. No trace is committed: the only capture
# recorded so far (macOS) named no component, and no Linux capture exists.
set -euo pipefail
cd "$(dirname "$0")"
VENV="${TMPDIR:-/tmp}/tracebom-fixture-venv"
python3 -m venv "$VENV"
"$VENV/bin/pip" install -q pyyaml
mkdir -p analysis/tracebom
tracebom --cmd "$VENV/bin/python trace_target.py" -o analysis/tracebom/trace-bom.json
