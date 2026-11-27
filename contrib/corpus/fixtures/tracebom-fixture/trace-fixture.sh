#!/usr/bin/env bash
# Recreate the tracing environment of this fixture: a venv with pyyaml.
# The trace itself was recorded with tracebom and is committed as trace/
# trace-bom.json; this script only rebuilds the interpreter the fixture ran on.
set -euo pipefail
cd "$(dirname "$0")"
python3 -m venv .venv-trace
./.venv-trace/bin/pip install -q pyyaml
