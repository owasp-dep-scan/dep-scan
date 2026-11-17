#!/usr/bin/env bash
# Scan one project's pre-generated repo-test data and assert the result.
#
# Copies the artifact the repotests-data action pulled into the reports
# layout, runs the depscan invocation the repo tests use over it
# (SemanticReachability with the --explain rendering), then asserts the
# reachable purl floor and the mustReach packages recorded in
# contrib/repotests/projects.json with the validator. A scan that silently
# reaches nothing fails the assert instead of passing on stale data.
#
# Arguments after `--` come in `--explanation-mode <mode>` pairs; each pair
# adds one more depscan run with that rendering, covering the NonReachables
# and Endpoints modes some projects exercise.
#
# Usage: repotest-project.sh NAME [-- --explanation-mode MODE ...]
# Environment:
#   DATA_DIR    pulled data base directory (default: repotests-data)
#   REPORTS_DIR reports base directory (default: depscan_reports)
#   DEPSCAN     depscan invocation (default: uv run depscan)
#   PYTHON      python invocation for the validator
#               (default: uv run --no-sync python)
set -euo pipefail

NAME="$1"
shift
EXTRA_MODES=()
if [ "${1:-}" = "--" ]; then
  shift
  while [ $# -gt 0 ]; do
    if [ "$1" != "--explanation-mode" ] || [ $# -lt 2 ]; then
      echo "Arguments after -- must be --explanation-mode <mode> pairs" >&2
      exit 1
    fi
    EXTRA_MODES+=("$2")
    shift 2
  done
fi

DATA_DIR="${DATA_DIR:-repotests-data}"
REPORTS_DIR="${REPORTS_DIR:-depscan_reports}"
DEPSCAN="${DEPSCAN:-uv run depscan}"
PYTHON="${PYTHON:-uv run --no-sync python}"

PROJECT_DIR="$REPORTS_DIR/$NAME"
mkdir -p "$PROJECT_DIR"
cp -R "$DATA_DIR/$NAME/." "$PROJECT_DIR/"

run_depscan() {
  # shellcheck disable=SC2086
  $DEPSCAN --src "$PROJECT_DIR" --bom-dir "$PROJECT_DIR" \
    --reports-dir "$PROJECT_DIR" --reachability-analyzer SemanticReachability \
    --explain "$@"
}

run_depscan
# The guarded expansion keeps bash 3.2 (macOS) from calling an empty array
# unbound under set -u.
for MODE in ${EXTRA_MODES[@]+"${EXTRA_MODES[@]}"}; do
  run_depscan --explanation-mode "$MODE"
done

# shellcheck disable=SC2086
$PYTHON contrib/repotests/validate.py assert "$PROJECT_DIR" \
  --projects contrib/repotests/projects.json --name "$NAME"

rm -rf "$PROJECT_DIR"
echo "repotests $NAME passed"
