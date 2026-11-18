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
# Arguments after `--` come in pairs. Each `--explanation-mode <mode>` pair
# adds one more depscan run with that rendering, covering the NonReachables
# and Endpoints modes some projects exercise; each `--reachability-analyzer
# <analyzer>` pair adds one more run with that analyzer in place of
# SemanticReachability, such as FrameworkReachability.
#
# Usage: repotest-project.sh NAME [-- --explanation-mode MODE ...]
#                                 [-- --reachability-analyzer ANALYZER ...]
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
EXTRA_ANALYZERS=()
if [ "${1:-}" = "--" ]; then
  shift
  while [ $# -gt 0 ]; do
    if [ $# -lt 2 ]; then
      echo "Arguments after -- must come in pairs" >&2
      exit 1
    fi
    case "$1" in
      --explanation-mode) EXTRA_MODES+=("$2") ;;
      --reachability-analyzer) EXTRA_ANALYZERS+=("$2") ;;
      *)
        echo "Arguments after -- must be --explanation-mode <mode> or --reachability-analyzer <analyzer> pairs" >&2
        exit 1
        ;;
    esac
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
  # The pulled data holds slices and provenance JSON next to the BOMs, so
  # detection alone would classify the directory as source; the forced kind
  # keeps every scan on the BOM-directory ingestion path. The first argument
  # is the reachability analyzer.
  local analyzer="$1"
  shift
  # shellcheck disable=SC2086
  $DEPSCAN scan "$PROJECT_DIR" --target-kind bom-dir \
    --reports-dir "$PROJECT_DIR" --reachability-analyzer "$analyzer" \
    --explain "$@"
}

# The guarded expansions keep bash 3.2 (macOS) from calling an empty array
# unbound under set -u.
for ANALYZER in ${EXTRA_ANALYZERS[@]+"${EXTRA_ANALYZERS[@]}"}; do
  run_depscan "$ANALYZER"
done
for MODE in ${EXTRA_MODES[@]+"${EXTRA_MODES[@]}"}; do
  run_depscan SemanticReachability --explanation-mode "$MODE"
done
# The SemanticReachability run goes last, so the assert below reads its
# reports.
run_depscan SemanticReachability

# shellcheck disable=SC2086
$PYTHON contrib/repotests/validate.py assert "$PROJECT_DIR" \
  --projects contrib/repotests/projects.json --name "$NAME"

rm -rf "$PROJECT_DIR"
echo "repotests $NAME passed"
