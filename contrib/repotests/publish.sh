#!/usr/bin/env bash
# Push one generation of repo-test data to GHCR and write testdata.lock.json.
#
# Run by the publish job of repotests-data.yml over a data root that holds one
# directory per project, each with the files generate.sh produced plus its
# generation.json provenance record. Every file except generation.json becomes
# one layer of an OCI artifact tagged after the project, generation and cdxgen
# version, carrying the source repository, commit, generator versions, cdxgen
# arguments and generation date as annotations. The lock file written at the
# end pins each project to the manifest digest of exactly what was pushed, so
# consumers pull by digest and a refresh reaches them only through a pull
# request that changes the lock file.
#
# The caller must already be logged in to the registry (oras login). Nothing
# here runs project code or cdxgen.
#
# Usage: publish.sh DATA_ROOT REGISTRY
# Environment: ORAS_BIN (default: oras)
set -euo pipefail

DATA_ROOT="$1"
REGISTRY="$2"
ORAS_BIN="${ORAS_BIN:-oras}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SUMMARY_FILE="${GITHUB_STEP_SUMMARY:-/dev/stdout}"

echo "| Project | Tag | Manifest digest |" >> "$SUMMARY_FILE"
echo "| --- | --- | --- |" >> "$SUMMARY_FILE"

for PROJECT_DIR in "$DATA_ROOT"/*/; do
  PROJECT_DIR="${PROJECT_DIR%/}"
  GENERATION_JSON="$PROJECT_DIR/generation.json"
  [ -f "$GENERATION_JSON" ] || continue

  # One provenance field per line, in a fixed order. Plain variables keep
  # the script working on the bash 3.2 that macOS ships, which has no
  # associative arrays.
  {
    IFS= read -r GEN_NAME
    IFS= read -r GEN_GIT
    IFS= read -r GEN_COMMIT
    IFS= read -r GEN_CDXGEN_VERSION
    IFS= read -r GEN_ATOM_VERSION
    IFS= read -r GEN_PLUGINS_VERSION
    IFS= read -r GEN_GENERATED
    IFS= read -r GEN_TAG
    IFS= read -r GEN_CDXGEN_ARGS
  } < <(python3 - "$GENERATION_JSON" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fp:
    generation = json.load(fp)
for key in (
    "name",
    "git",
    "commit",
    "cdxgenVersion",
    "atomVersion",
    "cdxgenPluginsVersion",
    "generated",
    "tag",
):
    value = str(generation[key])
    if "\n" in value:
        sys.exit(f"{key} in {sys.argv[1]} spans several lines")
    print(value)
print(" ".join(generation["cdxgenArgs"]))
PY
)

  NAME="$GEN_NAME"
  TAG="$GEN_TAG"
  REF="$REGISTRY:$TAG"

  LAYER_ARGS=()
  for DATA_FILE in "$PROJECT_DIR"/*.json; do
    BASENAME="$(basename "$DATA_FILE")"
    [ "$BASENAME" = "generation.json" ] && continue
    [ "$BASENAME" = "descriptor.json" ] && continue
    LAYER_ARGS+=("./$BASENAME:application/json")
  done
  if [ "${#LAYER_ARGS[@]}" -eq 0 ]; then
    echo "No data files to publish for $NAME" >&2
    exit 1
  fi

  echo "Pushing $NAME as $REF"
  (cd "$PROJECT_DIR" && "$ORAS_BIN" push "$REF" \
    --artifact-type application/vnd.owasp-dep-scan.repotests.v1 \
    --annotation "org.opencontainers.image.source=$GEN_GIT" \
    --annotation "org.opencontainers.image.revision=$GEN_COMMIT" \
    --annotation "org.opencontainers.image.created=$GEN_GENERATED" \
    --annotation "io.owasp-dep-scan.testdata.project=$GEN_NAME" \
    --annotation "io.owasp-dep-scan.testdata.cdxgen-version=$GEN_CDXGEN_VERSION" \
    --annotation "io.owasp-dep-scan.testdata.atom-version=$GEN_ATOM_VERSION" \
    --annotation "io.owasp-dep-scan.testdata.cdxgen-plugins-version=$GEN_PLUGINS_VERSION" \
    --annotation "io.owasp-dep-scan.testdata.cdxgen-args=$GEN_CDXGEN_ARGS" \
    "${LAYER_ARGS[@]}")

  # The descriptor is the digest the lock file pins; fetching it through the
  # registry proves the push is readable before anything records it.
  "$ORAS_BIN" manifest fetch --descriptor "$REF" > "$PROJECT_DIR/descriptor.json"
  DIGEST="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["digest"])' "$PROJECT_DIR/descriptor.json")"
  echo "| $NAME | $TAG | $DIGEST |" >> "$SUMMARY_FILE"
done

python3 "$SCRIPT_DIR/validate.py" lock \
  --data-root "$DATA_ROOT" \
  --lock-out "$DATA_ROOT/testdata.lock.json" \
  --registry "$REGISTRY"
echo "Lock file written to $DATA_ROOT/testdata.lock.json"
