#!/usr/bin/env bash
# Generate the repo-test data of one project declared in projects.json.
#
# The project is cloned at exactly its pinned commit (never a branch or a
# tag), then cdxgen runs once per project type with the recorded arguments,
# writing every BOM, reachables and usages slice, and OpenAPI file into
# OUT_DIR. The generate job of repotests-data.yml and local pre-flight runs
# both use this script, so both produce the same file layout: one directory
# per project, holding sbom-<type>.cdx.json, <language>-reachables.slices.json,
# <language>-usages.slices.json and <language>-openapi.json files.
#
# cdxgen executes the scanned project's build tooling (package managers,
# compilers), so this script must only run in an environment that holds no
# write token, such as the generate job, or deliberately on a workstation.
#
# Usage: generate.sh NAME SRC_DIR OUT_DIR [PROJECTS_JSON]
# Environment:
#   CDXGEN_BIN            cdxgen executable (default: cdxgen on PATH)
#   GENERATE_TIMEOUT_SECS per-type cdxgen timeout in seconds (default: 5400)
set -euo pipefail

NAME="$1"
SRC_DIR="$2"
OUT_DIR="$3"
PROJECTS_JSON="${4:-$(cd "$(dirname "$0")" && pwd)/projects.json}"

CDXGEN_BIN="${CDXGEN_BIN:-cdxgen}"
# npm prefix holding the cdxgen install; the recorded atom and plugins
# versions are read from its node_modules. Defaults to the global prefix.
CDXGEN_NPM_PREFIX="${CDXGEN_NPM_PREFIX:-$(npm prefix -g)}"
GENERATE_TIMEOUT_SECS="${GENERATE_TIMEOUT_SECS:-5400}"
# cdxgen stops atom after ~19.5 minutes by default, which large JVM and C
# projects do not fit; give atom the same budget the outer timeout gives
# the whole run. ATOM_TIMEOUT is milliseconds.
export ATOM_TIMEOUT="${ATOM_TIMEOUT:-$((GENERATE_TIMEOUT_SECS * 1000))}"

# timeout(1) is GNU coreutils; macOS ships it as gtimeout when coreutils is
# installed through Homebrew.
TIMEOUT_BIN="$(command -v timeout || command -v gtimeout || true)"
if [ -z "$TIMEOUT_BIN" ]; then
  echo "GNU timeout (or gtimeout) is required to bound each cdxgen run" >&2
  exit 1
fi

# Tab-separated fields: the two JSON arrays carry spaces of their own.
IFS=$'\t' read -r GIT_URL COMMIT TYPES_JSON CDXGEN_ARGS_JSON < <(python3 - "$PROJECTS_JSON" "$NAME" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fp:
    projects = json.load(fp)["projects"]
entry = next((p for p in projects if p["name"] == sys.argv[2]), None)
if entry is None:
    sys.exit(f"No project named {sys.argv[2]} in {sys.argv[1]}")
print(
    entry["git"],
    entry["commit"],
    json.dumps(entry["types"], separators=(",", ":")),
    json.dumps(entry.get("cdxgenArgs", []), separators=(",", ":")),
    sep="\t",
)
PY
)

mapfile -t TYPES < <(python3 -c 'import json,sys; [print(t) for t in json.loads(sys.argv[1])]' "$TYPES_JSON")
mapfile -t CDXGEN_ARGS < <(python3 -c 'import json,sys; [print(a) for a in json.loads(sys.argv[1])]' "$CDXGEN_ARGS_JSON")

if [ ! -d "$SRC_DIR/.git" ]; then
  echo "Cloning $GIT_URL at $COMMIT"
  mkdir -p "$SRC_DIR"
  git -C "$SRC_DIR" init -q
  git -C "$SRC_DIR" remote add origin "$GIT_URL"
  git -C "$SRC_DIR" fetch -q --depth 1 origin "$COMMIT"
  git -C "$SRC_DIR" checkout -q --detach FETCH_HEAD
fi
HEAD_COMMIT="$(git -C "$SRC_DIR" rev-parse HEAD)"
if [ "$HEAD_COMMIT" != "$COMMIT" ]; then
  echo "SRC_DIR holds $HEAD_COMMIT but projects.json pins $COMMIT" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
for project_type in "${TYPES[@]}"; do
  echo "Generating $NAME ($project_type) with $CDXGEN_BIN ${CDXGEN_ARGS[*]} -t $project_type"
  "$TIMEOUT_BIN" --signal=KILL "$GENERATE_TIMEOUT_SECS" \
    "$CDXGEN_BIN" "${CDXGEN_ARGS[@]}" -t "$project_type" \
    -o "$OUT_DIR/sbom-$project_type.cdx.json" \
    "$SRC_DIR" || {
      code=$?
      echo "cdxgen for $NAME ($project_type) failed with exit code $code" >&2
      exit "$code"
    }
done

# Only the JSON files are test data. The atom databases (*.atom) and source
# maps (*.json.map) cdxgen leaves beside them are large and read by nothing
# downstream, so they are removed before the files are uploaded.
find "$OUT_DIR" -maxdepth 1 -type f ! -name '*.json' -delete

# Provenance of this generation, read by the publish job to annotate the OCI
# artifact and to write testdata.lock.json. Written last: the file exists only
# once every type ran successfully. The version is matched on the dotted
# triple because the banner line carries ANSI colour codes around it.
CDXGEN_VERSION="$("$CDXGEN_BIN" --version | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')"
if [ -z "$CDXGEN_VERSION" ]; then
  echo "Could not read the cdxgen version from $CDXGEN_BIN --version" >&2
  exit 1
fi
python3 "$(cd "$(dirname "$0")" && pwd)/write_provenance.py" "$OUT_DIR" \
  --name "$NAME" \
  --git "$GIT_URL" \
  --commit "$COMMIT" \
  --types-json "$TYPES_JSON" \
  --cdxgen-args-json "$CDXGEN_ARGS_JSON" \
  --cdxgen-version "$CDXGEN_VERSION" \
  --npm-prefix "$CDXGEN_NPM_PREFIX"

echo "Files generated for $NAME:"
(cd "$OUT_DIR" && find . -maxdepth 1 -type f -name "*.json" -exec ls -lh {} \;)
