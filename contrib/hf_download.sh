#!/usr/bin/env bash
# Wrapper around `hf download` that retries with exponential backoff.
#
# The repo tests pull pre-generated BOMs from the AppThreat/ukaina dataset in
# every matrix job. huggingface.co answers a share of those requests with
# HTTP 429 (Too Many Requests) even with HF_TOKEN set, simply because the whole
# matrix fetches the same dataset at the same time. A single attempt is
# therefore not reliable enough to gate a build on.
#
# The CLI runs through uvx so the download does not depend on the project
# virtual environment.
#
# Usage: hf_download.sh <hf download arguments...>
# Tunables: HF_DOWNLOAD_ATTEMPTS (default 5), HF_DOWNLOAD_DELAY (default 15s).
set -uo pipefail

attempts="${HF_DOWNLOAD_ATTEMPTS:-5}"
delay="${HF_DOWNLOAD_DELAY:-15}"

for attempt in $(seq 1 "${attempts}"); do
  if uvx --from "huggingface_hub[cli]" hf download "$@"; then
    exit 0
  fi
  if [ "${attempt}" -eq "${attempts}" ]; then
    break
  fi
  echo "hf download failed (attempt ${attempt}/${attempts}); retrying in ${delay}s" >&2
  sleep "${delay}"
  delay=$((delay * 2))
done

echo "hf download failed after ${attempts} attempts: $*" >&2
exit 1
