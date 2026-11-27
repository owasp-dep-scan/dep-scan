#!/usr/bin/env bash
# Rebuild the two committed binaries from src/vulnerable.c in a Linux
# container, so the corpus carries ELF binaries whose hardening properties
# are reproducible. The unprotected build uses none of the hardening flags;
# the protected build uses the stack protector, full RELRO, PIE and NX.
set -euo pipefail
cd "$(dirname "$0")"

docker run --rm -v "$PWD":/w --workdir /w gcc:13-bookworm \
  bash -c '
    set -euxo pipefail
    gcc -O0 -o binary-unprotected src/vulnerable.c \
      -fno-stack-protector -no-pie -Wl,-z,norelro -Wl,-z,execstack
    gcc -O2 -o binary-protected src/vulnerable.c \
      -fstack-protector-strong -D_FORTIFY_SOURCE=2 -pie -fPIE \
      -Wl,-z,relro,-z,now
    strip binary-unprotected binary-protected
  '

echo "built binary-unprotected and binary-protected"
