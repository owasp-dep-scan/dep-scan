#!/usr/bin/env bash
# Build the fixture's two binaries from src/vulnerable.c with the system C
# compiler ($CC, else cc). The corpus scorer runs this script in its copy of
# the fixture before the scan, so no binary is committed and the digest
# covers the sources only. The unprotected build turns off the stack
# protector, PIE, RELRO, NX and fortification; the protected build turns
# them on. The labels describe ELF binaries, so the build needs a Linux
# compiler, and exits 3 elsewhere.
set -euo pipefail
cd "$(dirname "$0")"
CC="${CC:-cc}"
if [ "$(uname -s)" != "Linux" ]; then
  echo "the fixture needs a Linux C compiler that produces ELF binaries; this host is $(uname -s)" >&2
  exit 3
fi
if ! command -v "$CC" >/dev/null 2>&1; then
  echo "no C compiler ($CC) on PATH" >&2
  exit 3
fi
"$CC" -O0 -o binary-unprotected src/vulnerable.c \
  -U_FORTIFY_SOURCE -fno-stack-protector -fno-pie -no-pie \
  -Wl,-z,norelro -Wl,-z,execstack
"$CC" -O2 -o binary-protected src/vulnerable.c \
  -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE -pie \
  -Wl,-z,relro,-z,now -Wl,-z,noexecstack
strip binary-unprotected binary-protected
echo "built binary-unprotected and binary-protected with $("$CC" --version | head -n 1)"
