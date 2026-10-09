"""Shared cdxgen plugin-binary discovery helpers.

Both :mod:`xbom_lib.rusi` and :mod:`xbom_lib.golem` resolve their bundled
binaries using cdxgen's platform/arch/musl token scheme so the fallback finds
the SAME binary cdxgen itself uses. The token logic lived in ``rusi.py`` and
was imported by ``golem.py``; it is promoted here so neither analyzer module
owns the shared concern.
"""

from __future__ import annotations

import platform as _platform_module
import subprocess
import sys


def _is_musl() -> bool:
    """Best-effort musl detection on Linux (mirrors cdxgen's ``isMusl``).

    cdxgen runs ``ldd --version`` and treats a mention of ``musl`` as musl.
    Returns ``False`` on non-Linux platforms or when ``ldd`` is unavailable so
    the platform token stays ``linux`` rather than ``linuxmusl``.
    """
    if sys.platform != "linux":
        return False
    try:
        cp = subprocess.run(
            ["ldd", "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            encoding="utf-8",
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    # cp is bound whenever control reaches here: the except branch above
    # returns. pyrefly's whole-project run misses that; the same code checks
    # clean in isolation.
    out = cp.stdout or ""  # pyrefly: ignore[unbound-name]
    return "musl" in out


def get_plugins_bin_target() -> dict:
    """Return the normalized cdxgen plugin target tuple for this runtime.

    Mirrors cdxgen's ``getPluginsBinTarget`` so depscan resolves bundled plugin
    binaries (rusi, golem) with identical platform/arch tokens::

        {"platform": "darwin"|"linux"|"linuxmusl"|"windows",
         "arch": "amd64"|"arm64"|"386"|"ppc64le"|<machine>,
         "extn": ".exe"|""}
    """
    if sys.platform == "win32":
        platform_name = "windows"
    elif sys.platform == "linux" and _is_musl():
        platform_name = "linuxmusl"
    else:
        # cdxgen's process.platform yields "darwin"/"linux"; sys.platform does
        # the same on CPython.
        platform_name = sys.platform

    machine = (_platform_module.machine() or "").lower()
    if machine in ("x86", "i386", "i686", "x32"):
        arch = "386"
    elif machine in ("x86_64", "amd64", "x64"):
        arch = "amd64"
    elif machine in ("arm64", "aarch64"):
        arch = "arm64"
    elif machine in ("ppc64", "ppc64le", "powerpc64"):
        arch = "ppc64le"
    else:
        arch = machine

    extn = ".exe" if sys.platform == "win32" else ""
    return {"platform": platform_name, "arch": arch, "extn": extn}
