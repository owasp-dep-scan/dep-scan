"""Shared cdxgen plugin-binary discovery helpers.

:mod:`xbom_lib.rusi`, :mod:`xbom_lib.golem`, :mod:`xbom_lib.dosai` and
:mod:`xbom_lib.kosi` resolve their bundled binaries using cdxgen's platform/arch/musl token scheme so the fallback finds
the SAME binary cdxgen itself uses. The token logic lived in ``rusi.py`` and
was imported by ``golem.py``; it is promoted here so neither analyzer module
owns the shared concern.
"""

from __future__ import annotations

import json
import os
import platform as _platform_module
import re
import subprocess
import sys
from typing import Any, Dict, List, NamedTuple, Optional

from xbom_lib.process import find_executable


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


# ---------------------------------------------------------------------------
# The cdxgen plugins directory
# ---------------------------------------------------------------------------

#: cdxgen's own usability rule for a plugins directory: a manifest, or at
#: least one of the plugin subdirectories it knows.
PLUGINS_DIR_TOOLS = (
    "cargo-auditable",
    "cdxrs",
    "cdxui",
    "dosai",
    "golem",
    "kosi",
    "osquery",
    "rusi",
    "sourcekitten",
    "trivy",
    "trustinspector",
)

#: How many parent directories above the cdxgen entry point are probed.
_PLUGINS_DIR_WALK_DEPTH = 6


class PluginsDir(NamedTuple):
    """A usable cdxgen plugins directory and how it was found.

    ``source`` is ``env`` (``CDXGEN_PLUGINS_DIR``), ``cdxgen-install`` (the
    npm package installed beside cdxgen) or ``bundled-sea`` (a ``plugins``
    directory next to a standalone cdxgen binary).
    """

    path: str
    source: str


def resolve_cdxgen_path() -> Optional[str]:
    """The cdxgen executable a scan would start from PATH, or ``None``.

    Uses ``CDXGEN_CMD`` when set and otherwise the name ``cdxgen``, the same
    command ``find_cdxgen_cmd`` looks for.
    """
    command = os.environ.get("CDXGEN_CMD", "").strip() or "cdxgen"
    return find_executable(command)


#: The npm package names cdxgen has been published under; a global install
#: puts one of them under ``<prefix>/node_modules`` (``%APPDATA%\\npm`` on
#: Windows).
_CDXGEN_PACKAGE_DIRS = (("@cdxgen", "cdxgen"), ("@cyclonedx", "cdxgen"))

#: The script a package-manager shim starts, as the shim writes it: npm and
#: pnpm use ``%dp0%``/``%~dp0`` in ``.cmd`` files and ``$basedir`` in the
#: ``.ps1`` and shell shims, followed by a path relative to the shim.
_SHIM_TARGET_RE = re.compile(
    r"""(?:%~?dp0%?|\$basedir|\$PSScriptRoot)[\\/]+([^"'\s%$]*?cdxgen[\\/]bin[\\/]cdxgen\.js)"""
)
_SHIM_MAX_BYTES = 65536


def _shim_script_dirs(shim_path: str) -> List[str]:
    """The ``bin`` directory of the cdxgen script a shim starts, or ``[]``.

    On Windows npm and pnpm do not link ``cdxgen`` into the package; they
    write ``cdxgen.cmd`` (plus ``.ps1`` and shell variants) beside the
    package, and the shim names the script relative to its own directory.
    pnpm's global shims can point several directories away, so the target
    is read from the shim instead of guessed. Anything unreadable gives
    nothing.
    """
    directory = os.path.dirname(shim_path)
    names = [os.path.basename(shim_path)]
    stem = os.path.splitext(names[0])[0]
    names += [stem + ext for ext in (".cmd", ".ps1", "")]
    dirs: List[str] = []
    for name in names:
        candidate = os.path.join(directory, name)
        try:
            if not os.path.isfile(candidate) or os.path.getsize(candidate) > _SHIM_MAX_BYTES:
                continue
            with open(candidate, encoding="utf-8", errors="replace") as fp:
                text = fp.read()
        except OSError:
            continue
        for match in _SHIM_TARGET_RE.finditer(text):
            relative = re.split(r"[\\/]+", match.group(1))
            script = os.path.realpath(os.path.join(directory, *relative))
            if os.path.isfile(script):
                package_root = os.path.dirname(os.path.dirname(script))
                if package_root not in dirs:
                    dirs.append(package_root)
    return dirs


def _walk_candidates(start: str, target: Dict[str, str]) -> List[str]:
    """Plugins directories at and above ``start``, nearest first."""
    found: List[str] = []
    ancestor = start
    for _ in range(_PLUGINS_DIR_WALK_DEPTH):
        found.append(os.path.join(ancestor, "plugins"))
        packages = [os.path.join(ancestor, "node_modules", *name) for name in _CDXGEN_PACKAGE_DIRS]
        # The plugins package hoisted next to cdxgen, then nested inside a
        # cdxgen package that sits beside a shim.
        for node_modules in [os.path.join(ancestor, "node_modules")] + [
            os.path.join(package, "node_modules") for package in packages
        ]:
            found.append(
                os.path.join(
                    node_modules,
                    "@cdxgen",
                    f"cdxgen-plugins-bin-{target['platform']}-{target['arch']}",
                    "plugins",
                )
            )
        for package in packages:
            found.append(os.path.join(package, "plugins"))
        parent = os.path.dirname(ancestor)
        if parent == ancestor:
            break
        ancestor = parent
    return found


def candidate_plugins_dirs(
    cdxgen_path: Optional[str] = None, target: Optional[Dict[str, str]] = None
) -> List[str]:
    """Every plugins directory cdxgen could use, best candidate first.

    cdxgen honours ``CDXGEN_PLUGINS_DIR``, then a ``plugins`` directory next
    to its own install (the bundled caxa binary), then the npm package
    ``@cdxgen/cdxgen-plugins-bin-<platform>-<arch>`` installed beside it.
    The last two are probed by walking up from the real location of the
    cdxgen command, so a symlink such as ``~/.local/bin/cdxgen`` leads to
    the install it points at.

    A Windows package-manager shim (``%APPDATA%\\npm\\cdxgen.cmd``) is not a
    link. For a shim the walk also starts in the script it starts, and
    probes the cdxgen package beside it (``node_modules/@cdxgen/cdxgen`` or
    ``node_modules/@cyclonedx/cdxgen``) with the plugins package nested in
    it or hoisted next to it.
    """
    target = target or get_plugins_bin_target()
    candidates = []
    env_dir = os.environ.get("CDXGEN_PLUGINS_DIR", "").strip()
    if env_dir and os.path.isdir(env_dir):
        candidates.append(env_dir)
    if cdxgen_path:
        starts = [os.path.dirname(os.path.realpath(cdxgen_path))]
        starts.extend(_shim_script_dirs(cdxgen_path))
        for start in starts:
            candidates.extend(_walk_candidates(start, target))
    unique: List[str] = []
    seen = set()
    for candidate in candidates:
        key = os.path.normpath(candidate)
        if key not in seen:
            seen.add(key)
            unique.append(candidate)
    return unique


def usable_plugins_dir(path: str) -> bool:
    """True for a directory cdxgen would accept as its plugins directory."""
    if not os.path.isdir(path):
        return False
    if os.path.isfile(os.path.join(path, "plugins-manifest.json")):
        return True
    return any(os.path.isdir(os.path.join(path, tool)) for tool in PLUGINS_DIR_TOOLS)


def discover_plugins_dir(
    cdxgen_path: Optional[str] = None, target: Optional[Dict[str, str]] = None
) -> Optional[PluginsDir]:
    """The first usable plugins directory, or ``None``.

    ``cdxgen_path`` is the cdxgen executable to start the search from; when
    omitted, the command found by :func:`resolve_cdxgen_path` is used.
    """
    if cdxgen_path is None:
        cdxgen_path = resolve_cdxgen_path()
    env_dir = os.environ.get("CDXGEN_PLUGINS_DIR", "").strip()
    for candidate in candidate_plugins_dirs(cdxgen_path, target):
        if not usable_plugins_dir(candidate):
            continue
        if env_dir and os.path.normpath(candidate) == os.path.normpath(env_dir):
            source = "env"
        elif os.path.isfile(os.path.join(candidate, os.pardir, "package.json")):
            source = "cdxgen-install"
        else:
            source = "bundled-sea"
        return PluginsDir(candidate, source)
    return None


def read_plugins_manifest(plugins_dir: str) -> Dict[str, Any]:
    """The parsed ``plugins-manifest.json`` of a plugins directory, or ``{}``."""
    try:
        with open(os.path.join(plugins_dir, "plugins-manifest.json"), encoding="utf-8") as fp:
            manifest = json.load(fp)
    except (OSError, ValueError):
        return {}
    return manifest if isinstance(manifest, dict) else {}


def manifest_binary_path(plugins_dir: str, tool: str) -> Optional[str]:
    """The ``binaryPath`` the manifest records for ``tool``, resolved against
    ``plugins_dir`` (the manifest writes it relative to the package root, with
    a leading ``plugins/``). ``None`` when the manifest does not name it."""
    for plugin in read_plugins_manifest(plugins_dir).get("plugins") or []:
        if not isinstance(plugin, dict) or plugin.get("name") != tool:
            continue
        relative = str(plugin.get("binaryPath") or "").replace("\\", "/")
        if not relative:
            return None
        if relative.startswith("plugins/"):
            relative = relative[len("plugins/") :]
        return os.path.join(plugins_dir, *relative.split("/"))
    return None


def bundled_plugin_path(
    plugins_dir: Optional[str], tool: str, target: Optional[dict] = None
) -> Optional[str]:
    """The ``tool`` binary inside ``plugins_dir``, or ``None`` when missing.

    The manifest's ``binaryPath`` wins when it points at a file; otherwise
    the conventional ``<pluginsDir>/<tool>/<tool>-<platform>-<arch><extn>``
    layout is used.
    """
    if not plugins_dir:
        return None
    target = target or get_plugins_bin_target()
    recorded = manifest_binary_path(plugins_dir, tool)
    if recorded and os.path.isfile(recorded):
        return recorded
    candidate = os.path.join(
        plugins_dir,
        tool,
        f"{tool}-{target['platform']}-{target['arch']}{target['extn']}",
    )
    return candidate if os.path.isfile(candidate) else None


def find_bundled_plugin(tool: str, target: Optional[dict] = None) -> Optional[str]:
    """Find ``tool`` in the plugins directory a scan's cdxgen would use.

    ``CDXGEN_PLUGINS_DIR`` is tried first, even when cdxgen would not accept
    it as a plugins directory. Then comes the first usable directory
    discovered from the cdxgen install (see :func:`discover_plugins_dir`).
    """
    target = target or get_plugins_bin_target()
    env_dir = os.environ.get("CDXGEN_PLUGINS_DIR", "").strip()
    if env_dir:
        found = bundled_plugin_path(env_dir, tool, target)
        if found:
            return found
    discovered = discover_plugins_dir(target=target)
    if discovered:
        return bundled_plugin_path(discovered.path, tool, target)
    return None


def is_in_plugins_dir(path: str, target: Optional[dict] = None) -> bool:
    """True when ``path`` lies inside the env or discovered plugins directory."""
    roots = []
    env_dir = os.environ.get("CDXGEN_PLUGINS_DIR", "").strip()
    if env_dir:
        roots.append(env_dir)
    discovered = discover_plugins_dir(target=target)
    if discovered:
        roots.append(discovered.path)
    resolved = os.path.normpath(path)
    return any(resolved.startswith(os.path.join(os.path.normpath(root), "")) for root in roots)
