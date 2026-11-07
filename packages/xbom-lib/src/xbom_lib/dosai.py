"""dosai (Dotnet Source and Assembly Inspector) binary discovery and invocation.

dosai is a .NET analysis engine (C#/VB/F#/R) shipped prebuilt via
cdxgen-plugins-bin. It inspects source (Roslyn + dedicated frontends) AND
assemblies (Reflection + IL) and emits a call graph, interprocedural
source->sink dataflow slices, explicit per-package reachability, weakness
candidates, dangerous-API reachability, and crypto/CBOM evidence. dep-scan
consumes that native report directly for reachability and converts a
projection into an atom-shaped reachables slice (see
:mod:`analysis_lib.dosai_slices`) so the existing purl-keyed reachability
pipeline lights up.

This module is the **direct-spawn FALLBACK**. The primary path consumes the
cdxgen-persisted combined native report at
``<bomdir>/dotnet-semantics.slices.json`` (see :func:`run_dosai_reachability`
in depscan/lib/bom.py), which cdxgen produces under ``--profile research`` +
``--semantics-slices-file``. This runner is only used when that persisted
report is absent or unrecognized (cdxgen/plugins unavailable, or reachability
invoked without cdxgen).

Binary resolution order (mirrors cdxgen's ``resolvePluginBinary`` so the
fallback finds the SAME binary cdxgen uses):
  1. ``DOSAI_CMD`` env var (cdxgen's primary plugin override -- check FIRST so
     we use the same binary that produced the persisted report).
  2. ``DEPSCAN_DOSAI_BINARY`` env var (depscan convenience override).
  3. ``find_executable("dosai")`` / ``find_executable("Dosai")`` (PATH lookup --
     local installs / plugins-bin PATH entry).
  4. ``CDXGEN_PLUGINS_DIR`` bundled layout
     ``<pluginsDir>/dosai/dosai-<platform>-<arch><extn>`` using cdxgen's
     platform/arch/musl tokens (reused from :mod:`xbom_lib.plugins`).
  5. Not found -> graceful skip with a diagnostic (never crash).

Note on bundled asset casing: upstream dosai release assets are named
``Dosai-<platform>`` (e.g. ``Dosai-osx-arm64``), but cdxgen-plugins-bin's
install step RENAMES them to the lowercase ``dosai-<platform>-<arch><extn>``
layout shared with golem/rusi (verified in
cdxgen-plugins-bin/packages/*/build-*.sh). cdxgen's
``resolveBundledPluginBinary("dosai")`` therefore resolves the same lowercase
path, and :func:`bundled_dosai_path` mirrors it verbatim.

Safety gate (per dosai THREAT_MODEL + dep-scan AGENTS.md): dosai performs
static source/assembly inspection -- it does NOT execute the target and does
NOT run ``dotnet build``. However it REQUIRES a .NET runtime to load (it
prints a "Dotnet SDK is not installed" / "You must install or update .NET"
message and exits non-zero without one). Self-contained "-full" release
binaries bundle the runtime and need no SDK. We probe for either before
invoking, and skip gracefully with a clear diagnostic when neither is present.

We do NOT run ``dotnet restore`` ourselves (untrusted-repo + network risk).
For full-fidelity versioned NuGet purls, scan a tree that has already been
restored (``project.assets.json`` / ``*.deps.json`` present); otherwise dosai
falls back to versionless ``System.*`` framework purls which are still
reconciled where the SBOM carries them.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from logging import Logger
from typing import Optional

from xbom_lib.plugins import get_plugins_bin_target
from xbom_lib.process import build_command, find_executable, tool_env


# ---------------------------------------------------------------------------
# Constants -- mirrored in depscan/lib/config.py for the CLI layer.
# ---------------------------------------------------------------------------

# env override for the binary path (depscan convenience).
DOSAI_BINARY_ENV = "DEPSCAN_DOSAI_BINARY"

# cdxgen's plugin override env for dosai (see cdxgen's
# PLUGIN_ENV_COMMAND_NAMES). Honored FIRST so depscan's fallback resolves the
# same binary cdxgen itself uses (and which produced the persisted report).
DOSAI_CMD_ENV = "DOSAI_CMD"

# dosai subcommands we invoke. dataflows carries taint slices + reachability +
# weakness/dangerous-API; methods carries the call graph + API endpoints +
# dependency-level reachability. Both are needed for full reachability.
DOSAI_DATAFLOWS_COMMAND = "dataflows"
DOSAI_METHODS_COMMAND = "methods"
DOSAI_COMMANDS = (DOSAI_DATAFLOWS_COMMAND, DOSAI_METHODS_COMMAND)

# Pattern packs select the source/sink categories dosai looks for. ``all``
# maximizes the reachability signal (mirror cdxgen's research-profile default).
# NOTE: only the ``dataflows`` command accepts ``--pattern-packs``; the
# ``methods`` command does not (System.CommandLine rejects unknown options --
# verified in Dosai/CommandLine.cs). cdxgen's runDosaiCommand does the same.
DEFAULT_PATTERN_PACKS = "all"

# Raw native artifacts persisted in the bom dir (source of truth -- never
# deleted). The combined semantics-slices report is assembled by cdxgen on the
# primary path; on the fallback path we persist these two raw files.
DOSAI_DATAFLOWS_FILE = "dotnet-dataflows.json"
DOSAI_METHODS_FILE = "dotnet-methods.json"

# Wall-clock cap so a stuck dosai process can never block a scan indefinitely.
# Generous for large .NET workspaces; override via ``DEPSCAN_DOSAI_TIMEOUT``
# (seconds).
DEFAULT_TIMEOUT = int(os.environ.get("DEPSCAN_DOSAI_TIMEOUT", "1800") or 1800)

# Substrings dosai prints (on stdout/stderr) when no .NET runtime is present.
# When we see these, the run is skipped (not failed) with a diagnostic pointing
# at the self-contained "-full" binary / cdxgen dotnet container images.
_DOTNET_SDK_MISSING_MARKERS = (
    "Dotnet SDK is not installed",
    "You must install or update .NET to run this application",
)

# Filename hint that a dosai binary is self-contained (bundles the runtime) and
# therefore does not need a separate ``dotnet`` on PATH.
_SELF_CONTAINED_HINT = "-full"


@dataclass
class DosaiResult:
    """Outcome of a dosai run.

    ``methods_path`` / ``dataflows_path`` are set only when the respective
    native artifact was produced. ``success`` is True only when at least one
    artifact was written.
    """

    success: bool = False
    methods_path: Optional[str] = None
    dataflows_path: Optional[str] = None
    skipped: bool = False
    command_output: str = ""
    version: Optional[str] = None
    timed_out: bool = False


# ---------------------------------------------------------------------------
# Binary discovery
# ---------------------------------------------------------------------------


def bundled_dosai_path(plugins_dir: Optional[str], target: Optional[dict] = None) -> Optional[str]:
    """Return the expected dosai binary path inside a cdxgen-plugins-bin dir.

    Mirrors cdxgen's ``resolveBundledPluginBinary`` for the ``dosai`` tool::

        <pluginsDir>/dosai/dosai-<platform>-<arch><extn>

    Returns the path only when it exists on disk; otherwise ``None``. ``None``
    is also returned when ``plugins_dir`` is empty so callers can chain.

    Upstream release assets are ``Dosai-<platform>`` but cdxgen-plugins-bin
    renames them to this lowercase layout on install (see module docstring).
    """
    if not plugins_dir:
        return None
    target = target or get_plugins_bin_target()
    candidate = os.path.join(
        plugins_dir,
        "dosai",
        f"dosai-{target['platform']}-{target['arch']}{target['extn']}",
    )
    return candidate if os.path.isfile(candidate) else None


def find_dosai_binary(logger: Optional[Logger] = None) -> Optional[str]:
    """Locate the dosai binary, matching cdxgen's resolution.

    Resolution order:
      1. ``DOSAI_CMD`` env (cdxgen's primary plugin override).
      2. ``DEPSCAN_DOSAI_BINARY`` env (depscan convenience override).
      3. ``find_executable("dosai")`` / ``find_executable("Dosai")`` (PATH).
      4. ``CDXGEN_PLUGINS_DIR`` bundled layout (see :func:`bundled_dosai_path`).

    Returns an absolute path string or ``None`` (graceful skip).
    """
    # 1-2. env overrides -- DOSAI_CMD first so we match the binary cdxgen uses,
    #      then the depscan-specific override.
    for env_name in (DOSAI_CMD_ENV, DOSAI_BINARY_ENV):
        env_path = os.environ.get(env_name, "").strip()
        if env_path:
            if os.path.isfile(env_path):
                return env_path
            if logger:
                logger.debug(
                    "%s=%s does not point to a file; continuing resolution",
                    env_name,
                    env_path,
                )

    # 3. PATH lookup -- covers local installs and the cdxgen-plugins-bin PATH
    #    entry. Try both lowercase ``dosai`` and PascalCase ``Dosai`` since the
    #    upstream binary is ``Dosai`` (Linux/macOS) / ``Dosai.exe`` (Windows).
    for name in ("dosai", "Dosai"):
        found = find_executable(name)
        if found:
            return found

    # 4. cdxgen-plugins-bin bundled layout.
    plugins_dir = os.environ.get("CDXGEN_PLUGINS_DIR", "").strip()
    if plugins_dir:
        candidate = bundled_dosai_path(plugins_dir)
        if candidate:
            return candidate

    return None


def get_dosai_version(binary: str, logger: Optional[Logger] = None) -> Optional[str]:
    """Return the dosai version string (``dosai --version``), or ``None``.

    dosai prints e.g. ``3.0.5+ac48920c5569cc86292e797ffadb2b67a900c6a2``; we
    take the first whitespace token and strip any ``+<sha>`` suffix.
    """
    try:
        cp = subprocess.run(
            build_command([binary, "--version"]),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=tool_env(),
            shell=False,
            encoding="utf-8",
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as e:
        if logger:
            logger.debug("dosai --version failed: %s", e)
        return None
    out = (cp.stdout or "").strip()
    if not out:
        return None
    tok = out.split()[0]
    # drop the ``+<sha>`` build metadata if present -> ``3.0.5``
    return tok.split("+", 1)[0] if "+" in tok else tok


# ---------------------------------------------------------------------------
# .NET runtime check (safety gate)
# ---------------------------------------------------------------------------


def _is_self_contained_binary(binary: Optional[str]) -> bool:
    """Return True if ``binary`` looks like a self-contained dosai build.

    The "-full" release binaries bundle the .NET runtime and need no SDK. We
    treat a filename containing the ``-full`` hint as self-contained.
    """
    return bool(binary) and _SELF_CONTAINED_HINT in os.path.basename(binary or "")


def dotnet_runtime_available(
    binary: Optional[str] = None, logger: Optional[Logger] = None
) -> bool:
    """Return True if dosai can run in this environment.

    dosai needs a .NET runtime to load. This is satisfied by EITHER:

    - a self-contained "-full" dosai binary (bundles the runtime), OR
    - a usable ``dotnet`` on PATH (``dotnet --version`` succeeds).

    Without either, dosai prints a "Dotnet SDK is not installed" message and
    exits non-zero. We check explicitly so we can skip gracefully with a clear
    diagnostic rather than letting dosai fail with an opaque error.
    """
    if _is_self_contained_binary(binary):
        return True
    try:
        cp = subprocess.run(
            build_command(["dotnet", "--version"]),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=tool_env(),
            shell=False,
            encoding="utf-8",
            check=False,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        if logger:
            logger.debug("dotnet --version invocation failed or 'dotnet' not on PATH")
        return False
    if cp.returncode != 0:
        if logger:
            logger.debug("dotnet --version returned rc=%s", cp.returncode)
        return False
    return True


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def _build_dosai_args(
    src_dir: str,
    out_path: str,
    command: str,
    *,
    pattern_packs: str = DEFAULT_PATTERN_PACKS,
) -> list:
    """Build the dosai argument list for one command.

    Mirrors cdxgen's ``runDosaiCommand``: ``[<command>, "--path", <src>, "--o",
    <out>]`` plus ``--pattern-packs <packs>`` ONLY for the ``dataflows``
    command (the ``methods`` command does not accept it -- see module
    docstring). Run with ``shell=False``, ``cwd=<src>``.
    """
    args = [command, "--path", os.path.abspath(src_dir), "--o", os.path.abspath(out_path)]
    if command == DOSAI_DATAFLOWS_COMMAND and pattern_packs:
        args.extend(["--pattern-packs", pattern_packs])
    return args


def _dosai_sdk_missing(output: str) -> bool:
    """Return True if dosai's output indicates a missing .NET runtime."""
    if not output:
        return False
    return any(marker in output for marker in _DOTNET_SDK_MISSING_MARKERS)


def _run_dosai_once(
    binary: str,
    src_dir: str,
    out_path: str,
    command: str,
    *,
    pattern_packs: str,
    logger: Optional[Logger],
    timeout: Optional[int],
    version: Optional[str],
) -> tuple[bool, str, bool]:
    """Execute a single dosai command. Returns ``(ok, output, sdk_missing)``.

    ``ok`` is True only when the command succeeded AND wrote the output file.
    ``sdk_missing`` flags a missing .NET runtime so the caller can skip (not
    fail) with a diagnostic.
    """
    args = [binary] + _build_dosai_args(src_dir, out_path, command, pattern_packs=pattern_packs)
    if logger:
        logger.debug("Executing '%s'", " ".join(args))
    try:
        cp = subprocess.run(
            build_command(args),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=os.path.abspath(src_dir) if os.path.isdir(src_dir) else None,
            env=tool_env(),
            shell=False,
            encoding="utf-8",
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return False, f"dosai {command} timed out after {timeout}s", False
    except (OSError, subprocess.SubprocessError) as e:
        return False, f"dosai {command} invocation failed: {e}", False

    out = cp.stdout or ""
    if _dosai_sdk_missing(out):
        return False, out, True
    if cp.returncode != 0 or not os.path.exists(out_path):
        if logger:
            logger.debug("dosai %s produced no report (rc=%s).", command, cp.returncode)
            logger.debug(out)
        return False, out, False
    return True, out, False


def run_dosai(
    src_dir: str,
    out_dir: str,
    *,
    pattern_packs: str = DEFAULT_PATTERN_PACKS,
    logger: Optional[Logger] = None,
    timeout: Optional[int] = DEFAULT_TIMEOUT,
) -> DosaiResult:
    """Run dosai ``dataflows`` + ``methods`` on ``src_dir`` and persist raw JSON.

    Writes the native artifacts to ``<out_dir>/dotnet-dataflows.json`` and
    ``<out_dir>/dotnet-methods.json`` (source of truth -- never deleted) and
    returns a :class:`DosaiResult` carrying both paths.

    When the binary or .NET runtime is missing the result is ``skipped=True,
    success=False`` -- callers should treat that as a soft fallback (warn,
    continue without dosai reachability), never an error. ``success`` is True
    when at least one of the two artifacts was produced (a single-artifact
    result is still useful: dataflows carries its own ``PackageReachability``).
    """
    binary = find_dosai_binary(logger=logger)
    if not binary:
        if logger:
            logger.warning(
                "dosai binary not found (set %s or install cdxgen-plugins-bin). "
                ".NET reachability via dosai will be skipped.",
                DOSAI_BINARY_ENV,
            )
        return DosaiResult(success=False, skipped=True, command_output="dosai binary not found")

    if not dotnet_runtime_available(binary=binary, logger=logger):
        if logger:
            logger.warning(
                ".NET runtime not found ('dotnet' not on PATH and %s is not a "
                "self-contained '-full' build). dosai requires .NET to run. "
                ".NET reachability will be skipped. Use the cdxgen dotnet "
                "container images or download a dosai '-full' binary from "
                "https://github.com/owasp-dep-scan/dosai/releases and set %s.",
                binary,
                DOSAI_CMD_ENV,
            )
        return DosaiResult(
            success=False,
            skipped=True,
            command_output=".NET runtime not found",
        )

    version = get_dosai_version(binary, logger=logger)
    if version and logger:
        logger.debug("dosai version: %s", version)

    os.makedirs(out_dir, exist_ok=True)
    dataflows_path = os.path.join(out_dir, DOSAI_DATAFLOWS_FILE)
    methods_path = os.path.join(out_dir, DOSAI_METHODS_FILE)

    outputs = []
    sdk_missing = False
    for command, out_path in (
        (DOSAI_DATAFLOWS_COMMAND, dataflows_path),
        (DOSAI_METHODS_COMMAND, methods_path),
    ):
        ok, out, missing = _run_dosai_once(
            binary,
            src_dir,
            out_path,
            command,
            pattern_packs=pattern_packs,
            logger=logger,
            timeout=timeout,
            version=version,
        )
        outputs.append(out)
        if missing:
            sdk_missing = True

    combined_output = "\n".join(o for o in outputs if o)

    # A missing .NET runtime mid-run is a skip, not a hard failure.
    if sdk_missing:
        if logger:
            logger.warning(
                "dosai reported the .NET SDK/runtime is not installed. Use the "
                "cdxgen dotnet container images or a dosai '-full' binary from "
                "https://github.com/owasp-dep-scan/dosai/releases. .NET "
                "reachability will be skipped."
            )
        return DosaiResult(
            success=False,
            skipped=True,
            command_output=combined_output,
            version=version,
        )

    have_dataflows = os.path.exists(dataflows_path)
    have_methods = os.path.exists(methods_path)
    if not (have_dataflows or have_methods):
        return DosaiResult(success=False, command_output=combined_output, version=version)

    return DosaiResult(
        success=True,
        methods_path=methods_path if have_methods else None,
        dataflows_path=dataflows_path if have_dataflows else None,
        command_output=combined_output,
        version=version,
    )
