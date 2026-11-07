"""rusi (Rust Source Inspector) binary discovery and invocation.

rusi is a Rust analysis engine shipped prebuilt via cdxgen-plugins-bin. It
emits a call graph + interprocedural source->sink dataflow slices with PURL
attribution. dep-scan converts that report into an atom-shaped reachables
slice (see :mod:`analysis_lib.rusi_slices`) so the existing purl-keyed
reachability pipeline lights up with zero analyzer changes.

Binary resolution order (mirrors cdxgen's ``resolvePluginBinary`` so the
fallback finds the SAME binary cdxgen uses):
  1. ``RUSI_CMD`` env var (cdxgen's primary plugin override).
  2. ``DEPSCAN_RUSI_BINARY`` env var (depscan convenience override).
  3. ``find_executable("rusi")`` (PATH lookup -- local installs / plugins-bin PATH).
  4. ``CDXGEN_PLUGINS_DIR`` bundled layout
     ``<pluginsDir>/rusi/rusi-<platform>-<arch><extn>`` using cdxgen's
     platform/arch/musl tokens.
  5. Not found -> graceful skip with a diagnostic (never crash).

Safety gate (per rusi THREAT_MODEL): the default backend is ``stable``
(syn-based, parsing only, safe on untrusted repos). The ``compiler`` backend
embeds nightly rustc and runs ``cargo``/``rustc`` on the target, so it is
only enabled when the user opts in (``--deep`` or an explicit
``--rust-analyzer-backend compiler``). On the ``stable`` backend, rusi does
NOT execute cargo/rustc -- verified by direct measurement on the
vulnerable-web-app fixture (``security-deps`` completes in ~0.1s with no
build artifacts).
"""

from __future__ import annotations

import json
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

# Minimum rusi version known to produce the schema this converter targets.
# The converter is defensive, so this is a soft gate (warn, don't crash).
RUSI_MIN_VERSION = "2.5.2"

# env override for the binary path
RUSI_BINARY_ENV = "DEPSCAN_RUSI_BINARY"

# cdxgen's plugin override env for rusi (see cdxgen's
# PLUGIN_ENV_COMMAND_NAMES). Honored FIRST so depscan's fallback resolves the
# same binary cdxgen itself uses (and which produced the persisted report).
RUSI_CMD_ENV = "RUSI_CMD"

# Default invocation. ``stable`` backend = syn-based parsing, no cargo build.
# ``security-deps`` is the richest dataflow mode that still works on stable
# (it only escalates to full dep-body analysis under ``compiler`` mode).
DEFAULT_BACKEND = "stable"
DEFAULT_CALLGRAPH_MODE = "static"
DEFAULT_DATAFLOW_MODE = "security-deps"

# Wall-clock cap so a stuck rusi process can never block a scan indefinitely.
# Generous for large workspaces on the stable (parsing-only) backend; override
# via ``DEPSCAN_RUSI_TIMEOUT`` (seconds).
DEFAULT_TIMEOUT = int(os.environ.get("DEPSCAN_RUSI_TIMEOUT", "1800") or 1800)


@dataclass
class RusiResult:
    """Outcome of a rusi run. ``report_path`` is set only on success."""

    success: bool = False
    report_path: Optional[str] = None
    skipped: bool = False
    command_output: str = ""
    version: Optional[str] = None
    timed_out: bool = False


# ---------------------------------------------------------------------------
# Binary discovery
# ---------------------------------------------------------------------------


def bundled_rusi_path(plugins_dir: Optional[str], target: Optional[dict] = None) -> Optional[str]:
    """Return the expected rusi binary path inside a cdxgen-plugins-bin dir.

    Mirrors cdxgen's ``resolveBundledPluginBinary`` for the ``rusi`` tool::

        <pluginsDir>/rusi/rusi-<platform>-<arch><extn>

    Returns the path only when it exists on disk; otherwise ``None``. ``None``
    is also returned when ``plugins_dir`` is empty so callers can chain.
    """
    if not plugins_dir:
        return None
    target = target or get_plugins_bin_target()
    candidate = os.path.join(
        plugins_dir,
        "rusi",
        f"rusi-{target['platform']}-{target['arch']}{target['extn']}",
    )
    return candidate if os.path.isfile(candidate) else None


def find_rusi_binary(logger: Optional[Logger] = None) -> Optional[str]:
    """Locate the rusi binary, matching cdxgen's resolution.

    Resolution order:
      1. ``RUSI_CMD`` env (cdxgen's primary plugin override).
      2. ``DEPSCAN_RUSI_BINARY`` env (depscan convenience override).
      3. ``find_executable("rusi")`` (PATH).
      4. ``CDXGEN_PLUGINS_DIR`` bundled layout (see :func:`bundled_rusi_path`).

    Returns an absolute path string or ``None`` (graceful skip).
    """
    # 1. env overrides -- RUSI_CMD first so we match the binary cdxgen uses,
    #    then the depscan-specific override.
    for env_name in (RUSI_CMD_ENV, RUSI_BINARY_ENV):
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

    # 2. PATH lookup -- covers local installs and the cdxgen-plugins-bin PATH entry
    found = find_executable("rusi")
    if found:
        return found

    # 3. cdxgen-plugins-bin bundled layout: <pluginsDir>/rusi/rusi-<platform>-<arch><extn>
    plugins_dir = os.environ.get("CDXGEN_PLUGINS_DIR", "").strip()
    if plugins_dir:
        candidate = bundled_rusi_path(plugins_dir)
        if candidate:
            return candidate

    return None


def get_rusi_version(binary: str, logger: Optional[Logger] = None) -> Optional[str]:
    """Return the rusi version string (``rusi --version``), or ``None``."""
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
            logger.debug("rusi --version failed: %s", e)
        return None
    out = (cp.stdout or "").strip()
    # output shape: "rusi 2.5.2"
    for tok in out.split():
        if tok and tok[0].isdigit():
            return tok
    return None


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def run_rusi(
    src_dir: str,
    out_path: str,
    *,
    backend: str = DEFAULT_BACKEND,
    callgraph_mode: str = DEFAULT_CALLGRAPH_MODE,
    dataflow_mode: str = DEFAULT_DATAFLOW_MODE,
    include_tests: bool = False,
    logger: Optional[Logger] = None,
    timeout: Optional[int] = DEFAULT_TIMEOUT,
) -> RusiResult:
    """Run ``rusi analyze`` on ``src_dir`` and write the report to ``out_path``.

    Returns a :class:`RusiResult`. When the binary is missing the result is
    ``skipped=True, success=False`` -- callers should treat that as a soft
    fallback (warn, continue without rusi reachability), never an error.

    The ``compiler`` backend builds the target (rustc/cargo invocation) and
    MUST only be requested for trusted/local input -- callers enforce the
    opt-in; this function just forwards the value. When a ``compiler`` run
    fails to produce a report (the target does not build), this function
    automatically retries ONCE on the ``stable`` backend and logs a warning,
    so reachability degrades instead of being lost entirely.
    """
    binary = find_rusi_binary(logger=logger)
    if not binary:
        if logger:
            logger.warning(
                "rusi binary not found (set %s or install cdxgen-plugins-bin). "
                "Rust reachability via rusi will be skipped.",
                RUSI_BINARY_ENV,
            )
        return RusiResult(success=False, skipped=True, command_output="rusi binary not found")

    version = get_rusi_version(binary, logger=logger)
    if version and logger:
        logger.debug("rusi version: %s (min expected %s)", version, RUSI_MIN_VERSION)

    abs_src_dir = os.path.abspath(src_dir)

    result = _run_rusi_once(
        binary,
        abs_src_dir,
        out_path,
        backend=backend,
        callgraph_mode=callgraph_mode,
        dataflow_mode=dataflow_mode,
        include_tests=include_tests,
        logger=logger,
        timeout=timeout,
        version=version,
    )

    # Compiler-backend fallback: if the deep/compiler run failed to emit a
    # report (the target does not build under the embedded rustc), retry once
    # on the parsing-only ``stable`` backend so reachability degrades instead
    # of being lost. We do NOT retry a stable run (it would just repeat), and
    # we do NOT retry timeouts (a stable run would likely time out too on a
    # pathological workspace).
    if not result.success and not result.timed_out and backend and backend != DEFAULT_BACKEND:
        if logger:
            logger.warning(
                "rusi '%s' backend did not produce a report; retrying once on "
                "the '%s' backend so Rust reachability degrades gracefully. "
                "Set --rust-analyzer-backend stable to silence this.",
                backend,
                DEFAULT_BACKEND,
            )
        result = _run_rusi_once(
            binary,
            abs_src_dir,
            out_path,
            backend=DEFAULT_BACKEND,
            callgraph_mode=callgraph_mode,
            dataflow_mode=dataflow_mode,
            include_tests=include_tests,
            logger=logger,
            timeout=timeout,
            version=version,
        )

    if not result.success or not result.report_path:
        return result

    # schema/version sanity (soft): warn but keep the file so the converter
    # can still try.
    report_ok, schema_msg = _peek_report(result.report_path)
    if logger and not report_ok:
        logger.warning(
            "rusi report at %s did not validate: %s. Conversion may be incomplete.",
            result.report_path,
            schema_msg,
        )
    return result


def _run_rusi_once(
    binary: str,
    abs_src_dir: str,
    out_path: str,
    *,
    backend: str,
    callgraph_mode: str,
    dataflow_mode: str,
    include_tests: bool,
    logger: Optional[Logger],
    timeout: Optional[int],
    version: Optional[str],
) -> RusiResult:
    """Execute a single ``rusi analyze`` invocation. Does NOT retry."""
    args = [
        binary,
        "analyze",
        "--dir",
        abs_src_dir,
        "--backend",
        backend,
        "--callgraph",
        callgraph_mode,
        "--dataflow",
        dataflow_mode,
        "--out",
        out_path,
    ]
    if include_tests:
        args.append("--tests")

    if logger:
        logger.debug("Executing '%s'", " ".join(args))

    env = os.environ.copy()
    try:
        cp = subprocess.run(
            build_command(args),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=abs_src_dir if os.path.isdir(abs_src_dir) else None,
            env=tool_env(env),
            shell=False,
            encoding="utf-8",
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return RusiResult(
            success=False,
            command_output=f"rusi timed out after {timeout}s",
            version=version,
            timed_out=True,
        )
    except (OSError, subprocess.SubprocessError) as e:
        return RusiResult(
            success=False,
            command_output=f"rusi invocation failed: {e}",
            version=version,
        )

    out = cp.stdout or ""
    if cp.returncode != 0 or not os.path.exists(out_path):
        if logger:
            logger.debug("rusi '%s' backend produced no report (rc=%s).", backend, cp.returncode)
            logger.debug(out)
        return RusiResult(success=False, command_output=out, version=version)

    return RusiResult(success=True, report_path=out_path, command_output=out, version=version)


def _peek_report(out_path: str):
    """Cheap validation of the produced report. Returns (ok, message).

    Detection is by structural SHAPE, not the ``schema_version`` URL prefix: a
    rusi report is a dict carrying its producer identity (``tool``/``runtime``)
    alongside at least one analysis section (``call_graph``/``data_flow``).
    """
    try:
        with open(out_path, encoding="utf-8") as fp:
            data = json.load(fp)
    except (OSError, ValueError) as e:
        return False, f"unreadable JSON ({e})"
    if not isinstance(data, dict):
        return False, "report is not a JSON object"
    has_producer = isinstance(data.get("tool"), dict) or isinstance(data.get("runtime"), dict)
    has_section = isinstance(data.get("call_graph"), dict) or isinstance(
        data.get("data_flow"), dict
    )
    if not (has_producer and has_section):
        return False, "missing rusi producer (tool/runtime) and section (call_graph/data_flow)"
    return True, "ok"
