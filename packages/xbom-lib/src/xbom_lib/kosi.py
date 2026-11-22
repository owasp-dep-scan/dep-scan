"""kosi (Kotlin Source Inspector) binary discovery and invocation.

kosi is a Kotlin/JVM/Android analysis engine shipped prebuilt via
cdxgen-plugins-bin. Its report (schema ``kosi/1``) carries library usages,
imports, and, on the ``resolved`` tier, a call graph and source->sink
dataflow slices. dep-scan's kosi adapter reads that report into the evidence store (see
:mod:`analysis_lib.evidence.adapters.kosi`) so the purl-keyed reachability
pipeline reads Kotlin evidence the same way it reads golem and rusi evidence.

Binary resolution order (the same as :mod:`xbom_lib.golem`, so the fallback
finds the binary cdxgen uses):
  1. ``KOSI_CMD`` env var (cdxgen's plugin override).
  2. ``DEPSCAN_KOSI_BINARY`` env var (dep-scan override).
  3. ``find_executable("kosi")`` (PATH lookup).
  4. ``CDXGEN_PLUGINS_DIR`` bundled layout
     (or the plugins directory found beside the cdxgen install, see
     :func:`xbom_lib.plugins.discover_plugins_dir`)
     ``<pluginsDir>/kosi/kosi-<platform>-<arch><extn>``.
  5. Not found: graceful skip with a diagnostic, never a crash.

Backend and safety: the default ``syntax`` backend parses source files and
never runs Gradle or Maven, which makes it safe on untrusted input. It
reports usages and imports only. The ``resolved`` backend adds the call graph
and dataflow slices; it reads build files as text and finds dependency jars
in the local Gradle and Maven caches, it does not run the build. Callers
choose it explicitly.
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from logging import Logger
from typing import Optional

from xbom_lib.plugins import bundled_plugin_path, find_bundled_plugin, get_plugins_bin_target
from xbom_lib.process import build_command, find_executable, tool_env

# env override for the binary path (dep-scan convenience)
KOSI_BINARY_ENV = "DEPSCAN_KOSI_BINARY"

# cdxgen's plugin override env for kosi; honored first.
KOSI_CMD_ENV = "KOSI_CMD"

# ``syntax`` parses source only. ``resolved`` adds the call graph and
# dataflow slices on top of the local dependency caches.
DEFAULT_BACKEND = "syntax"
RESOLVED_BACKEND = "resolved"
RESOLVED_CALLGRAPH_MODE = "static"
RESOLVED_DATAFLOW_MODE = "security"

# The report schema family this runner and converter target.
KOSI_SCHEMA_PREFIX = "kosi/"

# Wall-clock cap so a stuck kosi process can never block a scan. Override with
# ``DEPSCAN_KOSI_TIMEOUT`` (seconds).
DEFAULT_TIMEOUT = int(os.environ.get("DEPSCAN_KOSI_TIMEOUT", "1800") or 1800)


@dataclass
class KosiResult:
    """Outcome of a kosi run. ``report_path`` is set only on success."""

    success: bool = False
    report_path: Optional[str] = None
    skipped: bool = False
    command_output: str = ""
    version: Optional[str] = None
    timed_out: bool = False
    backend: str = DEFAULT_BACKEND


def bundled_kosi_path(plugins_dir: Optional[str], target: Optional[dict] = None) -> Optional[str]:
    """Return the kosi binary path inside a cdxgen-plugins-bin directory.

    Layout: ``<pluginsDir>/kosi/kosi-<platform>-<arch><extn>``. The path is
    returned only when the file exists.
    """
    return bundled_plugin_path(plugins_dir, "kosi", target or get_plugins_bin_target())


def find_kosi_binary(logger: Optional[Logger] = None) -> Optional[str]:
    """Locate the kosi binary: ``KOSI_CMD``, ``DEPSCAN_KOSI_BINARY``, PATH,
    then the ``CDXGEN_PLUGINS_DIR`` layout and the plugins directory found
    beside the cdxgen install. Returns ``None`` when absent."""
    for env_name in (KOSI_CMD_ENV, KOSI_BINARY_ENV):
        env_path = os.environ.get(env_name, "").strip()
        if env_path:
            if os.path.isfile(env_path):
                return env_path
            if logger:
                logger.debug(
                    "%s=%s does not point to a file; continuing resolution", env_name, env_path
                )
    found = find_executable("kosi")
    if found:
        return found
    return find_bundled_plugin("kosi", get_plugins_bin_target())


def get_kosi_version(binary: str, logger: Optional[Logger] = None) -> Optional[str]:
    """Return kosi's version, or ``None``.

    ``kosi --version`` prints a JSON object (``{"version": "4.3.1", ...}``).
    A native image also writes JVM warnings to stderr, so only stdout is read.
    """
    try:
        cp = subprocess.run(
            build_command([binary, "--version"]),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=tool_env(),
            shell=False,
            encoding="utf-8",
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as e:
        if logger:
            logger.debug("kosi --version failed: %s", e)
        return None
    try:
        data = json.loads(cp.stdout or "")
    except ValueError:
        return None
    version = data.get("version") if isinstance(data, dict) else None
    return version if isinstance(version, str) and version else None


def _build_kosi_args(src_dir: str, out_path: str, *, backend: str) -> list:
    """Build the ``kosi analyze`` argument list.

    The ``syntax`` tier has no call graph or dataflow engine, so those flags
    are only passed for the ``resolved`` tier.
    """
    args = ["analyze", "--dir", os.path.abspath(src_dir), "--backend", backend, "--out", out_path]
    if backend == RESOLVED_BACKEND:
        args += [
            "--callgraph",
            RESOLVED_CALLGRAPH_MODE,
            "--dataflow",
            RESOLVED_DATAFLOW_MODE,
        ]
    return args


def run_kosi(
    src_dir: str,
    out_path: str,
    *,
    backend: str = DEFAULT_BACKEND,
    logger: Optional[Logger] = None,
    timeout: Optional[int] = DEFAULT_TIMEOUT,
) -> KosiResult:
    """Run ``kosi analyze`` on ``src_dir`` and write the report to ``out_path``.

    When the binary is missing the result is ``skipped=True, success=False``;
    callers treat that as a soft fallback (warn, continue without kosi
    reachability), never an error.
    """
    binary = find_kosi_binary(logger=logger)
    if not binary:
        if logger:
            logger.warning(
                "kosi binary not found (set %s or install cdxgen-plugins-bin). "
                "Kotlin reachability via kosi will be skipped.",
                KOSI_BINARY_ENV,
            )
        return KosiResult(
            success=False, skipped=True, command_output="kosi binary not found", backend=backend
        )
    version = get_kosi_version(binary, logger=logger)
    abs_src_dir = os.path.abspath(src_dir)
    full_cmd = [binary] + _build_kosi_args(abs_src_dir, out_path, backend=backend)
    if logger:
        logger.debug("Executing '%s'", " ".join(full_cmd))
    try:
        cp = subprocess.run(
            build_command(full_cmd),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=abs_src_dir if os.path.isdir(abs_src_dir) else None,
            env=tool_env(),
            shell=False,
            encoding="utf-8",
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return KosiResult(
            command_output=f"kosi timed out after {timeout}s",
            version=version,
            timed_out=True,
            backend=backend,
        )
    except (OSError, subprocess.SubprocessError) as e:
        return KosiResult(
            command_output=f"kosi invocation failed: {e}", version=version, backend=backend
        )
    out = cp.stdout or ""
    if cp.returncode != 0 or not os.path.exists(out_path):
        if logger:
            logger.debug("kosi produced no report (rc=%s).", cp.returncode)
            logger.debug(out)
        return KosiResult(command_output=out, version=version, backend=backend)
    report_ok, message = _peek_report(out_path)
    if logger and not report_ok:
        logger.warning(
            "kosi report at %s did not validate: %s. Conversion may be incomplete.",
            out_path,
            message,
        )
    return KosiResult(
        success=True,
        report_path=out_path,
        command_output=out,
        version=version,
        backend=backend,
    )


def _peek_report(out_path: str):
    """Cheap validation of the produced report. Returns ``(ok, message)``."""
    try:
        with open(out_path, encoding="utf-8") as fp:
            data = json.load(fp)
    except (OSError, ValueError) as e:
        return False, f"unreadable JSON ({e})"
    if not isinstance(data, dict):
        return False, "report is not a JSON object"
    if not str(data.get("schemaVersion") or "").startswith(KOSI_SCHEMA_PREFIX):
        return False, "schemaVersion is not a kosi/ schema"
    return True, "ok"
