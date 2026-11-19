"""golem (Go Source Inspector) binary discovery and invocation.

golem is a Go static-analysis engine shipped prebuilt via cdxgen-plugins-bin.
It emits a call graph + interprocedural source->sink dataflow slices with
PURL attribution, API endpoints, crypto evidence, and supply-chain metadata.
dep-scan converts that report into an atom-shaped reachables slice (see
:mod:`analysis_lib.golem_slices`) so the existing purl-keyed reachability
pipeline lights up with zero analyzer changes.

Binary resolution order (mirrors cdxgen's ``resolvePluginBinary`` so the
fallback finds the SAME binary cdxgen uses):
  1. ``GOLEM_CMD`` env var (cdxgen's primary plugin override).
  2. ``DEPSCAN_GOLEM_BINARY`` env var (depscan convenience override).
  3. ``find_executable("golem")`` (PATH lookup -- local installs / plugins-bin PATH).
  4. ``CDXGEN_PLUGINS_DIR`` bundled layout
     ``<pluginsDir>/golem/golem-<platform>-<arch><extn>`` using cdxgen's
     platform/arch/musl tokens (reused from :mod:`xbom_lib.rusi`).
  5. Not found -> graceful skip with a diagnostic (never crash).

Safety gate (per golem THREAT_MODEL): golem has a single backend -- it loads
packages via ``golang.org/x/tools/go/packages`` with full type/SSA info. It
does NOT run the program and does NOT run ``go:generate``. BUT package loading
uses the **local Go toolchain**, and loading in this mode runs ``go list
-compiled``, which compiles cgo packages: the machine's C compiler runs with
flags taken from the scanned code (``#cgo`` directives, ``.syso`` files,
``#cgo pkg-config:`` lines). Module downloads **can occur** depending on the
user's Go env (proxy/module cache). This is the analog of rusi's "compiler
backend builds the target".

Plan:
  - Require a Go toolchain (``go version``) before invoking golem; skip
    gracefully with a diagnostic if absent (never crash).
  - Run golem with a hardened Go env by default: ``GOFLAGS=-mod=readonly``.
  - Force cgo off: ``CGO_ENABLED=0`` and no ``CGO_*_ALLOW`` variables, even
    when the caller's environment sets them (see :func:`apply_cgo_env`, which
    the cdxgen generators share). Packages that need cgo are not loaded and
    their reachability is missing. ``--go-analyzer-cgo`` opts in, keeps the
    caller's cgo environment, and warns about the C compiler and about
    toolchains older than go1.26.11 / go1.27.4.
  - ``--go-analyzer-network offline`` sets ``GOPROXY=off`` to forbid
    downloads entirely (requires a warm module cache). Default ``auto``.
  - ``--include-all-flows`` is ALWAYS passed: without it, golem drops
    call-graph edges and dataflow slices rooted entirely in the module cache
    (``/go/pkg/mod/...``) -- exactly the dependency-CVE reachability flows
    we need. This is a non-negotiable correctness requirement.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass
from logging import Logger
from typing import Optional

from xbom_lib.plugins import get_plugins_bin_target
from xbom_lib.process import build_command, find_executable, tool_env


# ---------------------------------------------------------------------------
# Constants -- mirrored in depscan/lib/config.py for the CLI layer.
# ---------------------------------------------------------------------------

# env override for the binary path (depscan convenience)
GOLEM_BINARY_ENV = "DEPSCAN_GOLEM_BINARY"

# cdxgen's plugin override env for golem (see cdxgen's PLUGIN_ENV_COMMAND_NAMES).
# Honored FIRST so depscan's fallback resolves the same binary cdxgen itself
# uses (and which produced the persisted report).
GOLEM_CMD_ENV = "GOLEM_CMD"

# Default invocation modes. ``static`` call graph + ``all`` dataflow gives
# the richest reachability signal (mirror cdxgen's research profile defaults).
DEFAULT_CALLGRAPH_MODE = "static"
DEFAULT_DATAFLOW_MODE = "all"

# ``--include-all-flows`` is REQUIRED for dependency-CVE reachability. By
# default golem drops call-graph edges and dataflow slices rooted entirely in
# the module cache -- exactly the flows we need to prove a vulnerable
# dependency is reached. This is always on; no override.
INCLUDE_ALL_FLOWS = True

# Entry points golem measures reachability from, passed as ``--roots``.
# ``main`` is golem's own default (it already adds ``init`` and type-resolved
# framework registrations); naming ``init`` and ``handlers`` as well records the
# choice on the command line and adds functions shaped like
# ``func(http.ResponseWriter, *http.Request)``, which serve requests without
# being called from ``main``. ``exported`` is left out on purpose: for an
# application it would mark every public function reached and make the
# per-node verdicts meaningless. A library with no ``main`` therefore reports
# no reachability, which golem records as ``skipped`` rather than "unreachable".
DEFAULT_ROOTS = ("main", "init", "handlers")

# Witness paths per requested symbol, passed as ``--max-paths-per-symbol``
# whenever symbols are requested. Matches golem's own default.
DEFAULT_MAX_PATHS_PER_SYMBOL = 3

# Wall-clock cap so a stuck golem process can never block a scan indefinitely.
# Generous for large Go workspaces; override via ``DEPSCAN_GOLEM_TIMEOUT``
# (seconds).
DEFAULT_TIMEOUT = int(os.environ.get("DEPSCAN_GOLEM_TIMEOUT", "1800") or 1800)

# The environment variables that re-enable #cgo flags Go refuses for safety.
# A scanned package's ``#cgo`` directives, ``.syso`` files or
# ``#cgo pkg-config:`` lines can make the C compiler or linker run code on the
# machine that loads the package, and these variables re-allow the refused
# flags for every package in the build. golem's package loader compiles cgo
# packages, so none of them may pass through to golem by default.
CGO_ALLOW_ENV_VARS = (
    "CGO_CFLAGS_ALLOW",
    "CGO_CPPFLAGS_ALLOW",
    "CGO_CXXFLAGS_ALLOW",
    "CGO_FFLAGS_ALLOW",
    "CGO_LDFLAGS_ALLOW",
)

# The Go releases that closed the cgo flag holes, per release line. A
# toolchain older than these (or older than the whole 1.26 line) still lets a
# package's flags reach the C compiler when cgo is on.
GO_CGO_PATCHED_RELEASES = {"1.26": (1, 26, 11), "1.27": (1, 27, 4)}

# ``go version`` prints ``go version go1.26.10 X:boringcrypto linux/amd64``;
# the second token carries the release (``go1.26.10``, ``go1.28rc1``,
# ``go1.29beta1``) or the word ``devel`` for a source build.
_GO_RELEASE_RE = re.compile(r"^go(\d+)\.(\d+)(?:\.(\d+))?(?:(?:rc|beta)\d+)?$")


@dataclass
class GolemResult:
    """Outcome of a golem run. ``report_path`` is set only on success."""

    success: bool = False
    report_path: Optional[str] = None
    skipped: bool = False
    command_output: str = ""
    version: Optional[str] = None
    timed_out: bool = False
    #: The ``--roots`` specifiers the run asked for; empty when the golem
    #: binary predates the flag and its own default root set applied.
    roots: tuple = ()


# ---------------------------------------------------------------------------
# Binary discovery
# ---------------------------------------------------------------------------


def bundled_golem_path(plugins_dir: Optional[str], target: Optional[dict] = None) -> Optional[str]:
    """Return the expected golem binary path inside a cdxgen-plugins-bin dir.

    Mirrors cdxgen's ``resolveBundledPluginBinary`` for the ``golem`` tool::

        <pluginsDir>/golem/golem-<platform>-<arch><extn>

    Returns the path only when it exists on disk; otherwise ``None``.
    """
    if not plugins_dir:
        return None
    target = target or get_plugins_bin_target()
    candidate = os.path.join(
        plugins_dir,
        "golem",
        f"golem-{target['platform']}-{target['arch']}{target['extn']}",
    )
    return candidate if os.path.isfile(candidate) else None


def find_golem_binary(logger: Optional[Logger] = None) -> Optional[str]:
    """Locate the golem binary, matching cdxgen's resolution.

    Resolution order:
      1. ``GOLEM_CMD`` env (cdxgen's primary plugin override).
      2. ``DEPSCAN_GOLEM_BINARY`` env (depscan convenience override).
      3. ``find_executable("golem")`` (PATH).
      4. ``CDXGEN_PLUGINS_DIR`` bundled layout (see :func:`bundled_golem_path`).

    Returns an absolute path string or ``None`` (graceful skip).
    """
    for env_name in (GOLEM_CMD_ENV, GOLEM_BINARY_ENV):
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

    found = find_executable("golem")
    if found:
        return found

    plugins_dir = os.environ.get("CDXGEN_PLUGINS_DIR", "").strip()
    if plugins_dir:
        candidate = bundled_golem_path(plugins_dir)
        if candidate:
            return candidate

    return None


def get_golem_version(binary: str, logger: Optional[Logger] = None) -> Optional[str]:
    """Return the golem version string (``golem --version``), or ``None``."""
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
            logger.debug("golem --version failed: %s", e)
        return None
    out = (cp.stdout or "").strip()
    # output shape: "golem 2.5.2"
    for tok in out.split():
        if tok and tok[0].isdigit():
            return tok
    return None


_ROOTS_FLAG_SUPPORT: dict = {}


def golem_supports_roots(binary: str, logger: Optional[Logger] = None) -> bool:
    """Return True if ``binary`` accepts ``--roots`` and ``--reachable-symbols``.

    Releases before the call-graph rework reject both flags and abort, so the
    flags are only passed after ``golem analyze -h`` lists them. Asking the
    binary is more reliable than comparing version strings, since a source
    build reports ``dev``. The answer is remembered per binary path.
    """
    if binary in _ROOTS_FLAG_SUPPORT:
        return _ROOTS_FLAG_SUPPORT[binary]
    supported = False
    try:
        cp = subprocess.run(
            build_command([binary, "analyze", "-h"]),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=tool_env(),
            shell=False,
            encoding="utf-8",
            check=False,
            timeout=30,
        )
        text = cp.stdout or ""
        supported = bool(re.search(r"^\s+-{1,2}roots\b", text, re.M)) and bool(
            re.search(r"^\s+-{1,2}reachable-symbols\b", text, re.M)
        )
    except (OSError, subprocess.SubprocessError) as e:
        if logger:
            logger.debug("golem analyze -h failed: %s", e)
    _ROOTS_FLAG_SUPPORT[binary] = supported
    return supported


# ---------------------------------------------------------------------------
# Go toolchain check (safety gate)
# ---------------------------------------------------------------------------


def go_toolchain_available(logger: Optional[Logger] = None) -> bool:
    """Return True if a Go toolchain is available (``go version`` succeeds).

    golem loads packages via ``golang.org/x/tools/go/packages`` which
    delegates to the local Go toolchain. Without ``go`` on PATH, golem cannot
    function. We check this explicitly so we can skip gracefully with a clear
    diagnostic rather than letting golem fail with an opaque error.
    """
    return go_toolchain_release_probe(logger=logger)[0]


def go_toolchain_release_probe(logger: Optional[Logger] = None) -> tuple:
    """Run ``go version`` once and return ``(available, release)``.

    ``available`` is True when a Go toolchain answered, whether or not its
    output could be parsed. ``release`` is the token naming the release, such
    as ``go1.26.10``, ``go1.28rc1`` or ``go1.29beta1``; a source build reports
    ``devel`` and an unparseable report reports ``None``.
    """
    try:
        cp = subprocess.run(
            build_command(["go", "version"]),
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
            logger.debug("go version invocation failed or 'go' not on PATH")
        return False, None
    if cp.returncode != 0:
        if logger:
            logger.debug("go version returned rc=%s", cp.returncode)
        return False, None
    for tok in (cp.stdout or "").split():
        if tok == "devel" or _GO_RELEASE_RE.match(tok):
            return True, tok
    return True, None


def go_toolchain_version(logger: Optional[Logger] = None) -> Optional[str]:
    """Return the Go release token from ``go version``, or ``None``."""
    return go_toolchain_release_probe(logger=logger)[1]


def go_toolchain_has_cgo_fixes(release: Optional[str]) -> bool:
    """Return True if the Go release named by ``release`` includes the cgo
    flag fixes.

    The fixes landed in go1.26.11 and go1.27.4, so anything newer on those
    lines and every release candidate of a later line counts as fixed. A
    ``devel`` build or a release that cannot be parsed returns False: it
    cannot be dated, so the operator who enabled cgo is warned rather than
    reassured.
    """
    if not release or release == "devel":
        return False
    match = _GO_RELEASE_RE.match(release)
    if not match:
        return False
    major, minor = int(match.group(1)), int(match.group(2))
    # A release candidate carries no patch number and counts as patch 0.
    patch = int(match.group(3) or 0)
    threshold = GO_CGO_PATCHED_RELEASES.get(f"{major}.{minor}")
    if threshold is not None:
        return (major, minor, patch) >= threshold
    # A release candidate of a line newer than the fixed ones carries the
    # fixes from the start.
    return (major, minor) > max(tuple(int(p) for p in key.split(".")) for key in GO_CGO_PATCHED_RELEASES)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def apply_cgo_env(env: dict, allow_cgo: bool) -> dict:
    """Apply the cgo rule to ``env`` in place and return it.

    With ``allow_cgo`` the caller's ``CGO_ENABLED`` is kept, defaulting to 1.
    Without it, ``CGO_ENABLED`` is forced to 0 and every ``CGO_*_ALLOW``
    variable is removed even when the caller's environment sets them. This is
    the one place that knows the rule; the golem runner and the cdxgen
    generators both call it, because cdxgen can also end up running golem for
    a Go project.
    """
    if allow_cgo:
        # The operator opted in: keep their CGO_ENABLED, defaulting to 1 so a
        # plain environment still loads cgo packages.
        env.setdefault("CGO_ENABLED", "1")
    else:
        env["CGO_ENABLED"] = "0"
        for var in CGO_ALLOW_ENV_VARS:
            env.pop(var, None)
    return env


def _build_hardened_go_env(network_mode: str, allow_cgo: bool = False) -> dict:
    """Build a hardened Go environment for golem's subprocess.

    - Default: ``GOFLAGS=-mod=readonly`` (prevents go from rewriting go.mod
      during package loading on untrusted repos).
    - ``offline``: additionally sets ``GOPROXY=off`` to forbid module
      downloads entirely. Requires a warm module cache (``GOMODCACHE``);
      golem will error on missing modules instead of downloading them.
    - Respects the user's existing ``GOFLAGS``/``GOPROXY``/``GONOSUMCHECK``
      only when they are already set; our defaults do not override explicit
      user configuration.
    - cgo is the exception to that rule and is always forced off (see
      :func:`apply_cgo_env`): golem's package loader compiles cgo packages,
      and a package's ``#cgo`` directives would otherwise run flags on the C
      compiler with the caller's ``CGO_ENABLED`` and ``CGO_*_ALLOW`` values
      applied. Those are removed even when the caller's environment sets
      them, because many CI images export ``CGO_ENABLED=1`` for their own
      builds and that choice must not silently turn cgo on for a scan of
      untrusted code. Pass ``allow_cgo=True`` only for an explicit operator
      opt-in (``--go-analyzer-cgo``).
    """
    env = os.environ.copy()
    # Harden module resolution: never let go rewrite go.mod on untrusted input
    # unless the user explicitly set GOFLAGS.
    if "GOFLAGS" not in env:
        env["GOFLAGS"] = "-mod=readonly"
    if network_mode == "offline":
        # GOPROXY=off forbids all module downloads. golem will fail rather
        # than silently fetch code from the network.
        env["GOPROXY"] = "off"
    return apply_cgo_env(env, allow_cgo)


def _dataflow_worker_count() -> int:
    """Return the worker count mirroring cdxgen's ``appendGolemDataFlowArgs``:
    ``min(cpu_count, 4)``, at least 1.
    """
    try:
        import multiprocessing

        return max(1, min(multiprocessing.cpu_count(), 4))
    except Exception:
        return 1


def _build_golem_args(
    src_dir: str,
    out_path: str,
    *,
    callgraph_mode: str,
    dataflow_mode: str,
    deep: bool,
    roots: Optional[tuple] = None,
    reachable_symbols_file: Optional[str] = None,
    max_paths_per_symbol: int = DEFAULT_MAX_PATHS_PER_SYMBOL,
) -> list:
    """Build the ``golem analyze`` argument list.

    Mirrors cdxgen's ``runGolemAnalysis`` + ``appendGolemDataFlowArgs`` so the
    direct-golem fallback produces the same report shape cdxgen would.
    ``--include-all-flows`` is ALWAYS included (non-negotiable for dependency
    reachability -- see module docstring).

    ``roots`` becomes ``--roots`` (comma-separated) and
    ``reachable_symbols_file`` becomes ``--reachable-symbols`` with
    ``--max-paths-per-symbol``. Both default to off so callers that talk to an
    older golem build never pass flags it rejects; :func:`run_golem` decides.
    """
    workers = _dataflow_worker_count()
    # ``--deep`` trades breadth for per-slice depth (fewer, deeper slices),
    # mirroring cdxgen. ``DEPSCAN_GOLEM_MAX_SLICES`` overrides either default.
    max_slices = 250 if deep else 1000
    env_max_slices = os.environ.get("DEPSCAN_GOLEM_MAX_SLICES", "").strip()
    if env_max_slices.isdigit() and int(env_max_slices) > 0:
        max_slices = int(env_max_slices)
    args = [
        "analyze",
        "--dir",
        os.path.abspath(src_dir),
        "--format",
        "json",
        "--callgraph",
        callgraph_mode,
        "--out",
        out_path,
        # REQUIRED: without this, flows rooted entirely in the module cache
        # (dependency-internal call stacks) are silently dropped.
        "--include-all-flows",
        "--dataflow",
        dataflow_mode,
        "--dataflow-callgraph",
        "static",
        "--dataflow-pattern-packs",
        "all",
        "--dataflow-max-slices",
        str(max_slices),
        "--dataflow-workers",
        str(workers),
        "--max-procs",
        str(workers),
        "--dataflow-large-repo-functions",
        "1000",
        "--dataflow-max-function-instructions",
        "200",
        "--dataflow-max-trace-nodes",
        "64",
        "--dataflow-max-trace-edges",
        "128",
        "--dataflow-skip-generated",
        "--dataflow-skip-tests",
    ]
    if roots:
        args += ["--roots", ",".join(roots)]
    if reachable_symbols_file:
        args += [
            "--reachable-symbols",
            reachable_symbols_file,
            "--max-paths-per-symbol",
            str(max_paths_per_symbol),
        ]
    return args


def run_golem(
    src_dir: str,
    out_path: str,
    *,
    callgraph_mode: str = DEFAULT_CALLGRAPH_MODE,
    dataflow_mode: str = DEFAULT_DATAFLOW_MODE,
    network_mode: str = "auto",
    deep: bool = False,
    allow_cgo: bool = False,
    roots: Optional[tuple] = DEFAULT_ROOTS,
    reachable_symbols: Optional[list] = None,
    logger: Optional[Logger] = None,
    timeout: Optional[int] = DEFAULT_TIMEOUT,
) -> GolemResult:
    """Run ``golem analyze`` on ``src_dir`` and write the report to ``out_path``.

    Returns a :class:`GolemResult`. When the binary or Go toolchain is missing
    the result is ``skipped=True, success=False`` -- callers should treat that
    as a soft fallback (warn, continue without golem reachability), never an
    error.

    ``network_mode``: ``"auto"`` (default) allows golem's package loader to
    download missing modules per the user's Go env. ``"offline"`` sets
    ``GOPROXY=off`` to forbid all downloads (requires a warm module cache).

    ``allow_cgo``: cgo stays off by default, so packages that need cgo are
    not loaded and their reachability is missing. With ``allow_cgo=True``
    (the ``--go-analyzer-cgo`` opt-in) the package loader compiles cgo
    packages with the caller's ``CGO_ENABLED`` and ``CGO_*_ALLOW`` values,
    which means the C compiler runs with flags taken from the scanned code
    and its dependencies; the toolchain release is checked and warned about
    when it predates the Go releases that refuse those flags.

    ``roots``: the entry-point set golem measures reachability from (see
    :data:`DEFAULT_ROOTS`); the report's ``callGraph.roots`` records what was
    resolved. ``reachable_symbols``: names (case-insensitive substrings of a
    node id or label) to emit witness paths for, such as the vulnerable
    functions of matched advisories. Both are skipped, with a debug message,
    when the golem binary does not know the flags.
    """
    binary = find_golem_binary(logger=logger)
    if not binary:
        if logger:
            logger.warning(
                "golem binary not found (set %s or install cdxgen-plugins-bin). "
                "Go reachability via golem will be skipped.",
                GOLEM_BINARY_ENV,
            )
        return GolemResult(success=False, skipped=True, command_output="golem binary not found")

    if not go_toolchain_available(logger=logger):
        if logger:
            logger.warning(
                "Go toolchain ('go') not found on PATH. golem requires a local "
                "Go installation to load packages. Go reachability will be skipped."
            )
        return GolemResult(success=False, skipped=True, command_output="go toolchain not found")

    if allow_cgo and logger:
        logger.warning(
            "cgo is enabled for this golem run (--go-analyzer-cgo): the C "
            "compiler will run with flags taken from the scanned code and its "
            "dependencies. Use this only for input you trust."
        )
        release = go_toolchain_version(logger=logger)
        if not go_toolchain_has_cgo_fixes(release):
            logger.warning(
                "Go %s is not known to refuse unsafe cgo flags (go1.26.11 "
                "and go1.27.4 fixed these). Upgrade the Go toolchain to "
                "go1.26.11, go1.27.4 or newer before scanning untrusted input "
                "with cgo enabled.",
                release or "(unrecognised release)",
            )

    version = get_golem_version(binary, logger=logger)
    if version and logger:
        logger.debug("golem version: %s", version)

    abs_src_dir = os.path.abspath(src_dir)
    used_roots: tuple = ()
    symbols_file: Optional[str] = None
    if roots or reachable_symbols:
        if golem_supports_roots(binary, logger=logger):
            used_roots = tuple(roots or ())
            symbols = sorted({str(s).strip() for s in (reachable_symbols or []) if str(s).strip()})
            if symbols:
                symbols_file = out_path + ".symbols.txt"
                with open(symbols_file, "w", encoding="utf-8") as fp:
                    fp.write("\n".join(symbols) + "\n")
        elif logger:
            logger.debug(
                "golem %s does not support --roots/--reachable-symbols; "
                "its default root set applies.",
                version or binary,
            )
    args = _build_golem_args(
        abs_src_dir,
        out_path,
        callgraph_mode=callgraph_mode,
        dataflow_mode=dataflow_mode,
        deep=deep,
        roots=used_roots,
        reachable_symbols_file=symbols_file,
    )
    full_cmd = [binary] + args

    if logger:
        logger.debug("Executing '%s'", " ".join(full_cmd))

    env = _build_hardened_go_env(network_mode, allow_cgo=allow_cgo)
    try:
        cp = subprocess.run(
            build_command(full_cmd),
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
        return GolemResult(
            success=False,
            command_output=f"golem timed out after {timeout}s",
            version=version,
            timed_out=True,
        )
    except (OSError, subprocess.SubprocessError) as e:
        return GolemResult(
            success=False,
            command_output=f"golem invocation failed: {e}",
            version=version,
        )

    out = cp.stdout or ""
    if cp.returncode != 0 or not os.path.exists(out_path):
        if logger:
            logger.debug("golem produced no report (rc=%s).", cp.returncode)
            logger.debug(out)
        return GolemResult(success=False, command_output=out, version=version)

    # Warn on truncation so partial results are visible.
    _check_truncation(out_path, logger=logger)

    # schema/version sanity (soft): warn but keep the file so the converter
    # can still try.
    report_ok, schema_msg = _peek_report(out_path)
    if logger and not report_ok:
        logger.warning(
            "golem report at %s did not validate: %s. Conversion may be incomplete.",
            out_path,
            schema_msg,
        )
    return GolemResult(
        success=True,
        report_path=out_path,
        command_output=out,
        version=version,
        roots=used_roots,
    )


def _check_truncation(out_path: str, logger: Optional[Logger] = None) -> None:
    """Read ``dataFlow.stats.truncated`` / ``truncationReasons[]`` and warn."""
    try:
        with open(out_path, encoding="utf-8") as fp:
            data = json.load(fp)
    except (OSError, ValueError):
        return
    if not isinstance(data, dict):
        return
    df = data.get("dataFlow")
    if not isinstance(df, dict):
        return
    stats = df.get("stats")
    if not isinstance(stats, dict):
        return
    if stats.get("truncated"):
        reasons = stats.get("truncationReasons") or []
        reason_str = ", ".join(str(r) for r in reasons) if reasons else "unknown"
        if logger:
            logger.warning(
                "golem dataflow was truncated (%s). Reachability results may "
                "be partial; increase --dataflow-max-slices via the "
                "DEPSCAN_GOLEM_MAX_SLICES env or reduce scope.",
                reason_str,
            )


def _peek_report(out_path: str):
    """Cheap validation of the produced report. Returns (ok, message).

    Detection is by structural SHAPE, not ``schemaVersion``: a golem report
    is a dict carrying its producer identity (``tool``/``runtime``) alongside
    at least one analysis section (``callGraph``/``dataFlow``). This is the
    same strategy as :func:`xbom_lib.rusi._peek_report` but with camelCase
    section keys (golem JSON is lowerCamelCase).
    """
    try:
        with open(out_path, encoding="utf-8") as fp:
            data = json.load(fp)
    except (OSError, ValueError) as e:
        return False, f"unreadable JSON ({e})"
    if not isinstance(data, dict):
        return False, "report is not a JSON object"
    has_producer = isinstance(data.get("tool"), dict) or isinstance(data.get("runtime"), dict)
    has_section = isinstance(data.get("callGraph"), dict) or isinstance(data.get("dataFlow"), dict)
    if not (has_producer and has_section):
        return False, "missing golem producer (tool/runtime) and section (callGraph/dataFlow)"
    return True, "ok"
