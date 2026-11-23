import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from logging import Logger
from typing import Any, Dict, List, Optional, Tuple

import httpx

from xbom_lib import BOMResult, XBOMGenerator
from xbom_lib.golem import CGO_ALLOW_ENV_VARS, apply_cgo_env
from xbom_lib.process import build_command, find_executable, tool_env

cdxgen_server_headers = {
    "Content-Type": "application/json",
    "Accept-Encoding": "gzip",
}

# cdxgen timeout. Increased to 30 minutes
CDXGEN_TIMEOUT_MS = os.getenv("CDXGEN_TIMEOUT_MS", str(int(30 * 60 * 1000)))

# Version of the cdxgen container images to use. cdxgen publishes exact
# versions as bare tags ("13.8.0") and the rolling major and minor tags with
# a "v" prefix ("v13", "v13.8"); a "v13.8.0" image tag does not exist. The
# SEA release assets, in contrast, live under the "v13.8.0" git tag.
CDXGEN_IMAGE_VERSION = os.getenv("CDXGEN_IMAGE_VERSION", "13.8.0")
CDXGEN_IMAGE_ROLLING_VERSION = os.getenv("CDXGEN_IMAGE_ROLLING_VERSION", "v13")

# Oldest cdxgen this version of dep-scan works with. cdxgen 13.8 introduced
# the callsites slice, build introspection and the 4/5 exit statuses that the
# callers below rely on, so an older command is refused before it runs.
CDXGEN_MIN_VERSION = os.getenv("CDXGEN_MIN_VERSION", "13.8.0")

# The npm package that installs the cdxgen command, used in every install
# hint. cdxgen publishes as @cdxgen/cdxgen since 13.0.
CDXGEN_NPM_PACKAGE = "@cdxgen/cdxgen"


def _version_tuple(version: str) -> Tuple[int, ...]:
    """Numeric parts of a version; a pre-release sorts below its release.

    ``13.8.0`` becomes ``(13, 8, 0, 1)`` and ``13.8.0-beta.1`` becomes
    ``(13, 8, 0, 0)``, so a pre-release of the minimum version is refused.
    """
    release, _, pre = version.partition("-")
    parts = tuple(int(part) for part in release.split(".") if part.isdigit())
    return (*parts, 0 if pre else 1)


def cdxgen_min_version_tuple() -> Tuple[int, ...]:
    return _version_tuple(CDXGEN_MIN_VERSION)


def cdxgen_install_hint() -> str:
    return f"npm install -g {CDXGEN_NPM_PACKAGE}@{CDXGEN_MIN_VERSION}"


# cdxgen official image namespaces
OFFICIAL_IMAGE_NAMESPACES = (
    "ghcr.io/cdxgen/",
    "ghcr.io/cyclonedx/",
    "ghcr.io/appthreat/",
    "ghcr.io/owasp-dep-scan/",
)

# cdxgen default image to use; read at call time so CDXGEN_SECURE_MODE set
# for one scan changes the image choice of the same process.
DEFAULT_IMAGE_NAME = "default"
DEFAULT_SECURE_IMAGE_NAME = "default-secure"


def default_image_name() -> str:
    """The image family to use, honouring CDXGEN_SECURE_MODE right now."""
    if os.getenv("CDXGEN_SECURE_MODE", "") in ("true", "1"):
        return DEFAULT_SECURE_IMAGE_NAME
    return DEFAULT_IMAGE_NAME


PROJECT_TYPE_IMAGE = {
    "default": f"ghcr.io/cdxgen/cdxgen:{CDXGEN_IMAGE_VERSION}",
    # The deno and bun images publish only the rolling "v13" tag in the 13.x
    # line, so they use it to keep their runtimes. The node20, dotnet6 and
    # dotnet7 images publish no 13.x tag at all; those types run the general
    # and dotnet8 images below.
    "deno": f"ghcr.io/cdxgen/cdxgen-deno:{CDXGEN_IMAGE_ROLLING_VERSION}",
    "bun": f"ghcr.io/cdxgen/cdxgen-bun:{CDXGEN_IMAGE_ROLLING_VERSION}",
    "default-secure": f"ghcr.io/cdxgen/cdxgen-secure:{CDXGEN_IMAGE_VERSION}",
    "java": f"ghcr.io/cdxgen/cdxgen-temurin-java21:{CDXGEN_IMAGE_VERSION}",
    "java24": f"ghcr.io/cdxgen/cdxgen:{CDXGEN_IMAGE_VERSION}",
    "android": f"ghcr.io/cdxgen/cdxgen:{CDXGEN_IMAGE_VERSION}",
    "java8": f"ghcr.io/cdxgen/cdxgen-temurin-java8:{CDXGEN_IMAGE_VERSION}",
    "java11-slim": f"ghcr.io/cdxgen/cdxgen-java11-slim:{CDXGEN_IMAGE_VERSION}",
    "java11": f"ghcr.io/cdxgen/cdxgen-java11:{CDXGEN_IMAGE_VERSION}",
    "java17": f"ghcr.io/cdxgen/cdxgen-java17:{CDXGEN_IMAGE_VERSION}",
    "java17-slim": f"ghcr.io/cdxgen/cdxgen-java17-slim:{CDXGEN_IMAGE_VERSION}",
    "java21": f"ghcr.io/cdxgen/cdxgen-temurin-java21:{CDXGEN_IMAGE_VERSION}",
    "node20": f"ghcr.io/cdxgen/cdxgen:{CDXGEN_IMAGE_VERSION}",
    "python39": f"ghcr.io/cdxgen/cdxgen-python39:{CDXGEN_IMAGE_VERSION}",
    "python310": f"ghcr.io/cdxgen/cdxgen-python310:{CDXGEN_IMAGE_VERSION}",
    "python311": f"ghcr.io/cdxgen/cdxgen-python311:{CDXGEN_IMAGE_VERSION}",
    "python312": f"ghcr.io/cdxgen/cdxgen-python312:{CDXGEN_IMAGE_VERSION}",
    "python": f"ghcr.io/cdxgen/cdxgen-python312:{CDXGEN_IMAGE_VERSION}",
    "swift": f"ghcr.io/cdxgen/cdxgen-debian-swift6:{CDXGEN_IMAGE_VERSION}",
    "swift6": f"ghcr.io/cdxgen/cdxgen-debian-swift6:{CDXGEN_IMAGE_VERSION}",
    "ruby26": f"ghcr.io/cdxgen/cdxgen-debian-ruby26:{CDXGEN_IMAGE_VERSION}",
    "ruby33": f"ghcr.io/cdxgen/cdxgen-debian-ruby33:{CDXGEN_IMAGE_VERSION}",
    "ruby34": f"ghcr.io/cdxgen/cdxgen-debian-ruby34:{CDXGEN_IMAGE_VERSION}",
    "ruby": f"ghcr.io/cdxgen/cdxgen-debian-ruby34:{CDXGEN_IMAGE_VERSION}",
    "dotnet-core": f"ghcr.io/cdxgen/cdxgen-debian-dotnet8:{CDXGEN_IMAGE_VERSION}",
    "dotnet-framework": f"ghcr.io/cdxgen/cdxgen-debian-dotnet8:{CDXGEN_IMAGE_VERSION}",
    "dotnet6": f"ghcr.io/cdxgen/cdxgen-debian-dotnet8:{CDXGEN_IMAGE_VERSION}",
    "dotnet7": f"ghcr.io/cdxgen/cdxgen-debian-dotnet8:{CDXGEN_IMAGE_VERSION}",
    "dotnet8": f"ghcr.io/cdxgen/cdxgen-debian-dotnet8:{CDXGEN_IMAGE_VERSION}",
    "dotnet9": f"ghcr.io/cdxgen/cdxgen-debian-dotnet9:{CDXGEN_IMAGE_VERSION}",
    "dotnet": f"ghcr.io/cdxgen/cdxgen-debian-dotnet9:{CDXGEN_IMAGE_VERSION}",
}


def get_env_options_value(options: Dict, k: str, default: Optional[str] = None) -> str:
    return os.getenv(k.upper(), options.get(k.lower(), default))


def deep_enabled(options: Dict) -> bool:
    """Whether the ``deep`` option asks for a deep cdxgen scan.

    ``deep`` reaches the generators either as a real boolean (depscan's blint
    fallback and the depscan server normalize it) or as the strings the
    lifecycle stages pass ("true"/"false"). A bare truthiness test would treat
    the string "false" as enabled (issue #536), and a membership test against
    ("true", "1") alone would drop a boolean True, so normalize both forms
    here and keep every generator consistent.
    """
    deep = options.get("deep")
    if isinstance(deep, bool):
        return deep
    return str(deep).strip().lower() in ("true", "1")


def get_image_for_type(options: Dict, project_type: str | list | None) -> str:
    image_name = default_image_name()
    if not project_type:
        return PROJECT_TYPE_IMAGE[image_name]
    project_types: list[str] = project_type if isinstance(project_type, list) else [project_type]
    ptype = project_types[0] if len(project_types) == 1 else image_name
    default_img = PROJECT_TYPE_IMAGE.get(ptype, PROJECT_TYPE_IMAGE[image_name])
    return get_env_options_value(
        options,
        f"cdxgen_image_{ptype}",
        default_img,
    )


def needs_latest_image(image_name):
    return any(
        image_name.startswith(ns) for ns in OFFICIAL_IMAGE_NAMESPACES
    ) or image_name.endswith((":latest", ":master", ":main", ":v11"))


def resource_path(relative_path):
    """
    Determine the absolute path of a resource file based on its relative path.

    :param relative_path: Relative path of the resource file.
    :return: Absolute path of the resource file
    """
    # sys._MEIPASS only exists inside a PyInstaller frozen bundle; fall back
    # to this module's directory in a regular install.
    base_path = getattr(sys, "_MEIPASS", None) or os.path.dirname(__file__)
    return os.path.join(base_path, relative_path)


def _exec_timeout_seconds() -> Optional[float]:
    """cdxgen's own CDXGEN_TIMEOUT_MS plus five minutes for it to wind down."""
    try:
        return int(CDXGEN_TIMEOUT_MS) / 1000 + 300
    except (TypeError, ValueError):
        return None


def cdxgen_timeout_hint() -> str:
    """The cdxgen time budget that was in effect, and how to raise it.

    dep-scan passes this budget to every cdxgen run and stops cdxgen at it,
    so a run that failed under it may or may not have been stopped by the
    budget; the text names what was in effect without claiming the cause.
    """
    return (
        f"The run had a CDXGEN_TIMEOUT_MS budget of {CDXGEN_TIMEOUT_MS} ms in effect; "
        "if cdxgen was stopped at the budget, raise CDXGEN_TIMEOUT_MS for this scan"
    )


def as_command_list(cmd) -> List[str]:
    """Normalize a resolved tool command to the argument list to execute.

    ``find_cdxgen_cmd`` returns a single path, but tests and embedders may
    hand back a full command such as ``[sys.executable, "fake_cdxgen.py"]``,
    which is how a fake cdxgen runs on Windows without an execute bit.
    """
    if isinstance(cmd, (list, tuple)):
        return [str(part) for part in cmd]
    return [str(cmd)]


# Version probes already run in this process, keyed by the command, so a
# lifecycle scan asks cdxgen for its version once, not once per stage.
_version_probe_cache: Dict[str, Optional[str]] = {}

_VERSION_RE = re.compile(r"CycloneDX\s+Generator\s+v?(\d+(?:\.\d+)+(?:-[0-9A-Za-z.]+)?)")


def cdxgen_version(cmd, logger: Optional[Logger] = None) -> Optional[str]:
    """Ask ``cmd`` for its version and return it as a string, or None.

    cdxgen prints ``CycloneDX Generator 13.8.0`` on ``--version``; anything
    that cannot be parsed (missing binary, crash, unexpected output) yields
    None so the caller can refuse the command.
    """
    cmd_list = as_command_list(cmd)
    key = " ".join(cmd_list)
    if key in _version_probe_cache:
        return _version_probe_cache[key]
    try:
        # The probe never scans code, so cgo stays off here regardless of
        # options; a cdxgen release before the matching golem fix would
        # otherwise pass its whole environment to golem.
        cp = subprocess.run(
            build_command([*cmd_list, "--version"]),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=tool_env(apply_cgo_env(os.environ.copy(), False)),
            shell=False,
            encoding="utf-8",
            check=False,
            timeout=60,
        )
        found = _VERSION_RE.search(cp.stdout or "")
        version = found.group(1) if found else None
    except (OSError, subprocess.SubprocessError) as e:
        if logger:
            logger.debug("Could not run %s --version: %s", key, e)
        version = None
    _version_probe_cache[key] = version
    return version


def check_cdxgen_version(cmd, logger: Optional[Logger] = None) -> Tuple[bool, Optional[str]]:
    """Whether ``cmd`` is at least CDXGEN_MIN_VERSION.

    Returns ``(accepted, version)``; ``version`` is None when the probe could
    not read a version at all, which is refused like an old one. The caller
    is expected to log the message that names the remedy.
    """
    version = cdxgen_version(cmd, logger=logger)
    if version is None:
        return False, None
    return _version_tuple(version) >= cdxgen_min_version_tuple(), version


def exec_tool(
    args: List[str],
    cwd: Optional[str] = None,
    env: Optional[Dict] = None,
    stdout: int = subprocess.PIPE,
    logger: Optional[Logger] = None,
) -> BOMResult:
    """
    Convenience method to invoke cli tools

    :param args: Command line arguments
    :param cwd: Working directory
    :param env: Environment variables
    :param stdout: Specifies stdout of command
    :param logger: Logger object
    """
    if env is None:
        env = os.environ.copy()
    result = BOMResult(success=True)
    try:
        if logger and stdout != subprocess.DEVNULL:
            logger.debug("Executing '%s'", " ".join(args))
        cp = subprocess.run(
            build_command(args),
            stdout=stdout,
            stderr=subprocess.STDOUT,
            cwd=cwd,
            env=tool_env(env),
            shell=False,
            encoding="utf-8",
            check=False,
            timeout=_exec_timeout_seconds(),
        )
        result.command_output = cp.stdout
        result.returncode = cp.returncode
        if logger and stdout != subprocess.DEVNULL:
            logger.debug(cp.stdout)
    except Exception as e:
        result.success = False
        result.command_output = f"Exception while running cdxgen: {e}"
    return result


def _set_plugins_dir_if_present(candidate: str) -> None:
    """Point ``CDXGEN_PLUGINS_DIR`` at ``candidate`` only when it actually holds
    a cdxgen plugins tree.

    The bundled ``local_bin/cdxgen`` is a self-contained caxa binary that
    already carries ``@cdxgen/cdxgen-plugins-bin`` and auto-detects it from its
    own extraction directory. cdxgen gives ``CDXGEN_PLUGINS_DIR`` top priority,
    so pointing it at ``local_bin`` (which contains only the cdxgen binary)
    would OVERRIDE and disable the bundled plugins (rusi/golem/osquery). Only
    set it for genuine npm-style layouts where a ``plugins`` dir or a tool
    subdir (e.g. ``rusi``) is present next to the resolved path.
    """
    if not candidate or not os.path.isdir(candidate):
        return
    has_plugins = os.path.isdir(os.path.join(candidate, "plugins")) or any(
        os.path.isdir(os.path.join(candidate, tool)) for tool in ("rusi", "golem", "osquery")
    )
    if has_plugins:
        os.environ["CDXGEN_PLUGINS_DIR"] = candidate


def find_cdxgen_cmd(use_bin=True, logger: Optional[Logger] = None):
    if use_bin:
        cdxgen_cmd = os.environ.get("CDXGEN_CMD", "cdxgen")
        if not find_executable(cdxgen_cmd):
            local_bin = resource_path(
                os.path.join(
                    "local_bin",
                    "cdxgen.exe" if sys.platform == "win32" else "cdxgen",
                )
            )
            if not os.path.exists(local_bin):
                if logger:
                    logger.info(
                        "%s command not found. Please install using npm install "
                        "%s or set PATH variable",
                        cdxgen_cmd,
                        CDXGEN_NPM_PACKAGE,
                    )
                return False
            cdxgen_cmd = local_bin
            # Defensive: ensure the bundled cdxgen SEA binary is executable.
            # PyInstaller preserves file mode for --add-binary, but some
            # tempdir filesystems do not retain the bit on extraction.
            if sys.platform != "win32":
                try:
                    current_mode = os.stat(cdxgen_cmd).st_mode
                    if not (current_mode & 0o111):
                        os.chmod(cdxgen_cmd, current_mode | 0o755)
                except OSError:
                    pass
            # The bundled caxa cdxgen auto-detects its own plugins; only set
            # CDXGEN_PLUGINS_DIR when local_bin actually carries a plugins tree.
            _set_plugins_dir_if_present(resource_path("local_bin"))
            return cdxgen_cmd
        else:
            return cdxgen_cmd
    else:
        lbin = os.getenv("APPDATA") if sys.platform == "win32" else "local_bin"
        local_bin = resource_path(
            os.path.join(
                f"{lbin}\\npm\\" if sys.platform == "win32" else "local_bin",
                "cdxgen" if sys.platform != "win32" else "cdxgen.cmd",
            )
        )
        if not os.path.exists(local_bin):
            if logger:
                logger.info(
                    "%s command not found. Please install using npm install "
                    "%s or set PATH variable",
                    local_bin,
                    CDXGEN_NPM_PACKAGE,
                )
            return None
        cdxgen_cmd = local_bin
        # Set the plugins directory only when it actually holds a plugins tree,
        # so a bundled caxa cdxgen can auto-detect its own plugins instead.
        plugins_candidate = (
            resource_path("local_bin")
            if sys.platform != "win32"
            else resource_path(
                os.path.join(
                    lbin,
                    "\\npm\\node_modules\\@cdxgen\\cdxgen\\node_modules\\@cdxgen\\cdxgen-plugins-bin\\plugins",
                )
            )
        )
        _set_plugins_dir_if_present(plugins_candidate)
        return cdxgen_cmd


def cdxgen_source_arg(source_dir: str) -> str:
    """The source argument to hand cdxgen for ``source_dir``.

    cdxgen is launched with its working directory set to the source directory,
    so a relative argument would be resolved a second time against it --
    ``<src>/<src>``, a directory that does not exist -- and the plugins
    (rusi, golem, kosi) would analyse nothing. A local directory is therefore
    always passed absolute, and so is a local file, so that a value such as
    ``-x/../file`` cannot be read as an option. Anything else (a git URL, a
    purl, an image name) is passed through untouched.
    """
    if source_dir and os.path.exists(source_dir):
        return os.path.abspath(source_dir)
    return source_dir


# The slices cdxgen writes for a single project type, in argument order.
SLICE_KINDS = ("deps", "usages", "callsites", "data-flow", "reachables", "semantics")


def slices_file_paths(project_type, dir):
    """The ``(option, path)`` pairs of the slices files for one project type."""
    return [
        (f"--{kind}-slices-file", os.path.join(dir, f"{project_type}-{kind}.slices.json"))
        for kind in SLICE_KINDS
    ]


def set_slices_args(project_type_list, args, dir):
    """Add the ``--*-slices-file`` arguments for a single project type.

    The slices are written next to the BOM in ``dir``. The callsites slice
    joins the others so the file is kept next to them.
    """
    if len(project_type_list) == 1:
        for option, path in slices_file_paths(project_type_list[0], dir):
            args.append(option)
            args.append(path)


def remove_stale_slices(project_type, dir, logger: Optional[Logger] = None):
    """Delete slices files a previous run left at this run's slices paths.

    cdxgen 13.8 does not regenerate a slices file that already exists: atom
    reuses it, and in secure mode cdxgen writes this run's slices to a
    temporary directory instead when the existing file is inside the scanned
    tree. Either way the scan would read the previous run's slices. Returns
    the removed paths.
    """
    removed = []
    for _option, path in slices_file_paths(project_type, dir):
        if os.path.isfile(path):
            os.remove(path)
            removed.append(path)
            if logger:
                logger.debug("Removed the slices file %s left by a previous run.", path)
    return removed


def is_remote_source(source_dir, options: Optional[Dict] = None) -> bool:
    """Whether this scan hands cdxgen something it must fetch itself.

    A git URL handed to cdxgen as the source, or a ``url`` option (the depscan
    server always sends one), means cdxgen clones untrusted code; secure mode
    is the contract for exactly that case.
    """
    options = options or {}
    url = options.get("url") or ""
    candidate = url if isinstance(url, str) and url else str(source_dir or "")
    if os.path.exists(candidate):
        return False
    return candidate.startswith(
        ("http://", "https://", "git://", "ssh://", "git@", "atom://")
    )


def is_server_scan(options: Optional[Dict] = None) -> bool:
    """Whether the depscan server asked for this BOM.

    The server sends the cdxgen-style ``multiProject``/``url`` options that
    the CLI never sets; either marker is enough. Server input is caller
    controlled, so those scans run cdxgen in secure mode.
    """
    options = options or {}
    return "multiProject" in options or bool(options.get("url"))


class CdxgenGenerator(XBOMGenerator):
    """
    Concrete implementation of XBOMGenerator using cdxgen.
    """

    def generate(self) -> BOMResult:
        """
        Generate the BOM using the cdxgen tool.
        """
        options = self.options
        project_type_list = self.options.get("project_type", [])
        techniques = self.options.get("techniques", []) or []
        lifecycles = self.options.get("lifecycles", []) or []
        env = os.environ.copy()
        # cdxgen may run golem for a Go project, and golem's package loader
        # compiles cgo packages, so this run gets cgo off unless the operator
        # opted in with --go-analyzer-cgo. A cdxgen release before the
        # matching golem fix passes its whole environment to golem, so the
        # caller's CGO_ENABLED and CGO_*_ALLOW values must not reach it.
        apply_cgo_env(env, bool(options.get("go_analyzer_cgo")))
        # Remote repositories and server-initiated scans hand cdxgen code it
        # must clone or read from a caller-chosen path, so those runs use
        # cdxgen's secure mode.
        if is_remote_source(self.source_dir, options) or is_server_scan(options):
            env["CDXGEN_SECURE_MODE"] = "true"
        # Implement the BOM generation logic using cdxgen.
        cdxgen_cmd = find_cdxgen_cmd(logger=self.logger)
        if not cdxgen_cmd:
            cdxgen_cmd = find_cdxgen_cmd(False, logger=self.logger)
        if not cdxgen_cmd:
            cdxgen_cmd = "cdxgen"
        project_type_args: list[str] = [f"-t {item}" for item in project_type_list]
        technique_args: list[str] = [f"--technique {item}" for item in techniques]
        args: list[str] = as_command_list(cdxgen_cmd)
        args = args + (" ".join(project_type_args).split())
        # The excluded types were removed from the types depscan scans; cdxgen
        # filters the BOM contents the same way.
        for excluded_type in options.get("exclude_types") or []:
            args += ["--exclude-type", str(excluded_type)]
        args = args + ["-o", self.bom_file]
        if options.get("spec_version"):
            args = args + ["--spec-version", str(options.get("spec_version"))]
        if technique_args:
            args = args + (" ".join(technique_args).split())
        if deep_enabled(options):
            args.append("--deep")
        if options.get("fail_on_error"):
            args.append("--fail-on-error")
        if options.get("profile"):
            args.append("--profile")
            args.append(options.get("profile", ""))
            if options.get("slices", True):
                set_slices_args(project_type_list, args, os.path.dirname(self.bom_file))
            if options.get("profile") not in ("generic",):
                # This would help create openapi spec file inside the reports directory
                env["ATOM_TOOLS_WORK_DIR"] = os.path.realpath(os.path.dirname(self.bom_file))
                env["ATOM_TOOLS_OPENAPI_FILENAME"] = f"{project_type_list[0]}-openapi.json"
        if options.get("cdxgen_args"):
            args += shlex.split(options.get("cdxgen_args", ""))
        # Build introspection: the JSON report is named after the BOM so it
        # lands next to it, and every lifecycle stage keeps its own report.
        args += ["--introspect", "--introspect-json", f"{self.bom_file}.introspection.json"]
        if len(lifecycles) == 1:
            args = args + ["--lifecycle", lifecycles[0]]
        # Bug #233 - Source directory could be None when working with url
        if self.source_dir:
            args.append(cdxgen_source_arg(self.source_dir))
        # Setup cdxgen thought logging
        if self.options.get("explain"):
            env["CDXGEN_THINK_MODE"] = "true"
        # Manage cdxgen temp directory
        cdxgen_temp_dir = None
        if not os.getenv("CDXGEN_TEMP_DIR"):
            cdxgen_temp_dir = tempfile.mkdtemp(
                prefix="cdxgen-temp-", dir=os.getenv("DEPSCAN_TEMP_DIR")
            )
            env["CDXGEN_TEMP_DIR"] = cdxgen_temp_dir
        env["CDXGEN_TIMEOUT_MS"] = CDXGEN_TIMEOUT_MS
        # Propagate plugin-discovery env to the cdxgen subprocess so cdxgen can
        # locate the SAME rusi/golem/dosai binary depscan resolved (RUSI_CMD /
        # GOLEM_CMD / DOSAI_CMD) and the plugins dir find_cdxgen_cmd just
        # detected (CDXGEN_PLUGINS_DIR). ``env`` was copied before
        # find_cdxgen_cmd ran, so re-sync these explicitly rather than relying
        # on copy order; this keeps cdxgen's plugin resolution consistent with
        # depscan's fallback in xbom_lib/rusi.py / golem.py / dosai.py.
        for _plug_env in ("RUSI_CMD", "GOLEM_CMD", "DOSAI_CMD", "CDXGEN_PLUGINS_DIR"):
            _plug_val = os.environ.get(_plug_env)
            if _plug_val:
                env[_plug_env] = _plug_val
        if cdxgen_cmd:
            bom_result = exec_tool(
                args,
                self.source_dir
                if not any(t in project_type_list for t in ("docker", "oci", "container"))
                and self.source_dir
                and os.path.isdir(self.source_dir)
                else None,
                env,
                logger=self.logger,
            )
        else:
            bom_result = BOMResult(
                success=False, command_output="Unable to locate cdxgen command."
            )
        if cdxgen_temp_dir:
            shutil.rmtree(cdxgen_temp_dir, ignore_errors=True)
        return bom_result


class CdxgenServerGenerator(CdxgenGenerator):
    """
    cdxgen generator that use a local cdxgen server for execution.
    """

    def generate(self) -> BOMResult:
        """
        Generate the BOM with cdxgen server.
        """
        options = self.options
        cdxgen_server = self.options.get("cdxgen_server")
        if not cdxgen_server:
            return BOMResult(
                success=False,
                command_output="Pass the `--cdxgen-server` argument to use the cdxgen server for BOM generation.",
            )
        project_type_list = self.options.get("project_type", [])
        src_dir = self.source_dir
        if not src_dir and self.options.get("path"):
            src_dir = self.options.get("path")
        with httpx.Client(http2=True, base_url=cdxgen_server, timeout=180) as client:
            sbom_url = f"{cdxgen_server}/sbom"
            if self.logger:
                self.logger.debug("Invoking cdxgen server at %s", sbom_url)
            try:
                r = client.post(
                    sbom_url,
                    json={
                        **options,
                        "url": options.get("url", ""),
                        "path": options.get("path", src_dir),
                        "type": ",".join(project_type_list),
                        "multiProject": options.get("multiProject", ""),
                    },
                    headers=cdxgen_server_headers,
                )
                if r.status_code == httpx.codes.OK:
                    try:
                        json_response = r.json()
                        if json_response:
                            with open(self.bom_file, "w", encoding="utf-8") as fp:
                                json.dump(json_response, fp)
                            return BOMResult(success=os.path.exists(self.bom_file))
                    except Exception as je:
                        return BOMResult(
                            success=False,
                            command_output=f"Unable to generate SBOM via cdxgen server due to {str(je)}",
                        )
                else:
                    return BOMResult(
                        success=False,
                        command_output=f"Unable to generate SBOM via cdxgen server due to {str(r.status_code)}",
                    )
            except Exception as e:
                if self.logger:
                    self.logger.error(e)
        return BOMResult(
            success=False,
            command_output="Unable to generate SBOM with cdxgen server. Trying to generate one locally.",
        )


class CdxgenImageBasedGenerator(CdxgenGenerator):
    """
    cdxgen generator that use container images for execution.
    """

    def __init__(
        self,
        source_dir: str,
        bom_file: str,
        logger: Optional[Logger] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(source_dir, bom_file, logger, options)
        cdxgen_temp_dir = os.getenv("CDXGEN_TEMP_DIR")
        if not cdxgen_temp_dir:
            cdxgen_temp_dir = tempfile.mkdtemp(
                prefix="cdxgen-temp-", dir=os.getenv("DEPSCAN_TEMP_DIR")
            )
            os.environ["CDXGEN_TEMP_DIR"] = cdxgen_temp_dir
        self.cdxgen_temp_dir = cdxgen_temp_dir

    def _container_run_cmd(self) -> Tuple[str, List[str]]:
        """
        Generate a container run command for the given project type, source directory, and output file
        """
        project_type_list = self.options.get("project_type", []) or []
        techniques = self.options.get("techniques") or []
        lifecycles = self.options.get("lifecycles") or []
        image_output_dir = "/reports"
        app_input_dir = "/app"
        container_tmp_dir = "/tmp"
        container_command = get_env_options_value(self.options, "DOCKER_CMD", "docker")
        image_name = get_image_for_type(self.options, project_type_list)
        run_command_args = [
            container_command,
            "run",
            "--rm",
            "--quiet",
            "--workdir",
            app_input_dir,
        ]
        output_file = os.path.basename(self.bom_file)
        output_dir = os.path.realpath(os.path.dirname(self.bom_file))
        # Setup environment variables
        # A remote repository or a server-initiated scan runs cdxgen in
        # secure mode, whatever CDXGEN_SECURE_MODE says in this environment.
        force_secure = is_remote_source(self.source_dir, self.options) or is_server_scan(
            self.options
        )
        for k, _ in os.environ.items():
            if force_secure and k == "CDXGEN_SECURE_MODE":
                continue
            # CDXGEN_TEMP_DIR is forwarded below with the in-container path:
            # the value in this environment is the host path of the temp
            # directory, which does not exist inside the container, and the
            # image's cdxgen dies creating it there.
            if k == "CDXGEN_TEMP_DIR":
                continue
            if k.startswith("CDXGEN_") or k.startswith("GIT") or k in ("FETCH_LICENSE",):
                run_command_args += ["-e", k]
        run_command_args += ["-e", f"CDXGEN_TIMEOUT_MS={CDXGEN_TIMEOUT_MS}"]
        # Pass the cgo rule into the container: cdxgen inside the image may
        # run golem for a Go project, and a cdxgen release before the
        # matching golem fix passes its whole environment to golem. The loop
        # above forwards only CDXGEN_*, GIT* and FETCH_LICENSE variables, so
        # the host's CGO_*_ALLOW values do not travel with it; the opt-in
        # forwards them by name, as that loop does, so their values stay off
        # the command line.
        if self.options.get("go_analyzer_cgo"):
            if os.environ.get("CGO_ENABLED"):
                run_command_args += ["-e", "CGO_ENABLED"]
            else:
                run_command_args += ["-e", "CGO_ENABLED=1"]
            for var in CGO_ALLOW_ENV_VARS:
                if os.environ.get(var) is not None:
                    run_command_args += ["-e", var]
        else:
            run_command_args += ["-e", "CGO_ENABLED=0"]
        if force_secure:
            run_command_args += ["-e", "CDXGEN_SECURE_MODE=true"]
        # Enabling license fetch will improve metadata such as tags and description
        # These will help with semantic reachability analysis
        if self.options.get("profile") not in ("generic",):
            # This would help create openapi spec file inside the reports directory
            run_command_args += ["-e", f"ATOM_TOOLS_WORK_DIR={image_output_dir}"]
            run_command_args += [
                "-e",
                f"ATOM_TOOLS_OPENAPI_FILENAME={project_type_list[0]}-openapi.json",
            ]
        run_command_args += ["-e", "CDXGEN_IN_CONTAINER=true"]
        # Do not repeat the sponsorship banner. Please note that cdxgen and depscan are separate projects, so they ideally require separate sponsorships.
        run_command_args += ["-e", "CDXGEN_NO_BANNER=true"]
        # Do not repeat the CDXGEN_DEBUG_MODE environment variable
        if os.getenv("SCAN_DEBUG_MODE") == "debug" and not os.getenv("CDXGEN_DEBUG_MODE"):
            run_command_args += ["-e", "CDXGEN_DEBUG_MODE=debug"]
        # Extra args like --platform=linux/amd64
        if os.getenv("DEPSCAN_DOCKER_ARGS"):
            run_command_args += os.getenv("DEPSCAN_DOCKER_ARGS", "").split(" ")
        # Setup volume mounts
        # Mount source directory as /app
        if os.path.isdir(self.source_dir):
            run_command_args += [
                "-v",
                f"{os.path.realpath(self.source_dir)}:{app_input_dir}:rw",
            ]
        else:
            run_command_args.append(self.source_dir)
        # The temp directory is mounted at /tmp, so the environment the
        # container sees must name /tmp: the host path cannot resolve inside
        # the container, and the image's cdxgen creates its temp directory
        # with a mkdir that cannot reach through the mount.
        run_command_args += ["-v", f"{self.cdxgen_temp_dir}:{container_tmp_dir}:rw"]
        run_command_args += ["-e", f"CDXGEN_TEMP_DIR={container_tmp_dir}"]
        run_command_args += [
            "-v",
            f"{output_dir}:{image_output_dir}:rw",
        ]
        # Mount the home directory as /root. Can be used for performance reasons.
        if self.options.get("insecure_mount_home"):
            run_command_args += ["-v", f"""{os.path.expanduser("~")}:/root:r"""]
        run_command_args.append(image_name)
        # output file mapped to the inside the image
        run_command_args += ["-o", f"{image_output_dir}/{output_file}"]
        # cdxgen args
        technique_args = [f"--technique {item}" for item in techniques]
        if technique_args:
            run_command_args += " ".join(technique_args).split()
        project_type_args = [f"-t {item}" for item in project_type_list]
        if project_type_args:
            run_command_args += " ".join(project_type_args).split()
        for excluded_type in self.options.get("exclude_types") or []:
            run_command_args += ["--exclude-type", str(excluded_type)]
        if self.options.get("spec_version"):
            run_command_args += ["--spec-version", str(self.options.get("spec_version"))]
        if self.options.get("profile"):
            run_command_args.append("--profile")
            run_command_args.append(self.options.get("profile", ""))
            if self.options.get("slices", True):
                set_slices_args(project_type_list, run_command_args, image_output_dir)
        # Build introspection report next to the BOM inside /reports, which
        # the volume mount maps onto the host reports directory.
        run_command_args += [
            "--introspect",
            "--introspect-json",
            f"{image_output_dir}/{output_file}.introspection.json",
        ]
        if len(lifecycles) == 1:
            run_command_args += ["--lifecycle", lifecycles[0]]
        if deep_enabled(self.options):
            run_command_args.append("--deep")
        if self.options.get("fail_on_error"):
            run_command_args.append("--fail-on-error")
        if self.options.get("cdxgen_args"):
            run_command_args += shlex.split(self.options.get("cdxgen_args", ""))
        return image_name, run_command_args

    def generate(self) -> BOMResult:
        """
        Generate the BOM with official container images.
        """
        container_command = get_env_options_value(self.options, "DOCKER_CMD", "docker")
        if not find_executable(container_command):
            return BOMResult(
                success=False,
                command_output=f"{container_command} command not found. Pass `--bom-engine CdxgenGenerator` to force depscan to use the local cdxgen CLI.",
            )
        image_name, run_command_args = self._container_run_cmd()
        # Should we pull the most recent image
        if needs_latest_image(image_name):
            if self.logger:
                self.logger.debug(f"Pulling the image {image_name} using {container_command}.")
            exec_tool([container_command, "pull", "--quiet", image_name], logger=self.logger)
        if self.logger:
            self.logger.debug(f"Executing {' '.join(run_command_args)}")
        bom_result = exec_tool(
            run_command_args, cwd=None, env=os.environ.copy(), logger=self.logger
        )
        if self.cdxgen_temp_dir:
            shutil.rmtree(self.cdxgen_temp_dir, ignore_errors=True)
        return bom_result
