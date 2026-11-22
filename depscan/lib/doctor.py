"""The doctor report: the tools, data and capabilities a scan can use here.

``depscan doctor`` prints this report as text or JSON and
:func:`depscan.api.doctor` returns it. The report never runs a scan, never
prompts and never downloads anything: every tool is located the same way a
scan locates it, each version is read with the tool's own version option
under a ten-second timeout, and the vulnerability database is inspected
read-only. A missing tool or a missing database is a reported state, not an
error, and the command exits 0 whenever it produced a report.

:data:`CAPABILITIES` is the only place that knows which capability needs
which tool or data. Analysis steps that want to check a requirement ask
:func:`requirement_missing` instead of re-deriving the mapping, so the table
stays the single source.
"""

import argparse
import json
import os
import platform as platform_module
import re
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from importlib import metadata, util
from typing import Any, Callable, Dict, List, Optional, Tuple

from vdb.lib import config as vdb_config
from vdb.lib import db as vdb_db

from depscan.lib.config import VDB_AGE_HOURS, read_vdb_image_marker
from xbom_lib import dosai as dosai_mod
from xbom_lib import golem as golem_mod
from xbom_lib import kosi as kosi_mod
from xbom_lib import rusi as rusi_mod
from xbom_lib.cdxgen import _VERSION_RE as _CDXGEN_VERSION_RE
from xbom_lib.cdxgen import (
    CDXGEN_MIN_VERSION,
    CDXGEN_NPM_PACKAGE,
    _version_tuple,
    cdxgen_min_version_tuple,
    find_cdxgen_cmd,
    resource_path,
)
from xbom_lib.plugins import (
    discover_plugins_dir,
    get_plugins_bin_target,
    is_in_plugins_dir,
    read_plugins_manifest,
)
from xbom_lib.process import (
    build_command,
    find_executable,
    find_in_interpreter_scripts,
    tool_env,
)

#: How long one tool's version probe may run.
PROBE_TIMEOUT_SEC = 10

#: How many tool lookups may probe at once. Each lookup waits on a
#: subprocess for most of its time, so this caps concurrent processes, not
#: threads doing work.
PROBE_WORKERS = 6

#: The version of the doctor report document itself.
SCHEMA_VERSION = "1"


def __getattr__(name: str):
    """The exit codes, resolved from the shared table on first use.

    The codes live in :data:`depscan.commands.output.EXIT_CODES`, and this
    module keeps no copy of them. The import cannot run while the module is
    being defined, in any placement: importing ``depscan.commands`` executes
    the verb registry, whose modules import :mod:`depscan.api`, which reads
    :class:`DoctorReport` from this module mid-flight. Deferring the import
    to the first attribute access keeps the module importable in any order
    and leaves the shared table the only place that knows the codes.
    """
    if name in ("EXIT_REQUIREMENT_NOT_MET", "EXIT_USAGE"):
        from depscan.commands import output

        return getattr(output, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


# Version strings are read from the tool's own output; each parser mirrors
# the parse the matching runner in xbom_lib uses.
_ATOM_VERSION_RE = re.compile(r"atom[,\s]+v?(\d+(?:\.\d+)+)", re.IGNORECASE)
_ATOM_TOOLS_VERSION_RE = re.compile(
    r"atom[- ]tools\s+\(version\s+v?(\d+(?:\.\d+)+)\)|"
    r"atom-tools\s+v?(\d+(?:\.\d+)+)",
    re.IGNORECASE,
)
_EDGA_VERSION_RE = re.compile(r"edga\s+v?(\d+(?:\.\d+)+)", re.IGNORECASE)
_GO_VERSION_RE = re.compile(r"\bgo(\d+(?:\.\d+)+)")
_DOSAI_BUILD_RE = re.compile(r"\+[^+\s]+")


def _parse_first_number(output: str) -> Optional[str]:
    """The first whitespace token that starts with a digit (golem, rusi)."""
    for token in output.split():
        if token and token[0].isdigit():
            return token
    return None


def _parse_dosai(output: str) -> Optional[str]:
    """dosai prints ``5.0.0+<sha>``; the build metadata is dropped."""
    token = _parse_first_number(output)
    if token is None:
        return None
    return _DOSAI_BUILD_RE.sub("", token, count=1)


def _parse_regex(regex) -> Callable[[str], Optional[str]]:
    """A version parser that searches with ``regex`` and takes the first
    non-empty group, so alternative patterns share one parser."""

    def parse(output: str) -> Optional[str]:
        found = regex.search(output)
        if not found:
            return None
        for group in found.groups():
            if group:
                return group
        return None

    return parse


def _parse_node(output: str) -> Optional[str]:
    """node prints ``v24.16.0``; anything else is not a version."""
    token = output.strip().split("\n")[0].strip()
    if token.startswith("v") and len(token) > 1:
        token = token[1:]
    return token if token[:1].isdigit() else None


@dataclass
class ToolStatus:
    """One tool, as the report shows it.

    ``path`` is null when the tool was not found and ``reason`` says why it
    is missing or unusable; a tool with a path and no reason satisfies a
    capability requirement. A version that cannot be read stays null without
    making the tool unusable, except cdxgen, which a scan refuses without a
    readable version and this report treats the same way.
    """

    name: str
    path: Optional[str] = None
    version: Optional[str] = None
    source: Optional[str] = None
    source_env: Optional[str] = None
    reason: Optional[str] = None
    min_version: Optional[str] = None
    plugin_platform: Optional[str] = None

    def __post_init__(self) -> None:
        # A finder may hand back a pathlib object; the report speaks strings.
        if self.path is not None:
            self.path = str(self.path)

    def to_dict(self) -> Dict[str, Any]:
        doc: Dict[str, Any] = {
            "name": self.name,
            "path": self.path,
            "version": self.version,
            "source": self.source,
            "reason": self.reason,
        }
        if self.source_env:
            doc["sourceEnv"] = self.source_env
        if self.min_version:
            doc["minVersion"] = self.min_version
        if self.plugin_platform:
            doc["platform"] = self.plugin_platform
        return doc

    @property
    def usable(self) -> bool:
        return bool(self.path) and self.reason is None


def _version_command(path: str, args: List[str]) -> List[str]:
    """The command line that asks ``path`` for its version."""
    return [path, *args]


def _run_version_probe_status(path: str, args: List[str]) -> Optional[Tuple[int, str]]:
    """Run ``path`` with ``args``; ``(exit code, combined output)`` or None
    when the command could not start, timed out or was refused."""
    path = str(path)
    try:
        cp = subprocess.run(
            build_command(_version_command(path, args)),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=tool_env(),
            shell=False,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=PROBE_TIMEOUT_SEC,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return cp.returncode, cp.stdout or ""


def _run_version_probe(path: str, args: List[str], require_success: bool = False) -> Optional[str]:
    """Run the tool's version option and return its combined output.

    Returns None when the command could not start, timed out or was refused
    by :func:`build_command`, and with ``require_success`` also when it
    exited non-zero. The scan's own checks for go and dotnet
    (``go_toolchain_available``, ``dotnet_runtime_available``) treat a
    non-zero exit as "cannot run", while its cdxgen probe reads the output
    whatever the exit code, so each caller picks the rule its scan uses.
    """
    result = _run_version_probe_status(path, args)
    if result is None:
        return None
    returncode, output = result
    if require_success and returncode != 0:
        return None
    return output


def _versioned_tool(
    name: str,
    path: Optional[str],
    parse: Callable[[str], Optional[str]],
    missing_reason: str,
    args: Optional[List[str]] = None,
    must_run: bool = False,
) -> ToolStatus:
    """Build the entry for a tool found on PATH: probe the version when found.

    With ``must_run``, a version command that fails or exits non-zero makes
    the tool unusable, matching the scan checks that run the same command
    before relying on the tool.
    """
    status = ToolStatus(name=name, path=path, source="path" if path else None)
    if not path:
        status.reason = missing_reason
        return status
    probe_args = args or ["--version"]
    output = _run_version_probe(path, probe_args, require_success=must_run)
    if output is None and must_run:
        status.reason = f"`{name} {' '.join(probe_args)}` failed, so a scan cannot use it"
    status.version = parse(output) if output else None
    return status


# --- tool discovery -----------------------------------------------------------


def _cdxgen_status() -> ToolStatus:
    """cdxgen, with the minimum version a scan enforces.

    Discovery follows ``find_cdxgen_cmd``: the ``CDXGEN_CMD`` environment
    variable, then PATH, then the binary bundled with the standalone
    packages. A version below ``CDXGEN_MIN_VERSION``, or none readable at
    all, makes the tool unusable with a reason, exactly as a scan refuses
    it.
    """
    status = ToolStatus(name="cdxgen", min_version=CDXGEN_MIN_VERSION)
    env_cmd = os.environ.get("CDXGEN_CMD", "").strip()
    from_env = bool(env_cmd) and find_executable(env_cmd) is not None
    local_bin = resource_path(
        os.path.join("local_bin", "cdxgen.exe" if sys.platform == "win32" else "cdxgen")
    )
    cmd = find_cdxgen_cmd() or find_cdxgen_cmd(False)
    if not cmd:
        status.reason = (
            f"not found on PATH and not bundled; install it with "
            f"`npm install -g {CDXGEN_NPM_PACKAGE}@{CDXGEN_MIN_VERSION}` or "
            "set CDXGEN_CMD"
        )
        return status
    path = str(cmd)
    # find_cdxgen_cmd leaves a bare command name when CDXGEN_CMD is unset and
    # cdxgen came from PATH; report and probe the resolved absolute path so
    # the plugins lookup below starts from a real location.
    path = find_executable(path) or path
    status.path = path
    if from_env:
        status.source = "env"
        status.source_env = "CDXGEN_CMD"
    elif os.path.abspath(path) == os.path.abspath(local_bin):
        status.source = "bundled-sea"
    else:
        status.source = "path"
    output = _run_version_probe(path, ["--version"])
    found = _CDXGEN_VERSION_RE.search(output) if output else None
    if found:
        status.version = found.group(1)
    if not status.version:
        status.reason = f"its version could not be read; {CDXGEN_MIN_VERSION} is the minimum"
    elif _version_tuple(status.version) < cdxgen_min_version_tuple():
        status.reason = f"cdxgen {status.version} is older than the {CDXGEN_MIN_VERSION} minimum"
    return status


#: The finder each plugin dep-scan invokes itself; the module lookup keeps
#: this table next to the tool names it maps.
_PLUGIN_FINDERS = {
    "golem": golem_mod.find_golem_binary,
    "rusi": rusi_mod.find_rusi_binary,
    "dosai": dosai_mod.find_dosai_binary,
    "kosi": kosi_mod.find_kosi_binary,
}


def _parse_kosi(output: str) -> Optional[str]:
    """The top-level ``version`` of the JSON object kosi prints.

    The object also carries nested ``version`` keys (the Kotlin compiler's,
    for one) and a native image may print JVM warnings around it, so a
    regular expression would take the wrong one. Every object that starts a
    line is decoded and only its own ``version`` key counts.
    """
    decoder = json.JSONDecoder()
    for match in re.finditer(r"^\s*\{", output, re.M):
        start = match.end() - 1
        try:
            document, _end = decoder.raw_decode(output, start)
        except ValueError:
            continue
        version = document.get("version") if isinstance(document, dict) else None
        if isinstance(version, str) and version:
            return version
    return None


def _plugin_tool_status(name: str, env_names: Tuple[str, ...]) -> ToolStatus:
    """golem, rusi, dosai or kosi: env override, PATH, then the plugins directory
    (``CDXGEN_PLUGINS_DIR`` or the one found beside the cdxgen install)."""
    status = ToolStatus(name=name)
    env_match = None
    for env_name in env_names:
        value = os.environ.get(env_name, "").strip()
        if value and os.path.isfile(value):
            env_match = (env_name, value)
            break
    path = _PLUGIN_FINDERS[name]()
    if not path:
        status.reason = (
            f"{name} was not found; set one of {', '.join(env_names)}, "
            "install it on PATH, point CDXGEN_PLUGINS_DIR at a cdxgen "
            "plugins directory or install @cdxgen/cdxgen-plugins-bin next to cdxgen"
        )
        return status
    status.path = path
    if env_match and path == env_match[1]:
        status.source = "env"
        status.source_env = env_match[0]
    elif is_in_plugins_dir(path):
        status.source = "plugins-dir"
    else:
        status.source = "path"
    if name == "dosai":
        probed = _run_version_probe_status(path, ["--version"])
        if probed is not None:
            failure = dosai_mod.dosai_launch_failure(probed[1], probed[0])
            if failure:
                # The output is the apphost's error, not a version.
                status.reason = failure
                return status
            status.version = _parse_dosai(probed[1]) if probed[1] else None
        output = None
    else:
        output = _run_version_probe(path, ["--version"])
    if output:
        if name == "kosi":
            # kosi prints a JSON object, {"version": "4.3.1", ...}, and a
            # native image may add JVM warnings around it.
            status.version = _parse_kosi(output)
        else:
            status.version = _parse_first_number(output)
    if name == "rusi":
        # A soft gate in the scan: an older rusi still runs, with a warning,
        # so the minimum is reported without making the tool unusable.
        status.min_version = rusi_mod.RUSI_MIN_VERSION
    return status


def _go_status() -> ToolStatus:
    """The Go toolchain golem loads packages with; version from ``go version``."""
    return _versioned_tool(
        "go",
        find_executable("go"),
        _parse_regex(_GO_VERSION_RE),
        "the Go toolchain golem needs was not found on PATH",
        args=["version"],
        must_run=True,
    )


def _dotnet_status(dosai_path: Optional[str]) -> ToolStatus:
    """The .NET runtime dosai needs, or the one a self-contained dosai bundles."""
    if dosai_mod._is_self_contained_binary(dosai_path):
        return ToolStatus(
            name="dotnet",
            path=dosai_path,
            source="bundled-runtime",
        )
    return _versioned_tool(
        "dotnet",
        find_executable("dotnet"),
        _parse_first_number,
        "the .NET runtime dosai needs was not found on PATH; a self-contained "
        "dosai binary (name containing '-full') would not need it",
        must_run=True,
    )


def _python_status() -> ToolStatus:
    return ToolStatus(
        name="python",
        path=sys.executable,
        version=platform_module.python_version(),
        source="runtime",
    )


def _python_package_version(name: str) -> str:
    """The installed version of a Python distribution."""
    return metadata.version(name)


def _blint_status() -> ToolStatus:
    """blint, which dep-scan uses as a Python library rather than a command."""
    status = ToolStatus(name="blint")
    try:
        status.version = _python_package_version("blint")
    except metadata.PackageNotFoundError:
        status.reason = (
            "the blint package is not installed; install depscan with the "
            "`all` extra or `pip install blint`"
        )
        return status
    try:
        spec = util.find_spec("blint")
    except (ImportError, ValueError):
        spec = None
    if spec and spec.origin:
        status.path = os.path.dirname(os.path.abspath(spec.origin))
    status.source = "library"
    return status


def _read_blintdb_location() -> Optional[str]:
    """The blintdb database path from blint's config, without importing blint.

    Importing ``blint`` executes blint.api and with it the binary analysis
    machinery (lief and friends) that only binary BOM generation needs, so
    every command paid that import just to learn where the database lives.
    blint's config module needs only the standard library and appdirs, so it
    is executed from its file instead. The module is registered in
    ``sys.modules`` only while it executes, because the dataclass machinery
    looks the defining module up there, and removed afterwards: a
    ``blint.config`` entry without its parent package would make a later
    ``import blint.config`` bind a package that lacks the attribute. When the
    standalone load fails for any reason, the plain import decides, and a
    blint that cannot be imported at all counts as not installed.
    """
    try:
        spec = util.find_spec("blint")
    except (ImportError, ValueError):
        return None
    if spec is None:
        return None
    if "blint.config" in sys.modules:
        return getattr(sys.modules["blint.config"], "BLINTDB_LOC", None)
    try:
        config_spec = util.spec_from_file_location(
            "blint.config", os.path.join(os.path.dirname(spec.origin or ""), "config.py")
        )
        if config_spec is None or config_spec.loader is None:
            raise ImportError("blint.config has no loader")
        module = util.module_from_spec(config_spec)
        sys.modules["blint.config"] = module
        try:
            config_spec.loader.exec_module(module)
        finally:
            sys.modules.pop("blint.config", None)
        return module.BLINTDB_LOC
    except Exception:
        try:
            from blint.config import BLINTDB_LOC
        except Exception:
            return None
        return BLINTDB_LOC


#: The blintdb path, resolved once at import time. blint.config reads the
#: environment when it executes, and the plain import this replaces resolved
#: the path during the startup import too, so the doctor report and the
#: manifest it feeds show the location the process started with however late
#: the report is collected.
_BLINTDB_LOC_AT_IMPORT = _read_blintdb_location()


def _blintdb_location() -> Optional[str]:
    """The blintdb path for this report: an already imported blint.config
    wins (tests stub it there), else the import-time resolution."""
    config = sys.modules.get("blint.config")
    if config is not None:
        return getattr(config, "BLINTDB_LOC", None)
    return _BLINTDB_LOC_AT_IMPORT


def _blintdb_status() -> ToolStatus:
    """The blintdb function-matching database blint downloads on demand.

    This report only looks: a missing database stays missing, because
    fetching one is a download this command never performs.
    """
    status = ToolStatus(name="blintdb")
    blintdb_loc = _blintdb_location()
    if blintdb_loc is None:
        status.reason = "blint is not installed, so blintdb cannot be used"
        return status
    if os.path.exists(blintdb_loc):
        status.path = blintdb_loc
        status.source = "library"
    else:
        status.reason = (
            f"no blintdb at {blintdb_loc}; blint downloads one on first use "
            "when USE_BLINTDB is set"
        )
    return status


# --- the cdxgen plugins directory ---------------------------------------------

#: Plugin binaries cdxgen invokes but depscan never resolves itself. golem,
#: rusi, dosai and kosi have their own entries because depscan runs them
#: directly.
#: The binary names follow cdxgen's ``plugin_binary_name`` scheme; osquery
#: ships a macOS app bundle and sourcekitten a plain name.
_PLUGIN_BINARY_NAMES = {
    "trivy": "trivy-cdxgen-{platform}-{arch}{extn}",
    "trustinspector": "trustinspector-cdxgen-{platform}-{arch}{extn}",
    "cdxrs": "cdxrs-{platform}-{arch}{extn}",
    "cdxui": "cdxui-{platform}-{arch}{extn}",
    "sourcekitten": "sourcekitten",
    "osquery": "osqueryi-{platform}-{arch}.app",
}


def _plugins_status(cdxgen_path: Optional[str], target: Dict[str, str]) -> List[ToolStatus]:
    """The plugins directory entry plus one entry per binary it ships.

    Versions come from ``plugins-manifest.json``, the record the plugins
    package writes when it builds; these binaries are cdxgen's to run, so
    this report never starts them.
    """
    discovered = discover_plugins_dir(cdxgen_path, target)
    plugins_dir = discovered.path if discovered else None
    source = discovered.source if discovered else None
    source_env = "CDXGEN_PLUGINS_DIR" if source == "env" else None
    entries = [
        ToolStatus(
            name="cdxgen-plugins",
            path=plugins_dir,
            source=source,
            source_env=source_env,
            plugin_platform=f"{target['platform']}-{target['arch']}",
        )
    ]
    if not plugins_dir:
        entries[0].reason = (
            "no cdxgen plugins directory was found; set CDXGEN_PLUGINS_DIR or "
            "install the @cdxgen/cdxgen-plugins-bin package next to cdxgen "
            "(a bundled cdxgen binary carries its own plugins inside itself)"
        )
        return entries
    entries[0].version = _manifest_package_version(plugins_dir)
    manifest_by_name = _manifest_plugins(plugins_dir)
    for tool, pattern in _PLUGIN_BINARY_NAMES.items():
        status = ToolStatus(
            name=tool,
            path=os.path.join(plugins_dir, tool, pattern.format(**target)),
            source="plugins-dir",
            plugin_platform=f"{target['platform']}-{target['arch']}",
        )
        manifest_entry = manifest_by_name.get(tool)
        if manifest_entry and manifest_entry.get("binaryPath"):
            relative = str(manifest_entry["binaryPath"]).replace("\\", "/")
            if relative.startswith("plugins/"):
                relative = relative[len("plugins/") :]
            status.path = os.path.join(plugins_dir, relative)
        exists = (
            os.path.isdir(status.path or "")
            if pattern.endswith(".app")
            else os.path.isfile(status.path or "")
        )
        if not exists:
            status.path = None
            status.reason = f"the {tool} plugin binary was not found in {plugins_dir}"
        elif manifest_entry and manifest_entry.get("version"):
            status.version = str(manifest_entry["version"])
        entries.append(status)
    return entries


def _manifest_package_version(plugins_dir: str) -> Optional[str]:
    package = read_plugins_manifest(plugins_dir).get("package") or {}
    version = str(package.get("version") or "")
    return version or None


def _manifest_plugins(plugins_dir: str) -> Dict[str, Dict[str, Any]]:
    return {
        str(plugin.get("name")): plugin
        for plugin in read_plugins_manifest(plugins_dir).get("plugins") or []
        if isinstance(plugin, dict) and plugin.get("name")
    }


# --- the vulnerability database -----------------------------------------------


def _vdb_flavor(marker: Optional[str]) -> Optional[str]:
    """The flavor of the recorded image ref, or of a shard-set marker."""
    if not marker:
        return None
    if marker.startswith("shards:"):
        return "shards"
    found = re.search(r"vdb7-([a-z0-9-]+):", marker)
    return found.group(1) if found else None


def _cve_metadata_rows() -> Optional[int]:
    """Rows in ``cve_metadata``, counted through a private read-only connection.

    The index file is opened with ``mode=ro`` on a connection of its own, so
    the inspection can never create, repair or populate the database and
    never touches the connections vdb keeps for a scan running in the same
    process. ``ensure_search_metadata`` is deliberately not reused: it fills
    the table when it is empty, which is a write. Returns None when the file
    is missing or cannot be read as a database with that table.
    """
    index_file = vdb_config.VDB_BIN_INDEX
    if not os.path.isfile(index_file):
        return None
    uri = Path(index_file).resolve().as_uri() + "?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True)
    except sqlite3.Error:
        return None
    try:
        row = conn.execute("SELECT count(*) FROM cve_metadata").fetchone()
        return int(row[0]) if row else 0
    except sqlite3.Error:
        return None
    finally:
        conn.close()


def _vdb_status() -> Dict[str, Any]:
    """The vulnerability database as the report shows it: read-only."""
    data_dir = vdb_config.DATA_DIR
    present = os.path.exists(vdb_config.VDB_BIN_FILE) or os.path.exists(vdb_config.VDB_BIN_INDEX)
    marker = read_vdb_image_marker(data_dir) if os.path.isdir(data_dir) else None
    db_metadata = None
    if present:
        try:
            db_metadata = vdb_db.get_db_file_metadata() or None
        except Exception:  # noqa: BLE001 - an unreadable metadata file is reported
            db_metadata = None
    created_utc = (db_metadata or {}).get("created_utc")
    age_hours = None
    stale = None
    if created_utc:
        try:
            created = datetime.fromisoformat(str(created_utc))
            age_hours = round((datetime.now(tz=timezone.utc) - created).total_seconds() / 3600, 1)
            stale = age_hours > VDB_AGE_HOURS
        except ValueError:
            created_utc = None
    cve_metadata_rows = _cve_metadata_rows() if present else None
    extended_present = bool(cve_metadata_rows) if cve_metadata_rows is not None else None
    if extended_present is None and db_metadata:
        extended_present = bool(db_metadata.get("include_metadata"))
    try:
        from vdb.lib import db_cmd

        store = db_cmd.store_status(vdb_config.VDB_SHARDS_DIR)
        shards_present = [
            {"name": str(shard.get("name")), "ageDays": shard.get("age_days")}
            for shard in store.get("shards") or []
            if shard.get("name")
        ]
    except Exception:  # noqa: BLE001 - an unreadable store is reported as empty
        shards_present = []
    return {
        "present": present,
        "directory": data_dir,
        "image": marker,
        "flavor": _vdb_flavor(marker),
        "shards": {
            "enabled": os.getenv("VDB_USE_SHARDS", "") in ("true", "1"),
            "present": shards_present,
        },
        "createdUtc": created_utc,
        "ageHours": age_hours,
        "stale": stale,
        "maxAgeHours": VDB_AGE_HOURS,
        "cveDataCount": (db_metadata or {}).get("cve_data_count"),
        "cveIndexCount": (db_metadata or {}).get("cve_index_count"),
        "extendedMetadataPresent": extended_present,
        "cveMetadataRows": cve_metadata_rows,
    }


# --- capabilities --------------------------------------------------------------


def issue_url(number: int) -> str:
    """The URL of a dep-scan issue."""
    return f"https://github.com/owasp-dep-scan/dep-scan/issues/{number}"


#: The reachability analyzers a scan can run, each with the capability it
#: satisfies. The requirements themselves stay in :data:`CAPABILITIES`; this
#: names the analyzer rows the manifest records, so a scan that cannot run
#: one analyzer names the capability and the doctor's reason.
ANALYZER_CAPABILITIES = {
    "atom": "reachability",
    "rusi": "reachability:rust",
    "golem": "reachability:go",
    "dosai": "reachability:dotnet",
    "kosi": "reachability:kotlin",
}


def requirement_reason(
    requirement: str, tools: Dict[str, ToolStatus], data: Dict[str, Any]
) -> str:
    """The doctor's human reason one requirement is not satisfied.

    Satisfied requirements have no reason, so callers ask this only after
    :func:`requirement_missing` returned the name.
    """
    if requirement.startswith("tool:"):
        status = tools.get(requirement[len("tool:") :])
        if status is None:
            return f"{requirement} is not a tool this version knows"
        if status.reason:
            return f"{status.name}: {status.reason}"
        return f"{status.name} has no readable version"
    if requirement == "data:vdb":
        vdb = data.get("vulnerabilityDatabase") or {}
        if not vdb.get("present"):
            return "the vulnerability database is not present"
        return "the vulnerability database has no searchable rows"
    if requirement.startswith("python:"):
        module = requirement[len("python:") :]
        return (
            f"the {module} module is not installed; install dep-scan with "
            f"the matching extra: `pip install owasp-depscan[{module}]`"
        )
    return f"{requirement} is not available"


def capability_unavailable_reason(
    name: str,
    tools: Dict[str, ToolStatus],
    data: Dict[str, Any],
    skip_requirements: Tuple[str, ...] = (),
) -> Optional[str]:
    """Why a capability cannot run here, or None when it can.

    Reads :data:`CAPABILITIES`, the single source of what each capability
    needs; callers never keep their own copy of the requirements. The reason
    names the capability and, for every unsatisfied requirement, the same
    message the doctor report prints for the tool or data behind it. An
    unknown name and a capability this version does not implement are
    reported as reasons too, because both mean the step cannot run.

    ``skip_requirements`` names requirements the caller's scan cannot fail
    on. The capability gate passes :data:`BOM_PRODUCER_REQUIREMENTS` for a
    run whose every target is a BOM file or BOM directory. The requirements
    stay in :data:`CAPABILITIES`; this argument only scopes them to the
    caller's targets.
    """
    spec = next((spec for spec in CAPABILITIES if spec.name == name), None)
    if spec is None:
        return f"{name} is not a capability this version knows"
    if not spec.implemented:
        return f"{name} is not implemented in this version ({issue_url(spec.issue)})"
    missing = [
        r
        for r in spec.requirements
        if r not in skip_requirements and requirement_missing(r, tools, data)
    ]
    if not missing:
        return None
    detail = "; ".join(f"{r} ({requirement_reason(r, tools, data)})" for r in missing)
    return f"capability {name} is unavailable: {detail}"


@dataclass(frozen=True)
class CapabilitySpec:
    """One capability row of :data:`CAPABILITIES`.

    A capability this dep-scan version does not implement carries no
    requirements: it cannot run here whatever tools are installed, and
    inventing requirements for it would promise checks that do not exist.
    ``issue`` is the dep-scan issue that designs or tracks the capability.
    """

    name: str
    description: str
    issue: int
    requirements: Tuple[str, ...] = ()
    implemented: bool = False


#: The requirements on the tools that run only while dep-scan produces a
#: BOM: cdxgen, and the language plugins and runtimes it and dep-scan's
#: BOM step drive to write reachables slices. A scan of a BOM file or BOM
#: directory produces no BOM, so none of these runs; the scan reads any
#: slices already next to the inventory and records reachability as not
#: assessed where there are none. The capability gate drops these for such
#: scans instead of refusing over a tool the scan would never call.
BOM_PRODUCER_REQUIREMENTS: Tuple[str, ...] = (
    "tool:cdxgen",
    "tool:golem",
    "tool:go",
    "tool:rusi",
    "tool:dosai",
    "tool:dotnet",
    "tool:kosi",
)


#: The single source for what each capability needs. Requirement names are
#: ``tool:<name>`` matching a tools entry, ``data:vdb`` for the
#: vulnerability database, or ``python:<module>`` for an importable Python
#: module this interpreter must have. Later analysis steps read this table
#: through :func:`requirement_missing` rather than keeping their own copy.
CAPABILITIES: Tuple[CapabilitySpec, ...] = (
    CapabilitySpec(
        name="vulnerabilities",
        description="Match components against the vulnerability database.",
        issue=592,
        requirements=("data:vdb",),
        implemented=True,
    ),
    CapabilitySpec(
        name="reachability",
        description="Reachability from the slices cdxgen and atom produce.",
        issue=592,
        requirements=("tool:cdxgen",),
        implemented=True,
    ),
    CapabilitySpec(
        name="reachability:rust",
        description="Rust reachability through the rusi plugin.",
        issue=603,
        requirements=("tool:cdxgen", "tool:rusi"),
        implemented=True,
    ),
    CapabilitySpec(
        name="reachability:go",
        description="Go reachability through the golem plugin and the Go toolchain.",
        issue=603,
        requirements=("tool:cdxgen", "tool:golem", "tool:go"),
        implemented=True,
    ),
    CapabilitySpec(
        name="reachability:kotlin",
        description="Kotlin and JVM reachability through the kosi plugin (syntax backend, no build).",
        issue=602,
        requirements=("tool:kosi",),
        implemented=True,
    ),
    CapabilitySpec(
        name="reachability:dotnet",
        description=".NET reachability through the dosai plugin and the .NET runtime.",
        issue=601,
        requirements=("tool:cdxgen", "tool:dosai", "tool:dotnet"),
        implemented=True,
    ),
    CapabilitySpec(
        name="license",
        description="License risk from the licence data vendored with dep-scan.",
        issue=592,
        requirements=(),
        implemented=True,
    ),
    CapabilitySpec(
        name="mcp",
        description="The MCP server over stdio (`depscan mcp`) for agents.",
        issue=631,
        requirements=("python:mcp",),
        implemented=True,
    ),
    CapabilitySpec(
        name="memory-safety",
        description="Memory-safety findings for C and C++ sources.",
        issue=613,
    ),
    CapabilitySpec(
        name="memory-safety:c",
        description="Memory-safety analysis of C sources with atom memory-safety.",
        issue=613,
    ),
    CapabilitySpec(
        name="mobile",
        description="Android and iOS app analysis.",
        issue=625,
    ),
    CapabilitySpec(
        name="mobile:android",
        description="Android app analysis with blint, atom and kosi.",
        issue=625,
    ),
    CapabilitySpec(
        name="supply-chain",
        description="Package risk audit and malware advisory reporting.",
        issue=606,
        implemented=True,
    ),
    CapabilitySpec(
        name="binary",
        description="Binary analysis with blint.",
        issue=620,
        requirements=("tool:blint",),
        implemented=True,
    ),
    CapabilitySpec(
        name="code",
        description="Findings from the analyzers' own code rules.",
        issue=605,
    ),
    CapabilitySpec(
        name="crypto",
        description="Crypto findings from the cbom-security audit pack.",
        issue=606,
    ),
)


@dataclass
class CapabilityStatus:
    """One evaluated capability row."""

    name: str
    status: str
    requirements: Tuple[str, ...]
    issue: int
    description: str
    missing: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "missing": self.missing,
            "requirements": list(self.requirements),
            "issue": issue_url(self.issue),
            "description": self.description,
        }


def requirement_missing(
    requirement: str, tools: Dict[str, ToolStatus], data: Dict[str, Any]
) -> Optional[str]:
    """Whether one requirement is satisfied; the requirement name when not.

    A tool requirement needs a tools entry with a path and no reason. The
    database requirement needs a present database with index rows; a present
    database whose row count is unknown does not satisfy it, because a scan
    cannot know it is not empty. A ``python:<module>`` requirement needs the
    module to be importable in this interpreter, looked up with
    :func:`importlib.util.find_spec` without importing it.
    """
    if requirement.startswith("tool:"):
        status = tools.get(requirement[len("tool:") :])
        if status is None or not status.usable:
            return requirement
        return None
    if requirement == "data:vdb":
        vdb = data.get("vulnerabilityDatabase") or {}
        if not vdb.get("present") or not vdb.get("cveIndexCount"):
            return requirement
        return None
    if requirement.startswith("python:"):
        module = requirement[len("python:") :]
        try:
            found = util.find_spec(module)
        except (ImportError, ValueError):
            found = None
        if found is None:
            return requirement
        return None
    return requirement


def _evaluate_capabilities(
    tools: Dict[str, ToolStatus], data: Dict[str, Any]
) -> List[CapabilityStatus]:
    statuses = []
    for spec in CAPABILITIES:
        if not spec.implemented:
            statuses.append(
                CapabilityStatus(
                    name=spec.name,
                    status="not-implemented",
                    requirements=spec.requirements,
                    issue=spec.issue,
                    description=spec.description,
                )
            )
            continue
        missing = [
            requirement
            for requirement in spec.requirements
            if requirement_missing(requirement, tools, data)
        ]
        statuses.append(
            CapabilityStatus(
                name=spec.name,
                status="unavailable" if missing else "available",
                requirements=spec.requirements,
                issue=spec.issue,
                description=spec.description,
                missing=missing,
            )
        )
    return statuses


# --- the report ----------------------------------------------------------------


def _depscan_version() -> str:
    try:
        return _python_package_version("owasp-depscan")
    except metadata.PackageNotFoundError:
        return "unknown"


def _platform_status(target: Dict[str, str]) -> Dict[str, Any]:
    libc = None
    if sys.platform == "linux":
        libc = "musl" if target["platform"] == "linuxmusl" else "glibc"
    return {
        "os": sys.platform,
        "arch": platform_module.machine(),
        "libc": libc,
    }


def build_tools() -> Tuple[List[ToolStatus], Dict[str, ToolStatus]]:
    """Locate every tool; returns the entries in report order and by name.

    Each version probe spends its time waiting on a subprocess and the tool
    lookups are independent of one another, so they run on a small thread
    pool and their results are assembled in report order afterwards. Two
    lookups need another tool's resolved path first: the cdxgen plugins
    directory follows cdxgen, and the .NET runtime entry follows dosai,
    whose self-contained binary bundles a runtime of its own.
    """
    with ThreadPoolExecutor(max_workers=PROBE_WORKERS) as pool:
        cdxgen = pool.submit(_cdxgen_status)
        atom = pool.submit(
            _versioned_tool,
            "atom",
            find_executable("atom"),
            _parse_regex(_ATOM_VERSION_RE),
            "atom was not found on PATH; cdxgen runs the atom it installs "
            "itself, and dep-scan calls atom directly only for the "
            "memory-safety check",
        )
        atom_tools = pool.submit(
            _versioned_tool,
            "atom-tools",
            find_executable("atom-tools") or find_in_interpreter_scripts("atom-tools"),
            _parse_regex(_ATOM_TOOLS_VERSION_RE),
            "atom-tools was not found on PATH or next to the Python that runs "
            "dep-scan; install it with `pip install atom-tools`",
        )
        edga = pool.submit(
            _versioned_tool,
            "edga",
            find_executable("edga"),
            _parse_regex(_EDGA_VERSION_RE),
            "edga was not found on PATH; it ships in atom's container images "
            "and improves the C and C++ front end",
        )
        node = pool.submit(
            _versioned_tool,
            "node",
            find_executable("node"),
            _parse_node,
            "node was not found on PATH; cdxgen needs it unless it runs from a bundled binary",
        )
        golem = pool.submit(
            _plugin_tool_status, "golem", (golem_mod.GOLEM_CMD_ENV, golem_mod.GOLEM_BINARY_ENV)
        )
        rusi = pool.submit(
            _plugin_tool_status, "rusi", (rusi_mod.RUSI_CMD_ENV, rusi_mod.RUSI_BINARY_ENV)
        )
        dosai = pool.submit(
            _plugin_tool_status, "dosai", (dosai_mod.DOSAI_CMD_ENV, dosai_mod.DOSAI_BINARY_ENV)
        )
        kosi = pool.submit(
            _plugin_tool_status, "kosi", (kosi_mod.KOSI_CMD_ENV, kosi_mod.KOSI_BINARY_ENV)
        )
        go = pool.submit(_go_status)
        cdxgen_status = cdxgen.result()
        plugins = pool.submit(_plugins_status, cdxgen_status.path, get_plugins_bin_target())
        dosai_status = dosai.result()
        dotnet = pool.submit(_dotnet_status, dosai_status.path)
        entries = [
            cdxgen_status,
            atom.result(),
            atom_tools.result(),
            edga.result(),
            node.result(),
            _python_status(),
            *plugins.result(),
            golem.result(),
            go.result(),
            rusi.result(),
            dosai_status,
            dotnet.result(),
            kosi.result(),
            _blint_status(),
            _blintdb_status(),
        ]
    return entries, {entry.name: entry for entry in entries}


@dataclass
class DoctorReport:
    """The doctor report: platform, tools, data and capabilities."""

    schema_version: str
    depscan_version: str
    platform: Dict[str, Any]
    tools: List[ToolStatus]
    data: Dict[str, Any]
    capabilities: List[CapabilityStatus]

    def tools_by_name(self) -> Dict[str, ToolStatus]:
        """The tool entries by name, as the capability checks look them up."""
        return {tool.name: tool for tool in self.tools}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schemaVersion": self.schema_version,
            "depscanVersion": self.depscan_version,
            "platform": self.platform,
            "tools": [tool.to_dict() for tool in self.tools],
            "data": self.data,
            "capabilities": [capability.to_dict() for capability in self.capabilities],
        }

    def to_text(self) -> str:
        """The text rendering ``depscan doctor`` prints."""
        lines = [
            "dep-scan doctor",
            f"  depscan {self.depscan_version} on {self.platform['os']}/"
            f"{self.platform['arch']}"
            + (f" ({self.platform['libc']})" if self.platform.get("libc") else ""),
            "",
            "Tools",
        ]
        name_width = max(len(tool.name) for tool in self.tools)
        version_width = max(len(tool.version or "version unknown") for tool in self.tools)
        for tool in self.tools:
            where = tool.source or "not found"
            if tool.source_env:
                where = f"{where}, {tool.source_env}"
            version = tool.version or "version unknown"
            lines.append(
                f"  {tool.name:<{name_width}}  {version:<{version_width}}  "
                f"{tool.path or '-'} ({where})"
            )
            if (
                tool.version
                and tool.min_version
                and not tool.reason
                and _version_tuple(tool.version) < _version_tuple(tool.min_version)
            ):
                lines.append(f"    older than {tool.min_version}; a scan warns and still runs it")
            if tool.reason:
                lines.append(f"    {tool.reason}")
        vdb = self.data.get("vulnerabilityDatabase") or {}
        lines += ["", "Data", "  vulnerability database"]
        if vdb.get("present"):
            detail = [f"present at {vdb.get('directory')}"]
            if vdb.get("image"):
                detail.append(f"image {vdb['image']}")
            if vdb.get("flavor"):
                detail.append(f"flavor {vdb['flavor']}")
            lines.append("    " + ", ".join(detail))
            if vdb.get("ageHours") is not None:
                stale = ""
                if vdb.get("stale"):
                    stale = f", stale (VDB_AGE_HOURS is {vdb.get('maxAgeHours')})"
                lines.append(
                    f"    {vdb['ageHours']} hours old{stale}, "
                    f"{vdb.get('cveDataCount')} data rows, "
                    f"{vdb.get('cveIndexCount')} index rows"
                )
            extended = vdb.get("extendedMetadataPresent")
            if extended is None:
                extended_text = "unknown"
            else:
                extended_text = "present" if extended else "absent"
            lines.append(
                f"    extended metadata: {extended_text} "
                f"({vdb.get('cveMetadataRows')} rows in cve_metadata)"
            )
            shards = vdb.get("shards") or {}
            names = ", ".join(str(shard.get("name")) for shard in shards.get("present") or [])
            lines.append(
                f"    shards: {'on' if shards.get('enabled') else 'off'}"
                + (f"; present: {names}" if names else "")
            )
        else:
            lines.append(
                f"    not present at {vdb.get('directory')}; a scan fetches one "
                "with `depscan vdb download` or 'vdb db refresh full'"
            )
        lines += ["", "Capabilities"]
        capability_width = max(len(capability.name) for capability in self.capabilities)
        for capability in self.capabilities:
            if capability.status == "available":
                note = "available"
            elif capability.status == "unavailable":
                note = "unavailable: " + ", ".join(capability.missing)
            else:
                note = f"not implemented yet ({issue_url(capability.issue)})"
            lines.append(f"  {capability.name:<{capability_width}}  {note}")
        return "\n".join(lines)


def doctor() -> DoctorReport:
    """Collect the report: locate the tools, read the data, evaluate the table."""
    target = get_plugins_bin_target()
    tools, tools_by_name = build_tools()
    data = {"vulnerabilityDatabase": _vdb_status()}
    return DoctorReport(
        schema_version=SCHEMA_VERSION,
        depscan_version=_depscan_version(),
        platform=_platform_status(target),
        tools=tools,
        data=data,
        capabilities=_evaluate_capabilities(tools_by_name, data),
    )


def capability_table_markdown() -> str:
    """:data:`CAPABILITIES` as the markdown table the documentation embeds.

    The documentation page carries the output of this function, so the
    published table cannot drift from the code.
    """
    lines = [
        "| Capability | What it is | What it needs in this version |",
        "| --- | --- | --- |",
    ]
    for spec in CAPABILITIES:
        if spec.implemented:
            needs = ", ".join(f"`{requirement}`" for requirement in spec.requirements)
            if not needs:
                needs = "nothing external"
        else:
            needs = f"not implemented yet ([dep-scan#{spec.issue}]({issue_url(spec.issue)}))"
        lines.append(f"| `{spec.name}` | {spec.description} | {needs} |")
    return "\n".join(lines)


# --- the command ---------------------------------------------------------------


def parse_doctor_args(argv: List[str]) -> argparse.Namespace:
    """Parse the arguments after ``doctor``."""
    parser = argparse.ArgumentParser(
        prog="depscan doctor",
        description="Report the tools, data and capabilities a scan can use here.",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="text for people, json for scripts (default: text)",
    )
    parser.add_argument(
        "--require",
        action="append",
        default=[],
        metavar="CAPABILITY",
        help=(
            "exit with code 4 unless these capabilities are available; "
            "comma-separated or repeated, for example "
            "--require vulnerabilities,reachability:go"
        ),
    )
    args = parser.parse_args(argv)
    args.require = [
        name.strip() for value in args.require for name in value.split(",") if name.strip()
    ]
    return args


def unmet_requirements(report: DoctorReport, required: List[str]) -> List[str]:
    """The required capabilities that are not available in ``report``."""
    status = {capability.name: capability.status for capability in report.capabilities}
    return [name for name in required if status.get(name) != "available"]


def run_doctor_command(argv: List[str]) -> int:
    """Run the doctor command; returns the process exit code.

    The report goes to stdout in the chosen format and messages go to
    stderr. The command never prompts and never downloads. It exits 0
    whenever it produced a report, even when tools are missing, unless
    ``--require`` names a capability that is not available here (exit 4),
    which lets an image build fail when it lacks a capability it is meant to
    have. An unknown capability name is a usage error (exit 2).

    In json format stdout carries exactly one document whatever the exit
    code: a failure writes the error document instead of the report, with
    the unknown capability names or the unmet requirement names in
    ``details``, and the same message on stderr as text. The text format
    still prints the report next to the message when ``--require`` fails.
    """
    from depscan.commands.output import (
        EXIT_REQUIREMENT_NOT_MET,
        EXIT_USAGE,
        print_error_document,
        print_json_document,
    )

    args = parse_doctor_args(argv)
    known = {spec.name for spec in CAPABILITIES}
    unknown = [name for name in args.require if name not in known]
    if unknown:
        message = (
            f"depscan doctor: unknown capability {', '.join(unknown)}; "
            f"known capabilities: {', '.join(sorted(known))}"
        )
        if args.format == "json":
            print_error_document(
                EXIT_USAGE, "doctor", message, {"unknownCapabilities": list(unknown)}
            )
        else:
            print(message, file=sys.stderr)
        return EXIT_USAGE
    report = doctor()
    unmet = unmet_requirements(report, args.require)
    if unmet:
        message = f"depscan doctor: required capabilities not available: {', '.join(unmet)}"
        if args.format == "json":
            print_error_document(
                EXIT_REQUIREMENT_NOT_MET, "doctor", message, {"unmet": list(unmet)}
            )
        else:
            print(report.to_text())
            print(message, file=sys.stderr)
        return EXIT_REQUIREMENT_NOT_MET
    if args.format == "json":
        print_json_document(report.to_dict())
    else:
        print(report.to_text())
    return 0
