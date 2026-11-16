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
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from importlib import metadata, util
from typing import Any, Callable, Dict, List, Optional, Tuple

from vdb.lib import config as vdb_config
from vdb.lib import db as vdb_db

from depscan.lib.config import VDB_AGE_HOURS, read_vdb_image_marker
from xbom_lib import dosai as dosai_mod
from xbom_lib import golem as golem_mod
from xbom_lib import rusi as rusi_mod
from xbom_lib.cdxgen import (
    CDXGEN_MIN_VERSION,
    CDXGEN_NPM_PACKAGE,
    _version_tuple,
    cdxgen_min_version_tuple,
    find_cdxgen_cmd,
    resource_path,
)
from xbom_lib.plugins import get_plugins_bin_target
from xbom_lib.process import build_command, find_executable, tool_env

#: How long one tool's version probe may run.
PROBE_TIMEOUT_SEC = 10

#: The version of the doctor report document itself.
SCHEMA_VERSION = "1"

# Version strings are read from the tool's own output; each parser mirrors
# the parse the matching runner in xbom_lib uses.
_CDXGEN_VERSION_RE = re.compile(
    r"CycloneDX\s+Generator\s+v?(\d+(?:\.\d+)+(?:-[0-9A-Za-z.]+)?)"
)
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


def _looks_like_python_script(path: str) -> bool:
    """Whether ``path`` is a Python script rather than a native binary.

    An absolute ``.py`` path, or any absolute path whose first line is a
    Python shebang, runs with the current interpreter. The test suite ships
    its fake tools as Python scripts and on Windows a Python script cannot
    be started directly, so the probe recognises them; an embedder can use
    the same trick to point an override at a Python shim. Relative paths are
    never inspected or run through the interpreter, because they resolve
    against the working directory and that is the scanned project during a
    scan.
    """
    if not os.path.isabs(path):
        return False
    if path.endswith(".py"):
        return True
    try:
        with open(path, encoding="utf-8", errors="replace") as fp:
            first = fp.readline(200)
    except OSError:
        return False
    return first.startswith("#!") and "python" in first


def _version_command(path: str, args: List[str]) -> List[str]:
    if _looks_like_python_script(path):
        return [sys.executable, path, *args]
    return [path, *args]


def _run_version_probe(path: str, args: List[str]) -> Optional[str]:
    """Run the tool's version option and return its combined output.

    Returns None when the command could not start, timed out or was refused
    by :func:`build_command`; callers report a null version in that case.
    """
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
    return cp.stdout or ""


def _versioned_tool(
    name: str,
    path: Optional[str],
    parse: Callable[[str], Optional[str]],
    missing_reason: str,
    args: Optional[List[str]] = None,
) -> ToolStatus:
    """Build the entry for a tool found on PATH: probe the version when found."""
    status = ToolStatus(name=name, path=path, source="path" if path else None)
    if not path:
        status.reason = missing_reason
        return status
    output = _run_version_probe(path, args or ["--version"])
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
        os.path.join(
            "local_bin", "cdxgen.exe" if sys.platform == "win32" else "cdxgen"
        )
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
        status.reason = (
            f"its version could not be read; {CDXGEN_MIN_VERSION} is the minimum"
        )
    elif _version_tuple(status.version) < cdxgen_min_version_tuple():
        status.reason = (
            f"cdxgen {status.version} is older than the "
            f"{CDXGEN_MIN_VERSION} minimum"
        )
    return status


#: The finder each plugin dep-scan invokes itself; the module lookup keeps
#: this table next to the tool names it maps.
_PLUGIN_FINDERS = {
    "golem": golem_mod.find_golem_binary,
    "rusi": rusi_mod.find_rusi_binary,
    "dosai": dosai_mod.find_dosai_binary,
}


def _plugin_tool_status(name: str, env_names: Tuple[str, ...]) -> ToolStatus:
    """golem, rusi or dosai: env override, PATH, then the plugins directory."""
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
            "install it on PATH or point CDXGEN_PLUGINS_DIR at a cdxgen "
            "plugins directory"
        )
        return status
    status.path = path
    plugins_dir = os.environ.get("CDXGEN_PLUGINS_DIR", "").strip()
    if env_match and path == env_match[1]:
        status.source = "env"
        status.source_env = env_match[0]
    elif plugins_dir and os.path.normpath(path).startswith(
        os.path.join(os.path.normpath(plugins_dir), "")
    ):
        status.source = "plugins-dir"
    else:
        status.source = "path"
    output = _run_version_probe(path, ["--version"])
    if output:
        status.version = (
            _parse_dosai(output) if name == "dosai" else _parse_first_number(output)
        )
    return status


def _go_status() -> ToolStatus:
    """The Go toolchain golem loads packages with; version from ``go version``."""
    return _versioned_tool(
        "go",
        find_executable("go"),
        _parse_regex(_GO_VERSION_RE),
        "the Go toolchain golem needs was not found on PATH",
        args=["version"],
    )


def _dotnet_status(dosai_path: Optional[str]) -> ToolStatus:
    """The .NET runtime dosai needs, or the one a self-contained dosai bundles."""
    if dosai_path and dosai_mod._SELF_CONTAINED_HINT in os.path.basename(dosai_path):
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


def _blintdb_status() -> ToolStatus:
    """The blintdb function-matching database blint downloads on demand.

    This report only looks: a missing database stays missing, because
    fetching one is a download this command never performs.
    """
    status = ToolStatus(name="blintdb")
    try:
        from blint.config import BLINTDB_LOC
    except ImportError:
        status.reason = "blint is not installed, so blintdb cannot be used"
        return status
    if os.path.exists(BLINTDB_LOC):
        status.path = BLINTDB_LOC
        status.source = "library"
    else:
        status.reason = (
            f"no blintdb at {BLINTDB_LOC}; blint downloads one on first use "
            "when USE_BLINTDB is set"
        )
    return status


# --- the cdxgen plugins directory ---------------------------------------------

#: Plugin binaries cdxgen invokes but depscan never resolves itself. golem,
#: rusi and dosai have their own entries because depscan runs them directly.
#: The binary names follow cdxgen's ``plugin_binary_name`` scheme; osquery
#: ships a macOS app bundle and sourcekitten a plain name.
_PLUGIN_BINARY_NAMES = {
    "trivy": "trivy-cdxgen-{platform}-{arch}{extn}",
    "trustinspector": "trustinspector-cdxgen-{platform}-{arch}{extn}",
    "kosi": "kosi-{platform}-{arch}{extn}",
    "cdxrs": "cdxrs-{platform}-{arch}{extn}",
    "cdxui": "cdxui-{platform}-{arch}{extn}",
    "sourcekitten": "sourcekitten",
    "osquery": "osqueryi-{platform}-{arch}.app",
}

#: cdxgen's own usability rule for a plugins directory: a manifest, or at
#: least one of the plugin subdirectories it knows.
_PLUGINS_DIR_TOOLS = (
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


def _candidate_plugins_dirs(
    cdxgen_path: Optional[str], target: Dict[str, str]
) -> List[str]:
    """Every plugins directory a scan could use, best candidate first.

    cdxgen honours ``CDXGEN_PLUGINS_DIR``, then a ``plugins`` directory next
    to its own install (the bundled caxa binary), then the npm package
    ``@cdxgen/cdxgen-plugins-bin-<platform>-<arch>`` installed beside it.
    The last two are probed by walking up from the resolved cdxgen command.
    """
    candidates = []
    env_dir = os.environ.get("CDXGEN_PLUGINS_DIR", "").strip()
    if env_dir and os.path.isdir(env_dir):
        candidates.append(env_dir)
    if cdxgen_path:
        ancestor = os.path.dirname(os.path.realpath(cdxgen_path))
        for _ in range(6):
            candidates.append(os.path.join(ancestor, "plugins"))
            candidates.append(
                os.path.join(
                    ancestor,
                    "node_modules",
                    "@cdxgen",
                    f"cdxgen-plugins-bin-{target['platform']}-{target['arch']}",
                    "plugins",
                )
            )
            ancestor = os.path.dirname(ancestor)
    unique = []
    for candidate in candidates:
        key = os.path.normpath(candidate)
        if key not in [os.path.normpath(seen) for seen in unique]:
            unique.append(candidate)
    return unique


def _usable_plugins_dir(path: str) -> bool:
    if not os.path.isdir(path):
        return False
    if os.path.isfile(os.path.join(path, "plugins-manifest.json")):
        return True
    return any(os.path.isdir(os.path.join(path, tool)) for tool in _PLUGINS_DIR_TOOLS)


def _read_plugins_manifest(plugins_dir: str) -> Dict[str, Any]:
    try:
        with open(
            os.path.join(plugins_dir, "plugins-manifest.json"), encoding="utf-8"
        ) as fp:
            manifest = json.load(fp)
    except (OSError, ValueError):
        return {}
    return manifest if isinstance(manifest, dict) else {}


def _plugins_status(
    cdxgen_path: Optional[str], target: Dict[str, str]
) -> List[ToolStatus]:
    """The plugins directory entry plus one entry per binary it ships.

    Versions come from ``plugins-manifest.json``, the record the plugins
    package writes when it builds; these binaries are cdxgen's to run, so
    this report never starts them.
    """
    plugins_dir = None
    source = None
    source_env = None
    for candidate in _candidate_plugins_dirs(cdxgen_path, target):
        if _usable_plugins_dir(candidate):
            plugins_dir = candidate
            if candidate == os.environ.get("CDXGEN_PLUGINS_DIR", "").strip():
                source = "env"
                source_env = "CDXGEN_PLUGINS_DIR"
            elif os.path.isfile(os.path.join(candidate, os.pardir, "package.json")):
                source = "cdxgen-install"
            else:
                source = "bundled-sea"
            break
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
    package = _read_plugins_manifest(plugins_dir).get("package") or {}
    version = str(package.get("version") or "")
    return version or None


def _manifest_plugins(plugins_dir: str) -> Dict[str, Dict[str, Any]]:
    return {
        str(plugin.get("name")): plugin
        for plugin in _read_plugins_manifest(plugins_dir).get("plugins") or []
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
    """Rows in ``cve_metadata`` through a read-only connection, or None.

    The database is opened read-only and only when both files exist, so this
    inspection can never create or repair one. ``ensure_search_metadata`` is
    deliberately not reused: it populates the table when it is empty, which
    is a write this report must not make.
    """
    if not (
        os.path.exists(vdb_config.VDB_BIN_FILE)
        and os.path.exists(vdb_config.VDB_BIN_INDEX)
    ):
        return None
    try:
        # Rebind first: a caller may hold connections to another database,
        # and this inspection must answer for the configured paths, read-only.
        vdb_db.reset_connections()
        vdb_db.get(read_only=True)
        return vdb_db.metadata_rows_count()
    except Exception:  # noqa: BLE001 - any driver error means unknown
        return None
    finally:
        vdb_db.reset_connections()


def _vdb_status() -> Dict[str, Any]:
    """The vulnerability database as the report shows it: read-only."""
    data_dir = vdb_config.DATA_DIR
    present = os.path.exists(vdb_config.VDB_BIN_FILE) or os.path.exists(
        vdb_config.VDB_BIN_INDEX
    )
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
            age_hours = round(
                (datetime.now(tz=timezone.utc) - created).total_seconds() / 3600, 1
            )
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


@dataclass(frozen=True)
class CapabilitySpec:
    """One capability row of :data:`CAPABILITIES`.

    A capability this dep-scan version does not implement carries no
    requirements: it cannot run here whatever tools are installed, and
    inventing requirements for it would promise checks that do not exist.
    The plan section says where the capability is designed.
    """

    name: str
    description: str
    plan: str
    requirements: Tuple[str, ...] = ()
    implemented: bool = False


#: The single source for what each capability needs. Requirement names are
#: ``tool:<name>`` matching a tools entry, or ``data:vdb`` for the
#: vulnerability database. Later analysis steps read this table through
#: :func:`requirement_missing` rather than keeping their own copy.
CAPABILITIES: Tuple[CapabilitySpec, ...] = (
    CapabilitySpec(
        name="vulnerabilities",
        description="Match components against the vulnerability database.",
        plan="depscan-v7-cli-policy.md D1",
        requirements=("data:vdb",),
        implemented=True,
    ),
    CapabilitySpec(
        name="reachability",
        description="Reachability from the slices cdxgen and atom produce.",
        plan="depscan-v7-cli-policy.md D1",
        requirements=("tool:cdxgen",),
        implemented=True,
    ),
    CapabilitySpec(
        name="reachability:rust",
        description="Rust reachability through the rusi plugin.",
        plan="depscan-v7-exploitability.md D7",
        requirements=("tool:cdxgen", "tool:rusi"),
        implemented=True,
    ),
    CapabilitySpec(
        name="reachability:go",
        description="Go reachability through the golem plugin and the Go toolchain.",
        plan="depscan-v7-exploitability.md D7",
        requirements=("tool:cdxgen", "tool:golem", "tool:go"),
        implemented=True,
    ),
    CapabilitySpec(
        name="reachability:dotnet",
        description=".NET reachability through the dosai plugin and the .NET runtime.",
        plan="depscan-v7-exploitability.md D5",
        requirements=("tool:cdxgen", "tool:dosai", "tool:dotnet"),
        implemented=True,
    ),
    CapabilitySpec(
        name="license",
        description="License risk from the licence data vendored with dep-scan.",
        plan="depscan-v7-cli-policy.md D1",
        requirements=(),
        implemented=True,
    ),
    CapabilitySpec(
        name="memory-safety",
        description="Memory-safety findings for C and C++ sources.",
        plan="depscan-v7-memory-safety.md D1",
    ),
    CapabilitySpec(
        name="memory-safety:c",
        description="Memory-safety analysis of C sources with atom memory-safety.",
        plan="depscan-v7-memory-safety.md D1",
    ),
    CapabilitySpec(
        name="mobile",
        description="Android and iOS app analysis.",
        plan="depscan-v7-mobile.md D1",
    ),
    CapabilitySpec(
        name="mobile:android",
        description="Android app analysis with blint, atom and kosi.",
        plan="depscan-v7-mobile.md D1",
    ),
    CapabilitySpec(
        name="supply-chain",
        description="Audit rule packs, package risk, provenance and CI pipeline risk.",
        plan="depscan-v7-supply-chain.md D1",
    ),
    CapabilitySpec(
        name="binary",
        description="Binary, installer, driver and container-image analysis with blint.",
        plan="depscan-v7-binaries.md D1",
    ),
    CapabilitySpec(
        name="code",
        description="Findings from the analyzers' own code rules.",
        plan="depscan-v7-exploitability.md D9",
    ),
    CapabilitySpec(
        name="crypto",
        description="Crypto findings from the cbom-security audit pack.",
        plan="depscan-v7-supply-chain.md D1",
    ),
)


@dataclass
class CapabilityStatus:
    """One evaluated capability row."""

    name: str
    status: str
    requirements: Tuple[str, ...]
    plan: str
    description: str
    missing: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "missing": self.missing,
            "requirements": list(self.requirements),
            "plan": self.plan,
            "description": self.description,
        }


def requirement_missing(
    requirement: str, tools: Dict[str, ToolStatus], data: Dict[str, Any]
) -> Optional[str]:
    """Whether one requirement is satisfied; the requirement name when not.

    A tool requirement needs a tools entry with a path and no reason. The
    database requirement needs a present database with index rows; a present
    database whose row count is unknown does not satisfy it, because a scan
    cannot know it is not empty.
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
                    plan=spec.plan,
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
                plan=spec.plan,
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
    """Locate every tool; returns the entries in report order and by name."""
    cdxgen = _cdxgen_status()
    golem = _plugin_tool_status(
        "golem", (golem_mod.GOLEM_CMD_ENV, golem_mod.GOLEM_BINARY_ENV)
    )
    rusi = _plugin_tool_status("rusi", (rusi_mod.RUSI_CMD_ENV, rusi_mod.RUSI_BINARY_ENV))
    dosai = _plugin_tool_status(
        "dosai", (dosai_mod.DOSAI_CMD_ENV, dosai_mod.DOSAI_BINARY_ENV)
    )
    entries = [
        cdxgen,
        _versioned_tool(
            "atom",
            find_executable("atom"),
            _parse_regex(_ATOM_VERSION_RE),
            "atom was not found on PATH; cdxgen runs the atom it installs "
            "itself, and dep-scan calls atom directly only for the "
            "memory-safety check",
        ),
        _versioned_tool(
            "atom-tools",
            find_executable("atom-tools"),
            _parse_regex(_ATOM_TOOLS_VERSION_RE),
            "atom-tools was not found on PATH; install it with "
            "`pip install atom-tools`",
        ),
        _versioned_tool(
            "edga",
            find_executable("edga"),
            _parse_regex(_EDGA_VERSION_RE),
            "edga was not found on PATH; it ships in atom's container images "
            "and improves the C and C++ front end",
        ),
        _versioned_tool(
            "node",
            find_executable("node"),
            _parse_node,
            "node was not found on PATH; cdxgen needs it unless it runs from "
            "a bundled binary",
        ),
        _python_status(),
        *_plugins_status(cdxgen.path, get_plugins_bin_target()),
        golem,
        _go_status(),
        rusi,
        dosai,
        _dotnet_status(dosai.path),
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
        for tool in self.tools:
            where = tool.source or "not found"
            if tool.source_env:
                where = f"{where}, {tool.source_env}"
            version = tool.version or "version unknown"
            lines.append(
                f"  {tool.name:<16} {version:<14} "
                f"{tool.path or '-'} ({where})"
            )
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
            names = ", ".join(
                str(shard.get("name")) for shard in shards.get("present") or []
            )
            lines.append(
                f"    shards: {'on' if shards.get('enabled') else 'off'}"
                + (f"; present: {names}" if names else "")
            )
        else:
            lines.append(
                f"    not present at {vdb.get('directory')}; a scan fetches one "
                "with `depscan-vdb download` or 'vdb db refresh full'"
            )
        lines += ["", "Capabilities"]
        for capability in self.capabilities:
            if capability.status == "available":
                note = "available"
            elif capability.status == "unavailable":
                note = "unavailable: " + ", ".join(capability.missing)
            else:
                note = f"not implemented ({capability.plan})"
            lines.append(f"  {capability.name:<22} {note}")
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
            needs = f"not implemented yet ({spec.plan})"
        lines.append(f"| `{spec.name}` | {spec.description} | {needs} |")
    return "\n".join(lines)


# --- the command ---------------------------------------------------------------


def parse_doctor_args(argv: List[str]) -> str:
    """Parse the arguments after ``doctor``; returns the output format."""
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
    args = parser.parse_args(argv)
    return args.format


def run_doctor_command(argv: List[str]) -> int:
    """Run the doctor command; returns the process exit code.

    The report goes to stdout in the chosen format and any logging goes to
    stderr. The command never prompts and never downloads, and it exits 0
    whenever it produced a report, even when tools are missing.
    """
    output_format = parse_doctor_args(argv)
    report = doctor()
    if output_format == "json":
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(report.to_text())
    return 0
