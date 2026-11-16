import os
import sys
from os.path import dirname, exists, join

from vdb.lib.db_cmd import FULL_DB_FLAVORS, resolve_full_image_url


def is_frozen():
    """Return True when running inside a PyInstaller bundle."""
    return getattr(sys, "frozen", False) and getattr(sys, "_MEIPASS", None) is not None


def resource_path(relative_path):
    """
    Resolve a resource path relative to the application root.

    When running from source, the application root is the repository root
    (parent of ``depscan/``), so callers pass paths prefixed with ``../..``
    from ``depscan/lib/``. When running inside a PyInstaller ``--onefile``
    bundle, ``sys._MEIPASS`` is the bundle root and the ``vendor/`` directory
    is added there directly via ``--add-data``; the ``../../`` prefix must be
    dropped so it does not escape above ``_MEIPASS``.

    :param relative_path:
    :return:
    """
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        # ``_MEIPASS`` is the bundle root; strip any leading ``../..`` that
        # would otherwise walk above it.
        cleaned = relative_path
        while cleaned.startswith((".." + os.sep, "../")):
            sep = os.sep if cleaned.startswith(".." + os.sep) else "/"
            cleaned = cleaned.split(sep, 1)[1]
        return join(meipass, cleaned)
    return join(dirname(__file__), relative_path)


license_data_dir = resource_path(
    join(
        "..",
        "..",
        "vendor",
        "choosealicense.com",
        "_licenses",
    )
)
spdx_license_list = resource_path(
    join(
        "..",
        "..",
        "vendor",
        "spdx",
        "json",
        "licenses.json",
    )
)
if not exists(license_data_dir):
    license_data_dir = resource_path(
        join(
            "vendor",
            "choosealicense.com",
            "_licenses",
        )
    )
    spdx_license_list = resource_path(
        join(
            "vendor",
            "spdx",
            "json",
            "licenses.json",
        )
    )


# Default ignore list
ignore_directories = [
    ".git",
    ".svn",
    ".mvn",
    ".idea",
    "dist",
    "bin",
    "obj",
    "backup",
    "docs",
    "tests",
    "test",
    "tmp",
    "report",
    "reports",
    "node_modules",
    ".terraform",
    ".serverless",
    "venv",
    "examples",
    "tutorials",
    "samples",
    "migrations",
    "db_migrations",
    "unittests",
    "unittests_legacy",
    "stubs",
    "mock",
    "mocks",
]


def get_float_from_env(name, default):
    """
    Retrieves a value from an environment variable and converts it to a
    float. If the value cannot be converted to a float, it returns the
    default value provided.

    :param name:
    :param default:
    :return:
    """
    value = os.getenv(name.upper(), default)
    try:
        value = float(value)
    except ValueError:
        value = default
    return value


def get_int_from_env(name, default):
    """
    Retrieves a value from an environment variable and converts it to an
    integer. If the value cannot be converted to an integer, it returns the
    default value provided.

    :param name:
    :param default:
    """
    return int(get_float_from_env(name, default))


NPM_SERVER = "https://registry.npmjs.org"

PYPI_SERVER = "https://pypi.org/pypi"

CARGO_SERVER = "https://crates.io/api/v1/crates"

# --- vdb database selection -----------------------------------------------
# vdb 7 publishes five complete databases ("flavors"), one per image repo
# ``ghcr.io/appthreat/vdb7-<flavor>``. The image URL for a flavor is resolved
# by vdb itself (``vdb.lib.db_cmd.resolve_full_image_url``), so a registry or
# tag override set through ``VDB_DATABASE_URL`` applies to every flavor.
VDB_FLAVORS = FULL_DB_FLAVORS

# The legacy ``--vdb-scope``/``--vdb-time``/``--vdb-extended`` triple mapped
# onto the published flavors. Combinations with no row (a two-year window in
# any scope, an app+OS 10-year or extended variant, and every per-distro
# image) have no v7 flavor; they are rejected with the flavors listed rather
# than silently mapped onto a bigger or smaller database.
#
# ============ ========= ========= ==========================
# scope        time      extended  flavor
# ============ ========= ========= ==========================
# ``app+os``   default   no        ``full``
# ``app``      default   no        ``app-only``
# ``app``      default   yes       ``app-extended``
# ``app``      10y       no        ``app-10y``
# ``app``      10y       yes       ``app-10y-extended``
# ============ ========= ========= ==========================
VDB_LEGACY_FLAVOR_MAP = {
    ("app+os", "default", False): "full",
    ("app", "default", False): "app-only",
    ("app", "default", True): "app-extended",
    ("app", "10y", False): "app-10y",
    ("app", "10y", True): "app-10y-extended",
}

VDB_SCOPES = ("app", "app+os")
VDB_TIMES = ("2y", "default", "10y")
VDB_COMPRESSIONS = ("xz", "zst")


def resolve_vdb_flavor(*, scope="app+os", time="default", extended=False):
    """Map the legacy scope/time/extended triple onto a published flavor.

    :raises ValueError: when the combination has no v7 flavor, naming the
        published flavors
    """
    if scope not in VDB_SCOPES:
        raise ValueError(f"Invalid scope '{scope}'. Use one of: {', '.join(VDB_SCOPES)}.")
    if time not in VDB_TIMES:
        raise ValueError(f"Invalid time '{time}'. Use one of: {', '.join(VDB_TIMES)}.")
    flavor = VDB_LEGACY_FLAVOR_MAP.get((scope, time, bool(extended)))
    if flavor is None:
        raise ValueError(
            f"No published vdb 7 flavor for scope={scope!r}, time={time!r}, "
            f"extended={bool(extended)!r}. Published flavors: "
            f"{', '.join(VDB_FLAVORS)}."
        )
    return flavor


def resolve_vdb_image_url(flavor=None, *, compression=None, image=None):
    """The OCI image URL for a database refresh, resolved by vdb.

    ``image`` wins verbatim. Otherwise ``vdb.lib.db_cmd.resolve_full_image_url``
    picks the flavor's URL (honouring a ``VDB_DATABASE_URL`` registry/tag
    override), and a ``zst`` compression choice swaps the encoding suffix of
    the resolved reference; v7 publishes only ``-xz`` and ``-zst`` tags.
    """
    if image:
        return image
    if flavor is not None and flavor not in VDB_FLAVORS:
        raise ValueError(f"Invalid flavor '{flavor}'. Use one of: {', '.join(VDB_FLAVORS)}.")
    if compression not in (None, *VDB_COMPRESSIONS):
        raise ValueError(
            f"Invalid compression '{compression}'. Use one of: {', '.join(VDB_COMPRESSIONS)}."
        )
    url = resolve_full_image_url(flavor=flavor)
    if compression == "zst" and url.endswith("-xz"):
        url = url[: -len("-xz")] + "-zst"
    return url


# --- variant marker ---------------------------------------------------------
# depscan-owned marker under the database directory that records what was last
# fetched: the image URL of a flavor, or "shards:<comma-separated names>" for
# a shard set. vdb's own metadata records created_utc but NOT the variant, so
# without this marker a flavor or shard-set switch would NOT re-download for
# up to VDB_AGE_HOURS (48h).
VDB_IMAGE_MARKER_FILE = ".depscan-vdb-image"

#: Marker prefix for a shard-set refresh; the shard names follow the colon.
VDB_SHARDS_MARKER_PREFIX = "shards:"


def vdb_image_marker_path(data_dir):
    """Return the path to the variant marker file under *data_dir*."""
    return join(data_dir, VDB_IMAGE_MARKER_FILE)


def read_vdb_image_marker(data_dir):
    """Read the recorded image ref from the marker, or ``None`` if absent."""
    marker = vdb_image_marker_path(data_dir)
    if not exists(marker):
        return None
    try:
        with open(marker, encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return None


def vdb_shards_marker(shard_names):
    """The marker value recording a refresh of *shard_names*."""
    return VDB_SHARDS_MARKER_PREFIX + ",".join(sorted(shard_names))


def write_vdb_image_marker(image_ref, data_dir):
    """Record *image_ref* as the last-pulled variant under *data_dir*."""
    marker = vdb_image_marker_path(data_dir)
    try:
        with open(marker, "w", encoding="utf-8") as fh:
            fh.write(image_ref)
    except OSError:
        pass


# How old vdb can be before it gets re-downloaded. 48 hours.
VDB_AGE_HOURS = get_int_from_env("VDB_AGE_HOURS", 48)

# Opt-in shard mode: refresh and search the type shards for the scan's purl
# types instead of a complete database (see docs/VULNERABILITY DATABASE).
VDB_USE_SHARDS = os.getenv("VDB_USE_SHARDS", "") in ("true", "1")

# Package risk scoring using a simple weighted formula with no backing
# research All parameters and their max value and weight can be overridden
# using environment variables

# Some constants and defaults
SECONDS_IN_DAY = 24 * 60 * 60
SECONDS_IN_HOUR = 60 * 60
DEFAULT_MAX_VALUE = 100
DEFAULT_WEIGHT = 1

# Package should have at least 3 versions
pkg_min_versions = get_float_from_env("pkg_min_versions", 3)
pkg_min_versions_max = get_float_from_env("pkg_min_versions_max", 100)
pkg_min_versions_weight = get_float_from_env("pkg_min_versions_weight", 2)

# At least 12 hours difference between the creation and modified time
mod_create_min_seconds = get_float_from_env("mod_create_min_seconds", 12 * SECONDS_IN_HOUR)
mod_create_min_seconds_max = get_float_from_env(
    "mod_create_min_seconds_max", 1000 * SECONDS_IN_DAY
)
mod_create_min_seconds_weight = get_float_from_env("mod_create_min_seconds_weight", 1)

# At least 12 hours difference between the latest version and the current time
latest_now_min_seconds = get_float_from_env("latest_now_min_seconds", 12 * SECONDS_IN_HOUR)
latest_now_min_seconds_max = get_float_from_env(
    "latest_now_min_seconds_max", 1000 * SECONDS_IN_DAY
)
latest_now_min_seconds_weight = get_float_from_env("latest_now_min_seconds_weight", 0.5)

# Time period after which certain risks can be considered safe. Quarantine
# period For eg: Packages that are over 1 year old
created_now_quarantine_seconds = get_float_from_env(
    "created_now_quarantine_seconds", 365 * SECONDS_IN_DAY
)
created_now_quarantine_seconds_max = get_float_from_env(
    "created_now_quarantine_seconds_max", 365 * SECONDS_IN_DAY
)
created_now_quarantine_seconds_weight = get_float_from_env(
    "created_now_quarantine_seconds_weight", 0.5
)

# Max package age - 6 years
latest_now_max_seconds = get_float_from_env("latest_now_max_seconds", 6 * 365 * SECONDS_IN_DAY)
latest_now_max_seconds_max = get_float_from_env(
    "latest_now_max_seconds_max", 6 * 365 * SECONDS_IN_DAY
)
latest_now_max_seconds_weight = get_float_from_env("latest_now_max_seconds_weight", 0.5)

# Package should have at least 2 maintainers
pkg_min_maintainers = get_float_from_env("pkg_min_maintainers", 2)
pkg_min_maintainers_max = get_float_from_env("pkg_min_maintainers_max", 20)
pkg_min_maintainers_weight = get_float_from_env("pkg_min_maintainers_weight", 2)

# Package should have at least 2 users
pkg_min_users = get_float_from_env("pkg_min_users", 2)
pkg_min_users_max = get_float_from_env("pkg_min_users_max", 20)
pkg_min_users_weight = get_float_from_env("pkg_min_users_weight", 0.25)

# Package with install scripts (npm)
pkg_install_scripts_max = get_float_from_env("pkg_install_scripts_max", 0)
pkg_install_scripts_weight = get_float_from_env("pkg_install_scripts_weight", 2)

# Node version risk
pkg_node_version = os.getenv("pkg_node_version".upper(), "0.,4,6,8,10,12")
pkg_node_version_max = get_float_from_env("pkg_node_version_max", 16)
pkg_node_version_weight = get_float_from_env("pkg_node_version_weight", 0.5)

# Package deprecated
pkg_deprecated_weight = get_float_from_env("pkg_deprecated_weight", 2)
pkg_deprecated_max = get_float_from_env("pkg_deprecated_max", 0)

# Package version deprecated
pkg_version_deprecated_weight = get_float_from_env("pkg_version_deprecated_weight", 2)
pkg_version_deprecated_max = get_float_from_env("pkg_version_deprecated_max", 0)

# Package version missing
pkg_version_missing_weight = get_float_from_env("pkg_version_missing_weight", 2)
pkg_version_missing_max = get_float_from_env("pkg_version_missing_max", 0)

# Package includes binary
pkg_includes_binary_weight = get_float_from_env("pkg_includes_binary_weight", 2)
pkg_includes_binary_max = get_float_from_env("pkg_includes_binary_max", 0)

# Package has attestation
pkg_attested_weight = get_float_from_env("pkg_attested_weight", -2)
pkg_attested_max = get_float_from_env("pkg_attested_max", 0)

# Package dependency confusion
pkg_private_on_public_registry_weight = get_float_from_env(
    "pkg_private_on_public_registry_weight", 4
)
pkg_private_on_public_registry_max = get_float_from_env("pkg_private_on_public_registry_max", 1)

# Package scope related weight
pkg_required_scope_weight = get_float_from_env("pkg_required_scope_weight", 4.0)
pkg_optional_scope_weight = get_float_from_env("pkg_optional_scope_weight", 0.5)
pkg_excluded_scope_weight = get_float_from_env("pkg_excluded_scope_weight", 0)
pkg_required_scope_max = get_float_from_env("pkg_required_scope_max", 1)
pkg_optional_scope_max = get_float_from_env("pkg_optional_scope_max", 1)
pkg_excluded_scope_max = get_float_from_env("pkg_excluded_scope_max", 1)

total_weight = (
    pkg_min_versions_weight
    + mod_create_min_seconds_weight
    + latest_now_min_seconds_weight
    + latest_now_max_seconds_weight
    + created_now_quarantine_seconds_weight
    + pkg_min_maintainers_weight
    + pkg_min_users_weight
    + pkg_install_scripts_weight
    + pkg_node_version_weight
    + pkg_required_scope_weight
    + pkg_optional_scope_weight
    + pkg_deprecated_weight
    + pkg_version_deprecated_weight
    + pkg_version_missing_weight
    + pkg_includes_binary_weight
    + pkg_private_on_public_registry_weight
)


# Package max risk score. All packages above this level will be reported
pkg_max_risk_score = get_float_from_env("pkg_max_risk_score", 0.5)

# Default request timeout
request_timeout_sec = get_int_from_env("request_timeout_sec", 20)

# Number of api failures that would stop the risk audit completely
max_request_failures = get_int_from_env("max_request_failures", 5)

# Universal scan
UNIVERSAL_SCAN_TYPE = "universal"

max_reachable_explanations = get_int_from_env("max_reachable_explanations", 20)

# How many explanations for a given combination of purls
max_purls_reachable_explanations = get_int_from_env("max_purls_reachable_explanations", 3)
max_source_reachable_explanations = get_int_from_env("max_source_reachable_explanations", 2)
max_sink_reachable_explanations = get_int_from_env("max_sink_reachable_explanations", 2)

max_purl_per_flow = get_int_from_env("max_purl_per_flow", 8)
max_flows_per_prompt = get_int_from_env("max_flows_per_prompt", 8)

# List of suffixes used by npm packages to indicate binary versions.
# This could be replaced with a better heuristics or lookup database in the future.
NPM_BINARY_PACKAGES_SUFFIXES = ("-prebuilt",)

DEPSCAN_DEFAULT_VDR_FILE = os.getenv("DEPSCAN_DEFAULT_VDR_FILE", "depscan-universal.vdr.json")

COMMON_CHECK_TAGS = (
    "validation",
    "encode",
    "encrypt",
    "sanitize",
    "authentication",
    "authorization",
)

# --- rusi (Rust Source Inspector) reachability ---------------------------
# env override for the rusi binary path. Mirrors RUSI_BINARY_ENV in
# xbom_lib/rusi.py; duplicated here so the CLI/config layer is standalone.
RUSI_BINARY_ENV = "DEPSCAN_RUSI_BINARY"
# rusi reports are detected by structural SHAPE (call_graph/data_flow +
# tool/runtime), not a schema_version prefix -- see analysis_lib.rusi_slices.
# Default rusi backend. ``stable`` = syn-based parsing, no cargo/rustc build
# (safe on untrusted repos). ``compiler`` embeds nightly rustc and builds the
# target -- only enabled via ``--deep`` or ``--rust-analyzer-backend compiler``.
RUSI_DEFAULT_BACKEND = "stable"
RUSI_DEFAULT_DATAFLOW_MODE = "security-deps"
RUSI_DEFAULT_CALLGRAPH_MODE = "static"
# Slice file dep-scan writes for rust projects. Matches the name cdxgen uses
# for atom reachables slices (set_slices_args in xbom_lib/cdxgen.py) so the
# glob-based discovery in ReachabilityAnalysisKV picks it up unchanged.
RUSI_REACHABLES_SLICE_FILE = "rust-reachables.slices.json"

# --- golem (Go Source Inspector) reachability ----------------------------
# env override for the golem binary path. Mirrors GOLEM_BINARY_ENV in
# xbom_lib/golem.py; duplicated here so the CLI/config layer is standalone.
GOLEM_BINARY_ENV = "DEPSCAN_GOLEM_BINARY"
# golem reports are detected by structural SHAPE (callGraph/dataFlow +
# tool/runtime), not a schemaVersion prefix -- see analysis_lib.golem_slices.
GOLEM_DEFAULT_CALLGRAPH_MODE = "static"
GOLEM_DEFAULT_DATAFLOW_MODE = "all"
# Slice file dep-scan writes for go projects. Matches the name cdxgen uses
# for atom reachables slices (set_slices_args in xbom_lib/cdxgen.py) so the
# glob-based discovery in ReachabilityAnalysisKV picks it up unchanged.
GOLEM_REACHABLES_SLICE_FILE = "go-reachables.slices.json"

# --- dosai (Dotnet Source and Assembly Inspector) reachability -----------
# env override for the dosai binary path. Mirrors DOSAI_BINARY_ENV in
# xbom_lib/dosai.py; duplicated here so the CLI/config layer is standalone.
DOSAI_BINARY_ENV = "DEPSCAN_DOSAI_BINARY"
# cdxgen's plugin override env for dosai. Honored FIRST so depscan's fallback
# resolves the same binary cdxgen uses (and which produced the persisted
# report).
DOSAI_CMD_ENV = "DOSAI_CMD"
# Pattern packs select the source/sink categories dosai looks for. ``all``
# maximizes the reachability signal (only the dataflows command accepts it).
DOSAI_PATTERN_PACKS_DEFAULT = "all"
# Raw native artifacts persisted in the bom dir on the direct-spawn fallback
# path (source of truth -- never deleted).
DOSAI_DATAFLOWS_FILE = "dotnet-dataflows.json"
DOSAI_METHODS_FILE = "dotnet-methods.json"
# dosai reports are detected by structural SHAPE (Metadata.Tool == "Dosai" +
# methods/dataflows OR Slices/PackageReachability/CallGraph), not a schema
# prefix -- see analysis_lib.dosai_slices.
# Atom projection dep-scan writes for dotnet projects. Matches the name cdxgen
# uses for atom reachables slices (set_slices_args in xbom_lib/cdxgen.py) so the
# glob-based discovery in ReachabilityAnalysisKV picks it up unchanged.
DOSAI_REACHABLES_SLICE_FILE = "dotnet-reachables.slices.json"
# Default analyzer mode. ``auto`` selects source when a source tree is present
# and assembly for bin/.nupkg-only inputs.
DOSAI_DEFAULT_ANALYZER_MODE = "auto"
# How many reachable explanations to render for dotnet (parallel to rust/go).
max_dotnet_reachable_explanations = get_int_from_env("max_dotnet_reachable_explanations", 20)
