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
# vdb 7 publishes twelve complete databases ("flavors"), one per image repo
# ``ghcr.io/appthreat/vdb7-<flavor>``: ``full`` and ``app-only``, each with a
# two-year, a 10-year and a metadata (``-extended``) variant. The image URL
# for a flavor vdb names in ``FULL_DB_FLAVORS`` is resolved by vdb itself
# (``vdb.lib.db_cmd.resolve_full_image_url``), so a registry or tag override
# set through ``VDB_DATABASE_URL`` applies to every flavor. The app+OS
# variants are published before every vdb release names them; their URL is
# derived from a flavor vdb does resolve, so the same override applies.
VDB_FLAVORS = (
    "full",
    "full-extended",
    "full-2y",
    "full-2y-extended",
    "full-10y",
    "full-10y-extended",
    "app-only",
    "app-extended",
    "app-2y",
    "app-2y-extended",
    "app-10y",
    "app-10y-extended",
)

# The legacy ``--vdb-scope``/``--vdb-time``/``--vdb-extended`` triple mapped
# onto the published flavors. Every scope, time and metadata combination has
# a row; only a per-distro image has no v7 flavor, and that is rejected with
# the flavors listed rather than silently mapped onto a bigger database.
#
# ============ ========= ========= ==========================
# scope        time      extended  flavor
# ============ ========= ========= ==========================
# ``app+os``   default   no        ``full``
# ``app+os``   default   yes       ``full-extended``
# ``app+os``   2y        no        ``full-2y``
# ``app+os``   2y        yes       ``full-2y-extended``
# ``app+os``   10y       no        ``full-10y``
# ``app+os``   10y       yes       ``full-10y-extended``
# ``app``      default   no        ``app-only``
# ``app``      default   yes       ``app-extended``
# ``app``      2y        no        ``app-2y``
# ``app``      2y        yes       ``app-2y-extended``
# ``app``      10y       no        ``app-10y``
# ``app``      10y       yes       ``app-10y-extended``
# ============ ========= ========= ==========================
VDB_LEGACY_FLAVOR_MAP = {
    ("app+os", "default", False): "full",
    ("app+os", "default", True): "full-extended",
    ("app+os", "2y", False): "full-2y",
    ("app+os", "2y", True): "full-2y-extended",
    ("app+os", "10y", False): "full-10y",
    ("app+os", "10y", True): "full-10y-extended",
    ("app", "default", False): "app-only",
    ("app", "default", True): "app-extended",
    ("app", "2y", False): "app-2y",
    ("app", "2y", True): "app-2y-extended",
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


def flavor_table_markdown() -> str:
    """The published flavors as the markdown table the database page embeds.

    Every row is derived from the flavor name itself, so the table cannot
    name a flavor ``VDB_FLAVORS`` does not hold, or lose one.
    """
    windows = {"default": "2020", "2y": "2024", "10y": "2016"}
    lines = [
        "| Flavor | Scope | NVD advisories from | Metadata tables |",
        "| --- | --- | --- | --- |",
    ]
    for flavor in VDB_FLAVORS:
        base = flavor
        extended = base.endswith("-extended")
        if extended:
            base = base[: -len("-extended")]
        window = "default"
        if base.endswith("-2y"):
            window = "2y"
            base = base[: -len("-2y")]
        elif base.endswith("-10y"):
            window = "10y"
            base = base[: -len("-10y")]
        scope = "app+OS" if base == "full" else "application ecosystems"
        lines.append(
            f"| `{flavor}` | {scope} | {windows[window]} | {'yes' if extended else 'no'} |"
        )
    return "\n".join(lines) + "\n"


def legacy_flavor_table_markdown() -> str:
    """The deprecated option triple as the markdown table the database page
    embeds, one row per entry of ``VDB_LEGACY_FLAVOR_MAP``."""
    lines = [
        "| `--vdb-scope` | `--vdb-time` | `--vdb-extended` | Flavor |",
        "| --- | --- | --- | --- |",
    ]
    for (scope, time, extended), flavor in VDB_LEGACY_FLAVOR_MAP.items():
        lines.append(
            f"| `{scope}` | `{time}` | {'yes' if extended else 'no'} | `{flavor}` |"
        )
    return "\n".join(lines) + "\n"


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
    if flavor is None or flavor in FULL_DB_FLAVORS:
        url = resolve_full_image_url(flavor=flavor)
    else:
        # vdb derives every non-env flavor as <registry>/vdb7-<flavor>:<tag>;
        # take the registry and tag from one it knows.
        reference = resolve_full_image_url(flavor="app-extended")
        url = reference.replace("/vdb7-app-extended:", f"/vdb7-{flavor}:", 1)
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

# Default request timeout for the registry and API lookups dep-scan makes
request_timeout_sec = get_int_from_env("request_timeout_sec", 20)

# Universal scan
UNIVERSAL_SCAN_TYPE = "universal"
#: The reachability analyzer that runs the language tools (golem, rusi, kosi,
#: dosai) on a scan whose project type names no language.
SEMANTIC_REACHABILITY_ANALYZER = "SemanticReachability"

# How many records the explanation renders per record source (each slices
# file or raw report the evidence store's records came from).
max_reachable_explanations = get_int_from_env("max_reachable_explanations", 20)

# How many explanations one combination of package purls, one path start and
# one path end (the symbol the first and the last witness node name) may each
# get, so one noisy package or entry point cannot fill the section.
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
# tool/runtime), not a schema_version prefix -- see the rusi evidence
# adapter, analysis_lib.evidence.adapters.rusi.
# Default rusi backend. ``stable`` = syn-based parsing, no cargo/rustc build
# (safe on untrusted repos). ``compiler`` embeds nightly rustc and builds the
# target -- only enabled via ``--deep`` or ``--rust-analyzer-backend compiler``.
RUSI_DEFAULT_BACKEND = "stable"
RUSI_DEFAULT_DATAFLOW_MODE = "security-deps"
RUSI_DEFAULT_CALLGRAPH_MODE = "static"
# The converted reachables slice an earlier dep-scan wrote for rust projects.
# Nothing writes it any more; the name stays so the stale-output cleanup
# removes a file an earlier run left behind instead of reading it.
RUSI_REACHABLES_SLICE_FILE = "rust-reachables.slices.json"

# --- golem (Go Source Inspector) reachability ----------------------------
# env override for the golem binary path. Mirrors GOLEM_BINARY_ENV in
# xbom_lib/golem.py; duplicated here so the CLI/config layer is standalone.
GOLEM_BINARY_ENV = "DEPSCAN_GOLEM_BINARY"
# golem reports are detected by structural SHAPE (callGraph/dataFlow +
# tool/runtime), not a schemaVersion prefix -- see the golem evidence
# adapter, analysis_lib.evidence.adapters.golem.
GOLEM_DEFAULT_CALLGRAPH_MODE = "static"
GOLEM_DEFAULT_DATAFLOW_MODE = "all"
# The converted reachables slice an earlier dep-scan wrote for go projects;
# kept for the stale-output cleanup, like RUSI_REACHABLES_SLICE_FILE.
GOLEM_REACHABLES_SLICE_FILE = "go-reachables.slices.json"

# --- kosi (Kotlin Source Inspector) reachability -------------------------
# env override for the kosi binary path. Mirrors KOSI_BINARY_ENV in
# xbom_lib/kosi.py; duplicated here so the CLI/config layer is standalone.
KOSI_BINARY_ENV = "DEPSCAN_KOSI_BINARY"
# kosi reports carry schemaVersion "kosi/1" and are detected by that prefix;
# see the kosi evidence adapter, analysis_lib.evidence.adapters.kosi. The
# default ``syntax`` backend parses source only and never runs Gradle or
# Maven.
KOSI_DEFAULT_BACKEND = "syntax"
# The converted reachables slice an earlier dep-scan wrote from a kosi
# report; kept for the stale-output cleanup, like
# RUSI_REACHABLES_SLICE_FILE. It is not ``kotlin-reachables``, which is the
# file atom writes for a kotlin scan.
KOSI_REACHABLES_SLICE_FILE = "kosi-reachables.slices.json"

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
# prefix -- see the dosai evidence adapter,
# analysis_lib.evidence.adapters.dosai.
# The converted reachables slice an earlier dep-scan wrote for dotnet
# projects; kept for the stale-output cleanup, like
# RUSI_REACHABLES_SLICE_FILE.
DOSAI_REACHABLES_SLICE_FILE = "dotnet-reachables.slices.json"
# Default analyzer mode. ``auto`` selects source when a source tree is present
# and assembly for bin/.nupkg-only inputs.
DOSAI_DEFAULT_ANALYZER_MODE = "auto"
