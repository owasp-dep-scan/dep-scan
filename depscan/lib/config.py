import os
import sys
from os.path import dirname, exists, join


def resource_path(relative_path):
    """

    :param relative_path:
    :return:
    """
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = dirname(__file__)
    return join(base_path, relative_path)


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
npm_app_info = {"name": "owasp-depscan", "version": "6.0.0"}

PYPI_SERVER = "https://pypi.org/pypi"

CARGO_SERVER = "https://crates.io/api/v1/crates"

# Use the env variable VDB_DATABASE_URL=ghcr.io/appthreat/vdbxz-app:v6.4.x for app-only database
vdb_database_url = os.getenv("VDB_DATABASE_URL", "ghcr.io/appthreat/vdbxz:v6.4.x")

# Larger 10 year database
vdb_10y_database_url = os.getenv(
    "VDB_10Y_DATABASE_URL", "ghcr.io/appthreat/vdbxz-10y:v6.4.x"
)

if os.getenv("USE_VDB_10Y", "") in ("true", "1"):
    vdb_database_url = vdb_10y_database_url

# How old vdb can be before it gets re-downloaded. 48 hours.
VDB_AGE_HOURS = get_int_from_env("VDB_AGE_HOURS", 48)

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
mod_create_min_seconds = get_float_from_env(
    "mod_create_min_seconds", 12 * SECONDS_IN_HOUR
)
mod_create_min_seconds_max = get_float_from_env(
    "mod_create_min_seconds_max", 1000 * SECONDS_IN_DAY
)
mod_create_min_seconds_weight = get_float_from_env("mod_create_min_seconds_weight", 1)

# At least 12 hours difference between the latest version and the current time
latest_now_min_seconds = get_float_from_env(
    "latest_now_min_seconds", 12 * SECONDS_IN_HOUR
)
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
latest_now_max_seconds = get_float_from_env(
    "latest_now_max_seconds", 6 * 365 * SECONDS_IN_DAY
)
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
pkg_private_on_public_registry_max = get_float_from_env(
    "pkg_private_on_public_registry_max", 1
)

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
max_purls_reachable_explanations = get_int_from_env(
    "max_purls_reachable_explanations", 3
)
max_source_reachable_explanations = get_int_from_env(
    "max_source_reachable_explanations", 2
)
max_sink_reachable_explanations = get_int_from_env("max_sink_reachable_explanations", 2)

max_purl_per_flow = get_int_from_env("max_purl_per_flow", 8)

RUBY_PLATFORM_MARKERS = [
    "-x86_64",
    "-x86",
    "-x64",
    "-aarch",
    "-arm",
    "-ruby",
    "-universal",
    "-java",
    "-truffle",
]

# List of suffixes used by npm packages to indicate binary versions.
# This could be replaced with a better heuristics or lookup database in the future.
NPM_BINARY_PACKAGES_SUFFIXES = ("-prebuilt",)

DEPSCAN_DEFAULT_VDR_FILE = os.getenv(
    "DEPSCAN_DEFAULT_VDR_FILE", "depscan-universal.vdr.json"
)

COMMON_CHECK_TAGS = (
    "validation",
    "encode",
    "encrypt",
    "sanitize",
    "authentication",
    "authorization",
)
