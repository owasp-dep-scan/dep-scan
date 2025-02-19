import os
import re
import sys
from os.path import dirname, exists, join

from depscan import get_version


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

# CPE Vendor aliases
vendor_alias = {
    "org.apache.commons.io": "commons-io",
    "org.apache.logging.log4j": "log4j",
    "org.apache.commons.beanutils": "commons-beanutils",
    "org.apache.commons.collections": "commons-collections",
    "org.apache.solr": "apache_solr",
    "org.spring": "vmware",
    "org.springframework": "pivotal_software",
    "io.undertow": "redhat",
    "ch.qos.logback": "logback",
    "ch.qos.slf4j": "slf4j",
    "org.yaml": "snakeyaml_project",
    "org.hibernate.validator": "org.hibernate",
    "org.hibernate": "redhat",
    "org.dom4j": "dom4j_project",
    "ant": "apache",
    "commons-": "apache",
    "org.quartz-scheduler": "softwareag",
    "org.mitre": "mitreid",
    "io.micronaut": "objectcomputing",
    "twistedmatrix": "twisted",
    "oneup": "1up",
    "io.ktor": "jetbrains",
    "com.puppycrawl.tools": "checkstyle",
    "org.opencastproject": "apereo",
    "bagisto": "webkul",
    "ro.pippo": "pippo",
    "ca.uhn.hapi.fhir": "fhir",
    "tensorflow": "google",
    "ansible": "redhat",
    "io.springfox": "smartbear",
    "log4net": "apache",
    "github": "github actions",
    "microsoft": "azure",
    "phenx": "dompdf",
}

# Package aliases
package_alias = {
    "struts2-core": "struts",
    "struts2-rest-plugin": "struts",
    "struts2-showcase": "struts",
    "jackson-databind": "jackson",
    "apache_tomcat": "tomcat",
    "tomcat_native": "tomcat",
    "tomcat_connectors": "tomcat",
    "tomcat_jk_connector": "tomcat",
    "tomcat-embed-core": "tomcat",
    "spring-security-core": "spring_security",
    "spring-security-crypto": "spring_security",
    "asciidoctorj": "asciidoctor",
    "postgresql": "postgresql_jdbc_driver",
    "itextpdf": "itext",
    "httpclient": "commons-httpclient",
    "priority": "python_priority_library",
    "rocketmq-broker": "rocketmq",
    "mysql_connector": "mysql-connector-java",
    "jhipster_kotlin": "jhipster",
    "spring-cloud-config-server": "spring_cloud_config",
    "django-rest-framework-json_web_tokens": "drf-jwt",
    "beam-sdks-java-io-mongodb": "beam",
    "sm-core-model": "shopizer",
    "openid-connect-server": "connect",
    "http4s-server_2.12": "http4s",
    "santuario_xml_security_for_java": "xmlsec",
    "uploader-bundle": "oneupuploaderbundle",
    "odata-client-core": "olingo",
    "odata-client-proxy": "olingo",
    "odata-server-core": "olingo",
    "syliusresourcebundle": "sylius",
    "ethereum_name_service": "ens",
    "tensorflow-gpu": "tensorflow",
    "tensorflow-cpu": "tensorflow",
    "class.upload.php": "verot",
    "redis_wrapper": "rediswrapper",
    "silverstripe-versionedfiles": "versionedfiles",
    "simplesamlphp-module-proxystatistics": "proxystatistics",
    "pac4j-saml": "pac4j",
    "universal_office_converter": "unoconv",
    "hapi-fhir-base": "hapi_fhir",
    "spring-data-jpa": "spring_data_java_persistance_api",
    "sanselan": "commons_imaging",
    "uima-ducc-web": "unstructured_information_management_architecture_distributed_uima_cluster_computing",
    "arrow-ank-gradle": "arrow",
    "openpgpjs": "openpgp",
    "storm-kafka": "storm",
    "storm-kafka-client": "storm",
    "tika-parsers": "tika",
    "ironic-discoverd": "ironic_inspector",
    "hawkbit-ui": "hawkbit",
    "hawkbit-starters": "hawkbit",
    "hawkbit-boot-starter": "hawkbit",
    "software_development_kit": "splunk-sdk",
    "jira_software_data_center": "jira",
    "springfox-swagger2": "swagger_ui",
    "spring-web": "spring_framework",
    "springfox-swagger-ui": "swagger_ui",
    "hibernate-core": "hibernate_orm",
    "json-smart": "json-smart-v2",
    "ojdbc7": "jdbc",
    "System.Text": ".net",
    "System.Net": "asp.net_core",
    "Microsoft.IdentityModel.Clients.ActiveDirectory": "active_directory_authentication_library",
    "starkbank_ecdsa": "ecdsa-elixir",
    "php-pear": "pear-core-minimal",
    "Selenium.WebDriver": "selenium",
    "selenium": "selenium",
    "numpy": "numpy",
}

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

# Package types allowed for each language
LANG_PKG_TYPES = {
    "python": "pypi",
    "java": "maven",
    "jvm": "maven",
    "groovy": "maven",
    "kotlin": "maven",
    "scala": "maven",
    "jenkins": "maven",
    "js": "npm",
    "javascript": "npm",
    "nodejs": "npm",
    "node.js": "npm",
    "npmjs": "npm",
    "go": "golang",
    "golang": "golang",
    "ruby": "gem",
    "php": "composer",
    "dotnet": "nuget",
    "csharp": "nuget",
    "rust": "cargo",
    "crates": "cargo",
    "dart": "pub",
    "cpp": "conan",
    "clojure": "clojars",
    "haskell": "hackage",
    "elixir": "hex",
    "github actions": "github",
    "github": "github",
}

# OS Package types
OS_PKG_TYPES = (
    "deb",
    "apk",
    "rpm",
    "swid",
    "alpm",
    "docker",
    "oci",
    "container",
    "generic",
    "qpkg",
    "buildroot",
    "coreos",
    "ebuild",
    "alpine",
    "alma",
    "almalinux",
    "debian",
    "ubuntu",
    "amazon",
    "rhel",
    "redhat",
    "rocky",
    "arch",
    "suse",
    "photon",
    "microsoft",
    "wolfi",
    "chainguard",
)

# List of Linux distros with support for editions
LINUX_DISTRO_WITH_EDITIONS = (
    "debian",
    "ubuntu",
    "alpine",
    "rhel",
    "redhat",
    "arch",
    "suse",
    "photon",
    "alma",
    "almalinux",
    "amazon",
    "rocky",
)


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

vdb_database_url = os.getenv("VDB_DATABASE_URL", "ghcr.io/appthreat/vdbxz:v6")
vdb_rafs_database_url = os.getenv(
    "VDB_RAFS_DATABASE_URL", "ghcr.io/appthreat/vdb:v6-rafs"
)

# Larger 10 year database
vdb_10y_database_url = os.getenv(
    "VDB_10Y_DATABASE_URL", "ghcr.io/appthreat/vdbxz-10y:v6"
)
vdb_10y_rafs_database_url = os.getenv(
    "VDB_10Y_RAFS_DATABASE_URL", "ghcr.io/appthreat/vdb-10y:v6-rafs"
)

if os.getenv("USE_VDB_10Y", "") in ("true", "1"):
    vdb_database_url = vdb_10y_database_url
    vdb_rafs_database_url = vdb_10y_rafs_database_url

# How old vdb can be before it gets re-downloaded
VDB_AGE_HOURS = get_int_from_env("VDB_AGE_HOURS", 24)

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
mod_create_min_seconds_weight = get_float_from_env(
    "mod_create_min_seconds_weight", 1
)

# At least 12 hours difference between the latest version and the current time
latest_now_min_seconds = get_float_from_env(
    "latest_now_min_seconds", 12 * SECONDS_IN_HOUR
)
latest_now_min_seconds_max = get_float_from_env(
    "latest_now_min_seconds_max", 1000 * SECONDS_IN_DAY
)
latest_now_min_seconds_weight = get_float_from_env(
    "latest_now_min_seconds_weight", 0.5
)

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
latest_now_max_seconds_weight = get_float_from_env(
    "latest_now_max_seconds_weight", 0.5
)

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
pkg_version_deprecated_weight = get_float_from_env(
    "pkg_version_deprecated_weight", 2
)
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

# Help text for various risk
risk_help_text = {
    "pkg_min_versions": "Has fewer versions",
    "latest_now_min_seconds": "Recently updated",
    "latest_now_max_seconds": "No recent updates",
    "pkg_min_maintainers": "Has fewer maintainers",
    "pkg_node_version": "Outdated Node version",
    "pkg_install_scripts": "Runs scripts on install",
    "pkg_deprecated": "Deprecated",
    "pkg_version_deprecated": "Deprecated version",
    "pkg_version_missing": "Non-existent version",
    "pkg_includes_binary": "Includes binary",
    "pkg_attested": "Has attestation",
    "pkg_private_on_public_registry": "Private package is public",
}

# Package max risk score. All packages above this level will be reported
pkg_max_risk_score = get_float_from_env("pkg_max_risk_score", 0.5)

# Default request timeout
request_timeout_sec = get_int_from_env("request_timeout_sec", 20)

# Number of api failures that would stop the risk audit completely
max_request_failures = get_int_from_env("max_request_failures", 5)

# Universal scan
UNIVERSAL_SCAN_TYPE = "universal"

max_reachable_explanations = get_int_from_env("max_reachable_explanations", 20)

max_purl_per_flow = get_int_from_env("max_purl_per_flow", 6)

# List of CWEs that could lead to damages, exploits, and container escapes
OS_VULN_KEY_CWES = (
    20,
    23,
    24,
    25,
    26,
    27,
    28,
    29,
    30,
    31,
    32,
    33,
    34,
    35,
    36,
    37,
    38,
    39,
    40,
    58,
    61,
    62,
    64,
    65,
    67,
    69,
    73,
    77,
    78,
    79,
    91,
    119,
    120,
    121,
    122,
    125,
    126,
    127,
    200,
    250,
    264,
    269,
    279,
    416,
    422,
    439,
    502,
    506,
    507,
    508,
    509,
    510,
    511,
    512,
    514,
    515,
    552,
    553,
    786,
    787,
    788,
    789,
    862,
    1386,
)

max_distro_vulnerabilities = get_int_from_env("max_distro_vulnerabilities", 200)

OS_PKG_UNINSTALLABLE = (
    "openssh",
    "cups",
    "imagemagick",
    "curl",
    "tar",
    "git",
    "avahi",
    "libssh",
    "subversion",
    "vim",
    "vim-minimal",
)

OS_PKG_IGNORABLE = ("linux", "systemd", "ncurses", "kernel")

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

CWE_SPLITTER = re.compile(r"(?<=CWE-)[0-9]\d{0,5}", re.IGNORECASE)
JFROG_ADVISORY = re.compile(r"(?P<id>jfsa\S+)", re.IGNORECASE)
ADVISORY = re.compile(r"(?P<org>[^\s./]+).(?:com|org)/(?:[\S]+)?/(?P<id>(?:(?:ghsa|ntap|rhsa|rhba|zdi|dsa|cisco|intel|usn)-)?[\w\d\-:]{5,})", re.IGNORECASE)

REF_MAP = {
    "repo_hosts": {
        re.compile(r"(?P<host>github|bitbucket|chromium)(?:.com|.org)/(?P<user>[\w\-.]+)/(?P<repo>[\w\-.]+)/(?P<type>pull|commit|commits|release|issues)(?:/detail\?id=)?(?:s/tag)?/?(?P<id>\S+)", re.IGNORECASE): "Generic",
        re.compile(r"github.com/(?P<user>[\w\-.]+)/(?P<repo>[\w\-.]+)/blob/(?P<ref>\S+)/(?P<file>\S+)", re.IGNORECASE): "GitHub Blob",
        re.compile(r"gist.github.com/(?P<user>[\w\-.]+)/(?P<id>\S+)", re.IGNORECASE): "GitHub Gist",
    },
    "other": {
        # "blog": "Blog Post",
        re.compile(r"lists.[\w\-]+.org/", re.IGNORECASE): "Vendor",
        re.compile("openwall.com|oss-security|www.mail-archive.com|portal.msrc.microsoft.com|mail.|securityfocus.|securitytracker.|/discussion/|/archives/|groups.", re.IGNORECASE): "Mailing List",
        re.compile(r"(?<=bugzilla.)(?P<org>\S+)\.\w{3}/show_bug.cgi\?id=(?P<id>\S+)", re.IGNORECASE): "Bugzilla",
        re.compile("exploit-db|seebug.org|seclists.org|nu11secur1ty|packetstormsecurity.com|coresecurity.com|project-zero|0dd.zone|synacktiv.com|bishopfox.com|zerodayinitiative.com|samba.org/samba/security/|synology.com/support/security/|us-cert.gov/advisories", re.IGNORECASE): "Exploit",
        ADVISORY: "Advisory",
        re.compile(r"cve-[0-9]{4,}-[0-9]{4,}$", re.IGNORECASE): "CVE Record",
        re.compile("hackerone|bugcrowd|bug-bounty|huntr.dev|bounties", re.IGNORECASE): "BugBounty",
        re.compile(r"(?P<org>snyk).io/vuln/(?P<id>\S+)", re.IGNORECASE): "Advisory",
        re.compile(r"(?P<org>vuldb).com/\?id.(?P<id>\d+)", re.IGNORECASE): "Advisory",
        re.compile("poc", re.IGNORECASE): "POC",
        # "oss-fuzz": "OSS-Fuzz",
        # "cwe.mitre.org/data/definitions/(?P<id>\d+).html": "CWE Definition",
        # "/(community|forum|discuss)": "Forum",
        # "bugs.|chat.": "Issue",
        # "wordpress|wpvulndb": "WordPress",
        # "chrome.google.com/webstore": "Chrome Extension",
    },
    "exploits": {
        "seclists": re.compile(r"(?P<org>seclists).org/(?P<id>\S+/\d{4}/\w{3}/\d{1,2})"),
        "generic": re.compile(r"(?P<org>[^/\s.]+)(?:.blogspot)?.(?:com|org|zone|gov)/(?:[\w-]+/){1,5}(?P<id>[^/\s)]+)", re.IGNORECASE)
    },
    "openwall": re.compile(r"(?P<org>openwall).com/lists/(?P<list_type>[^/]+)/(?P<id>\S+)", re.IGNORECASE),
}

SEVERITY_REF = {
    "critical": 1,
    "high": 2,
    "medium": 3,
    "low": 4,
    "unknown": 5,
    "none": 6,
}

TIME_FMT = "%Y-%m-%dT%H:%M:%S"

CWE_MAP = {
    5: 'J2EE Misconfiguration: Data Transmission Without Encryption',
    6: 'J2EE Misconfiguration: Insufficient Session-ID Length',
    7: 'J2EE Misconfiguration: Missing Custom Error Page',
    8: 'J2EE Misconfiguration: Entity Bean Declared Remote',
    9: 'J2EE Misconfiguration: Weak Access Permissions for EJB Methods',
    11: 'ASP.NET Misconfiguration: Creating Debug Binary',
    12: 'ASP.NET Misconfiguration: Missing Custom Error Page',
    13: 'ASP.NET Misconfiguration: Password in Configuration File',
    14: 'Compiler Removal of Code to Clear Buffers',
    15: 'External Control of System or Configuration Setting',
    20: 'Improper Input Validation',
    22: 'Improper Limitation of a Pathname to a Restricted Directory',
    23: 'Relative Path Traversal',
    24: 'Path Traversal',
    25: 'Path Traversal',
    26: 'Path Traversal',
    27: 'Path Traversal',
    28: 'Path Traversal',
    29: 'Path Traversal',
    30: 'Path Traversal',
    31: 'Path Traversal',
    32: 'Path Traversal',
    33: 'Path Traversal',
    34: 'Path Traversal',
    35: 'Path Traversal',
    36: 'Absolute Path Traversal',
    37: 'Path Traversal',
    38: 'Path Traversal',
    39: 'Path Traversal',
    40: 'Path Traversal',
    41: 'Improper Resolution of Path Equivalence',
    42: 'Path Equivalence',
    43: 'Path Equivalence',
    44: 'Path Equivalence',
    45: 'Path Equivalence',
    46: 'Path Equivalence',
    47: 'Path Equivalence',
    48: 'Path Equivalence',
    49: 'Path Equivalence',
    50: 'Path Equivalence',
    51: 'Path Equivalence',
    52: 'Path Equivalence',
    53: 'Path Equivalence',
    54: 'Path Equivalence',
    55: 'Path Equivalence',
    56: 'Path Equivalence',
    57: 'Path Equivalence',
    58: 'Path Equivalence',
    59: 'Improper Link Resolution Before File Access',
    61: 'UNIX Symbolic Link',
    62: 'UNIX Hard Link',
    64: 'Windows Shortcut Following',
    65: 'Windows Hard Link',
    66: 'Improper Handling of File Names that Identify Virtual Resources',
    67: 'Improper Handling of Windows Device Names',
    69: 'Improper Handling of Windows ::DATA Alternate Data Stream',
    71: 'DEPRECATED: Apple .DS_Store',
    72: 'Improper Handling of Apple HFS+ Alternate Data Stream Path',
    73: 'External Control of File Name or Path',
    74: 'Improper Neutralization of Special Elements in Output Used by a '
        'Downstream Component',
    75: 'Failure to Sanitize Special Elements into a Different Plane',
    76: 'Improper Neutralization of Equivalent Special Elements',
    77: 'Improper Neutralization of Special Elements used in a Command',
    78: 'Improper Neutralization of Special Elements used in an OS Command',
    79: 'Improper Neutralization of Input During Web Page Generation',
    80: 'Improper Neutralization of Script-Related HTML Tags in a Web Page',
    81: 'Improper Neutralization of Script in an Error Message Web Page',
    82: 'Improper Neutralization of Script in Attributes of IMG Tags in a Web '
        'Page',
    83: 'Improper Neutralization of Script in Attributes in a Web Page',
    84: 'Improper Neutralization of Encoded URI Schemes in a Web Page',
    85: 'Doubled Character XSS Manipulations',
    86: 'Improper Neutralization of Invalid Characters in Identifiers in Web '
        'Pages',
    87: 'Improper Neutralization of Alternate XSS Syntax',
    88: 'Improper Neutralization of Argument Delimiters in a Command',
    89: 'Improper Neutralization of Special Elements used in an SQL Command',
    90: 'Improper Neutralization of Special Elements used in an LDAP Query',
    91: 'XML Injection',
    92: 'DEPRECATED: Improper Sanitization of Custom Special Characters',
    93: 'Improper Neutralization of CRLF Sequences',
    94: 'Improper Control of Generation of Code',
    95: 'Improper Neutralization of Directives in Dynamically Evaluated Code',
    96: 'Improper Neutralization of Directives in Statically Saved Code',
    97: 'Improper Neutralization of Server-Side Includes',
    98: 'Improper Control of Filename for Include/Require Statement in PHP '
        'Program',
    99: 'Improper Control of Resource Identifiers',
    102: 'Struts: Duplicate Validation Forms',
    103: 'Struts: Incomplete validate',
    104: 'Struts: Form Bean Does Not Extend Validation Class',
    105: 'Struts: Form Field Without Validator',
    106: 'Struts: Plug-in Framework not in Use',
    107: 'Struts: Unused Validation Form',
    108: 'Struts: Unvalidated Action Form',
    109: 'Struts: Validator Turned Off',
    110: 'Struts: Validator Without Form Field',
    111: 'Direct Use of Unsafe JNI',
    112: 'Missing XML Validation',
    113: 'Improper Neutralization of CRLF Sequences in HTTP Headers',
    114: 'Process Control',
    115: 'Misinterpretation of Input',
    116: 'Improper Encoding or Escaping of Output',
    117: 'Improper Output Neutralization for Logs',
    118: 'Incorrect Access of Indexable Resource',
    119: 'Improper Restriction of Operations within the Bounds of a Memory '
         'Buffer',
    120: 'Buffer Copy without Checking Size of Input',
    121: 'Stack-based Buffer Overflow',
    122: 'Heap-based Buffer Overflow',
    123: 'Write-what-where Condition',
    124: 'Buffer Underwrite',
    125: 'Out-of-bounds Read',
    126: 'Buffer Over-read',
    127: 'Buffer Under-read',
    128: 'Wrap-around Error',
    129: 'Improper Validation of Array Index',
    130: 'Improper Handling of Length Parameter Inconsistency',
    131: 'Incorrect Calculation of Buffer Size',
    132: 'DEPRECATED: Miscalculated Null Termination',
    134: 'Use of Externally-Controlled Format String',
    135: 'Incorrect Calculation of Multi-Byte String Length',
    138: 'Improper Neutralization of Special Elements',
    140: 'Improper Neutralization of Delimiters',
    141: 'Improper Neutralization of Parameter/Argument Delimiters',
    142: 'Improper Neutralization of Value Delimiters',
    143: 'Improper Neutralization of Record Delimiters',
    144: 'Improper Neutralization of Line Delimiters',
    145: 'Improper Neutralization of Section Delimiters',
    146: 'Improper Neutralization of Expression/Command Delimiters',
    147: 'Improper Neutralization of Input Terminators',
    148: 'Improper Neutralization of Input Leaders',
    149: 'Improper Neutralization of Quoting Syntax',
    150: 'Improper Neutralization of Escape, Meta, or Control Sequences',
    151: 'Improper Neutralization of Comment Delimiters',
    152: 'Improper Neutralization of Macro Symbols',
    153: 'Improper Neutralization of Substitution Characters',
    154: 'Improper Neutralization of Variable Name Delimiters',
    155: 'Improper Neutralization of Wildcards or Matching Symbols',
    156: 'Improper Neutralization of Whitespace',
    157: 'Failure to Sanitize Paired Delimiters',
    158: 'Improper Neutralization of Null Byte or NUL Character',
    159: 'Improper Handling of Invalid Use of Special Elements',
    160: 'Improper Neutralization of Leading Special Elements',
    161: 'Improper Neutralization of Multiple Leading Special Elements',
    162: 'Improper Neutralization of Trailing Special Elements',
    163: 'Improper Neutralization of Multiple Trailing Special Elements',
    164: 'Improper Neutralization of Internal Special Elements',
    165: 'Improper Neutralization of Multiple Internal Special Elements',
    166: 'Improper Handling of Missing Special Element',
    167: 'Improper Handling of Additional Special Element',
    168: 'Improper Handling of Inconsistent Special Elements',
    170: 'Improper Null Termination',
    172: 'Encoding Error',
    173: 'Improper Handling of Alternate Encoding',
    174: 'Double Decoding of the Same Data',
    175: 'Improper Handling of Mixed Encoding',
    176: 'Improper Handling of Unicode Encoding',
    177: 'Improper Handling of URL Encoding',
    178: 'Improper Handling of Case Sensitivity',
    179: 'Incorrect Behavior Order: Early Validation',
    180: 'Incorrect Behavior Order: Validate Before Canonicalize',
    181: 'Incorrect Behavior Order: Validate Before Filter',
    182: 'Collapse of Data into Unsafe Value',
    183: 'Permissive List of Allowed Inputs',
    184: 'Incomplete List of Disallowed Inputs',
    185: 'Incorrect Regular Expression',
    186: 'Overly Restrictive Regular Expression',
    187: 'Partial String Comparison',
    188: 'Reliance on Data/Memory Layout',
    190: 'Integer Overflow or Wraparound',
    191: 'Integer Underflow',
    192: 'Integer Coercion Error',
    193: 'Off-by-one Error',
    194: 'Unexpected Sign Extension',
    195: 'Signed to Unsigned Conversion Error',
    196: 'Unsigned to Signed Conversion Error',
    197: 'Numeric Truncation Error',
    198: 'Use of Incorrect Byte Ordering',
    200: 'Exposure of Sensitive Information to an Unauthorized Actor',
    201: 'Insertion of Sensitive Information Into Sent Data',
    202: 'Exposure of Sensitive Information Through Data Queries',
    203: 'Observable Discrepancy',
    204: 'Observable Response Discrepancy',
    205: 'Observable Behavioral Discrepancy',
    206: 'Observable Internal Behavioral Discrepancy',
    207: 'Observable Behavioral Discrepancy With Equivalent Products',
    208: 'Observable Timing Discrepancy',
    209: 'Generation of Error Message Containing Sensitive Information',
    210: 'Self-generated Error Message Containing Sensitive Information',
    211: 'Externally-Generated Error Message Containing Sensitive Information',
    212: 'Improper Removal of Sensitive Information Before Storage or Transfer',
    213: 'Exposure of Sensitive Information Due to Incompatible Policies',
    214: 'Invocation of Process Using Visible Sensitive Information',
    215: 'Insertion of Sensitive Information Into Debugging Code',
    216: 'DEPRECATED: Containment Errors',
    217: 'DEPRECATED: Failure to Protect Stored Data from Modification',
    218: 'DEPRECATED: Failure to provide confidentiality for stored data',
    219: 'Storage of File with Sensitive Data Under Web Root',
    220: 'Storage of File With Sensitive Data Under FTP Root',
    221: 'Information Loss or Omission',
    222: 'Truncation of Security-relevant Information',
    223: 'Omission of Security-relevant Information',
    224: 'Obscured Security-relevant Information by Alternate Name',
    225: 'DEPRECATED: General Information Management Problems',
    226: 'Sensitive Information in Resource Not Removed Before Reuse',
    228: 'Improper Handling of Syntactically Invalid Structure',
    229: 'Improper Handling of Values',
    230: 'Improper Handling of Missing Values',
    231: 'Improper Handling of Extra Values',
    232: 'Improper Handling of Undefined Values',
    233: 'Improper Handling of Parameters',
    234: 'Failure to Handle Missing Parameter',
    235: 'Improper Handling of Extra Parameters',
    236: 'Improper Handling of Undefined Parameters',
    237: 'Improper Handling of Structural Elements',
    238: 'Improper Handling of Incomplete Structural Elements',
    239: 'Failure to Handle Incomplete Element',
    240: 'Improper Handling of Inconsistent Structural Elements',
    241: 'Improper Handling of Unexpected Data Type',
    242: 'Use of Inherently Dangerous Function',
    243: 'Creation of chroot Jail Without Changing Working Directory',
    244: 'Improper Clearing of Heap Memory Before Release',
    245: 'J2EE Bad Practices: Direct Management of Connections',
    246: 'J2EE Bad Practices: Direct Use of Sockets',
    247: 'DEPRECATED: Reliance on DNS Lookups in a Security Decision',
    248: 'Uncaught Exception',
    249: 'DEPRECATED: Often Misused: Path Manipulation',
    250: 'Execution with Unnecessary Privileges',
    252: 'Unchecked Return Value',
    253: 'Incorrect Check of Function Return Value',
    256: 'Plaintext Storage of a Password',
    257: 'Storing Passwords in a Recoverable Format',
    258: 'Empty Password in Configuration File',
    259: 'Use of Hard-coded Password',
    260: 'Password in Configuration File',
    261: 'Weak Encoding for Password',
    262: 'Not Using Password Aging',
    263: 'Password Aging with Long Expiration',
    266: 'Incorrect Privilege Assignment',
    267: 'Privilege Defined With Unsafe Actions',
    268: 'Privilege Chaining',
    269: 'Improper Privilege Management',
    270: 'Privilege Context Switching Error',
    271: 'Privilege Dropping / Lowering Errors',
    272: 'Least Privilege Violation',
    273: 'Improper Check for Dropped Privileges',
    274: 'Improper Handling of Insufficient Privileges',
    276: 'Incorrect Default Permissions',
    277: 'Insecure Inherited Permissions',
    278: 'Insecure Preserved Inherited Permissions',
    279: 'Incorrect Execution-Assigned Permissions',
    280: 'Improper Handling of Insufficient Permissions or Privileges ',
    281: 'Improper Preservation of Permissions',
    282: 'Improper Ownership Management',
    283: 'Unverified Ownership',
    284: 'Improper Access Control',
    285: 'Improper Authorization',
    286: 'Incorrect User Management',
    287: 'Improper Authentication',
    288: 'Authentication Bypass Using an Alternate Path or Channel',
    289: 'Authentication Bypass by Alternate Name',
    290: 'Authentication Bypass by Spoofing',
    291: 'Reliance on IP Address for Authentication',
    292: 'DEPRECATED: Trusting Self-reported DNS Name',
    293: 'Using Referer Field for Authentication',
    294: 'Authentication Bypass by Capture-replay',
    295: 'Improper Certificate Validation',
    296: 'Improper Following of a Certificates Chain of Trust',
    297: 'Improper Validation of Certificate with Host Mismatch',
    298: 'Improper Validation of Certificate Expiration',
    299: 'Improper Check for Certificate Revocation',
    300: 'Channel Accessible by Non-Endpoint',
    301: 'Reflection Attack in an Authentication Protocol',
    302: 'Authentication Bypass by Assumed-Immutable Data',
    303: 'Incorrect Implementation of Authentication Algorithm',
    304: 'Missing Critical Step in Authentication',
    305: 'Authentication Bypass by Primary Weakness',
    306: 'Missing Authentication for Critical Function',
    307: 'Improper Restriction of Excessive Authentication Attempts',
    308: 'Use of Single-factor Authentication',
    309: 'Use of Password System for Primary Authentication',
    311: 'Missing Encryption of Sensitive Data',
    312: 'Cleartext Storage of Sensitive Information',
    313: 'Cleartext Storage in a File or on Disk',
    314: 'Cleartext Storage in the Registry',
    315: 'Cleartext Storage of Sensitive Information in a Cookie',
    316: 'Cleartext Storage of Sensitive Information in Memory',
    317: 'Cleartext Storage of Sensitive Information in GUI',
    318: 'Cleartext Storage of Sensitive Information in Executable',
    319: 'Cleartext Transmission of Sensitive Information',
    321: 'Use of Hard-coded Cryptographic Key',
    322: 'Key Exchange without Entity Authentication',
    323: 'Reusing a Nonce, Key Pair in Encryption',
    324: 'Use of a Key Past its Expiration Date',
    325: 'Missing Cryptographic Step',
    326: 'Inadequate Encryption Strength',
    327: 'Use of a Broken or Risky Cryptographic Algorithm',
    328: 'Use of Weak Hash',
    329: 'Generation of Predictable IV with CBC Mode',
    330: 'Use of Insufficiently Random Values',
    331: 'Insufficient Entropy',
    332: 'Insufficient Entropy in PRNG',
    333: 'Improper Handling of Insufficient Entropy in TRNG',
    334: 'Small Space of Random Values',
    335: 'Incorrect Usage of Seeds in Pseudo-Random Number Generator',
    336: 'Same Seed in Pseudo-Random Number Generator',
    337: 'Predictable Seed in Pseudo-Random Number Generator',
    338: 'Use of Cryptographically Weak Pseudo-Random Number Generator',
    339: 'Small Seed Space in PRNG',
    340: 'Generation of Predictable Numbers or Identifiers',
    341: 'Predictable from Observable State',
    342: 'Predictable Exact Value from Previous Values',
    343: 'Predictable Value Range from Previous Values',
    344: 'Use of Invariant Value in Dynamically Changing Context',
    345: 'Insufficient Verification of Data Authenticity',
    346: 'Origin Validation Error',
    347: 'Improper Verification of Cryptographic Signature',
    348: 'Use of Less Trusted Source',
    349: 'Acceptance of Extraneous Untrusted Data With Trusted Data',
    350: 'Reliance on Reverse DNS Resolution for a Security-Critical Action',
    351: 'Insufficient Type Distinction',
    352: 'Cross-Site Request Forgery',
    353: 'Missing Support for Integrity Check',
    354: 'Improper Validation of Integrity Check Value',
    356: 'Product UI does not Warn User of Unsafe Actions',
    357: 'Insufficient UI Warning of Dangerous Operations',
    358: 'Improperly Implemented Security Check for Standard',
    359: 'Exposure of Private Personal Information to an Unauthorized Actor',
    360: 'Trust of System Event Data',
    362: 'Concurrent Execution using Shared Resource with Improper '
         'Synchronization',
    363: 'Race Condition Enabling Link Following',
    364: 'Signal Handler Race Condition',
    365: 'DEPRECATED: Race Condition in Switch',
    366: 'Race Condition within a Thread',
    367: 'Time-of-check Time-of-use',
    368: 'Context Switching Race Condition',
    369: 'Divide By Zero',
    370: 'Missing Check for Certificate Revocation after Initial Check',
    372: 'Incomplete Internal State Distinction',
    373: 'DEPRECATED: State Synchronization Error',
    374: 'Passing Mutable Objects to an Untrusted Method',
    375: 'Returning a Mutable Object to an Untrusted Caller',
    377: 'Insecure Temporary File',
    378: 'Creation of Temporary File With Insecure Permissions',
    379: 'Creation of Temporary File in Directory with Insecure Permissions',
    382: 'J2EE Bad Practices: Use of System.exit',
    383: 'J2EE Bad Practices: Direct Use of Threads',
    384: 'Session Fixation',
    385: 'Covert Timing Channel',
    386: 'Symbolic Name not Mapping to Correct Object',
    390: 'Detection of Error Condition Without Action',
    391: 'Unchecked Error Condition',
    392: 'Missing Report of Error Condition',
    393: 'Return of Wrong Status Code',
    394: 'Unexpected Status Code or Return Value',
    395: 'Use of NullPointerException Catch to Detect NULL Pointer Dereference',
    396: 'Declaration of Catch for Generic Exception',
    397: 'Declaration of Throws for Generic Exception',
    400: 'Uncontrolled Resource Consumption',
    401: 'Missing Release of Memory after Effective Lifetime',
    402: 'Transmission of Private Resources into a New Sphere',
    403: 'Exposure of File Descriptor to Unintended Control Sphere',
    404: 'Improper Resource Shutdown or Release',
    405: 'Asymmetric Resource Consumption',
    406: 'Insufficient Control of Network Message Volume',
    407: 'Inefficient Algorithmic Complexity',
    408: 'Incorrect Behavior Order: Early Amplification',
    409: 'Improper Handling of Highly Compressed Data',
    410: 'Insufficient Resource Pool',
    412: 'Unrestricted Externally Accessible Lock',
    413: 'Improper Resource Locking',
    414: 'Missing Lock Check',
    415: 'Double Free',
    416: 'Use After Free',
    419: 'Unprotected Primary Channel',
    420: 'Unprotected Alternate Channel',
    421: 'Race Condition During Access to Alternate Channel',
    422: 'Unprotected Windows Messaging Channel',
    423: 'DEPRECATED: Proxied Trusted Channel',
    424: 'Improper Protection of Alternate Path',
    425: 'Direct Request',
    426: 'Untrusted Search Path',
    427: 'Uncontrolled Search Path Element',
    428: 'Unquoted Search Path or Element',
    430: 'Deployment of Wrong Handler',
    431: 'Missing Handler',
    432: 'Dangerous Signal Handler not Disabled During Sensitive Operations',
    433: 'Unparsed Raw Web Content Delivery',
    434: 'Unrestricted Upload of File with Dangerous Type',
    435: 'Improper Interaction Between Multiple Correctly-Behaving Entities',
    436: 'Interpretation Conflict',
    437: 'Incomplete Model of Endpoint Features',
    439: 'Behavioral Change in New Version or Environment',
    440: 'Expected Behavior Violation',
    441: 'Unintended Proxy or Intermediary',
    443: 'DEPRECATED: HTTP response splitting',
    444: 'Inconsistent Interpretation of HTTP Requests',
    446: 'UI Discrepancy for Security Feature',
    447: 'Unimplemented or Unsupported Feature in UI',
    448: 'Obsolete Feature in UI',
    449: 'The UI Performs the Wrong Action',
    450: 'Multiple Interpretations of UI Input',
    451: 'User Interface',
    453: 'Insecure Default Variable Initialization',
    454: 'External Initialization of Trusted Variables or Data Stores',
    455: 'Non-exit on Failed Initialization',
    456: 'Missing Initialization of a Variable',
    457: 'Use of Uninitialized Variable',
    458: 'DEPRECATED: Incorrect Initialization',
    459: 'Incomplete Cleanup',
    460: 'Improper Cleanup on Thrown Exception',
    462: 'Duplicate Key in Associative List',
    463: 'Deletion of Data Structure Sentinel',
    464: 'Addition of Data Structure Sentinel',
    466: 'Return of Pointer Value Outside of Expected Range',
    467: 'Use of sizeof',
    468: 'Incorrect Pointer Scaling',
    469: 'Use of Pointer Subtraction to Determine Size',
    470: 'Use of Externally-Controlled Input to Select Classes or Code',
    471: 'Modification of Assumed-Immutable Data',
    472: 'External Control of Assumed-Immutable Web Parameter',
    473: 'PHP External Variable Modification',
    474: 'Use of Function with Inconsistent Implementations',
    475: 'Undefined Behavior for Input to API',
    476: 'NULL Pointer Dereference',
    477: 'Use of Obsolete Function',
    478: 'Missing Default Case in Multiple Condition Expression',
    479: 'Signal Handler Use of a Non-reentrant Function',
    480: 'Use of Incorrect Operator',
    481: 'Assigning instead of Comparing',
    482: 'Comparing instead of Assigning',
    483: 'Incorrect Block Delimitation',
    484: 'Omitted Break Statement in Switch',
    486: 'Comparison of Classes by Name',
    487: 'Reliance on Package-level Scope',
    488: 'Exposure of Data Element to Wrong Session',
    489: 'Active Debug Code',
    491: 'Public cloneable',
    492: 'Use of Inner Class Containing Sensitive Data',
    493: 'Critical Public Variable Without Final Modifier',
    494: 'Download of Code Without Integrity Check',
    495: 'Private Data Structure Returned From A Public Method',
    496: 'Public Data Assigned to Private Array-Typed Field',
    497: 'Exposure of Sensitive System Information to an Unauthorized Control '
         'Sphere',
    498: 'Cloneable Class Containing Sensitive Information',
    499: 'Serializable Class Containing Sensitive Data',
    500: 'Public Static Field Not Marked Final',
    501: 'Trust Boundary Violation',
    502: 'Deserialization of Untrusted Data',
    506: 'Embedded Malicious Code',
    507: 'Trojan Horse',
    508: 'Non-Replicating Malicious Code',
    509: 'Replicating Malicious Code',
    510: 'Trapdoor',
    511: 'Logic/Time Bomb',
    512: 'Spyware',
    514: 'Covert Channel',
    515: 'Covert Storage Channel',
    516: 'DEPRECATED: Covert Timing Channel',
    520: '.NET Misconfiguration: Use of Impersonation',
    521: 'Weak Password Requirements',
    522: 'Insufficiently Protected Credentials',
    523: 'Unprotected Transport of Credentials',
    524: 'Use of Cache Containing Sensitive Information',
    525: 'Use of Web Browser Cache Containing Sensitive Information',
    526: 'Cleartext Storage of Sensitive Information in an Environment '
         'Variable',
    527: 'Exposure of Version-Control Repository to an Unauthorized Control '
         'Sphere',
    528: 'Exposure of Core Dump File to an Unauthorized Control Sphere',
    529: 'Exposure of Access Control List Files to an Unauthorized Control '
         'Sphere',
    530: 'Exposure of Backup File to an Unauthorized Control Sphere',
    531: 'Inclusion of Sensitive Information in Test Code',
    532: 'Insertion of Sensitive Information into Log File',
    533: 'DEPRECATED: Information Exposure Through Server Log Files',
    534: 'DEPRECATED: Information Exposure Through Debug Log Files',
    535: 'Exposure of Information Through Shell Error Message',
    536: 'Servlet Runtime Error Message Containing Sensitive Information',
    537: 'Java Runtime Error Message Containing Sensitive Information',
    538: 'Insertion of Sensitive Information into Externally-Accessible File or'
         ' Directory',
    539: 'Use of Persistent Cookies Containing Sensitive Information',
    540: 'Inclusion of Sensitive Information in Source Code',
    541: 'Inclusion of Sensitive Information in an Include File',
    542: 'DEPRECATED: Information Exposure Through Cleanup Log Files',
    543: 'Use of Singleton Pattern Without Synchronization in a Multithreaded '
         'Context',
    544: 'Missing Standardized Error Handling Mechanism',
    545: 'DEPRECATED: Use of Dynamic Class Loading',
    546: 'Suspicious Comment',
    547: 'Use of Hard-coded, Security-relevant Constants',
    548: 'Exposure of Information Through Directory Listing',
    549: 'Missing Password Field Masking',
    550: 'Server-generated Error Message Containing Sensitive Information',
    551: 'Incorrect Behavior Order: Authorization Before Parsing and '
         'Canonicalization',
    552: 'Files or Directories Accessible to External Parties',
    553: 'Command Shell in Externally Accessible Directory',
    554: 'ASP.NET Misconfiguration: Not Using Input Validation Framework',
    555: 'J2EE Misconfiguration: Plaintext Password in Configuration File',
    556: 'ASP.NET Misconfiguration: Use of Identity Impersonation',
    558: 'Use of getlogin',
    560: 'Use of umask',
    561: 'Dead Code',
    562: 'Return of Stack Variable Address',
    563: 'Assignment to Variable without Use',
    564: 'SQL Injection: Hibernate',
    565: 'Reliance on Cookies without Validation and Integrity Checking',
    566: 'Authorization Bypass Through User-Controlled SQL Primary Key',
    567: 'Unsynchronized Access to Shared Data in a Multithreaded Context',
    568: 'finalize',
    570: 'Expression is Always False',
    571: 'Expression is Always True',
    572: 'Call to Thread run',
    573: 'Improper Following of Specification by Caller',
    574: 'EJB Bad Practices: Use of Synchronization Primitives',
    575: 'EJB Bad Practices: Use of AWT Swing',
    576: 'EJB Bad Practices: Use of Java I/O',
    577: 'EJB Bad Practices: Use of Sockets',
    578: 'EJB Bad Practices: Use of Class Loader',
    579: 'J2EE Bad Practices: Non-serializable Object Stored in Session',
    580: 'clone',
    581: 'Object Model Violation: Just One of Equals and Hashcode Defined',
    582: 'Array Declared Public, Final, and Static',
    583: 'finalize',
    584: 'Return Inside Finally Block',
    585: 'Empty Synchronized Block',
    586: 'Explicit Call to Finalize',
    587: 'Assignment of a Fixed Address to a Pointer',
    588: 'Attempt to Access Child of a Non-structure Pointer',
    589: 'Call to Non-ubiquitous API',
    590: 'Free of Memory not on the Heap',
    591: 'Sensitive Data Storage in Improperly Locked Memory',
    592: 'DEPRECATED: Authentication Bypass Issues',
    593: 'Authentication Bypass: OpenSSL CTX Object Modified after SSL Objects '
         'are Created',
    594: 'J2EE Framework: Saving Unserializable Objects to Disk',
    595: 'Comparison of Object References Instead of Object Contents',
    596: 'DEPRECATED: Incorrect Semantic Object Comparison',
    597: 'Use of Wrong Operator in String Comparison',
    598: 'Use of GET Request Method With Sensitive Query Strings',
    599: 'Missing Validation of OpenSSL Certificate',
    600: 'Uncaught Exception in Servlet ',
    601: 'URL Redirection to Untrusted Site',
    602: 'Client-Side Enforcement of Server-Side Security',
    603: 'Use of Client-Side Authentication',
    605: 'Multiple Binds to the Same Port',
    606: 'Unchecked Input for Loop Condition',
    607: 'Public Static Final Field References Mutable Object',
    608: 'Struts: Non-private Field in ActionForm Class',
    609: 'Double-Checked Locking',
    610: 'Externally Controlled Reference to a Resource in Another Sphere',
    611: 'Improper Restriction of XML External Entity Reference',
    612: 'Improper Authorization of Index Containing Sensitive Information',
    613: 'Insufficient Session Expiration',
    614: 'Sensitive Cookie in HTTPS Session Without Secure Attribute',
    615: 'Inclusion of Sensitive Information in Source Code Comments',
    616: 'Incomplete Identification of Uploaded File Variables',
    617: 'Reachable Assertion',
    618: 'Exposed Unsafe ActiveX Method',
    619: 'Dangling Database Cursor',
    620: 'Unverified Password Change',
    621: 'Variable Extraction Error',
    622: 'Improper Validation of Function Hook Arguments',
    623: 'Unsafe ActiveX Control Marked Safe For Scripting',
    624: 'Executable Regular Expression Error',
    625: 'Permissive Regular Expression',
    626: 'Null Byte Interaction Error',
    627: 'Dynamic Variable Evaluation',
    628: 'Function Call with Incorrectly Specified Arguments',
    636: 'Not Failing Securely',
    637: 'Unnecessary Complexity in Protection Mechanism',
    638: 'Not Using Complete Mediation',
    639: 'Authorization Bypass Through User-Controlled Key',
    640: 'Weak Password Recovery Mechanism for Forgotten Password',
    641: 'Improper Restriction of Names for Files and Other Resources',
    642: 'External Control of Critical State Data',
    643: 'Improper Neutralization of Data within XPath Expressions',
    644: 'Improper Neutralization of HTTP Headers for Scripting Syntax',
    645: 'Overly Restrictive Account Lockout Mechanism',
    646: 'Reliance on File Name or Extension of Externally-Supplied File',
    647: 'Use of Non-Canonical URL Paths for Authorization Decisions',
    648: 'Incorrect Use of Privileged APIs',
    649: 'Reliance on Obfuscation or Encryption of Security-Relevant Inputs '
         'without Integrity Checking',
    650: 'Trusting HTTP Permission Methods on the Server Side',
    651: 'Exposure of WSDL File Containing Sensitive Information',
    652: 'Improper Neutralization of Data within XQuery Expressions',
    653: 'Improper Isolation or Compartmentalization',
    654: 'Reliance on a Single Factor in a Security Decision',
    655: 'Insufficient Psychological Acceptability',
    656: 'Reliance on Security Through Obscurity',
    657: 'Violation of Secure Design Principles',
    662: 'Improper Synchronization',
    663: 'Use of a Non-reentrant Function in a Concurrent Context',
    664: 'Improper Control of a Resource Through its Lifetime',
    665: 'Improper Initialization',
    666: 'Operation on Resource in Wrong Phase of Lifetime',
    667: 'Improper Locking',
    668: 'Exposure of Resource to Wrong Sphere',
    669: 'Incorrect Resource Transfer Between Spheres',
    670: 'Always-Incorrect Control Flow Implementation',
    671: 'Lack of Administrator Control over Security',
    672: 'Operation on a Resource after Expiration or Release',
    673: 'External Influence of Sphere Definition',
    674: 'Uncontrolled Recursion',
    675: 'Multiple Operations on Resource in Single-Operation Context',
    676: 'Use of Potentially Dangerous Function',
    680: 'Integer Overflow to Buffer Overflow',
    681: 'Incorrect Conversion between Numeric Types',
    682: 'Incorrect Calculation',
    683: 'Function Call With Incorrect Order of Arguments',
    684: 'Incorrect Provision of Specified Functionality',
    685: 'Function Call With Incorrect Number of Arguments',
    686: 'Function Call With Incorrect Argument Type',
    687: 'Function Call With Incorrectly Specified Argument Value',
    688: 'Function Call With Incorrect Variable or Reference as Argument',
    689: 'Permission Race Condition During Resource Copy',
    690: 'Unchecked Return Value to NULL Pointer Dereference',
    691: 'Insufficient Control Flow Management',
    692: 'Incomplete Denylist to Cross-Site Scripting',
    693: 'Protection Mechanism Failure',
    694: 'Use of Multiple Resources with Duplicate Identifier',
    695: 'Use of Low-Level Functionality',
    696: 'Incorrect Behavior Order',
    697: 'Incorrect Comparison',
    698: 'Execution After Redirect',
    703: 'Improper Check or Handling of Exceptional Conditions',
    704: 'Incorrect Type Conversion or Cast',
    705: 'Incorrect Control Flow Scoping',
    706: 'Use of Incorrectly-Resolved Name or Reference',
    707: 'Improper Neutralization',
    708: 'Incorrect Ownership Assignment',
    710: 'Improper Adherence to Coding Standards',
    732: 'Incorrect Permission Assignment for Critical Resource',
    733: 'Compiler Optimization Removal or Modification of Security-critical '
         'Code',
    749: 'Exposed Dangerous Method or Function',
    754: 'Improper Check for Unusual or Exceptional Conditions',
    755: 'Improper Handling of Exceptional Conditions',
    756: 'Missing Custom Error Page',
    757: 'Selection of Less-Secure Algorithm During Negotiation',
    758: 'Reliance on Undefined, Unspecified, or Implementation-Defined '
         'Behavior',
    759: 'Use of a One-Way Hash without a Salt',
    760: 'Use of a One-Way Hash with a Predictable Salt',
    761: 'Free of Pointer not at Start of Buffer',
    762: 'Mismatched Memory Management Routines',
    763: 'Release of Invalid Pointer or Reference',
    764: 'Multiple Locks of a Critical Resource',
    765: 'Multiple Unlocks of a Critical Resource',
    766: 'Critical Data Element Declared Public',
    767: 'Access to Critical Private Variable via Public Method',
    768: 'Incorrect Short Circuit Evaluation',
    769: 'DEPRECATED: Uncontrolled File Descriptor Consumption',
    770: 'Allocation of Resources Without Limits or Throttling',
    771: 'Missing Reference to Active Allocated Resource',
    772: 'Missing Release of Resource after Effective Lifetime',
    773: 'Missing Reference to Active File Descriptor or Handle',
    774: 'Allocation of File Descriptors or Handles Without Limits or '
         'Throttling',
    775: 'Missing Release of File Descriptor or Handle after Effective '
         'Lifetime',
    776: 'Improper Restriction of Recursive Entity References in DTDs',
    777: 'Regular Expression without Anchors',
    778: 'Insufficient Logging',
    779: 'Logging of Excessive Data',
    780: 'Use of RSA Algorithm without OAEP',
    781: 'Improper Address Validation in IOCTL with METHOD_NEITHER I/O Control '
         'Code',
    782: 'Exposed IOCTL with Insufficient Access Control',
    783: 'Operator Precedence Logic Error',
    784: 'Reliance on Cookies without Validation and Integrity Checking in a '
         'Security Decision',
    785: 'Use of Path Manipulation Function without Maximum-sized Buffer',
    786: 'Access of Memory Location Before Start of Buffer',
    787: 'Out-of-bounds Write',
    788: 'Access of Memory Location After End of Buffer',
    789: 'Memory Allocation with Excessive Size Value',
    790: 'Improper Filtering of Special Elements',
    791: 'Incomplete Filtering of Special Elements',
    792: 'Incomplete Filtering of One or More Instances of Special Elements',
    793: 'Only Filtering One Instance of a Special Element',
    794: 'Incomplete Filtering of Multiple Instances of Special Elements',
    795: 'Only Filtering Special Elements at a Specified Location',
    796: 'Only Filtering Special Elements Relative to a Marker',
    797: 'Only Filtering Special Elements at an Absolute Position',
    798: 'Use of Hard-coded Credentials',
    799: 'Improper Control of Interaction Frequency',
    804: 'Guessable CAPTCHA',
    805: 'Buffer Access with Incorrect Length Value',
    806: 'Buffer Access Using Size of Source Buffer',
    807: 'Reliance on Untrusted Inputs in a Security Decision',
    820: 'Missing Synchronization',
    821: 'Incorrect Synchronization',
    822: 'Untrusted Pointer Dereference',
    823: 'Use of Out-of-range Pointer Offset',
    824: 'Access of Uninitialized Pointer',
    825: 'Expired Pointer Dereference',
    826: 'Premature Release of Resource During Expected Lifetime',
    827: 'Improper Control of Document Type Definition',
    828: 'Signal Handler with Functionality that is not Asynchronous-Safe',
    829: 'Inclusion of Functionality from Untrusted Control Sphere',
    830: 'Inclusion of Web Functionality from an Untrusted Source',
    831: 'Signal Handler Function Associated with Multiple Signals',
    832: 'Unlock of a Resource that is not Locked',
    833: 'Deadlock',
    834: 'Excessive Iteration',
    835: 'Loop with Unreachable Exit Condition',
    836: 'Use of Password Hash Instead of Password for Authentication',
    837: 'Improper Enforcement of a Single, Unique Action',
    838: 'Inappropriate Encoding for Output Context',
    839: 'Numeric Range Comparison Without Minimum Check',
    841: 'Improper Enforcement of Behavioral Workflow',
    842: 'Placement of User into Incorrect Group',
    843: 'Access of Resource Using Incompatible Type',
    862: 'Missing Authorization',
    863: 'Incorrect Authorization',
    908: 'Use of Uninitialized Resource',
    909: 'Missing Initialization of Resource',
    910: 'Use of Expired File Descriptor',
    911: 'Improper Update of Reference Count',
    912: 'Hidden Functionality',
    913: 'Improper Control of Dynamically-Managed Code Resources',
    914: 'Improper Control of Dynamically-Identified Variables',
    915: 'Improperly Controlled Modification of Dynamically-Determined Object '
         'Attributes',
    916: 'Use of Password Hash With Insufficient Computational Effort',
    917: 'Improper Neutralization of Special Elements used in an Expression '
         'Language Statement',
    918: 'Server-Side Request Forgery',
    920: 'Improper Restriction of Power Consumption',
    921: 'Storage of Sensitive Data in a Mechanism without Access Control',
    922: 'Insecure Storage of Sensitive Information',
    923: 'Improper Restriction of Communication Channel to Intended Endpoints',
    924: 'Improper Enforcement of Message Integrity During Transmission in a '
         'Communication Channel',
    925: 'Improper Verification of Intent by Broadcast Receiver',
    926: 'Improper Export of Android Application Components',
    927: 'Use of Implicit Intent for Sensitive Communication',
    939: 'Improper Authorization in Handler for Custom URL Scheme',
    940: 'Improper Verification of Source of a Communication Channel',
    941: 'Incorrectly Specified Destination in a Communication Channel',
    942: 'Permissive Cross-domain Policy with Untrusted Domains',
    943: 'Improper Neutralization of Special Elements in Data Query Logic',
    1004: 'Sensitive Cookie Without HttpOnly Flag',
    1007: 'Insufficient Visual Distinction of Homoglyphs Presented to User',
    1021: 'Improper Restriction of Rendered UI Layers or Frames',
    1022: 'Use of Web Link to Untrusted Target with window.opener Access',
    1023: 'Incomplete Comparison with Missing Factors',
    1024: 'Comparison of Incompatible Types',
    1025: 'Comparison Using Wrong Factors',
    1037: 'Processor Optimization Removal or Modification of '
          'Security-critical Code',
    1038: 'Insecure Automated Optimizations',
    1039: 'Automated Recognition Mechanism with Inadequate Detection or '
          'Handling of Adversarial Input Perturbations',
    1041: 'Use of Redundant Code',
    1042: 'Static Member Data Element outside of a Singleton Class Element',
    1043: 'Data Element Aggregating an Excessively Large Number of '
          'Non-Primitive Elements',
    1044: 'Architecture with Number of Horizontal Layers Outside of Expected '
          'Range',
    1045: 'Parent Class with a Virtual Destructor and a Child Class without a '
          'Virtual Destructor',
    1046: 'Creation of Immutable Text Using String Concatenation',
    1047: 'Modules with Circular Dependencies',
    1048: 'Invokable Control Element with Large Number of Outward Calls',
    1049: 'Excessive Data Query Operations in a Large Data Table',
    1050: 'Excessive Platform Resource Consumption within a Loop',
    1051: 'Initialization with Hard-Coded Network Resource Configuration Data',
    1052: 'Excessive Use of Hard-Coded Literals in Initialization',
    1053: 'Missing Documentation for Design',
    1054: 'Invocation of a Control Element at an Unnecessarily Deep '
          'Horizontal Layer',
    1055: 'Multiple Inheritance from Concrete Classes',
    1056: 'Invokable Control Element with Variadic Parameters',
    1057: 'Data Access Operations Outside of Expected Data Manager Component',
    1058: 'Invokable Control Element in Multi-Thread Context with non-Final '
          'Static Storable or Member Element',
    1059: 'Insufficient Technical Documentation',
    1060: 'Excessive Number of Inefficient Server-Side Data Accesses',
    1061: 'Insufficient Encapsulation',
    1062: 'Parent Class with References to Child Class',
    1063: 'Creation of Class Instance within a Static Code Block',
    1064: 'Invokable Control Element with Signature Containing an Excessive '
          'Number of Parameters',
    1065: 'Runtime Resource Management Control Element in a Component Built '
          'to Run on Application Servers',
    1066: 'Missing Serialization Control Element',
    1067: 'Excessive Execution of Sequential Searches of Data Resource',
    1068: 'Inconsistency Between Implementation and Documented Design',
    1069: 'Empty Exception Block',
    1070: 'Serializable Data Element Containing non-Serializable Item Elements',
    1071: 'Empty Code Block',
    1072: 'Data Resource Access without Use of Connection Pooling',
    1073: 'Non-SQL Invokable Control Element with Excessive Number of Data '
          'Resource Accesses',
    1074: 'Class with Excessively Deep Inheritance',
    1075: 'Unconditional Control Flow Transfer outside of Switch Block',
    1076: 'Insufficient Adherence to Expected Conventions',
    1077: 'Floating Point Comparison with Incorrect Operator',
    1078: 'Inappropriate Source Code Style or Formatting',
    1079: 'Parent Class without Virtual Destructor Method',
    1080: 'Source Code File with Excessive Number of Lines of Code',
    1082: 'Class Instance Self Destruction Control Element',
    1083: 'Data Access from Outside Expected Data Manager Component',
    1084: 'Invokable Control Element with Excessive File or Data Access '
          'Operations',
    1085: 'Invokable Control Element with Excessive Volume of Commented-out '
          'Code',
    1086: 'Class with Excessive Number of Child Classes',
    1087: 'Class with Virtual Method without a Virtual Destructor',
    1088: 'Synchronous Access of Remote Resource without Timeout',
    1089: 'Large Data Table with Excessive Number of Indices',
    1090: 'Method Containing Access of a Member Element from Another Class',
    1091: 'Use of Object without Invoking Destructor Method',
    1092: 'Use of Same Invokable Control Element in Multiple Architectural '
          'Layers',
    1093: 'Excessively Complex Data Representation',
    1094: 'Excessive Index Range Scan for a Data Resource',
    1095: 'Loop Condition Value Update within the Loop',
    1096: 'Singleton Class Instance Creation without Proper Locking or '
          'Synchronization',
    1097: 'Persistent Storable Data Element without Associated Comparison '
          'Control Element',
    1098: 'Data Element containing Pointer Item without Proper Copy Control '
          'Element',
    1099: 'Inconsistent Naming Conventions for Identifiers',
    1100: 'Insufficient Isolation of System-Dependent Functions',
    1101: 'Reliance on Runtime Component in Generated Code',
    1102: 'Reliance on Machine-Dependent Data Representation',
    1103: 'Use of Platform-Dependent Third Party Components',
    1104: 'Use of Unmaintained Third Party Components',
    1105: 'Insufficient Encapsulation of Machine-Dependent Functionality',
    1106: 'Insufficient Use of Symbolic Constants',
    1107: 'Insufficient Isolation of Symbolic Constant Definitions',
    1108: 'Excessive Reliance on Global Variables',
    1109: 'Use of Same Variable for Multiple Purposes',
    1110: 'Incomplete Design Documentation',
    1111: 'Incomplete I/O Documentation',
    1112: 'Incomplete Documentation of Program Execution',
    1113: 'Inappropriate Comment Style',
    1114: 'Inappropriate Whitespace Style',
    1115: 'Source Code Element without Standard Prologue',
    1116: 'Inaccurate Comments',
    1117: 'Callable with Insufficient Behavioral Summary',
    1118: 'Insufficient Documentation of Error Handling Techniques',
    1119: 'Excessive Use of Unconditional Branching',
    1120: 'Excessive Code Complexity',
    1121: 'Excessive McCabe Cyclomatic Complexity',
    1122: 'Excessive Halstead Complexity',
    1123: 'Excessive Use of Self-Modifying Code',
    1124: 'Excessively Deep Nesting',
    1125: 'Excessive Attack Surface',
    1126: 'Declaration of Variable with Unnecessarily Wide Scope',
    1127: 'Compilation with Insufficient Warnings or Errors',
    1164: 'Irrelevant Code',
    1173: 'Improper Use of Validation Framework',
    1174: 'ASP.NET Misconfiguration: Improper Model Validation',
    1176: 'Inefficient CPU Computation',
    1177: 'Use of Prohibited Code',
    1187: 'DEPRECATED: Use of Uninitialized Resource',
    1188: 'Insecure Default Initialization of Resource',
    1189: 'Improper Isolation of Shared Resources on System-on-a-Chip',
    1190: 'DMA Device Enabled Too Early in Boot Phase',
    1191: 'On-Chip Debug and Test Interface With Improper Access Control',
    1192: 'System-on-Chip',
    1193: 'Power-On of Untrusted Execution Core Before Enabling Fabric Access '
          'Control',
    1204: 'Generation of Weak Initialization Vector',
    1209: 'Failure to Disable Reserved Bits',
    1220: 'Insufficient Granularity of Access Control',
    1221: 'Incorrect Register Defaults or Module Parameters',
    1222: 'Insufficient Granularity of Address Regions Protected by Register '
          'Locks',
    1223: 'Race Condition for Write-Once Attributes',
    1224: 'Improper Restriction of Write-Once Bit Fields',
    1229: 'Creation of Emergent Resource',
    1230: 'Exposure of Sensitive Information Through Metadata',
    1231: 'Improper Prevention of Lock Bit Modification',
    1232: 'Improper Lock Behavior After Power State Transition',
    1233: 'Security-Sensitive Hardware Controls with Missing Lock Bit '
          'Protection',
    1234: 'Hardware Internal or Debug Modes Allow Override of Locks',
    1235: 'Incorrect Use of Autoboxing and Unboxing for Performance Critical '
          'Operations',
    1236: 'Improper Neutralization of Formula Elements in a CSV File',
    1239: 'Improper Zeroization of Hardware Register',
    1240: 'Use of a Cryptographic Primitive with a Risky Implementation',
    1241: 'Use of Predictable Algorithm in Random Number Generator',
    1242: 'Inclusion of Undocumented Features or Chicken Bits',
    1243: 'Sensitive Non-Volatile Information Not Protected During Debug',
    1244: 'Internal Asset Exposed to Unsafe Debug Access Level or State',
    1245: 'Improper Finite State Machines',
    1246: 'Improper Write Handling in Limited-write Non-Volatile Memories',
    1247: 'Improper Protection Against Voltage and Clock Glitches',
    1248: 'Semiconductor Defects in Hardware Logic with Security-Sensitive '
          'Implications',
    1249: 'Application-Level Admin Tool with Inconsistent View of Underlying '
          'Operating System',
    1250: 'Improper Preservation of Consistency Between Independent '
          'Representations of Shared State',
    1251: 'Mirrored Regions with Different Values',
    1252: 'CPU Hardware Not Configured to Support Exclusivity of Write and '
          'Execute Operations',
    1253: 'Incorrect Selection of Fuse Values',
    1254: 'Incorrect Comparison Logic Granularity',
    1255: 'Comparison Logic is Vulnerable to Power Side-Channel Attacks',
    1256: 'Improper Restriction of Software Interfaces to Hardware Features',
    1257: 'Improper Access Control Applied to Mirrored or Aliased Memory '
          'Regions',
    1258: 'Exposure of Sensitive System Information Due to Uncleared Debug '
          'Information',
    1259: 'Improper Restriction of Security Token Assignment',
    1260: 'Improper Handling of Overlap Between Protected Memory Ranges',
    1261: 'Improper Handling of Single Event Upsets',
    1262: 'Improper Access Control for Register Interface',
    1263: 'Improper Physical Access Control',
    1264: 'Hardware Logic with Insecure De-Synchronization between Control and '
          'Data Channels',
    1265: 'Unintended Reentrant Invocation of Non-reentrant Code Via Nested '
          'Calls',
    1266: 'Improper Scrubbing of Sensitive Data from Decommissioned Device',
    1267: 'Policy Uses Obsolete Encoding',
    1268: 'Policy Privileges are not Assigned Consistently Between Control and '
          'Data Agents',
    1269: 'Product Released in Non-Release Configuration',
    1270: 'Generation of Incorrect Security Tokens',
    1271: 'Uninitialized Value on Reset for Registers Holding Security '
          'Settings',
    1272: 'Sensitive Information Uncleared Before Debug/Power State Transition',
    1273: 'Device Unlock Credential Sharing',
    1274: 'Improper Access Control for Volatile Memory Containing Boot Code',
    1275: 'Sensitive Cookie with Improper SameSite Attribute',
    1276: 'Hardware Child Block Incorrectly Connected to Parent System',
    1277: 'Firmware Not Updateable',
    1278: 'Missing Protection Against Hardware Reverse Engineering Using '
          'Integrated Circuit',
    1279: 'Cryptographic Operations are run Before Supporting Units are Ready',
    1280: 'Access Control Check Implemented After Asset is Accessed',
    1281: 'Sequence of Processor Instructions Leads to Unexpected Behavior',
    1282: 'Assumed-Immutable Data is Stored in Writable Memory',
    1283: 'Mutable Attestation or Measurement Reporting Data',
    1284: 'Improper Validation of Specified Quantity in Input',
    1285: 'Improper Validation of Specified Index, Position, or Offset in '
          'Input',
    1286: 'Improper Validation of Syntactic Correctness of Input',
    1287: 'Improper Validation of Specified Type of Input',
    1288: 'Improper Validation of Consistency within Input',
    1289: 'Improper Validation of Unsafe Equivalence in Input',
    1290: 'Incorrect Decoding of Security Identifiers ',
    1291: 'Public Key Re-Use for Signing both Debug and Production Code',
    1292: 'Incorrect Conversion of Security Identifiers',
    1293: 'Missing Source Correlation of Multiple Independent Data',
    1294: 'Insecure Security Identifier Mechanism',
    1295: 'Debug Messages Revealing Unnecessary Information',
    1296: 'Incorrect Chaining or Granularity of Debug Components',
    1297: 'Unprotected Confidential Information on Device is Accessible by '
          'OSAT Vendors',
    1298: 'Hardware Logic Contains Race Conditions',
    1299: 'Missing Protection Mechanism for Alternate Hardware Interface',
    1300: 'Improper Protection of Physical Side Channels',
    1301: 'Insufficient or Incomplete Data Removal within Hardware Component',
    1302: 'Missing Security Identifier',
    1303: 'Non-Transparent Sharing of Microarchitectural Resources',
    1304: 'Improperly Preserved Integrity of Hardware Configuration State '
          'During a Power Save/Restore Operation',
    1310: 'Missing Ability to Patch ROM Code',
    1311: 'Improper Translation of Security Attributes by Fabric Bridge',
    1312: 'Missing Protection for Mirrored Regions in On-Chip Fabric Firewall',
    1313: 'Hardware Allows Activation of Test or Debug Logic at Runtime',
    1314: 'Missing Write Protection for Parametric Data Values',
    1315: 'Improper Setting of Bus Controlling Capability in Fabric End-point',
    1316: 'Fabric-Address Map Allows Programming of Unwarranted Overlaps of '
          'Protected and Unprotected Ranges',
    1317: 'Improper Access Control in Fabric Bridge',
    1318: 'Missing Support for Security Features in On-chip Fabrics or Buses',
    1319: 'Improper Protection against Electromagnetic Fault Injection',
    1320: 'Improper Protection for Outbound Error Messages and Alert Signals',
    1321: 'Improperly Controlled Modification of Object Prototype Attributes',
    1322: 'Use of Blocking Code in Single-threaded, Non-blocking Context',
    1323: 'Improper Management of Sensitive Trace Data',
    1324: 'DEPRECATED: Sensitive Information Accessible by Physical Probing '
          'of JTAG Interface',
    1325: 'Improperly Controlled Sequential Memory Allocation',
    1326: 'Missing Immutable Root of Trust in Hardware',
    1327: 'Binding to an Unrestricted IP Address',
    1328: 'Security Version Number Mutable to Older Versions',
    1329: 'Reliance on Component That is Not Updateable',
    1330: 'Remanent Data Readable after Memory Erase',
    1331: 'Improper Isolation of Shared Resources in Network On Chip',
    1332: 'Improper Handling of Faults that Lead to Instruction Skips',
    1333: 'Inefficient Regular Expression Complexity',
    1334: 'Unauthorized Error Injection Can Degrade Hardware Redundancy',
    1335: 'Incorrect Bitwise Shift of Integer',
    1336: 'Improper Neutralization of Special Elements Used in a Template '
          'Engine',
    1338: 'Improper Protections Against Hardware Overheating',
    1339: 'Insufficient Precision or Accuracy of a Real Number',
    1341: 'Multiple Releases of Same Resource or Handle',
    1342: 'Information Exposure through Microarchitectural State after '
          'Transient Execution',
    1351: 'Improper Handling of Hardware Behavior in Exceptionally Cold '
          'Environments',
    1357: 'Reliance on Insufficiently Trustworthy Component',
    1384: 'Improper Handling of Physical or Environmental Conditions',
    1385: 'Missing Origin Validation in WebSockets',
    1386: 'Insecure Operation on Windows Junction / Mount Point',
    1389: 'Incorrect Parsing of Numbers with Different Radices',
    1390: 'Weak Authentication',
    1391: 'Use of Weak Credentials',
    1392: 'Use of Default Credentials',
    1393: 'Use of Default Password',
    1394: 'Use of Default Cryptographic Key',
    1395: 'Dependency on Vulnerable Third-Party Component'
}

UPPER_VERSION_FROM_DETAIL_A = re.compile(r"(?:(( prior to)|( before)|( upgrading to)|( update to [a-z\s-]+)|( update [a-z\s-]+ to))( version)? )(?P<version>\d[^\s,]+)", re.IGNORECASE)

UPPER_VERSION_FROM_DETAIL_B = re.compile(r"(?:(( fix was released in)|( been addressed in)|( until)|( migrate to))( version)? )(?P<version>\d[^\s,]+)", re.IGNORECASE)

VERSION_RANGE = re.compile(r"vers:\S+/(?P<lower_comparator>[><=]{1,2})(?P<lower_version>\S+)\|(?P<upper_comparator>[><=]{1,2})(?P<upper_version>\S+)")

TOML_TEMPLATE = {
    "depscan_version": get_version(),
    "note": [
        {"audience": "", "category": "", "text": "", "title": ""},
    ],
    "reference": [
        {"category": "", "summary": "", "url": ""},
        {"category": "", "summary": "", "url": ""},
    ],
    "distribution": {"label": "", "text": "", "url": ""},
    "document": {"category": "csaf_vex", "title": "Your Title"},
    "product_tree": {"easy_import": ""},
    "publisher": {
        "category": "vendor",
        "contact_details": "vendor@mcvendorson.com",
        "name": "Vendor McVendorson",
        "namespace": "https://appthreat.com",
    },
    "tracking": {
        "current_release_date": "",
        "id": "",
        "initial_release_date": "",
        "status": "draft",
        "version": "",
        "revision_history": [{"date": "", "number": "", "summary": ""}],
    },
}
