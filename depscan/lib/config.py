import os
import sys
from os.path import dirname, exists, join


def resource_path(relative_path):
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
    "Microsoft.IdentityModel.Clients.ActiveDirectory": "active_directory_authentication_library",
    "starkbank_ecdsa": "ecdsa-elixir",
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
    "js": "npm",
    "javascript": "npm",
    "nodejs": "npm",
    "go": "golang",
    "golang": "golang",
    "ruby": "gem",
    "php": "composer",
    "dotnet": "nuget",
    "csharp": "nuget",
    "rust": "cargo",
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
    "generic",
    "qpkg",
    "buildroot",
    "coreos",
    "ebuild",
    "alpine",
    "alma",
    "debian",
    "ubuntu",
    "amazon",
    "redhat",
    "rocky",
    "archlinux",
    "suse",
    "photon",
    "microsoft",
)


def get_float_from_env(name, default):
    value = os.getenv(name.upper(), default)
    try:
        value = float(value)
    except ValueError:
        value = default
    return value


def get_int_from_env(name, default):
    return int(get_float_from_env(name, default))


npm_server = "https://registry.npmjs.org"
npm_app_info = {"name": "appthreat-depscan", "version": "1.0.0"}

pypi_server = "https://pypi.org/pypi"

# Package risk scoring using a simple weighted formula with no backing research
# All parameters and their max value and weight can be overridden using environment variables

# Some constants and defaults
seconds_in_day = 24 * 60 * 60
seconds_in_hour = 60 * 60
default_max_value = 100
default_weight = 1

# Package should have at least 3 versions
pkg_min_versions = get_float_from_env("pkg_min_versions", 3)
pkg_min_versions_max = get_float_from_env("pkg_min_versions_max", 100)
pkg_min_versions_weight = get_float_from_env("pkg_min_versions_weight", 2)

# At least 12 hours difference between the creation and modified time
mod_create_min_seconds = get_float_from_env(
    "mod_create_min_seconds", 12 * seconds_in_hour
)
mod_create_min_seconds_max = get_float_from_env(
    "mod_create_min_seconds_max", 1000 * seconds_in_day
)
mod_create_min_seconds_weight = get_float_from_env("mod_create_min_seconds_weight", 1)

# At least 12 hours difference between the latest version and the current time
latest_now_min_seconds = get_float_from_env(
    "latest_now_min_seconds", 12 * seconds_in_hour
)
latest_now_min_seconds_max = get_float_from_env(
    "latest_now_min_seconds_max", 1000 * seconds_in_day
)
latest_now_min_seconds_weight = get_float_from_env("latest_now_min_seconds_weight", 0.5)

# Time period after which certain risks can be considered safe. Quarantine period
# For eg: Packages that are over 1 year old
created_now_quarantine_seconds = get_float_from_env(
    "created_now_quarantine_seconds", 365 * seconds_in_day
)
created_now_quarantine_seconds_max = get_float_from_env(
    "created_now_quarantine_seconds_max", 365 * seconds_in_day
)
created_now_quarantine_seconds_weight = get_float_from_env(
    "created_now_quarantine_seconds_weight", 0.5
)

# Max package age - 6 years
latest_now_max_seconds = get_float_from_env(
    "latest_now_max_seconds", 6 * 365 * seconds_in_day
)
latest_now_max_seconds_max = get_float_from_env(
    "latest_now_max_seconds_max", 6 * 365 * seconds_in_day
)
latest_now_max_seconds_weight = get_float_from_env("latest_now_max_seconds_weight", 0.5)

# Package should have at least 2 maintainers
pkg_min_maintainers = get_float_from_env("pkg_min_maintainers", 2)
pkg_min_maintainers_max = get_float_from_env("pkg_min_maintainers_max", 10)
pkg_min_maintainers_weight = get_float_from_env("pkg_min_maintainers_weight", 2)

# Package should have at least 2 users
pkg_min_users = get_float_from_env("pkg_min_users", 2)
pkg_min_users_max = get_float_from_env("pkg_min_users_max", 20)
pkg_min_users_weight = get_float_from_env("pkg_min_users_weight", 0.25)

# Package with install scripts (npm)
pkg_install_scripts_max = get_float_from_env("pkg_install_scripts_max", 0)
pkg_install_scripts_weight = get_float_from_env("pkg_install_scripts_weight", 2)

# Node version risk
pkg_node_version = os.getenv("pkg_node_version".upper(), "0.,4,6")
pkg_node_version_max = get_float_from_env("pkg_node_version_max", 16)
pkg_node_version_weight = get_float_from_env("pkg_node_version_weight", 0.5)

# Package deprecated
pkg_deprecated_weight = get_float_from_env("pkg_deprecated_weight", 1)
pkg_deprecated_max = get_float_from_env("pkg_deprecated_max", 1)

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
    "pkg_private_on_public_registry": "Private package is public",
}

# Package max risk score. All packages above this level will be reported
pkg_max_risk_score = get_float_from_env("pkg_max_risk_score", 0.5)

# Default request timeout
request_timeout_sec = get_int_from_env("request_timeout_sec", 20)

# Number of api failures that would stop the risk audit completely
max_request_failures = get_int_from_env("max_request_failures", 5)
