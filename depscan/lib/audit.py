from vdb.lib.npm import NpmSource

from depscan.lib import config
from depscan.lib.pkg_query import npm_metadata, pypi_metadata

# Dict mapping project type to the audit source
type_audit_map = {"nodejs": NpmSource(), "js": NpmSource(), "javascript": NpmSource(), "ts": NpmSource(),
                  "typescript": NpmSource(), "npm": NpmSource()}

# Dict mapping project type to risk audit
risk_audit_map = {
    "npm": npm_metadata,
    "nodejs": npm_metadata,
    "js": npm_metadata,
    "javascript": npm_metadata,
    "ts": npm_metadata,
    "typescript": npm_metadata,
    "python": pypi_metadata,
    "py": pypi_metadata,
    "pypi": pypi_metadata,
}


def audit(project_type, pkg_list):
    """
    Method to audit packages using remote source such as npm advisory

    :param project_type: Project type
    :param pkg_list: List of packages
    :return: Results
    """
    results = type_audit_map[project_type].bulk_search(
        app_info=config.npm_app_info, pkg_list=pkg_list
    )
    return results


def risk_audit(project_type, scoped_pkgs, private_ns, pkg_list):
    """
    Method to perform risk audit for packages using package managers api

    :param scoped_pkgs: A list of scoped packages.
    :param project_type: Project type
    :param private_ns: Private namespace
    :param pkg_list: List of packages
    :return: Results of risk audit
    """
    audit_fn = risk_audit_map[project_type]
    results = audit_fn(scoped_pkgs, pkg_list, private_ns)
    return results
