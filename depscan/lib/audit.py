from vdb.lib.npm import NpmSource

from depscan.lib import config as config
from depscan.lib.pkg_query import npm_metadata, pypi_metadata

# Dict mapping project type to the audit source
type_audit_map = {"nodejs": NpmSource(), "js": NpmSource()}

# Dict mapping project type to risk audit
risk_audit_map = {
    "nodejs": npm_metadata,
    "js": npm_metadata,
    "python": pypi_metadata,
    "py": pypi_metadata,
}


def audit(project_type, pkg_list, report_file):
    """
    Method to audit packages using remote source such as npm advisory

    :param project_type: Project type
    :param pkg_list: List of packages
    :param report_file: Report file
    """
    results = type_audit_map[project_type].bulk_search(
        app_info=config.npm_app_info, pkg_list=pkg_list
    )
    return results


def risk_audit(project_type, scoped_pkgs, private_ns, pkg_list, report_file):
    """
    Method to perform risk audit for packages using package managers api

    :param project_type: Project type
    :param private_ns: Private namespace
    :param pkg_list: List of packages
    :param report_file: Report file
    """
    audit_fn = risk_audit_map[project_type]
    results = audit_fn(scoped_pkgs, pkg_list, private_ns)
    return results
