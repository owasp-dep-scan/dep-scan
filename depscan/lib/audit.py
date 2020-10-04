from vdb.lib.npm import NpmSource

# Dict mapping project type to the audit source
type_audit_map = {"nodejs": NpmSource(), "js": NpmSource()}


def audit(project_type, pkg_list, report_file):
    """
    Method to audit packages using remote source such as npm advisory

    :param project_type: Project type
    :param pkg_list: List of packages
    :param report_file: Report file
    """
    app_info = {"name": "appthreat-depscan", "version": "1.0.0"}
    results = type_audit_map[project_type].bulk_search(
        app_info=app_info, pkg_list=pkg_list
    )
    return results
