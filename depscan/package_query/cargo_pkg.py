from datetime import datetime

from depscan.lib import config
from depscan.package_query.pkg_query import compute_time_risks, calculate_risk_score


def cargo_pkg_risk(pkg_metadata, is_private_pk, scope, pkg):
    """
    Calculate various package risks based on the metadata from cargo.
    """
    risk_metrics = {
        "pkg_deprecated_risk": False,
        "pkg_version_deprecated_risk": False,
        "pkg_version_missing_risk": False,
        "pkg_includes_binary_risk": False,
        "pkg_min_versions_risk": False,
        "created_now_quarantine_seconds_risk": False,
        "latest_now_max_seconds_risk": False,
        "mod_create_min_seconds_risk": False,
        "pkg_min_maintainers_risk": False,
        "pkg_node_version_risk": False,
        "pkg_private_on_public_registry_risk": False,
    }

    print(risk_metrics)
