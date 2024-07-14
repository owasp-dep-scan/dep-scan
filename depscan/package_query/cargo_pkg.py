from datetime import datetime

from depscan.lib import config
from depscan.package_query.pkg_query import metadata_from_registry, compute_time_risks, calculate_risk_score


def cargo_metadata(scoped_pkgs, pkg_list, private_ns=None):
    """
    Method to query cargo for the package metadata
    """
    return metadata_from_registry("cargo", scoped_pkgs, pkg_list, private_ns)


def cargo_pkg_risk():
    """
    Calculate various package risks based on the metadata from cargo.
    """
    pass
