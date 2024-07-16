from datetime import datetime

from depscan.lib import config
from semver import Version
from depscan.lib.package_query.pkg_query import compute_time_risks, calculate_risk_score


def pypi_pkg_risk(pkg_metadata, is_private_pkg, scope, pkg):
    """
    Calculate various package risks based on the metadata from pypi.

    :param pkg_metadata: A dict containing the metadata of the package from PyPI
    :param is_private_pkg: Boolean to indicate if this package is private
    :param scope: Package scope
    :param pkg: Package object

    :return: Dict of risk metrics and corresponding PyPI values.
    """
    risk_metrics = {
        "pkg_deprecated_risk": False,
        "pkg_version_deprecated_risk": False,
        "pkg_version_missing_risk": False,
        "pkg_min_versions_risk": False,
        "created_now_quarantine_seconds_risk": False,
        "latest_now_max_seconds_risk": False,
        "mod_create_min_seconds_risk": False,
        "pkg_min_maintainers_risk": False,
        "pkg_private_on_public_registry_risk": False,
    }
    info = pkg_metadata.get("info", {})
    versions_dict = pkg_metadata.get("releases", {})
    versions = [ver[0] for k, ver in versions_dict.items() if ver]
    is_deprecated = info.get("yanked") and info.get("yanked_reason")
    is_version_deprecated = False
    if not is_deprecated and pkg and pkg.get("version"):
        theversion = versions_dict.get(pkg.get("version"), [])
        if isinstance(theversion, list) and len(theversion) > 0:
            theversion = theversion[0]
        elif theversion and theversion.get("yanked"):
            is_version_deprecated = True
        # Check if the version exists in the registry
        if not theversion:
            risk_metrics["pkg_version_missing_risk"] = True
            risk_metrics["pkg_version_missing_value"] = 1
    # Some packages like pypi:azure only mention deprecated in the description
    # without yanking the package
    pkg_description = info.get("description", "").lower()
    if not is_deprecated and (
        "is deprecated" in pkg_description
        or "no longer maintained" in pkg_description
    ):
        is_deprecated = True
    latest_deprecated = False
    version_nums = list(versions_dict.keys())
    # Ignore empty versions without metadata. Thanks pypi
    version_nums = [ver for ver in version_nums if versions_dict.get(ver)]
    try:
        first_version_num = min(
            version_nums,
            key=lambda x: Version.parse(x, optional_minor_and_patch=True),
        )
        latest_version_num = max(
            version_nums,
            key=lambda x: Version.parse(x, optional_minor_and_patch=True),
        )
    except (ValueError, TypeError):
        first_version_num = version_nums[0]
        latest_version_num = version_nums[-1]
    first_version = versions_dict.get(first_version_num)[0]
    latest_version = versions_dict.get(latest_version_num)[0]

    # Is the private package available publicly? Dependency confusion.
    if is_private_pkg and pkg_metadata:
        risk_metrics["pkg_private_on_public_registry_risk"] = True
        risk_metrics["pkg_private_on_public_registry_value"] = 1

    # If the package has fewer than minimum number of versions
    if len(versions):
        if len(versions) < config.pkg_min_versions:
            risk_metrics["pkg_min_versions_risk"] = True
            risk_metrics["pkg_min_versions_value"] = len(versions)
        # Check if the latest version is deprecated
        if latest_version and latest_version.get("yanked"):
            latest_deprecated = True

    # Created and modified time related checks
    if first_version and latest_version:
        created = first_version.get("upload_time")
        modified = latest_version.get("upload_time")
        if created and modified:
            modified_dt = datetime.fromisoformat(modified)
            created_dt = datetime.fromisoformat(created)
            mod_create_diff = modified_dt - created_dt
            latest_now_diff = datetime.now() - modified_dt
            created_now_diff = datetime.now() - created_dt
            risk_metrics = compute_time_risks(
                risk_metrics, created_now_diff, mod_create_diff, latest_now_diff
            )

    # Is the package deprecated
    if is_deprecated or latest_deprecated:
        risk_metrics["pkg_deprecated_risk"] = True
        risk_metrics["pkg_deprecated_value"] = 1
    elif is_version_deprecated:
        risk_metrics["pkg_version_deprecated_risk"] = True
        risk_metrics["pkg_version_deprecated_value"] = 1
    # Add package scope related weight
    if scope:
        risk_metrics[f"pkg_{scope}_scope_risk"] = True
        risk_metrics[f"pkg_{scope}_scope_value"] = 1

    risk_metrics["risk_score"] = calculate_risk_score(risk_metrics)
    return risk_metrics
