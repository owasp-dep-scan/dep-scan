from datetime import datetime, timezone

from depscan.lib import config
from depscan.lib.package_query.pkg_query import compute_time_risks, calculate_risk_score
from semver import Version

def set_binary_risks(risk_metrics, current_version, latest_version):
    """
    If current version has bin_names. then we should set "pkg_includes_binary_risk" as True.
    and add the number of bin_names to the "pkg_includes_binary_value" key.
    """
    version = current_version if current_version else latest_version
    bin_names = version.get('bin_names', [])
    risk_metrics["pkg_includes_binary_risk"] = True if len(bin_names)>0 else False
    risk_metrics["pkg_includes_binary_value"] = len(bin_names)


def cargo_pkg_risk(pkg_metadata, is_private_pkg, scope, pkg):
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
    versions_list = pkg_metadata.get("versions", [])
    versions_dict = {
        crate_version.get('num'): crate_version
        for crate_version in versions_list}
    versions_nums = [
        crate_version.get('num')
        for crate_version in versions_list]

    is_deprecated = versions_list[0].get("yanked")
    is_version_deprecated = False
    info = pkg_metadata.get("crate", {})
    if not is_deprecated and pkg and pkg.get("version"):
        theversion = versions_dict.get(pkg.get("version"), {})
        if isinstance(theversion, dict) and len(theversion) > 0:
            theversion = theversion.get('num')
        elif theversion and theversion.get("yanked"):
            is_version_deprecated = True
        # Check if the version exists in the registry
        if not theversion:
            risk_metrics["pkg_version_missing_risk"] = True
            risk_metrics["pkg_version_missing_value"] = 1

    pkg_description = info.get("description", "").lower()
    if not is_deprecated and (
        "is deprecated" in pkg_description
        or "no longer maintained" in pkg_description
    ):
        is_deprecated = True
    latest_deprecated = False

    try:
        first_version_num = min(
            versions_nums,
            key=lambda x: Version.parse(x, optional_minor_and_patch=True),
        )
        latest_version_num = max(
            versions_nums,
            key=lambda x: Version.parse(x, optional_minor_and_patch=True),
        )
    except (ValueError, TypeError):
        first_version_num = versions_nums[-1]
        latest_version_num = versions_nums[0]
    
    first_version = versions_dict[first_version_num]
    latest_version = versions_list[latest_version_num]

    # Is the private package available publicly? Dependency confusion.
    if is_private_pkg and pkg_metadata:
        risk_metrics["pkg_private_on_public_registry_risk"] = True
        risk_metrics["pkg_private_on_public_registry_value"] = 1

    # If the package has fewer than minimum number of versions
    if len(versions_list):
        if len(versions_list) < config.pkg_min_versions:
            risk_metrics["pkg_min_versions_risk"] = True
            risk_metrics["pkg_min_versions_value"] = len(versions_list)
        # Check if the latest version is deprecated
        if latest_version and latest_version.get("yanked"):
            latest_deprecated = True

    # Created and modified time related checks
    if first_version and latest_version:
        created = first_version.get("created_at")
        modified = latest_version.get("updated_at")
        if created and modified:
            modified_dt = datetime.fromisoformat(modified)
            created_dt = datetime.fromisoformat(created)
            mod_create_diff = modified_dt - created_dt
            latest_now_diff = datetime.now(timezone.utc) - modified_dt
            created_now_diff = datetime.now(timezone.utc) - created_dt
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

    set_binary_risks(risk_metrics, versions_dict.get(pkg.get("version"), {}), latest_version)

    risk_metrics["risk_score"] = calculate_risk_score(risk_metrics)
    return risk_metrics
