import math
from datetime import datetime

import httpx
from rich.progress import Progress

from depscan.lib import config
from depscan.lib.logger import LOG, console


def get_lookup_url(registry_type, pkg):
    """
    Generating the lookup URL based on the registry type and package
    information.

    :param registry_type: The type of registry ("npm" or "pypi")
    :param pkg: Dict or string of package information
    :returns: Package name, lookup URL
    """
    vendor = None
    if isinstance(pkg, dict):
        vendor = pkg.get("vendor")
        name = pkg.get("name")
    else:
        tmpA = pkg.split("|")
        name = tmpA[len(tmpA) - 2]
        if len(tmpA) == 3:
            vendor = tmpA[0]
    key = name
    # Prefix vendor for npm
    if registry_type == "npm":
        if vendor and vendor != "npm":
            # npm expects namespaces to start with an @
            if not vendor.startswith("@"):
                vendor = "@" + vendor
            key = f"{vendor}/{name}"
        return key, f"{config.npm_server}/{key}"
    elif registry_type == "pypi":
        return key, f"{config.pypi_server}/{key}/json"
    return None, None


def metadata_from_registry(registry_type, scoped_pkgs, pkg_list, private_ns=None):
    """
    Method to query registry for the package metadata

    :param registry_type: The type of registry to query
    :param scoped_pkgs: Dictionary of lists of packages per scope
    :param pkg_list: List of package dictionaries
    :param private_ns: Private namespace
    :return:  A dict of package metadata, risk metrics, and private package
    flag for each package
    """
    metadata_dict = {}
    # Circuit breaker flag to break the risk audit in case of many api errors
    circuit_breaker = False
    # Track the api failures count
    failure_count = 0
    done_count = 0
    with Progress(
        console=console,
        transient=True,
        redirect_stderr=False,
        redirect_stdout=False,
        refresh_per_second=1,
    ) as progress:
        task = progress.add_task("[green] Auditing packages", total=len(pkg_list))
        for pkg in pkg_list:
            if circuit_breaker:
                LOG.info(
                    "Risk audited has been interrupted due to frequent api "
                    "errors. Please try again later."
                )
                progress.stop()
                return {}
            scope = pkg.get("scope", "").lower()
            key, lookup_url = get_lookup_url(registry_type, pkg)
            if not key or not lookup_url or key.startswith("https://"):
                progress.advance(task)
                continue
            progress.update(task, description=f"Checking {key}")
            try:
                r = httpx.get(
                    url=lookup_url,
                    follow_redirects=True,
                    timeout=config.request_timeout_sec,
                )
                json_data = r.json()
                # Npm returns this error if the package is not found
                if (
                    json_data.get("code") == "MethodNotAllowedError"
                    or r.status_code > 400
                ):
                    continue
                is_private_pkg = False
                if private_ns:
                    namespace_prefixes = private_ns.split(",")
                    for ns in namespace_prefixes:
                        if key.lower().startswith(ns.lower()) or key.lower().startswith(
                            "@" + ns.lower()
                        ):
                            is_private_pkg = True
                            break
                risk_metrics = {}
                if registry_type == "npm":
                    risk_metrics = npm_pkg_risk(json_data, is_private_pkg, scope)
                elif registry_type == "pypi":
                    project_type_pkg = f"python:{key}".lower()
                    required_pkgs = scoped_pkgs.get("required", [])
                    optional_pkgs = scoped_pkgs.get("optional", [])
                    excluded_pkgs = scoped_pkgs.get("excluded", [])
                    if (
                        pkg.get("purl") in required_pkgs
                        or project_type_pkg in required_pkgs
                    ):
                        scope = "required"
                    elif (
                        pkg.get("purl") in optional_pkgs
                        or project_type_pkg in optional_pkgs
                    ):
                        scope = "optional"
                    elif (
                        pkg.get("purl") in excluded_pkgs
                        or project_type_pkg in excluded_pkgs
                    ):
                        scope = "excluded"
                    risk_metrics = pypi_pkg_risk(json_data, is_private_pkg, scope)
                metadata_dict[key] = {
                    "scope": scope,
                    "pkg_metadata": json_data,
                    "risk_metrics": risk_metrics,
                    "is_private_pkg": is_private_pkg,
                }
            except Exception as e:
                LOG.debug(e)
                failure_count += 1
            progress.advance(task)
            done_count += 1
            if failure_count >= config.max_request_failures:
                circuit_breaker = True
    LOG.debug(
        "Retrieved package metadata for %d/%d packages. Failures count %d",
        done_count,
        len(pkg_list),
        failure_count,
    )
    return metadata_dict


def npm_metadata(scoped_pkgs, pkg_list, private_ns=None):
    """
    Method to query npm for the package metadata

    :param scoped_pkgs: Dictionary of lists of packages per scope
    :param pkg_list: List of package dictionaries
    :param private_ns: Private namespace
    :return: A dict of package metadata, risk metrics, and private package
    flag for each package
    """
    return metadata_from_registry("npm", scoped_pkgs, pkg_list, private_ns)


def pypi_metadata(scoped_pkgs, pkg_list, private_ns=None):
    """
    Method to query pypi for the package metadata

    :param scoped_pkgs: Dictionary of lists of packages per scope
    :param pkg_list: List of package dictionaries
    :param private_ns: Private namespace
    :return: A dict of package metadata, risk metrics, and private package
    flag for each package
    """
    return metadata_from_registry("pypi", scoped_pkgs, pkg_list, private_ns)


def get_category_score(
    param, max_value=config.default_max_value, weight=config.default_weight
):
    """
    Return parameter score given its current value, max value and
    parameter weight.

    :param param: The current value of the parameter
    :param max_value: The maximum value of the parameter
    :param weight: The weight of the parameter
    :return: The calculated score as a float value
    """
    try:
        param = float(param)
    except ValueError:
        param = 0
    try:
        max_value = float(max_value)
    except ValueError:
        max_value = config.default_max_value
    try:
        weight = float(weight)
    except ValueError:
        weight = config.default_weight
    return (math.log(1 + param) / math.log(1 + max(param, max_value))) * weight


def calculate_risk_score(risk_metrics):
    """
    Method to calculate a total risk score based on risk metrics. This is
    based on a weighted formula and might require customization based on use
    cases

    :param risk_metrics: Dict containing many risk metrics
    :return: The calculated total risk score
    """
    if not risk_metrics:
        return 0
    num_risks = 0
    working_score = 0
    total_weight = 0
    for k, v in risk_metrics.items():
        # Is the _risk key set to True
        if k.endswith("_risk") and v is True:
            risk_category = k.replace("_risk", "")
            risk_category_value = risk_metrics.get(f"{risk_category}_value", 0)
            risk_category_max = getattr(
                config, f"{risk_category}_max", config.default_max_value
            )
            risk_category_weight = getattr(
                config, f"{risk_category}_weight", config.default_weight
            )
            risk_category_base = getattr(config, f"{risk_category}", 0)
            value = risk_category_value
            if (
                risk_category_base
                and (
                    isinstance(risk_category_base, float)
                    or isinstance(risk_category_base, int)
                )
                and risk_category_base > risk_category_value
            ):
                value = risk_category_base - risk_category_value
            elif risk_category_max and risk_category_max > risk_category_value:
                value = risk_category_max - risk_category_value
            cat_score = get_category_score(
                value, risk_category_max, risk_category_weight
            )
            total_weight += risk_category_weight
            working_score += min(cat_score, 1)
            num_risks += 1
    working_score = round(working_score * total_weight / config.total_weight, 5)
    working_score = max(min(working_score, 1), 0)
    return working_score


def compute_time_risks(
    risk_metrics, created_now_diff, mod_create_diff, latest_now_diff
):
    """
    Compute risks based on creation, modified and time elapsed

    :param risk_metrics: A dict containing the risk metrics for the package.
    :param created_now_diff: Time difference from creation of the package and
    the current time.
    :param mod_create_diff: Time difference from
    modification and creation of the package.
    :param latest_now_diff: Time difference between the latest version of the
    package and the current
    time.
    :return: The updated risk metrics dictionary with the calculated
    risks and values.
    """
    # Check if the package is at least 1 year old. Quarantine period.
    if created_now_diff.total_seconds() < config.created_now_quarantine_seconds:
        risk_metrics["created_now_quarantine_seconds_risk"] = True
        risk_metrics[
            "created_now_quarantine_seconds_value"
        ] = latest_now_diff.total_seconds()

    # Check for the maximum seconds difference between latest version and now
    if latest_now_diff.total_seconds() > config.latest_now_max_seconds:
        risk_metrics["latest_now_max_seconds_risk"] = True
        risk_metrics["latest_now_max_seconds_value"] = latest_now_diff.total_seconds()
        # Since the package is quite old we can relax the min versions risk
        risk_metrics["pkg_min_versions_risk"] = False
    else:
        # Check for the minimum seconds difference between creation and
        # modified date This check catches several old npm packages that was
        # created and immediately updated within a day To reduce noise we
        # check for the age first and perform this check only for newish
        # packages
        if mod_create_diff.total_seconds() < config.mod_create_min_seconds:
            risk_metrics["mod_create_min_seconds_risk"] = True
            risk_metrics[
                "mod_create_min_seconds_value"
            ] = mod_create_diff.total_seconds()
    # Check for the minimum seconds difference between latest version and now
    if latest_now_diff.total_seconds() < config.latest_now_min_seconds:
        risk_metrics["latest_now_min_seconds_risk"] = True
        risk_metrics["latest_now_min_seconds_value"] = latest_now_diff.total_seconds()
    return risk_metrics


def pypi_pkg_risk(pkg_metadata, is_private_pkg, scope):
    """
    Calculate various package risks based on the metadata from pypi.

    :param pkg_metadata: A dict containing the metadata of the package from PyPI
    :param is_private_pkg: Boolean to indicate if this package is private
    :param scope: Package scope
    :return: Dict of risk metrics and corresponding PyPI values.
    """
    risk_metrics = {
        "pkg_deprecated_risk": False,
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
    latest_deprecated = False
    first_version = None
    latest_version = None

    # Is the private package available publicly? Dependency confusion.
    if is_private_pkg and pkg_metadata:
        risk_metrics["pkg_private_on_public_registry_risk"] = True
        risk_metrics["pkg_private_on_public_registry_value"] = 1

    # If the package has fewer than minimum number of versions
    if len(versions):
        if len(versions) < config.pkg_min_versions:
            risk_metrics["pkg_min_versions_risk"] = True
            risk_metrics["pkg_min_versions_value"] = len(versions)
        first_version = versions[0]
        latest_version = versions[-1]
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
    # Add package scope related weight
    if scope:
        risk_metrics[f"pkg_{scope}_scope_risk"] = True
        risk_metrics[f"pkg_{scope}_scope_value"] = 1

    risk_metrics["risk_score"] = calculate_risk_score(risk_metrics)
    return risk_metrics


def npm_pkg_risk(pkg_metadata, is_private_pkg, scope):
    """
    Calculate various npm package risks based on the metadata from npm. The
    keys in the risk_metrics dict is based on the parameters specified in
    config.py and has a _risk suffix. Eg: config.pkg_min_versions would
    result in a boolean pkg_min_versions_risk and pkg_min_versions_value

    :param pkg_metadata: A dict containing the metadata of the npm package.
    :param is_private_pkg: Boolean to indicate if this package is private
    :param scope: Package scope
    :return: A dict containing the calculated risks and score.
    """
    # Some default values to ensure the structure is non-empty
    risk_metrics = {
        "pkg_deprecated_risk": False,
        "pkg_min_versions_risk": False,
        "created_now_quarantine_seconds_risk": False,
        "latest_now_max_seconds_risk": False,
        "mod_create_min_seconds_risk": False,
        "pkg_min_maintainers_risk": False,
        "pkg_node_version_risk": False,
        "pkg_private_on_public_registry_risk": False,
    }
    # Is the private package available publicly? Dependency confusion.
    if is_private_pkg and pkg_metadata:
        risk_metrics["pkg_private_on_public_registry_risk"] = True
        risk_metrics["pkg_private_on_public_registry_value"] = 1
    versions = pkg_metadata.get("versions", {})
    latest_version = pkg_metadata.get("dist-tags", {}).get("latest")
    engines_block_dict = versions.get(latest_version, {}).get("engines", {})
    # Check for scripts block
    scripts_block_dict = versions.get(latest_version, {}).get("scripts", {})
    is_deprecated = versions.get(latest_version, {}).get("deprecated", None)
    # Is the package deprecated
    if is_deprecated:
        risk_metrics["pkg_deprecated_risk"] = True
        risk_metrics["pkg_deprecated_value"] = 1
    scripts_block_list = []
    # There are some packages on npm with incorrectly configured scripts
    # block Good news is that the install portion would only for if the
    # scripts block is an object/dict
    if isinstance(scripts_block_dict, dict):
        scripts_block_list = [
            block
            for block in scripts_block_dict.keys()
            if "preinstall" in block or "postinstall" in block
        ]

    # If the package has fewer than minimum number of versions
    if len(versions) < config.pkg_min_versions:
        risk_metrics["pkg_min_versions_risk"] = True
        risk_metrics["pkg_min_versions_value"] = len(versions)
    # Time related checks
    time_info = pkg_metadata.get("time", {})
    modified = time_info.get("modified", "").replace("Z", "")
    created = time_info.get("created", "").replace("Z", "")
    if not modified and pkg_metadata.get("mtime"):
        modified = pkg_metadata.get("mtime").replace("Z", "")
    if not created and pkg_metadata.get("ctime"):
        created = pkg_metadata.get("ctime").replace("Z", "")
    latest_version_time = time_info.get(latest_version, "").replace("Z", "")
    if time_info and modified and created and latest_version_time:
        modified_dt = datetime.fromisoformat(modified)
        created_dt = datetime.fromisoformat(created)
        latest_version_time_dt = datetime.fromisoformat(latest_version_time)
        mod_create_diff = modified_dt - created_dt
        latest_now_diff = datetime.now() - latest_version_time_dt
        created_now_diff = datetime.now() - created_dt
        risk_metrics = compute_time_risks(
            risk_metrics, created_now_diff, mod_create_diff, latest_now_diff
        )

    # Maintainers count related risk. Ignore packages that are past
    # quarantine period
    maintainers = pkg_metadata.get("maintainers", [])
    if len(maintainers) < config.pkg_min_maintainers and risk_metrics.get(
        "created_now_quarantine_seconds_risk"
    ):
        risk_metrics["pkg_min_maintainers_risk"] = True
        risk_metrics["pkg_min_maintainers_value"] = len(maintainers)
        # Check for install scripts risk only for those packages with
        # maintainers risk
        if scripts_block_list:
            risk_metrics["pkg_install_scripts_risk"] = True
            risk_metrics["pkg_install_scripts_value"] = len(scripts_block_list)

    # Users count related risk. Ignore packages that are past quarantine period
    users = pkg_metadata.get("users", [])
    if (
        users
        and len(users) < config.pkg_min_users
        and risk_metrics.get("created_now_quarantine_seconds_risk")
    ):
        risk_metrics["pkg_min_users_risk"] = True
        risk_metrics["pkg_min_users_value"] = len(users)
    # Node engine version There are packages with incorrect node engine
    # specification which we can ignore for now
    if (
        engines_block_dict
        and isinstance(engines_block_dict, dict)
        and engines_block_dict.get("node")
        and isinstance(engines_block_dict.get("node"), str)
    ):
        node_version_spec = engines_block_dict.get("node")
        node_version = (
            node_version_spec.replace(">= ", "")
            .replace(">=", "")
            .replace("> ", "")
            .replace(">", "")
            .replace("~ ", "")
            .replace("~", "")
            .split(" ")[0]
        )
        for ver in config.pkg_node_version.split(","):
            if node_version.startswith(ver):
                risk_metrics["pkg_node_version_risk"] = True
                risk_metrics["pkg_node_version_value"] = 1
                break
    # Add package scope related weight
    if scope:
        risk_metrics[f"pkg_{scope}_scope_risk"] = True
        risk_metrics[f"pkg_{scope}_scope_value"] = 1

    risk_metrics["risk_score"] = calculate_risk_score(risk_metrics)
    return risk_metrics
