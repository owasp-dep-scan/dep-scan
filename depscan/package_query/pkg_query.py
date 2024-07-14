import math
import os

from rich.progress import Progress

from depscan.lib import config
from depscan.lib.logger import LOG, console
from depscan.package_query.npm_pkg import npm_pkg_risk
from depscan.package_query.pypi_pkg import pypi_pkg_risk

try:
    import hishel
    import redis

    storage = hishel.RedisStorage(
        ttl=config.get_int_from_env("DEPSCAN_CACHE_TTL", 36000),
        client=redis.Redis(
            host=os.getenv("DEPSCAN_CACHE_HOST", "127.0.0.1"),
            port=config.get_int_from_env("DEPSCAN_CACHE_PORT", 6379),
        ),
    )
    httpclient = hishel.CacheClient(storage=storage)
    LOG.debug("valkey cache activated.")
except ImportError:
    import httpx

    httpclient = httpx


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
        tmp_a = pkg.split("|")
        name = tmp_a[len(tmp_a) - 2]
        if len(tmp_a) == 3:
            vendor = tmp_a[0]
    key = name
    # Prefix vendor for npm
    if registry_type == "npm":
        if vendor and vendor != "npm":
            # npm expects namespaces to start with an @
            if not vendor.startswith("@"):
                vendor = "@" + vendor
            key = f"{vendor}/{name}"
        return key, f"{config.NPM_SERVER}/{key}"
    if registry_type == "pypi":
        return key, f"{config.PYPI_SERVER}/{key}/json"
    return None, None


def metadata_from_registry(
    registry_type, scoped_pkgs, pkg_list, private_ns=None
):
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
        disable=len(pkg_list) < 10
    ) as progress:
        task = progress.add_task(
            "[green] Auditing packages", total=len(pkg_list)
        )
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
                r = httpclient.get(
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
                        if key.lower().startswith(
                            ns.lower()
                        ) or key.lower().startswith("@" + ns.lower()):
                            is_private_pkg = True
                            break
                risk_metrics = {}
                if registry_type == "npm":
                    risk_metrics = npm_pkg_risk(
                        json_data, is_private_pkg, scope, pkg
                    )
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
                    risk_metrics = pypi_pkg_risk(
                        json_data, is_private_pkg, scope, pkg
                    )
                metadata_dict[key] = {
                    "scope": scope,
                    "purl": pkg.get("purl"),
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


def get_category_score(
    param, max_value=config.DEFAULT_MAX_VALUE, weight=config.DEFAULT_WEIGHT
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
        max_value = config.DEFAULT_MAX_VALUE
    try:
        weight = float(weight)
    except ValueError:
        weight = config.DEFAULT_WEIGHT
    return (
        0
        if weight == 0 or math.log(1 + max(param, max_value)) == 0
        else (math.log(1 + param) / math.log(1 + max(param, max_value)))
             * weight
    )


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
                config, f"{risk_category}_max", config.DEFAULT_MAX_VALUE
            )
            risk_category_weight = getattr(
                config, f"{risk_category}_weight", config.DEFAULT_WEIGHT
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
        risk_metrics["created_now_quarantine_seconds_value"] = (
            latest_now_diff.total_seconds()
        )

    # Check for the maximum seconds difference between latest version and now
    if latest_now_diff.total_seconds() > config.latest_now_max_seconds:
        risk_metrics["latest_now_max_seconds_risk"] = True
        risk_metrics["latest_now_max_seconds_value"] = (
            latest_now_diff.total_seconds()
        )
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
            risk_metrics["mod_create_min_seconds_value"] = (
                mod_create_diff.total_seconds()
            )
    # Check for the minimum seconds difference between latest version and now
    if latest_now_diff.total_seconds() < config.latest_now_min_seconds:
        risk_metrics["latest_now_min_seconds_risk"] = True
        risk_metrics["latest_now_min_seconds_value"] = (
            latest_now_diff.total_seconds()
        )
    return risk_metrics
