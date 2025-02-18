import math
import os

from depscan.lib import config
from depscan.lib.logger import LOG

try:
    if os.getenv("DEPSCAN_CACHE_HOST") or os.getenv("DEPSCAN_CACHE_PORT"):
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
    else:
        import httpx

        httpclient = httpx
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
    if registry_type == "cargo":
        return key, f"{config.CARGO_SERVER}/{key}"
    return None, None


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
