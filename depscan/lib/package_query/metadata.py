from concurrent.futures import ThreadPoolExecutor, as_completed

import httpx
from rich.progress import Progress

from depscan.lib import config
from depscan.lib.logger import console, LOG, spinners_enabled
from depscan.lib.package_query.npm_pkg import npm_pkg_risk
from depscan.lib.package_query.pkg_query import get_lookup_url
from depscan.lib.package_query.pypi_pkg import pypi_pkg_risk
from depscan.lib.package_query.cargo_pkg import cargo_pkg_risk

# Bounded concurrency for the registry audit. 8–16 workers; kept modest
# to respect registry rate limits.
_AUDIT_MAX_WORKERS = max(
    8, min(16, _n) if (_n := config.get_int_from_env("DEPSCAN_AUDIT_WORKERS", 0)) else 10
)


def _progress_disabled(pkg_count):
    """Whether the registry audit should leave its progress bar off.

    Fewer than 10 packages finish before a bar is worth drawing, and a bar
    animates by erasing itself, which only a terminal stderr supports.
    """
    return pkg_count < 10 or not spinners_enabled()


def _lookup_pkg_metadata(client, registry_type, scoped_pkgs, pkg_list, private_ns, pkg):
    """Look up a single package's metadata from the registry.

    Returns ``(key, metadata_entry_or_None, is_failure)``. ``client`` is a
    shared ``httpx.Client`` (thread-safe) reused across the audit pool.
    """
    scope = pkg.get("scope", "").lower()
    key, lookup_url = get_lookup_url(registry_type, pkg)
    if not key or not lookup_url or key.startswith("https://"):
        return key, None, False
    try:
        r = client.get(
            url=lookup_url,
            follow_redirects=True,
            timeout=config.request_timeout_sec,
        )
        json_data = r.json()
        # Npm is returning textual errors at times
        if isinstance(json_data, str):
            return key, None, False
        # Npm returns this error if the package is not found
        if isinstance(json_data, dict) and (
            json_data.get("code") == "MethodNotAllowedError" or r.status_code > 400
        ):
            return key, None, False
        is_private_pkg = False
        if private_ns:
            namespace_prefixes = private_ns.split(",")
            for ns in namespace_prefixes:
                if key.lower().startswith(ns.lower()) or key.lower().startswith("@" + ns.lower()):
                    is_private_pkg = True
                    break
        risk_metrics = {}
        match registry_type:
            case "npm":
                risk_metrics = npm_pkg_risk(json_data, is_private_pkg, scope, pkg)
            case "pypi":
                project_type_pkg = f"python:{key}".lower()
                required_pkgs = scoped_pkgs.get("required", [])
                optional_pkgs = scoped_pkgs.get("optional", [])
                excluded_pkgs = scoped_pkgs.get("excluded", [])
                if pkg.get("purl") in required_pkgs or project_type_pkg in required_pkgs:
                    scope = "required"
                elif pkg.get("purl") in optional_pkgs or project_type_pkg in optional_pkgs:
                    scope = "optional"
                elif pkg.get("purl") in excluded_pkgs or project_type_pkg in excluded_pkgs:
                    scope = "excluded"
                risk_metrics = pypi_pkg_risk(json_data, is_private_pkg, scope, pkg)
            case "cargo":
                risk_metrics = cargo_pkg_risk(json_data, is_private_pkg, scope, pkg)
            case _:
                pass
        return (
            key,
            {
                "scope": scope,
                "purl": pkg.get("purl"),
                "pkg_metadata": json_data,
                "risk_metrics": risk_metrics,
                "is_private_pkg": is_private_pkg,
            },
            False,
        )
    except Exception as e:
        LOG.debug(e)
        return key, None, True


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
    if not pkg_list:
        return {}
    metadata_dict = {}
    # Circuit breaker flag to break the risk audit in case of many api errors
    circuit_breaker = False
    # Track the api failures count
    failure_count = 0
    done_count = 0
    max_workers = min(_AUDIT_MAX_WORKERS, len(pkg_list))
    # A single httpx.Client is thread-safe and shares a connection pool across
    # the audit workers. The context manager guarantees sockets are closed.
    with (
        httpx.Client() as client,
        Progress(
            console=console,
            transient=True,
            redirect_stderr=False,
            redirect_stdout=False,
            refresh_per_second=1,
            disable=_progress_disabled(len(pkg_list)),
        ) as progress,
    ):
        task = progress.add_task("[green] Auditing packages", total=len(pkg_list))
        with ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="registry-audit"
        ) as executor:
            future_to_pkg = {
                executor.submit(
                    _lookup_pkg_metadata,
                    client,
                    registry_type,
                    scoped_pkgs,
                    pkg_list,
                    private_ns,
                    pkg,
                ): pkg
                for pkg in pkg_list
            }
            for future in as_completed(future_to_pkg):
                key, result, is_failure = future.result()
                if is_failure:
                    failure_count += 1
                if result:
                    metadata_dict[key] = result
                progress.advance(task)
                done_count += 1
                if failure_count >= config.max_request_failures:
                    circuit_breaker = True
                    break
            if circuit_breaker:
                for f in future_to_pkg:
                    f.cancel()
                LOG.info(
                    "Risk audited has been interrupted due to frequent api "
                    "errors. Please try again later."
                )
                progress.stop()
                return {}
    LOG.debug(
        "Retrieved package metadata for %d/%d packages. Failures count %d",
        done_count,
        len(pkg_list),
        failure_count,
    )
    return metadata_dict


def cargo_metadata(scoped_pkgs, pkg_list, private_ns=None):
    """
    Method to query cargo for the package metadata
    """
    return metadata_from_registry("cargo", scoped_pkgs, pkg_list, private_ns)


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
