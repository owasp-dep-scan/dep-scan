from datetime import datetime

from depscan.lib import config
from depscan.lib.package_query.pkg_query import httpclient, compute_time_risks, calculate_risk_score

def search_npm(keywords=None, insecure_only=False, unstable_only=False, pages=1, popularity=1.0, size=250):
    pkg_list = []
    for page in range(0, pages):
        from_value = page * 250
        registry_search_url = f"{config.NPM_SERVER}/-/v1/search?popularity={popularity}&size={size}&from={from_value}"
        if insecure_only:
            registry_search_url = f"{registry_search_url}&text=is:insecure"
        elif unstable_only:
            registry_search_url = f"{registry_search_url}&text=is:unstable"
        elif keywords:
            registry_search_url = f"{registry_search_url}&text=keywords:{','.join(keywords)}"
        else:
            registry_search_url = f"{registry_search_url}&text=not:insecure"
        try:
            r = httpclient.get(
                url=registry_search_url,
                follow_redirects=True,
                timeout=config.request_timeout_sec,
            )
            result = r.json()
            if result and not r.is_error and result.get("objects"):
                for aobj in result.get("objects"):
                    if aobj and aobj.get("package"):
                        package = aobj.get("package")
                        flags = aobj.get("flags", {})
                        name = package.get("name")
                        if name.startswith("@types/"):
                            continue
                        is_pkg_insecure = True if flags.get("insecure", 0) == 1 else False
                        pkg_list.append(
                            {
                                "name": name,
                                "version": package.get("version"),
                                "purl": f'pkg:npm/{package.get("name").replace("@", "%40")}@{package.get("version")}',
                                "insecure": is_pkg_insecure,
                                "unstable": flags.get("unstable", False)
                            }
                        )
        except Exception as e:
            print(e)
            pass
    return pkg_list


def get_npm_download_stats(name, period="last-year"):
    """
    Method to download npm stats

    :param name: Package name
    :param period: Stats period
    """
    stats_url = f"https://api.npmjs.org/downloads/point/{period}/{name}"
    try:
        r = httpclient.get(
            url=stats_url,
            follow_redirects=True,
            timeout=config.request_timeout_sec,
        )
        return r.json()
    except Exception:
        return {}


def npm_pkg_risk(pkg_metadata, is_private_pkg, scope, pkg):
    """
    Calculate various npm package risks based on the metadata from npm. The
    keys in the risk_metrics dict is based on the parameters specified in
    config.py and has a _risk suffix. Eg: config.pkg_min_versions would
    result in a boolean pkg_min_versions_risk and pkg_min_versions_value

    :param pkg_metadata: A dict containing the metadata of the npm package.
    :param is_private_pkg: Boolean to indicate if this package is private
    :param scope: Package scope
    :param pkg: Package object

    :return: A dict containing the calculated risks and score.
    """
    # Some default values to ensure the structure is non-empty
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
    # Is the private package available publicly? Dependency confusion.
    if is_private_pkg and pkg_metadata:
        risk_metrics["pkg_private_on_public_registry_risk"] = True
        risk_metrics["pkg_private_on_public_registry_value"] = 1
    versions = pkg_metadata.get("versions", {})
    latest_version = pkg_metadata.get("dist-tags", {}).get("latest")
    engines_block_dict = versions.get(latest_version, {}).get("engines", {})
    # Check for scripts block
    scripts_block_dict = versions.get(latest_version, {}).get("scripts", {})
    bin_block_dict = versions.get(latest_version, {}).get("bin", {})
    theversion = None
    if pkg:
        if pkg.get("version"):
            theversion = versions.get(pkg.get("version"), {})
            # Check if the version exists in the registry
            if not theversion:
                risk_metrics["pkg_version_missing_risk"] = True
                risk_metrics["pkg_version_missing_value"] = 1
        # Proceed with the rest of checks using the latest version
        if not theversion:
            theversion = versions.get(latest_version, {})
        # Get the version specific engines and scripts block
        if theversion.get("engines"):
            engines_block_dict = theversion.get("engines")
        if theversion.get("scripts"):
            scripts_block_dict = theversion.get("scripts")
        if theversion.get("bin"):
            bin_block_dict = theversion.get("bin")
        # Check if there is any binary downloaded and offered
        if theversion.get("binary"):
            risk_metrics["pkg_includes_binary_risk"] = True
            risk_metrics["pkg_includes_binary_value"] = 1
            # Capture the remote host
            if theversion["binary"].get("host"):
                risk_metrics["pkg_includes_binary_info"] = (
                    f'Host: {theversion["binary"].get("host")}\nBinary: {theversion["binary"].get("module_name")}'
                )
            # For some packages,
            elif theversion["binary"].get("napi_versions"):
                if theversion.get("repository", {}).get("url"):
                    risk_metrics["pkg_includes_binary_info"] = (
                        f'Repository: {theversion.get("repository").get("url")}'
                    )
                elif theversion.get("homepage"):
                    risk_metrics["pkg_includes_binary_info"] = (
                        f'Homepage: {theversion.get("homepage")}'
                    )
        elif bin_block_dict and maybe_binary_npm_package(pkg.get("name")):
            # See #317
            risk_metrics["pkg_includes_binary_risk"] = True
            risk_metrics["pkg_includes_binary_value"] = len(
                bin_block_dict.keys()
            )
            bin_block_desc = ""
            for k, v in bin_block_dict.items():
                bin_block_desc = f"{bin_block_desc}\n{k}: {v}"
            if bin_block_desc:
                risk_metrics["pkg_includes_binary_info"] = (
                    f"Binary commands:{bin_block_desc}"
                )
        # Look for slsa attestations
        if theversion.get("dist", {}).get("attestations") and theversion.get(
            "dist", {}
        ).get("signatures"):
            attestations = theversion.get("dist").get("attestations")
            signatures = theversion.get("dist").get("signatures")
            if (
                attestations.get("url").startswith(
                    "https://registry.npmjs.org/"
                )
                and attestations.get("provenance", {}).get("predicateType", "")
                == "https://slsa.dev/provenance/v1"
            ):
                risk_metrics["pkg_attested_check"] = True
                risk_metrics["pkg_attested_value"] = len(signatures)
                risk_metrics["pkg_attested_info"] = "\n".join(
                    [sig.get("keyid") for sig in signatures]
                )
        # In some packages like biomejs, there would be no binary section
        # case 1: optional dependencies section might have a bunch of packages for each os
        # case 2: prebuild, prebuild-install, prebuildify in dependencies
        # case 3: there could be a libc attribute
        # case 4: fileCount <= 2 and size > 20 MB
        if not theversion.get("binary"):
            binary_count = 1
            if theversion.get("bin"):
                binary_count = max(len(theversion.get("bin", {}).keys()), 1)
            for opkg in theversion.get("optionalDependencies", {}).keys():
                if (
                    "linux" in opkg
                    or "darwin" in opkg
                    or "win32" in opkg
                    or "arm64" in opkg
                    or "musl" in opkg
                ):
                    risk_metrics["pkg_includes_binary_risk"] = True
                    risk_metrics["pkg_includes_binary_value"] = binary_count
                    break
            # Eg: pkg:npm/zeromq@6.0.0-beta.19
            dev_deps = list(theversion.get("devDependencies", {}).keys())
            direct_deps = list(theversion.get("dependencies", {}).keys())
            if "prebuild" in " ".join(dev_deps) or "prebuild" in " ".join(
                direct_deps
            ):
                risk_metrics["pkg_includes_binary_risk"] = True
                risk_metrics["pkg_includes_binary_value"] = binary_count
            if not risk_metrics.get("pkg_includes_binary_risk"):
                if theversion.get("libc"):
                    risk_metrics["pkg_includes_binary_risk"] = True
                    risk_metrics["pkg_includes_binary_value"] = len(
                        theversion.get("libc", [])
                    )
                elif (
                    theversion.get("dist", {}).get("fileCount", 0) <= 2
                    and theversion.get("dist", {}).get("unpackedSize")
                    and (
                        theversion.get("dist").get("unpackedSize", 0)
                        / (1000 * 1000)
                    )
                    > 20
                ):
                    risk_metrics["pkg_includes_binary_risk"] = True
                    risk_metrics["pkg_includes_binary_value"] = 1
    is_deprecated = (
        versions.get(latest_version, {}).get("deprecated", None) is not None
    )
    is_version_deprecated = (
        True if theversion and theversion.get("deprecated") else False
    )
    # Is the package deprecated
    if is_deprecated:
        risk_metrics["pkg_deprecated_risk"] = True
        risk_metrics["pkg_deprecated_value"] = 1
    elif is_version_deprecated:
        risk_metrics["pkg_version_deprecated_risk"] = True
        risk_metrics["pkg_version_deprecated_value"] = 1
        # The deprecation reason for a specific version are often useful
        risk_metrics["pkg_version_deprecated_info"] = theversion.get(
            "deprecated"
        )
    scripts_block_list = []
    # There are some packages on npm with incorrectly configured scripts
    # block Good news is that the install portion would only for if the
    # scripts block is an object/dict
    if isinstance(scripts_block_dict, dict):
        scripts_block_list = [
            block
            for block in scripts_block_dict.keys()
            if block in ("preinstall", "postinstall", "prebuild")
        ]
        # Detect the use of prebuild-install
        # https://github.com/prebuild/prebuild-install
        # https://github.com/prebuild/prebuildify
        if not risk_metrics.get("pkg_includes_binary_risk"):
            if scripts_block_dict.get("prebuild", "").startswith("prebuild"):
                risk_metrics["pkg_includes_binary_risk"] = True
                risk_metrics["pkg_includes_binary_value"] = 1
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


def maybe_binary_npm_package(name: str) -> bool:
    """
    Check if a package might be a binary by checking the naming conventions.

    :param name: Packagename
    :returns: boolean
    """
    if not name:
        return False
    for bin_suffix in config.NPM_BINARY_PACKAGES_SUFFIXES:
        if name.endswith(bin_suffix):
            return True
    return False
