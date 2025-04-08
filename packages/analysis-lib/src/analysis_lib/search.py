from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

from vdb.lib.search import (
    search_by_any,
    search_by_cpe_like,
    search_by_url,
    search_by_purl_like,
)

from analysis_lib.normalize import create_pkg_variations, dealias_packages, dedup


def get_pkg_vendor_name(pkg: Dict) -> Tuple[str, str]:
    """
    Method to extract vendor and name information from package. If vendor
    information is not available package url is used to extract the package
    registry provider such as pypi, maven

    :param pkg: a dictionary representing a package
    :return: vendor and name as a tuple
    """
    vendor = pkg.get("vendor", "")
    if not vendor:
        purl = pkg.get("purl")
        if purl:
            purl_parts = purl.split("/")
            if purl_parts:
                vendor = purl_parts[0].replace("pkg:", "")
        else:
            vendor = ""
    name = pkg.get("name", "")
    return vendor, name


def get_pkgs_by_scope(pkg_list):
    """
    Method to return the packages by scope as defined in CycloneDX spec -
    required, optional and excluded

    :param pkg_list: List of packages
    :return: Dictionary of packages categorized by scope if available. Empty if
                no scope information is available
    """
    scoped_pkgs = {}
    if not pkg_list:
        return scoped_pkgs
    for pkg in pkg_list:
        if pkg.get("scope"):
            vendor, name = get_pkg_vendor_name(pkg)
            scope = pkg.get("scope").lower()
            if pkg.get("purl"):
                scoped_pkgs.setdefault(scope, []).append(pkg.get("purl"))
            else:
                scoped_pkgs.setdefault(scope, []).append(f"{vendor}:{name}")
    return scoped_pkgs


def get_scope_from_imports(project_type, pkg_list, all_imports):
    """
    Method to compute the packages scope defined in CycloneDX spec - required,
    optional and excluded

    :param project_type: Project type
    :param pkg_list: List of packages
    :param all_imports: List of imports detected
    :return: Dictionary of packages categorized by scope if available. Empty if
                no scope information is available
    """
    scoped_pkgs = {}
    if not pkg_list or not all_imports:
        return scoped_pkgs
    for pkg in pkg_list:
        scope = "optional"
        vendor, name = get_pkg_vendor_name(pkg)
        if name in all_imports or name.lower().replace("py", "") in all_imports:
            scope = "required"
        if pkg.get("purl"):
            scoped_pkgs.setdefault(scope, []).append(pkg.get("purl"))
        else:
            scoped_pkgs.setdefault(scope, []).append(f"{vendor}:{name}")
        scoped_pkgs[scope].append(f"{project_type}:{name.lower()}")
    return scoped_pkgs


def find_vulns(
    project_type: str | None,
    pkg_list: List[Dict[str, Any]],
    fuzzy_search: bool = False,
    search_order: Optional[str] = None,
):
    """
    Method to search packages in our vulnerability database

    :param project_type: Project type.
    :param pkg_list: List of packages to search.
    :param fuzzy_search: Perform fuzzy search by creating variations. Disabled by default.

    :returns: raw_results, pkg_aliases, purl_aliases
    """
    expanded_list = []
    # The challenge we have is to broaden our search and create several
    # variations of the package and vendor names to perform a broad search.
    # We then have to map the results back to the original package names and
    # package urls.
    pkg_aliases = defaultdict(list)
    purl_aliases = {}
    expanded_list = []
    if fuzzy_search:
        for pkg in pkg_list:
            tmp_expanded, pkg_aliases, tmp_purl_aliases = generate_variations(
                pkg, pkg_aliases
            )
            expanded_list.extend(tmp_expanded)
            purl_aliases |= tmp_purl_aliases
    else:
        expanded_list = pkg_list
    raw_results = []
    for pkg in expanded_list:
        if res := search_expanded(pkg, fuzzy_search, search_order):
            raw_results.extend(res)
    raw_results = dedup(project_type, raw_results)
    pkg_aliases = dealias_packages(
        raw_results, pkg_aliases=pkg_aliases, purl_aliases=purl_aliases
    )
    return raw_results, pkg_aliases, purl_aliases


def search_expanded(pkg: Dict, fuzzy_search, search_order) -> List:
    """Searches packages and variations"""
    raw_results = []
    # Default search order is purl or cpe or url (pcu)
    search_term = pkg.get("purl") or pkg.get("cpe") or pkg.get("url")
    # Make the search logic and order configurable
    search_logic = search_by_any
    if search_order == "purl":
        search_logic = search_by_purl_like
        search_term = pkg.get("purl")
    elif search_order == "cpe":
        search_logic = search_by_cpe_like
        search_term = pkg.get("cpe")
    elif search_order == "url":
        search_logic = search_by_url
        search_term = pkg.get("url")
    elif search_order == "cpu":
        search_logic = search_by_any
        search_term = pkg.get("cpe") or pkg.get("purl") or pkg.get("url")
    # Give preference to our search logic
    if search_term and (res := search_logic(search_term, with_data=True)):
        raw_results.extend(res)
    elif fuzzy_search:
        # Perform fuzzy search if requested retaining the search logic
        alt_search_term = (
            f"pkg:generic/{pkg.get('vendor')}/{pkg.get('name')}"
            if pkg.get("vendor")
            else pkg["name"]
        )
        if pkg.get("version"):
            alt_search_term = f"{alt_search_term}@{pkg.get('version')}"
        if res := search_logic(alt_search_term, with_data=True):
            raw_results.extend(res)
    return raw_results


def generate_variations(pkg: Dict, pkg_aliases: Dict) -> Tuple[List, Dict, Dict]:
    """Generates a variation of the package and aliases for it."""
    expanded_list, pkg_aliases, purl_aliases = [], {}, {}
    variations = create_pkg_variations(pkg)
    if variations:
        expanded_list += variations
    vendor, name = get_pkg_vendor_name(pkg)
    version = pkg.get("version")
    if pkg.get("purl"):
        ppurl = pkg["purl"]
        purl_aliases[ppurl] = ppurl
        purl_aliases[f"{vendor.lower()}:{name.lower()}:{version}"] = ppurl
        if ppurl.startswith("pkg:npm"):
            purl_aliases[f"npm:{vendor.lower()}/{name.lower()}:{version}"] = ppurl
        if not purl_aliases.get(f"{vendor.lower()}:{name.lower()}"):
            purl_aliases[f"{vendor.lower()}:{name.lower()}"] = ppurl
    if variations:
        for vari in variations:
            vari_full_pkg = f"{vari.get('vendor')}:{vari.get('name')}"
            if pkg_aliases.get(f"{vendor.lower()}:{name.lower()}:{version}"):
                pkg_aliases[f"{vendor.lower()}:{name.lower()}:{version}"].append(
                    vari_full_pkg
                )
            else:
                pkg_aliases[f"{vendor.lower()}:{name.lower()}:{version}"] = [
                    vari_full_pkg
                ]
            if pkg.get("purl"):
                purl_aliases[f"{vari_full_pkg.lower()}:{version}"] = pkg["purl"]
    return expanded_list, pkg_aliases, purl_aliases
