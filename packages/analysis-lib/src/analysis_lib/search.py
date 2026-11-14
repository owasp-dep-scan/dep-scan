import logging
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

from vdb.lib import db as _vdb_db
from vdb.lib.search import (
    ShardCoverageError,
    get_cve_data_batched,
    search_by_any,
    search_by_cpe_like,
    search_by_url,
    search_by_purl_like,
    search_packages_batched,
)

from analysis_lib.normalize import create_pkg_variations, dealias_packages, dedup

# Named under the "depscan" tree so depscan's logging setup keeps it; the
# library stays usable without depscan.
LOG = logging.getLogger("depscan.analysis_lib")


def search_guarding_coverage(search_logic, term, **kwargs):
    """Run a single-term vdb search, turning a shard coverage gap into a
    warning instead of an abort.

    On a shard store, vdb raises ``ShardCoverageError`` from single-purl
    searches whose purl type no local shard serves, because a bare empty
    answer cannot say "not checked". The component is left out of the
    results and the gap is warned with the type named; treating it as clean
    is exactly what must not happen.
    """
    try:
        return search_logic(term, **kwargs)
    except ShardCoverageError as e:
        purl_type = term.split("pkg:", 1)[-1].split("/", 1)[0] if term.startswith("pkg:") else term
        LOG.warning(
            "purl type '%s' has no local shard, so components of that type "
            "were NOT assessed; this is not a clean result. %s",
            purl_type,
            e,
        )
        return []


def _extended_metadata_available() -> bool:
    """True when vdb's extended search-metadata tables are populated.

    vdb populates ``severity``/``package_scope``/date/``source`` on results only
    when the extended metadata tables (``cve_metadata``) are present (the
    ``*-extended`` DB). On the default DB those fields are absent, so pushing a
    ``severity_threshold``/scope/date/source filter down would silently drop rows
    that simply lack the metadata. depscan must therefore only push those filters
    down when this returns True; its own Python-side logic remains authoritative
    otherwise.
    """
    try:
        from vdb.lib.search import ensure_search_metadata

        return ensure_search_metadata()
    except Exception:
        return False


def build_search_filters(options=None) -> Dict[str, Any]:
    """Assemble a vdb ``filters`` dict from depscan analysis options.

    vdb's search API accepts a ``filters`` dict that narrows results inside the
    DB instead of in Python post-processing. This helper builds that dict
    conservatively so the default DB is never silently under-reported:

    - ``exclude_malware`` / ``malware_only`` are always safe to push down because
      vdb populates ``is_malware`` on every result (via the ``MAL-`` fallback in
      ``_attach_metadata``) even on the default DB.
    - ``severity_threshold`` depends on the extended metadata tables and is only
      added when ``_extended_metadata_available()`` is True. depscan keeps its own
      severity gating authoritative otherwise.

    ``options`` may be a ``VdrAnalysisKV`` (attributes) or a plain dict (the
    depscan_options shape used in cli.py). It may be ``None`` (no filtering).
    """
    filters: Dict[str, Any] = {}
    if options is None:
        return filters

    def _opt(name, default=None):
        if hasattr(options, name):
            return getattr(options, name, default)
        if isinstance(options, dict):
            return options.get(name, default)
        return default

    exclude_malware = _opt("exclude_malware", False)
    malware_only = _opt("malware_only", False)
    severity = _opt("severity")
    if exclude_malware:
        filters["exclude_malware"] = True
    if malware_only:
        filters["malware_only"] = True
    # Metadata-dependent filters: only push down when the extended metadata is
    # available, otherwise these would silently drop rows on the default DB.
    if severity and _extended_metadata_available():
        filters["severity_threshold"] = severity
    return filters


# Ecosystems whose namespace/name vdb stores in lowercase. Maven is deliberately
# excluded (artifact IDs are case-sensitive). Golang is excluded (Go module
# paths are case-sensitive). OS types are excluded because distro qualifiers and
# namespace aliases are handled by vdb's canonicalize_os_purl_prefix at lookup
# time.
_CASE_INSENSITIVE_PURL_TYPES = frozenset(
    {
        "npm",
        "pypi",
        "composer",
        "hex",
        "elixir",
        "cargo",
        "crates",
        "nuget",
        "gem",
        "rubygems",
        "pub",
        "dart",
        "github",
        "bitbucket",
        "gitlab",
    }
)


def canonicalize_search_purl(purl: str) -> str:
    """Canonicalise a purl for vdb search.

    For ecosystems whose namespace/name vdb stores in lowercase (npm, pypi,
    cargo, github, …), the ``pkg:type/namespace/name`` prefix is lowercased so a
    mixed-case SBOM purl still matches. Maven and Golang are preserved
    (case-sensitive). OS/container purls are left untouched so distro qualifiers
    (distro_name, distro, arch) and namespace aliases survive intact. Version,
    qualifiers, and subpath are always preserved verbatim.

    This is a hot path (called per component), so it deliberately avoids a full
    ``PackageURL`` parse+rebuild round-trip. It works on the raw string and
    short-circuits when the purl is already lowercase (the common case). Note
    that vdb's ``search_by_purl_like`` also lowercases the purl_prefix at lookup
    time; this function keeps depscan's ``matched_by`` and any custom-data keys
    consistent with that folding without paying the parse cost.
    """
    if not purl or not purl.startswith("pkg:"):
        return purl
    # Fast path: nothing to fold.
    if purl == purl.lower():
        return purl
    ptype = purl[4:].split("/", 1)[0].lower()
    if ptype not in _CASE_INSENSITIVE_PURL_TYPES:
        return purl
    # Cut off qualifiers (?) and subpath (#), which must be preserved verbatim.
    end = len(purl)
    for sep in ("?", "#"):
        idx = purl.find(sep)
        if idx != -1 and idx < end:
            end = idx
    prefix, tail = purl[:end], purl[end:]
    # The version separator '@' is the one after the final '/', so a scoped-npm
    # namespace written with a literal '@' (pkg:npm/@Scope/Name) is not mistaken
    # for a version. Version, qualifiers and subpath are preserved as-is.
    last_slash = prefix.rfind("/")
    at_pos = prefix.find("@", last_slash + 1)
    name_end = at_pos if at_pos != -1 else len(prefix)
    # Lowercase the type/namespace/name and encode a literal npm scope '@' as
    # %40 (purl spec), so "@Scope" and "%40Scope" converge on the same form.
    folded = prefix[:name_end].lower().replace("/@", "/%40")
    return folded + prefix[name_end:] + tail


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
    filters: Optional[Dict[str, Any]] = None,
):
    """
    Method to search packages in our vulnerability database

    :param project_type: Project type.
    :param pkg_list: List of packages to search.
    :param fuzzy_search: Perform fuzzy search by creating variations. Disabled by default.
    :param search_order: Search order such as purl, cpe, url, cpu.
    :param filters: Optional vdb push-down filters (see build_search_filters).
        When None or empty, behaviour is identical to the unfiltered path.

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
            tmp_expanded, pkg_aliases, tmp_purl_aliases = generate_variations(pkg, pkg_aliases)
            expanded_list.extend(tmp_expanded)
            purl_aliases |= tmp_purl_aliases
    else:
        expanded_list = pkg_list
    # The batched path pushes the per-package search loop down into vdb's
    # search_packages_batched, doing a lightweight with_data=False first pass
    # and hydrating only matched components. It is the default for the default
    # search order; fuzzy search and a custom search_order fall back to the
    # serial path (which preserves their variation/ordering semantics).
    if not fuzzy_search and not search_order:
        raw_results = find_vulns_batched(expanded_list, filters)
    else:
        raw_results = []
        for pkg in expanded_list:
            if res := search_expanded(pkg, fuzzy_search, search_order, filters):
                raw_results.extend(res)
    raw_results = dedup(project_type, raw_results)
    pkg_aliases = dealias_packages(raw_results, pkg_aliases=pkg_aliases, purl_aliases=purl_aliases)
    return raw_results, pkg_aliases, purl_aliases


def _pkg_to_locator(pkg: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], str]:
    """Convert a package dict to a vdb search locator.

    Mirrors the term-priority used by search_expanded: purl, then cpe, then url.
    Purls are canonicalised for search (T4). Returns ``(locator, original_purl)``
    so the caller can restore matched_by to the SBOM purl after hydration.
    """
    purl = pkg.get("purl") or ""
    if purl:
        return {"purl": canonicalize_search_purl(purl)}, purl
    cpe = pkg.get("cpe")
    if cpe:
        return {"cpe": cpe}, ""
    url = pkg.get("url")
    if url:
        return {"url": url}, ""
    return None, ""


def find_vulns_batched(
    expanded_list: List[Dict[str, Any]], filters: Optional[Dict[str, Any]] = None
) -> List:
    """Batched vulnerability search using vdb's search_packages_batched.

    Two-pass strategy:
      1. Lightweight pass (with_data=False) — index-only, no pydantic
         hydration, to identify which components have any matches.
      2. Hydration pass — full CVE source data for matched components only.

    When no custom-data overlay is loaded (the common case), pass 2 hydrates
    the index hits captured in pass 1 directly via ``get_cve_data_batched``,
    avoiding a redundant index query. When custom data is present, each matched
    purl is re-searched with ``with_data=True`` so DB + overlay results are
    merged correctly.

    ``filters`` is applied only in pass 1 (``search_packages_batched`` and the
    custom-data ``search_by_purl_like``). Pass 2's ``get_cve_data_batched`` does
    not accept filters (verified against vdb), so pass 1 must narrow the index
    hits and pass 2 hydrates only the already-filtered set. When ``filters`` is
    None/empty, behaviour is identical to the unfiltered path.

    The versionless-purl skip (#465) is preserved: components that carry a
    purl but no version are not searched.
    """
    from vdb.lib.search import CUSTOM_DATA_CACHE

    locators: List[Dict[str, Any]] = []
    # Map canonical search term -> original SBOM purl for matched_by restoration
    term_to_original: Dict[str, str] = {}
    for pkg in expanded_list:
        # Versionless-purl skip (non-fuzzy only — fuzzy mode uses the serial
        # path). See Discussion #465.
        if pkg.get("purl") and not pkg.get("version"):
            continue
        loc, original_purl = _pkg_to_locator(pkg)
        if loc:
            locators.append(loc)
            if original_purl:
                key = loc.get("purl") or loc.get("cpe") or ""
                if key:
                    term_to_original[key] = original_purl
    if not locators:
        return []

    # Pass 1: identify matched locators without paying hydration cost. Filters
    # are pushed down here so the index hits (and result_count) already reflect
    # the narrowed set.
    hits_by_term: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    matched_terms: List[str] = []
    for batch in search_packages_batched(
        locators, batch_size=50, with_data=False, filters=filters
    ):
        for summary in batch:
            if summary.get("result_count", 0) > 0:
                term = summary["locator"].get("purl") or summary["locator"].get("cpe") or ""
                if term:
                    hits_by_term[term] = summary.get("results", [])
                    matched_terms.append(term)
    if not matched_terms:
        return []

    has_custom = bool(CUSTOM_DATA_CACHE)
    db_conn, _ = _vdb_db.get(read_only=True)
    raw_results: List = []
    for term in matched_terms:
        hits = hits_by_term[term]
        original = term_to_original.get(term, term)
        if has_custom:
            # Custom overlay may add or override results; re-search this term
            # with full data so DB + custom are merged by search_by_purl_like.
            results = list(
                search_guarding_coverage(
                    search_by_purl_like, term, with_data=True, filters=filters
                )
            )
        else:
            # Direct hydration of the index hits from pass 1 — avoids
            # re-querying the cve_index for matched components. get_cve_data_batched
            # takes no filters (verified); pass 1 already narrowed the hits.
            results = list(get_cve_data_batched(db_conn, hits, term))
        _restore_matched_by(results, term, original)
        raw_results.extend(results)
    return raw_results


def _restore_matched_by(results, canonical_term, original_term):
    """Restore the original-case purl as matched_by after a canonicalized search."""
    if not results or canonical_term == original_term:
        return
    for r in results:
        if r.get("matched_by") == canonical_term:
            r["matched_by"] = original_term


def search_expanded(
    pkg: Dict,
    fuzzy_search,
    search_order,
    filters: Optional[Dict[str, Any]] = None,
) -> List:
    """Searches packages and variations"""
    raw_results = []
    # Default search order is purl or cpe or url (pcu)
    search_term = pkg.get("purl") or pkg.get("cpe") or pkg.get("url")
    original_purl = pkg.get("purl") or ""
    # Canonicalise the purl for search (lowercase for case-insensitive types)
    # so mixed-case SBOM purls still match vdb entries. matched_by is restored
    # to the original purl afterwards to keep downstream linking intact.
    if search_term and isinstance(search_term, str) and search_term.startswith("pkg:"):
        search_term = canonicalize_search_purl(search_term)
    # Make the search logic and order configurable
    search_logic = search_by_any
    if search_order == "purl":
        search_logic = search_by_purl_like
        search_term = pkg.get("purl")
        if search_term:
            search_term = canonicalize_search_purl(search_term)
    elif search_order == "cpe":
        search_logic = search_by_cpe_like
        search_term = pkg.get("cpe")
    elif search_order == "url":
        search_logic = search_by_url
        search_term = pkg.get("url")
    elif search_order == "cpu":
        search_logic = search_by_any
        search_term = pkg.get("cpe") or pkg.get("purl") or pkg.get("url")
        if search_term and isinstance(search_term, str) and search_term.startswith("pkg:"):
            search_term = canonicalize_search_purl(search_term)
    # Discussion #465. When there are versionless purls, filter them in non-fuzzy mode
    if not fuzzy_search and search_term and pkg.get("purl") and not pkg.get("version"):
        return raw_results
    # Give preference to our search logic
    if search_term and (
        res := search_guarding_coverage(search_logic, search_term, with_data=True, filters=filters)
    ):
        _restore_matched_by(res, search_term, original_purl)
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
        if res := search_logic(alt_search_term, with_data=True, filters=filters):
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
                pkg_aliases[f"{vendor.lower()}:{name.lower()}:{version}"].append(vari_full_pkg)
            else:
                pkg_aliases[f"{vendor.lower()}:{name.lower()}:{version}"] = [vari_full_pkg]
            if pkg.get("purl"):
                purl_aliases[f"{vari_full_pkg.lower()}:{version}"] = pkg["purl"]
    return expanded_list, pkg_aliases, purl_aliases
