"""Pure, dependency-free helpers shared across analysis_lib modules.

This is a leaf module: it must not import from other analysis_lib modules.
Both ``utils`` and ``output`` import from here, which keeps the import graph
acyclic (``utils`` already imports ``output`` for the tree rendering helpers).
"""

from typing import Dict, Optional

from vdb.lib.vers import RANGE_CLASS_BY_SCHEME, vers_compare


def is_malware_vuln(vuln: Dict) -> bool:
    """Detect a malware advisory using vdb's native ``is_malware`` signal.

    vdb's ``_attach_metadata`` populates ``is_malware`` on every hydrated result
    when extended metadata is present, and otherwise derives it from the
    ``MAL-`` cve_id prefix. This helper mirrors that fallback so behaviour is
    identical on the default DB (where ``is_malware`` comes from the prefix) and
    more accurate on the extended DB (where the metadata row is authoritative).

    The input is a vulnerability dict in either shape depscan handles: a raw vdb
    search result (carries ``cve_id`` and, when hydrated, ``is_malware``) or a
    ``VulnerabilityOccurrence.to_dict()`` (carries ``id``). When the
    ``is_malware`` key is absent we fall back to a prefix match on whichever id
    field is present.
    """
    if "is_malware" in vuln:
        return bool(vuln.get("is_malware"))
    vid = str(vuln.get("cve_id") or vuln.get("id") or "")
    return vid.startswith("MAL-")


def vers_scheme_for_purl(purl: Optional[str]) -> str:
    """The vers scheme that orders *purl*'s versions the way its ecosystem does.

    ``RANGE_CLASS_BY_SCHEME`` is vdb's own table of implemented schemes, so a
    purl type vdb has a comparator for (npm, pypi, maven, golang, cargo, gem,
    nuget, composer, deb, rpm, apk, and the rest) is used verbatim. Any other
    type (swift, pub, cran, cocoapods, conda, docker, and friends) falls back
    to ``generic``, the scheme whose ordering vers_compare itself substitutes
    for unknown schemes.
    """
    purl_type = (purl or "").split("pkg:", 1)[-1].split("/", 1)[0].lower()
    return purl_type if purl_type in RANGE_CLASS_BY_SCHEME else "generic"


def version_in_range(
    version: str,
    min_version: str,
    max_version: str,
    purl: Optional[str] = None,
) -> bool:
    """True when *version* lies in the closed interval of the two bounds.

    The interval is inclusive on both ends, matching the comparison this
    replaced. A ``*`` upper bound adds no restriction: vers_compare drops
    wildcard bounds, leaving the bare lower bound. The scheme segment comes
    from the purl so Debian revisions, RubyGems pre-releases, Maven qualifiers and
    the other ecosystem orderings apply; a missing or unrecognised purl
    degrades to ``generic``.
    """
    scheme = vers_scheme_for_purl(purl)
    return vers_compare(version, f"vers:{scheme}/>={min_version}|<={max_version}")


def max_version(version_list, purl: Optional[str] = None):
    """
    Method to return the highest version from the list

    :param version_list: single version string or set of versions
    :param purl: a purl of the package the versions belong to, used to pick
        the ecosystem ordering (Debian revisions, Maven qualifiers, ...). When
        omitted the versions are ordered generically.
    :return: max version
    """
    if isinstance(version_list, str):
        return version_list
    if isinstance(version_list, set):
        version_list = list(version_list)
    if len(version_list) == 1:
        return version_list[0]
    min_ver = "0"
    max_ver = version_list[0]
    for vl in version_list:
        if not vl:
            continue
        if not version_in_range(vl, min_ver, max_ver, purl=purl):
            max_ver = vl
    return max_ver
