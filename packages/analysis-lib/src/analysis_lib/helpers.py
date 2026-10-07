"""Pure, dependency-free helpers shared across analysis_lib modules.

This is a leaf module: it must not import from other analysis_lib modules.
Both ``utils`` and ``output`` import from here, which keeps the import graph
acyclic (``utils`` already imports ``output`` for the tree rendering helpers).
"""

from typing import Dict

from vdb.lib.utils import version_compare


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


def max_version(version_list):
    """
    Method to return the highest version from the list

    :param version_list: single version string or set of versions
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
    for i, vl in enumerate(version_list):
        if not vl:
            continue
        if not version_compare(vl, min_ver, max_ver):
            max_ver = vl
    return max_ver
