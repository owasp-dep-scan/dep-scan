"""Reference and id building for CSAF vulnerabilities.

Reuses :func:`analysis_lib.advisory.get_ref_summary_helper` so reference
classification lives in a single place in the codebase.

Schema rules enforced here:

* Every reference has a non-empty ``summary`` and a ``url`` that is a valid
  http(s) IRI.
* Every id has non-empty ``system_name`` and ``text``.
"""

import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from analysis_lib.advisory import get_ref_summary_helper
from analysis_lib.config import REF_MAP

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
# Advisory prefixes worth surfacing as CSAF ids, mapped to the issuing
# system_name required by the CSAF ``ids`` schema. Distro advisories
# (DLA/DSA/ELSA/ALAS/USN/...) are included so items that carry only such an
# identifier are never left without a CSAF vulnerability id (§6.1.27).
_ADVISORY_SYSTEMS = {
    "CVE": "MITRE CVE",
    "GHSA": "GitHub Security Advisory",
    "RHSA": "Red Hat Security Advisory",
    "RHBA": "Red Hat Bug Advisory",
    "DSA": "Debian Security Advisory",
    "DLA": "Debian LTS Advisory",
    "USN": "Ubuntu Security Notice",
    "ELSA": "Oracle Linux Security Advisory",
    "ELBA": "Oracle Linux Bug Advisory",
    "ALAS": "Amazon Linux Security Advisory",
    "ALAS2": "Amazon Linux 2 Security Advisory",
    "ALBA": "AlmaLinux Bug Advisory",
    "ALSA": "AlmaLinux Security Advisory",
    "ALS2": "AlmaLinux 2 Security Advisory",
    "ASFA": "AlmaLinux SIG Advisory",
    "GLSA": "Gentoo Linux Security Advisory",
    "MGASA": "Mageia Security Advisory",
    "SUSE-SU": "SUSE Security Update",
    "OPENSUSE-SU": "openSUSE Security Update",
    "FEDORA": "Fedora Update Advisory",
    "NTAP": "NetApp Advisory",
    "ZDI": "Zero Day Initiative Advisory",
}
_ADVISORY_TOKEN_RE = re.compile(
    r"\b((?:"
    + "|".join(sorted(_ADVISORY_SYSTEMS, key=len, reverse=True))
    + r")-[0-9A-Za-z:.\-]{2,})\b",
    re.IGNORECASE,
)
_VALID_SCHEMES = {"http", "https"}


def _system_name_for(token: str) -> str:
    """Map an advisory token (e.g. ``DLA-4485-1``) to its issuing system."""
    upper = token.upper()
    for prefix in sorted(_ADVISORY_SYSTEMS, key=len, reverse=True):
        if upper.startswith(prefix + "-"):
            return _ADVISORY_SYSTEMS[prefix]
    if _CVE_RE.match(token):
        return _ADVISORY_SYSTEMS["CVE"]
    return "Advisory"


def synthesize_id(source: str) -> Optional[Dict[str, str]]:
    """Extract a CSAF ``ids`` entry from a raw id/title string, or ``None``.

    Used as a last-resort so a vulnerability whose only identifier lives in its
    ``id``/``title`` (distro advisories like ``DLA-4485-1``) still satisfies
    §6.1.27 (each item must carry at least one of ``cve``/``ids``).
    """
    token = _extract_advisory_token(source or "", source or "")
    if not token:
        return None
    return {"system_name": _system_name_for(token), "text": token.upper()}


def _is_real_url(url: str) -> bool:
    if not url:
        return False
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    return parsed.scheme in _VALID_SCHEMES and bool(parsed.netloc)


def _extract_advisory_token(url: str, title: str) -> str:
    """Pull a recognizable advisory/CVE id out of a url or title."""
    for source in (url, title or ""):
        m = _ADVISORY_TOKEN_RE.search(source)
        if m:
            return m.group(1).upper()
        m = _CVE_RE.search(source)
        if m:
            return m.group(0).upper()
    return ""


def _summarize(url: str, fallback_name: str) -> str:
    """Return a non-empty CSAF summary for a url."""
    _, _, summary = get_ref_summary_helper(url, REF_MAP)
    if summary and summary != "Other":
        return summary
    if fallback_name:
        return fallback_name
    return summary or "External"


def build_references_and_ids(
    references: List[Dict[str, Any]],
    advisories: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, str]], List[Dict[str, str]]]:
    """Build CSAF ``references`` and ``ids`` lists from VDR inputs.

    :return: ``(references, ids)`` each de-duplicated and schema-clean.
    """
    refs_out: List[Dict[str, str]] = []
    ids_out: List[Dict[str, str]] = []
    seen_refs = set()
    seen_ids = set()

    # VDR references carry id/source; advisories carry title/url.
    combined = []
    for r in references or []:
        url = (r.get("source") or {}).get("url") or r.get("url") or ""
        combined.append(
            {
                "url": url,
                "id": r.get("id") or "",
                "name": (r.get("source") or {}).get("name") or "",
                "title": r.get("title") or "",
            }
        )
    for a in advisories or []:
        combined.append(
            {
                "url": a.get("url") or "",
                "id": "",
                "name": "",
                "title": a.get("title") or "",
            }
        )

    for entry in combined:
        url = entry["url"].strip()
        if not _is_real_url(url):
            continue
        summary = _summarize(url, entry["name"])
        if not summary:
            continue
        ref_key = (summary, url)
        if ref_key not in seen_refs:
            seen_refs.add(ref_key)
            refs_out.append({"summary": summary, "url": url, "category": "external"})

        token = (entry["id"] or _extract_advisory_token(url, entry["title"])).strip()
        if not token:
            continue
        text = token.upper()
        id_key = (summary, text)
        if id_key in seen_ids:
            continue
        seen_ids.add(id_key)
        ids_out.append({"system_name": summary, "text": text})

    ids_out.sort(key=lambda i: (i["system_name"], i["text"]))
    refs_out.sort(key=lambda r: (r["url"], r["summary"]))
    return refs_out, ids_out
