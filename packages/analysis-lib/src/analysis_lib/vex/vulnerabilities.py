"""Compose a single CSAF vulnerability from a VDR vulnerability record.

Brings together the product-id map (product_tree), reachability
classification, CVSS scoring, references and CWE handling into one
:class:`analysis_lib.vex.models.Vulnerability`.

Notable behaviour:

* CWE ids are emitted as ``CWE-<n>`` with the exact MITRE name; if the name is
  unknown the CWE is omitted rather than emitted as a placeholder.
* CSAF 2.0 allows only one ``cwe`` per vulnerability, so any additional CWEs
  become developer notes; CSAF 2.1 carries them all in ``cwes``.
* Notes without non-empty text are never generated.
* ``product_status`` and ``flags`` come from reachability, not version ranges.
"""

from typing import Any, Dict, List, Optional

from analysis_lib.config import CWE_MAP
from analysis_lib.vex.cvss import parse_ratings
from analysis_lib.vex.dates import to_csaf_datetime
from analysis_lib.vex.models import Flag, Note, Reference, Score, Vulnerability
from analysis_lib.vex.reachability import classify
from analysis_lib.vex.refs import build_references_and_ids, synthesize_id

_DESCRIPTION_CATEGORY = "description"
_DETAILS_CATEGORY = "details"
_OTHER_CATEGORY = "other"


def _resolve_cwes(cwes: List[Any]) -> List[Dict[str, str]]:
    """Resolve raw CWE ids to ``[{"id": "CWE-<n>", "name": <MITRE name>}]``.

    Ids whose MITRE name is unknown are dropped so a placeholder never reaches
    the document. Order is preserved so the first entry is the primary CWE.
    """
    resolved: List[Dict[str, str]] = []
    for cwe_id in cwes:
        try:
            numeric = int(cwe_id)
        except (TypeError, ValueError):
            continue
        name = CWE_MAP.get(numeric)
        if not name:
            continue
        resolved.append({"id": f"CWE-{numeric}", "name": name})
    return resolved


def _extra_cwe_notes(cwes: List[Dict[str, str]]) -> List[Note]:
    """Developer notes for CWEs beyond the first (used only for CSAF 2.0, which
    permits a single ``cwe`` per vulnerability)."""
    notes: List[Note] = []
    for cwe in cwes[1:]:
        notes.append(
            Note(
                category=_OTHER_CATEGORY,
                text=cwe["name"],
                title=f"Additional CWE: {cwe['id']}",
                audience="developers",
            )
        )
    return notes


def _build_notes(vuln: Dict[str, Any], extra_cwe_notes: List[Note]) -> List[Note]:
    """Assemble notes that always carry non-empty text."""
    notes: List[Note] = list(extra_cwe_notes)

    description = (vuln.get("description") or "").replace("\n", " ").strip()
    if description:
        notes.append(Note(category=_DESCRIPTION_CATEGORY, text=description))
    detail = (vuln.get("detail") or "").replace("\n", " ").strip()
    if detail:
        notes.append(Note(category=_DETAILS_CATEGORY, text=detail))
    recommendation = (vuln.get("recommendation") or "").replace("\n", " ").strip()
    if recommendation:
        notes.append(
            Note(
                category=_OTHER_CATEGORY,
                text=recommendation,
                title="Recommended Action",
            )
        )
    return notes


def _build_acknowledgements(source: Dict[str, Any]) -> List[Dict[str, Any]]:
    if not source or not source.get("name"):
        return []
    org = source["name"].replace(" Advisory", "")
    if source.get("url"):
        return [{"organization": org, "urls": [source["url"]]}]
    return [{"organization": org}]


def build_vulnerability(
    vuln: Dict[str, Any],
    purl_to_id: Dict[str, str],
    reached_purls: Dict[str, int],
    csaf_version: str = "2.1",
) -> Optional[Vulnerability]:
    """Map one VDR vulnerability to a CSAF :class:`Vulnerability`.

    Returns ``None`` when the vulnerability touches no product known to the
    product tree (it would otherwise have an empty product_status, which CSAF
    forbids for a vulnerability that has no other anchors).
    """
    product_status, flags, score_product_ids = classify(vuln, purl_to_id, reached_purls)
    if not product_status and not score_product_ids:
        return None

    cwes = _resolve_cwes(vuln.get("cwes") or [])
    # 2.0 keeps a single cwe and spills the rest into notes; 2.1 keeps them all.
    extra_cwe_notes = _extra_cwe_notes(cwes) if csaf_version == "2.0" else []
    notes = _build_notes(vuln, extra_cwe_notes)
    references, ids = build_references_and_ids(
        vuln.get("references") or [], vuln.get("advisories") or []
    )

    raw_scores = parse_ratings(vuln.get("ratings") or [], csaf_version)
    scores = _build_scores(raw_scores, score_product_ids)

    flag_models = [Flag(label=f["label"], product_ids=f["product_ids"]) for f in flags]
    reference_models = [
        Reference(summary=r["summary"], url=r["url"], category=r.get("category"))
        for r in references
    ]
    remediations = _build_remediations(vuln, product_status.get("known_affected") or [])

    raw_id = str(vuln.get("id") or "")
    cve = raw_id if raw_id.upper().startswith("CVE-") else None
    title = vuln.get("bom-ref") or vuln.get("id") or "vulnerability"

    # §6.1.27.8: a CSAF vulnerability item must carry at least one of cve/ids.
    # When neither the CVE nor the reference builder produced an identifier
    # (e.g. distro advisories like DLA-4485-1 or Go ids like GO-2026-5932
    # stored only in the title/id), synthesize one from the raw id or title,
    # and fall back to the raw id itself, so the item is never anonymous.
    if not cve and not ids:
        synthetic = synthesize_id(raw_id) or synthesize_id(title)
        if synthetic:
            ids = [synthetic]
        elif raw_id:
            # An id no known prefix matches is still the advisory's own
            # identifier; the source database names the system that issued it.
            source_name = str((vuln.get("source") or {}).get("name") or "").strip()
            ids = [{"system_name": source_name or "dep-scan", "text": raw_id}]

    return Vulnerability(
        cve=cve,
        title=title,
        cwes=cwes,
        notes=notes,
        product_status=product_status,
        scores=scores,
        flags=flag_models,
        references=reference_models,
        ids=ids,
        acknowledgments=_build_acknowledgements(vuln.get("source") or {}),
        # ``published`` is the public disclosure date. dep-scan has no separate
        # signal for when the issue was first *discovered*, so discovery_date is
        # left unset rather than fabricated as a copy of the disclosure date.
        disclosure_date=to_csaf_datetime(vuln.get("published") or vuln.get("updated")),
        remediations=remediations,
    )


def _build_remediations(vuln: Dict[str, Any], affected_ids: List[str]) -> List[Dict[str, Any]]:
    """Build the action statement CSAF requires for ``known_affected`` products.

    The CSAF VEX profile (§6.1.27.10) mandates a remediation for every
    ``known_affected`` product. When the VDR carries a fix recommendation we
    emit a ``vendor_fix``; otherwise the honest statement is ``none_available``.
    """
    if not affected_ids:
        return []
    product_ids = sorted(set(affected_ids))
    recommendation = (vuln.get("recommendation") or "").replace("\n", " ").strip()
    if recommendation:
        return [{"category": "vendor_fix", "details": recommendation, "product_ids": product_ids}]
    return [
        {
            "category": "none_available",
            "details": "No remediation information is available from dep-scan for this product.",
            "product_ids": product_ids,
        }
    ]


def _build_scores(raw_scores: List[Dict[str, Any]], score_product_ids: List[str]) -> List[Score]:
    """Assemble CVSS scores, keeping at most one per CVSS version.

    §6.1.7 forbids multiple scores of the same CVSS version for the same
    product. Because every score here targets the same ``score_product_ids``
    set, we keep only the first body seen per family (v2/v3/v4). The first
    body wins because :func:`parse_ratings` preserves VDR ordering, which
    places the primary source first.
    """
    if not score_product_ids or not raw_scores:
        return []
    seen_families: set = set()
    scores: List[Score] = []
    for body in raw_scores:
        for family in ("cvss_v2", "cvss_v3", "cvss_v4"):
            content = body.get(family)
            if not content or family in seen_families:
                continue
            seen_families.add(family)
            scores.append(Score(products=score_product_ids, **{family: content}))
    return scores
