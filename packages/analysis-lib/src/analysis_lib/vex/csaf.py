"""CSAF VEX orchestrator.

``build_csaf`` assembles a complete, schema-ready CSAF document dict from a
VDR result, the source BOM and the reachability map. It owns the product-id
integrity check (every referenced product must be defined in the product tree)
and the aggregate-severity computation.

This module is deliberately free of IO: all filesystem and TOML concerns live
in :mod:`analysis_lib.vex.emit`.
"""

from typing import Any, Dict, List, Optional

from analysis_lib.vex.cvss import best_severity
from analysis_lib.vex.models import CsafDoc, Document, Note, Publisher, Reference
from analysis_lib.vex.product_tree import (
    build_product_tree,
    defined_product_ids,
    referenced_product_ids,
)
from analysis_lib.vex.tracking import build_tracking
from analysis_lib.vex.vulnerabilities import build_vulnerability

LEGAL_DISCLAIMER = (
    "Depscan reachability analysis only covers the project source code, not "
    "the code of dependencies. A dependency may execute vulnerable code when "
    "called even if it is not in the project's source code. A product that "
    "no analyzer observed on an executed path is reported as "
    "'under_investigation', not as 'known_not_affected'."
)


def _aggregate_severity(scores_bodies: List[Dict[str, Any]]) -> Optional[str]:
    sev = best_severity(scores_bodies)
    if not sev:
        return None
    # SEVERITY_REF maps lower-case name -> rank; surface a capitalized label.
    return sev.capitalize()


def _build_publisher(meta: Dict[str, Any]) -> Publisher:
    publisher = meta.get("publisher") or {}
    return Publisher(
        category=publisher.get("category") or "vendor",
        name=publisher.get("name") or "OWASP dep-scan",
        namespace=publisher.get("namespace") or "https://github.com/owasp-dep-scan/dep-scan",
        contact_details=publisher.get("contact_details"),
    )


def _build_document_notes(meta: Dict[str, Any]) -> List[Note]:
    notes: List[Note] = []
    for raw in meta.get("note") or []:
        text = (raw.get("text") or "").strip() if isinstance(raw, dict) else ""
        if not text:
            continue
        notes.append(
            Note(
                category=(raw.get("category") or "other") if isinstance(raw, dict) else "other",
                text=text,
                title=raw.get("title") if isinstance(raw, dict) else None,
                audience=raw.get("audience") if isinstance(raw, dict) else None,
            )
        )
    notes.append(Note(category="legal_disclaimer", text=LEGAL_DISCLAIMER))
    return notes


def _build_document_references(meta: Dict[str, Any]) -> List[Reference]:
    refs: List[Reference] = []
    for raw in meta.get("reference") or []:
        if not isinstance(raw, dict):
            continue
        summary = (raw.get("summary") or "").strip()
        url = (raw.get("url") or "").strip()
        if not summary or not url:
            continue
        refs.append(
            Reference(summary=summary, url=url, category=raw.get("category") or "external")
        )
    return refs


def build_csaf(
    bom: Dict[str, Any],
    pkg_vulnerabilities: List[Dict[str, Any]],
    reached_purls: Optional[Dict[str, int]] = None,
    meta: Optional[Dict[str, Any]] = None,
    csaf_version: str = "2.1",
) -> Dict[str, Any]:
    """Assemble a CSAF document dict ready for schema validation/writing.

    :param bom: CycloneDX BOM used to build the product tree.
    :param pkg_vulnerabilities: VDR vulnerability records (``vdr_result.pkg_vulnerabilities``).
    :param reached_purls: reachability map (``vdr_result.reached_purls``).
    :param meta: optional ``csaf.toml`` metadata (publisher/tracking/notes/refs).
    :param csaf_version: target CSAF version (``"2.0"`` or ``"2.1"``).
    """
    meta = meta or {}
    document_meta = meta.get("document") or {}
    product_tree, purl_to_id = build_product_tree(bom, csaf_version)

    reached = reached_purls or {}
    vuln_models = []
    scores_for_aggregate: List[Dict[str, Any]] = []
    for raw_vuln in pkg_vulnerabilities or []:
        vuln_model = build_vulnerability(raw_vuln, purl_to_id, reached, csaf_version)
        if vuln_model is None:
            continue
        vuln_models.append(vuln_model)
        for score in vuln_model.scores:
            if score.cvss_v2:
                scores_for_aggregate.append({"cvss_v2": score.cvss_v2})
            if score.cvss_v3:
                scores_for_aggregate.append({"cvss_v3": score.cvss_v3})
            if score.cvss_v4:
                scores_for_aggregate.append({"cvss_v4": score.cvss_v4})

    tracking = build_tracking(meta.get("tracking") or {}, generated_id="")
    publisher = _build_publisher(meta)
    distribution = meta.get("distribution") or {}
    doc = Document(
        category=document_meta.get("category") or "csaf_vex",
        csaf_version=csaf_version,
        title=document_meta.get("title") or "dep-scan VEX",
        publisher=publisher,
        tracking=tracking,
        notes=_build_document_notes(meta),
        references=_build_document_references(meta),
        aggregate_severity=_aggregate_severity(scores_for_aggregate),
        tlp_label=(distribution.get("tlp") or {}).get("label")
        if isinstance(distribution, dict)
        else None,
        distribution_text=distribution.get("text") if isinstance(distribution, dict) else None,
    )

    csaf = CsafDoc(document=doc, product_tree=product_tree, vulnerabilities=vuln_models)
    out = csaf.to_dict(csaf_version)

    # Integrity check the JSON Schema cannot express: every referenced
    # product_id must be defined in the product_tree.
    _assert_no_dangling_references(out)

    return out


def _assert_no_dangling_references(doc: Dict[str, Any]) -> None:
    defined = defined_product_ids(doc)
    referenced = referenced_product_ids(doc)
    dangling = referenced - defined
    if dangling:
        raise AssertionError(
            f"CSAF document has {len(dangling)} product_id(s) referenced in "
            f"product_status/scores/flags/remediations but missing from the "
            f"product_tree. First few: {sorted(dangling)[:5]}"
        )
