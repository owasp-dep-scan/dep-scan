"""Conversion of cdx-audit findings into dep-scan findings.

cdxgen's ``cdx-audit`` is the supply-chain audit engine dep-scan runs: the
rule ids, severities, categories and the components each finding names are
cdx-audit's own, and dep-scan presents them. The findings
reach the findings file from the annotation records the evidence adapter
built from the audit report: the adapter is the only reader of the report
format, and the findings file reads only records.

One finding per cdx-audit rule and component. The category is
``supply-chain``, except for two audit packs, which are findings of the
category that already owns them: a ``cbom-security`` rule is a ``crypto``
finding and a ``rootfs-hardening`` rule a ``binary-hardening`` finding. The
fingerprint carries the rule id, the component purls and the finding's file
(the lockfile that declared the component, so two copies in a monorepo stay
apart), all in spellings that survive a rescan from a moved root, so the
same audit of the same tree keeps its ids and a suppression keyed on one
finding does not swallow another. A finding located by a bom-ref that is
no purl names no component; the bom-ref goes into the fingerprint's symbols
and a property instead. A predictive finding names the audited dependency
as its component, so the upstream component and file it matched go into
the symbols too.
"""

import json
from typing import Any, Iterable, List, Optional

from packageurl import PackageURL

from analysis_lib.evidence import Evidence
from analysis_lib.findings.fingerprint import finding_fingerprint
from analysis_lib.findings.model import (
    Coverage,
    CoverageReason,
    Finding,
    FindingProperty,
    Location,
    Producer,
)

#: The severity names the finding schema publishes; cdx-audit uses the same
#: four plus none-like values on results that found nothing.
_SEVERITIES = ("critical", "high", "medium", "low", "info")
_CONFIDENCES = ("high", "medium", "low")

#: The audit categories that map onto finding categories other than
#: ``supply-chain``, the category that already owns what they report.
CATEGORY_TO_FINDING_CATEGORY = {
    "cbom-security": "crypto",
    "rootfs-hardening": "binary-hardening",
}

#: The capability a finding's coverage caveats name, as the doctor names the
#: check that ran the audit.
SUPPLY_CHAIN_CAPABILITY = "supply-chain"


def _severity(value: Any) -> str:
    """The finding severity of a cdx-audit severity. A finding that states
    none is counted as ``low`` by cdx-audit's own summary, so it is ``low``
    here too and the two counts agree."""
    name = str(value or "").strip().lower()
    if not name:
        return "low"
    return name if name in _SEVERITIES else "unknown"


def _is_purl(value: Any) -> bool:
    """Whether ``value`` is a package URL the fingerprint can normalise."""
    if not isinstance(value, str) or not value.startswith("pkg:"):
        return False
    try:
        PackageURL.from_string(value)
    except ValueError:
        return False
    return True


def _category(attributes: dict) -> str:
    name = str(attributes.get("category") or "")
    if name in CATEGORY_TO_FINDING_CATEGORY:
        return CATEGORY_TO_FINDING_CATEGORY[name]
    rule = str(attributes.get("id") or "")
    if rule.startswith(("CBS-", "CBC-")):
        return "crypto"
    if rule.startswith("RFS-"):
        return "binary-hardening"
    return "supply-chain"


def _evidence(value: Any) -> Optional[List[str]]:
    if value in (None, "", {}, []):
        return None
    if isinstance(value, str):
        return [value]
    return [json.dumps(value, sort_keys=True, default=str)]


def findings_from_cdx_audit_records(records: Optional[Iterable[Evidence]]) -> List[Finding]:
    """The supply-chain findings of the cdx-audit records the adapter made.

    Only the adapter's negative annotation records are findings. The
    producer version is the record's own, which on a live scan is the
    cdxgen version the audit ran under. The fingerprint carries the rule
    id, the record's subject purls and the finding's file in its relative
    spelling, so a record from a moved root keeps its finding id and the
    same rule on two components gives two findings that can be suppressed
    separately.

    The finding's components are the record's subject purls: in direct
    audit mode the component the finding names in the user's BOM, in
    predictive mode the audited dependency whose upstream the audit
    cloned. Its coverage carries the record's coverage-gap caveats (a
    target cap, an offline run, a spent time budget, targets skipped or
    failed) as reasons, so a bounded audit never reads as complete; the
    state stays ``assessed``, because the audit ran and reported the
    finding.

    A record whose attributes carry no rule id is skipped. The fingerprint
    keys on the package, not the version, so the same rule on two versions
    of one package collapses onto one finding whose components hold both
    versions' purls: every component the audit named stays named.
    """
    findings: List[Finding] = []
    seen = set()
    by_id = {}
    for record in records or []:
        if record.kind != "annotation" or record.polarity != "negative":
            continue
        if record.producer.name != "cdx-audit":
            continue
        attributes = record.attributes if isinstance(record.attributes, dict) else {}
        rule = str(attributes.get("id") or "").strip()
        if not rule:
            continue
        category = _category(attributes)
        title = str(attributes.get("name") or "").strip() or rule
        confidence = (record.confidence or "").strip().lower()
        file = record.locations[0].file if record.locations else None
        properties = []
        for name, key in (
            ("cdx-audit:category", "category"),
            ("cdx-audit:auditMode", "auditMode"),
            ("cdx-audit:targetPurl", "targetPurl"),
            ("cdx-audit:auditSeverity", "auditSeverity"),
            ("cdx-audit:auditScore", "auditScore"),
            ("cdx-audit:message", "message"),
            ("cdx-audit:bomRef", "bomRef"),
            ("cdx-audit:findingPurl", "findingPurl"),
            ("cdx-audit:upstreamFile", "upstreamFile"),
        ):
            value = attributes.get(key)
            if value not in (None, ""):
                properties.append(FindingProperty(name=name, value=str(value)))
        reasons = [
            CoverageReason(
                capability=SUPPLY_CHAIN_CAPABILITY, reason=caveat.kind, detail=caveat.detail
            )
            for caveat in record.caveats or []
            if caveat.kind in ("coverage-gap", "record-skipped")
        ]
        # Only package URLs are components; a finding located by a bom-ref
        # that is no purl (a crypto asset, a rootfs file, a serial number)
        # keeps that reference in its properties and its fingerprint.
        purls = sorted(purl for purl in record.subject.purls if _is_purl(purl))
        ref = record.subject.component_ref
        components = purls or None
        # What tells two findings of one rule on the same components apart
        # beyond the file: the bom-ref of a component that has no purl, and
        # in predictive mode the upstream component and file the finding
        # was matched on, since every predictive finding of one target
        # names the target as its component.
        symbols = []
        if not purls and ref:
            symbols.append(str(ref))
        if attributes.get("auditMode") == "predictive":
            for key in ("findingPurl", "findingRef", "upstreamFile"):
                value = attributes.get(key)
                if value not in (None, ""):
                    symbols.append(f"{key}={value}")
        finding = Finding(
            id=finding_fingerprint(category, rule, purls, file=file or "", symbols=symbols),
            category=category,
            rule=rule,
            title=title,
            severity=_severity(attributes.get("severity")),
            coverage=Coverage(state="assessed", reasons=reasons or None),
            producer=Producer(name="cdx-audit", version=record.producer.version),
            confidence=confidence if confidence in _CONFIDENCES else None,
            components=components,
            locations=[Location(file=file)] if file else None,
            evidence=_evidence(attributes.get("evidence")),
            properties=properties or None,
        )
        earlier = by_id.get(finding.id)
        if earlier is None:
            seen.add(finding.id)
            by_id[finding.id] = finding
            findings.append(finding)
        else:
            # The fingerprint keys on the package, not the version (the
            # schema's own rule), so the same rule on two versions of one
            # package lands here. Merge: every component the audit named
            # stays named, and no count disappears.
            merged = sorted(set((earlier.components or []) + (components or [])))
            if merged:
                earlier.components = merged
    return findings
