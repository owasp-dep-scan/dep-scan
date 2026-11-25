"""cdx-audit reports -> evidence records.

This module is the only code that knows cdxgen's ``cdx-audit`` JSON report
format, in both audit modes. The direct BOM audit report holds one result per
input BOM with the rule findings the audit pack matched on that BOM's
components and workflows. The predictive report holds one result per audited
upstream target with the findings the target's child SBOM yielded, plus the
targets the audit skipped or failed and the target-selection entries it left
out; those become ``coverage-gap`` caveats, never silent omissions.

Every rule finding becomes one ``annotation`` record with polarity
``negative``. In direct mode the record's subject is the component the
finding's location names, and the finding's file (a path inside the scanned
tree when the BOM was generated from it) is stored relative to the source
root. In predictive mode the record's subject is the audited dependency's own
purl, the purl the user's BOM carries: the finding's own location names a
component of the upstream child SBOM, which the user's BOM does not carry,
so it is kept in the record's attributes instead.

The report names its own shape version in ``version`` and the producing tool
in ``tool``; the gate runs on the shape version, and the producer block
carries the tool version. A report whose shape predates the version field is
accepted with a ``schema-unknown`` caveat.
"""

from typing import Any, Dict, List, Optional, Tuple

from analysis_lib.evidence import (
    Evidence,
    EvidenceCaveat,
    EvidenceLocation,
    EvidenceProducer,
)
from analysis_lib.evidence.adapters import (
    AdapterResult,
    STATUS_COMPLETED,
    SkipTally,
    SourcePaths,
    TOO_DEEP_REASON,
    as_dict,
    as_str,
    build_record,
    gate_report_version,
    guard_extract,
    not_assessed,
    stable_discriminator,
)

#: The report shape version this adapter reads. cdx-audit stamps
#: ``version: 1`` on both modes' JSON reports.
SUPPORTED_REPORT_VERSION_MAJOR = 1
KNOWN_REPORT_VERSION_MINOR = 0

PRODUCER_NAME = "cdx-audit"


def _parse_document(document: Any) -> Tuple[Optional[Any], Optional[str]]:
    """A report as a parsed value, accepting JSON text as well as an
    already-parsed object."""
    import json

    if isinstance(document, (str, bytes)):
        try:
            return json.loads(document), None
        except ValueError as e:
            return None, f"the report is not valid JSON: {e}"
    return document, None


def _purls_of(location: Any) -> List[str]:
    """The purls one finding's location names, preferring the ``purl`` over
    the ``bom-ref`` when they differ."""
    purl = as_str(as_dict(location).get("purl"))
    if purl:
        return [purl]
    ref = as_str(as_dict(location).get("bomRef"))
    return [ref] if ref else []


def _finding_record(
    finding: dict,
    *,
    producer: EvidenceProducer,
    paths: SourcePaths,
    source: str,
    subject_purls: List[str],
    component_ref: Optional[str],
    audit_attributes: Dict[str, Any],
    caveats: Tuple[EvidenceCaveat, ...],
    skipped: SkipTally,
    confidence: Optional[str] = None,
) -> Optional[Evidence]:
    """One annotation record for one cdx-audit rule finding.

    The record keeps the finding's rule id, title, severity, category,
    message, mitigation and evidence object as given (paths neutralized),
    plus the audited target's own assessment in predictive mode. Its
    location carries the finding's file in the relative spelling, and a
    file the source root cannot hold is left out with the basename kept in
    the attributes.
    """
    rule_id = as_str(finding.get("ruleId"))
    if not rule_id:
        skipped.add("findings carry no rule id and became no record")
        return None
    location = as_dict(finding.get("location"))
    attributes: Dict[str, Any] = {"id": rule_id}
    for key in ("name", "description", "severity", "category", "message", "mitigation"):
        value = finding.get(key)
        if value is not None:
            attributes[key] = paths.redact(value) if isinstance(value, str) else value
    finding_purl = as_str(location.get("purl"))
    if finding_purl:
        attributes["findingPurl"] = finding_purl
    evidence = finding.get("evidence")
    if evidence not in (None, {}, []):
        attributes["evidence"] = paths.redact(paths.neutral(evidence))
    attributes.update(audit_attributes)
    file_relative = paths.relative(location.get("file"))
    locations = [EvidenceLocation(file=file_relative)] if file_relative else []
    if (
        isinstance(location.get("file"), str)
        and location.get("file").strip()
        and file_relative is None
        and "file" in location
    ):
        # The file sits outside the source root; keep its basename so the
        # finding still names where it pointed.
        attributes["findingFile"] = location["file"].replace("\\", "/").rsplit("/", 1)[-1]
    discriminator_object = {
        "ruleId": rule_id,
        "purl": finding_purl or component_ref or "",
        "file": file_relative or "",
        "message": as_str(finding.get("message")),
    }
    return build_record(
        source=source,
        producer=producer,
        kind="annotation",
        polarity="negative",
        discriminator=stable_discriminator(discriminator_object, paths),
        purls=tuple(subject_purls),
        component_ref=component_ref,
        locations=tuple(locations),
        confidence=confidence if confidence in ("high", "medium", "low") else None,
        attributes=attributes,
        caveats=caveats,
    )


@guard_extract(PRODUCER_NAME)
def extract(
    report,
    *,
    source: str,
    producer_version: str = "",
    source_root=None,
    mode: Optional[str] = None,
) -> AdapterResult:
    """One cdx-audit JSON report as evidence records.

    ``report`` is the parsed report (or its JSON text). ``source`` is the
    scan-directory-relative name of the report file the records came from.
    ``producer_version`` is the cdxgen version cdx-audit belongs to; the
    report's own ``version`` field gates the shape. ``source_root`` is the
    scanned directory for making the findings' file paths relative.
    ``mode`` names the audit mode when the caller already knows it; a
    report that names no ``auditMode`` reads as predictive, the shape the
    tool wrote before the field existed.
    """
    document, error = _parse_document(report)
    if error is not None or not isinstance(document, dict):
        reason = error or (
            f"the cdx-audit report is a {type(document).__name__}, not the report object"
        )
        return not_assessed(f"the cdx-audit report is malformed and was not assessed: {reason}")

    gate = gate_report_version(
        document.get("version"),
        SUPPORTED_REPORT_VERSION_MAJOR,
        KNOWN_REPORT_VERSION_MINOR,
        holder="report",
        noun="report shape version",
    )
    if not gate.accepted:
        return not_assessed(
            f"the cdx-audit report shape is not supported and was not assessed: {gate.reason}"
        )
    tool = as_dict(document.get("tool"))
    version_text = as_str(producer_version) or as_str(tool.get("version")) or "unknown"
    producer = EvidenceProducer(
        name=PRODUCER_NAME,
        version=version_text,
        report_schema_version=as_str(document.get("version")) or "unknown",
    )

    audit_mode = as_str(document.get("auditMode")) or as_str(mode) or "predictive"
    paths = SourcePaths([source_root])
    skipped = SkipTally()
    caveats: List[EvidenceCaveat] = list(gate.caveats)
    records: List[Evidence] = []

    results = document.get("results")
    if results is not None and not isinstance(results, list):
        return not_assessed(
            "the cdx-audit report is malformed and was not assessed: "
            f"its results value is a {type(results).__name__}, expected an array"
        )

    # The run-level shortfall markers the summary carries: a target cap that
    # cut the queue, an offline run, a spent time budget. Each becomes one
    # coverage-gap caveat so a consumer never reads a bounded audit as a
    # complete one.
    summary = as_dict(document.get("summary"))
    truncated = summary.get("targetCapTruncated")
    if isinstance(truncated, int) and not isinstance(truncated, bool) and truncated > 0:
        caveats.append(
            EvidenceCaveat(
                kind="coverage-gap",
                detail=(
                    f"the audit's target cap left {truncated} target(s) unanalyzed"
                ),
            )
        )
    if summary.get("offline") is True:
        caveats.append(
            EvidenceCaveat(
                kind="coverage-gap",
                detail="the audit ran offline and made no upstream requests",
            )
        )
    if summary.get("timeBudgetExhausted") is True:
        caveats.append(
            EvidenceCaveat(
                kind="coverage-gap",
                detail="the audit's time budget was spent before every target started",
            )
        )

    for entry in results or []:
        if not isinstance(entry, dict):
            skipped.add("report results are not JSON objects and became no record")
            continue
        if audit_mode == "direct":
            findings = entry.get("findings")
            if findings is not None and not isinstance(findings, list):
                skipped.add(
                    "direct results carry a findings value that is not an array "
                    "and became no record"
                )
                findings = []
            for finding in findings or []:
                if not isinstance(finding, dict):
                    skipped.add("findings are not JSON objects and became no record")
                    continue
                try:
                    record = _finding_record(
                        finding,
                        producer=producer,
                        paths=paths,
                        source=source,
                        subject_purls=_purls_of(finding.get("location")),
                        component_ref=as_str(
                            (finding.get("location") or {}).get("bomRef")
                        )
                        or None,
                        audit_attributes={"auditMode": "direct"},
                        caveats=tuple(caveats),
                        skipped=skipped,
                    )
                except RecursionError:
                    skipped.add(TOO_DEEP_REASON)
                    continue
                if record is not None:
                    records.append(record)
            continue
        # Predictive mode: one result per target.
        target = as_dict(entry.get("target"))
        target_purl = as_str(target.get("purl"))
        target_refs = [
            as_str(ref) for ref in target.get("bomRefs", []) if isinstance(ref, str) and ref
        ] or ([target_purl] if target_purl else [])
        status = as_str(entry.get("status")) or "audited"
        if status != "audited":
            # A target the audit skipped (offline, time budget, no
            # repository resolved from the purl) or failed on (a clone or
            # child SBOM error) is coverage the audit did not get.
            reason = as_str(entry.get("error")) or as_str(target.get("purl"))
            error_type = as_str(entry.get("errorType"))
            detail = f"the predictive audit did not audit {target_purl or 'a target'}"
            if status == "skipped":
                detail += "; it was skipped"
            else:
                detail += f"; it failed ({error_type or 'runtime error'})"
            if reason:
                detail += f": {reason}"
            caveats.append(EvidenceCaveat(kind="coverage-gap", detail=detail))
            continue
        assessment = as_dict(entry.get("assessment"))
        audit_attributes = {
            "auditMode": "predictive",
            "targetPurl": target_purl,
        }
        for key in ("score", "severity", "confidenceLabel"):
            value = assessment.get(key)
            if value is not None:
                audit_attributes[f"audit{key[0].upper()}{key[1:]}"] = value
        findings = entry.get("findings")
        if findings is not None and not isinstance(findings, list):
            skipped.add(
                "predictive results carry a findings value that is not an array "
                "and became no record"
            )
            findings = []
        for finding in findings or []:
            if not isinstance(finding, dict):
                skipped.add("findings are not JSON objects and became no record")
                continue
            try:
                record = _finding_record(
                    finding,
                    producer=producer,
                    paths=paths,
                    source=source,
                    subject_purls=sorted(set(target_refs)),
                    component_ref=target_refs[0] if target_refs else None,
                    audit_attributes=audit_attributes,
                    caveats=tuple(caveats),
                    skipped=skipped,
                    confidence=as_str(assessment.get("confidenceLabel")) or None,
                )
            except RecursionError:
                skipped.add(TOO_DEEP_REASON)
                continue
            if record is not None:
                records.append(record)

    # Target-selection skips: purls the audit never considered, each with
    # its own reason.
    selection_skips = document.get("skipped")
    if selection_skips is not None and not isinstance(selection_skips, list):
        skipped.add("the report's skipped value is not an array and was not read")
        selection_skips = []
    for skip in selection_skips or []:
        if not isinstance(skip, dict):
            skipped.add("skipped entries are not JSON objects and were not read")
            continue
        reason = as_str(skip.get("reason")) or "no reason given"
        purl = as_str(skip.get("purl"))
        detail = f"the audit did not select {purl or 'a purl'} for analysis: {reason}"
        caveats.append(EvidenceCaveat(kind="coverage-gap", detail=detail))

    outside = paths.producer_caveat()
    all_caveats = _dedupe(caveats + skipped.caveats() + ([outside] if outside else []))
    return AdapterResult(status=STATUS_COMPLETED, records=records, caveats=all_caveats)


def _dedupe(caveats: List[EvidenceCaveat]) -> List[EvidenceCaveat]:
    out: List[EvidenceCaveat] = []
    seen = set()
    for caveat in caveats:
        key = (caveat.kind, caveat.detail)
        if key in seen:
            continue
        seen.add(key)
        out.append(caveat)
    return out


__all__ = [
    "KNOWN_REPORT_VERSION_MINOR",
    "PRODUCER_NAME",
    "SUPPORTED_REPORT_VERSION_MAJOR",
    "extract",
]
