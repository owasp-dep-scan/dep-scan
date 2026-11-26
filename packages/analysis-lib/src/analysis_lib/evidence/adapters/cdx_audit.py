"""cdx-audit reports -> evidence records.

This module is the only code that knows cdxgen's ``cdx-audit`` JSON report
format, in both audit modes. The direct BOM audit report holds one result per
input BOM with the rule findings the audit pack matched on that BOM's
components and workflows. The predictive report holds one result per audited
upstream target with the findings the target's child SBOM yielded, plus the
targets the audit skipped or failed and the target-selection entries it left
out; those become ``coverage-gap`` caveats, never silent omissions. A direct
result's ``coverage`` block states whether the registry lookups ran and how
many components a registry answered for; the rules that read registry
metadata could not assess the rest, which is a coverage gap too. Its
``privateNamespace`` part counts the components matching a private namespace
the public registry was asked about, and the ones it did not answer about.

Every rule finding becomes one ``annotation`` record with polarity
``negative``. In direct mode the record's subject is the component the
finding's location names: its purl when the location carries one that
parses, and otherwise no purl at all, with the location's bom-ref (a crypto
asset, a rootfs file, a serial number) kept as the component reference. The
finding's file is the location's own ``file`` (a workflow file) or, for a
package rule, each manifest or lockfile the matched component's
``internal:SrcFile`` properties name, stored relative to the source root; a
component two lockfiles of a monorepo declare gives one record per
lockfile. In predictive mode the record's subject is the audited
dependency's own purl, the purl the user's BOM carries: the finding's own
location names a component and a file of the upstream repository, which
the user's tree does not hold, so both are kept in the record's attributes
instead.

Caveats are collected per run before any record is built: the summary's
shortfall markers, the skipped and failed targets, the target-selection
skips (one caveat per reason with its count) and the findings that became
no record ride on every record of the run, and a direct result's registry
coverage caveats on the records of that result.

The report names its own shape version in ``version`` and the producing tool
in ``tool``; the gate runs on the shape version, and the producer block
carries the tool version. A report whose shape predates the version field is
accepted with a ``schema-unknown`` caveat.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from packageurl import PackageURL

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

#: The cdx-audit rules that read registry metadata. They evaluate only what
#: the BOM carries, so a direct audit that did not look the packages up, or
#: whose lookup a registry did not answer, could not assess them.
REGISTRY_RULES = (
    "deprecated npm packages, yanked releases, missing versions, package age "
    "and native binaries"
)


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


def _count(value: Any) -> int:
    """A non-negative integer count, or 0 for anything else (a negative
    number, a boolean, text, a missing value)."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return 0
    return value


def _private_namespace_caveat(block: Dict[str, Any]) -> Optional[EvidenceCaveat]:
    """The caveat of a direct result's private-namespace ``coverage`` block.

    cdx-audit counts the components whose name matches a private namespace
    (``matched``) and, having asked the public registry about each name, the
    ones it did not answer about (``unknown``). A name nobody answered about
    is neither reported as published publicly nor known to be free, which is
    a coverage gap; ``publicRegistry`` says whether the registries were asked
    at all.
    """
    matched = _count(block.get("matched"))
    unknown = _count(block.get("unknown"))
    if not matched or not unknown:
        return None
    if as_str(block.get("publicRegistry")) == "offline":
        why = "the audit ran offline and made no registry request"
    else:
        why = "the public registry did not answer about them"
    share = f"{unknown} of {matched}" if unknown != matched else str(unknown)
    return EvidenceCaveat(
        kind="coverage-gap",
        detail=(
            f"the dependency-confusion check did not assess {share} component(s) "
            f"matching a private namespace, because {why}"
        ),
    )


def _registry_caveats(coverage: Dict[str, Any]) -> List[EvidenceCaveat]:
    """The caveats of a direct result's registry ``coverage`` block.

    cdx-audit counts the npm, PyPI and Cargo components that name a version
    (``eligible``), the ones a registry answered for, and the rest
    (``withoutMetadata``), and says under ``registryMetadata`` whether the
    lookups ran at all. A lookup that did not run, or a component no
    registry answered for, leaves the rules that read registry metadata
    unable to assess that component, which is a coverage gap and never a
    clean result.
    """
    caveats: List[EvidenceCaveat] = []
    private_namespace = _private_namespace_caveat(as_dict(coverage.get("privateNamespace")))
    if private_namespace is not None:
        caveats.append(private_namespace)
    eligible = _count(coverage.get("eligible"))
    without = _count(coverage.get("withoutMetadata"))
    mode = as_str(coverage.get("registryMetadata"))
    scope = f"{eligible} npm, PyPI or Cargo component(s)" if eligible else "the scan's components"
    if mode and mode != "fetched":
        why = (
            "the audit ran offline and made no registry request"
            if mode == "offline"
            else f"the audit was not asked for registry lookups ({mode})"
        )
        caveats.append(
            EvidenceCaveat(
                kind="coverage-gap",
                detail=(
                    f"cdx-audit did not look up registry metadata because {why}, "
                    f"so its rules that read it ({REGISTRY_RULES}) did not assess {scope}"
                ),
            )
        )
    # The per-component count means something only when the lookups ran:
    # offline or unrequested, every eligible component is without metadata
    # and the caveat above already says why.
    if without and mode == "fetched":
        share = f"{without} of {eligible}" if eligible else str(without)
        caveats.append(
            EvidenceCaveat(
                kind="coverage-gap",
                detail=(
                    f"{share} npm, PyPI or Cargo component(s) carry no registry metadata "
                    "after the lookup (absent from the registry, served from an index "
                    "the public registry does not hold, or failed in the lookup), so "
                    f"cdx-audit's rules that read it ({REGISTRY_RULES}) did not assess them"
                ),
            )
        )
    return caveats


def _is_purl(value: str) -> bool:
    """Whether ``value`` parses as a package URL. A bom-ref such as
    ``crypto/algorithm/md5@1.2.840.113549.2.5``, ``urn:uuid:...`` or
    ``file:/usr/bin/su`` names a component but is no purl."""
    if not value.startswith("pkg:"):
        return False
    try:
        PackageURL.from_string(value)
    except ValueError:
        return False
    return True


def _purls_of(location: Any) -> List[str]:
    """The purls one finding's location names: the ``purl`` when it parses,
    else the ``bomRef`` when that is a purl. A location that names its
    component only by a bom-ref that is no purl names no purl at all; the
    bom-ref stays the record's component reference."""
    block = as_dict(location)
    for key in ("purl", "bomRef"):
        value = as_str(block.get(key)).strip()
        if value and _is_purl(value):
            return [value]
    return []


def _component_ref_of(location: Any) -> Optional[str]:
    """The bom-ref a finding's location names, else its purl."""
    block = as_dict(location)
    return as_str(block.get("bomRef")).strip() or as_str(block.get("purl")).strip() or None


#: The property names a cdxgen component records its declaring manifest or
#: lockfile under. cdxgen writes ``internal:SrcFile``; older BOMs and other
#: generators write ``SrcFile``.
SRC_FILE_PROPERTIES = ("internal:SrcFile", "SrcFile")


def _declaring_files(finding: dict) -> List[str]:
    """The manifests or lockfiles that declare the component a finding
    matched, from the matched component's ``SrcFile`` properties.

    cdxgen merges every copy of one package version in a monorepo into one
    component with one ``SrcFile`` per declaring file, so the copies are
    told apart by these files and nothing else."""
    files: List[str] = []
    properties = as_dict(finding.get("_match")).get("properties")
    for prop in properties if isinstance(properties, list) else []:
        prop = as_dict(prop)
        if as_str(prop.get("name")) in SRC_FILE_PROPERTIES:
            value = as_str(prop.get("value")).strip()
            if value and value not in files:
                files.append(value)
    return files


@dataclass
class _PendingFinding:
    """One finding read and validated, waiting for the run's caveats."""

    finding: dict
    subject_purls: List[str]
    component_ref: Optional[str]
    audit_attributes: Dict[str, Any]
    file_relative: Optional[str]
    outside_file: Optional[str]
    upstream_file: Optional[str]
    result_caveats: Tuple[EvidenceCaveat, ...] = ()
    confidence: Optional[str] = None


def _finding_record(
    pending: _PendingFinding,
    *,
    producer: EvidenceProducer,
    paths: SourcePaths,
    source: str,
    caveats: Tuple[EvidenceCaveat, ...],
) -> Evidence:
    """One annotation record for one cdx-audit rule finding.

    The record keeps the finding's rule id, title, severity, category,
    message, mitigation and evidence object as given (paths neutralized),
    plus the audited target's own assessment in predictive mode. In direct
    mode its location carries the finding's file in the relative spelling,
    and a file the source root cannot hold is left out with the basename
    kept in the attributes. In predictive mode the file is one in the
    target's upstream repository, so it stays an attribute and never
    becomes a location in the user's tree.
    """
    finding = pending.finding
    rule_id = as_str(finding.get("ruleId"))
    location = as_dict(finding.get("location"))
    attributes: Dict[str, Any] = {"id": rule_id}
    for key in ("name", "description", "severity", "category", "message", "mitigation"):
        value = finding.get(key)
        if value is not None:
            attributes[key] = paths.redact(value) if isinstance(value, str) else value
    finding_purl = location.get("purl")
    finding_purl = finding_purl.strip() if isinstance(finding_purl, str) else ""
    if finding_purl:
        attributes["findingPurl"] = finding_purl
    finding_ref = location.get("bomRef")
    finding_ref = finding_ref.strip() if isinstance(finding_ref, str) else ""
    if finding_ref and finding_ref != finding_purl:
        attributes["findingRef"] = finding_ref
    if pending.component_ref and not pending.subject_purls:
        attributes["bomRef"] = pending.component_ref
    evidence = finding.get("evidence")
    if evidence not in (None, {}, []):
        attributes["evidence"] = paths.redact(paths.neutral(evidence))
    attributes.update(pending.audit_attributes)
    if pending.outside_file:
        # The file sits outside the source root; keep its basename so the
        # finding still names where it pointed.
        attributes["findingFile"] = pending.outside_file
    if pending.upstream_file:
        attributes["upstreamFile"] = paths.redact(pending.upstream_file)
    locations = (
        (EvidenceLocation(file=pending.file_relative),) if pending.file_relative else ()
    )
    discriminator_object = {
        "ruleId": rule_id,
        "purl": finding_purl or pending.component_ref or "",
        "file": pending.file_relative or pending.upstream_file or "",
        "message": as_str(finding.get("message")),
    }
    return build_record(
        source=source,
        producer=producer,
        kind="annotation",
        polarity="negative",
        discriminator=stable_discriminator(discriminator_object, paths),
        purls=tuple(pending.subject_purls),
        component_ref=pending.component_ref,
        locations=locations,
        confidence=pending.confidence if pending.confidence in ("high", "medium", "low") else None,
        attributes=attributes,
        caveats=_dedupe(list(caveats) + list(pending.result_caveats)),
    )


def _direct_pending(
    finding: dict,
    paths: SourcePaths,
    probe: SourcePaths,
    result_caveats: Tuple[EvidenceCaveat, ...],
) -> List[_PendingFinding]:
    """The pending records of one direct finding: one per file it names.

    The file is the finding location's own ``file`` when the rule names one
    (a workflow file), else each manifest or lockfile that declared the
    matched component, so two lockfiles of a monorepo that pin the same
    package give two findings. A declaring file the source root cannot
    hold (a path inside a container image) is no location in the scanned
    tree and is left out without a caveat; ``probe`` tests that without
    counting it."""
    location = as_dict(finding.get("location"))
    own_file = as_str(location.get("file")).strip()
    raw_files = [own_file] if own_file else []
    if not raw_files:
        raw_files = [path for path in _declaring_files(finding) if probe.relative(path)]
    raw_files = raw_files or [""]
    pending: List[_PendingFinding] = []
    for raw in raw_files:
        relative = paths.relative(raw) if raw else None
        outside = raw.replace("\\", "/").rsplit("/", 1)[-1] if raw and relative is None else None
        pending.append(
            _PendingFinding(
                finding=finding,
                subject_purls=_purls_of(location),
                component_ref=_component_ref_of(location),
                audit_attributes={"auditMode": "direct"},
                file_relative=relative,
                outside_file=outside,
                upstream_file=None,
                result_caveats=result_caveats,
            )
        )
    return pending


def _selection_skip_caveats(selection_skips: List[Any], skipped: SkipTally) -> List[EvidenceCaveat]:
    """One caveat per target-selection skip reason, with its count.

    A predictive audit of a large BOM skips hundreds of purls for the same
    reason (an ecosystem it does not audit, an allowlisted package), so
    each reason is stated once with how many purls it left out, and a
    reason that covers a single purl names it."""
    by_reason: Dict[str, List[str]] = {}
    for skip in selection_skips:
        if not isinstance(skip, dict):
            skipped.add("skipped entries are not JSON objects and were not read")
            continue
        reason = as_str(skip.get("reason")) or "no reason given"
        by_reason.setdefault(reason, []).append(as_str(skip.get("purl")))
    caveats = []
    for reason, purls in by_reason.items():
        if len(purls) == 1:
            subject = purls[0] or "a purl"
        else:
            subject = f"{len(purls)} purls"
        caveats.append(
            EvidenceCaveat(
                kind="coverage-gap",
                detail=f"the audit did not select {subject} for analysis: {reason}",
            )
        )
    return caveats


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

    Every caveat of the run (its summary markers, the targets it skipped or
    failed, the purls it did not select, findings it could not read) is
    collected before any record is built, and every record of the run
    carries the same set; a direct result's own registry coverage caveats
    go on that result's records only.
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
    probe = SourcePaths([source_root])
    skipped = SkipTally()
    run_caveats: List[EvidenceCaveat] = list(gate.caveats)
    result_level: List[EvidenceCaveat] = []
    pending: List[_PendingFinding] = []

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
        run_caveats.append(
            EvidenceCaveat(
                kind="coverage-gap",
                detail=f"the audit's target cap left {truncated} target(s) unanalyzed",
            )
        )
    if summary.get("offline") is True:
        run_caveats.append(
            EvidenceCaveat(
                kind="coverage-gap",
                detail="the audit ran offline and made no upstream requests",
            )
        )
    if summary.get("timeBudgetExhausted") is True:
        run_caveats.append(
            EvidenceCaveat(
                kind="coverage-gap",
                detail="the audit's time budget was spent before every target started",
            )
        )

    for entry in results or []:
        if not isinstance(entry, dict):
            skipped.add("report results are not JSON objects and became no record")
            continue
        findings = entry.get("findings")
        if findings is not None and not isinstance(findings, list):
            skipped.add(
                f"{audit_mode} results carry a findings value that is not an array "
                "and became no record"
            )
            findings = []
        if audit_mode == "direct":
            # This result's coverage gaps belong to the BOM it audited, so
            # they go on that BOM's records.
            coverage_caveats = tuple(_registry_caveats(as_dict(entry.get("coverage"))))
            result_level.extend(coverage_caveats)
            for finding in findings or []:
                if not isinstance(finding, dict):
                    skipped.add("findings are not JSON objects and became no record")
                    continue
                if not as_str(finding.get("ruleId")):
                    skipped.add("findings carry no rule id and became no record")
                    continue
                pending.extend(_direct_pending(finding, paths, probe, coverage_caveats))
            continue
        # Predictive mode: one result per target.
        target = as_dict(entry.get("target"))
        target_purl = as_str(target.get("purl"))
        bom_refs = target.get("bomRefs")
        target_refs = [
            ref for ref in (bom_refs if isinstance(bom_refs, list) else []) if isinstance(ref, str) and ref
        ] or ([target_purl] if target_purl else [])
        subject_purls = sorted({ref for ref in target_refs if _is_purl(ref)})
        status = as_str(entry.get("status")) or "audited"
        if status != "audited":
            # A target the audit skipped (offline, time budget, no
            # repository resolved from the purl) or failed on (a clone or
            # child SBOM error) is coverage the audit did not get. The error
            # text can name paths on this machine, so it is redacted.
            reason = paths.redact(as_str(entry.get("error")))
            error_type = as_str(entry.get("errorType"))
            detail = f"the predictive audit did not audit {target_purl or 'a target'}"
            if status == "skipped":
                detail += "; it was skipped"
            else:
                detail += f"; it failed ({error_type or 'runtime error'})"
            if reason:
                detail += f": {reason}"
            run_caveats.append(EvidenceCaveat(kind="coverage-gap", detail=detail))
            continue
        assessment = as_dict(entry.get("assessment"))
        audit_attributes = {"auditMode": "predictive", "targetPurl": target_purl}
        for key in ("score", "severity", "confidenceLabel"):
            value = assessment.get(key)
            if value is not None:
                audit_attributes[f"audit{key[0].upper()}{key[1:]}"] = value
        for finding in findings or []:
            if not isinstance(finding, dict):
                skipped.add("findings are not JSON objects and became no record")
                continue
            if not as_str(finding.get("ruleId")):
                skipped.add("findings carry no rule id and became no record")
                continue
            upstream = as_str(as_dict(finding.get("location")).get("file")).strip()
            pending.append(
                _PendingFinding(
                    finding=finding,
                    subject_purls=subject_purls,
                    component_ref=target_refs[0] if target_refs else None,
                    audit_attributes=audit_attributes,
                    file_relative=None,
                    outside_file=None,
                    upstream_file=upstream.replace("\\", "/") or None,
                    confidence=as_str(assessment.get("confidenceLabel")) or None,
                )
            )

    # Target-selection skips: purls the audit never considered, counted
    # per reason.
    selection_skips = document.get("skipped")
    if selection_skips is not None and not isinstance(selection_skips, list):
        skipped.add("the report's skipped value is not an array and was not read")
        selection_skips = []
    run_caveats.extend(_selection_skip_caveats(selection_skips or [], skipped))
    outside = paths.producer_caveat()
    run_level = _dedupe(run_caveats + skipped.caveats() + ([outside] if outside else []))

    records: List[Evidence] = []
    for item in pending:
        try:
            records.append(
                _finding_record(
                    item,
                    producer=producer,
                    paths=paths,
                    source=source,
                    caveats=tuple(run_level),
                )
            )
        except RecursionError:
            skipped.add(TOO_DEEP_REASON)
    too_deep = [caveat for caveat in skipped.caveats() if TOO_DEEP_REASON in caveat.detail]
    all_caveats = _dedupe(run_level + result_level + too_deep)
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
