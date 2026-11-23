"""Conversion of blint security check findings into dep-scan findings.

blint reports two kinds of results for a binary: security check findings (a
missing stack protector, a writable and executable segment, an unsigned
executable) and capability reviews (the binary imports a function that reads
the environment). Only the checks are findings: each one names a hardening
property the binary lacks, which is the ``binary-hardening`` category of the
finding schema. The capability reviews describe behaviour, not a defect, and
stay in the raw ``reviews.json`` report next to the BOM.

One finding per blint rule and binary. The fingerprint carries the rule and
the binary's path as the record spells it, relative to the scan root, so
moving the scan root or rebuilding the binary under the same path keeps the
id, and the same rule firing on two different binaries gives two findings
that can be suppressed separately.

The checks reach the findings file from the presence records the evidence
adapter built from the review's documents: the adapter is the only reader of
the report format, and the findings file reads only records.
"""

import json
from typing import Any, Iterable, List, Optional

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

# The severity names the finding schema publishes. blint uses the same five
# plus none-like values on a few wasm findings.
_SEVERITIES = ("critical", "high", "medium", "low", "info")
_CONFIDENCES = ("high", "medium", "low")


def _severity(value: Any) -> str:
    name = str(value or "").strip().lower()
    return name if name in _SEVERITIES else "unknown"


def _evidence(value: Any) -> Optional[List[str]]:
    if value in (None, "", {}, []):
        return None
    if isinstance(value, str):
        return [value]
    return [json.dumps(value, sort_keys=True, default=str)]


#: The capability a binary-hardening finding's coverage names, as the
#: doctor names it.
BINARY_CAPABILITY = "binary"

#: The record caveat kinds that mean the review did not cover everything it
#: was asked to: units blint failed or skipped, and report entries the
#: adapter could not turn into records.
_COVERAGE_CAVEAT_KINDS = ("coverage-gap", "record-skipped")


def _coverage(record: Evidence) -> Coverage:
    """The finding's coverage from the record's caveats. The state is always
    ``assessed``, because blint ran and reported the finding; the units it
    failed or skipped, and the entries the adapter could not read, follow as
    one reason per coverage caveat, in the record's order."""
    reasons = [
        CoverageReason(capability=BINARY_CAPABILITY, reason=caveat.kind, detail=caveat.detail)
        for caveat in record.caveats or []
        if caveat.kind in _COVERAGE_CAVEAT_KINDS
    ]
    return Coverage(state="assessed", reasons=reasons or None)


def findings_from_blint_records(records: Optional[Iterable[Evidence]]) -> List[Finding]:
    """The findings of the blint check records the evidence adapter made.

    Only the adapter's negative presence records are checks: a capability
    review's positive record describes behaviour, not a defect, and a
    record of another producer or kind is not blint's to say. The producer
    version is the record's own, which on a live scan is the blint that
    just ran (the version the blint-written BOM's ``metadata.tools``
    names). The fingerprint carries the rule id and the binary's path,
    which the adapter already made relative to the scan root, so a record
    from a moved root keeps the finding id. A record whose location the
    adapter left out because the binary sits outside the root carries the
    path's basename in its attributes, and the finding uses that basename.

    The finding's components are the record's subject purls, the binary's
    reconciled component. Its coverage carries the record's coverage-gap
    and record-skipped caveats (units blint failed or skipped, report
    entries that became no record) as reasons and reads ``not_assessed``
    when there is one, so a review that did not cover the whole target
    never reads as complete.

    A record whose attributes carry no rule id is skipped, and the same
    rule on the same binary collapses onto one finding.
    """
    findings: List[Finding] = []
    seen = set()
    for record in records or []:
        if record.kind != "presence" or record.polarity != "negative":
            continue
        if record.producer.name != "blint":
            continue
        attributes = record.attributes if isinstance(record.attributes, dict) else {}
        rule = str(attributes.get("id") or "").strip()
        if not rule:
            continue
        if record.locations:
            binary = record.locations[0].file
        else:
            # The adapter leaves the location out when the binary sits
            # outside the scan root and keeps the path's basename in the
            # record's attributes; the finding falls back to it.
            binary = str(attributes.get("fileName") or "")
        title = str(attributes.get("title") or "").strip() or rule
        confidence = (record.confidence or "").strip().lower()
        properties = []
        for name, key in (
            ("blint:exeType", "exe_type"),
            ("blint:findingId", "finding_id"),
            ("blint:exeName", "exe_name"),
        ):
            value = attributes.get(key)
            if value:
                properties.append(FindingProperty(name=name, value=str(value)))
        finding = Finding(
            id=finding_fingerprint("binary-hardening", rule, [], file=binary),
            category="binary-hardening",
            rule=rule,
            title=title,
            severity=_severity(attributes.get("severity")),
            coverage=_coverage(record),
            producer=Producer(name="blint", version=record.producer.version),
            confidence=confidence if confidence in _CONFIDENCES else None,
            components=sorted(record.subject.purls) or None,
            locations=[Location(binary=binary)] if binary else None,
            evidence=_evidence(attributes.get("evidence")),
            properties=properties or None,
        )
        if finding.id not in seen:
            seen.add(finding.id)
            findings.append(finding)
    return findings
