"""Conversion of blint security check findings into dep-scan findings.

blint reports two kinds of results for a binary: security check findings (a
missing stack protector, a writable and executable segment, an unsigned
executable) and capability reviews (the binary imports a function that reads
the environment). Only the checks are findings: each one names a hardening
property the binary lacks, which is the ``binary-hardening`` category of the
finding schema. The capability reviews describe behaviour, not a defect, and
stay in the raw ``reviews.json`` report next to the BOM.

One finding per blint rule and binary. The fingerprint carries the rule and
the binary's path relative to the scan root, so moving the scan root or
rebuilding the binary under the same path keeps the id, and the same rule
firing on two different binaries gives two findings that can be suppressed
separately.

The checks reach the findings file through two readers that agree field for
field on the same report: this module's document reader for a blint
``findings.json``, and the records reader for the presence records the
evidence adapter built from that document. The records reader takes the
binary path from the record's location, which the adapter made relative to
the scan root, so the ``blint:exeName`` property spells the path the way the
record carries it.
"""

import json
import ntpath
import os
import re
from typing import Any, Dict, Iterable, List, Optional

from analysis_lib.evidence import Evidence
from analysis_lib.findings.fingerprint import finding_fingerprint
from analysis_lib.findings.model import (
    Coverage,
    Finding,
    FindingProperty,
    Location,
    Producer,
)

# The severity names the finding schema publishes. blint uses the same five
# plus none-like values on a few wasm findings.
_SEVERITIES = ("critical", "high", "medium", "low", "info")
_CONFIDENCES = ("high", "medium", "low")
_DRIVE_PATH = re.compile(r"^[A-Za-z]:(/|$)")


def _severity(value: Any) -> str:
    name = str(value or "").strip().lower()
    return name if name in _SEVERITIES else "unknown"


def _relative_binary(filename: Any, scan_root: Optional[str]) -> str:
    """The binary's path relative to ``scan_root``, with forward slashes.

    Both paths are made absolute first, so a relative and an absolute
    spelling of the same scan directory give the same result. When the scan
    root is the binary itself (a single-file target) the result is the file
    name, not ``.``. A path outside the root, or with no root to be relative
    to, falls back to the file name alone (a relative name is kept as it is): an absolute path would tie the
    finding id to one machine's checkout location. A Windows path (a drive
    or a UNC share, with either kind of separator) is handled with Windows
    path rules on any host, so the id is the same on every platform.
    """
    path = str(filename or "")
    if not path:
        return ""
    normalised = path.replace("\\", "/")
    name = normalised.rsplit("/", 1)[-1]
    if not scan_root:
        return normalised if not _is_absolute(normalised) else name
    root = str(scan_root)
    windows = bool(_DRIVE_PATH.match(normalised) or _DRIVE_PATH.match(root.replace("\\", "/")))
    module = ntpath if windows or normalised.startswith("//") else os.path
    try:
        relative = module.relpath(module.abspath(path), module.abspath(root))
    except ValueError:
        return name
    relative = relative.replace("\\", "/")
    if relative == ".":
        return name
    if relative == ".." or relative.startswith("../"):
        # A relative name that does not sit under the root as written is
        # taken as already relative to the root.
        return name if _is_absolute(normalised) else normalised
    return relative


def _is_absolute(normalised: str) -> bool:
    return normalised.startswith("/") or bool(_DRIVE_PATH.match(normalised))


def _evidence(value: Any) -> Optional[List[str]]:
    if value in (None, "", {}, []):
        return None
    if isinstance(value, str):
        return [value]
    return [json.dumps(value, sort_keys=True, default=str)]


def finding_from_blint(
    blint_finding: Dict[str, Any],
    *,
    producer_version: str,
    scan_root: Optional[str] = None,
) -> Finding:
    """One ``binary-hardening`` finding for one blint check result.

    :raises ValueError: when the blint finding has no rule id.
    """
    rule = str(blint_finding.get("id") or "").strip()
    if not rule:
        raise ValueError("the blint finding has no rule id")
    binary = _relative_binary(blint_finding.get("filename"), scan_root)
    title = str(blint_finding.get("title") or "").strip() or rule
    confidence = str(blint_finding.get("confidence") or "").strip().lower()
    properties = []
    for name, key in (
        ("blint:exeType", "exe_type"),
        ("blint:findingId", "finding_id"),
        ("blint:exeName", "exe_name"),
    ):
        value = blint_finding.get(key)
        if value:
            properties.append(FindingProperty(name=name, value=str(value)))
    return Finding(
        id=finding_fingerprint("binary-hardening", rule, [], file=binary),
        category="binary-hardening",
        rule=rule,
        title=title,
        severity=_severity(blint_finding.get("severity")),
        coverage=Coverage(state="assessed"),
        producer=Producer(name="blint", version=producer_version),
        confidence=confidence if confidence in _CONFIDENCES else None,
        locations=[Location(binary=binary)] if binary else None,
        evidence=_evidence(blint_finding.get("evidence")),
        properties=properties or None,
    )


def findings_from_blint(
    document: Optional[Dict[str, Any]],
    *,
    producer_version: str,
    scan_root: Optional[str] = None,
) -> List[Finding]:
    """The findings of a blint ``findings.json`` document.

    The same rule on the same binary collapses onto one finding. A document
    that is not a mapping, or an entry that is not a mapping or has no rule
    id, is skipped: a damaged review report must not stop the findings file.
    """
    findings: List[Finding] = []
    seen = set()
    entries = document.get("findings") if isinstance(document, dict) else None
    for entry in entries or []:
        if not isinstance(entry, dict) or not str(entry.get("id") or "").strip():
            continue
        finding = finding_from_blint(entry, producer_version=producer_version, scan_root=scan_root)
        if finding.id not in seen:
            seen.add(finding.id)
            findings.append(finding)
    return findings


def findings_from_blint_records(records: Optional[Iterable[Evidence]]) -> List[Finding]:
    """The findings of the blint check records the evidence adapter made.

    Only the adapter's negative presence records are checks: a capability
    review's positive record describes behaviour, not a defect, and a
    record of another producer or kind is not blint's to say. The producer
    version is the record's own, which on a live scan is the blint that
    just ran (the version the blint-written BOM's ``metadata.tools``
    names). The fingerprint carries the rule id and the binary's path,
    which the adapter already made relative to the scan root, so a record
    from a moved root gives the finding the document reader gives for the
    same report. A record whose location the adapter left out because the
    binary sits outside the root carries the path's basename in its
    attributes, and the finding uses that basename, the same fallback the
    document reader applies.

    A record whose attributes carry no rule id is skipped, the same way
    the document reader skips an entry with no id, and the same rule on
    the same binary collapses onto one finding.
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
            # record's attributes; the finding falls back to it exactly
            # as the document reader falls back to the basename.
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
            coverage=Coverage(state="assessed"),
            producer=Producer(name="blint", version=record.producer.version),
            confidence=confidence if confidence in _CONFIDENCES else None,
            locations=[Location(binary=binary)] if binary else None,
            evidence=_evidence(attributes.get("evidence")),
            properties=properties or None,
        )
        if finding.id not in seen:
            seen.add(finding.id)
            findings.append(finding)
    return findings
