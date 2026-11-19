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
"""

import json
import ntpath
import os
import re
from typing import Any, Dict, List, Optional

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
