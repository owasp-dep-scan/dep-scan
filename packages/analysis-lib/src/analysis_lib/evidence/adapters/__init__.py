"""The contract every evidence adapter follows.

An adapter turns one producer's report into evidence records, and it is the
only code that knows that report's format. Every adapter exposes one entry
point, ``extract(report, *, source, producer_version, ...)``, and returns an
:class:`AdapterResult`. The result is either the records the report yielded
or a not-assessed result whose reason says what stood in the way: a missing
tool, an unsupported report schema version, a truncated or malformed
report. None of those ever read as zero findings. One report object that
cannot become a record is a ``record-skipped`` caveat, never a silent drop.

The helpers here are the parts every adapter shares: the schema version
gate, the witness path cap, the caveat helpers and the record builder that
computes ids. The per-producer modules own everything format-specific.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from analysis_lib.evidence import (
    CAVEAT_KINDS,
    EVIDENCE_SCHEMA_VERSION,
    Evidence,
    EvidenceCaveat,
    EvidenceLocation,
    EvidencePathNode,
    EvidenceProducer,
    EvidenceSubject,
    KINDS,
    MAX_PATH_NODES,
    POLARITIES,
    content_discriminator,
    record_id,
)

#: The two states an adapter result can end in. ``completed`` means the
#: adapter read the report and built the records it could; ``not-assessed``
#: means the adapter could not assess the report at all, with the reason.
STATUS_COMPLETED = "completed"
STATUS_NOT_ASSESSED = "not-assessed"


@dataclass
class AdapterResult:
    """What one adapter made of one report.

    ``caveats`` are the producer-level caveats: the ones that apply to the
    report as a whole rather than to a single record, such as a schema
    drift or a truncation the producer itself reported. The adapter also
    lands each of them on every record it applies to.
    """

    status: str
    reason: Optional[str] = None
    records: List[Evidence] = field(default_factory=list)
    caveats: List[EvidenceCaveat] = field(default_factory=list)


def not_assessed(reason: str) -> AdapterResult:
    """The result for a report that could not be assessed, with the reason.

    This is the only way to report nothing: an empty record list from a
    completed run means the producer genuinely found nothing, while this
    result says the analysis never got far enough to find anything.
    """
    return AdapterResult(status=STATUS_NOT_ASSESSED, reason=reason)


@dataclass
class VersionGate:
    """The outcome of the report schema version check.

    ``accepted`` is False only for a version this adapter cannot read at
    all, and ``reason`` then names the version seen. A gate that accepted a
    drifted report carries the caveat the reader should see.
    """

    accepted: bool
    reason: Optional[str] = None
    caveats: List[EvidenceCaveat] = field(default_factory=list)


def gate_report_version(
    report_version: Optional[str], supported_major: int, known_minor: int
) -> VersionGate:
    """The schema version gate every adapter applies to its report.

    A report that names no version, or one that does not parse as
    ``<major>.<minor>``, is accepted with a ``schema-unknown`` caveat, since
    the report shape itself still decides whether it can be read. A newer
    minor of the supported major is accepted with a ``schema-minor``
    caveat. A different major is refused with a reason naming the version
    seen, and the adapter returns a not-assessed result with that reason.
    """
    text = (report_version or "").strip()
    if not text:
        return VersionGate(
            True,
            caveats=[
                EvidenceCaveat(kind="schema-unknown", detail="the report names no schema version")
            ],
        )
    parts = text.split(".")
    if not parts[0].isdigit():
        return VersionGate(
            True,
            caveats=[
                EvidenceCaveat(
                    kind="schema-unknown",
                    detail=f"the report names an unparsable schema version {text!r}",
                )
            ],
        )
    major = int(parts[0])
    if major != supported_major:
        return VersionGate(
            False,
            reason=(
                f"the report schema version {text} is not supported; "
                f"this adapter reads major {supported_major} reports"
            ),
        )
    minor = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    if minor > known_minor:
        return VersionGate(
            True,
            caveats=[
                EvidenceCaveat(
                    kind="schema-minor",
                    detail=(
                        f"the report names schema version {text}; "
                        f"this adapter knows {supported_major}.{known_minor} and earlier"
                    ),
                )
            ],
        )
    return VersionGate(True)


def cap_path(
    nodes: List[EvidencePathNode],
) -> Tuple[List[EvidencePathNode], Optional[EvidenceCaveat]]:
    """The witness path a record carries, at most :data:`MAX_PATH_NODES`
    nodes.

    A longer path keeps its first nodes, in the producer's order, and the
    truncation comes back as the caveat to record alongside it. A path
    within the cap comes back unchanged with no caveat.
    """
    if len(nodes) <= MAX_PATH_NODES:
        return nodes, None
    return (
        nodes[:MAX_PATH_NODES],
        EvidenceCaveat(
            kind="path-truncated",
            detail=f"kept the first {MAX_PATH_NODES} of {len(nodes)} witness nodes",
        ),
    )


def add_caveat(record: Evidence, kind: str, detail: str) -> None:
    """Attach one caveat to a record, unless the very same caveat is
    already on it."""
    if kind not in CAVEAT_KINDS:
        raise ValueError(f"unknown caveat kind {kind!r}; known kinds: {', '.join(CAVEAT_KINDS)}")
    caveat = EvidenceCaveat(kind=kind, detail=detail)
    if caveat not in record.caveats:
        record.caveats.append(caveat)


def build_record(
    *,
    source: str,
    producer: EvidenceProducer,
    kind: str,
    discriminator: str,
    polarity: str = "positive",
    purls: Tuple[str, ...] = (),
    component_ref: Optional[str] = None,
    locations: Tuple[EvidenceLocation, ...] = (),
    path: Tuple[EvidencePathNode, ...] = (),
    confidence: Optional[str] = None,
    attributes: Optional[dict] = None,
    caveats: Tuple[EvidenceCaveat, ...] = (),
) -> Evidence:
    """One record, with the id, the path cap and the caveats applied.

    Everything the producer stated is kept as given: the confidence string,
    the attributes, the purls. The id comes from the record's identity
    parts and the discriminator, which is the producer's own object id when
    the report names one and :func:`content_discriminator` of the report
    object when it does not. A path longer than the cap is truncated and
    the truncation caveat is appended to the record's caveats.
    """
    if kind not in KINDS:
        raise ValueError(f"unknown record kind {kind!r}; known kinds: {', '.join(KINDS)}")
    if polarity not in POLARITIES:
        raise ValueError(f"unknown polarity {polarity!r}; known: {', '.join(POLARITIES)}")
    path_nodes, truncated = cap_path(list(path))
    record_caveats = list(caveats)
    if truncated is not None:
        record_caveats.append(truncated)
    location_list = list(locations)
    first = location_list[0] if location_list else None
    return Evidence(
        schema_version=EVIDENCE_SCHEMA_VERSION,
        id=record_id(producer.name, kind, purls, first, discriminator),
        producer=producer,
        kind=kind,
        polarity=polarity,
        subject=EvidenceSubject(purls=list(purls), component_ref=component_ref),
        source=source,
        locations=location_list,
        caveats=record_caveats,
        path=path_nodes or None,
        confidence=confidence,
        attributes=attributes,
    )


__all__ = [
    "AdapterResult",
    "STATUS_COMPLETED",
    "STATUS_NOT_ASSESSED",
    "VersionGate",
    "add_caveat",
    "build_record",
    "cap_path",
    "content_discriminator",
    "gate_report_version",
    "not_assessed",
]
