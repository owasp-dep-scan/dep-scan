"""cdxgen CycloneDX BOM and introspection report -> evidence records.

This module is the only code that knows the CycloneDX evidence shapes a
cdxgen BOM carries: a component's ``evidence.occurrences`` (the places a
package's code was seen, with a location, line, symbol and offset), its
``evidence.callstack`` (the frame chain cdxgen recorded for the package),
the document-level ``annotations`` (the SaaSBOM provenance note, whose
subjects are purls, and the bom-audit findings, whose subjects are the BOM
serial number), and the build-introspection report that sits beside the
BOM when cdxgen ran with ``--introspect``.

Four kinds of evidence become records:

1. One ``occurrence`` record per occurrence entry, with the component's
   purl and ``bom-ref``, the occurrence's location relativized, its line
   and symbol, and its remaining fields (``offset``) in the attributes.
2. One ``callstack`` record per callstack object, the frames in the
   producer's order as the witness path. A callstack whose ``frames``
   list is empty still becomes a record with no path: the object is
   truthy evidence of usage, and the presence axis must see it. The
   frame ``column`` has no field on a witness node and is not carried
   anywhere. A callstack object with no keys at all is falsy, proves no
   usage and is counted as a skip, never dropped silently.
3. One ``annotation`` record per ``annotations[]`` entry. The subject
   purls are the ``subjects`` entries that are purls; a bom-audit
   annotation subjects the BOM serial number, which is not a purl, so
   its record keeps empty purls while the attributes keep the subjects,
   the annotator and the text exactly as given (cdxgen renders its
   ``cdx:audit:*`` facts into the text; a BOM that carries a properties
   array has it kept as name/value pairs too). The annotation timestamp
   is dropped from the record and left out of the id, so a regenerated
   BOM that rewrites only the timestamp keeps the same record id.
4. One ``introspection`` record per introspection report: the ``overall``
   block and the ``ledger`` block as given, gated on the report's own
   ``schemaVersion`` and versioned from its own ``cdxgen`` block. The
   introspection report is a second input: when it is malformed or names
   an unsupported schema major, that costs one ``record-skipped`` caveat
   on the BOM result, never a not-assessed BOM. A ledger the producer
   marked truncated adds a ``budget`` caveat.

The population walk mirrors the package loader's: the root component's
nested ``metadata.component.components``, the top-level ``components``,
and one level of nesting below each of them. Component-type filtering
stays the loader's business; this adapter records the evidence the BOM
actually carries.

The version gates read the documents' own versions: the BOM's
``specVersion`` (major 1, minor 7 known; a 2.0 BOM is refused as
not-assessed naming the version) and the introspection report's
``schemaVersion`` (major 1, minor 1 known). The producer version is the
cdxgen version the BOM's own ``metadata.tools`` names, in either the
1.5 list form or the 1.6 ``components`` form, never the locally
installed cdxgen; ``unknown`` when the BOM names none, and for the
introspection record the version the report's ``cdxgen`` block names.

Record paths are relative to the caller's source root with forward
slashes; the BOM does not name its source directory. A location the root
cannot relativize is left out of the record with a
``location-outside-root`` caveat rather than stored absolute, and ids
are computed from root-neutral content, so the same BOM produced in
another directory gives the same ids.
"""

from __future__ import annotations

import json
from typing import Any, List, Optional, Tuple

from analysis_lib.evidence import (
    EvidenceCaveat,
    EvidenceLocation,
    EvidencePathNode,
    EvidenceProducer,
)
from analysis_lib.evidence.adapters import (
    AdapterResult,
    STATUS_COMPLETED,
    SkipTally,
    SourcePaths,
    as_dict,
    as_hashable_str,
    as_line,
    as_list,
    as_str,
    build_record,
    gate_report_version,
    guard_extract,
    neutral_discriminator,
    not_assessed,
)

#: The BOM spec version major this adapter reads, and the newest minor it
#: knows. cdxgen 13.9 writes 1.7; a 2.0 BOM is a shape it must refuse.
SUPPORTED_MAJOR = 1
KNOWN_MINOR = 7

#: The introspection report's own schema version gate.
INTROSPECTION_SUPPORTED_MAJOR = 1
INTROSPECTION_KNOWN_MINOR = 1

PRODUCER_NAME = "cdxgen"


def _parse_report(value: Any) -> Tuple[Optional[Any], Optional[str]]:
    """The report as a parsed value, accepting JSON text as well as a
    parsed object."""
    if isinstance(value, (str, bytes)):
        try:
            return json.loads(value), None
        except ValueError as e:
            return None, f"the report is not valid JSON: {e}"
    return value, None


def _bom_tool_version(bom: dict) -> str:
    """The cdxgen version the BOM's own ``metadata.tools`` names.

    CycloneDX 1.5 spells the section as a list of tool objects and 1.6 as
    an object with ``components``; both are read. The locally installed
    cdxgen is never asked: the BOM's own statement is the evidence.
    """
    tools = as_dict(bom.get("metadata")).get("tools")
    entries = (
        as_list(tools) if isinstance(tools, list) else as_list(as_dict(tools).get("components"))
    )
    for entry in entries:
        if isinstance(entry, dict) and as_str(entry.get("name")) == "cdxgen":
            version = as_str(entry.get("version"))
            if version:
                return version
    return ""


#: The BOM sections the adapter reads, with the JSON type each must have
#: when present. A section of another type means the document is not the
#: shape cdxgen writes and is not assessed at all.
_SECTION_TYPES = (
    (("metadata",), dict),
    (("components",), list),
    (("annotations",), list),
)


def _section_problem(bom: dict) -> Optional[str]:
    """The first consumed section of the wrong JSON type, named, or ``None``.

    A ``null`` section reads as absent. Any other value of the wrong type
    means the document is not a BOM this adapter can read.
    """
    for keys, expected in _SECTION_TYPES:
        value = bom.get(keys[0])
        if value is not None and not isinstance(value, expected):
            want = "an object" if expected is dict else "an array"
            return f"{keys[0]} is a {type(value).__name__}, expected {want}"
    return None


def _population(bom: dict, skipped: SkipTally) -> List[Any]:
    """The components the package loader walks: the root component's
    nested components, the top-level components, and one level of nesting
    below each of them.

    A component or components section of the wrong JSON type hides what it
    would have carried; each such section is counted in ``skipped`` so the
    loss is never silent.
    """
    population: List[Any] = []
    metadata = bom.get("metadata")
    root_component = metadata.get("component") if isinstance(metadata, dict) else None
    if root_component is not None and not isinstance(root_component, dict):
        skipped.add(
            "metadata.component values are not JSON objects, "
            "so their nested components became no record"
        )
    else:
        population.extend(as_list(as_dict(root_component).get("components")))
    components = as_list(bom.get("components"))
    population.extend(components)
    for comp in components:
        if not isinstance(comp, dict):
            continue
        nested = comp.get("components")
        if nested is None:
            continue
        if isinstance(nested, list):
            population.extend(nested)
        else:
            skipped.add("nested components values are not arrays and became no record")
    return population


def _purls(component: dict) -> Tuple[str, ...]:
    purl = as_str(component.get("purl"))
    return (purl,) if purl else ()


def _introspection_record(
    introspection: Any,
    source: str,
    paths: SourcePaths,
) -> Tuple[Optional[Any], List[EvidenceCaveat]]:
    """The introspection report as its record, plus the caveats it owes.

    The report is a second input with its own gate: a malformed report or
    one that names an unsupported schema major costs one ``record-skipped``
    caveat here, and never a not-assessed BOM. Its record carries only its
    own gate's caveats, not the BOM's.
    """
    parsed, parse_error = _parse_report(introspection)
    if parse_error or not isinstance(parsed, dict):
        reason = parse_error or (
            f"the introspection report is a {type(parsed).__name__}, not the report object"
        )
        return None, [
            EvidenceCaveat(
                kind="record-skipped",
                detail=f"the introspection report became no record: {reason}",
            )
        ]
    gate = gate_report_version(
        parsed.get("schemaVersion"), INTROSPECTION_SUPPORTED_MAJOR, INTROSPECTION_KNOWN_MINOR
    )
    if not gate.accepted:
        return None, [
            EvidenceCaveat(
                kind="record-skipped",
                detail=f"the introspection report became no record: {gate.reason}",
            )
        ]
    caveats = list(gate.caveats)
    ledger = as_dict(parsed.get("ledger"))
    if ledger.get("truncated"):
        caveats.append(
            EvidenceCaveat(
                kind="budget",
                detail="the introspection ledger is marked truncated, so its counts may be incomplete",
            )
        )
    overall = as_dict(parsed.get("overall"))
    attributes = {}
    if overall:
        attributes["overall"] = overall
    if ledger:
        attributes["ledger"] = ledger
    raw_version = parsed.get("schemaVersion")
    seen_version = (
        str(raw_version).strip()
        if isinstance(raw_version, (str, int, float)) and not isinstance(raw_version, bool)
        else ""
    )
    producer = EvidenceProducer(
        name=PRODUCER_NAME,
        version=as_str(as_dict(parsed.get("cdxgen")).get("version")) or "unknown",
        report_schema_version=seen_version or "unknown",
    )
    # The id covers only the blocks the record carries, so a re-run of the
    # same build (a new runId and timestamp, the same verdict) keeps it.
    record = build_record(
        source=source,
        producer=producer,
        kind="introspection",
        discriminator=neutral_discriminator(attributes, paths),
        attributes=attributes or None,
        caveats=tuple(caveats),
    )
    return record, []


@guard_extract(PRODUCER_NAME)
def extract(
    bom,
    *,
    source: str,
    introspection=None,
    introspection_source: str = "",
    source_root: Optional[str] = None,
) -> AdapterResult:
    """One cdxgen BOM, with its optional introspection report, as evidence
    records.

    ``bom`` is the parsed CycloneDX BOM or its JSON text. ``source`` is the
    scan-directory-relative file the BOM was read from. ``introspection``
    is the parsed build-introspection report that sits beside the BOM (or
    its JSON text, or ``None`` when there is none), and
    ``introspection_source`` its scan-directory-relative file. ``source_root``
    is the scanned source directory as the caller knows it; record paths are
    relative to it with forward slashes. The result is the records, or
    not-assessed with the reason: a document that is not a BOM object, has
    a consumed section of an unexpected type, or names a BOM ``specVersion``
    this adapter does not read is never read as a smaller report.
    """
    bom, parse_error = _parse_report(bom)
    if parse_error or not isinstance(bom, dict):
        reason = parse_error or (
            f"the report is a {type(bom).__name__}, not the CycloneDX BOM object"
        )
        return not_assessed(reason)
    problem = _section_problem(bom)
    if problem:
        return not_assessed(f"the cdxgen BOM is malformed and was not assessed: {problem}")
    gate = gate_report_version(bom.get("specVersion"), SUPPORTED_MAJOR, KNOWN_MINOR)
    if not gate.accepted:
        return not_assessed(
            gate.reason or "the BOM names a schema version this adapter cannot read"
        )
    base_caveats = list(gate.caveats)

    raw_spec = bom.get("specVersion")
    seen_version = (
        str(raw_spec).strip()
        if isinstance(raw_spec, (str, int, float)) and not isinstance(raw_spec, bool)
        else ""
    )
    producer = EvidenceProducer(
        name=PRODUCER_NAME,
        version=_bom_tool_version(bom) or "unknown",
        report_schema_version=seen_version or "unknown",
    )

    paths = SourcePaths(roots=[source_root])
    skipped = SkipTally()
    records: List = []

    for component in _population(bom, skipped):
        if not isinstance(component, dict):
            skipped.add("components entries are not JSON objects and became no record")
            continue
        evidence = as_dict(component.get("evidence"))
        purls = _purls(component)
        component_ref = as_hashable_str(component.get("bom-ref"))

        raw_occurrences = evidence.get("occurrences")
        if raw_occurrences is None:
            occurrences: List = []
        elif isinstance(raw_occurrences, list):
            occurrences = raw_occurrences
        else:
            skipped.add(
                "evidence.occurrences values are not arrays and became no occurrence record"
            )
            occurrences = []

        for occurrence in occurrences:
            if not isinstance(occurrence, dict):
                skipped.add(
                    "evidence.occurrences entries are not JSON objects and became no record"
                )
                continue
            location = as_str(occurrence.get("location")).strip()
            if not location:
                skipped.add("evidence.occurrences entries name no location and became no record")
                continue
            file = paths.relative(location)
            line = as_line(occurrence.get("line"))
            symbol = as_str(occurrence.get("symbol")) or None
            attributes = {
                key: value
                for key, value in occurrence.items()
                if key not in ("location", "line", "symbol")
            }
            caveats = list(base_caveats)
            if file is None:
                caveats.append(paths.outside_root_caveat(1))
            records.append(
                build_record(
                    source=source,
                    producer=producer,
                    kind="occurrence",
                    discriminator=neutral_discriminator(occurrence, paths),
                    purls=purls,
                    component_ref=component_ref,
                    locations=(EvidenceLocation(file=file, line=line, method=symbol),)
                    if file is not None
                    else (),
                    attributes=attributes or None,
                    caveats=tuple(caveats),
                )
            )

        raw_callstack = evidence.get("callstack")
        if raw_callstack is None:
            continue
        if not isinstance(raw_callstack, dict):
            skipped.add("evidence.callstack values are not JSON objects and became no record")
            continue
        if not raw_callstack:
            # A keyless callstack object is falsy in Python, so it proves
            # no usage on the BOM reader either; it is counted, not dropped.
            skipped.add("evidence.callstack objects are empty and became no record")
            continue
        raw_frames = raw_callstack.get("frames")
        if raw_frames is not None and not isinstance(raw_frames, list):
            # The callstack object itself is still truthy usage evidence, so
            # its record stands with no witness path and the loss counted.
            skipped.add("evidence.callstack frames values are not arrays and name no witness node")
            raw_frames = None
        frames = as_list(raw_frames)
        nodes: List[EvidencePathNode] = []
        left_out = 0
        for frame in frames:
            if not isinstance(frame, dict):
                skipped.add(
                    "evidence.callstack frames are not JSON objects and name no witness node"
                )
                continue
            raw_file = frame.get("fullFilename")
            file = paths.relative(raw_file)
            if isinstance(raw_file, str) and raw_file.strip() and file is None:
                left_out += 1
            nodes.append(
                EvidencePathNode(
                    file=file,
                    line=as_line(frame.get("line")),
                    method=as_str(frame.get("function")) or None,
                    symbol=as_str(frame.get("module")) or as_str(frame.get("package")) or None,
                )
            )
        caveats = list(base_caveats)
        if left_out:
            caveats.append(paths.outside_root_caveat(left_out))
        records.append(
            build_record(
                source=source,
                producer=producer,
                kind="callstack",
                discriminator=neutral_discriminator(raw_callstack, paths),
                purls=purls,
                component_ref=component_ref,
                path=tuple(nodes),
                caveats=tuple(caveats),
            )
        )

    for annotation in as_list(bom.get("annotations")):
        if not isinstance(annotation, dict):
            skipped.add("annotations entries are not JSON objects and became no record")
            continue
        raw_subjects = annotation.get("subjects")
        if raw_subjects is not None and not isinstance(raw_subjects, list):
            skipped.add("annotation subjects values are not arrays and name no subject")
        subjects = [s for s in as_list(raw_subjects) if isinstance(s, str)]
        attributes = {}
        annotator = annotation.get("annotator")
        if annotator is not None:
            attributes["annotator"] = annotator
        if "subjects" in annotation:
            attributes["subjects"] = raw_subjects
        properties = annotation.get("properties")
        if properties is not None and not isinstance(properties, list):
            skipped.add("annotation properties values are not arrays and name no property")
        elif isinstance(properties, list):
            attributes["properties"] = properties
        text = annotation.get("text")
        if isinstance(text, str) and text:
            attributes["text"] = text
        # The timestamp changes on every regenerated BOM while the annotation
        # stays the same, so the id hashes the object without it, the way the
        # introspection id leaves the report's run ids out.
        annotation_for_id = {k: v for k, v in annotation.items() if k != "timestamp"}
        records.append(
            build_record(
                source=source,
                producer=producer,
                kind="annotation",
                discriminator=neutral_discriminator(annotation_for_id, paths),
                purls=tuple(s for s in subjects if s.startswith("pkg:")),
                attributes=attributes or None,
                caveats=tuple(base_caveats),
            )
        )

    introspection_records: List = []
    introspection_caveats: List[EvidenceCaveat] = []
    if introspection is not None:
        introspection_evidence, introspection_caveats = _introspection_record(
            introspection, introspection_source or source, paths
        )
        if introspection_evidence is not None:
            introspection_records.append(introspection_evidence)
            # The introspection report's own caveats travel with the result
            # as well, so a reader sees its drift without opening its record.
            introspection_caveats.extend(introspection_evidence.caveats)

    outside = paths.producer_caveat()
    caveats = base_caveats + introspection_caveats + skipped.caveats()
    if outside:
        caveats.append(outside)
    return AdapterResult(
        status=STATUS_COMPLETED, records=records + introspection_records, caveats=caveats
    )


__all__ = [
    "INTROSPECTION_KNOWN_MINOR",
    "INTROSPECTION_SUPPORTED_MAJOR",
    "KNOWN_MINOR",
    "PRODUCER_NAME",
    "SUPPORTED_MAJOR",
    "extract",
]
