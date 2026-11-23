"""cdxgen CycloneDX BOM and introspection report -> evidence records.

This module is the only code that knows the CycloneDX evidence shapes a
cdxgen BOM carries: a component's ``evidence.occurrences`` (the places a
package's code was seen, with a location, line, symbol and offset), its
``evidence.callstack`` (the frame chain cdxgen recorded for the package),
the document-level ``annotations`` (the SaaSBOM provenance note, whose
subjects are purls, and the bom-audit findings, whose subjects are the BOM
serial number), the ``cdx:kosi:*`` properties cdxgen writes when kosi
analysed a Kotlin project, and the build-introspection report that sits
beside the BOM when cdxgen ran with ``--introspect``.

Five kinds of evidence become records:

1. One ``occurrence`` record per occurrence entry, with the component's
   purl and ``bom-ref``, the occurrence's location relativized, its line
   and symbol, and its remaining fields (``offset``, ``additionalContext``)
   in the attributes. A ``line`` or ``symbol`` no location carries (a line
   of 0, a symbol that is not a string, or any line when the record has no
   location) stays in the attributes as given. An entry that names no location, or is not a JSON object, still
   becomes a record with no location and the entry in its attributes: a
   non-empty occurrences value is usage evidence, and the presence axis
   must see it. A truthy occurrences value that is not an array becomes
   one such record.
2. One ``callstack`` record per callstack value, the frames in the
   producer's order as the witness path. The frames are also kept as
   given in the ``frames`` attribute, with ``fullFilename`` relativized
   (``null`` when no root holds it), because a witness node has no field
   for the frame's ``column``, ``parameters`` or the ``package`` a frame
   names beside its ``module``. A callstack whose ``frames`` list is empty
   still becomes a record with no path, and so does a truthy callstack
   that is not a JSON object: either is usage evidence. A falsy callstack
   (``{}``, ``[]``) proves no usage and is counted as a skip.
3. One ``annotation`` record per ``annotations[]`` entry. The subject
   purls are the ``subjects`` entries that are purls; a bom-audit
   annotation subjects the BOM serial number, which is not a purl, so its
   record keeps empty purls while the attributes keep the subjects, the
   annotator and the text as given (cdxgen renders its ``cdx:audit:*``
   facts into the text; a properties array is kept too). The annotation
   timestamp is dropped from the record.
4. One ``introspection`` record per introspection report: the
   ``overall``, ``ledger``, ``ecosystems``, ``coverageGaps``,
   ``remediation`` and ``observations`` blocks as given, gated on the
   report's own ``schemaVersion`` and versioned from its own ``cdxgen``
   block. ``coverageGaps`` names the ecosystems cdxgen found markers for
   but could not assess. The introspection report is a second input: when
   it is malformed or names an unsupported schema major, that costs one
   ``record-skipped`` caveat on the BOM result, never a not-assessed BOM.
   A ledger the producer marked truncated adds a ``budget`` caveat.
5. One ``entry-point`` record per service that carries a
   ``cdx:kosi:endpoint:*`` property: a route kosi found the application
   serving. It names no package (the purls stay empty), so it is kept as
   attack surface without counting any package as reached; the name,
   endpoints, authentication flags and properties are its attributes.

The remaining ``cdx:kosi:*`` properties travel with the records. A
component's own ``cdx:kosi:*`` properties (``reachableFromRoots``,
``dataFlowCategories``, ``pathKind``, ``crossesDependency``) are kept in
the ``kosiProperties`` attribute of that component's occurrence and
callstack records. The run-level properties cdxgen writes on the root
component (``metadata.component``, or ``metadata.properties``) become
caveats, the same way the kosi adapter reads them from kosi's own report:
``cdx:kosi:degraded`` and ``cdx:kosi:diagnosticErrors`` become
``coverage-gap`` caveats, each ``cdx:kosi:diagnostic:<code>`` count
becomes a ``timeout``, ``budget`` or ``coverage-gap`` caveat by its code,
and they land on the result and on every occurrence, callstack and
entry-point record of the BOM. The other run-level properties (the kosi
and Kotlin versions, slice counts, source coverage, the root's own
data-flow facts) are counted by name in a ``record-skipped`` caveat, and
so are services kosi found as outbound calls (``cdx:kosi:service:*``),
which name no package.

The population walk mirrors the package loader's: the root component's
nested ``metadata.component.components``, the top-level ``components``,
and one level of nesting below each of them. Component-type filtering
stays the loader's business; this adapter records the evidence the BOM
actually carries.

Two version gates apply, both on what the BOM itself states, never on the
locally installed cdxgen. The BOM's ``specVersion`` (major 1, minor 7
known) and the cdxgen version its ``metadata.tools`` names (major 13,
minor 9 known, the release line the shapes were checked against; older
releases spelled an occurrence's line inside its location). Another major
of either is refused as not-assessed naming the version; a newer minor
is accepted with a ``schema-minor`` caveat; a BOM that names no cdxgen
version, or that another tool wrote, is accepted with a
``schema-unknown`` caveat naming what it lists. The introspection report
has its own ``schemaVersion`` gate (major 1, minor 1 known). A BOM
section of the wrong type (``metadata``, ``components``, ``annotations``,
``services``) costs that section alone, counted, and the other sections
still give records.

No record carries an absolute path, a user name or the scan root. Record
paths are relative to the caller's source root with forward slashes; a
location the root cannot relativize is left out of the record with a
``location-outside-root`` caveat, and every attribute string has the
root and home directories taken out. Record ids are computed with every
path spelled by :meth:`SourcePaths.stable` (relative to the root, or
``<outside>/`` and the file name), so the same BOM produced in another
directory or by another user gives the same ids. An annotation's id
leaves out what changes when the same BOM is generated again: the
timestamp, a subject that is the BOM's own serial number, and the
creation date the SaaSBOM note writes into its text; a bom-audit
annotation is identified by its ``cdx:audit:*`` facts and subjects.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

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
    TOO_DEEP_REASON,
    as_dict,
    as_hashable_str,
    as_line,
    as_list,
    as_str,
    build_record,
    gate_cdxgen_tool_version,
    gate_report_version,
    guard_extract,
    not_assessed,
    stable_discriminator,
)

#: The BOM spec version major this adapter reads, and the newest minor it
#: knows. cdxgen 13.9 writes 1.7; a 2.0 BOM is a shape it must refuse.
SUPPORTED_MAJOR = 1
KNOWN_MINOR = 7

#: The cdxgen release line whose BOM shapes this adapter was checked
#: against, and the newest minor of it.
CDXGEN_SUPPORTED_MAJOR = 13
CDXGEN_KNOWN_MINOR = 9

#: The introspection report's own schema version gate.
INTROSPECTION_SUPPORTED_MAJOR = 1
INTROSPECTION_KNOWN_MINOR = 1

#: The introspection report blocks the record keeps, in the order the
#: report writes them. ``overall`` and ``ledger`` are objects, the rest
#: arrays.
INTROSPECTION_BLOCKS: Tuple[Tuple[str, type], ...] = (
    ("overall", dict),
    ("ledger", dict),
    ("ecosystems", list),
    ("coverageGaps", list),
    ("remediation", list),
    ("observations", list),
)

PRODUCER_NAME = "cdxgen"

#: The prefix of every property cdxgen writes from a kosi report.
KOSI_PREFIX = "cdx:kosi:"
KOSI_ENDPOINT_PREFIX = "cdx:kosi:endpoint:"
KOSI_SERVICE_PREFIX = "cdx:kosi:service:"
KOSI_DIAGNOSTIC_PREFIX = "cdx:kosi:diagnostic:"

#: The date the SaaSBOM provenance note writes into its text
#: (``created on Sunday, November 22, 2026``), and any ISO timestamp.
_DATE_RE = re.compile(
    r"\b(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), "
    r"[A-Z][a-z]+ \d{1,2}, \d{4}\b"
)
_ISO_TIMESTAMP_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?"
)

#: One ``| cdx:audit:<name> | <value> |`` row of a bom-audit annotation's
#: text table.
_AUDIT_ROW_RE = re.compile(r"^\|\s*(cdx:audit:[^|\s]+)\s*\|\s*(.*?)\s*\|\s*$", re.MULTILINE)


def _parse_report(value: Any) -> Tuple[Optional[Any], Optional[str]]:
    """The report as a parsed value, accepting JSON text as well as a
    parsed object."""
    if isinstance(value, (str, bytes)):
        try:
            return json.loads(value), None
        except RecursionError:
            return None, "the report nests its values deeper than this adapter reads"
        except ValueError as e:
            return None, f"the report is not valid JSON: {e}"
    return value, None


#: The BOM sections the adapter reads, with the JSON type each must have
#: when present. A section of another type costs that section alone.
_SECTION_TYPES = (
    ("metadata", dict),
    ("components", list),
    ("annotations", list),
    ("services", list),
)


def _count_section_problems(bom: dict, skipped: SkipTally) -> None:
    """Count every consumed section of the wrong JSON type. A ``null``
    section reads as absent; any other value of the wrong type costs that
    section's objects, and the other sections are still read."""
    for key, expected in _SECTION_TYPES:
        value = bom.get(key)
        if value is not None and not isinstance(value, expected):
            want = "an object" if expected is dict else "an array"
            skipped.add(
                f"{key} sections are a {type(value).__name__}, expected {want}, "
                "and their contents became no record"
            )


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


def _properties(obj: Any) -> List[Tuple[str, Any]]:
    """The ``(name, value)`` pairs of an object's properties array; entries
    that are not objects with a string name are passed over (the caller
    reads only the names it knows)."""
    pairs = []
    for entry in as_list(as_dict(obj).get("properties")):
        if isinstance(entry, dict):
            name = as_hashable_str(entry.get("name"))
            if name is not None:
                pairs.append((name, entry.get("value")))
    return pairs


def _grouped(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    """Properties keyed by name; a name stated more than once keeps every
    value, as a list, in the order stated."""
    out: Dict[str, Any] = {}
    for name, value in pairs:
        if name not in out:
            out[name] = value
        elif isinstance(out[name], list):
            out[name].append(value)
        else:
            out[name] = [out[name], value]
    return out


# ---------------------------------------------------------------------------
# kosi properties
# ---------------------------------------------------------------------------


def _kosi_run_caveats(bom: dict, skipped: SkipTally) -> List[EvidenceCaveat]:
    """The caveats the BOM's run-level ``cdx:kosi:*`` properties carry.

    cdxgen writes them on the root component (``metadata.component``);
    ``metadata.properties`` is read as well. ``degraded`` and
    ``diagnosticErrors`` mean parts of kosi's analysis are absent or not
    facts about the code; a diagnostic count is a timeout, a budget or a
    place kosi could not look, by its code. Every other run-level property
    is counted by name, so none disappears without a count."""
    metadata = as_dict(bom.get("metadata"))
    pairs = [
        (name, value)
        for name, value in _properties(metadata.get("component")) + _properties(metadata)
        if name.startswith(KOSI_PREFIX)
    ]
    caveats: List[EvidenceCaveat] = []
    other: List[str] = []
    for name, value in pairs:
        text = value if isinstance(value, str) else json.dumps(value)
        if name == "cdx:kosi:degraded":
            caveats.append(
                EvidenceCaveat(
                    kind="coverage-gap",
                    detail=(
                        f"kosi marked its analysis degraded ({text}), so its counts are not "
                        "facts about the code"
                    ),
                )
            )
        elif name == "cdx:kosi:diagnosticErrors":
            caveats.append(
                EvidenceCaveat(
                    kind="coverage-gap",
                    detail=(
                        f"kosi reported error diagnostics ({text}): those parts of its "
                        "analysis are absent from the BOM"
                    ),
                )
            )
        elif name.startswith(KOSI_DIAGNOSTIC_PREFIX):
            code = name[len(KOSI_DIAGNOSTIC_PREFIX) :]
            detail = f"kosi diagnostic {code} reported {text} time(s)"
            words = code.lower().split("-")
            if "timeout" in words:
                caveats.append(EvidenceCaveat(kind="timeout", detail=detail))
            elif any(
                word.startswith("truncat") or word in ("budget", "cap", "caps") for word in words
            ):
                caveats.append(EvidenceCaveat(kind="budget", detail=detail))
            else:
                caveats.append(EvidenceCaveat(kind="coverage-gap", detail=detail))
        else:
            other.append(name)
    if other:
        skipped.add(
            "root cdx:kosi: properties that describe the kosi run or the application "
            f"rather than a dependency became no record ({', '.join(sorted(set(other)))})",
            len(other),
        )
    return _dedupe(caveats)


def _kosi_entry_point(
    service: dict,
    producer: EvidenceProducer,
    source: str,
    paths: SourcePaths,
    caveats: List[EvidenceCaveat],
):
    """The entry-point record of a route kosi found the application
    serving, or ``None`` for a service that carries no
    ``cdx:kosi:endpoint:*`` property."""
    pairs = _properties(service)
    if not any(name.startswith(KOSI_ENDPOINT_PREFIX) for name, _ in pairs):
        return None
    attributes: Dict[str, Any] = {}
    for field in ("name", "endpoints", "authenticated", "x-trust-boundary"):
        if service.get(field) is not None:
            attributes[field] = paths.redact(service[field])
    attributes["properties"] = paths.redact(_grouped(pairs))
    return build_record(
        source=source,
        producer=producer,
        kind="entry-point",
        discriminator=stable_discriminator(
            {key: value for key, value in service.items() if key != "bom-ref"}, paths
        ),
        attributes=attributes,
        caveats=tuple(caveats),
    )


# ---------------------------------------------------------------------------
# Introspection
# ---------------------------------------------------------------------------


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
    attributes: Dict[str, Any] = {}
    for block, expected in INTROSPECTION_BLOCKS:
        value = parsed.get(block)
        if value is None:
            continue
        if not isinstance(value, expected):
            want = "object" if expected is dict else "array"
            caveats.append(
                EvidenceCaveat(
                    kind="record-skipped",
                    detail=(
                        f"the introspection report's {block} block is a "
                        f"{type(value).__name__}, not the {want} expected; "
                        "it became no attribute"
                    ),
                )
            )
            continue
        if value:
            attributes[block] = paths.redact(value)
    if as_dict(parsed.get("ledger")).get("truncated"):
        caveats.append(
            EvidenceCaveat(
                kind="budget",
                detail="the introspection ledger is marked truncated, so its counts may be incomplete",
            )
        )
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
    # The id covers the verdict blocks only, so a re-run of the same build
    # (a new runId and timestamp, the same verdict) keeps it.
    verdict = {key: attributes[key] for key in ("overall", "ledger") if key in attributes}
    record = build_record(
        source=source,
        producer=producer,
        kind="introspection",
        discriminator=stable_discriminator(verdict, paths),
        attributes=attributes or None,
        caveats=tuple(caveats),
    )
    return record, []


# ---------------------------------------------------------------------------
# Annotations
# ---------------------------------------------------------------------------


def _annotation_identity(annotation: dict, serial: Optional[str]) -> Any:
    """What an annotation's id hashes: its content without the parts that
    change when the same BOM is generated again.

    The timestamp is left out, and a subject that is the BOM's own serial
    number (a fresh ``urn:uuid`` every run) reads ``<bom>``. A bom-audit
    annotation is its ``cdx:audit:*`` facts (from the text table and any
    properties array), its subjects and its annotator; any other
    annotation is its content with the creation date and timestamps in its
    text spelled ``<date>``."""
    subjects = [
        "<bom>" if serial and subject == serial else subject
        for subject in as_list(annotation.get("subjects"))
    ]
    text = annotation.get("text")
    audit: Dict[str, Any] = {}
    if isinstance(text, str):
        for name, value in _AUDIT_ROW_RE.findall(text):
            audit.setdefault(name, value)
    for name, value in _properties(annotation):
        if name.startswith("cdx:audit:"):
            audit.setdefault(name, value)
    if "cdx:audit:ruleId" in audit or "cdx:audit:target:purl" in audit:
        return {"audit": audit, "subjects": subjects, "annotator": annotation.get("annotator")}
    identity = {
        key: value for key, value in annotation.items() if key not in ("timestamp", "subjects")
    }
    identity["subjects"] = subjects
    if isinstance(text, str):
        identity["text"] = _ISO_TIMESTAMP_RE.sub("<date>", _DATE_RE.sub("<date>", text))
    return identity


# ---------------------------------------------------------------------------
# The adapter
# ---------------------------------------------------------------------------


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
    not-assessed with the reason: a document that is not a BOM object, or
    names a BOM ``specVersion`` or cdxgen major this adapter does not read,
    is never read as a smaller report. A section of the wrong type is a
    counted skip.
    """
    bom, parse_error = _parse_report(bom)
    if parse_error or not isinstance(bom, dict):
        reason = parse_error or (
            f"the report is a {type(bom).__name__}, not the CycloneDX BOM object"
        )
        return not_assessed(reason)
    gate = gate_report_version(bom.get("specVersion"), SUPPORTED_MAJOR, KNOWN_MINOR)
    if not gate.accepted:
        return not_assessed(
            gate.reason or "the BOM names a schema version this adapter cannot read"
        )
    tool_gate, tool_version = gate_cdxgen_tool_version(
        bom, CDXGEN_SUPPORTED_MAJOR, CDXGEN_KNOWN_MINOR, "BOM"
    )
    if not tool_gate.accepted:
        return not_assessed(tool_gate.reason or "")
    base_caveats = list(gate.caveats) + list(tool_gate.caveats)

    raw_spec = bom.get("specVersion")
    seen_version = (
        str(raw_spec).strip()
        if isinstance(raw_spec, (str, int, float)) and not isinstance(raw_spec, bool)
        else ""
    )
    producer = EvidenceProducer(
        name=PRODUCER_NAME,
        version=tool_version,
        report_schema_version=seen_version or "unknown",
    )

    paths = SourcePaths(roots=[source_root])
    skipped = SkipTally()
    records: List = []
    _count_section_problems(bom, skipped)
    kosi_caveats = _kosi_run_caveats(bom, skipped)
    evidence_caveats = base_caveats + kosi_caveats

    for component in _population(bom, skipped):
        if not isinstance(component, dict):
            skipped.add("components entries are not JSON objects and became no record")
            continue
        try:
            records.extend(
                _component_records(component, producer, source, paths, evidence_caveats, skipped)
            )
        except RecursionError:
            skipped.add(TOO_DEEP_REASON)

    serial = as_hashable_str(bom.get("serialNumber"))
    annotations = bom.get("annotations")
    for annotation in annotations if isinstance(annotations, list) else []:
        try:
            record = _annotation_record(
                annotation, serial, producer, source, paths, base_caveats, skipped
            )
        except RecursionError:
            skipped.add(TOO_DEEP_REASON)
            continue
        if record is not None:
            records.append(record)

    services = bom.get("services")
    outbound = 0
    for service in services if isinstance(services, list) else []:
        if not isinstance(service, dict):
            continue
        try:
            record = _kosi_entry_point(service, producer, source, paths, evidence_caveats)
        except RecursionError:
            skipped.add(TOO_DEEP_REASON)
            continue
        if record is not None:
            records.append(record)
        elif any(name.startswith(KOSI_SERVICE_PREFIX) for name, _ in _properties(service)):
            outbound += 1
    skipped.add(
        "services kosi found as outbound calls name no package and became no record", outbound
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
    caveats = evidence_caveats + introspection_caveats + skipped.caveats()
    if outside:
        caveats.append(outside)
    return AdapterResult(
        status=STATUS_COMPLETED, records=records + introspection_records, caveats=caveats
    )


def _component_records(
    component: dict,
    producer: EvidenceProducer,
    source: str,
    paths: SourcePaths,
    base_caveats: List[EvidenceCaveat],
    skipped: SkipTally,
) -> List:
    """The occurrence and callstack records of one component."""
    records: List = []
    evidence = as_dict(component.get("evidence"))
    purls = _purls(component)
    component_ref = as_hashable_str(component.get("bom-ref"))
    kosi = _grouped([pair for pair in _properties(component) if pair[0].startswith(KOSI_PREFIX)])

    def record(kind: str, obj: Any, **fields: Any):
        attributes = dict(fields.pop("attributes", None) or {})
        if kosi:
            attributes["kosiProperties"] = paths.redact(kosi)
        return build_record(
            source=source,
            producer=producer,
            kind=kind,
            discriminator=stable_discriminator(obj, paths),
            purls=purls,
            component_ref=component_ref,
            attributes=attributes or None,
            **fields,
        )

    raw_occurrences = evidence.get("occurrences")
    if isinstance(raw_occurrences, list):
        occurrences = raw_occurrences
    elif raw_occurrences:
        # A truthy value of the wrong type is still usage evidence on the
        # component reading, so it stands as one record with no location.
        occurrences = [raw_occurrences]
    else:
        if raw_occurrences is not None and raw_occurrences != []:
            skipped.add("evidence.occurrences values are empty and became no record")
        occurrences = []

    for occurrence in occurrences:
        if not isinstance(occurrence, dict):
            records.append(
                record(
                    "occurrence",
                    occurrence,
                    attributes={"occurrence": paths.redact(occurrence)},
                    caveats=tuple(base_caveats),
                )
            )
            continue
        location = as_str(occurrence.get("location")).strip()
        file = paths.relative(location) if location else None
        raw_line = occurrence.get("line")
        line = as_line(raw_line)
        raw_symbol = occurrence.get("symbol")
        symbol = as_str(raw_symbol) or None
        attributes = {
            key: paths.redact(value)
            for key, value in occurrence.items()
            if key not in ("location", "line", "symbol")
        }
        # A line or symbol that no location carries (there is no location,
        # or the location cannot hold the value) stays in the attributes.
        if raw_line is not None and (file is None or line is None):
            attributes["line"] = raw_line
        if raw_symbol is not None and raw_symbol != "" and (file is None or symbol is None):
            attributes["symbol"] = paths.redact(raw_symbol)
        caveats = list(base_caveats)
        if location and file is None:
            caveats.append(paths.outside_root_caveat(1))
        records.append(
            record(
                "occurrence",
                occurrence,
                locations=(EvidenceLocation(file=file, line=line, method=symbol),)
                if file is not None
                else (),
                attributes=attributes,
                caveats=tuple(caveats),
            )
        )

    raw_callstack = evidence.get("callstack")
    if raw_callstack is None:
        return records
    if not raw_callstack:
        # A falsy callstack ({} or []) proves no usage on the component
        # reading either; it is counted, not dropped.
        skipped.add("evidence.callstack values are empty and became no record")
        return records
    if not isinstance(raw_callstack, dict):
        records.append(
            record(
                "callstack",
                raw_callstack,
                attributes={"callstack": paths.redact(raw_callstack)},
                caveats=tuple(base_caveats),
            )
        )
        return records
    raw_frames = raw_callstack.get("frames")
    if raw_frames is not None and not isinstance(raw_frames, list):
        # The callstack object itself is still truthy usage evidence, so
        # its record stands with no witness path and the loss counted.
        skipped.add("evidence.callstack frames values are not arrays and name no witness node")
        raw_frames = None
    nodes: List[EvidencePathNode] = []
    kept_frames: List[Any] = []
    left_out = 0
    for frame in as_list(raw_frames):
        if not isinstance(frame, dict):
            skipped.add("evidence.callstack frames are not JSON objects and name no witness node")
            kept_frames.append(paths.redact(frame))
            continue
        raw_file = frame.get("fullFilename")
        file = paths.relative(raw_file)
        if isinstance(raw_file, str) and raw_file.strip() and file is None:
            left_out += 1
        kept = {key: paths.redact(value) for key, value in frame.items()}
        if "fullFilename" in frame:
            kept["fullFilename"] = file
        kept_frames.append(kept)
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
    other = {key: paths.redact(value) for key, value in raw_callstack.items() if key != "frames"}
    attributes = dict(other)
    if kept_frames:
        attributes["frames"] = kept_frames
    records.append(
        record(
            "callstack",
            raw_callstack,
            path=tuple(nodes),
            attributes=attributes,
            caveats=tuple(caveats),
        )
    )
    return records


def _annotation_record(
    annotation: Any,
    serial: Optional[str],
    producer: EvidenceProducer,
    source: str,
    paths: SourcePaths,
    base_caveats: List[EvidenceCaveat],
    skipped: SkipTally,
):
    """The record of one annotation, or ``None`` with the reason counted."""
    if not isinstance(annotation, dict):
        skipped.add("annotations entries are not JSON objects and became no record")
        return None
    raw_subjects = annotation.get("subjects")
    if raw_subjects is not None and not isinstance(raw_subjects, list):
        skipped.add("annotation subjects values are not arrays and name no subject")
    subjects = [s for s in as_list(raw_subjects) if isinstance(s, str)]
    attributes = {}
    annotator = annotation.get("annotator")
    if annotator is not None:
        attributes["annotator"] = paths.redact(annotator)
    if "subjects" in annotation:
        attributes["subjects"] = paths.redact(raw_subjects)
    properties = annotation.get("properties")
    if properties is not None and not isinstance(properties, list):
        skipped.add("annotation properties values are not arrays and name no property")
    elif isinstance(properties, list):
        attributes["properties"] = paths.redact(properties)
    text = annotation.get("text")
    if isinstance(text, str) and text:
        attributes["text"] = paths.redact(text)
    return build_record(
        source=source,
        producer=producer,
        kind="annotation",
        discriminator=stable_discriminator(_annotation_identity(annotation, serial), paths),
        purls=tuple(s for s in subjects if s.startswith("pkg:")),
        attributes=attributes or None,
        caveats=tuple(base_caveats),
    )


def _dedupe(caveats: List[EvidenceCaveat]) -> List[EvidenceCaveat]:
    out: List[EvidenceCaveat] = []
    for caveat in caveats:
        if caveat not in out:
            out.append(caveat)
    return out


__all__ = [
    "CDXGEN_KNOWN_MINOR",
    "CDXGEN_SUPPORTED_MAJOR",
    "INTROSPECTION_BLOCKS",
    "INTROSPECTION_KNOWN_MINOR",
    "INTROSPECTION_SUPPORTED_MAJOR",
    "KNOWN_MINOR",
    "PRODUCER_NAME",
    "SUPPORTED_MAJOR",
    "extract",
]
