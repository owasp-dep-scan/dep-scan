"""tracebom trace BOM -> evidence records.

tracebom is the dynamic-trace mode of the cdxgen package: it runs one
command inside a sandbox, watches the shared libraries the command loads,
the endpoints it opens and the cryptography it negotiates, and writes a
CycloneDX BOM about what it saw. This module is the only code that knows
that report format.

A trace BOM is recognised by shape, not by a format marker: a CycloneDX
BOM any of whose components (nested ones included), services or metadata
properties carry a ``cdx:dynamic:`` property. An ordinary source BOM never
does and is refused. The version gate reads the BOM's own ``specVersion``
(major 1, minor 7 known); the producer is named ``tracebom`` at the cdxgen
version the BOM's ``metadata.tools`` states, because tracebom ships inside
the cdxgen package and has no version of its own.

Three kinds of object become ``runtime-trace`` records, all with positive
polarity:

1. A component carrying a ``cdx:dynamic:`` property (a traced library, or
   an executed process on producers that record one). Its purl and
   ``bom-ref`` are the subject, the ``cdx:dynamic:filePath`` property
   becomes the location relative to the source root, and every remaining
   property is kept as an attribute exactly as stated.
2. A service, an endpoint observation: empty purls, the name, endpoints
   and egress decision kept as given.
3. A ``cryptographic-asset`` component, with its ``cryptoProperties``
   kept as given.

A runtime observation is not reachability evidence. The trace's subjects
are the traced command's environment, library files, endpoints and
algorithms, whose purls do not in general reconcile to the scanned BOM's
components, and one traced run must not mark application dependencies
reached with no code path between them. ``runtime-trace`` therefore stays
out of :data:`analysis_lib.reachability.REACHED_COUNTED_KINDS` and grades
nothing; the records are the evidence a later reconciliation contract can
count.

An object that cannot become a record (a component or service whose
``properties`` or ``endpoints`` are of the wrong JSON type, a property
entry that is not an object with a name) is counted in one
``record-skipped`` caveat per reason, never dropped silently. A file path
no root holds never enters a record as an absolute path: the record says
which files it left out through a ``location-outside-root`` caveat.

Record ids do not follow the directory the trace ran in. The purl,
``bom-ref`` and ``evidence`` identity of a traced object restate the file
path or the name the object already carries (the producer derives the
generic purl's subpath from the loaded file's path), so the discriminator
leaves exactly those three fields out and hashes the rest with the roots
rewritten; the same trace produced in another directory then gives the
same ids.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Iterator, List, Optional, Tuple

from analysis_lib.evidence import (
    EvidenceCaveat,
    EvidenceLocation,
    EvidenceProducer,
)
from analysis_lib.evidence.adapters import (
    AdapterResult,
    STATUS_COMPLETED,
    SkipTally,
    SourcePaths,
    as_dict,
    as_hashable_str,
    as_list,
    as_str,
    build_record,
    gate_report_version,
    guard_extract,
    is_absolute_path,
    neutral_discriminator,
    not_assessed,
)

#: The trace BOM schema major this adapter reads, and the newest minor it
#: knows. tracebom writes the CycloneDX spec version it was told to
#: (``--spec-version``, 1.7 by default).
SUPPORTED_MAJOR = 1
KNOWN_MINOR = 7

PRODUCER_NAME = "tracebom"

#: Every property tracebom states about the traced run lives under this
#: prefix; the presence of one such property is what makes a BOM a trace
#: BOM.
DYNAMIC_PROPERTY_PREFIX = "cdx:dynamic:"

#: The property that names the file a traced component was loaded from.
FILE_PATH_PROPERTY = "cdx:dynamic:filePath"

#: The component type of a cryptographic asset the trace observed.
CRYPTO_ASSET_TYPE = "cryptographic-asset"

#: Component and service fields the discriminator leaves out because the
#: producer derives them from the object's own file path or name, which
#: the hashed fields already carry.
_DISCRIMINATOR_EXCLUDED_FIELDS = ("purl", "bom-ref", "evidence")


def is_tracebom_report(report) -> bool:
    """True when ``report`` has the shape of a trace BOM: a JSON object
    with a ``cdx:dynamic:`` property on a component (nested components
    included), a service or the metadata."""
    if not isinstance(report, dict):
        return False
    for component in _walk_components(report.get("components")):
        if _has_dynamic_property(component):
            return True
    for service in as_list(report.get("services")):
        if isinstance(service, dict) and _has_dynamic_property(service):
            return True
    return _has_dynamic_property(as_dict(report.get("metadata")))


def _has_dynamic_property(obj: dict) -> bool:
    properties = obj.get("properties")
    return isinstance(properties, list) and any(
        isinstance(entry, dict) and as_str(entry.get("name")).startswith(DYNAMIC_PROPERTY_PREFIX)
        for entry in properties
    )


def _walk_components(value: Any, skipped: Optional[SkipTally] = None) -> Iterator[dict]:
    """Every component of a components array, the nested ones included.

    An entry that is not a JSON object, and a ``components`` array of the
    wrong type one level down, are counted as skips when a tally is given,
    so neither disappears without a count."""
    for entry in as_list(value):
        if not isinstance(entry, dict):
            if skipped is not None:
                skipped.add("components entries are not JSON objects and became no record")
            continue
        nested = entry.get("components")
        if nested is not None and not isinstance(nested, list):
            if skipped is not None:
                skipped.add("components whose nested components are not an array became no record")
            continue
        yield entry
        if nested:
            yield from _walk_components(nested, skipped)


def _property_pairs(obj: dict, skipped: SkipTally) -> List[Tuple[str, Any]]:
    """The ``(name, value)`` pairs of an object's CycloneDX properties.

    A ``properties`` of the wrong type is the caller's signal that the
    object cannot be read (it is skipped there); a malformed entry is
    counted here and the well-formed ones still pass through."""
    properties = obj.get("properties")
    if not isinstance(properties, list):
        return []
    pairs: List[Tuple[str, Any]] = []
    bad_entries = 0
    for entry in properties:
        name = as_hashable_str(entry.get("name")) if isinstance(entry, dict) else None
        if name is None:
            bad_entries += 1
            continue
        pairs.append((name, entry.get("value")))
    skipped.add(
        "property entries that are not objects with a name became no attribute or location",
        bad_entries,
    )
    return pairs


class _PathValues:
    """Builds the path-carrying parts of one record through the report's
    :class:`SourcePaths`, counting the files left out so the record can
    say so."""

    def __init__(self, paths: SourcePaths) -> None:
        self.paths = paths
        self.left_out: set = set()

    def location(self, value: Any) -> Optional[EvidenceLocation]:
        """The location for one ``cdx:dynamic:filePath`` value: the file
        relative to the root, or ``None`` when no root holds it (counted)
        or the value is no path at all."""
        if not isinstance(value, str) or not value.strip():
            return None
        relative = self.paths.relative(value)
        if relative is None:
            self.left_out.add(value)
            return None
        return EvidenceLocation(file=relative)

    def attribute(self, value: Any) -> Any:
        """The stored form of a property value: a path relative to the root
        when the value is an absolute path, the value itself otherwise. An
        absolute path no root holds is left out and counted."""
        if isinstance(value, str) and is_absolute_path(value.replace("\\", "/").strip()):
            relative = self.paths.relative(value)
            if relative is None:
                self.left_out.add(value)
                return None
            return relative
        return value

    def caveats(self, base: List[EvidenceCaveat]) -> Tuple[EvidenceCaveat, ...]:
        if not self.left_out:
            return tuple(base)
        return tuple(base) + (self.paths.outside_root_caveat(len(self.left_out)),)


def _parse_report(report) -> Tuple[Optional[Any], Optional[str]]:
    """The report as a parsed value, accepting JSON text as well as a
    parsed object."""
    if isinstance(report, (str, bytes)):
        try:
            return json.loads(report), None
        except ValueError as e:
            return None, f"the report is not valid JSON: {e}"
    return report, None


def _spec_version_text(report: dict) -> str:
    """The ``specVersion`` as text, keeping a number the gate can read."""
    seen = report.get("specVersion")
    if isinstance(seen, str):
        return seen.strip()
    if isinstance(seen, (int, float)) and not isinstance(seen, bool):
        return str(seen)
    return ""


def _cdxgen_tool_version(report: dict) -> str:
    """The cdxgen version the BOM's ``metadata.tools`` names, in either the
    1.5 list form or the 1.6 ``components`` form; ``unknown`` when the BOM
    names none."""
    tools = as_dict(report.get("metadata")).get("tools")
    entries = tools if isinstance(tools, list) else as_list(as_dict(tools).get("components"))
    for entry in entries:
        if isinstance(entry, dict) and as_str(entry.get("name")) == "cdxgen":
            version = as_str(entry.get("version"))
            if version:
                return version
    return "unknown"


def _discriminant(obj: dict, paths: SourcePaths) -> str:
    """The root-neutral discriminator of one report object, over the
    object without the fields that restate its own path or name."""
    identity = {
        key: value for key, value in obj.items() if key not in _DISCRIMINATOR_EXCLUDED_FIELDS
    }
    return neutral_discriminator(identity, paths)


def _merge_attribute(attributes: Dict[str, Any], key: str, value: Any) -> None:
    """Store one producer property under its name; a name the producer
    stated twice keeps every value, as a list."""
    if key not in attributes:
        attributes[key] = value
    elif isinstance(attributes[key], list):
        attributes[key].append(value)
    else:
        attributes[key] = [attributes[key], value]


@guard_extract(PRODUCER_NAME)
def extract(report, *, source: str, source_root: Optional[str] = None) -> AdapterResult:
    """One trace BOM as evidence records.

    ``report`` is the parsed trace BOM or its JSON text. ``source`` is the
    scan-directory-relative file the BOM was read from, and
    ``source_root`` the scanned source directory the caller knows: record
    paths are relative to it. The result is the records, or not-assessed
    with the reason: a report that is not JSON, has a consumed section of
    an unexpected type, is not a trace BOM, or names an unsupported
    ``specVersion`` major is never read as a smaller report.
    """
    report, parse_error = _parse_report(report)
    if parse_error or not isinstance(report, dict):
        reason = parse_error or (
            f"the report is a {type(report).__name__}, not the trace BOM object"
        )
        return not_assessed(reason)
    problem = _section_problem(report)
    if problem:
        return not_assessed(f"the trace BOM is malformed and was not assessed: {problem}")
    if not is_tracebom_report(report):
        return not_assessed(
            "the BOM carries no cdx:dynamic: property on any component, service or the "
            "metadata, so it is not a trace BOM; it was not assessed"
        )

    seen = _spec_version_text(report)
    gate = gate_report_version(seen, SUPPORTED_MAJOR, KNOWN_MINOR)
    if not gate.accepted:
        return not_assessed(gate.reason or "")
    base_caveats = list(gate.caveats)

    producer = EvidenceProducer(
        name=PRODUCER_NAME,
        version=_cdxgen_tool_version(report),
        report_schema_version=seen or "unknown",
    )
    paths = SourcePaths(roots=[source_root])
    skipped = SkipTally()
    records = []

    for component in _walk_components(report.get("components"), skipped):
        properties = component.get("properties")
        if properties is not None and not isinstance(properties, list):
            skipped.add("components whose properties are not an array became no record")
            continue
        pairs = _property_pairs(component, skipped)
        if not any(name.startswith(DYNAMIC_PROPERTY_PREFIX) for name, _ in pairs):
            if as_str(component.get("type")) == CRYPTO_ASSET_TYPE:
                records.append(_crypto_record(component, producer, source, paths, base_caveats))
            continue
        records.append(
            _traced_component_record(
                component, pairs, producer, source, paths, base_caveats, skipped
            )
        )

    for service in as_list(report.get("services")):
        if not isinstance(service, dict):
            skipped.add("services entries are not JSON objects and became no record")
            continue
        properties = service.get("properties")
        if properties is not None and not isinstance(properties, list):
            skipped.add("services whose properties are not an array became no record")
            continue
        endpoints = service.get("endpoints")
        if endpoints is not None and not isinstance(endpoints, list):
            skipped.add("services whose endpoints are not an array became no record")
            continue
        where = _PathValues(paths)
        attributes: Dict[str, Any] = {}
        for field in ("name", "endpoints"):
            if service.get(field) is not None:
                attributes[field] = service[field]
        for name, value in _property_pairs(service, skipped):
            # A service's dynamic properties are keyed by their tracebom
            # names (``egressDecision``), the vocabulary the record's
            # readers use; a property outside the prefix keeps the name it
            # was stated with.
            key = (
                name[len(DYNAMIC_PROPERTY_PREFIX) :]
                if name.startswith(DYNAMIC_PROPERTY_PREFIX)
                else name
            )
            stored = where.attribute(value)
            if stored is not None:
                _merge_attribute(attributes, key, stored)
        records.append(
            build_record(
                source=source,
                producer=producer,
                kind="runtime-trace",
                discriminator=_discriminant(service, paths),
                attributes=attributes,
                caveats=where.caveats(base_caveats),
            )
        )

    outside = paths.producer_caveat()
    caveats = _dedupe_caveats(base_caveats + skipped.caveats() + ([outside] if outside else []))
    return AdapterResult(status=STATUS_COMPLETED, records=records, caveats=caveats)


def _traced_component_record(
    component: dict,
    pairs: List[Tuple[str, Any]],
    producer: EvidenceProducer,
    source: str,
    paths: SourcePaths,
    base_caveats: List[EvidenceCaveat],
    skipped: SkipTally,
):
    """The runtime-trace record of a component the trace saw loaded or
    executed, told apart by its ``cdx:dynamic:`` properties."""
    where = _PathValues(paths)
    purl = as_hashable_str(component.get("purl"))
    locations: List[EvidenceLocation] = []
    attributes: Dict[str, Any] = {}
    for name, value in pairs:
        if name == FILE_PATH_PROPERTY:
            if isinstance(value, str) and value.strip():
                location = where.location(value)
                if location is not None:
                    locations.append(location)
            else:
                skipped.add(
                    "cdx:dynamic:filePath properties whose value is not a non-empty string "
                    "became no location"
                )
            continue
        stored = where.attribute(value)
        if stored is not None:
            _merge_attribute(attributes, name, stored)
    return build_record(
        source=source,
        producer=producer,
        kind="runtime-trace",
        discriminator=_discriminant(component, paths),
        purls=(purl,) if purl else (),
        component_ref=as_hashable_str(component.get("bom-ref")),
        locations=tuple(locations),
        attributes=attributes,
        caveats=where.caveats(base_caveats),
    )


def _crypto_record(
    component: dict,
    producer: EvidenceProducer,
    source: str,
    paths: SourcePaths,
    base_caveats: List[EvidenceCaveat],
):
    """The runtime-trace record of a cryptographic asset the trace
    observed, carrying its ``cryptoProperties`` as the producer stated
    them."""
    purl = as_hashable_str(component.get("purl"))
    crypto = component.get("cryptoProperties")
    return build_record(
        source=source,
        producer=producer,
        kind="runtime-trace",
        discriminator=_discriminant(component, paths),
        purls=(purl,) if purl else (),
        component_ref=as_hashable_str(component.get("bom-ref")),
        attributes={"cryptoProperties": crypto} if crypto is not None else {},
        caveats=tuple(base_caveats),
    )


#: The report sections the adapter reads, with the JSON type each must
#: have when present. ``metadata.tools`` accepts the 1.5 list form and the
#: 1.6 ``components`` form. A section of another type is a malformed
#: report.
_SECTION_TYPES = (
    (("components",), list),
    (("services",), list),
    (("metadata",), dict),
    (("metadata", "tools"), (dict, list)),
    (("metadata", "tools", "components"), list),
)

_SECTION_LABELS = {dict: "an object", list: "an array"}


def _section_problem(report: dict) -> Optional[str]:
    """The first consumed section of the wrong JSON type, named, or ``None``.

    A ``null`` section reads as absent. Any other value of the wrong type
    means the report is not the shape tracebom writes."""
    for keys, expected in _SECTION_TYPES:
        value: Any = report
        for key in keys:
            if not isinstance(value, dict):
                value = None
                break
            value = value.get(key)
        if value is None or isinstance(value, expected):
            continue
        kinds = expected if isinstance(expected, tuple) else (expected,)
        want = " or ".join(_SECTION_LABELS[kind] for kind in kinds)
        return f"{'.'.join(keys)} is a {type(value).__name__}, expected {want}"
    return None


def _dedupe_caveats(caveats: List[EvidenceCaveat]) -> List[EvidenceCaveat]:
    out: List[EvidenceCaveat] = []
    seen: set = set()
    for caveat in caveats:
        key = (caveat.kind, caveat.detail)
        if key in seen:
            continue
        seen.add(key)
        out.append(caveat)
    return out


__all__ = [
    "KNOWN_MINOR",
    "PRODUCER_NAME",
    "SUPPORTED_MAJOR",
    "extract",
    "is_tracebom_report",
]
