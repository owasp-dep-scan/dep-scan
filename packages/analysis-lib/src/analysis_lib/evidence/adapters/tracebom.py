"""tracebom trace BOM -> evidence records.

tracebom is the dynamic-trace mode of the cdxgen package: it runs one
command inside a sandbox, watches the shared libraries the command loads,
the endpoints it opens and the cryptography it negotiates, and writes a
CycloneDX BOM about what it saw. This module is the only code that knows
that report format.

A trace BOM is recognised by shape, not by a format marker: a CycloneDX
BOM any of whose components (nested ones included), services or metadata
properties carry a ``cdx:dynamic:`` property, or any of whose services
carries tracebom's ``urn:service:dynamic:`` bom-ref. A trace that observed
only cryptography (TLS seen, no library hashed, no egress proxy) carries
neither, so a BOM whose ``metadata.tools`` names cdxgen, that names no
``metadata.component`` and whose components are all cryptographic assets
is read as a trace BOM too; a source BOM always names its root component.
An ordinary source BOM matches none of these and is refused.

Two version gates apply. The BOM's own ``specVersion`` (major 1, minor 7
known) and the cdxgen version its ``metadata.tools`` names, because
tracebom ships inside the cdxgen package and has no version of its own
(major 13, minor 9 known). Another major of either is refused as
not-assessed naming the version; a newer minor is accepted with a
``schema-minor`` caveat; a BOM that names no cdxgen version is accepted
with a ``schema-unknown`` caveat, which names the tools it does list when
another tool wrote it.

Three kinds of object become ``runtime-trace`` records, all with positive
polarity:

1. A component carrying a ``cdx:dynamic:`` property (a traced library, or
   an executed process on producers that record one). Its purl and
   ``bom-ref`` are the subject, the ``cdx:dynamic:filePath`` property
   becomes the location relative to the source root, and every remaining
   property is kept as an attribute under the name it was stated with.
2. A service, an endpoint observation: empty purls, the ``name`` and
   ``endpoints`` kept as given, and the properties under a ``properties``
   attribute keyed by the names they were stated with, so a producer
   property never merges with a service field.
3. A ``cryptographic-asset`` component, with its ``cryptoProperties``
   kept as given.

A runtime observation is not reachability evidence. The trace's subjects
are the traced command's environment, library files, endpoints and
algorithms, whose purls do not in general reconcile to the scanned BOM's
components, and one traced run must not mark application dependencies
reached with no code path between them. ``runtime-trace`` therefore stays
out of :data:`analysis_lib.reachability.REACHED_COUNTED_KINDS` and grades
nothing.

Every report object that becomes no record is counted in one
``record-skipped`` caveat per reason, never dropped silently: a component
or service whose ``properties`` or ``endpoints`` are of the wrong JSON
type, a property entry that is not an object with a name, a component
that carries neither a ``cdx:dynamic:`` property nor the cryptographic
asset type, a subtree nested deeper than :data:`MAX_COMPONENT_DEPTH`, and
a section (``components``, ``services``, ``metadata``) of the wrong type,
whose loss leaves the other sections' records standing. The metadata's
``cdx:dynamic:`` properties describe the traced run itself (a dry run
leaves only the attempted-operation counts there, with no component or
service beside them), so they are counted by name in the same way and a
dry-run trace never reads as a trace that observed nothing.

No record carries an absolute path, a user name or the scan root. The
producer builds a library's generic purl as ``pkg:generic/<name>#<path>``
with the loaded file's absolute path as the subpath (and its ``bom-ref``
as the decoded purl); the record keeps that subpath relative to the source
root when the root holds the file and drops it otherwise, with the file
counted in a ``location-outside-root`` caveat. A property value is scrubbed
by its name: a property whose name ends in ``path``, ``file``,
``filename``, ``dir`` or ``directory`` (``cdx:dynamic:filePath``, and the
same keys inside an object value) holds one file path, stored relative to
the root or left out and counted; every other string has the root and any
home directory taken out (:meth:`SourcePaths.redact`), so a URL path such
as ``/api/v1/users`` is kept as given.

Record ids do not follow the directory the trace ran in or the user who
ran it. The purl, ``bom-ref`` and ``evidence`` identity of a traced object
restate the file path or the name the object already carries, so the
discriminator leaves exactly those three fields out and hashes the rest
with every path spelled by :meth:`SourcePaths.stable`.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterator, List, Optional, Tuple
from urllib.parse import quote, unquote

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
    TOO_DEEP_REASON,
    as_dict,
    as_hashable_str,
    as_list,
    as_str,
    build_record,
    cdxgen_tool,
    gate_cdxgen_tool_version,
    gate_report_version,
    guard_extract,
    is_absolute_path,
    not_assessed,
    stable_discriminator,
)

#: The trace BOM schema major this adapter reads, and the newest minor it
#: knows. tracebom writes the CycloneDX spec version it was told to
#: (``--spec-version``, 1.7 by default).
SUPPORTED_MAJOR = 1
KNOWN_MINOR = 7

#: The cdxgen release line whose tracebom output this adapter was checked
#: against, and the newest minor of it.
CDXGEN_SUPPORTED_MAJOR = 13
CDXGEN_KNOWN_MINOR = 9

PRODUCER_NAME = "tracebom"

#: Every property tracebom states about the traced run lives under this
#: prefix; the presence of one such property is what makes a BOM a trace
#: BOM.
DYNAMIC_PROPERTY_PREFIX = "cdx:dynamic:"

#: The bom-ref prefix tracebom gives every service it builds.
DYNAMIC_SERVICE_REF_PREFIX = "urn:service:dynamic:"

#: The property that names the file a traced component was loaded from.
FILE_PATH_PROPERTY = "cdx:dynamic:filePath"

#: The component type of a cryptographic asset the trace observed.
CRYPTO_ASSET_TYPE = "cryptographic-asset"

#: How many levels of nested components the adapter walks. tracebom
#: writes a flat list; a deeper subtree is counted, not read.
MAX_COMPONENT_DEPTH = 64

#: Component and service fields the discriminator leaves out because the
#: producer derives them from the object's own file path or name, which
#: the hashed fields already carry.
_DISCRIMINATOR_EXCLUDED_FIELDS = ("purl", "bom-ref", "evidence")

#: A property or object key that names a file path: the last ``:``
#: segment ends in one of these words, compared without case.
_PATH_KEY_RE = re.compile(r"(?:path|file|filename|dir|directory)$", re.IGNORECASE)


def _is_path_key(key: Any) -> bool:
    return isinstance(key, str) and bool(_PATH_KEY_RE.search(key.rsplit(":", 1)[-1]))


def is_tracebom_report(report) -> bool:
    """True when ``report`` has the shape of a trace BOM (see the module
    docstring). Safe on any JSON value: the component walk is iterative and
    stops at :data:`MAX_COMPONENT_DEPTH`, so a hostile nesting depth never
    raises."""
    if not isinstance(report, dict):
        return False
    for component in _walk_components(report.get("components")):
        if _has_dynamic_property(component):
            return True
    for service in as_list(report.get("services")):
        if isinstance(service, dict) and (
            _has_dynamic_property(service)
            or as_str(service.get("bom-ref")).startswith(DYNAMIC_SERVICE_REF_PREFIX)
        ):
            return True
    metadata = as_dict(report.get("metadata"))
    if _has_dynamic_property(metadata):
        return True
    components = as_list(report.get("components"))
    return (
        bool(components)
        and metadata.get("component") is None
        and cdxgen_tool(report)[0]
        and all(
            isinstance(c, dict) and as_str(c.get("type")) == CRYPTO_ASSET_TYPE for c in components
        )
    )


def _has_dynamic_property(obj: dict) -> bool:
    properties = obj.get("properties")
    return isinstance(properties, list) and any(
        isinstance(entry, dict) and as_str(entry.get("name")).startswith(DYNAMIC_PROPERTY_PREFIX)
        for entry in properties
    )


def _walk_components(value: Any, skipped: Optional[SkipTally] = None) -> Iterator[dict]:
    """Every component of a components array, the nested ones included, in
    document order (a component before its nested components).

    The walk keeps its own stack, so no nesting depth raises. An entry that
    is not a JSON object, a ``components`` array of the wrong type one
    level down, and a subtree below :data:`MAX_COMPONENT_DEPTH` are counted
    as skips when a tally is given, so none disappears without a count."""
    stack: List[Tuple[Iterator[Any], int]] = [(iter(as_list(value)), 1)]
    while stack:
        entries, depth = stack[-1]
        entry = next(entries, _END)
        if entry is _END:
            stack.pop()
            continue
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
            if depth >= MAX_COMPONENT_DEPTH:
                if skipped is not None:
                    skipped.add(
                        f"components nested deeper than {MAX_COMPONENT_DEPTH} levels "
                        "became no record",
                        _subtree_size(nested),
                    )
                continue
            stack.append((iter(nested), depth + 1))


_END = object()


def _subtree_size(value: list) -> int:
    """How many component objects a nested array holds, counted without
    recursion."""
    count = 0
    pending = [value]
    while pending:
        for entry in pending.pop():
            if isinstance(entry, dict):
                count += 1
                nested = entry.get("components")
                if isinstance(nested, list):
                    pending.append(nested)
    return count


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

    def path(self, value: str) -> Optional[str]:
        """One file path relative to the root, or ``None`` (counted) when no
        root holds it."""
        relative = self.paths.relative(value)
        if relative is None:
            self.left_out.add(value)
        return relative

    def location(self, value: Any) -> Optional[EvidenceLocation]:
        """The location for one ``cdx:dynamic:filePath`` value: the file
        relative to the root, or ``None`` when no root holds it (counted)
        or the value is no path at all."""
        if not isinstance(value, str) or not value.strip():
            return None
        relative = self.path(value)
        return EvidenceLocation(file=relative) if relative is not None else None

    def attribute(self, name: str, value: Any) -> Any:
        """The stored form of one property value. A path-named property
        holds a file path: relative when a root holds it, otherwise left out
        (counted), and ``None`` comes back. Any other string has the root
        and home directories taken out. An object or array keeps its shape,
        its own keys deciding the rule for the values below them."""
        if isinstance(value, str):
            text = value.strip()
            if _is_path_key(name) and is_absolute_path(text.replace("\\", "/")):
                return self.path(value)
            return self.paths.redact(value)
        if isinstance(value, list):
            return [self.attribute(name, item) for item in value]
        if isinstance(value, dict):
            return {key: self.attribute(key, item) for key, item in value.items()}
        return value

    def caveats(self, base: List[EvidenceCaveat]) -> Tuple[EvidenceCaveat, ...]:
        if not self.left_out:
            return tuple(base)
        return tuple(base) + (self.paths.outside_root_caveat(len(self.left_out)),)


def _library_subpath(file_path: str) -> str:
    """The purl subpath the producer derives from a loaded file's path:
    backslashes read as forward slashes and the drive or UNC prefix and
    leading separators dropped (cdxgen's ``librarySubpath``)."""
    subpath = file_path
    if re.match(r"^[A-Za-z]:[\\/]", subpath) or subpath.startswith("\\\\"):
        subpath = subpath.replace("\\", "/")
        if re.match(r"^[A-Za-z]:/", subpath):
            subpath = subpath[3:]
    return subpath.lstrip("/")


def _encode_subpath(path: str) -> str:
    return "/".join(quote(segment, safe="") for segment in path.split("/"))


def _subject(
    component: dict, file_paths: List[str], where: _PathValues
) -> Tuple[Optional[str], Optional[str]]:
    """The record's subject purl and component ref, with no path the root
    does not hold.

    The producer's purl is kept as given unless it is a generic purl
    carrying a subpath or a qualifier that spells an absolute file path.
    Such a subpath becomes the file's path relative to the root when the
    root holds it (matched through the component's ``cdx:dynamic:filePath``
    values, or read as a POSIX path when none matches) and is dropped
    otherwise, with the file counted as left out; such a qualifier follows
    the same rule. The ``bom-ref`` follows its purl: the producer sets it
    to the decoded purl, and a bom-ref that restates the original subpath
    any other way has it rewritten the same way."""
    purl = as_hashable_str(component.get("purl"))
    ref = as_hashable_str(component.get("bom-ref"))
    if not purl or not purl.startswith("pkg:generic/"):
        return purl, _redacted_ref(ref, where)
    head, _, subpath = purl.partition("#")
    base, _, query = head.partition("?")
    new_subpath: Optional[str] = None
    decoded = unquote(subpath).strip("/") if subpath else ""
    if decoded:
        new_subpath = _relative_subpath(decoded, file_paths, where)
    kept_qualifiers = []
    for pair in query.split("&") if query else []:
        key, _, raw = pair.partition("=")
        value = unquote(raw)
        if is_absolute_path(value.replace("\\", "/")):
            relative = where.path(value)
            if relative is None:
                continue
            raw = quote(relative, safe="/")
        kept_qualifiers.append(f"{key}={raw}")
    new_purl = base
    if kept_qualifiers:
        new_purl += "?" + "&".join(kept_qualifiers)
    if new_subpath:
        new_purl += "#" + _encode_subpath(new_subpath)
    if new_purl == purl:
        return purl, _redacted_ref(ref, where)
    if ref is not None and ref == purl:
        ref = new_purl
    elif ref is not None and ref == unquote(purl):
        ref = unquote(new_purl)
    elif ref is not None and decoded and decoded in ref:
        ref = ref.replace("#" + decoded, "#" + new_subpath if new_subpath else "")
        ref = ref.replace(decoded, new_subpath or "")
    return new_purl, _redacted_ref(ref, where)


def _relative_subpath(decoded: str, file_paths: List[str], where: _PathValues) -> Optional[str]:
    """A generic purl's subpath relative to the root, or ``None`` when no
    root holds the file it names (counted as left out)."""
    for file_path in file_paths:
        if _library_subpath(file_path.strip()) == decoded:
            return where.path(file_path)
    return where.path("/" + decoded)


def _redacted_ref(ref: Optional[str], where: _PathValues) -> Optional[str]:
    return where.paths.redact(ref) if ref is not None else None


def _parse_report(report) -> Tuple[Optional[Any], Optional[str]]:
    """The report as a parsed value, accepting JSON text as well as a
    parsed object."""
    if isinstance(report, (str, bytes)):
        try:
            return json.loads(report), None
        except RecursionError:
            return None, "the report nests its values deeper than this adapter reads"
        except ValueError as e:
            return None, f"the report is not valid JSON: {e}"
    return report, None


def _spec_version_text(report: dict) -> str:
    """The ``specVersion`` as the report schema version text, for a BOM the
    gate already accepted: a string as stated, a number as its text, and
    empty when the BOM names no version. The gate itself reads the raw
    value, so a version of the wrong JSON type is refused there rather
    than flattened into a missing one."""
    seen = report.get("specVersion")
    if isinstance(seen, str):
        return seen.strip()
    if isinstance(seen, (int, float)) and not isinstance(seen, bool):
        return str(seen)
    return ""


def _discriminant(obj: dict, paths: SourcePaths) -> str:
    """The machine-neutral discriminator of one report object, over the
    object without the fields that restate its own path or name."""
    identity = {
        key: value for key, value in obj.items() if key not in _DISCRIMINATOR_EXCLUDED_FIELDS
    }
    return stable_discriminator(identity, paths)


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
    with the reason: a report that is not JSON, is not a trace BOM, or
    names an unsupported ``specVersion`` or cdxgen major is never read as
    a smaller report. A section of the wrong type is a counted skip.
    """
    report, parse_error = _parse_report(report)
    if parse_error or not isinstance(report, dict):
        reason = parse_error or (
            f"the report is a {type(report).__name__}, not the trace BOM object"
        )
        return not_assessed(reason)
    if not is_tracebom_report(report):
        return not_assessed(
            "the BOM carries no cdx:dynamic: property on any component, service or the "
            "metadata, no tracebom service and no trace-only cryptography, so it is not a "
            "trace BOM; it was not assessed"
        )

    seen = _spec_version_text(report)
    gate = gate_report_version(report.get("specVersion"), SUPPORTED_MAJOR, KNOWN_MINOR)
    if not gate.accepted:
        return not_assessed(gate.reason or "")
    tool_gate, tool_version = gate_cdxgen_tool_version(
        report, CDXGEN_SUPPORTED_MAJOR, CDXGEN_KNOWN_MINOR, "tracebom"
    )
    if not tool_gate.accepted:
        return not_assessed(tool_gate.reason or "")
    base_caveats = list(gate.caveats) + list(tool_gate.caveats)

    producer = EvidenceProducer(
        name=PRODUCER_NAME,
        version=tool_version,
        report_schema_version=seen or "unknown",
    )
    paths = SourcePaths(roots=[source_root])
    skipped = SkipTally()
    records = []
    _count_section_problems(report, skipped)
    _count_metadata_dynamic_properties(report, skipped)

    for component in _walk_components(report.get("components"), skipped):
        try:
            record = _component_record(component, producer, source, paths, base_caveats, skipped)
        except RecursionError:
            skipped.add(TOO_DEEP_REASON)
            continue
        if record is not None:
            records.append(record)

    for service in as_list(report.get("services")):
        try:
            record = _service_record(service, producer, source, paths, base_caveats, skipped)
        except RecursionError:
            skipped.add(TOO_DEEP_REASON)
            continue
        if record is not None:
            records.append(record)

    outside = paths.producer_caveat()
    caveats = _dedupe_caveats(base_caveats + skipped.caveats() + ([outside] if outside else []))
    return AdapterResult(status=STATUS_COMPLETED, records=records, caveats=caveats)


def _component_record(
    component: dict,
    producer: EvidenceProducer,
    source: str,
    paths: SourcePaths,
    base_caveats: List[EvidenceCaveat],
    skipped: SkipTally,
):
    """The record of one component, or ``None`` with the reason counted."""
    properties = component.get("properties")
    if properties is not None and not isinstance(properties, list):
        skipped.add("components whose properties are not an array became no record")
        return None
    pairs = _property_pairs(component, skipped)
    if any(name.startswith(DYNAMIC_PROPERTY_PREFIX) for name, _ in pairs):
        return _traced_component_record(
            component, pairs, producer, source, paths, base_caveats, skipped
        )
    if as_str(component.get("type")) == CRYPTO_ASSET_TYPE:
        return _crypto_record(component, producer, source, paths, base_caveats)
    skipped.add(
        "components carry no cdx:dynamic: property and are no cryptographic asset, "
        "so they name nothing the trace observed and became no record"
    )
    return None


def _service_record(
    service: Any,
    producer: EvidenceProducer,
    source: str,
    paths: SourcePaths,
    base_caveats: List[EvidenceCaveat],
    skipped: SkipTally,
):
    """The record of one service, or ``None`` with the reason counted."""
    if not isinstance(service, dict):
        skipped.add("services entries are not JSON objects and became no record")
        return None
    properties = service.get("properties")
    if properties is not None and not isinstance(properties, list):
        skipped.add("services whose properties are not an array became no record")
        return None
    endpoints = service.get("endpoints")
    if endpoints is not None and not isinstance(endpoints, list):
        skipped.add("services whose endpoints are not an array became no record")
        return None
    where = _PathValues(paths)
    attributes: Dict[str, Any] = {}
    for field in ("name", "endpoints"):
        if service.get(field) is not None:
            attributes[field] = paths.redact(service[field])
    stated: Dict[str, Any] = {}
    for name, value in _property_pairs(service, skipped):
        stored = where.attribute(name, value)
        if stored is not None:
            _merge_attribute(stated, name, stored)
    if stated:
        attributes["properties"] = stated
    return build_record(
        source=source,
        producer=producer,
        kind="runtime-trace",
        discriminator=_discriminant(service, paths),
        attributes=attributes,
        caveats=where.caveats(base_caveats),
    )


def _count_section_problems(report: dict, skipped: SkipTally) -> None:
    """Count every consumed section of the wrong JSON type. A ``null``
    section reads as absent; any other value of the wrong type costs that
    section's objects alone, and the other sections are still read."""
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
        skipped.add(
            f"{'.'.join(keys)} sections are a {type(value).__name__}, expected {want}, "
            "and their contents became no record"
        )


def _count_metadata_dynamic_properties(report: dict, skipped: SkipTally) -> None:
    """Count the metadata's ``cdx:dynamic:`` properties that become no
    record, naming them.

    These properties describe the traced run itself rather than any traced
    object: a dry run denies every side effect and leaves only the
    attempted-operation counts here, with no component or service beside
    them. They marked the BOM as a trace, so they are counted rather than
    dropped, and a dry-run trace never reads as a trace that observed
    nothing."""
    pairs = _property_pairs(as_dict(report.get("metadata")), skipped)
    dynamic = [name for name, _ in pairs if name.startswith(DYNAMIC_PROPERTY_PREFIX)]
    if dynamic:
        skipped.add(
            "metadata cdx:dynamic: properties that describe the traced run rather than "
            f"any traced object became no record ({', '.join(sorted(set(dynamic)))})",
            len(dynamic),
        )


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
    locations: List[EvidenceLocation] = []
    attributes: Dict[str, Any] = {}
    file_paths: List[str] = []
    for name, value in pairs:
        if name == FILE_PATH_PROPERTY:
            if isinstance(value, str) and value.strip():
                file_paths.append(value)
                location = where.location(value)
                if location is not None:
                    locations.append(location)
            else:
                skipped.add(
                    "cdx:dynamic:filePath properties whose value is not a non-empty string "
                    "became no location"
                )
            continue
        stored = where.attribute(name, value)
        if stored is not None:
            _merge_attribute(attributes, name, stored)
    purl, component_ref = _subject(component, file_paths, where)
    return build_record(
        source=source,
        producer=producer,
        kind="runtime-trace",
        discriminator=_discriminant(component, paths),
        purls=(purl,) if purl else (),
        component_ref=component_ref,
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
    where = _PathValues(paths)
    purl, component_ref = _subject(component, [], where)
    crypto = component.get("cryptoProperties")
    return build_record(
        source=source,
        producer=producer,
        kind="runtime-trace",
        discriminator=_discriminant(component, paths),
        purls=(purl,) if purl else (),
        component_ref=component_ref,
        attributes={"cryptoProperties": paths.redact(crypto)} if crypto is not None else {},
        caveats=where.caveats(base_caveats),
    )


#: The report sections the adapter reads, with the JSON type each must
#: have when present. ``metadata.tools`` accepts the 1.5 list form and the
#: 1.6 ``components`` form.
_SECTION_TYPES = (
    (("components",), list),
    (("services",), list),
    (("metadata",), dict),
    (("metadata", "tools"), (dict, list)),
    (("metadata", "tools", "components"), list),
    (("metadata", "properties"), list),
)

_SECTION_LABELS = {dict: "an object", list: "an array"}


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
    "CDXGEN_KNOWN_MINOR",
    "CDXGEN_SUPPORTED_MAJOR",
    "KNOWN_MINOR",
    "MAX_COMPONENT_DEPTH",
    "PRODUCER_NAME",
    "SUPPORTED_MAJOR",
    "extract",
    "is_tracebom_report",
]
