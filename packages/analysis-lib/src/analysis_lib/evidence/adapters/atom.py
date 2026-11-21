"""The atom evidence adapter.

atom is cdxgen's code analysis engine, and its native output is what this
adapter reads: the reachables slices (bare JSON arrays of flow objects, one
``slices.json`` plus ``slices_1..N.json`` split files), the usages slices
(JSON objects with an ``objectSlices`` array), the callsites slices (JSON
objects with a ``callsites`` array) and the OpenAPI documents whose path
objects carry the ``x-atom-usages`` extension atom-tools writes. Each input
becomes one kind of record: a reachables flow becomes a ``reached-flow``
record whose subject is the flow's own purls and whose path is the flow's
nodes, an ``objectSlices`` entry becomes a ``usage`` record, a callsites
entry becomes a ``callsite`` record, and an ``x-atom-usages`` object becomes
an ``entry-point`` record.

atom names no schema version in its reports, so the version comes from the
shape: a bare array is the atom 4 reachables shape (the same rule the
repotests staleness validator applies) and becomes ``"4"``; an object with a
``reachables`` key is the atom 2 wrapped shape, refused here as an unknown
major version with the reason naming the version seen. A file that is
neither is not assessed with the reason naming what it holds, and a
truncated or malformed file is not assessed as well; a damaged report in any
input role fails the whole result, because a producer result that read only
part of its input must not read as a complete one.

The run-level markers the runner saw become caveats on every record and in
the producer caveats: the ``--parse-report`` document atom writes on request
lists the files the frontends left out or only partly read (a ``budget``
caveat), and an exit-124 timeout the runner captured is passed through as
the ``timeout`` caveat text it was given. A report array element that is not
a flow object becomes a ``record-skipped`` caveat, never a silent drop.

Service attribution is adapter work: a flow's ``attributes.servicePurls``
holds exactly the purls the positional tag walk in this module marks as
services, so the engine never parses node tags.

The report schema keeps a witness node to ``file``, ``line``, ``method`` and
``symbol``. atom's nodes carry more than that (the source ``code``, the
``tags`` string, signatures and class names); the tag string survives as the
service purls it marks and the rest is left out of the record rather than
reshaped into fields the schema does not have.
"""

import json
import os
from collections import Counter
from typing import Any, Dict, Iterable, Iterator, List, Optional, Set, Tuple, Union

from analysis_lib.config import SERVICE_TAGS
from analysis_lib.evidence import (
    Evidence,
    EvidenceCaveat,
    EvidenceLocation,
    EvidencePathNode,
    EvidenceProducer,
    content_discriminator,
)
from analysis_lib.evidence.adapters import (
    STATUS_COMPLETED,
    AdapterResult,
    VersionGate,
    add_caveat,
    build_record,
    gate_report_version,
    not_assessed,
)

#: A report path as the caller holds it: a string or a path-like object.
StrPath = Union[str, "os.PathLike[str]"]

#: The producer name every record of this adapter carries.
PRODUCER_NAME = "atom"

#: The report major this adapter reads and the newest minor of it it knows.
#: atom's reports carry no version field, so the shape implies the version
#: and there is no minor to know beyond the shape itself.
SUPPORTED_MAJOR = 4
KNOWN_MINOR = 0

#: The reachables flow attributes the record keeps as given, when the flow
#: names them.
FLOW_ATTRIBUTE_KEYS = ("reachableFromRoots", "minDepth", "rootIds", "rootLabels")

#: The callsite facts a record keeps in attributes, on top of the location
#: and the subject purl.
CALLSITE_ATTRIBUTE_KEYS = ("kind", "via")


class _Damaged(Exception):
    """A report file that cannot be assessed, with the reason for the
    not-assessed result it forces."""


def _damaged_reason(path: str, role: str, problem: str) -> str:
    return f"the atom {role} {os.path.basename(path)} {problem}"


def _forward_slashes(value: str) -> str:
    return value.replace(os.sep, "/")


def _text(value: Any) -> Optional[str]:
    """A non-empty string value, or nothing."""
    return value if isinstance(value, str) and value else None


def _line_number(value: Any) -> Optional[int]:
    """A line number the schema can carry: an integer from 1 up."""
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 1 else None


def _source_name(path: StrPath) -> str:
    return os.path.basename(os.fspath(path))


def _skip_space(text: str, idx: int) -> int:
    while idx < len(text) and text[idx] in " \t\n\r":
        idx += 1
    return idx


def _read_text(path: str, role: str) -> str:
    try:
        with open(path, encoding="utf-8") as fp:
            return fp.read()
    except (OSError, UnicodeDecodeError) as exc:
        raise _Damaged(_damaged_reason(path, role, f"could not be read ({exc})")) from exc


def _decode_at(
    decoder: json.JSONDecoder, text: str, idx: int, path: str, role: str
) -> Tuple[Any, int]:
    """The JSON value starting at ``idx`` and the position just past it.

    A value that cannot be parsed is a damaged report: the reason names the
    file and where the parse stopped.
    """
    try:
        value, end = decoder.raw_decode(text, idx)
    except json.JSONDecodeError as exc:
        raise _Damaged(
            _damaged_reason(
                path, role, f"is truncated or malformed ({exc.msg} at character {exc.pos})"
            )
        ) from exc
    return value, end


def _iter_array(text: str, idx: int, path: str, role: str) -> Iterator[Any]:
    """Yield each element of the JSON array starting at ``idx``.

    The walk is the engine's raw_decode walk over the array text, with one
    difference: an array that runs past the end of the text is a damaged
    report here, while the engine's walk quietly returns whatever it parsed.
    The adapter must know when an element was lost, so the array has to
    close.
    """
    decoder = json.JSONDecoder()
    idx += 1  # past the opening bracket
    expect_value = True
    while True:
        idx = _skip_space(text, idx)
        if idx >= len(text):
            raise _Damaged(
                _damaged_reason(path, role, "is truncated; the JSON array does not close")
            )
        ch = text[idx]
        if expect_value:
            if ch == "]":
                return
            value, idx = _decode_at(decoder, text, idx, path, role)
            yield value
            expect_value = False
        elif ch == ",":
            expect_value = True
            idx += 1
        elif ch == "]":
            return
        else:
            raise _Damaged(
                _damaged_reason(
                    path, role, f"is malformed: expected ',' or ']' at character {idx}"
                )
            )


def _object_shape_reason(decoder: json.JSONDecoder, text: str, idx: int, path: str) -> str:
    """The not-assessed reason for a reachables file that opens as an object.

    An object with a ``reachables`` key is the atom 2 wrapped shape; the
    version gate refuses it as an unknown major and the reason names the
    version it saw. Any other object is neither shape this adapter reads.
    """
    role = "reachables slice"
    document = _decode_at(decoder, text, idx, path, role)[0]
    if isinstance(document, dict) and "reachables" in document:
        gate = gate_report_version("2", SUPPORTED_MAJOR, KNOWN_MINOR)
        return gate.reason or _damaged_reason(
            path, role, "is the atom 2 wrapped shape, which this adapter does not read"
        )
    if isinstance(document, dict):
        label = next(iter(document), "an empty object")
        return _damaged_reason(
            path,
            role,
            f"is neither a bare array of flow objects nor the atom 2 reachables object; "
            f"it starts with the key {label!r}",
        )
    return _damaged_reason(
        path, role, f"is neither a JSON array nor an object; it holds a {type(document).__name__}"
    )


def _flow_identity(flow: Dict[str, Any]) -> str:
    """The stable identity of a reachables flow: the content hash of the
    whole flow object, so a flow repeated in a second split file is seen as
    the same one."""
    return content_discriminator(flow)


def _node_location(node: Dict[str, Any]) -> Optional[EvidenceLocation]:
    """The location of a flow node: its method's file, line and name."""
    name = _text(node.get("parentFileName"))
    if name is None:
        return None
    return EvidenceLocation(
        file=_forward_slashes(name),
        line=_line_number(node.get("lineNumber")),
        method=_text(node.get("parentMethodName")),
    )


def _node_path_node(node: Dict[str, Any]) -> EvidencePathNode:
    symbol = _text(node.get("fullName")) or _text(node.get("name"))
    file_name = _text(node.get("parentFileName"))
    return EvidencePathNode(
        file=_forward_slashes(file_name) if file_name else None,
        line=_line_number(node.get("lineNumber")),
        method=_text(node.get("parentMethodName")),
        symbol=symbol,
    )


def _split_tag_pieces(value: Any) -> List[str]:
    """Flatten a node ``tags`` value (comma-string or list) into stripped
    non-empty pieces, preserving order. atom stores a comma-string; a list is
    accepted too."""
    pieces: List[str] = []

    def _walk(v: Any) -> None:
        if isinstance(v, str):
            for piece in v.split(","):
                piece = piece.strip()
                if piece:
                    pieces.append(piece)
        elif isinstance(v, (list, tuple)):
            for item in v:
                _walk(item)

    _walk(value)
    return pieces


def _node_service_purls(pieces: List[str], flow_purls: List[str]) -> Set[str]:
    """The purls a node's tag string marks as services.

    A node's ``tags`` string interleaves purls and free-form tags in discovery
    order, e.g. ``"pkg:npm/jsonwebtoken@0.4.0, token, web,
    pkg:npm/%40codemirror/lang-json@6.0.2"``: the free-form tags describe the
    NEAREST preceding purl in that string, so ``token``/``web`` belong to
    ``jsonwebtoken`` and ``codemirror`` gets none. Flattening every node tag
    across the whole flow and applying it to EVERY flow purl leaks service
    tags onto unrelated packages, so tags are associated per node.

    atom 4 adds one order this positional walk must also cover: for a call
    whose own tags name no purl, the callee's package URLs are appended AFTER
    them (``withPurls`` in ``ReachableSlicing.scala``), so a service tag can
    PRECEDE every purl in the string (``"web, pkg:npm/express@4.22.2"``). Such
    a tag describes the call, and the purls appended right after it are the
    callee's packages (often two versions of one library), so it applies to
    each purl in the run that directly follows it and to nothing after the
    next free-form tag.

    A node that carries a SERVICE_TAG but names no purl at all keeps the
    fallback to the flow-level ``purls`` so the signal is never lost.
    """
    node_purl_is_service: Dict[str, bool] = {}
    current_purl = None
    pending_service = False
    for piece in pieces:
        if piece.startswith("pkg:"):
            node_purl_is_service.setdefault(piece, False)
            current_purl = piece
            if pending_service:
                node_purl_is_service[piece] = True
            continue
        # A free-form tag ends the run of purls a leading service tag covers.
        pending_service = False
        if piece in SERVICE_TAGS:
            # Attribute to the nearest preceding purl; if none came yet, the
            # pending flag hands the tag to the purls that directly follow.
            if current_purl is not None:
                node_purl_is_service[current_purl] = True
            else:
                pending_service = True
    if any(node_purl_is_service.values()):
        return {p for p, has_svc in node_purl_is_service.items() if has_svc}
    if not node_purl_is_service and any(p in SERVICE_TAGS for p in pieces):
        return set(flow_purls)
    return set()


def _flow_service_purls(flow: Dict[str, Any]) -> Set[str]:
    """The purls in ``flow`` that carry a SERVICE_TAG on their OWN node. See
    :func:`_node_service_purls` for the association rules."""
    flow_purls = flow.get("purls") or []
    service_purls: Set[str] = set()
    nodes = flow.get("flows")
    if isinstance(nodes, list):
        for node in nodes:
            if not isinstance(node, dict):
                continue
            pieces = _split_tag_pieces(node.get("tags"))
            if not pieces:
                continue
            service_purls.update(_node_service_purls(pieces, flow_purls))
    return service_purls


def _flow_record(
    flow: Dict[str, Any],
    source: str,
    producer: EvidenceProducer,
    caveats: List[EvidenceCaveat],
) -> Evidence:
    """The reached-flow record of one unique flow object."""
    nodes = [node for node in (flow.get("flows") or []) if isinstance(node, dict)]
    location = _node_location(nodes[0]) if nodes else None
    attributes: Dict[str, Any] = {key: flow[key] for key in FLOW_ATTRIBUTE_KEYS if key in flow}
    service_purls = _flow_service_purls(flow)
    if service_purls:
        attributes["servicePurls"] = sorted(service_purls)
    return build_record(
        source=source,
        producer=producer,
        kind="reached-flow",
        discriminator=_flow_identity(flow),
        purls=tuple(purl for purl in (flow.get("purls") or []) if _text(purl)),
        locations=(location,) if location is not None else (),
        path=tuple(_node_path_node(node) for node in nodes),
        attributes=attributes or None,
        caveats=tuple(caveats),
    )


def _usage_record(
    entry: Dict[str, Any],
    source: str,
    producer: EvidenceProducer,
    caveats: List[EvidenceCaveat],
) -> Evidence:
    """The usage record of one ``objectSlices`` entry.

    The entry's own position is the location; each usage below it contributes
    one witness node shaped from the object the usage targets. Usage
    sub-entries that carry no target object contribute no node; they are
    structure atom gives no schema field to, not lost records.
    """
    file_name = _text(entry.get("fileName"))
    location = (
        EvidenceLocation(
            file=_forward_slashes(file_name),
            line=_line_number(entry.get("lineNumber")),
            method=_text(entry.get("fullName")),
        )
        if file_name
        else None
    )
    path_nodes: List[EvidencePathNode] = []
    for usage in entry.get("usages") or []:
        if not isinstance(usage, dict):
            continue
        target = usage.get("targetObj")
        if not isinstance(target, dict):
            continue
        path_nodes.append(
            EvidencePathNode(
                symbol=_text(target.get("name")),
                line=_line_number(target.get("lineNumber")),
                method=_text(target.get("resolvedMethod")),
            )
        )
    return build_record(
        source=source,
        producer=producer,
        kind="usage",
        discriminator=content_discriminator(entry),
        purls=(),
        locations=(location,) if location is not None else (),
        path=tuple(path_nodes),
        caveats=tuple(caveats),
    )


def _callsite_record(
    entry: Dict[str, Any],
    source: str,
    producer: EvidenceProducer,
    caveats: List[EvidenceCaveat],
) -> Evidence:
    """The callsite record of one callsites entry.

    Callsite records never count as reached evidence; they record where a
    package's code is called from and how the call site was resolved.
    """
    file_name = _text(entry.get("file"))
    location = (
        EvidenceLocation(
            file=_forward_slashes(file_name),
            line=_line_number(entry.get("line")),
            method=_text(entry.get("method")),
        )
        if file_name
        else None
    )
    purl = _text(entry.get("purl"))
    attributes = {
        key: value for key in CALLSITE_ATTRIBUTE_KEYS if (value := _text(entry.get(key)))
    }
    return build_record(
        source=source,
        producer=producer,
        kind="callsite",
        discriminator=content_discriminator(entry),
        purls=(purl,) if purl else (),
        locations=(location,) if location is not None else (),
        attributes=attributes or None,
        caveats=tuple(caveats),
    )


def _extension_locations(extension: Dict[str, Any]) -> List[EvidenceLocation]:
    """The file and line locations an ``x-atom-usages`` object names.

    The values are per-file lists of line numbers, in the shape atom-tools
    writes for both its ``call`` and ``target`` maps; the walk reads every
    map the object carries, the way the engine reads them.
    """
    locations: List[EvidenceLocation] = []
    for _kind, per_file in extension.items():
        if not isinstance(per_file, dict):
            continue
        for file, lines in per_file.items():
            file_name = _text(file)
            if file_name is None or not isinstance(lines, (list, tuple, set)):
                continue
            for line in lines:
                number = _line_number(line)
                if number is not None:
                    locations.append(
                        EvidenceLocation(file=_forward_slashes(file_name), line=number)
                    )
    return locations


def _entry_point_records(
    path: str,
    producer: EvidenceProducer,
    caveats: List[EvidenceCaveat],
    skipped: List[EvidenceCaveat],
) -> List[Any]:
    """The entry-point records of one OpenAPI document.

    One record per path object that carries ``x-atom-usages``, either beside
    its methods (the Java, JavaScript and Python shape) or inside one method
    object (the Ruby and Scala shape, which names the method). The records
    carry no purls; the extension maps files to lines, and endpoint reach
    attribution stays the engine's job.
    """
    role = "OpenAPI document"
    name = _source_name(path)
    try:
        with open(path, encoding="utf-8") as fp:
            document = json.load(fp)
    except (OSError, UnicodeDecodeError) as exc:
        raise _Damaged(_damaged_reason(path, role, f"could not be read ({exc})")) from exc
    except json.JSONDecodeError as exc:
        raise _Damaged(
            _damaged_reason(
                path, role, f"is truncated or malformed ({exc.msg} at character {exc.pos})"
            )
        ) from exc
    if not isinstance(document, dict):
        raise _Damaged(
            _damaged_reason(path, role, f"holds a JSON {type(document).__name__}, not an object")
        )
    paths = document.get("paths")
    paths = paths if isinstance(paths, dict) else {}
    records: List[Evidence] = []
    for endpoint, path_object in paths.items():
        if not isinstance(path_object, dict):
            skipped.append(
                EvidenceCaveat(
                    kind="record-skipped",
                    detail=(
                        f"the atom {role} {name} holds a paths entry that is not an object; "
                        "it became no record"
                    ),
                )
            )
            continue
        for method_key, value in path_object.items():
            if method_key == "x-atom-usages":
                extension = value
                method = None
            elif isinstance(value, dict) and value.get("x-atom-usages"):
                extension = value["x-atom-usages"]
                method = method_key
            else:
                continue
            if not isinstance(extension, dict):
                skipped.append(
                    EvidenceCaveat(
                        kind="record-skipped",
                        detail=(
                            f"the atom {role} {name} holds an x-atom-usages value that is not "
                            f"an object for the endpoint {endpoint!r}; it became no record"
                        ),
                    )
                )
                continue
            identity: Dict[str, Any] = {"endpoint": endpoint, "x-atom-usages": extension}
            attributes: Dict[str, Any] = {"endpoint": endpoint}
            if method is not None:
                identity["method"] = method
                attributes["method"] = method
            records.append(
                build_record(
                    source=name,
                    producer=producer,
                    kind="entry-point",
                    discriminator=content_discriminator(identity),
                    purls=(),
                    locations=tuple(_extension_locations(extension)),
                    attributes=attributes,
                    caveats=tuple(caveats),
                )
            )
    return records


def _object_entries(path: str, role: str, key: str) -> List[Any]:
    """The array under ``key`` in one wrapped atom report file."""
    try:
        with open(path, encoding="utf-8") as fp:
            document = json.load(fp)
    except (OSError, UnicodeDecodeError) as exc:
        raise _Damaged(_damaged_reason(path, role, f"could not be read ({exc})")) from exc
    except json.JSONDecodeError as exc:
        raise _Damaged(
            _damaged_reason(
                path, role, f"is truncated or malformed ({exc.msg} at character {exc.pos})"
            )
        ) from exc
    if not isinstance(document, dict):
        raise _Damaged(
            _damaged_reason(
                path,
                role,
                f"is not the atom 4 shape: a {role} carries a JSON object with an array "
                f"under {key!r}, not a JSON {type(document).__name__}",
            )
        )
    entries = document.get(key)
    if not isinstance(entries, list):
        problem = "is missing" if key not in document else "is not an array"
        raise _Damaged(_damaged_reason(path, role, f"is not a readable {role}: {key!r} {problem}"))
    return entries


def _parse_report_caveats(paths: Iterable[StrPath]) -> List[EvidenceCaveat]:
    """One budget caveat per atom ``--parse-report`` document that lists
    files the frontends left out or only partly read.

    A report that cannot be read still caveats, naming the file, so the
    runner's request for one is never lost quietly. A report with no failed
    files adds nothing: the run parsed what it was given.
    """
    caveats: List[EvidenceCaveat] = []
    for path in paths:
        name = _source_name(path)
        try:
            with open(path, encoding="utf-8") as fp:
                document = json.load(fp)
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            caveats.append(
                EvidenceCaveat(
                    kind="budget",
                    detail=f"the atom parse report {name} could not be read ({exc.__class__.__name__})",
                )
            )
            continue
        records = document.get("records") if isinstance(document, dict) else None
        records = [record for record in records or [] if isinstance(record, dict)]
        if not records:
            continue
        counts = Counter(str(record.get("outcome") or "unknown outcome") for record in records)
        summary = ", ".join(f"{outcome}: {count}" for outcome, count in sorted(counts.items()))
        caveats.append(
            EvidenceCaveat(
                kind="budget",
                detail=(
                    f"the atom parse report {name} lists {len(records)} file(s) the frontends "
                    f"left out or only partly read ({summary})"
                ),
            )
        )
    return caveats


def _timeout_caveats(reasons: Iterable[str]) -> List[EvidenceCaveat]:
    """One timeout caveat per reason the runner captured, kept as given."""
    return [EvidenceCaveat(kind="timeout", detail=reason) for reason in reasons if reason]


def extract(
    report: Optional[Iterable["StrPath"]],
    *,
    producer_version: str = "unknown",
    usages_files: Optional[Iterable["StrPath"]] = None,
    callsites_files: Optional[Iterable["StrPath"]] = None,
    openapi_files: Optional[Iterable["StrPath"]] = None,
    parse_reports: Optional[Iterable["StrPath"]] = None,
    timeout_reasons: Optional[Iterable[str]] = None,
) -> AdapterResult:
    """The records of one atom analysis: its reachables, usages and callsites
    slices and its OpenAPI documents.

    ``report`` holds the reachables slices paths, the input the reached sets
    are counted from; the other roles are optional. ``producer_version`` is
    the atom version the caller learned from its tool status, or the default
    ``"unknown"``. Every record's source is the file it was read from, named
    as it appears in the scan directory.

    A report that cannot be read whole returns a not-assessed result whose
    reason names the file and the problem; the same holds for the atom 2
    wrapped reachables shape, which the version gate refuses as an unknown
    major. The parse reports and timeout reasons the runner saw become
    caveats on every record and in the producer caveats.
    """
    reachables = [str(path) for path in report or []]
    usages = [str(path) for path in usages_files or []]
    callsites = [str(path) for path in callsites_files or []]
    openapi = [str(path) for path in openapi_files or []]
    if not (reachables or usages or callsites or openapi):
        return not_assessed("no atom report was given; the adapter has nothing to read")

    producer = EvidenceProducer(
        name=PRODUCER_NAME,
        version=producer_version or "unknown",
        report_schema_version="unknown",
    )
    # The caveats every record carries: the run-level markers, known before
    # any record is built.
    record_caveats = _parse_report_caveats(parse_reports or [])
    record_caveats.extend(_timeout_caveats(timeout_reasons or []))
    skipped: List[EvidenceCaveat] = []
    records: List[Evidence] = []
    seen: Set[str] = set()
    shape_version: Optional[str] = None

    for slice_file in reachables:
        name = _source_name(slice_file)
        role = "reachables slice"
        try:
            text = _read_text(slice_file, role)
            lead = _skip_space(text, 0)
            if lead >= len(text):
                return not_assessed(_damaged_reason(slice_file, role, "holds no JSON document"))
            decoder = json.JSONDecoder()
            if text[lead] == "{":
                return not_assessed(_object_shape_reason(decoder, text, lead, slice_file))
            if text[lead] != "[":
                return not_assessed(
                    _damaged_reason(
                        slice_file,
                        role,
                        f"is not a JSON array or object; it starts with {text[lead]!r}",
                    )
                )
            shape_version = str(SUPPORTED_MAJOR)
            non_flow_objects = 0
            for flow in _iter_array(text, lead, slice_file, role):
                if not isinstance(flow, dict):
                    non_flow_objects += 1
                    continue
                identity = _flow_identity(flow)
                if identity in seen:
                    continue
                seen.add(identity)
                records.append(_flow_record(flow, name, producer, record_caveats))
        except _Damaged as exc:
            return not_assessed(str(exc))
        if non_flow_objects:
            skipped.append(
                EvidenceCaveat(
                    kind="record-skipped",
                    detail=(
                        f"the atom {role} {name} holds {non_flow_objects} array element(s) that "
                        "are not flow objects; they became no record"
                    ),
                )
            )

    producer.report_schema_version = shape_version or "unknown"
    gate: VersionGate = gate_report_version(shape_version or "", SUPPORTED_MAJOR, KNOWN_MINOR)
    for caveat in gate.caveats:
        for record in records:
            add_caveat(record, caveat.kind, caveat.detail)
        record_caveats.append(caveat)

    try:
        for usages_file in usages:
            name = _source_name(usages_file)
            entries = _object_entries(usages_file, "usages slice", "objectSlices")
            non_entries = 0
            for entry in entries:
                if not isinstance(entry, dict):
                    non_entries += 1
                    continue
                records.append(_usage_record(entry, name, producer, record_caveats))
            if non_entries:
                skipped.append(
                    EvidenceCaveat(
                        kind="record-skipped",
                        detail=(
                            f"the atom usages slice {name} holds {non_entries} objectSlices "
                            "element(s) that are not objects; they became no record"
                        ),
                    )
                )
        for callsites_file in callsites:
            name = _source_name(callsites_file)
            entries = _object_entries(callsites_file, "callsites slice", "callsites")
            non_entries = 0
            for entry in entries:
                if not isinstance(entry, dict):
                    non_entries += 1
                    continue
                records.append(_callsite_record(entry, name, producer, record_caveats))
            if non_entries:
                skipped.append(
                    EvidenceCaveat(
                        kind="record-skipped",
                        detail=(
                            f"the atom callsites slice {name} holds {non_entries} callsites "
                            "element(s) that are not objects; they became no record"
                        ),
                    )
                )
        for openapi_file in openapi:
            records.extend(_entry_point_records(openapi_file, producer, record_caveats, skipped))
    except _Damaged as exc:
        return not_assessed(str(exc))

    return AdapterResult(
        status=STATUS_COMPLETED,
        records=records,
        caveats=[*record_caveats, *skipped],
    )
