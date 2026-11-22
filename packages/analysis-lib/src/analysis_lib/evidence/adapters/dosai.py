"""The dosai evidence adapter.

dosai (the Dotnet Source and Assembly Inspector) writes PascalCase reports
that state reachability per package outright: a ``PackageReachability``
entry carries ``Purl``, ``Reachable``, ``ReachabilityKind`` and usually a
``Confidence``, the ``dataflows`` half carries the taint slices with their
node paths, and the transparency sections (``ExploitChains``,
``AttackSurface``, ``SanitizedFlows``, ``Services``, ``DeadCode``) carry
the exposure and barrier facts. Reports arrive as the combined envelope
dep-scan assembles (``{"Metadata", "methods", "dataflows"}``) or as one
standalone half (flat ``Nodes``/``Slices`` marks dataflows; ``CallGraph``/
``ApiEndpoints`` marks methods).

The sections this adapter reads become these records:

- ``Slices[]`` become ``reached-flow`` records carrying the witness node
  path (nodes from the dataflows ``Nodes`` and the methods
  ``CallGraph.Nodes``) and the slice annotation (the exploit chains that
  cover the slice, its exposure tier, the sanitized flows recorded beside
  it). A slice that names no package purl of its own attributes nothing.
- ``PackageReachability`` entries dosai calls reachable split by kind and
  confidence: ``DataFlowNode``, ``DataFlowEdge``, ``DataFlowSlice`` and
  ``CallGraphEdge`` count at Medium or High confidence,
  ``ExternalCallGraphNode`` counts at High confidence, and every other kind
  (``Dependency``, ``InternalCallGraphNode``) or any Low-confidence entry
  becomes a ``dependency`` record, which is evidence a later reader can
  weigh but never counts as reached. The record's ``confidence`` is the
  entry's own; when an entry states none, the kind's default decides the
  counting, the record carries ``confidenceSource: "kind-default"`` and
  names the default in the ``confidenceDefault`` attribute, and
  ``ExternalCallGraphNode`` and the data-flow kinds default to High. An
  entry dosai calls not reachable becomes a negative ``no-path`` record.
- ``ApiEndpoints`` and ``AttackSurface`` entry points become
  ``entry-point`` records with the exposure tier, the route and the trust
  zone of the owning service in their attributes. An API endpoint's
  subject is the first purl it lists that reconciles.
- ``ExploitChains`` become ``exploit-chain`` records whose subject purls
  are the covered slice's purls and whose attributes carry the entry
  point, exposure tier, hop count, route and slice id.
- ``SanitizedFlows`` become ``sanitizer`` records with negative polarity,
  and a sanitized flow that shares a node with a slice and sits on its
  path is listed in that slice record's ``sanitizersNearby``.
- ``DeadCode`` entries and the unreachable nodes of the methods
  ``Reachability`` list become ``dead-code`` records with negative
  polarity.
- ``Services`` become records that carry the service's trust zone: an
  inbound or bidirectional service is attack surface and becomes an
  ``entry-point`` record, an outbound one becomes a ``presence`` record.
  Services attribute no package, so neither moves the reached set.
- ``WeaknessCandidates`` become ``weakness`` records and
  ``DangerousApiReachability`` entries become ``dangerous-api`` records.
  Their subjects are the purls the entry names (``Purls``, ``Purl``),
  reconciled; every field dosai wrote is kept in the attributes as given;
  the location is the sink location, or the first location the evidence
  lists. Neither kind counts as reached evidence.

Attributes keep the producer's own statements under the names the report
uses or the settled evidence vocabulary uses: ``exposure``,
``exploitChainIds``, ``exploitChains``, ``trustZone``, ``route``,
``sanitizersNearby``, ``hopCount``, ``entryPointId``, ``kind``,
``servicePurls``, plus ``sliceId`` on slice and chain records and the
service identity fields on service records, so every transparency fact
the report states stays recoverable from the records. Nothing is
inferred, and a purl dosai did not give is never invented.

Two ``minimal-api`` caveats mark attribution dosai can get wrong. A
route-bearing entry point dosai tied to the ``cli`` or ``mcp`` tier carries
one. And in a report that has minimal-API routes (entry point ids of the
form ``ep:op:svc:minimal-api:...``), every exploit chain, slice and
reachable package entry tied to no entry point, or only to entry points
that are not routes, carries one: dosai 5.x ties minimal-API flows to the
program's command-line entry point or to none (dosai issue 140).

The purl reconciler matches NuGet purls to the BOM exactly or by
case-folded name, and keeps an unmatched NuGet purl (a versionless
framework assembly) as given. Purls of other ecosystems cannot be
attributed and the entry naming one is counted as skipped.

File paths are relative to the ``Metadata.InputPath`` dosai states, when
it is absolute, or to the caller's source root; a file in the NuGet cache
is spelled by its cache path, and any other absolute path is left out with
a ``location-outside-root`` caveat.

The report schema version gate reads major 5 (5.0 and 5.1) and checks
every version the report states, the top-level ``Metadata`` and each
half's own; one that names another major refuses the report as not
assessed, with the reason naming the version seen. A newer minor is
accepted with a ``schema-minor`` caveat and a report that names no version
with a ``schema-unknown`` one. A report that does not parse, that is not a
dosai report, or that holds a consumed section of the wrong shape is not
assessed with the reason, and never a clean result with zero findings. The
budget, timeout and truncation markers dosai reports through its
``Diagnostics`` lists and its ``EntryPointsTruncated`` flags become
``budget`` and ``timeout`` caveats on the affected records and in the
producer caveats; report objects that cannot become records are counted in
one ``record-skipped`` caveat per reason.
"""

import json
import os
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

from packageurl import PackageURL

from analysis_lib.evidence import (
    Evidence,
    EvidenceCaveat,
    EvidenceLocation,
    EvidencePathNode,
    EvidenceProducer,
    content_discriminator,
)
from analysis_lib.evidence.adapters import (
    AdapterResult,
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
    not_assessed,
)

#: The producer name every record of this adapter carries.
PRODUCER_NAME = "dosai"

#: The report schema major this adapter reads, and the newest minor of it
#: it knows. The dosai 5.0.0 release and dosai main both write 5.1.
SUPPORTED_MAJOR = 5
KNOWN_MINOR = 1

#: dosai names itself in ``Metadata.Tool``.
DOSAI_TOOL_NAME = "Dosai"

#: The raw report names a BOM directory search looks at, in the order the
#: search tries them: the fallback runner's artifacts under
#: ``analysis/dosai/``, the combined report cdxgen persists for a source
#: scan, and the cdxgen evinse name for the dataflows half.
REPORT_CANDIDATES = (
    os.path.join("analysis", "dosai", "dotnet-dataflows.json"),
    os.path.join("analysis", "dosai", "dotnet-methods.json"),
    "dotnet-semantics.slices.json",
    "csharp-data-flow.slices.json",
)

#: ReachabilityKind -> default Confidence when an entry states none. The
#: external call graph kind defaults to High: a node the call graph reaches
#: is call evidence. A kind not listed defaults to Low.
_KIND_TO_CONFIDENCE = {
    "DataFlowNode": "High",
    "DataFlowEdge": "High",
    "DataFlowSlice": "High",
    "CallGraphEdge": "High",
    "ExternalCallGraphNode": "High",
    "Dependency": "Low",
}

#: The confidence names the matrix knows, by their case-folded spelling.
_CONF_NAMES = {"low": "Low", "medium": "Medium", "high": "High"}

#: The kinds whose entries count at Medium or High confidence. The external
#: call graph kind counts only at High.
_MEDIUM_HIGH_KINDS = ("DataFlowNode", "DataFlowEdge", "DataFlowSlice", "CallGraphEdge")

#: Entry-point exposure classes dosai derives, most exposed first. A class
#: that is not listed ranks after every listed one.
EXPOSURE_ORDER = (
    "anonymous-http",
    "anonymous-rpc",
    "authenticated-http",
    "authenticated-rpc",
    "queue",
    "mcp",
    "cli",
)

#: dosai sink and source categories that map onto a service, so a slice or
#: reachability entry in one of them carries ``servicePurls``.
_CATEGORY_TO_SERVICE_TAG = {
    "sql": "sql",
    "sql-query": "sql",
    "sql-injection": "sql",
    "deserialization": "rpc",
    "command-execution": "rpc",
    "process-execution": "rpc",
    "filesystem": "storage",
    "file-write": "storage",
    "file-read": "storage",
    "network-request": "http",
    "network-connect": "http",
    "html-response": "web",
    "xss": "web",
    "redirect": "http",
    "crypto": "rpc",
    "http-request": "http",
    "http-parameter": "http",
}

#: The exposure tiers a route-bearing entry point must not be tied to: that
#: pairing is the minimal-API attribution dosai can get wrong.
_MINIMAL_API_TIERS = ("cli", "mcp")

#: Source-file extensions that count as evidence locations. Assembly paths
#: dosai also lists are not source evidence.
_SOURCE_EXT_RE = re.compile(r"\.(cs|vb|fs|fsx|fsi|r|rmd|qmd)$", re.IGNORECASE)

# The consumed sections of each report half, for shape validation and for
# the per-half caveats. ``Diagnostics`` is a list of strings, the rest hold
# objects.
_DATAFLOWS_LISTS = (
    "Slices",
    "PackageReachability",
    "ExploitChains",
    "AttackSurface",
    "EntryPoints",
    "SanitizedFlows",
    "WeaknessCandidates",
    "DangerousApiReachability",
    "Nodes",
    "Diagnostics",
)
_METHODS_LISTS = (
    "PackageReachability",
    "ApiEndpoints",
    "Services",
    "DeadCode",
    "Reachability",
    "EntryPoints",
    "Diagnostics",
)


# ---------------------------------------------------------------------------
# Purl reconciliation
# ---------------------------------------------------------------------------


def _normalize_nuget_key(purl: Optional[str]) -> Optional[str]:
    """The normalized alias key for a purl: ``type/namespace/name`` all
    lowercased, version, qualifiers and subpath dropped."""
    if not isinstance(purl, str) or not purl:
        return None
    try:
        obj = PackageURL.from_string(purl)
        return "/".join(
            [
                (obj.type or "").lower(),
                (obj.namespace or "").lower(),
                (obj.name or "").lower(),
            ]
        )
    except Exception:
        return purl.split("?")[0].split("#")[0].split("@")[0].lower()


def build_bom_purl_index(
    bom_components: Optional[Iterable[dict]],
    extra_components: Optional[Iterable[dict]] = None,
) -> Dict[str, str]:
    """The ``alias-key -> versioned-purl`` index a NuGet BOM reconciles
    against: for every NuGet component the exact versioned purl and the
    case-folded name key, so a versionless framework purl dosai reports
    matches the BOM's versioned spelling."""
    index: Dict[str, str] = {}
    for component in list(bom_components or []) + list(extra_components or []):
        if not isinstance(component, dict):
            continue
        purl = component.get("purl", "")
        if not isinstance(purl, str) or not purl.startswith("pkg:nuget/"):
            continue
        index.setdefault(purl, purl)
        key = _normalize_nuget_key(purl)
        if key and key not in index:
            index[key] = purl
    return index


def reconcile_purl(dosai_purl: Optional[str], bom_index: Dict[str, str]) -> Optional[str]:
    """Map a dosai purl onto a BOM versioned purl: exact match first, then
    the case-folded name. A NuGet purl the BOM does not name is kept as
    given (framework assemblies are legitimately absent from a restored
    BOM), and a purl of any other ecosystem cannot be attributed."""
    if not isinstance(dosai_purl, str) or not dosai_purl:
        return None
    if not dosai_purl.startswith("pkg:nuget/"):
        return None
    if dosai_purl in bom_index:
        return bom_index[dosai_purl]
    key = _normalize_nuget_key(dosai_purl)
    if key and key in bom_index:
        return bom_index[key]
    return dosai_purl


def reconcile_purls(dosai_purls: Iterable[Optional[str]], bom_index: Dict[str, str]) -> List[str]:
    """Reconcile and de-duplicate purls into a sorted list."""
    seen: set = set()
    out: List[str] = []
    for raw in dosai_purls or []:
        purl = reconcile_purl(raw, bom_index)
        if purl and purl not in seen:
            seen.add(purl)
            out.append(purl)
    return sorted(out)


# ---------------------------------------------------------------------------
# Report shape
# ---------------------------------------------------------------------------


def is_dosai_report(report: Any) -> bool:
    """Whether ``report`` has the structural shape of a dosai report: a
    dict whose ``Metadata.Tool`` is Dosai that carries the combined
    envelope or at least one consumed analysis section."""
    if not isinstance(report, dict):
        return False
    meta = report.get("Metadata")
    if not isinstance(meta, dict) or meta.get("Tool") != DOSAI_TOOL_NAME:
        return False
    if "dataflows" in report or "methods" in report:
        return True
    return any(k in report for k in ("Slices", "PackageReachability", "CallGraph", "ApiEndpoints"))


def _looks_like_dataflows(obj: Any) -> bool:
    if not isinstance(obj, dict):
        return False
    return any(k in obj for k in ("Slices", "DangerousApiReachability", "WeaknessCandidates")) or (
        "Nodes" in obj and "CallGraph" not in obj
    )


def _looks_like_methods(obj: Any) -> bool:
    if not isinstance(obj, dict):
        return False
    return any(k in obj for k in ("CallGraph", "ApiEndpoints", "Dependencies", "MethodCalls"))


def split_report(report: Any) -> Tuple[Optional[dict], Optional[dict]]:
    """Split a report into its ``(dataflows, methods)`` halves, either from
    the combined envelope or by classifying a standalone half by its keys."""
    if not isinstance(report, dict):
        return None, None
    if "dataflows" in report or "methods" in report:
        dataflows = report.get("dataflows")
        methods = report.get("methods")
        return (
            dataflows if isinstance(dataflows, dict) else None,
            methods if isinstance(methods, dict) else None,
        )
    if _looks_like_dataflows(report):
        return report, None
    if _looks_like_methods(report):
        return None, report
    return None, None


def combine_reports(dataflows: Optional[dict], methods: Optional[dict]) -> Optional[dict]:
    """The combined envelope from the two standalone halves, the way the
    scan assembles it: the dataflows metadata is the richer one and wins."""
    if not isinstance(dataflows, dict) and not isinstance(methods, dict):
        return None
    meta = (
        (dataflows or {}).get("Metadata")
        or (methods or {}).get("Metadata")
        or {"Tool": DOSAI_TOOL_NAME}
    )
    return {
        "Metadata": meta,
        "methods": methods or {},
        "dataflows": dataflows or {},
    }


# ---------------------------------------------------------------------------
# Small shared helpers
# ---------------------------------------------------------------------------


def _most_exposed(exposures: Iterable[Any]) -> Optional[str]:
    """The most exposed class among ``exposures``, or ``None`` when none."""
    found = [e for e in exposures if isinstance(e, str) and e]
    if not found:
        return None
    return min(
        found,
        key=lambda e: EXPOSURE_ORDER.index(e) if e in EXPOSURE_ORDER else len(EXPOSURE_ORDER),
    )


def _route_key(method: Any, route: Any) -> Tuple[str, str]:
    """The key a route is matched on. ``ApiEndpoints[].Route`` omits the
    leading slash that ``Path`` and the attack surface rows carry."""
    path = as_str(route).strip()
    if path and not path.startswith("/"):
        path = "/" + path
    return (as_str(method).upper(), path)


def _line_key(file_name: Any, line: Any) -> Tuple[str, int]:
    """Case-insensitive base name plus line, the way a sanitizer location is
    compared with a data-flow node location."""
    base = as_str(file_name).replace("\\", "/").rsplit("/", 1)[-1].lower()
    return (base, as_line(line) or 0)


def _parent_method(entry: Dict[str, Any]) -> str:
    """A ``ClassName.MethodName`` parent-method string."""
    cls = as_str(entry.get("ClassName")) or as_str(entry.get("Namespace"))
    method = as_str(entry.get("MethodName")) or as_str(entry.get("Name"))
    if cls and method:
        return f"{cls}.{method}"
    return method or cls


def _is_source_file(path: Any) -> bool:
    return isinstance(path, str) and bool(path) and bool(_SOURCE_EXT_RE.search(path))


def _ids(value: Any) -> List[str]:
    """The string ids of a producer id list; anything else in it is no id."""
    return [item for item in as_list(value) if isinstance(item, str) and item]


def _is_minimal_api_entry(entry_id: Any, kind: Any) -> bool:
    """Whether an entry point is a minimal-API route: dosai spells their ids
    ``ep:op:svc:minimal-api:...``, and a kind naming minimal APIs says the
    same."""
    if isinstance(entry_id, str) and "minimal-api" in entry_id.lower():
        return True
    folded = as_str(kind).lower().replace("-", "").replace("_", "").replace(" ", "")
    return "minimalapi" in folded


class _Where:
    """Builds one record's locations and witness nodes through the report's
    :class:`SourcePaths`, counting the files left out so the record can say
    so."""

    def __init__(self, paths: SourcePaths) -> None:
        self.paths = paths
        self.left_out: set = set()

    def file(self, value: Any) -> Optional[str]:
        if not isinstance(value, str) or not value:
            return None
        relative = self.paths.relative(value)
        if relative is None:
            self.left_out.add(value)
        return relative

    def location(
        self, file_name: Any, line: Any, method: Any = None
    ) -> Optional[EvidenceLocation]:
        """A location for a producer file name and line, or ``None`` when the
        entry names no file the record can carry."""
        file_value = self.file(file_name)
        if not file_value:
            return None
        return EvidenceLocation(file=file_value, line=as_line(line), method=as_str(method) or None)

    def caveats(self, *groups: Iterable[EvidenceCaveat]) -> Tuple[EvidenceCaveat, ...]:
        out: List[EvidenceCaveat] = []
        for group in groups:
            for caveat in group:
                if caveat not in out:
                    out.append(caveat)
        if self.left_out:
            out.append(self.paths.outside_root_caveat(len(self.left_out)))
        return tuple(out)


def _source_locations(entry: Dict[str, Any], where: _Where) -> List[EvidenceLocation]:
    """The source-file locations of a ``PackageReachability`` entry, in the
    order dosai lists them. dosai names the file ``Path`` or ``FileName``
    and the line ``LineNumber``; ``File`` and ``Line`` are read as well."""
    out: List[EvidenceLocation] = []
    for location in as_list(entry.get("SourceLocations")):
        if not isinstance(location, dict):
            continue
        path = location.get("Path") or location.get("FileName") or location.get("File")
        if not _is_source_file(path):
            continue
        line = location.get("LineNumber")
        if line is None:
            line = location.get("Line")
        location_obj = where.location(path, line)
        if location_obj:
            out.append(location_obj)
    return out


def _confidence_of(entry: Dict[str, Any]) -> Tuple[str, Any, Optional[str]]:
    """The entry's reachability kind, the confidence it states as given, and
    the confidence the counting decision uses.

    A stated ``Low``, ``Medium`` or ``High`` (in any letter case) is used as
    stated. An entry that states none falls back to its kind's default. A
    stated value that is none of those three is no confidence the matrix
    knows, and the entry does not count.
    """
    kind = as_str(entry.get("ReachabilityKind")) or "Dependency"
    given = entry.get("Confidence")
    if given is None or given == "":
        return kind, None, _KIND_TO_CONFIDENCE.get(kind, "Low")
    if isinstance(given, str) and given.strip().lower() in _CONF_NAMES:
        return kind, given, _CONF_NAMES[given.strip().lower()]
    return kind, given, None


def _counts_as_reached(kind: str, confidence: Optional[str]) -> bool:
    """The reachability matrix: data-flow and call-graph edge entries count
    at Medium or High, external call graph entries count only at High, and
    everything else (the Dependency kind, the internal call graph kind, an
    unknown kind, every Low entry and every entry whose confidence is not a
    known one) is recorded without counting."""
    if confidence is None or confidence == "Low":
        return False
    if kind in _MEDIUM_HIGH_KINDS:
        return True
    if kind == "ExternalCallGraphNode":
        return confidence == "High"
    return False


# ---------------------------------------------------------------------------
# Transparency lookups
# ---------------------------------------------------------------------------


class _Transparency:
    """The lookup tables built once from a report's transparency sections.

    ``ExploitChains``, ``AttackSurface`` and ``SanitizedFlows`` come from
    the dataflows half, ``Services`` with their trust zones from the
    methods half, and the node index from both halves' nodes. Any section
    may be absent; every table is then empty and the records carry no
    annotation from it.
    """

    def __init__(
        self,
        dataflows: dict,
        methods: dict,
        bom_index: Dict[str, str],
        skipped: SkipTally,
    ):
        self.bom_index = bom_index
        self.chains: List[dict] = []
        for chain in as_list(dataflows.get("ExploitChains")):
            if isinstance(chain, dict):
                self.chains.append(chain)
            else:
                skipped.add("ExploitChains entries are not JSON objects and became no record")
        self.sanitized_flows: List[dict] = []
        for flow in as_list(dataflows.get("SanitizedFlows")):
            if isinstance(flow, dict):
                self.sanitized_flows.append(flow)
            else:
                skipped.add("SanitizedFlows entries are not JSON objects and became no record")
        self.attack_surface: List[dict] = []
        for group in as_list(dataflows.get("AttackSurface")):
            if isinstance(group, dict):
                self.attack_surface.append(group)
            else:
                skipped.add("AttackSurface entries are not JSON objects and became no record")
        self.services: List[dict] = []
        for service in as_list(methods.get("Services")):
            if isinstance(service, dict):
                self.services.append(service)
            else:
                skipped.add("Services entries are not JSON objects and became no record")
        # The node index: the methods call graph's nodes and the dataflows
        # nodes, the dataflows node winning where both name one id.
        self.nodes: Dict[str, dict] = {}
        for node in as_list(as_dict(methods.get("CallGraph")).get("Nodes")) + as_list(
            dataflows.get("Nodes")
        ):
            if isinstance(node, dict) and as_hashable_str(node.get("Id")):
                self.nodes[node["Id"]] = node
        self.entry_exposure: Dict[str, str] = {}
        self.route_exposure: Dict[Tuple[str, str], str] = {}
        self.route_by_entry: Dict[str, str] = {}
        # Entry points that are routes (a route-bearing entry, a minimal-API
        # id), and whether the report has minimal-API routes at all.
        self.route_entries: set = set()
        self.has_minimal_api = False
        for group in self.attack_surface:
            group_exposure = group.get("Exposure")
            for entry in as_list(group.get("EntryPoints")):
                if not isinstance(entry, dict):
                    continue
                entry_id = as_hashable_str(entry.get("EntryPointId"))
                self._note_entry(entry_id, entry.get("Kind"), entry.get("Route"))
                exposure = as_hashable_str(entry.get("Exposure")) or as_hashable_str(
                    group_exposure
                )
                if not exposure:
                    continue
                if entry_id:
                    self.entry_exposure[entry_id] = exposure
                route = as_hashable_str(entry.get("Route"))
                if route:
                    key = _route_key(entry.get("HttpMethod"), route)
                    self.route_exposure[key] = (
                        _most_exposed([exposure, self.route_exposure.get(key)]) or exposure
                    )
                    if entry_id:
                        self.route_by_entry.setdefault(entry_id, route)
        for half in (dataflows, methods):
            for entry in as_list(half.get("EntryPoints")):
                if not isinstance(entry, dict):
                    continue
                entry_id = as_hashable_str(entry.get("Id"))
                route = as_hashable_str(entry.get("Route"))
                self._note_entry(entry_id, entry.get("Kind"), route)
                if entry_id and route:
                    self.route_by_entry.setdefault(entry_id, route)
        self.chains_by_slice: Dict[str, List[dict]] = {}
        for chain in self.chains:
            exposure = as_hashable_str(chain.get("Exposure"))
            entry_id = as_hashable_str(chain.get("EntryPointId"))
            if exposure and entry_id:
                self.entry_exposure.setdefault(entry_id, exposure)
            slice_id = as_hashable_str(chain.get("SliceId"))
            if slice_id:
                self.chains_by_slice.setdefault(slice_id, []).append(chain)
        self.trust_zone_by_route: Dict[Tuple[str, str], dict] = {}
        for service in self.services:
            zone = service.get("TrustZone")
            if not zone:
                continue
            for operation in as_list(service.get("Operations")):
                if not isinstance(operation, dict):
                    continue
                path = (
                    as_str(operation.get("Path"))
                    or as_str(operation.get("RouteTemplate"))
                    or as_str(operation.get("Name"))
                )
                if path:
                    self.trust_zone_by_route[_route_key(operation.get("HttpMethod"), path)] = {
                        "trustZone": zone,
                        "serviceId": service.get("Id"),
                    }
        self.slice_purls: Dict[str, List[str]] = {}
        for sl in as_list(dataflows.get("Slices")):
            slice_id = as_hashable_str(sl.get("Id")) if isinstance(sl, dict) else None
            if slice_id:
                own = self.own_slice_purls(sl)
                self.slice_purls[slice_id] = (
                    reconcile_purls(own + self.node_purls(sl), bom_index) if own else []
                )
        self.sanitizers_nearby: Dict[str, List[dict]] = self._match_sanitizers(dataflows)

    def _note_entry(self, entry_id: Optional[str], kind: Any, route: Any) -> None:
        minimal = _is_minimal_api_entry(entry_id, kind)
        if minimal:
            self.has_minimal_api = True
        if entry_id and (minimal or as_hashable_str(route)):
            self.route_entries.add(entry_id)

    def own_slice_purls(self, sl: dict) -> List[Optional[str]]:
        """The purls a slice names itself: ``Purls``, ``SinkPurl`` and
        ``SourcePurl``, reconciled. A slice that names none attributes
        nothing, whatever its nodes carry."""
        raw = list(as_list(sl.get("Purls"))) + [sl.get("SinkPurl"), sl.get("SourcePurl")]
        return [p for p in raw if reconcile_purl(p, self.bom_index)]

    def node_purls(self, sl: dict) -> List[Optional[str]]:
        return [
            self.nodes[nid].get("Purl")
            for nid in _ids(sl.get("NodeIds"))
            if isinstance(self.nodes.get(nid), dict)
        ]

    def _match_sanitizers(self, dataflows: dict) -> Dict[str, List[dict]]:
        """Map a slice id to the sanitized flows recorded beside it: a flow
        is near a slice when the two share a source node and the sanitizer
        sits on the slice's path (same file and line as one of its nodes).
        Matching only annotates; dosai emits no slice for a trace it
        sanitized, so a present slice was never stopped."""
        if not self.sanitized_flows:
            return {}
        matched: Dict[str, List[dict]] = {}
        for sl in as_list(dataflows.get("Slices")):
            slice_id = as_hashable_str(sl.get("Id")) if isinstance(sl, dict) else None
            if not slice_id:
                continue
            node_ids = _ids(sl.get("NodeIds"))
            node_set = set(node_ids)
            node_locations = {
                _line_key(
                    self.nodes[nid].get("Path") or self.nodes[nid].get("FileName"),
                    self.nodes[nid].get("LineNumber"),
                )
                for nid in node_ids
                if nid in self.nodes
            }
            for flow in self.sanitized_flows:
                flow_id = as_hashable_str(flow.get("Id"))
                if not flow_id:
                    continue
                if not node_set.intersection(_ids(flow.get("SourceIds"))):
                    continue
                if _line_key(flow.get("FileName"), flow.get("LineNumber")) not in node_locations:
                    continue
                matched.setdefault(slice_id, []).append(
                    {
                        "id": flow_id,
                        "category": flow.get("SanitizerCategory") or flow.get("SanitizerSymbol"),
                    }
                )
        return matched

    def slice_annotation(self, sl: dict) -> Optional[dict]:
        """The transparency attributes of one slice, or ``None`` when the
        report carries none for it."""
        slice_id = as_hashable_str(sl.get("Id"))
        chains = self.chains_by_slice.get(slice_id, []) if slice_id else []
        nearby = self.sanitizers_nearby.get(slice_id, []) if slice_id else []
        if not chains and not nearby:
            return None
        annotation: dict = {
            "sliceId": slice_id,
            "exposure": _most_exposed(c.get("Exposure") for c in chains),
            "exploitChains": [self.compact_chain(c) for c in chains],
        }
        if nearby:
            annotation["sanitizersNearby"] = sorted(nearby, key=lambda n: str(n["id"]))
        return annotation

    def compact_chain(self, chain: dict) -> dict:
        """The chain facts a later reader needs, with the entry point's
        route resolved when the report names one."""
        compact = {
            "id": chain.get("Id"),
            "entryPointId": chain.get("EntryPointId"),
            "exposure": chain.get("Exposure"),
            "hopCount": chain.get("HopCount", 0),
            "confidence": chain.get("Confidence"),
        }
        entry_id = as_hashable_str(chain.get("EntryPointId"))
        route = self.route_by_entry.get(entry_id) if entry_id else None
        if route:
            compact["route"] = route
        return compact

    def package_annotation(self, pr: dict) -> Optional[dict]:
        """The exposure and chain ids of the entry points and exploit chains
        that reach a package, or ``None`` when the report names none."""
        exposures: List[Any] = [self.entry_exposure.get(e) for e in _ids(pr.get("EntryPointIds"))]
        chain_ids: List[str] = []
        for slice_id in _ids(pr.get("SliceIds")):
            for chain in self.chains_by_slice.get(slice_id, []):
                exposures.append(chain.get("Exposure"))
                chain_id = as_hashable_str(chain.get("Id"))
                if chain_id and chain_id not in chain_ids:
                    chain_ids.append(chain_id)
        exposure = _most_exposed(exposures)
        if not exposure and not chain_ids:
            return None
        return {"exposure": exposure, "exploitChainIds": sorted(chain_ids)}

    def endpoint_zone(self, method: Any, route: Any) -> dict:
        """The exposure tier and the owning service's trust zone of a
        route, as far as the report states them."""
        key = _route_key(method, route)
        annotation: dict = {}
        if key in self.route_exposure:
            annotation["exposure"] = self.route_exposure[key]
        zone = self.trust_zone_by_route.get(key)
        if zone:
            annotation.update(zone)
        return annotation

    # --- the minimal-API attribution caveat --------------------------------

    def minimal_api_caveat(self, what: str, entry_ids: List[str]) -> Optional[EvidenceCaveat]:
        """The ``minimal-api`` caveat for a record tied to ``entry_ids``, or
        ``None``. It applies only in a report that has minimal-API routes,
        to a record tied to no entry point or to entry points none of which
        is a route: that is the attribution dosai gets wrong for minimal-API
        flows, which it ties to the program's command-line entry point or
        to no entry point at all."""
        if not self.has_minimal_api:
            return None
        if any(entry_id in self.route_entries for entry_id in entry_ids):
            return None
        tied = (
            "to the entry point(s) " + ", ".join(entry_ids) + ", none of which is a route"
            if entry_ids
            else "to no entry point"
        )
        return EvidenceCaveat(
            kind="minimal-api",
            detail=(
                f"the report has minimal-API routes and dosai tied {what} {tied}; dosai can "
                "attribute minimal-API flows to the wrong entry point (dosai issue 140)"
            ),
        )

    def slice_entry_ids(self, slice_id: Optional[str]) -> List[str]:
        if not slice_id:
            return []
        out: List[str] = []
        for chain in self.chains_by_slice.get(slice_id, []):
            entry_id = as_hashable_str(chain.get("EntryPointId"))
            if entry_id and entry_id not in out:
                out.append(entry_id)
        return out


# ---------------------------------------------------------------------------
# Caveat collection
# ---------------------------------------------------------------------------

_BUDGET_RE = re.compile(r"budget|truncat", re.IGNORECASE)
_TIMEOUT_RE = re.compile(r"timed out|timeout", re.IGNORECASE)


def _diagnostic_caveats(lines: Iterable[Any]) -> List[EvidenceCaveat]:
    """The budget and timeout caveats dosai reports through its
    ``Diagnostics`` lists, in list order."""
    caveats: List[EvidenceCaveat] = []
    for line in lines or []:
        if not isinstance(line, str):
            continue
        if _BUDGET_RE.search(line):
            caveats.append(EvidenceCaveat(kind="budget", detail=line))
        elif _TIMEOUT_RE.search(line):
            caveats.append(EvidenceCaveat(kind="timeout", detail=line))
    return caveats


def _section_lists(section: dict, names: Tuple[str, ...], half: str) -> Optional[str]:
    """The name of the first consumed section of the wrong shape, or
    ``None`` when every present section has the shape dosai writes. A
    ``null`` section reads as absent."""
    for name in names:
        value = section.get(name)
        if value is not None and not isinstance(value, list):
            return f"the {half} section's {name} is {type(value).__name__}, expected a list"
    call_graph = section.get("CallGraph")
    if call_graph is not None:
        if not isinstance(call_graph, dict):
            return (
                f"the {half} section's CallGraph is {type(call_graph).__name__}, "
                "expected an object"
            )
        nodes = call_graph.get("Nodes")
        if nodes is not None and not isinstance(nodes, list):
            return (
                f"the {half} section's CallGraph.Nodes is {type(nodes).__name__}, expected a list"
            )
    return None


def _gate_versions(
    parsed: dict, dataflows: dict, methods: dict
) -> Tuple[Optional[str], List[EvidenceCaveat], str]:
    """Gate every schema version the report states: the top-level
    ``Metadata`` and each half's own. Returns the refusal reason (``None``
    when every version is readable), the gate caveats, and the version the
    producer block names (the first one stated, else ``unknown``)."""
    stated: List[Tuple[str, Any]] = []
    for label, holder in (("report", parsed), ("dataflows", dataflows), ("methods", methods)):
        meta = holder.get("Metadata")
        if isinstance(meta, dict) and meta.get("SchemaVersion") not in (None, ""):
            stated.append((label, meta["SchemaVersion"]))
    caveats: List[EvidenceCaveat] = []
    if not stated:
        gate = gate_report_version(None, SUPPORTED_MAJOR, KNOWN_MINOR)
        return None, list(gate.caveats), "unknown"
    for label, version in stated:
        gate = gate_report_version(version, SUPPORTED_MAJOR, KNOWN_MINOR)
        if not gate.accepted:
            where = "the report metadata" if label == "report" else f"the {label} metadata"
            return f"{where}: {gate.reason}", [], "unknown"
        for caveat in gate.caveats:
            if caveat not in caveats:
                caveats.append(caveat)
    return None, caveats, str(stated[0][1])


def _source_paths(
    parsed: dict, dataflows: dict, methods: dict, source_root: Optional[str]
) -> SourcePaths:
    """The path mapping of one dosai report: the ``InputPath`` each
    ``Metadata`` block states, when it is absolute, and the caller's source
    root. dosai already writes most locations relative to the input."""
    roots: List[Any] = [source_root]
    for holder in (parsed, dataflows, methods):
        meta = as_dict(holder.get("Metadata"))
        roots.append(meta.get("InputPath"))
        roots.append(meta.get("InputFullPath"))
    return SourcePaths(roots)


# ---------------------------------------------------------------------------
# Record builders
# ---------------------------------------------------------------------------


class _Context:
    """What every record builder of one report shares."""

    def __init__(
        self,
        source: str,
        producer: EvidenceProducer,
        transparency: _Transparency,
        paths: SourcePaths,
        side_caveats: Dict[str, List[EvidenceCaveat]],
        skipped: SkipTally,
    ) -> None:
        self.source = source
        self.producer = producer
        self.transparency = transparency
        self.paths = paths
        self.side_caveats = side_caveats
        self.skipped = skipped

    def discriminator(self, obj: Any, own_id: Any = None, *extra: Any) -> str:
        """The producer's own id when the object has one (dosai numbers its
        objects per report, independent of any path), else the content hash
        of the object with the roots spelled the same wherever the report
        was produced."""
        key = as_hashable_str(own_id)
        if key:
            return ":".join([key, *(str(e) for e in extra)]) if extra else key
        return content_discriminator([self.paths.neutral(obj), *extra])


def _slice_record(sl: dict, ctx: _Context) -> Optional[Evidence]:
    """The reached-flow record of one data-flow slice, with the witness
    node path and the slice annotation. A slice that names no package purl
    of its own, or walks no node, attributes nothing and is counted as
    skipped."""
    transparency = ctx.transparency
    own = transparency.own_slice_purls(sl)
    if not own:
        ctx.skipped.add("data-flow slices name no package purl of their own and became no record")
        return None
    node_ids = _ids(sl.get("NodeIds"))
    if not node_ids:
        ctx.skipped.add("data-flow slices walk no node and became no record")
        return None
    purls = reconcile_purls(own + transparency.node_purls(sl), transparency.bom_index)
    where = _Where(ctx.paths)
    path: List[EvidencePathNode] = []
    locations: List[EvidenceLocation] = []
    for nid in node_ids:
        node = transparency.nodes.get(nid)
        if not isinstance(node, dict):
            continue
        file_value = node.get("Path") or node.get("FileName")
        method = _parent_method(node) or None
        location = where.location(file_value, node.get("LineNumber"), method)
        path.append(
            EvidencePathNode(
                file=location.file if location else None,
                line=as_line(node.get("LineNumber")),
                method=method,
                symbol=as_str(node.get("Symbol")) or as_str(node.get("Name")) or None,
            )
        )
        if location:
            locations.append(location)
    attributes: dict = {}
    annotation = transparency.slice_annotation(sl)
    if annotation:
        attributes.update(annotation)
    category = as_str(sl.get("SinkCategory"))
    if category in _CATEGORY_TO_SERVICE_TAG:
        service_purls = reconcile_purls(
            list(as_list(sl.get("Purls"))) + [sl.get("SinkPurl")], transparency.bom_index
        )
        if service_purls:
            attributes["servicePurls"] = service_purls
    slice_id = as_hashable_str(sl.get("Id"))
    minimal = transparency.minimal_api_caveat(
        f"the data-flow slice {slice_id or 'without an id'}",
        transparency.slice_entry_ids(slice_id),
    )
    confidence = sl.get("Confidence")
    return build_record(
        source=ctx.source,
        producer=ctx.producer,
        kind="reached-flow",
        discriminator=ctx.discriminator(sl, slice_id),
        purls=tuple(purls),
        locations=tuple(locations),
        path=tuple(path),
        confidence=confidence if isinstance(confidence, str) and confidence else None,
        attributes=attributes or None,
        caveats=where.caveats(ctx.side_caveats["dataflows"], [minimal] if minimal else []),
    )


def _package_reachability_record(pr: dict, half: str, ctx: _Context) -> Optional[Evidence]:
    """The record of one ``PackageReachability`` entry.

    An entry dosai calls reachable becomes a reached-flow or a dependency
    record per the reachability matrix; an entry dosai calls not reachable
    becomes a negative ``no-path`` record; an entry with neither verdict,
    or whose purl cannot be attributed, is counted as skipped. The record's
    confidence is the one the entry states, exactly as stated; when the
    entry states none, the kind's default only decides the counting, and the
    record carries ``confidenceSource: "kind-default"`` with the default in
    the ``confidenceDefault`` attribute.
    """
    transparency = ctx.transparency
    verdict = pr.get("Reachable")
    if verdict is not True and verdict is not False:
        ctx.skipped.add(
            "PackageReachability entries state no Reachable verdict and became no record"
        )
        return None
    raw_purl = pr.get("Purl")
    purl = reconcile_purl(raw_purl, transparency.bom_index)
    if not purl:
        if isinstance(raw_purl, str) and raw_purl:
            ctx.skipped.add(
                "PackageReachability entries name a purl outside NuGet, which this adapter "
                "cannot attribute, and became no record"
            )
        else:
            ctx.skipped.add(
                "PackageReachability entries name no package purl and became no record"
            )
        return None
    kind, given, effective = _confidence_of(pr)
    counted = verdict is True and _counts_as_reached(kind, effective)
    attributes: dict = {"kind": kind}
    if given is None:
        attributes["confidenceSource"] = "kind-default"
        attributes["confidenceDefault"] = effective
    elif not isinstance(given, str):
        attributes["confidenceGiven"] = given
    annotation = transparency.package_annotation(pr)
    if annotation:
        attributes.update(annotation)
    category = next((c for c in as_list(pr.get("Categories")) if isinstance(c, str)), "")
    if counted and category in _CATEGORY_TO_SERVICE_TAG:
        attributes["servicePurls"] = [purl]
    where = _Where(ctx.paths)
    locations = _source_locations(pr, where)
    if verdict is False:
        record_kind, polarity, extra = "no-path", "negative", []
    else:
        record_kind = "reached-flow" if counted else "dependency"
        polarity = "positive"
        minimal = transparency.minimal_api_caveat(
            f"the package reachability of {purl}", _ids(pr.get("EntryPointIds"))
        )
        extra = [minimal] if minimal else []
    return build_record(
        source=ctx.source,
        producer=ctx.producer,
        kind=record_kind,
        polarity=polarity,
        # The same entry can appear in both halves; the half keeps them apart
        # so the caveats each half carries stay on its own record.
        discriminator=ctx.discriminator(pr, None, half),
        purls=(purl,),
        locations=tuple(locations),
        confidence=given if isinstance(given, str) else None,
        attributes=attributes,
        caveats=where.caveats(ctx.side_caveats[half], extra),
    )


def _endpoint_attributes(
    entry: dict, transparency: _Transparency
) -> Tuple[dict, List[EvidenceCaveat]]:
    """The shared entry-point attributes of an API endpoint or attack
    surface entry, plus the minimal-API caveat when dosai tied a
    route-bearing entry to a cli or mcp tier."""
    attributes: dict = {}
    caveats: List[EvidenceCaveat] = []
    entry_id = entry.get("EntryPointId") or entry.get("OperationId")
    if entry_id:
        attributes["entryPointId"] = entry_id
    kind = entry.get("Kind") or entry.get("EndpointKind")
    if kind:
        attributes["kind"] = kind
    route = entry.get("Route") or entry.get("Path")
    if route:
        attributes["route"] = route
    attributes.update(transparency.endpoint_zone(entry.get("HttpMethod"), route))
    exposure = entry.get("Exposure") or attributes.get("exposure")
    if exposure:
        attributes["exposure"] = exposure
    if route and exposure in _MINIMAL_API_TIERS:
        caveats.append(
            EvidenceCaveat(
                kind="minimal-api",
                detail=(
                    f"the entry point {entry_id or route} carries the route {route} but dosai"
                    f" tied it to the {exposure} tier, the minimal-API attribution dosai can"
                    " get wrong"
                ),
            )
        )
    return attributes, caveats


def _api_endpoint_record(entry: dict, ctx: _Context) -> Optional[Evidence]:
    """The entry-point record of one ``ApiEndpoints`` entry. Its subject is
    the first purl the entry lists that reconciles, the package serving the
    route; every purl the entry lists is kept as given in the ``purls``
    attribute. An entry that names no route cannot be an entry point and is
    counted as skipped."""
    route = entry.get("Route") or entry.get("Path")
    if not route:
        ctx.skipped.add("ApiEndpoints entries name no route and became no record")
        return None
    attributes, extra_caveats = _endpoint_attributes(entry, ctx.transparency)
    listed = as_list(entry.get("Purls"))
    handler_purl = next(
        (p for p in (reconcile_purl(raw, ctx.transparency.bom_index) for raw in listed) if p),
        None,
    )
    if len(listed) > 1:
        attributes["purls"] = listed
    where = _Where(ctx.paths)
    location = where.location(
        entry.get("FilePath") or entry.get("FileName"),
        entry.get("LineNumber"),
        _parent_method(entry),
    )
    return build_record(
        source=ctx.source,
        producer=ctx.producer,
        kind="entry-point",
        discriminator=ctx.discriminator(entry, entry.get("OperationId")),
        purls=(handler_purl,) if handler_purl else (),
        locations=tuple([location] if location else []),
        attributes=attributes or None,
        caveats=where.caveats(ctx.side_caveats["methods"], extra_caveats),
    )


def _attack_surface_record(entry: dict, caveats: List[EvidenceCaveat], ctx: _Context) -> Evidence:
    """The entry-point record of one ``AttackSurface`` entry, carrying the
    exposure tier of the group or the entry and the trust zone of the
    service that owns the route."""
    attributes, extra_caveats = _endpoint_attributes(entry, ctx.transparency)
    where = _Where(ctx.paths)
    location = where.location(entry.get("FileName"), entry.get("LineNumber"))
    return build_record(
        source=ctx.source,
        producer=ctx.producer,
        kind="entry-point",
        discriminator=ctx.discriminator(entry, entry.get("EntryPointId")),
        locations=tuple([location] if location else []),
        attributes=attributes or None,
        caveats=where.caveats(caveats, extra_caveats),
    )


def _exploit_chain_record(chain: dict, ctx: _Context) -> Evidence:
    """The exploit-chain record of one ``ExploitChains`` entry: the covered
    slice's purls as the subject, the chain's own id, entry point, exposure
    tier, hop count, route and slice id as attributes. The chain id is what
    the reachability entries' ``exploitChainIds`` reference, so it stays a
    readable value and not only the record id's hash input."""
    transparency = ctx.transparency
    attributes: dict = {}
    for key, field in (
        ("id", "Id"),
        ("entryPointId", "EntryPointId"),
        ("exposure", "Exposure"),
        ("hopCount", "HopCount"),
        ("sliceId", "SliceId"),
    ):
        value = chain.get(field)
        if value is not None:
            attributes[key] = value
    entry_id = as_hashable_str(chain.get("EntryPointId"))
    route = transparency.route_by_entry.get(entry_id) if entry_id else None
    if route:
        attributes["route"] = route
    slice_id = as_hashable_str(chain.get("SliceId"))
    purls = transparency.slice_purls.get(slice_id, []) if slice_id else []
    chain_id = as_hashable_str(chain.get("Id"))
    minimal = transparency.minimal_api_caveat(
        f"the exploit chain {chain_id or 'without an id'}", [entry_id] if entry_id else []
    )
    confidence = chain.get("Confidence")
    return build_record(
        source=ctx.source,
        producer=ctx.producer,
        kind="exploit-chain",
        discriminator=ctx.discriminator(chain, chain_id),
        purls=tuple(purls),
        confidence=confidence if isinstance(confidence, str) and confidence else None,
        attributes=attributes or None,
        caveats=_Where(ctx.paths).caveats(
            ctx.side_caveats["dataflows"], [minimal] if minimal else []
        ),
    )


#: A dosai location string, ``<file>:<line>[:<column>]``.
_LOCATION_TEXT_RE = re.compile(r"^(?P<file>.+?):(?P<line>\d+)(?::\d+)?$")


def _text_location(where: "_Where", values: Iterable[Any]) -> Optional[EvidenceLocation]:
    """The first ``<file>:<line>[:<column>]`` string among ``values`` that
    names a source file, as a location."""
    for value in values:
        if not isinstance(value, str):
            continue
        match = _LOCATION_TEXT_RE.match(value.strip())
        if match and _is_source_file(match.group("file")):
            return where.location(match.group("file"), match.group("line"))
    return None


def _weakness_record(entry: dict, ctx: _Context) -> Evidence:
    """The weakness record of one ``WeaknessCandidates`` entry: the purls
    the entry names as the subject, its confidence as stated, every field
    kept as given, and the sink location (else the source location) as the
    record's location. A weakness tied to an entry point that is not a
    route, in a report with minimal-API routes, carries the minimal-API
    caveat like the chain it comes from."""
    transparency = ctx.transparency
    purls = reconcile_purls(as_list(entry.get("Purls")), transparency.bom_index)
    where = _Where(ctx.paths)
    location = _text_location(where, (entry.get("SinkLocation"), entry.get("SourceLocation")))
    entry_id = as_hashable_str(entry.get("EntryPointId"))
    minimal = transparency.minimal_api_caveat(
        f"the weakness candidate {as_hashable_str(entry.get('Id')) or 'without an id'}",
        [entry_id] if entry_id else [],
    )
    confidence = entry.get("Confidence")
    return build_record(
        source=ctx.source,
        producer=ctx.producer,
        kind="weakness",
        discriminator=ctx.discriminator(entry, entry.get("Id")),
        purls=tuple(purls),
        locations=tuple([location] if location else []),
        confidence=confidence if isinstance(confidence, str) and confidence else None,
        attributes=dict(entry) or None,
        caveats=where.caveats(ctx.side_caveats["dataflows"], [minimal] if minimal else []),
    )


def _dangerous_api_record(entry: dict, ctx: _Context) -> Evidence:
    """The dangerous-api record of one ``DangerousApiReachability`` entry:
    the purl the entry names as the subject, its confidence as stated,
    every field kept as given, and the first location its evidence lists.
    In a report with minimal-API routes, an entry tied to no route carries
    the minimal-API caveat."""
    transparency = ctx.transparency
    purl = reconcile_purl(entry.get("Purl"), transparency.bom_index)
    where = _Where(ctx.paths)
    location = _text_location(where, as_list(entry.get("Evidence")))
    minimal = transparency.minimal_api_caveat(
        f"the dangerous API call {as_hashable_str(entry.get('Id')) or 'without an id'}",
        _ids(entry.get("EntryPointIds")),
    )
    confidence = entry.get("Confidence")
    return build_record(
        source=ctx.source,
        producer=ctx.producer,
        kind="dangerous-api",
        discriminator=ctx.discriminator(entry, entry.get("Id")),
        purls=(purl,) if purl else (),
        locations=tuple([location] if location else []),
        confidence=confidence if isinstance(confidence, str) and confidence else None,
        attributes=dict(entry) or None,
        caveats=where.caveats(ctx.side_caveats["dataflows"], [minimal] if minimal else []),
    )


def _sanitizer_record(flow: dict, ctx: _Context) -> Evidence:
    """The sanitizer record of one ``SanitizedFlows`` entry: negative
    polarity, the sanitized trace's own fields kept as attributes."""
    attributes = {
        key: value
        for key, value in flow.items()
        if key not in ("Id", "FileName", "LineNumber") and value is not None
    }
    where = _Where(ctx.paths)
    location = where.location(flow.get("FileName"), flow.get("LineNumber"))
    return build_record(
        source=ctx.source,
        producer=ctx.producer,
        kind="sanitizer",
        polarity="negative",
        discriminator=ctx.discriminator(flow, flow.get("Id")),
        locations=tuple([location] if location else []),
        attributes=attributes or None,
        caveats=where.caveats(ctx.side_caveats["dataflows"]),
    )


def _dead_code_record(entry: dict, ctx: _Context) -> Evidence:
    """The dead-code record of one ``DeadCode`` entry: negative polarity,
    the dead method's location and identity."""
    attributes: dict = {}
    for key, field in (("kind", "Kind"), ("namespace", "Namespace"), ("className", "ClassName")):
        value = entry.get(field)
        if value:
            attributes[key] = value
    where = _Where(ctx.paths)
    location = where.location(entry.get("FileName"), entry.get("LineNumber"), entry.get("Name"))
    return build_record(
        source=ctx.source,
        producer=ctx.producer,
        kind="dead-code",
        polarity="negative",
        discriminator=ctx.discriminator(entry, entry.get("NodeId")),
        locations=tuple([location] if location else []),
        attributes=attributes or None,
        caveats=where.caveats(ctx.side_caveats["methods"]),
    )


def _unreachable_node_record(entry: dict, ctx: _Context) -> Evidence:
    """The dead-code record of one unreachable node of the methods
    ``Reachability`` list: negative polarity, the node identity and depth
    as attributes."""
    attributes: dict = {"nodeId": entry.get("NodeId")}
    for key, field in (
        ("depthFromEntryPoint", "DepthFromEntryPoint"),
        ("fanIn", "FanIn"),
        ("fanOut", "FanOut"),
    ):
        value = entry.get(field)
        if value is not None:
            attributes[key] = value
    return build_record(
        source=ctx.source,
        producer=ctx.producer,
        kind="dead-code",
        polarity="negative",
        discriminator=ctx.discriminator(entry, entry.get("NodeId")),
        attributes=attributes,
        caveats=_Where(ctx.paths).caveats(ctx.side_caveats["methods"]),
    )


def _service_record(service: dict, ctx: _Context) -> Evidence:
    """The record of one ``Services`` entry: an inbound or bidirectional
    service is attack surface and becomes an entry-point record, an
    outbound one becomes a presence record. Services attribute no package."""
    direction = as_str(service.get("Direction"))
    kind = "presence" if direction == "outbound" else "entry-point"
    attributes: dict = {}
    for key, field in (
        ("serviceId", "Id"),
        ("name", "Name"),
        ("serviceKind", "ServiceKind"),
        ("direction", "Direction"),
        ("trustZone", "TrustZone"),
        ("crossesTrustBoundary", "CrossesTrustBoundary"),
    ):
        value = service.get(field)
        if value is not None and value != "":
            attributes[key] = value
    location_obj = as_dict(service.get("Location"))
    evidence_obj = as_dict(service.get("Evidence"))
    where = _Where(ctx.paths)
    location = where.location(
        location_obj.get("FileName") or evidence_obj.get("FileName"),
        location_obj.get("LineNumber") or evidence_obj.get("LineNumber"),
    )
    return build_record(
        source=ctx.source,
        producer=ctx.producer,
        kind=kind,
        discriminator=ctx.discriminator(service, service.get("Id")),
        locations=tuple([location] if location else []),
        attributes=attributes or None,
        caveats=where.caveats(ctx.side_caveats["methods"]),
    )


# ---------------------------------------------------------------------------
# The entry point
# ---------------------------------------------------------------------------


def _materialize(report: Any) -> Tuple[Optional[Any], Optional[str]]:
    """The parsed report object, or the reason it could not be read. A
    mapping is taken as given; a string or byte string that names an
    existing file is read, and otherwise parsed as JSON text."""
    if isinstance(report, dict):
        return report, None
    text: Optional[str] = None
    if isinstance(report, bytes):
        try:
            text = report.decode("utf-8")
        except UnicodeDecodeError as e:
            return None, f"the report is not valid UTF-8: {e}"
    elif isinstance(report, str):
        if os.path.isfile(report):
            try:
                with open(report, encoding="utf-8") as fp:
                    text = fp.read()
            except (OSError, UnicodeDecodeError) as e:
                return None, f"the report file could not be read: {e}"
        else:
            text = report
    elif hasattr(report, "__fspath__"):
        path = os.fspath(report)
        if not os.path.isfile(path):
            return None, f"the report file {os.path.basename(path)} does not exist"
        try:
            with open(path, encoding="utf-8") as fp:
                text = fp.read()
        except (OSError, UnicodeDecodeError) as e:
            return None, f"the report file could not be read: {e}"
    else:
        return None, (
            f"the report is {type(report).__name__}; a dosai report is a JSON object or the"
            " file that holds one"
        )
    if text is None:
        return None, "the report holds no text"
    try:
        return json.loads(text), None
    except json.JSONDecodeError as e:
        return None, (
            f"the report is truncated or not valid JSON and was not assessed: {e}"
            " (a report that cannot be parsed must never read as zero findings)"
        )


@guard_extract(PRODUCER_NAME)
def extract(
    report: Any,
    *,
    source: str = "",
    producer_version: str = "",
    bom_index: Optional[Dict[str, str]] = None,
    source_root: Optional[str] = None,
) -> AdapterResult:
    """The evidence records of one dosai report.

    ``report`` is the parsed report, its JSON text, or the path of the file
    that holds either; the parsed form is what the scan hands over, the
    text and path forms let a BOM-directory reader hand over what it found.
    ``source`` names the report file the records came from, as the scan
    directory spells it, and defaults to the report file's base name.
    ``producer_version`` is the dosai version the caller learned from its
    tool status; the ``AnalyzerVersion`` the report states wins when it has
    one. ``bom_index`` is the alias index :func:`build_bom_purl_index`
    builds from the BOM components; without it every NuGet purl is kept as
    the report spells it. ``source_root`` is the scanned source directory
    as the caller knows it; an absolute file path dosai writes is made
    relative to it or to the ``Metadata.InputPath`` the report states.

    A report that cannot be read, parsed, recognized, or gated returns a
    not-assessed result whose reason says what stood in the way. A
    completed result carries every record the report supports, the
    producer-level caveats, and a ``record-skipped`` caveat per reason
    some report objects could not become records, with their count.
    """
    parsed, reason = _materialize(report)
    if reason:
        return not_assessed(reason)
    if not isinstance(parsed, dict):
        return not_assessed(
            f"the report is {type(parsed).__name__}, not a JSON object; not assessed"
        )
    if not is_dosai_report(parsed):
        return not_assessed(
            "the report does not carry a dosai report (no Dosai tool metadata and none of"
            " the dosai sections); not assessed"
        )
    dataflows, methods = split_report(parsed)
    dataflows = dataflows if isinstance(dataflows, dict) else {}
    methods = methods if isinstance(methods, dict) else {}
    for half, section, names in (
        ("dataflows", dataflows, _DATAFLOWS_LISTS),
        ("methods", methods, _METHODS_LISTS),
    ):
        problem = _section_lists(section, names, half)
        if problem:
            return not_assessed(f"the report is malformed and was not assessed: {problem}")

    refusal, gate_caveats, schema_version = _gate_versions(parsed, dataflows, methods)
    if refusal:
        return not_assessed(refusal)

    meta = next(
        (
            holder["Metadata"]
            for holder in (parsed, dataflows, methods)
            if isinstance(holder.get("Metadata"), dict)
        ),
        {},
    )
    source_name = source or (
        os.path.basename(report)
        if isinstance(report, str) and os.path.isfile(report)
        else "unknown"
    )
    producer = EvidenceProducer(
        name=PRODUCER_NAME,
        version=as_str(meta.get("AnalyzerVersion")) or producer_version or "unknown",
        report_schema_version=schema_version,
    )
    bom_index = bom_index or {}
    skipped = SkipTally()
    paths = _source_paths(parsed, dataflows, methods, source_root)
    transparency = _Transparency(dataflows, methods, bom_index, skipped)
    side_caveats: Dict[str, List[EvidenceCaveat]] = {
        "dataflows": list(gate_caveats)
        + _diagnostic_caveats(as_list(dataflows.get("Diagnostics"))),
        "methods": list(gate_caveats) + _diagnostic_caveats(as_list(methods.get("Diagnostics"))),
    }
    ctx = _Context(source_name, producer, transparency, paths, side_caveats, skipped)
    records: List[Evidence] = []

    for sl in as_list(dataflows.get("Slices")):
        if not isinstance(sl, dict):
            skipped.add("Slices entries are not JSON objects and became no record")
            continue
        record = _slice_record(sl, ctx)
        if record:
            records.append(record)
    for section, side in ((dataflows, "dataflows"), (methods, "methods")):
        for pr in as_list(section.get("PackageReachability")):
            if not isinstance(pr, dict):
                skipped.add(
                    f"{side} PackageReachability entries are not JSON objects and became no record"
                )
                continue
            record = _package_reachability_record(pr, side, ctx)
            if record:
                records.append(record)
    for endpoint in as_list(methods.get("ApiEndpoints")):
        if not isinstance(endpoint, dict):
            skipped.add("ApiEndpoints entries are not JSON objects and became no record")
            continue
        record = _api_endpoint_record(endpoint, ctx)
        if record:
            records.append(record)
    for group in transparency.attack_surface:
        group_caveats = list(side_caveats["dataflows"])
        if group.get("EntryPointsTruncated"):
            group_caveats.append(
                EvidenceCaveat(
                    kind="budget",
                    detail=(
                        "the attack surface group's entry points are truncated; dosai kept"
                        " only the first ones"
                    ),
                )
            )
        for entry in as_list(group.get("EntryPoints")):
            if not isinstance(entry, dict):
                skipped.add("AttackSurface entry points are not JSON objects and became no record")
                continue
            records.append(_attack_surface_record(entry, group_caveats, ctx))
    for chain in transparency.chains:
        records.append(_exploit_chain_record(chain, ctx))
    for flow in transparency.sanitized_flows:
        records.append(_sanitizer_record(flow, ctx))
    for section, builder in (
        ("WeaknessCandidates", _weakness_record),
        ("DangerousApiReachability", _dangerous_api_record),
    ):
        for entry in as_list(dataflows.get(section)):
            if not isinstance(entry, dict):
                skipped.add(f"{section} entries are not JSON objects and became no record")
                continue
            records.append(builder(entry, ctx))
    for entry in as_list(methods.get("DeadCode")):
        if not isinstance(entry, dict):
            skipped.add("DeadCode entries are not JSON objects and became no record")
            continue
        records.append(_dead_code_record(entry, ctx))
    for entry in as_list(methods.get("Reachability")):
        if not isinstance(entry, dict):
            skipped.add("Reachability entries are not JSON objects and became no record")
            continue
        # A reachable node is the call graph working as expected and says
        # nothing about a package; only the unreachable ones are evidence.
        if entry.get("Reachable"):
            continue
        records.append(_unreachable_node_record(entry, ctx))
    for service in transparency.services:
        records.append(_service_record(service, ctx))

    caveats = side_caveats["dataflows"] + [
        c for c in side_caveats["methods"] if c not in side_caveats["dataflows"]
    ]
    caveats.extend(skipped.caveats())
    outside = paths.producer_caveat()
    if outside:
        caveats.append(outside)
    return AdapterResult(status="completed", records=records, caveats=caveats)


__all__ = [
    "DOSAI_TOOL_NAME",
    "EXPOSURE_ORDER",
    "KNOWN_MINOR",
    "PRODUCER_NAME",
    "REPORT_CANDIDATES",
    "SUPPORTED_MAJOR",
    "AdapterResult",
    "build_bom_purl_index",
    "combine_reports",
    "extract",
    "is_dosai_report",
    "reconcile_purl",
    "reconcile_purls",
    "split_report",
]
