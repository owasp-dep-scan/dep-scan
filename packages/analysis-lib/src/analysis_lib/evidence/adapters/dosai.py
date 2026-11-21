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

Every record kind the report supports has a home:

- ``Slices[]`` become ``reached-flow`` records carrying the witness node
  path and the slice annotation (the exploit chains that cover the slice,
  its exposure tier, the sanitized flows recorded beside it).
- ``PackageReachability`` entries split by kind and confidence:
  ``DataFlowNode`` and ``CallGraphEdge`` count at Medium or High
  confidence, ``ExternalCallGraphNode`` counts at High confidence, and a
  ``Dependency``-kind entry or any Low-confidence entry becomes a
  ``dependency`` record, which is evidence a later reader can weigh but
  never counts as reached. When an entry states no ``Confidence``, the
  kind's default applies, and ``ExternalCallGraphNode`` defaults to High.
  An entry whose ``Reachable`` is false produces no record, matching the
  flow projection this adapter replaces, which emitted flows only for
  entries dosai called reachable.
- ``ApiEndpoints`` and ``AttackSurface`` entry points become
  ``entry-point`` records with the exposure tier, the route and the trust
  zone of the owning service in their attributes. A route-bearing entry
  dosai tied to the ``cli`` or ``mcp`` tier carries the ``minimal-api``
  caveat, because that pairing is the minimal-API attribution dosai can
  get wrong.
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

Attributes keep the producer's own statements under the names the report
uses or the settled evidence vocabulary uses: ``exposure``,
``exploitChainIds``, ``exploitChains``, ``trustZone``, ``route``,
``sanitizersNearby``, ``hopCount``, ``entryPointId``, ``kind``,
``servicePurls``, plus ``sliceId`` on slice and chain records and the
service identity fields on service records, so the transparency facts the
old facts sidecar carried stay recoverable from the records. Nothing is
inferred: a confidence the report does not state comes only from the
kind-default table above, and a purl dosai did not give is never invented.

The purl reconciler keeps the behaviour of the converter this adapter
replaces: NuGet purls match the BOM exactly or by case-folded name, and an
unmatched NuGet purl (a versionless framework assembly) is kept as given.
Purls of other ecosystems cannot be attributed and the entry saying them
becomes a ``record-skipped`` caveat.

The report schema version gate accepts major 5 (5.0 and 5.1) and refuses
everything below it as not assessed with the reason naming the version it
saw; a newer minor is accepted with a ``schema-minor`` caveat and a report
that names no version with a ``schema-unknown`` one. A report that does
not parse, that is not a dosai report, or that holds a consumed section of
the wrong shape is not assessed with the reason, never an exception, and
never a clean result with zero findings. The budget, timeout and
truncation markers dosai reports through its ``Diagnostics`` lists and its
``EntryPointsTruncated`` flags become ``budget`` and ``timeout`` caveats
on the affected records and in the producer caveats; a report object that
cannot become a record becomes a ``record-skipped`` caveat, never a silent
drop.
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
    VersionGate,
    build_record,
    gate_report_version,
    not_assessed,
)

#: The producer name every record of this adapter carries.
PRODUCER_NAME = "dosai"

#: The report schema major this adapter reads, and the newest minor of it
#: it knows. dosai 5.0 and main both write 5.1.
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
#: external call graph kind defaults to High: a call-graph fact is call
#: evidence, and dropping it to Low hid reachable packages from the flow
#: projection this adapter replaces.
_KIND_TO_CONFIDENCE = {
    "DataFlowNode": "High",
    "CallGraphEdge": "High",
    "ExternalCallGraphNode": "High",
    "Dependency": "Low",
}
_CONF_RANK = {"Low": 1, "Medium": 2, "High": 3}

#: The kinds whose entries count at Medium or High confidence. The external
#: call graph kind counts only at High.
_MEDIUM_HIGH_KINDS = ("DataFlowNode", "CallGraphEdge")

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
# Purl reconciliation (unchanged from the converter this adapter replaces)
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
    return any(
        k in report for k in ("Slices", "PackageReachability", "CallGraph", "ApiEndpoints")
    )


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


def _forward_slashes(value: Any) -> str:
    return str(value or "").replace("\\", "/").replace(os.sep, "/")


def _line_number(value: Any) -> Optional[int]:
    try:
        line = int(value or 0)
    except (TypeError, ValueError):
        return None
    return line or None


def _most_exposed(exposures: Iterable[Optional[str]]) -> Optional[str]:
    """The most exposed class among ``exposures``, or ``None`` when none."""
    found = [e for e in exposures if isinstance(e, str) and e]
    if not found:
        return None
    return min(found, key=lambda e: EXPOSURE_ORDER.index(e) if e in EXPOSURE_ORDER else len(EXPOSURE_ORDER))


def _route_key(method: Any, route: Any) -> Tuple[str, str]:
    """The key a route is matched on. ``ApiEndpoints[].Route`` omits the
    leading slash that ``Path`` and the attack surface rows carry."""
    path = str(route or "").strip()
    if path and not path.startswith("/"):
        path = "/" + path
    return (str(method or "").upper(), path)


def _line_key(file_name: Any, line: Any) -> Tuple[str, int]:
    """Case-insensitive base name plus line, the way a sanitizer location is
    compared with a data-flow node location."""
    base = os.path.basename(_forward_slashes(file_name)).lower()
    try:
        return (base, int(line or 0))
    except (TypeError, ValueError):
        return (base, 0)


def _parent_method(entry: Dict[str, Any]) -> str:
    """A ``ClassName.MethodName`` parent-method string."""
    cls = entry.get("ClassName") or entry.get("Namespace") or ""
    method = entry.get("MethodName") or entry.get("Name") or ""
    if cls and method:
        return f"{cls}.{method}"
    return method or cls


def _is_source_file(path: Any) -> bool:
    return bool(path) and bool(_SOURCE_EXT_RE.search(str(path)))


def _location_of(file_name: Any, line: Any, method: Any = None) -> Optional[EvidenceLocation]:
    """A location for a producer file name and line, or ``None`` when the
    entry names no file."""
    file_value = _forward_slashes(file_name)
    if not file_value:
        return None
    return EvidenceLocation(file=file_value, line=_line_number(line), method=method or None)


def _source_locations(entry: Dict[str, Any]) -> List[EvidenceLocation]:
    """The source-file locations of a ``PackageReachability`` entry, in the
    order dosai lists them."""
    out: List[EvidenceLocation] = []
    for location in entry.get("SourceLocations") or []:
        if not isinstance(location, dict):
            continue
        path = location.get("Path") or location.get("FileName")
        if not _is_source_file(path):
            continue
        location_obj = _location_of(path, location.get("LineNumber"))
        if location_obj:
            out.append(location_obj)
    return out


def _confidence_of(entry: Dict[str, Any]) -> Tuple[str, str]:
    """The entry's reachability kind and its effective confidence: the
    confidence the entry states, else the kind's default."""
    kind = entry.get("ReachabilityKind") or "Dependency"
    confidence = str(entry.get("Confidence") or _KIND_TO_CONFIDENCE.get(kind, "Low")).capitalize()
    return kind, confidence


def _counts_as_reached(kind: str, confidence: str) -> bool:
    """The reachability matrix: dataflow and call-graph entries count at
    Medium or High, external call graph entries count only at High, and
    everything else (the Dependency kind and every Low entry) is recorded
    without counting."""
    if confidence == "Low":
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
    methods half. Any section may be absent; every table is then empty and
    the records carry no annotation from it.
    """

    def __init__(self, dataflows: Optional[dict], methods: Optional[dict], bom_index: Dict[str, str]):
        dataflows = dataflows or {}
        methods = methods or {}
        self.chains: List[dict] = [c for c in (dataflows.get("ExploitChains") or []) if isinstance(c, dict)]
        self.sanitized_flows: List[dict] = [
            f for f in (dataflows.get("SanitizedFlows") or []) if isinstance(f, dict)
        ]
        self.attack_surface: List[dict] = [
            g for g in (dataflows.get("AttackSurface") or []) if isinstance(g, dict)
        ]
        self.services: List[dict] = [s for s in (methods.get("Services") or []) if isinstance(s, dict)]
        self.nodes: Dict[str, dict] = {
            n["Id"]: n for n in (dataflows.get("Nodes") or []) if isinstance(n, dict) and n.get("Id")
        }
        self.bom_index = bom_index
        self.entry_exposure: Dict[str, str] = {}
        self.route_exposure: Dict[Tuple[str, str], str] = {}
        self._route_by_entry: Dict[str, str] = {}
        for group in self.attack_surface:
            group_exposure = group.get("Exposure")
            for entry in group.get("EntryPoints") or []:
                if not isinstance(entry, dict):
                    continue
                exposure = entry.get("Exposure") or group_exposure
                if not exposure:
                    continue
                if entry.get("EntryPointId"):
                    self.entry_exposure[entry["EntryPointId"]] = exposure
                if entry.get("Route"):
                    key = _route_key(entry.get("HttpMethod"), entry.get("Route"))
                    self.route_exposure[key] = (
                        _most_exposed([exposure, self.route_exposure.get(key)]) or exposure
                    )
                    self._route_by_entry.setdefault(entry["EntryPointId"], entry["Route"])
        for entry in dataflows.get("EntryPoints") or []:
            if isinstance(entry, dict) and entry.get("Id") and entry.get("Route"):
                self._route_by_entry.setdefault(entry["Id"], entry["Route"])
        self.chains_by_slice: Dict[str, List[dict]] = {}
        for chain in self.chains:
            exposure = chain.get("Exposure")
            if exposure and chain.get("EntryPointId"):
                self.entry_exposure.setdefault(chain["EntryPointId"], exposure)
            if chain.get("SliceId"):
                self.chains_by_slice.setdefault(chain["SliceId"], []).append(chain)
        self.trust_zone_by_route: Dict[Tuple[str, str], dict] = {}
        for service in self.services:
            zone = service.get("TrustZone")
            if not zone:
                continue
            for operation in service.get("Operations") or []:
                if not isinstance(operation, dict):
                    continue
                path = operation.get("Path") or operation.get("RouteTemplate") or operation.get("Name")
                if path:
                    self.trust_zone_by_route[_route_key(operation.get("HttpMethod"), path)] = {
                        "trustZone": zone,
                        "serviceId": service.get("Id"),
                    }
        self.slice_purls: Dict[str, List[str]] = {}
        for sl in dataflows.get("Slices") or []:
            if isinstance(sl, dict) and sl.get("Id"):
                self.slice_purls[sl["Id"]] = reconcile_purls(
                    list(sl.get("Purls") or []) + [sl.get("SinkPurl"), sl.get("SourcePurl")]
                    + self._node_purls(sl),
                    bom_index,
                )
        self.sanitizers_nearby: Dict[str, List[dict]] = self._match_sanitizers(dataflows)

    def _node_purls(self, sl: dict) -> List[Optional[str]]:
        return [
            self.nodes[nid].get("Purl")
            for nid in sl.get("NodeIds") or []
            if isinstance(self.nodes.get(nid), dict)
        ]

    def _match_sanitizers(self, dataflows: Optional[dict]) -> Dict[str, List[dict]]:
        """Map a slice id to the sanitized flows recorded beside it: a flow
        is near a slice when the two share a source node and the sanitizer
        sits on the slice's path (same file and line as one of its nodes).
        Matching only annotates; dosai emits no slice for a trace it
        sanitized, so a present slice was never stopped."""
        if not self.sanitized_flows:
            return {}
        matched: Dict[str, List[dict]] = {}
        for sl in (dataflows or {}).get("Slices") or []:
            if not isinstance(sl, dict) or not sl.get("Id"):
                continue
            node_ids = [nid for nid in (sl.get("NodeIds") or []) if isinstance(nid, str)]
            node_set = set(node_ids)
            node_locations = {
                _line_key(self.nodes[nid].get("Path") or self.nodes[nid].get("FileName"),
                          self.nodes[nid].get("LineNumber"))
                for nid in node_ids
                if nid in self.nodes
            }
            for flow in self.sanitized_flows:
                if not flow.get("Id"):
                    continue
                if not node_set.intersection(flow.get("SourceIds") or []):
                    continue
                if _line_key(flow.get("FileName"), flow.get("LineNumber")) not in node_locations:
                    continue
                matched.setdefault(sl["Id"], []).append(
                    {
                        "id": flow["Id"],
                        "category": flow.get("SanitizerCategory") or flow.get("SanitizerSymbol"),
                    }
                )
        return matched

    def slice_annotation(self, sl: dict) -> Optional[dict]:
        """The transparency attributes of one slice, or ``None`` when the
        report carries none for it."""
        slice_id = sl.get("Id")
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
        route = self._route_by_entry.get(chain.get("EntryPointId") or "")
        if route:
            compact["route"] = route
        return compact

    def package_annotation(self, pr: dict) -> Optional[dict]:
        """The exposure and chain ids of the entry points and exploit chains
        that reach a package, or ``None`` when the report names none."""
        slice_ids = [s for s in (pr.get("SliceIds") or []) if isinstance(s, str)]
        exposures = [self.entry_exposure.get(e) for e in (pr.get("EntryPointIds") or [])]
        chain_ids: List[str] = []
        for slice_id in slice_ids:
            for chain in self.chains_by_slice.get(slice_id, []):
                exposures.append(chain.get("Exposure"))
                if chain.get("Id") and chain["Id"] not in chain_ids:
                    chain_ids.append(chain["Id"])
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


def _section_lists(section: Optional[dict], names: Tuple[str, ...], half: str) -> Optional[str]:
    """The name of the first consumed section of the wrong shape, or
    ``None`` when every present section is a list."""
    if not isinstance(section, dict):
        return None
    for name in names:
        if name in section and not isinstance(section[name], list):
            return f"the {half} section's {name} is {type(section[name]).__name__}, expected a list"
    return None


# ---------------------------------------------------------------------------
# Record builders
# ---------------------------------------------------------------------------


def _slice_record(
    sl: dict,
    transparency: _Transparency,
    source: str,
    producer: EvidenceProducer,
    caveats: Tuple[EvidenceCaveat, ...],
    skipped: List[EvidenceCaveat],
) -> Optional[Evidence]:
    """The reached-flow record of one data-flow slice, with the witness
    node path and the slice annotation. A slice that names no package purl
    attributes nothing and becomes a record-skipped caveat."""
    nodes = transparency.nodes
    node_ids = [nid for nid in (sl.get("NodeIds") or []) if isinstance(nid, str)]
    purls = transparency.slice_purls.get(sl.get("Id") or "") or reconcile_purls(
        list(sl.get("Purls") or []) + [sl.get("SinkPurl"), sl.get("SourcePurl")]
        + transparency._node_purls(sl),
        transparency.bom_index,
    )
    if not purls:
        label = sl.get("Id") or "without an id"
        skipped.append(
            EvidenceCaveat(
                kind="record-skipped",
                detail=f"the data-flow slice {label} names no package purls; nothing to attribute",
            )
        )
        return None
    path: List[EvidencePathNode] = []
    locations: List[EvidenceLocation] = []
    for nid in node_ids:
        node = nodes.get(nid)
        if not isinstance(node, dict):
            continue
        path.append(
            EvidencePathNode(
                file=_forward_slashes(node.get("Path") or node.get("FileName")) or None,
                line=_line_number(node.get("LineNumber")),
                method=_parent_method(node) or None,
                symbol=str(node.get("Symbol") or node.get("Name") or "") or None,
            )
        )
        location = _location_of(
            node.get("Path") or node.get("FileName"), node.get("LineNumber"), _parent_method(node)
        )
        if location:
            locations.append(location)
    attributes: dict = {}
    annotation = transparency.slice_annotation(sl)
    if annotation:
        attributes.update(annotation)
    category = str(sl.get("SinkCategory") or "")
    if category in _CATEGORY_TO_SERVICE_TAG:
        service_purls = reconcile_purls(
            list(sl.get("Purls") or []) + [sl.get("SinkPurl")], transparency.bom_index
        )
        if service_purls:
            attributes["servicePurls"] = service_purls
    return build_record(
        source=source,
        producer=producer,
        kind="reached-flow",
        discriminator=str(sl.get("Id") or content_discriminator(sl)),
        purls=tuple(purls),
        locations=tuple(locations),
        path=tuple(path),
        attributes=attributes or None,
        caveats=caveats,
    )


def _package_reachability_record(
    pr: dict,
    transparency: _Transparency,
    source: str,
    producer: EvidenceProducer,
    caveats: Tuple[EvidenceCaveat, ...],
    skipped: List[EvidenceCaveat],
) -> Optional[Evidence]:
    """The reached-flow or dependency record of one ``PackageReachability``
    entry, per the reachability matrix. An entry dosai marked not reachable
    produces no record, and an entry whose purl cannot be attributed
    becomes a record-skipped caveat."""
    if not pr.get("Reachable"):
        return None
    raw_purl = pr.get("Purl")
    purl = reconcile_purl(raw_purl, transparency.bom_index)
    if not purl:
        skipped.append(
            EvidenceCaveat(
                kind="record-skipped",
                detail=(
                    "the PackageReachability entry names no NuGet purl this adapter can"
                    f" attribute: {raw_purl!r}"
                )
                if raw_purl
                else "the PackageReachability entry names no package purl",
            )
        )
        return None
    kind, confidence = _confidence_of(pr)
    counted = _counts_as_reached(kind, confidence)
    attributes: dict = {"kind": kind}
    annotation = transparency.package_annotation(pr)
    if annotation:
        attributes.update(annotation)
    category = next((c for c in (pr.get("Categories") or []) if isinstance(c, str)), "")
    if counted and category in _CATEGORY_TO_SERVICE_TAG:
        attributes["servicePurls"] = [purl]
    return build_record(
        source=source,
        producer=producer,
        kind="reached-flow" if counted else "dependency",
        discriminator=content_discriminator(pr),
        purls=(purl,),
        locations=tuple(_source_locations(pr)),
        confidence=confidence,
        attributes=attributes,
        caveats=caveats,
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
    zone = transparency.endpoint_zone(entry.get("HttpMethod"), route)
    attributes.update(zone)
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


def _api_endpoint_record(
    entry: dict,
    transparency: _Transparency,
    source: str,
    producer: EvidenceProducer,
    caveats: Tuple[EvidenceCaveat, ...],
    skipped: List[EvidenceCaveat],
) -> Optional[Evidence]:
    """The entry-point record of one ``ApiEndpoints`` entry. An entry that
    names no route cannot be an entry point and becomes a caveat."""
    route = entry.get("Route") or entry.get("Path")
    if not route:
        skipped.append(
            EvidenceCaveat(
                kind="record-skipped",
                detail="the API endpoint entry names no route; no entry point to record",
            )
        )
        return None
    attributes, extra_caveats = _endpoint_attributes(entry, transparency)
    handler_purls = reconcile_purls(list(entry.get("Purls") or []), transparency.bom_index)
    method_name = _parent_method(entry) or None
    location = _location_of(
        entry.get("FilePath") or entry.get("FileName"), entry.get("LineNumber"), method_name
    )
    discriminator = str(entry.get("OperationId") or content_discriminator(entry))
    return build_record(
        source=source,
        producer=producer,
        kind="entry-point",
        discriminator=discriminator,
        purls=tuple(handler_purls),
        locations=tuple([location] if location else []),
        attributes=attributes or None,
        caveats=tuple(list(caveats) + list(extra_caveats)),
    )


def _attack_surface_record(
    group: dict,
    entry: dict,
    transparency: _Transparency,
    source: str,
    producer: EvidenceProducer,
    caveats: Tuple[EvidenceCaveat, ...],
) -> Optional[Evidence]:
    """The entry-point record of one ``AttackSurface`` entry, carrying the
    exposure tier of the group or the entry and the trust zone of the
    service that owns the route."""
    attributes, extra_caveats = _endpoint_attributes(entry, transparency)
    location = _location_of(entry.get("FileName"), entry.get("LineNumber"))
    discriminator = str(entry.get("EntryPointId") or content_discriminator(entry))
    return build_record(
        source=source,
        producer=producer,
        kind="entry-point",
        discriminator=discriminator,
        locations=tuple([location] if location else []),
        attributes=attributes or None,
        caveats=tuple(list(caveats) + list(extra_caveats)),
    )


def _exploit_chain_record(
    chain: dict,
    transparency: _Transparency,
    source: str,
    producer: EvidenceProducer,
    caveats: Tuple[EvidenceCaveat, ...],
) -> Evidence:
    """The exploit-chain record of one ``ExploitChains`` entry: the covered
    slice's purls as the subject, the chain's own id, entry point, exposure
    tier, hop count, route and slice id as attributes. The chain id is what
    the reachability entries' ``exploitChainIds`` reference, so it stays a
    readable value and not only the record id's hash input."""
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
    route = transparency._route_by_entry.get(chain.get("EntryPointId") or "")
    if route:
        attributes["route"] = route
    purls = transparency.slice_purls.get(chain.get("SliceId") or "", [])
    return build_record(
        source=source,
        producer=producer,
        kind="exploit-chain",
        discriminator=str(chain.get("Id") or content_discriminator(chain)),
        purls=tuple(purls),
        confidence=str(chain.get("Confidence") or "") or None,
        attributes=attributes or None,
        caveats=caveats,
    )


def _sanitizer_record(
    flow: dict,
    source: str,
    producer: EvidenceProducer,
    caveats: Tuple[EvidenceCaveat, ...],
) -> Evidence:
    """The sanitizer record of one ``SanitizedFlows`` entry: negative
    polarity, the sanitized trace's own fields kept as attributes."""
    attributes = {
        key: value
        for key, value in flow.items()
        if key not in ("Id", "FileName", "LineNumber") and value is not None
    }
    location = _location_of(flow.get("FileName"), flow.get("LineNumber"))
    return build_record(
        source=source,
        producer=producer,
        kind="sanitizer",
        polarity="negative",
        discriminator=str(flow.get("Id") or content_discriminator(flow)),
        locations=tuple([location] if location else []),
        attributes=attributes or None,
        caveats=caveats,
    )


def _dead_code_record(
    entry: dict,
    source: str,
    producer: EvidenceProducer,
    caveats: Tuple[EvidenceCaveat, ...],
) -> Evidence:
    """The dead-code record of one ``DeadCode`` entry: negative polarity,
    the dead method's location and identity."""
    attributes: dict = {}
    for key, field in (("kind", "Kind"), ("namespace", "Namespace"), ("className", "ClassName")):
        value = entry.get(field)
        if value:
            attributes[key] = value
    location = _location_of(
        entry.get("FileName"), entry.get("LineNumber"), entry.get("Name") or None
    )
    return build_record(
        source=source,
        producer=producer,
        kind="dead-code",
        polarity="negative",
        discriminator=str(entry.get("NodeId") or content_discriminator(entry)),
        locations=tuple([location] if location else []),
        attributes=attributes or None,
        caveats=caveats,
    )


def _unreachable_node_record(
    entry: dict,
    source: str,
    producer: EvidenceProducer,
    caveats: Tuple[EvidenceCaveat, ...],
) -> Evidence:
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
        source=source,
        producer=producer,
        kind="dead-code",
        polarity="negative",
        discriminator=str(entry.get("NodeId") or content_discriminator(entry)),
        attributes=attributes,
        caveats=caveats,
    )


def _service_record(
    service: dict,
    source: str,
    producer: EvidenceProducer,
    caveats: Tuple[EvidenceCaveat, ...],
) -> Evidence:
    """The record of one ``Services`` entry: an inbound or bidirectional
    service is attack surface and becomes an entry-point record, an
    outbound one becomes a presence record. Services attribute no package."""
    direction = str(service.get("Direction") or "")
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
    location_obj = service.get("Location") if isinstance(service.get("Location"), dict) else {}
    evidence_obj = service.get("Evidence") if isinstance(service.get("Evidence"), dict) else {}
    location = _location_of(
        location_obj.get("FileName") or evidence_obj.get("FileName"),
        location_obj.get("LineNumber") or evidence_obj.get("LineNumber"),
    )
    return build_record(
        source=source,
        producer=producer,
        kind=kind,
        discriminator=str(service.get("Id") or content_discriminator(service)),
        locations=tuple([location] if location else []),
        attributes=attributes or None,
        caveats=caveats,
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
            except OSError as e:
                return None, f"the report file could not be read: {e}"
        else:
            text = report
    elif hasattr(report, "__fspath__"):
        path = os.fspath(report)
        if not os.path.isfile(path):
            return None, f"the report file {path} does not exist"
        try:
            with open(path, encoding="utf-8") as fp:
                text = fp.read()
        except OSError as e:
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


def extract(
    report: Any,
    *,
    source: str = "",
    producer_version: str = "",
    bom_index: Optional[Dict[str, str]] = None,
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
    the report spells it.

    A report that cannot be read, parsed, recognized, or gated returns a
    not-assessed result whose reason says what stood in the way. A
    completed result carries every record the report supports, the
    producer-level caveats, and a ``record-skipped`` caveat for every
    report object that could not become a record.
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

    # The combined envelope carries the report metadata the scan chose at
    # the top level; a standalone half carries its own. The halves' own
    # blocks only matter for a hand-assembled envelope without one.
    meta = (
        parsed.get("Metadata")
        if isinstance(parsed.get("Metadata"), dict)
        else None
    ) or (
        dataflows.get("Metadata") if isinstance(dataflows.get("Metadata"), dict) else None
    ) or (methods.get("Metadata") if isinstance(methods.get("Metadata"), dict) else None) or {}
    gate: VersionGate = gate_report_version(meta.get("SchemaVersion"), SUPPORTED_MAJOR, KNOWN_MINOR)
    if not gate.accepted:
        return not_assessed(gate.reason or "the report schema version is not supported")

    source_name = source or (
        os.path.basename(str(report)) if isinstance(report, str) and os.path.isfile(str(report)) else "unknown"
    )
    producer = EvidenceProducer(
        name=PRODUCER_NAME,
        version=str(meta.get("AnalyzerVersion") or producer_version or "unknown"),
        report_schema_version=str(meta.get("SchemaVersion") or "unknown"),
    )
    bom_index = bom_index or {}

    transparency = _Transparency(dataflows, methods, bom_index)
    side_caveats: Dict[str, List[EvidenceCaveat]] = {
        "dataflows": list(gate.caveats) + _diagnostic_caveats(dataflows.get("Diagnostics") or []),
        "methods": list(gate.caveats) + _diagnostic_caveats(methods.get("Diagnostics") or []),
    }
    truncated_groups = [
        group
        for group in transparency.attack_surface
        if isinstance(group, dict) and group.get("EntryPointsTruncated")
    ]
    skipped: List[EvidenceCaveat] = []
    records: List[Evidence] = []

    for sl in dataflows.get("Slices") or []:
        if not isinstance(sl, dict):
            skipped.append(
                EvidenceCaveat(kind="record-skipped", detail="the Slices entry is not an object")
            )
            continue
        record = _slice_record(
            sl, transparency, source_name, producer, tuple(side_caveats["dataflows"]), skipped
        )
        if record:
            records.append(record)
    for section, side in ((dataflows, "dataflows"), (methods, "methods")):
        for pr in section.get("PackageReachability") or []:
            if not isinstance(pr, dict):
                skipped.append(
                    EvidenceCaveat(
                        kind="record-skipped",
                        detail=f"the {side} PackageReachability entry is not an object",
                    )
                )
                continue
            record = _package_reachability_record(
                pr, transparency, source_name, producer, tuple(side_caveats[side]), skipped
            )
            if record:
                records.append(record)
    for endpoint in methods.get("ApiEndpoints") or []:
        if not isinstance(endpoint, dict):
            skipped.append(
                EvidenceCaveat(
                    kind="record-skipped", detail="the ApiEndpoints entry is not an object"
                )
            )
            continue
        record = _api_endpoint_record(
            endpoint, transparency, source_name, producer, tuple(side_caveats["methods"]), skipped
        )
        if record:
            records.append(record)
    for group in transparency.attack_surface:
        if not isinstance(group, dict):
            skipped.append(
                EvidenceCaveat(
                    kind="record-skipped", detail="the AttackSurface entry is not an object"
                )
            )
            continue
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
        for entry in group.get("EntryPoints") or []:
            if not isinstance(entry, dict):
                skipped.append(
                    EvidenceCaveat(
                        kind="record-skipped",
                        detail="the AttackSurface entry point is not an object",
                    )
                )
                continue
            record = _attack_surface_record(
                group, entry, transparency, source_name, producer, tuple(group_caveats)
            )
            if record:
                records.append(record)
    for chain in transparency.chains:
        records.append(
            _exploit_chain_record(
                chain, transparency, source_name, producer, tuple(side_caveats["dataflows"])
            )
        )
    for flow in transparency.sanitized_flows:
        records.append(
            _sanitizer_record(flow, source_name, producer, tuple(side_caveats["dataflows"]))
        )
    for entry in methods.get("DeadCode") or []:
        if not isinstance(entry, dict):
            skipped.append(
                EvidenceCaveat(kind="record-skipped", detail="the DeadCode entry is not an object")
            )
            continue
        records.append(
            _dead_code_record(entry, source_name, producer, tuple(side_caveats["methods"]))
        )
    for entry in methods.get("Reachability") or []:
        if not isinstance(entry, dict):
            skipped.append(
                EvidenceCaveat(
                    kind="record-skipped", detail="the Reachability entry is not an object"
                )
            )
            continue
        if entry.get("Reachable"):
            continue
        records.append(
            _unreachable_node_record(entry, source_name, producer, tuple(side_caveats["methods"]))
        )
    for service in transparency.services:
        records.append(
            _service_record(service, source_name, producer, tuple(side_caveats["methods"]))
        )

    caveats = side_caveats["dataflows"] + [
        c for c in side_caveats["methods"] if c not in side_caveats["dataflows"]
    ]
    caveats.extend(skipped)
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
