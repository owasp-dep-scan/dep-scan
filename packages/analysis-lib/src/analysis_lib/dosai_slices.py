"""dosai (Dotnet Source and Assembly Inspector) native report reader,
purl reconciler, native-reachability extractor, and atom projection emitter.

dosai's native output is **PascalCase** (``PackageReachability``, ``Slices``,
``Nodes``, ``SinkPurl``, ``SourceLocations``, ``WeaknessCandidates``,
``DangerousApiReachability``, ``ApiEndpoints``, ``CallGraph``) and is strictly
richer than the atom flow shape: it states reachability explicitly per package
(``Reachable`` + ``ReachabilityKind`` + ``Confidence`` + ``EvidenceKinds`` +
``SourceLocations``). We therefore consume the native facts DIRECTLY for the
reachability verdict and ALSO emit an atom-shaped ``dotnet-reachables.slices.json``
**projection** so the existing purl-keyed reachability pipeline + ``--explain``
renderer light up with zero engine changes (mirror golem/rusi).

Two design principles (see ~/dosai-reachability-plan.md §0):

1. **Reachability truth comes from native ``PackageReachability[]``**, NOT from
   re-inferring reachedness by parsing atom flow tags. ``extract_native_reachability``
   maps dosai's native facts straight into a reached-purl map with dosai's own
   confidence.
2. **The atom projection faithfully carries every native-reachable purl** in its
   flows' ``purls`` lists, so the existing engine's ``reached_purls`` loop
   (``reachability.py``) picks them up unchanged. The projection is *derived*,
   not authoritative; a native-engine follow-up can later consume
   :func:`extract_native_reachability` directly.

dosai reports appear in two shapes, both recognized here:

- **combined** (cdxgen primary path, ``dotnet-semantics.slices.json``):
  ``{"Metadata": {"Tool": "Dosai", ...}, "methods": {...}, "dataflows": {...}}``
  where ``methods``/``dataflows`` are the full native slices.
- **standalone** (direct-spawn fallback, ``dotnet-dataflows.json`` /
  ``dotnet-methods.json``): a single native slice whose top-level keys identify
  which one it is (flat ``Nodes``/``Slices`` -> dataflows; nested
  ``CallGraph``/``ApiEndpoints`` -> methods).

Public surface:
    - :func:`is_dosai_report` -- shape-based report detection (combined or standalone)
    - :func:`build_bom_purl_index` -- NuGet alias-purl index from BOM components
    - :func:`reconcile_purl` -- dosai purl -> BOM versioned purl (keeps framework purls)
    - :func:`extract_native_reachability` -- native reachability facts (the truth)
    - :func:`convert_dosai_report` -- atom-shaped projection for the engine + explainer
    - :func:`write_slices_file` -- atomic deterministic writer (mirrors golem/rusi)
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any, Dict, Iterable, List, Optional

from packageurl import PackageURL


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# dosai reports are detected by SHAPE: a dict whose ``Metadata.Tool`` is
# ``"Dosai"`` AND that carries at least one analysis section we consume. This
# works for the combined envelope (``methods``/``dataflows``) AND for a
# standalone native slice (``Slices``/``PackageReachability``/``CallGraph``).
DOSAI_TOOL_NAME = "Dosai"
DOSAI_COMBINED_KEYS = ("methods", "dataflows")
DOSAI_SECTION_KEYS = ("Slices", "PackageReachability", "CallGraph", "ApiEndpoints")

# Standalone language token emitted in every node's ``tags`` so
# ``explainer.is_analyzer_slice`` relaxes the node-count gates for honest 2-node
# dosai flows (mirrors the ``rust``/``go`` token from rusi/golem).
DOSAI_LANG_TOKEN = "dotnet"

# dosai data-flow SinkCategory -> dep-scan SERVICE_TAGS vocabulary (config.py).
# Conservative mapping: only categories whose intent clearly maps to an existing
# service tag. Used for positional service attribution in the atom projection so
# ``SemanticReachability._flow_service_purls`` attributes the framework crate on
# the endpoint/service path to ``reached_services``.
DOSAI_CATEGORY_TO_SERVICE_TAG = {
    # sinks
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
    # sources
    "http-request": "http",
    "http-parameter": "http",
}

# SERVICE_TAG used for HTTP ApiEndpoint handler flows. ``api`` is a SERVICE_TAG
# (config.py) so SemanticReachability attributes the framework crate on the
# endpoint path to ``reached_services``.
DOSAI_ENDPOINT_SERVICE_TAG = "api"

# Source-file extensions dosai emits occurrence evidence for (mirror
# dosaiParsers.js ``dosaiSourceLocation`` regex). Assembly/.dll locations are
# NOT source evidence and are filtered out.
_DOSAI_SOURCE_EXT_RE = re.compile(r"\.(cs|vb|fs|fsx|fsi|r|rmd|qmd)$", re.IGNORECASE)

# ReachabilityKind -> default Confidence when dosai omits it.
_KIND_TO_CONFIDENCE = {
    "DataFlowNode": "High",
    "CallGraphEdge": "High",
    "Dependency": "Low",
}
_CONF_RANK = {"Low": 1, "Medium": 2, "High": 3}


# ---------------------------------------------------------------------------
# Purl parsing + reconciliation (mirrors cdxgen dosaiParsers.js)
# ---------------------------------------------------------------------------


def _normalize_nuget_key(purl: Optional[str]) -> Optional[str]:
    """Return the normalized alias key for a purl.

    Mirrors cdxgen's ``normalizeDosaiPurlKey``:
    ``[type, namespace||"", name].join("/")`` all lowercased. For NuGet
    (namespace-less) this yields ``"nuget/<name-lowercased>"`` (with an empty
    namespace segment, exactly like the JS reference). Returns ``None`` for a
    non-string/empty purl.
    """
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
        # manual fallback mirror: drop ?qual #sub @version, lowercase
        return purl.split("?")[0].split("#")[0].split("@")[0].lower()


def build_bom_purl_index(
    bom_components: Optional[Iterable[dict]],
    extra_components: Optional[Iterable[dict]] = None,
) -> Dict[str, str]:
    """Build a multi-form ``alias-key -> versioned-purl`` index from a NuGet BOM.

    Mirrors cdxgen's ``buildDosaiPurlAliasMap``. For each NuGet BOM component
    the index stores:
      1. the exact versioned purl (``pkg:nuget/Newtonsoft.Json@13.0.3``)
      2. the normalized alias key (``nuget//newtonsoft.json``)

    So a dosai versionless framework purl (``pkg:nuget/System.Text.Json``)
    matches a BOM versioned purl (``pkg:nuget/System.Text.Json@10.0.0``) via the
    case-insensitive normalized name. Non-nuget components are ignored.
    """
    index: Dict[str, str] = {}
    for c in list(bom_components or []) + list(extra_components or []):
        if not isinstance(c, dict):
            continue
        purl = c.get("purl", "")
        if not isinstance(purl, str) or not purl.startswith("pkg:nuget/"):
            continue
        index.setdefault(purl, purl)
        key = _normalize_nuget_key(purl)
        if key and key not in index:
            index[key] = purl
    return index


def reconcile_purl(dosai_purl: Optional[str], bom_index: Dict[str, str]) -> Optional[str]:
    """Map a dosai purl onto a BOM versioned purl.

    Mirrors cdxgen's ``resolveDosaiComponentPurl``:
      1. exact match in the BOM index
      2. normalized-name match (case-insensitive, version/qualifier/subpath dropped)

    Rules:
      - Non-nuget / malformed / empty -> ``None`` (we only reconcile NuGet purls).
      - Matched -> the BOM's canonical versioned purl.
      - **Unmatched NuGet purl -> KEPT AS-IS** (framework versionless purls like
        ``pkg:nuget/System.Runtime`` are legitimately not always in a restored
        SBOM; do NOT drop them, and do NOT invent a version). Callers may treat
        these as low-confidence. This is the deliberate divergence from
        golem/rusi (which return ``None``) and mirrors cdxgen's own fallback.
    """
    if not isinstance(dosai_purl, str) or not dosai_purl:
        return None
    if not dosai_purl.startswith("pkg:nuget/"):
        return None
    if dosai_purl in bom_index:
        return bom_index[dosai_purl]
    key = _normalize_nuget_key(dosai_purl)
    if key and key in bom_index:
        return bom_index[key]
    # framework versionless purl absent from BOM: keep as-is (low confidence)
    return dosai_purl


def reconcile_purls(dosai_purls: Iterable[str], bom_index: Dict[str, str]) -> List[str]:
    """Reconcile + de-duplicate a collection of dosai purls.

    Returns a sorted (deterministic) list of non-None reconciled purls.
    """
    seen = set()
    out = []
    for dp in dosai_purls or []:
        vp = reconcile_purl(dp, bom_index)
        if vp and vp not in seen:
            seen.add(vp)
            out.append(vp)
    return sorted(out)


# ---------------------------------------------------------------------------
# Report shape detection + split (combined vs standalone)
# ---------------------------------------------------------------------------


def is_dosai_report(report) -> bool:
    """Return True if ``report`` has the structural shape of a dosai report.

    Detection is by shape (not a schema-version prefix): a dict whose
    ``Metadata.Tool`` equals ``"Dosai"`` AND that carries at least one analysis
    section we consume (``methods``/``dataflows`` for the combined envelope, or
    ``Slices``/``PackageReachability``/``CallGraph``/``ApiEndpoints`` for a
    standalone native slice). This reliably distinguishes a genuine dosai report
    from an atom-produced ``*-semantics.slices.json`` that shares the path.
    """
    if not isinstance(report, dict):
        return False
    meta = report.get("Metadata")
    if not isinstance(meta, dict) or meta.get("Tool") != DOSAI_TOOL_NAME:
        return False
    if any(k in report for k in DOSAI_COMBINED_KEYS):
        return True
    return any(k in report for k in DOSAI_SECTION_KEYS)


def _looks_like_dataflows(obj: Optional[dict]) -> bool:
    """A standalone dosai dataflows slice has flat ``Nodes``/``Edges`` and/or
    ``Slices``."""
    if not isinstance(obj, dict):
        return False
    return any(k in obj for k in ("Slices", "DangerousApiReachability", "WeaknessCandidates")) or (
        "Nodes" in obj and "CallGraph" not in obj
    )


def _looks_like_methods(obj: Optional[dict]) -> bool:
    """A standalone dosai methods slice has a nested ``CallGraph`` and/or
    ``ApiEndpoints``/``Dependencies``."""
    if not isinstance(obj, dict):
        return False
    return any(k in obj for k in ("CallGraph", "ApiEndpoints", "Dependencies", "MethodCalls"))


def split_dosai_report(report: Optional[dict]) -> tuple[Optional[dict], Optional[dict]]:
    """Split a dosai report into ``(dataflows, methods)``.

    Handles both shapes:
    - combined: ``report["dataflows"]`` / ``report["methods"]`` (each may be
      missing/empty if dosai produced only one artifact).
    - standalone: a single native slice, classified by its keys into either
      slot (the other slot is ``None``).
    """
    if not isinstance(report, dict):
        return None, None
    if "dataflows" in report or "methods" in report:
        df = report.get("dataflows")
        mt = report.get("methods")
        return (df if isinstance(df, dict) else None, mt if isinstance(mt, dict) else None)
    # standalone
    if _looks_like_dataflows(report):
        return report, None
    if _looks_like_methods(report):
        return None, report
    return None, None


# ---------------------------------------------------------------------------
# Transparency facts: exploit chains, exposure tiers, sanitized flows, services
# ---------------------------------------------------------------------------

# Entry-point exposure classes dosai derives (Transparency.cs), most exposed
# first. A class that is not listed ranks after every listed one.
EXPOSURE_ORDER = (
    "anonymous-http",
    "anonymous-rpc",
    "authenticated-http",
    "authenticated-rpc",
    "queue",
    "mcp",
    "cli",
)

# Key added to every atom-shaped flow that carries dosai transparency facts.
# The reachability engine and the explainer read only ``flows`` and ``purls``
# from a reachables flow, so the extra key is ignored by them and can grow
# without a change to the slice readers.
DOSAI_FLOW_KEY = "dosai"


def exposure_rank(exposure: Optional[str]) -> int:
    """Rank an exposure class, lower is more exposed; unknown classes sort last."""
    try:
        return EXPOSURE_ORDER.index(exposure or "")
    except ValueError:
        return len(EXPOSURE_ORDER)


def _most_exposed(exposures: Iterable[Optional[str]]) -> Optional[str]:
    """Return the most exposed class among ``exposures``, or ``None`` when empty."""
    found = [e for e in exposures if isinstance(e, str) and e]
    return min(found, key=exposure_rank) if found else None


def _route_key(method: Optional[str], route: Optional[str]) -> tuple:
    """Key an HTTP route so the spellings dosai uses in different sections meet:
    ``ApiEndpoints[].Route`` omits the leading slash that ``Path`` and
    ``AttackSurface`` rows carry."""
    path = (route or "").strip()
    if path and not path.startswith("/"):
        path = "/" + path
    return ((method or "").upper(), path)


def _line_key(file_name: Optional[str], line) -> tuple:
    """Case-insensitive base name plus line, the way a sanitizer location is
    compared with a data-flow node location."""
    base = os.path.basename(str(file_name or "").replace("\\", "/")).lower()
    try:
        return (base, int(line or 0))
    except (TypeError, ValueError):
        return (base, 0)


class _TransparencyContext:
    """Lookup tables built once per report from the dosai transparency sections.

    ``ExploitChains``, ``AttackSurface`` and ``SanitizedFlows`` come from the
    ``dataflows`` command, ``Services`` (with ``TrustZone``) from ``methods``.
    Any section may be absent in an older dosai report; every table is then
    simply empty and callers get no annotation.
    """

    def __init__(self, dataflows: Optional[dict], methods: Optional[dict]):
        dataflows = dataflows if isinstance(dataflows, dict) else {}
        methods = methods if isinstance(methods, dict) else {}
        self.chains: List[dict] = [
            c for c in (dataflows.get("ExploitChains") or []) if isinstance(c, dict)
        ]
        self.sanitized_flows: List[dict] = [
            f for f in (dataflows.get("SanitizedFlows") or []) if isinstance(f, dict)
        ]
        self.attack_surface: List[dict] = [
            g for g in (dataflows.get("AttackSurface") or []) if isinstance(g, dict)
        ]
        self.services: List[dict] = [
            s for s in (methods.get("Services") or []) if isinstance(s, dict)
        ]
        self.entry_exposure: Dict[str, str] = {}
        self.route_exposure: Dict[tuple, str] = {}
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
                    if entry.get("EntryPointId"):
                        self._route_by_entry[entry["EntryPointId"]] = entry["Route"]
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
        self.trust_zone_by_route: Dict[tuple, dict] = {}
        for service in self.services:
            zone = service.get("TrustZone")
            if not zone:
                continue
            for op in service.get("Operations") or []:
                if not isinstance(op, dict):
                    continue
                path = op.get("Path") or op.get("RouteTemplate") or op.get("Name")
                if path:
                    self.trust_zone_by_route[_route_key(op.get("HttpMethod"), path)] = {
                        "trustZone": zone,
                        "serviceId": service.get("Id"),
                    }
        self.sanitizers_nearby: Dict[str, List[dict]] = self._match_sanitizers(dataflows)

    def _match_sanitizers(self, dataflows: dict) -> Dict[str, List[dict]]:
        """Map a slice id to the sanitized flows recorded next to it.

        ``SanitizedFlows`` is dosai's negative evidence: traces a sanitizer
        expression or validation guard stopped. Dosai emits no slice for a
        trace it sanitized, and a category-scoped sanitizer (``HtmlEncode``)
        lists no taint kinds, so a sanitized flow says nothing that would
        justify dropping a slice. It is matched only to annotate: a flow is
        near a slice when the two share a node and the sanitizer sits on the
        slice's path (same file and line as one of its nodes).
        """
        if not self.sanitized_flows:
            return {}
        nodes = {
            n["Id"]: n
            for n in (dataflows.get("Nodes") or [])
            if isinstance(n, dict) and n.get("Id")
        }
        matched: Dict[str, List[dict]] = {}
        for sl in dataflows.get("Slices") or []:
            if not isinstance(sl, dict) or not sl.get("Id"):
                continue
            node_ids = [nid for nid in (sl.get("NodeIds") or []) if isinstance(nid, str)]
            node_set = set(node_ids)
            node_locations = {
                _line_key(_node_file(nodes[nid]), nodes[nid].get("LineNumber"))
                for nid in node_ids
                if nid in nodes
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
        """The ``dosai`` flow key for one data-flow slice, or ``None`` when the
        report carries no transparency facts for it."""
        slice_id = sl.get("Id")
        chains = self.chains_by_slice.get(slice_id, []) if slice_id else []
        nearby = self.sanitizers_nearby.get(slice_id, []) if slice_id else []
        if not chains and not nearby:
            return None
        annotation: dict = {
            "sliceId": slice_id,
            "exposure": _most_exposed(c.get("Exposure") for c in chains),
            "exploitChains": [self._compact_chain(c) for c in chains],
        }
        if nearby:
            annotation["sanitizersNearby"] = sorted(nearby, key=lambda n: str(n["id"]))
        return annotation

    def _compact_chain(self, chain: dict) -> dict:
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
        """The ``dosai`` flow key for a ``PackageReachability`` entry: the
        exposure of the entry points and exploit chains that reach it."""
        slice_ids = [s for s in (pr.get("SliceIds") or []) if isinstance(s, str)]
        exposures = [self.entry_exposure.get(e) for e in (pr.get("EntryPointIds") or [])]
        chain_ids: List[str] = []
        for sid in slice_ids:
            for chain in self.chains_by_slice.get(sid, []):
                exposures.append(chain.get("Exposure"))
                if chain.get("Id") and chain["Id"] not in chain_ids:
                    chain_ids.append(chain["Id"])
        exposure = _most_exposed(exposures)
        if not exposure and not chain_ids:
            return None
        return {"exposure": exposure, "exploitChainIds": sorted(chain_ids)}

    def endpoint_annotation(self, endpoint: dict) -> Optional[dict]:
        """The ``dosai`` flow key for an ``ApiEndpoints`` entry: its exposure
        tier and the trust zone of the service that owns the route."""
        route = endpoint.get("Route") or endpoint.get("Path")
        if not route:
            return None
        key = _route_key(endpoint.get("HttpMethod"), route)
        annotation: dict = {}
        if key in self.route_exposure:
            annotation["exposure"] = self.route_exposure[key]
        zone = self.trust_zone_by_route.get(key)
        if zone:
            annotation.update(zone)
        return annotation or None

    def facts(self) -> dict:
        """Compact transparency facts for the native-reachability sidecar."""
        return {
            "exploit_chains": [self._compact_chain(c) | {"sliceId": c.get("SliceId")} for c in self.chains],
            "attack_surface": [
                {
                    "exposure": g.get("Exposure"),
                    "entry_point_count": g.get("EntryPointCount", 0),
                    "exploit_chain_count": g.get("ExploitChainCount", 0),
                    "weakness_count": g.get("WeaknessCount", 0),
                    "high_severity_weakness_count": g.get("HighSeverityWeaknessCount", 0),
                }
                for g in self.attack_surface
            ],
            "sanitized_flows": [
                {
                    "id": f.get("Id"),
                    "kind": f.get("Kind"),
                    "sanitizer": f.get("SanitizerSymbol") or f.get("SanitizerCategory"),
                    "source_ids": list(f.get("SourceIds") or []),
                    "file": f.get("FileName"),
                    "line": f.get("LineNumber"),
                }
                for f in self.sanitized_flows
            ],
            "sanitizers_nearby": {
                slice_id: [n["id"] for n in nearby]
                for slice_id, nearby in sorted(self.sanitizers_nearby.items())
            },
            "services": [
                {
                    "id": s.get("Id"),
                    "name": s.get("Name"),
                    "kind": s.get("ServiceKind"),
                    "direction": s.get("Direction"),
                    "trust_zone": s.get("TrustZone"),
                    "crosses_trust_boundary": s.get("CrossesTrustBoundary"),
                }
                for s in self.services
            ],
        }


# ---------------------------------------------------------------------------
# Native reachability extraction (the source of truth) -- Gate 3
# ---------------------------------------------------------------------------


def _confidence_for_kind(kind: Optional[str]) -> str:
    return _KIND_TO_CONFIDENCE.get(kind or "", "Low")


def _conf_rank(conf: Optional[str]) -> int:
    return _CONF_RANK.get((conf or "").capitalize(), 0)


def _is_source_file(path: Optional[str]) -> bool:
    return bool(path) and bool(_DOSAI_SOURCE_EXT_RE.search(str(path)))


def _extract_source_locations(pr: dict) -> List[str]:
    """Return ``file#line`` occurrence strings from a PackageReachability entry,
    keeping only source-file locations (.cs/.vb/.fs/.r). Mirrors cdxgen's
    ``dosaiSourceLocation`` source-only filter."""
    out: List[str] = []
    for sl in pr.get("SourceLocations", []) or []:
        if not isinstance(sl, dict):
            continue
        path = sl.get("Path") or sl.get("FileName")
        if not _is_source_file(path):
            continue
        line = sl.get("LineNumber")
        if line and int(line or 0) > 0:
            out.append(f"{path}#{line}")
        elif path and path not in out:
            out.append(path)
    return out


def extract_native_reachability(report, bom_index: Optional[Dict[str, str]] = None) -> dict:
    """Extract dosai's native reachability facts (the source of truth).

    These are consumed directly for the reachability verdict and for advanced
    analysis (weakness candidates, dangerous-API reachability). The atom
    projection (:func:`convert_dosai_report`) is a *derived* rendering of the
    same facts for the existing engine + explainer.

    Returns::

        {
          "reached_purls": { purl: {"confidence": str, "kind": str,
                                    "sources": [str, ...]} },
          "reached_services": { purl: True },   # purls reaching a service sink
          "weakness_candidates": [ ... ],       # pass-through (CWE-tagged)
          "dangerous_api_reachability": [ ... ],# pass-through
          "source_locations": { purl: [str, ...] },
          "exploit_chains": [ ... ],            # compact chains with exposure
          "attack_surface": [ ... ],            # per-exposure rollups
          "sanitized_flows": [ ... ],           # negative evidence
          "sanitizers_nearby": { slice: [ids] },# sanitized flows beside a slice
          "services": [ ... ],                  # inbound/outbound with trust zone
        }

    ``reached_purls`` includes every purl whose dosai ``Reachable`` is true; the
    highest-confidence fact wins when the same purl appears in both the
    dataflows and methods slices (dataflows is authoritative for call/dataflow
    evidence). ``ReachabilityKind`` ``DataFlowNode``/``CallGraphEdge`` => High
    (call/dataflow evidence); ``Dependency`` => Low (import/lockfile only).

    Sanitized flows never remove a package from the reached set: dosai emits
    no slice for a trace it sanitized, so a slice that is present was not
    stopped. A reached purl carries the ``exposure`` tier of the entry points
    that reach it and the ids of its exploit chains.
    """
    bom_index = bom_index or {}
    dataflows, methods = split_dosai_report(report)
    ctx = _TransparencyContext(dataflows, methods)
    reached: Dict[str, dict] = {}
    source_locations: Dict[str, List[str]] = {}

    # dataflows first (higher fidelity), then methods (Dependency-level). When
    # the same purl appears in both, keep the higher-confidence fact.
    for src in (dataflows, methods):
        if not isinstance(src, dict):
            continue
        for pr in src.get("PackageReachability", []) or []:
            if not isinstance(pr, dict):
                continue
            raw = pr.get("Purl")
            if not raw:
                continue
            purl = reconcile_purl(raw, bom_index)
            if not purl:
                continue
            # Only reachable packages contribute facts. NOTE: Dependency-kind
            # entries ARE included here (Low confidence) as a superset for
            # advanced analysis, but are deliberately EXCLUDED from the atom
            # projection's verdict flows (see _emit_reachability_flows) because
            # import/lockfile-only evidence is too weak to call "reachable".
            # Consumers of this facts sidecar must not treat Low/Dependency
            # entries as verdict-reachable.
            if not pr.get("Reachable"):
                continue
            kind = pr.get("ReachabilityKind") or "Dependency"
            confidence = (pr.get("Confidence") or _confidence_for_kind(kind)).capitalize()
            sources = _extract_source_locations(pr)
            if sources:
                source_locations.setdefault(purl, [])
                for s in sources:
                    if s not in source_locations[purl]:
                        source_locations[purl].append(s)
            existing = reached.get(purl)
            if existing is None or _conf_rank(confidence) > _conf_rank(existing.get("confidence")):
                fact = {"confidence": confidence, "kind": kind, "sources": sources}
                fact.update(ctx.package_annotation(pr) or {})
                reached[purl] = fact

    # reached_services: purls that reach a mapped service sink category.
    reached_services: Dict[str, bool] = {}
    if isinstance(dataflows, dict):
        for sl in dataflows.get("Slices", []) or []:
            if not isinstance(sl, dict):
                continue
            cat = sl.get("SinkCategory") or ""
            if cat not in DOSAI_CATEGORY_TO_SERVICE_TAG:
                continue
            for raw in (sl.get("Purls") or []) + [sl.get("SinkPurl")]:
                purl = reconcile_purl(raw, bom_index) if raw else None
                if purl:
                    reached_services[purl] = True

    weakness = []
    dangerous = []
    if isinstance(dataflows, dict):
        weakness = [w for w in (dataflows.get("WeaknessCandidates") or []) if isinstance(w, dict)]
        dangerous = [
            d for d in (dataflows.get("DangerousApiReachability") or []) if isinstance(d, dict)
        ]

    facts = {
        "reached_purls": reached,
        "reached_services": reached_services,
        "weakness_candidates": weakness,
        "dangerous_api_reachability": dangerous,
        "source_locations": source_locations,
    }
    facts.update(ctx.facts())
    return facts


# ---------------------------------------------------------------------------
# Atom-shaped slice emission (the projection) -- Gate 4
# ---------------------------------------------------------------------------


def _flow_identity(flow: dict) -> bytes:
    """Stable identity hash for dedup (mirrors reachability._flow_identity)."""
    return hashlib.md5(
        json.dumps(flow, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).digest()


def _build_node_tags(
    purl: Optional[str],
    category: str,
    rule_name: str,
    service_tag: Optional[str] = None,
) -> str:
    """Compose the per-node ``tags`` comma-string.

    Format: ``"<versioned-purl>, <service-tag>, dotnet, <rule/category>"``.

    The token IMMEDIATELY after the purl is the service tag (when one applies)
    so ``SemanticReachability._flow_service_purls`` positional association
    attributes the service to THIS purl. A standalone ``dotnet`` language token
    is always present so ``explainer.is_analyzer_slice`` relaxes the node-count
    gates for honest 2-node dosai flows.
    """
    parts: List[str] = []
    if purl:
        parts.append(purl)
    if service_tag is None:
        service_tag = DOSAI_CATEGORY_TO_SERVICE_TAG.get(category or "")
    if service_tag:
        parts.append(service_tag)
        if category and category != service_tag:
            parts.append(category)
    # standalone language token (always present, mirrors golem/rusi)
    parts.append(DOSAI_LANG_TOKEN)
    if rule_name:
        parts.append(rule_name)
    return ", ".join(parts)


def _node_label(node: dict, idx: int, last_idx: int, is_external: bool) -> str:
    """Map a dosai node's role to an atom label the explainer renders well.

    ``CALL`` for external dependency calls, ``METHOD_PARAMETER_IN`` for the
    first node of a slice, ``RETURN`` for the last, ``IDENTIFIER`` otherwise.
    Source/sink roles (``IsSource``/``IsSink``) override when set.
    """
    if is_external:
        return "CALL"
    if node.get("IsSource"):
        return "METHOD_PARAMETER_IN"
    if node.get("IsSink"):
        return "RETURN"
    if idx == 0:
        return "METHOD_PARAMETER_IN"
    if idx == last_idx:
        return "RETURN"
    return "IDENTIFIER"


def _node_parent_method(node: dict) -> str:
    """Build a ``ClassName.MethodName`` parent-method string for a node."""
    cls = node.get("ClassName") or node.get("Namespace") or ""
    method = node.get("MethodName") or node.get("Name") or ""
    if cls and method:
        return f"{cls}.{method}"
    return method or cls


def _node_file(node: dict) -> str:
    return node.get("Path") or node.get("FileName") or ""


def _resolve_node_purl(node: dict, bom_index: Dict[str, str]) -> Optional[str]:
    """Resolve a node's purl from the node itself (``Purl``) or its module
    identity. Returns a reconciled BOM purl or ``None``."""
    return reconcile_purl(node.get("Purl"), bom_index)


def _make_node(
    node_id: str,
    node: dict,
    *,
    purl: Optional[str],
    category: str,
    rule_name: str,
    idx: int,
    last_idx: int,
    is_external: bool,
) -> dict:
    label = _node_label(node, idx, last_idx, is_external)
    pos_line = int(node.get("LineNumber") or 0)
    pos_col = int(node.get("ColumnNumber") or 0)
    return {
        "id": node_id,
        "tags": _build_node_tags(purl, category, rule_name),
        "code": node.get("Symbol") or node.get("Name") or node.get("Code") or "",
        "fullName": node.get("Symbol") or node.get("Name") or "",
        "lineNumber": pos_line,
        "columnNumber": pos_col,
        "parentFileName": _node_file(node),
        "label": label,
        "name": node.get("Symbol") or node.get("Name") or "",
        "parentMethodName": _node_parent_method(node),
        "isExternal": is_external,
    }


def _emit_slice_flows(
    dataflows: dict,
    nodes_by_id: Dict[str, dict],
    bom_index: Dict[str, str],
    ctx: Optional[_TransparencyContext] = None,
) -> List[dict]:
    """Emit one atom flow per dosai ``dataflows.Slices[]`` entry (taint witness).

    Walks ``NodeIds`` in order to build an atom node path; reconciles slice +
    node purls. Source-file locations only.

    A flow carries the ``dosai`` key with its exploit chains, entry-point
    exposure tier and the sanitized flows recorded beside it
    (``sanitizersNearby``) when the report has them. The annotation never
    changes ``purls``: dosai emits no slice for a trace it sanitized.
    """
    flows: List[dict] = []
    for sl in dataflows.get("Slices", []) or []:
        if not isinstance(sl, dict):
            continue
        flow_purls: set = set()
        for raw in (sl.get("Purls") or []) + [sl.get("SinkPurl"), sl.get("SourcePurl")]:
            vp = reconcile_purl(raw, bom_index) if raw else None
            if vp:
                flow_purls.add(vp)
        if not flow_purls:
            continue
        sink_category = sl.get("SinkCategory") or ""
        rule_name = sl.get("Summary") or sl.get("Id") or "dataflow"
        node_ids = sl.get("NodeIds", []) or []
        last_idx = len(node_ids) - 1
        flow_nodes: List[dict] = []
        for idx, nid in enumerate(node_ids):
            node = nodes_by_id.get(nid) or {"Id": nid}
            node_purl = _resolve_node_purl(node, bom_index)
            if node_purl:
                flow_purls.add(node_purl)
            # Deterministic fallback purl for an internal (purl-less) witness
            # node: sorted()[0], NOT next(iter(set)) -- set iteration order is
            # PYTHONHASHSEED-dependent and would make the emitted slice bytes
            # (and dedup identity) vary across processes.
            tag_purl = node_purl or (sorted(flow_purls)[0] if flow_purls else None)
            is_external = bool(node_purl)
            flow_nodes.append(
                _make_node(
                    nid,
                    node,
                    purl=tag_purl,
                    category=sink_category,
                    rule_name=rule_name,
                    idx=idx,
                    last_idx=last_idx,
                    is_external=is_external,
                )
            )
        if not flow_nodes:
            continue
        flow: Dict[str, Any] = {"flows": flow_nodes, "purls": sorted(flow_purls)}
        annotation = ctx.slice_annotation(sl) if ctx else None
        if annotation:
            flow[DOSAI_FLOW_KEY] = annotation
        flows.append(flow)
    return flows


def _emit_reachability_flows(
    dataflows: dict,
    methods: dict,
    bom_index: Dict[str, str],
    ctx: Optional[_TransparencyContext] = None,
) -> List[dict]:
    """Emit an honest 2-node flow per native-reachable PackageReachability entry
    whose ``ReachabilityKind`` is call/dataflow evidence
    (``CallGraphEdge``/``DataFlowNode``).

    This is the PRIMARY reachability signal: dosai already tells us the package
    is reachable, so this flow always renders (even when no dataflow slice
    formed). The sink node carries a real source location from
    ``SourceLocations[]`` so the explainer shows a meaningful file:line. Both
    dataflows and methods PackageReachability are covered (deduped by purl).
    """
    flows: List[dict] = []
    seen_purls: set = set()
    for src in (dataflows, methods):
        if not isinstance(src, dict):
            continue
        for pr in src.get("PackageReachability", []) or []:
            if not isinstance(pr, dict):
                continue
            if not pr.get("Reachable"):
                continue
            kind = pr.get("ReachabilityKind") or "Dependency"
            if kind not in ("CallGraphEdge", "DataFlowNode"):
                continue  # Dependency-only is too weak to render a flow
            raw = pr.get("Purl")
            if not raw:
                continue
            purl = reconcile_purl(raw, bom_index)
            if not purl or purl in seen_purls:
                continue
            seen_purls.add(purl)
            sources = _extract_source_locations(pr)
            sink = sources[0] if sources else ""
            sink_file = sink.split("#")[0] if sink else ""
            sink_line = 0
            if "#" in sink:
                try:
                    sink_line = int(sink.split("#", 1)[1])
                except ValueError:
                    sink_line = 0
            cat = next((c for c in (pr.get("Categories") or []) if isinstance(c, str)), "")
            category = cat or "reachability"
            rule = f"{kind}"
            flow_hash = hashlib.md5(purl.encode("utf-8")).hexdigest()[:16]
            source_node = {
                "id": f"dosai-pr-src-{flow_hash}",
                "tags": _build_node_tags(None, category, rule),
                "code": "reachable package",
                "fullName": "",
                "lineNumber": 0,
                "columnNumber": 0,
                "parentFileName": sink_file,
                "label": "IDENTIFIER",
                "name": "reachable package",
                "parentMethodName": "",
                "isExternal": False,
            }
            sink_node = {
                "id": f"dosai-pr-{flow_hash}",
                "tags": _build_node_tags(purl, category, rule),
                "code": purl,
                "fullName": purl,
                "lineNumber": sink_line,
                "columnNumber": 0,
                "parentFileName": sink_file,
                "label": "CALL",
                "name": purl.rsplit("/", 1)[-1].split("@")[0],
                "parentMethodName": "",
                "isExternal": True,
            }
            flow: Dict[str, Any] = {"flows": [source_node, sink_node], "purls": [purl]}
            annotation = ctx.package_annotation(pr) if ctx else None
            if annotation:
                flow[DOSAI_FLOW_KEY] = annotation
            flows.append(flow)
    return flows


def _emit_endpoint_flows(
    methods: dict, bom_index: Dict[str, str], ctx: Optional[_TransparencyContext] = None
) -> List[dict]:
    """Emit one flow per dosai ``methods.ApiEndpoints[]`` entry (endpoint
    reachability). Each endpoint becomes a single-node flow tagged with the
    ``api`` service tag so ``reached_services`` picks it up."""
    if not isinstance(methods, dict):
        return []
    flows: List[dict] = []
    for ep in methods.get("ApiEndpoints", []) or []:
        if not isinstance(ep, dict):
            continue
        route = ep.get("Route") or ep.get("Path") or ""
        if not route:
            continue
        # The endpoint handler itself; attribute the framework crate purl if
        # discoverable, otherwise emit an endpoint-only flow (no purl).
        handler_purl = None
        for raw in ep.get("Purls") or []:
            handler_purl = reconcile_purl(raw, bom_index) if raw else None
            if handler_purl:
                break
        method = ep.get("HttpMethod") or ""
        path = ep.get("Path") or ep.get("FileName") or ""
        line = int(ep.get("LineNumber") or 0)
        col = int(ep.get("ColumnNumber") or 0)
        handler = _node_parent_method(ep)
        rule = "endpoint"
        flow_hash = hashlib.md5((method + "|" + route).encode("utf-8")).hexdigest()[:16]
        node = {
            "id": f"dosai-ep-{flow_hash}",
            "tags": _build_node_tags(
                handler_purl, "endpoint", rule, service_tag=DOSAI_ENDPOINT_SERVICE_TAG
            ),
            "code": f"{method} {route}".strip(),
            "fullName": handler,
            "lineNumber": line,
            "columnNumber": col,
            "parentFileName": path,
            "label": "CALL",
            "name": route,
            "parentMethodName": handler,
            "isExternal": True,
        }
        flow: Dict[str, Any] = {
            "flows": [node],
            "purls": [handler_purl] if handler_purl else [],
        }
        annotation = ctx.endpoint_annotation(ep) if ctx else None
        if annotation:
            flow[DOSAI_FLOW_KEY] = annotation
        flows.append(flow)
    return flows


def convert_dosai_report(report, bom_index: Optional[Dict[str, str]] = None) -> List[dict]:
    """Convert a parsed dosai report into an atom-shaped reachables slice list.

    Emits three kinds of flows (all atom-shaped ``{"flows": [...], "purls":
    [...]}``):

      1. **Dataflow slice flows** -- one per ``dataflows.Slices[]`` (taint
         witness). Richest evidence.
      2. **Reachability flows** -- one 2-node flow per native-reachable
         ``PackageReachability[]`` entry with call/dataflow evidence. This is the
         PRIMARY signal and always renders for a reachable package.
      3. **Endpoint flows** -- one per ``methods.ApiEndpoints[]``.

    Every native-reachable purl (``Reachable==true`` with kind
    ``DataFlowNode``/``CallGraphEdge``) appears in at least one flow's ``purls``,
    so the existing engine's ``reached_purls`` loop picks them up unchanged.

    Flows carry an optional ``dosai`` key (exploit chains, exposure tier,
    trust zone, sanitizers nearby); see :data:`DOSAI_FLOW_KEY`.

    Deterministic: flows deduped by identity, then sorted by (purls, first-node
    id) -- mirrors golem/rusi.
    """
    bom_index = bom_index or {}
    dataflows, methods = split_dosai_report(report)
    dataflows = dataflows or {}
    methods = methods or {}

    # node index for dataflows (flat Nodes) and methods (nested CallGraph.Nodes)
    df_nodes: Dict[str, dict] = {}
    for n in dataflows.get("Nodes") or []:
        if isinstance(n, dict):
            nid = n.get("Id")
            if nid:
                df_nodes[nid] = n
    cg = methods.get("CallGraph") or {}
    cg_nodes: Dict[str, dict] = {}
    for n in cg.get("Nodes") or []:
        if isinstance(n, dict):
            nid = n.get("Id")
            if nid:
                cg_nodes[nid] = n
    # merge; dataflows nodes take precedence for slice walking
    nodes_by_id = {**cg_nodes, **df_nodes}

    ctx = _TransparencyContext(dataflows, methods)
    flows: List[dict] = []
    flows.extend(_emit_slice_flows(dataflows, nodes_by_id, bom_index, ctx))
    flows.extend(_emit_reachability_flows(dataflows, methods, bom_index, ctx))
    flows.extend(_emit_endpoint_flows(methods, bom_index, ctx))

    # dedup identical flows by identity, then sort for determinism
    seen: set = set()
    unique: List[dict] = []
    for f in flows:
        ident = _flow_identity(f)
        if ident in seen:
            continue
        seen.add(ident)
        unique.append(f)
    unique.sort(key=lambda f: (tuple(f.get("purls", [])), _sort_key_flows(f.get("flows", []))))
    return unique


def _sort_key_flows(flows: List[dict]) -> str:
    if not flows:
        return ""
    return str(flows[0].get("id", ""))


def write_slices_file(slice_path: str, flows: List[dict]) -> None:
    """Write the atom-shaped slice list atomically and deterministically.

    Mirrors golem/rusi ``write_slices_file``: split into batches of 1000 flows
    (``<base>-<n>.slices.json``) when the list exceeds 1000 so no single slice
    file grows unbounded; the primary file gets the first batch.
    """
    out_dir = os.path.dirname(os.path.abspath(slice_path)) or "."
    os.makedirs(out_dir, exist_ok=True)
    if len(flows) <= 1000:
        _write_json_atomic(slice_path, flows)
        return
    base, ext = os.path.splitext(slice_path)
    for i, start in enumerate(range(0, len(flows), 1000), start=1):
        batch = flows[start : start + 1000]
        path = slice_path if i == 1 else f"{base}-{i}{ext or '.json'}"
        _write_json_atomic(path, batch)


def _write_json_atomic(path: str, payload) -> None:
    data = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fp:
        fp.write(data)
    os.replace(tmp, path)
