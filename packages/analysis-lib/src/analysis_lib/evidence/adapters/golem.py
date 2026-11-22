"""golem (Go Source Inspector) report -> evidence records.

This module is the only code that knows the golem report format: a
lowerCamelCase JSON object whose ``schemaVersion`` is a URL ending in the
``v<major>[.<minor>]`` schema version, carrying ``tool``/``runtime``,
``modules``, a ``callGraph`` and a ``dataFlow``.

Four kinds of evidence become records:

1. Dataflow slices (``dataFlow.slices[]``) become ``reached-flow`` records
   whose ``path`` is the slice's witness nodes in golem's order. A slice
   golem marked ``reachableFromRoots: false`` on a dispatch-aware graph
   lives in code the application never drives into and is not recorded.
2. Call-graph edges whose target resolves to a BOM dependency become
   ``reached-flow`` records with the caller-to-callee two-node path. On the
   dispatch-aware graph golem stamps ``reachablePackages`` with, edges into
   packages that graph never reaches through non-init code are import
   plumbing, not reachability evidence, and are not recorded. The gate is
   per package: an edge whose target node alone is marked unreachable from
   the roots is still recorded, with golem's per-node ``reachableFromRoots``
   kept in its attributes.
3. ``callGraph.reachability.paths[]``, the witness paths golem computes for
   symbols requested with ``--reachable-symbols``, become ``reached-flow``
   records whose ``path`` is the call stack from a root to the symbol.
4. ``usages[]`` become ``usage`` records and ``apiEndpoints[]`` become
   ``entry-point`` records.

A golem purl is reconciled onto a BOM component through three forms (exact,
version-stripped, subpath+version-stripped), mirroring cdxgen's
``createPurlAliasMap``; Go module paths are literal, so no ``-``/``_``
normalization happens. Edges and usages into the standard library or the
workspace's own module are not dependency evidence and make no record.
Every other report object that makes no record (one that names only
packages the BOM does not carry, an unrooted slice, an edge into an
unreached package, an entry that is not a JSON object) is counted in one
``record-skipped`` caveat per reason.

File paths are relative to the analysed directory golem names
(``options.directory``) or the caller's source root; a file in another
module's directory is spelled ``<module>@<version>/<file>``, a file in the
Go module cache by its cache path, and any other absolute path is left out
with a ``location-outside-root`` caveat. Record ids leave out golem's own
object ids, which golem derives from absolute file names, so the same
report produced in another directory gives the same ids.

Golem's own budget markers travel with the records: a ``sliceReachability``
run that only came back ``partial``, and the dataflow truncation fields,
land as ``budget`` caveats on the producer result and on every record, since
either can hide evidence anywhere in the report.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

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

#: The report schema major this adapter reads, and the newest minor it
#: knows. golem's schema version is a URL whose last segment is
#: ``v<major>[.<minor>]``.
SUPPORTED_MAJOR = 6
KNOWN_MINOR = 0

#: golem reports are detected by SHAPE, not ``schemaVersion``: a JSON object
#: carrying its producer identity (``tool``/``runtime``) alongside at least
#: one analysis section this module consumes (``callGraph``/``dataFlow``).
#: golem JSON uses lowerCamelCase keys, unlike rusi's snake_case, which
#: reliably separates a golem report from an atom semantics slice sharing
#: the same path.
PRODUCER_NAME = "golem"
GOLEM_PRODUCER_KEYS = ("tool", "runtime")
GOLEM_SECTION_KEYS = ("callGraph", "dataFlow")

# golem dataflow source/sink categories -> dep-scan SERVICE_TAGS vocabulary
# (config.py). Conservative mapping: only categories whose intent clearly
# maps to an existing service tag.
GOLEM_CATEGORY_TO_SERVICE_TAG = {
    # sinks
    "sql-query": "sql",
    "sql-injection": "sql",
    "network-request": "http",
    "network-connect": "http",
    "html-response": "web",
    "command-execution": "rpc",
    "process-execution": "rpc",
    # sources
    "http-request": "http",
    "http-parameter": "http",
}

# Service tag for HTTP api_endpoint handler records; ``api`` is a SERVICE_TAG
# so SemanticReachability attributes the handler purl to reached_services.
GOLEM_ENDPOINT_SERVICE_TAG = "api"

# Call graphs whose "unreachable" the adapter may act on. golem computes the
# slice verdicts on RTA and falls back to CHA only when RTA panics; both
# follow interface and func-value dispatch. Static and VTA graphs miss that
# dispatch, so a "false" from them is not evidence that code is unused.
SOUND_REACHABILITY_ALGORITHMS = frozenset({"rta", "cha"})


def is_golem_report(report) -> bool:
    """True when ``report`` has the structural shape of a golem report."""
    if not isinstance(report, dict):
        return False
    has_producer = any(isinstance(report.get(k), dict) for k in GOLEM_PRODUCER_KEYS)
    has_section = any(isinstance(report.get(k), dict) for k in GOLEM_SECTION_KEYS)
    return has_producer and has_section


# ---------------------------------------------------------------------------
# Purl parsing + reconciliation (mirrors cdxgen's createPurlAliasMap)
# ---------------------------------------------------------------------------


def _purl_without_version(purl: Optional[str]) -> str:
    """Strip version, subpath, and qualifiers from a purl.

    For ``pkg:golang/github.com/foo/bar@v1.2.3#internal/baz`` this returns
    ``pkg:golang/github.com/foo/bar``, the bare module purl the Go BOM
    indexes at module granularity.
    """
    if not purl:
        return ""
    return purl.split("?")[0].split("#")[0].split("@")[0]


def build_bom_purl_index(
    bom_components: Optional[Iterable[dict]],
    extra_components: Optional[Iterable[dict]] = None,
) -> Dict[str, str]:
    """Build a multi-form ``alias-purl -> versioned-purl`` index from a Go BOM.

    For each Go BOM component the index stores the exact versioned purl and
    the version-stripped purl, so a golem package-level
    ``pkg:golang/foo/bar@v1.2.3#internal/baz`` matches a BOM
    ``pkg:golang/foo/bar@v1.2.3`` through the version+subpath-stripped form.
    No ``-``/``_`` normalization is performed: Go module paths are literal.
    ``extra_components`` accepts the metadata.component root, so the
    versioned workspace purl is always in the index.
    """
    index: Dict[str, str] = {}
    for c in list(bom_components or []) + list(extra_components or []):
        if not isinstance(c, dict):
            continue
        purl = c.get("purl", "")
        if not isinstance(purl, str) or not purl.startswith("pkg:golang/"):
            continue
        index.setdefault(purl, purl)
        no_version = _purl_without_version(purl)
        if no_version:
            index.setdefault(no_version, purl)
    return index


def reconcile_purl(golem_purl: Optional[str], bom_index: Dict[str, str]) -> Optional[str]:
    """Map a golem purl onto a BOM versioned purl, by exact and then
    version-stripped match.

    Non-golang, malformed and empty purls map to nothing, and so does a purl
    the BOM has no component for: an unmatched purl would only add noise. A
    standard-library purl never arrives here (golem marks it ``standard``
    with an empty purl, which maps to nothing).
    """
    if not isinstance(golem_purl, str) or not golem_purl.startswith("pkg:golang/"):
        return None
    if golem_purl in bom_index:
        return bom_index[golem_purl]
    no_version = _purl_without_version(golem_purl)
    if no_version and no_version in bom_index:
        return bom_index[no_version]
    return None


# ---------------------------------------------------------------------------
# Version gate
# ---------------------------------------------------------------------------


def _gate_version(report: dict) -> str:
    """The schema version text the gate can read: the tail of golem's
    ``schemaVersion`` URL, without its ``v`` prefix."""
    text = str(report.get("schemaVersion") or "").strip()
    tail = text.rsplit("/", 1)[-1]
    if tail.startswith("v"):
        tail = tail[1:]
    return tail


# ---------------------------------------------------------------------------
# Root-reachability helpers, and module path resolution
# ---------------------------------------------------------------------------


def _slice_reachability(df: dict) -> Optional[dict]:
    """golem's ``dataFlow.sliceReachability`` when its verdicts are usable.

    Returns the section only when it says the verdicts were computed on a
    graph in :data:`SOUND_REACHABILITY_ALGORITHMS`. Anything else, an older
    golem that stamped ``reachableFromRoots`` from whatever ``--callgraph``
    built, a library whose only roots are initializers, an unknown
    algorithm, yields nothing and the historical keep-everything behaviour.
    """
    sr = df.get("sliceReachability") if isinstance(df, dict) else None
    if not isinstance(sr, dict) or sr.get("status") not in ("computed", "partial"):
        return None
    algorithms = {a for a in str(sr.get("algorithm") or "").split(",") if a}
    if not algorithms or not algorithms <= SOUND_REACHABILITY_ALGORITHMS:
        return None
    return sr


def _reachable_package_set(sr: Optional[dict]) -> Optional[Set[str]]:
    """Packages golem's sound graph reaches through non-init code, or
    ``None`` when call-graph evidence must not be gated.

    Only a fully ``computed`` section qualifies: in a ``partial`` multi-module
    merge a skipped child (a library module) contributed no packages, and
    gating on the union would mark its genuinely used dependencies unreached.
    golem omits the list when it is empty, so a computed section without it
    is an empty set, not "unknown".
    """
    if not sr or sr.get("status") != "computed":
        return None
    return {p for p in as_list(sr.get("reachablePackages")) if isinstance(p, str)}


def _node_reachability(cg: dict) -> Dict[str, dict]:
    """Per-node root reachability from ``callGraph.reachability.nodes[]``.

    The result maps a call-graph node id to ``reachableFromRoots``,
    ``minDepth`` and ``rootIds`` as golem reported them, plus ``rootLabels``,
    the ``function`` text of each root. An older golem, or a library with no
    entry root, has no section and the map is empty: a missing entry means
    "not computed", never "unreachable".
    """
    reach = cg.get("reachability") if isinstance(cg, dict) else None
    if not isinstance(reach, dict):
        return {}
    root_labels = {
        r["id"]: r.get("function") or r["id"]
        for r in as_list(cg.get("roots"))
        if isinstance(r, dict) and as_hashable_str(r.get("id"))
    }
    out: Dict[str, dict] = {}
    for entry in as_list(reach.get("nodes")):
        if not isinstance(entry, dict) or not as_hashable_str(entry.get("nodeId")):
            continue
        root_ids = [r for r in as_list(entry.get("rootIds")) if isinstance(r, str)]
        info: dict = {"reachableFromRoots": bool(entry.get("reachableFromRoots"))}
        if isinstance(entry.get("minDepth"), int):
            info["minDepth"] = entry["minDepth"]
        info["rootIds"] = root_ids
        info["rootLabels"] = [root_labels.get(r, r) for r in root_ids]
        out[entry["nodeId"]] = info
    return out


def _build_module_path_index(
    report_modules: Optional[Iterable[dict]],
    bom_index: Dict[str, str],
) -> Dict[str, str]:
    """Build ``module.path -> reconciled BOM purl`` from golem's modules[].

    golem nodes and dataflow slices carry ``packagePath`` (a Go import path)
    rather than always a purl; the owning module is found by longest-prefix
    match against module paths.
    """
    index: Dict[str, str] = {}
    for mod in report_modules or []:
        if not isinstance(mod, dict):
            continue
        path = as_str(mod.get("path"))
        if not path:
            continue
        vpurl = reconcile_purl(mod.get("purl", ""), bom_index)
        if vpurl:
            index.setdefault(path, vpurl)
    return index


def _resolve_package_path(
    package_path: Optional[str],
    module_index: Dict[str, str],
) -> Optional[str]:
    """The reconciled BOM purl for a Go package path, by longest-prefix
    match against the module index."""
    if not package_path:
        return None
    best: Optional[str] = None
    best_len = 0
    for mod_path, vpurl in module_index.items():
        if package_path == mod_path or package_path.startswith(mod_path + "/"):
            if len(mod_path) > best_len:
                best = vpurl
                best_len = len(mod_path)
    return best


def _module_purl_from_obj(module_obj: Optional[dict], bom_index: Dict[str, str]) -> Optional[str]:
    """The reconciled purl of a golem ``module`` sub-object."""
    if not isinstance(module_obj, dict):
        return None
    return reconcile_purl(module_obj.get("purl", ""), bom_index)


def _is_main_module(node: dict) -> bool:
    """True when a golem node is the workspace app module."""
    mod = node.get("module")
    return isinstance(mod, dict) and bool(mod.get("main"))


# ---------------------------------------------------------------------------
# Record construction
# ---------------------------------------------------------------------------


def _pos_line(pos: Any) -> Optional[int]:
    return as_line(as_dict(pos).get("line"))


class _Locations:
    """Builds a record's locations and witness nodes through the report's
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

    def location(self, pos: Any, method: Optional[str]) -> Optional[EvidenceLocation]:
        file = self.file(as_dict(pos).get("filename"))
        if not file:
            return None
        return EvidenceLocation(file=file, line=_pos_line(pos), method=method or None)

    def caveats(self, base: List[EvidenceCaveat]) -> Tuple[EvidenceCaveat, ...]:
        if not self.left_out:
            return tuple(base)
        return tuple(base) + (self.paths.outside_root_caveat(len(self.left_out)),)


def _service_purls(pairs: List[Tuple[Optional[str], str]], flow_purls: Set[str]) -> List[str]:
    """Purls a record's category pairs mark as services.

    Each pair is a (purl, category) the producer stated on one object, the
    form the engine's positional tag walk attributes: the purl the category
    sits on carries the service when the category maps to one, and a
    category-mapped object that names no purl at all hands the service to
    the record's whole purl set, never to a neighbouring package.
    """
    out: Set[str] = set()
    for purl, category in pairs:
        if not GOLEM_CATEGORY_TO_SERVICE_TAG.get(category):
            continue
        if purl:
            out.add(purl)
        else:
            return sorted(flow_purls)
    return sorted(out)


def _parse_report(report) -> Tuple[Optional[Any], Optional[str]]:
    """The report as a parsed value, accepting JSON text as well as a
    parsed object."""
    if isinstance(report, (str, bytes)):
        try:
            return json.loads(report), None
        except ValueError as e:
            return None, f"the report is not valid JSON: {e}"
    return report, None


def _source_paths(report: dict, source_root: Optional[str]) -> SourcePaths:
    """The path mapping of one golem report: the analysed directory golem
    names (``options.directory``, else ``runtime.workingDir``) and the
    caller's source root as roots, and every non-main module directory as a
    ``<module>@<version>`` prefix."""
    options = as_dict(report.get("options"))
    runtime = as_dict(report.get("runtime"))
    roots = [options.get("directory"), runtime.get("workingDir"), source_root]
    for module in as_list(report.get("modules")):
        module = as_dict(module)
        if module.get("main"):
            roots.append(module.get("dir"))
    prefixes = []
    for module in as_list(report.get("modules")):
        module = as_dict(module)
        path, version = as_str(module.get("path")), as_str(module.get("version"))
        if module.get("main") or not path:
            continue
        label = f"{path}@{version}" if version else path
        prefixes.append((module.get("dir"), label))
    return SourcePaths(roots, prefixes)


@guard_extract(PRODUCER_NAME)
def extract(
    report,
    *,
    source: str,
    producer_version: str = "",
    bom_components: Optional[Iterable[dict]] = None,
    extra_components: Optional[Iterable[dict]] = None,
    source_root: Optional[str] = None,
) -> AdapterResult:
    """One golem report as evidence records.

    ``report`` is the parsed golem report or its JSON text. ``source`` is
    the scan-directory-relative file the report was read from.
    ``producer_version`` is the golem tool version when the caller knows it;
    the report's own ``tool.version`` is used otherwise. ``bom_components``
    and ``extra_components`` (the metadata.component root) feed the purl
    reconciliation index. ``source_root`` is the scanned source directory
    as the caller knows it; record paths are relative to it or to the
    directory golem names in the report, whichever holds the file. The
    result is the records, or not-assessed with the reason: a report that
    is not valid JSON, does not have the golem shape, names a schema major
    this adapter does not read, or has a section of an unexpected type is
    never read as a smaller report.
    """
    report, parse_error = _parse_report(report)
    if parse_error or not isinstance(report, dict):
        reason = parse_error or (
            f"the report is a {type(report).__name__}, not the golem report object"
        )
        return not_assessed(reason)
    if not is_golem_report(report):
        return not_assessed(
            "the report does not have the golem shape (tool/runtime identity "
            "plus a callGraph or dataFlow section); it was not assessed"
        )
    problem = _section_problem(report)
    if problem:
        return not_assessed(f"the golem report is malformed and was not assessed: {problem}")

    seen_version = as_str(report.get("schemaVersion")).strip()
    gate = gate_report_version(_gate_version(report), SUPPORTED_MAJOR, KNOWN_MINOR)
    if not gate.accepted:
        return not_assessed(
            f"the report schema version {seen_version or _gate_version(report)!r} is "
            f"not supported; this adapter reads golem schema major {SUPPORTED_MAJOR} reports"
        )
    report_caveats = list(gate.caveats)

    tool = as_dict(report.get("tool"))
    version = producer_version or as_str(tool.get("version")) or "unknown"
    report_schema_version = seen_version or "unknown"
    producer = EvidenceProducer(
        name=PRODUCER_NAME, version=version, report_schema_version=report_schema_version
    )

    # Budget markers golem stamped on the report as a whole. Either can hide
    # evidence anywhere, so both land on every record the adapter emits.
    budget_details: List[str] = []
    df = as_dict(report.get("dataFlow"))
    sr = as_dict(df.get("sliceReachability"))
    if sr.get("status") == "partial":
        detail = "golem's slice reachability came back partial"
        if sr.get("reason"):
            detail += f" ({sr['reason']})"
        budget_details.append(detail)
    stats = as_dict(df.get("stats"))
    if stats.get("truncated"):
        reasons = ", ".join(str(r) for r in as_list(stats.get("truncationReasons")))
        detail = "golem truncated the dataflow analysis"
        if reasons:
            detail += f" ({reasons})"
        budget_details.append(detail)
    budget_caveats = [EvidenceCaveat(kind="budget", detail=d) for d in budget_details]
    base_caveats = report_caveats + budget_caveats

    bom_index = build_bom_purl_index(bom_components, extra_components=extra_components)
    module_index = _build_module_path_index(as_list(report.get("modules")), bom_index)
    paths = _source_paths(report, source_root)

    cg = as_dict(report.get("callGraph"))
    cg_nodes = {
        n["id"]: n
        for n in as_list(cg.get("nodes"))
        if isinstance(n, dict) and as_hashable_str(n.get("id"))
    }
    df_nodes = {
        n["id"]: n
        for n in as_list(df.get("nodes"))
        if isinstance(n, dict) and as_hashable_str(n.get("id"))
    }

    skipped = SkipTally()

    def node(nodes: Dict[str, dict], node_id: Any) -> dict:
        key = as_hashable_str(node_id)
        return nodes.get(key, {}) if key else {}

    # symbol/package attribution indexes, built from every external edge,
    # reachable or not: a kept slice can traverse an unreachable intermediate
    # function, and its nodes still need purl attribution.
    symbol_to_purl: Dict[str, str] = {}
    for e in as_list(cg.get("edges")):
        if not isinstance(e, dict):
            continue
        tgt = node(cg_nodes, e.get("targetId"))
        vpurl = (
            reconcile_purl(e.get("sinkPurl"), bom_index)
            or _module_purl_from_obj(tgt.get("module"), bom_index)
            or reconcile_purl(tgt.get("purl"), bom_index)
            or _resolve_package_path(tgt.get("packagePath"), module_index)
        )
        if not vpurl or tgt.get("standard") or _is_main_module(tgt):
            continue
        tgt_name = e.get("targetName") or tgt.get("label") or tgt.get("name") or ""
        for nm in (tgt.get("name"), tgt.get("label"), tgt_name):
            if isinstance(nm, str) and nm:
                symbol_to_purl.setdefault(nm, vpurl)

    slice_reach = _slice_reachability(df)
    reachable_packages = _reachable_package_set(slice_reach)
    node_reach = _node_reachability(cg)

    records = []

    # --- dataflow slice records -------------------------------------------
    for sl in as_list(df.get("slices")):
        if not isinstance(sl, dict):
            skipped.add("dataFlow.slices entries are not JSON objects and became no record")
            continue
        # reachableFromRoots is False only for slices that live entirely in
        # code the application never drives into, trusted only when
        # sliceReachability says a dispatch-aware graph produced it. Absent
        # keeps the slice: the flag is a filter, not a requirement. Such a
        # slice is not reached evidence and is counted, not recorded.
        if slice_reach is not None and sl.get("reachableFromRoots") is False:
            skipped.add(
                "dataFlow.slices entries golem marked unreachable from every root "
                "(reachableFromRoots false on a dispatch-aware graph) became no record"
            )
            continue
        flow_purls: Set[str] = set()
        service_pairs: List[Tuple[Optional[str], str]] = []
        path_nodes: List[EvidencePathNode] = []
        locations: List[EvidenceLocation] = []
        where = _Locations(paths)
        sink_category = as_str(sl.get("sinkCategory"))

        for rp in as_list(sl.get("purls")):
            vp = reconcile_purl(rp, bom_index)
            if vp:
                flow_purls.add(vp)
        for key in ("sourcePurl", "sinkPurl"):
            vp = reconcile_purl(sl.get(key), bom_index)
            if vp:
                flow_purls.add(vp)
        for key in ("sourcePackagePath", "sinkPackagePath"):
            vp = _resolve_package_path(as_str(sl.get(key)), module_index)
            if vp:
                flow_purls.add(vp)
        for key in ("sourceName", "sinkName"):
            nm = as_str(sl.get(key))
            if nm in symbol_to_purl:
                flow_purls.add(symbol_to_purl[nm])

        for nid in as_list(sl.get("nodeIds")):
            n = node(df_nodes, nid)
            npurl = (
                reconcile_purl(n.get("purl"), bom_index)
                or _module_purl_from_obj(n.get("module"), bom_index)
                or _resolve_package_path(as_str(n.get("packagePath")), module_index)
            )
            nm = as_str(n.get("name")) or as_str(n.get("symbol"))
            sym_purl = symbol_to_purl.get(nm)
            if sym_purl:
                flow_purls.add(sym_purl)
            if npurl:
                flow_purls.add(npurl)
            tag_purl = sym_purl or npurl
            node_category = as_str(n.get("category")) or (sink_category if sym_purl else "")
            if tag_purl:
                service_pairs.append((tag_purl, node_category))
            pos = as_dict(n.get("position"))
            function = as_str(n.get("function"))
            path_nodes.append(
                EvidencePathNode(
                    file=where.file(pos.get("filename")),
                    line=_pos_line(pos),
                    method=function or as_str(sl.get("sinkFunction")) or None,
                    symbol=as_str(n.get("symbol")) or nm or None,
                )
            )
            location = where.location(pos, function)
            if location:
                locations.append(location)
        if not flow_purls:
            skipped.add(
                "dataFlow.slices entries name no package this BOM carries and became no record"
            )
            continue
        # every purl the slice names but no witness node carries gets the
        # sink category's service, the same position the sink node holds
        represented = {purl for purl, _ in service_pairs}
        for m in sorted(flow_purls - represented):
            service_pairs.append((m, sink_category))
        attributes: dict = {"servicePurls": _service_purls(service_pairs, flow_purls)}
        confidence = sl.get("confidence")
        records.append(
            build_record(
                source=source,
                producer=producer,
                kind="reached-flow",
                discriminator=neutral_discriminator(sl, paths, [p.to_dict() for p in path_nodes]),
                purls=tuple(sorted(flow_purls)),
                locations=tuple(locations),
                path=tuple(path_nodes),
                confidence=confidence if isinstance(confidence, str) and confidence else None,
                attributes=attributes,
                caveats=where.caveats(base_caveats),
            )
        )

    # --- call-graph external-module records --------------------------------
    for e in as_list(cg.get("edges")):
        if not isinstance(e, dict):
            skipped.add("callGraph.edges entries are not JSON objects and became no record")
            continue
        tgt = node(cg_nodes, e.get("targetId"))
        src = node(cg_nodes, e.get("sourceId"))
        # A call into the standard library or the workspace's own module is
        # not dependency evidence; such an edge describes the application
        # and is not a record the report fails to give.
        if tgt.get("standard") or _is_main_module(tgt):
            continue
        vpurl = (
            reconcile_purl(e.get("sinkPurl"), bom_index)
            or _module_purl_from_obj(tgt.get("module"), bom_index)
            or reconcile_purl(tgt.get("purl"), bom_index)
            or _resolve_package_path(as_str(tgt.get("packagePath")), module_index)
        )
        if not vpurl:
            skipped.add(
                "callGraph.edges entries call a package this BOM does not carry and became no record"
            )
            continue
        # Skip targets in packages golem's sound graph never reaches through
        # non-init code: an edge into a blank-imported package's init, or
        # between two functions of a never-called dependency, is import
        # plumbing or library self-analysis, not reachability evidence.
        pp = as_str(tgt.get("packagePath"))
        if reachable_packages is not None and pp and pp not in reachable_packages:
            skipped.add(
                "callGraph.edges entries call into packages golem's dispatch-aware graph "
                "never reaches from non-init code and became no record"
            )
            continue
        callee = as_str(e.get("targetName")) or as_str(tgt.get("label")) or as_str(tgt.get("name"))
        caller = as_str(e.get("sourceName")) or as_str(src.get("label")) or as_str(src.get("name"))
        pos = as_dict(tgt.get("position")) or as_dict(e.get("position"))
        where = _Locations(paths)
        location = where.location(pos, callee)
        target_key = as_hashable_str(e.get("targetId"))
        attributes = dict(node_reach.get(target_key, {})) if target_key else {}
        attributes["servicePurls"] = []
        path = (
            EvidencePathNode(method=caller or None, symbol=caller or None),
            EvidencePathNode(
                file=location.file if location else None,
                line=_pos_line(pos),
                method=callee or None,
                symbol=callee or None,
            ),
        )
        records.append(
            build_record(
                source=source,
                producer=producer,
                kind="reached-flow",
                discriminator=neutral_discriminator(e, paths, [p.to_dict() for p in path]),
                purls=(vpurl,),
                locations=tuple(loc for loc in (location,) if loc),
                path=path,
                attributes=attributes,
                caveats=where.caveats(base_caveats),
            )
        )

    # --- witness path records ----------------------------------------------
    reach = as_dict(cg.get("reachability"))
    for path_entry in as_list(reach.get("paths")):
        if not isinstance(path_entry, dict):
            skipped.add(
                "callGraph.reachability.paths entries are not JSON objects and became no record"
            )
            continue
        node_ids = [n for n in as_list(path_entry.get("nodeIds")) if isinstance(n, str)]
        symbol = as_str(path_entry.get("symbol"))
        purls: Set[str] = set()
        path_nodes = []
        where = _Locations(paths)
        for nid in node_ids:
            n = cg_nodes.get(nid)
            if not n:
                continue
            vpurl = None
            if not n.get("standard") and not _is_main_module(n):
                vpurl = (
                    reconcile_purl(n.get("purl"), bom_index)
                    or _module_purl_from_obj(n.get("module"), bom_index)
                    or _resolve_package_path(as_str(n.get("packagePath")), module_index)
                )
            if vpurl:
                purls.add(vpurl)
            label = as_str(n.get("label")) or as_str(n.get("name")) or nid
            pos = as_dict(n.get("position"))
            path_nodes.append(
                EvidencePathNode(
                    file=where.file(pos.get("filename")),
                    line=_pos_line(pos),
                    method=label,
                    symbol=label,
                )
            )
        if not purls or not path_nodes:
            skipped.add(
                "callGraph.reachability.paths entries name no BOM dependency on their path "
                "and became no record"
            )
            continue
        attributes = dict(node_reach.get(node_ids[-1], {})) if node_ids else {}
        if symbol:
            attributes["symbol"] = symbol
        attributes["servicePurls"] = []
        records.append(
            build_record(
                source=source,
                producer=producer,
                kind="reached-flow",
                discriminator=neutral_discriminator(
                    path_entry, paths, [p.to_dict() for p in path_nodes]
                ),
                purls=tuple(sorted(purls)),
                path=tuple(path_nodes),
                attributes=attributes,
                caveats=where.caveats(base_caveats),
            )
        )

    # --- usage records -------------------------------------------------------
    for usage in as_list(report.get("usages")):
        if not isinstance(usage, dict):
            skipped.add("usages entries are not JSON objects and became no record")
            continue
        # A use of the standard library or of the workspace's own module is
        # not dependency evidence.
        mod_obj = as_dict(usage.get("module"))
        if usage.get("standard") or mod_obj.get("main"):
            continue
        vpurl = _module_purl_from_obj(mod_obj, bom_index) or _resolve_package_path(
            as_str(usage.get("packagePath")), module_index
        )
        if not vpurl:
            skipped.add("usages entries resolve to no BOM module purl and became no record")
            continue
        sym = as_str(usage.get("qualifiedName")) or as_str(usage.get("name"))
        pos = as_dict(as_dict(usage.get("range")).get("start"))
        where = _Locations(paths)
        location = where.location(pos, sym)
        records.append(
            build_record(
                source=source,
                producer=producer,
                kind="usage",
                discriminator=neutral_discriminator(usage, paths),
                purls=(vpurl,),
                locations=tuple(loc for loc in (location,) if loc),
                attributes={"servicePurls": []},
                caveats=where.caveats(base_caveats),
            )
        )

    # --- api endpoint records ------------------------------------------------
    for ep in as_list(report.get("apiEndpoints")):
        if not isinstance(ep, dict):
            skipped.add("apiEndpoints entries are not JSON objects and became no record")
            continue
        handler_vpurl = _resolve_package_path(as_str(ep.get("packagePath")), module_index)
        if not handler_vpurl:
            skipped.add("apiEndpoints entries resolve to no BOM module purl and became no record")
            continue
        path_ = as_str(ep.get("path"))
        handler = as_str(ep.get("handler"))
        pos = as_dict(as_dict(ep.get("range")).get("start"))
        where = _Locations(paths)
        location = where.location(pos, handler or path_)
        records.append(
            build_record(
                source=source,
                producer=producer,
                kind="entry-point",
                discriminator=neutral_discriminator(ep, paths),
                purls=(handler_vpurl,),
                locations=tuple(loc for loc in (location,) if loc),
                # the endpoint service tag is what attributes the handler
                # purl to reached_services in the engine
                attributes={"servicePurls": [handler_vpurl]},
                caveats=where.caveats(base_caveats),
            )
        )

    outside = paths.producer_caveat()
    caveats = _dedupe_caveats(base_caveats + skipped.caveats() + ([outside] if outside else []))
    return AdapterResult(status=STATUS_COMPLETED, records=records, caveats=caveats)


#: The report sections the adapter reads, with the JSON type each must have
#: when present. A section of another type is a malformed report.
_SECTION_TYPES = (
    (("options",), dict),
    (("runtime",), dict),
    (("tool",), dict),
    (("modules",), list),
    (("usages",), list),
    (("apiEndpoints",), list),
    (("callGraph",), dict),
    (("callGraph", "nodes"), list),
    (("callGraph", "edges"), list),
    (("callGraph", "roots"), list),
    (("callGraph", "reachability"), dict),
    (("callGraph", "reachability", "nodes"), list),
    (("callGraph", "reachability", "paths"), list),
    (("dataFlow",), dict),
    (("dataFlow", "nodes"), list),
    (("dataFlow", "slices"), list),
)


def _section_problem(report: dict) -> Optional[str]:
    """The first consumed section of the wrong JSON type, named, or ``None``.

    A ``null`` section reads as absent. Any other value of the wrong type
    means the report is not the shape golem writes.
    """
    for keys, expected in _SECTION_TYPES:
        value: Any = report
        for key in keys:
            if not isinstance(value, dict):
                value = None
                break
            value = value.get(key)
        if value is not None and not isinstance(value, expected):
            label = ".".join(keys)
            want = "an object" if expected is dict else "an array"
            return f"{label} is a {type(value).__name__}, expected {want}"
    return None


def _dedupe_caveats(caveats: List[EvidenceCaveat]) -> List[EvidenceCaveat]:
    out: List[EvidenceCaveat] = []
    seen: Set[Tuple[str, str]] = set()
    for caveat in caveats:
        key = (caveat.kind, caveat.detail)
        if key in seen:
            continue
        seen.add(key)
        out.append(caveat)
    return out


__all__ = [
    "PRODUCER_NAME",
    "SUPPORTED_MAJOR",
    "build_bom_purl_index",
    "extract",
    "is_golem_report",
    "reconcile_purl",
]
