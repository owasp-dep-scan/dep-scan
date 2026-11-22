"""golem (Go Source Inspector) report -> evidence records.

This module is the only code that knows the golem report format: a
lowerCamelCase JSON object whose ``schemaVersion`` is a URL ending in the
``v<major>[.<minor>]`` schema version, carrying ``tool``/``runtime``,
``modules``, a ``callGraph`` and a ``dataFlow``.

Four kinds of evidence become records:

1. Dataflow slices (``dataFlow.slices[]``) become ``reached-flow`` records
   whose ``path`` is the slice's witness nodes in golem's order.
2. Call-graph edges whose target resolves to a BOM dependency become
   ``reached-flow`` records with the caller-to-callee two-node path. On the
   dispatch-aware graph golem stamps ``reachablePackages`` with, edges into
   packages that graph never reaches through non-init code are import
   plumbing, not reachability evidence, and are left out exactly as the
   slice converter left them out.
3. ``callGraph.reachability.paths[]``, the witness paths golem computes for
   symbols requested with ``--reachable-symbols``, become ``reached-flow``
   records whose ``path`` is the call stack from a root to the symbol.
4. ``usages[]`` become ``usage`` records and ``apiEndpoints[]`` become
   ``entry-point`` records.

A golem purl is reconciled onto a BOM component through three forms (exact,
version-stripped, subpath+version-stripped), mirroring cdxgen's
``createPurlAliasMap``; Go module paths are literal, so no ``-``/``_``
normalization happens. A slice or edge whose purls name no BOM component is
left out: the producer named a package this BOM does not carry, and an
unmatched purl never incremented the reached set. An object the report
itself left shapeless (not a JSON object where one belongs) is a
``record-skipped`` caveat, never a silent drop.

Golem's own budget markers travel with the records: a ``sliceReachability``
run that only came back ``partial``, and the dataflow truncation fields,
land as ``budget`` caveats on the producer result and on every record, since
either can hide evidence anywhere in the report.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from analysis_lib.evidence import (
    EvidenceCaveat,
    EvidenceLocation,
    EvidencePathNode,
    EvidenceProducer,
    content_discriminator,
)
from analysis_lib.evidence.adapters import (
    AdapterResult,
    STATUS_COMPLETED,
    build_record,
    gate_report_version,
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
    return {p for p in (sr.get("reachablePackages") or []) if isinstance(p, str)}


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
        r.get("id"): r.get("function") or r.get("id")
        for r in cg.get("roots", []) or []
        if isinstance(r, dict) and r.get("id")
    }
    out: Dict[str, dict] = {}
    for entry in reach.get("nodes", []) or []:
        if not isinstance(entry, dict) or not entry.get("nodeId"):
            continue
        root_ids = [r for r in entry.get("rootIds", []) or [] if isinstance(r, str)]
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
        path = mod.get("path", "")
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


def _pos_line(pos: Optional[dict]) -> Optional[int]:
    try:
        line = int((pos or {}).get("line") or 0)
    except (TypeError, ValueError):
        return None
    return line or None


def _relative(file: Optional[str], root: str) -> Optional[str]:
    """The file path relative to the analysed root, with forward slashes.

    Paths the report points outside the root are kept as given; nothing is
    guessed beyond the root prefix the report itself names.
    """
    if not file:
        return None
    out = file
    if root and (out == root or out.startswith(root + "/") or out.startswith(root + os.sep)):
        out = out[len(root):].lstrip("/").lstrip(os.sep) or file
    return out.replace(os.sep, "/")


def _location(pos: Optional[dict], method: Optional[str], root: str) -> Optional[EvidenceLocation]:
    file = _relative((pos or {}).get("filename"), root)
    if not file:
        return None
    return EvidenceLocation(file=file, line=_pos_line(pos), method=method or None)


def _service_purls(
    pairs: List[Tuple[Optional[str], str]], flow_purls: Set[str]
) -> List[str]:
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


def _reach_attributes(info: Optional[dict]) -> dict:
    return dict(info) if info else {}


def _parse_report(report) -> Tuple[Optional[Any], Optional[str]]:
    """The report as a parsed value, accepting JSON text as well as a
    parsed object."""
    if isinstance(report, (str, bytes)):
        try:
            return json.loads(report), None
        except ValueError as e:
            return None, f"the report is not valid JSON: {e}"
    return report, None


def extract(
    report,
    *,
    source: str,
    producer_version: str = "",
    bom_components: Optional[Iterable[dict]] = None,
    extra_components: Optional[Iterable[dict]] = None,
) -> AdapterResult:
    """One golem report as evidence records.

    ``report`` is the parsed golem report or its JSON text. ``source`` is
    the scan-directory-relative file the report was read from.
    ``producer_version`` is the golem tool version when the caller knows it;
    the report's own ``tool.version`` is used otherwise. ``bom_components``
    and ``extra_components`` (the metadata.component root) feed the purl
    reconciliation index. The result is the records, or not-assessed with
    the reason: a report that is not valid JSON, does not have the golem
    shape, or names a schema major this adapter does not read is never read
    as a smaller report.
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

    seen_version = str(report.get("schemaVersion") or "").strip()
    gate = gate_report_version(_gate_version(report), SUPPORTED_MAJOR, KNOWN_MINOR)
    if not gate.accepted:
        return not_assessed(
            f"the report schema version {seen_version or _gate_version(report)} is "
            f"not supported; this adapter reads golem schema major {SUPPORTED_MAJOR} reports"
        )
    report_caveats = list(gate.caveats)

    tool = report.get("tool") if isinstance(report.get("tool"), dict) else {}
    version = producer_version or str(tool.get("version") or "") or "unknown"
    report_schema_version = seen_version or "unknown"
    producer = EvidenceProducer(
        name=PRODUCER_NAME, version=version, report_schema_version=report_schema_version
    )

    # Budget markers golem stamped on the report as a whole. Either can hide
    # evidence anywhere, so both land on every record the adapter emits.
    budget_details: List[str] = []
    df = report.get("dataFlow") if isinstance(report.get("dataFlow"), dict) else {}
    sr = df.get("sliceReachability") if isinstance(df.get("sliceReachability"), dict) else None
    if isinstance(sr, dict) and sr.get("status") == "partial":
        detail = "golem's slice reachability came back partial"
        if sr.get("reason"):
            detail += f" ({sr['reason']})"
        budget_details.append(detail)
    stats = df.get("stats") if isinstance(df.get("stats"), dict) else {}
    if stats.get("truncated"):
        reasons = ", ".join(str(r) for r in stats.get("truncationReasons") or [])
        detail = "golem truncated the dataflow analysis"
        if reasons:
            detail += f" ({reasons})"
        budget_details.append(detail)
    budget_caveats = [EvidenceCaveat(kind="budget", detail=d) for d in budget_details]
    base_caveats = report_caveats + budget_caveats

    bom_index = build_bom_purl_index(bom_components, extra_components=extra_components)
    module_index = _build_module_path_index(report.get("modules"), bom_index)
    root = str((report.get("options") or {}).get("directory") or "")

    cg = report.get("callGraph") or {}
    cg_nodes = {n.get("id"): n for n in cg.get("nodes", []) if isinstance(n, dict)}
    df_nodes = {n.get("id"): n for n in df.get("nodes", []) if isinstance(n, dict)}

    skipped: List[EvidenceCaveat] = []

    # symbol/package attribution indexes, built from every external edge,
    # reachable or not: a kept slice can traverse an unreachable intermediate
    # function, and its nodes still need purl attribution.
    symbol_to_purl: Dict[str, str] = {}
    for e in cg.get("edges", []) or []:
        if not isinstance(e, dict):
            continue
        tgt = cg_nodes.get(e.get("targetId")) or {}
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
            if nm:
                symbol_to_purl.setdefault(nm, vpurl)

    slice_reach = _slice_reachability(df)
    reachable_packages = _reachable_package_set(slice_reach)
    node_reach = _node_reachability(cg)

    records = []

    # --- dataflow slice records -------------------------------------------
    for sl in df.get("slices", []) or []:
        if not isinstance(sl, dict):
            skipped.append(
                EvidenceCaveat(
                    kind="record-skipped",
                    detail="dataFlow.slices carries a non-object entry; it was not turned into a record",
                )
            )
            continue
        # reachableFromRoots is False only for slices that live entirely in
        # code the application never drives into, trusted only when
        # sliceReachability says a dispatch-aware graph produced it. Absent
        # keeps the slice: the flag is a filter, not a requirement.
        if slice_reach is not None and sl.get("reachableFromRoots") is False:
            continue
        flow_purls: Set[str] = set()
        service_pairs: List[Tuple[Optional[str], str]] = []
        path_nodes: List[EvidencePathNode] = []
        rule_name = sl.get("ruleName") or sl.get("ruleId") or ""
        sink_category = sl.get("sinkCategory") or ""

        for rp in sl.get("purls", []) or []:
            vp = reconcile_purl(rp, bom_index)
            if vp:
                flow_purls.add(vp)
        for key in ("sourcePurl", "sinkPurl"):
            vp = reconcile_purl(sl.get(key, ""), bom_index)
            if vp:
                flow_purls.add(vp)
        for key in ("sourcePackagePath", "sinkPackagePath"):
            vp = _resolve_package_path(sl.get(key, ""), module_index)
            if vp:
                flow_purls.add(vp)
        for key in ("sourceName", "sinkName"):
            nm = sl.get(key, "")
            if nm in symbol_to_purl:
                flow_purls.add(symbol_to_purl[nm])

        node_ids_list = sl.get("nodeIds", []) or []
        for nid in node_ids_list:
            n = df_nodes.get(nid) or {}
            npurl = (
                reconcile_purl(n.get("purl"), bom_index)
                or _module_purl_from_obj(n.get("module"), bom_index)
                or _resolve_package_path(n.get("packagePath"), module_index)
            )
            nm = n.get("name") or n.get("symbol") or ""
            sym_purl = symbol_to_purl.get(nm)
            if sym_purl:
                flow_purls.add(sym_purl)
            if npurl:
                flow_purls.add(npurl)
            tag_purl = sym_purl or npurl
            node_category = n.get("category") or (sink_category if sym_purl else "")
            if tag_purl:
                service_pairs.append((tag_purl, node_category))
            pos = n.get("position") or {}
            path_nodes.append(
                EvidencePathNode(
                    file=_relative((pos or {}).get("filename"), root),
                    line=_pos_line(pos),
                    method=n.get("function") or sl.get("sinkFunction") or None,
                    symbol=n.get("symbol") or nm or None,
                )
            )
        if not flow_purls:
            continue
        # every purl the slice names but no witness node carries gets the
        # sink category's service, the way the converter appended it to the
        # sink node's tags for the engine's positional walk
        represented = {
            purl for purl, _ in service_pairs
        }
        missing = flow_purls - represented
        if missing:
            for m in sorted(missing):
                service_pairs.append((m, sink_category))
        attributes: dict = _reach_attributes(None)
        attributes["servicePurls"] = _service_purls(service_pairs, flow_purls)
        records.append(
            build_record(
                source=source,
                producer=producer,
                kind="reached-flow",
                discriminator=str(sl.get("id") or content_discriminator(sl)),
                purls=tuple(sorted(flow_purls)),
                locations=tuple(
                    loc
                    for loc in (
                        _location(n.get("position"), n.get("function"), root)
                        for n in (df_nodes.get(nid) or {} for nid in node_ids_list)
                    )
                    if loc
                ),
                path=tuple(path_nodes),
                confidence=str(sl["confidence"]) if sl.get("confidence") else None,
                attributes=attributes,
                caveats=tuple(base_caveats),
            )
        )

    # --- call-graph external-module records --------------------------------
    for e in cg.get("edges", []) or []:
        if not isinstance(e, dict):
            skipped.append(
                EvidenceCaveat(
                    kind="record-skipped",
                    detail="callGraph.edges carries a non-object entry; it was not turned into a record",
                )
            )
            continue
        tgt = cg_nodes.get(e.get("targetId")) or {}
        src = cg_nodes.get(e.get("sourceId")) or {}
        vpurl = (
            reconcile_purl(e.get("sinkPurl"), bom_index)
            or _module_purl_from_obj(tgt.get("module"), bom_index)
            or reconcile_purl(tgt.get("purl"), bom_index)
            or _resolve_package_path(tgt.get("packagePath"), module_index)
        )
        if not vpurl or tgt.get("standard") or _is_main_module(tgt):
            continue
        # Skip targets in packages golem's sound graph never reaches through
        # non-init code: an edge into a blank-imported package's init, or
        # between two functions of a never-called dependency, is import
        # plumbing or library self-analysis, not reachability evidence.
        pp = tgt.get("packagePath")
        if reachable_packages is not None and pp and pp not in reachable_packages:
            continue
        callee = e.get("targetName") or tgt.get("label") or tgt.get("name") or ""
        caller = e.get("sourceName") or src.get("label") or src.get("name") or ""
        pos = tgt.get("position") or e.get("position") or {}
        attributes = _reach_attributes(node_reach.get(str(e.get("targetId"))))
        attributes["servicePurls"] = []
        records.append(
            build_record(
                source=source,
                producer=producer,
                kind="reached-flow",
                discriminator=str(e.get("id") or content_discriminator(e)),
                purls=(vpurl,),
                locations=tuple(
                    loc
                    for loc in (_location(pos, callee, root),)
                    if loc
                ),
                path=(
                    EvidencePathNode(
                        method=caller or None,
                        symbol=caller or None,
                    ),
                    EvidencePathNode(
                        file=_relative((pos or {}).get("filename"), root),
                        line=_pos_line(pos),
                        method=callee or None,
                        symbol=callee or None,
                    ),
                ),
                attributes=attributes,
                caveats=tuple(base_caveats),
            )
        )

    # --- witness path records ----------------------------------------------
    reach = cg.get("reachability") if isinstance(cg, dict) else None
    paths = reach.get("paths") if isinstance(reach, dict) else None
    for path in paths or []:
        if not isinstance(path, dict):
            skipped.append(
                EvidenceCaveat(
                    kind="record-skipped",
                    detail="callGraph.reachability.paths carries a non-object entry; it was not turned into a record",
                )
            )
            continue
        node_ids = [n for n in path.get("nodeIds", []) or [] if isinstance(n, str)]
        symbol = path.get("symbol") or ""
        purls: Set[str] = set()
        path_nodes = []
        for nid in node_ids:
            n = cg_nodes.get(nid)
            if not n:
                continue
            vpurl = None
            if not n.get("standard") and not _is_main_module(n):
                vpurl = (
                    reconcile_purl(n.get("purl"), bom_index)
                    or _module_purl_from_obj(n.get("module"), bom_index)
                    or _resolve_package_path(n.get("packagePath"), module_index)
                )
            if vpurl:
                purls.add(vpurl)
            label = n.get("label") or n.get("name") or nid
            pos = n.get("position") or {}
            path_nodes.append(
                EvidencePathNode(
                    file=_relative((pos or {}).get("filename"), root),
                    line=_pos_line(pos),
                    method=label,
                    symbol=label,
                )
            )
        if not purls or not path_nodes:
            if not purls:
                skipped.append(
                    EvidenceCaveat(
                        kind="record-skipped",
                        detail=(
                            "callGraph.reachability.paths entry "
                            f"{str(path.get('symbol') or '')!r} names no BOM dependency on its path; "
                            "it was not turned into a record"
                        ),
                    )
                )
            continue
        attributes = _reach_attributes(node_reach.get(node_ids[-1] if node_ids else ""))
        if symbol:
            attributes["symbol"] = symbol
        attributes["servicePurls"] = []
        records.append(
            build_record(
                source=source,
                producer=producer,
                kind="reached-flow",
                discriminator=str(path.get("id") or content_discriminator(path)),
                purls=tuple(sorted(purls)),
                path=tuple(path_nodes),
                attributes=attributes,
                caveats=tuple(base_caveats),
            )
        )

    # --- usage records -------------------------------------------------------
    for usage in report.get("usages", []) or []:
        if not isinstance(usage, dict):
            skipped.append(
                EvidenceCaveat(
                    kind="record-skipped",
                    detail="usages carries a non-object entry; it was not turned into a record",
                )
            )
            continue
        if usage.get("standard"):
            continue
        vpurl = _module_purl_from_obj(usage.get("module"), bom_index) or _resolve_package_path(
            usage.get("packagePath"), module_index
        )
        if not vpurl:
            skipped.append(
                EvidenceCaveat(
                    kind="record-skipped",
                    detail=(
                        "usages entry "
                        f"{str(usage.get('qualifiedName') or usage.get('name') or '')!r} "
                        "resolves to no BOM module purl; it was not turned into a record"
                    ),
                )
            )
            continue
        mod_obj = usage.get("module") or {}
        if isinstance(mod_obj, dict) and mod_obj.get("main"):
            continue
        sym = usage.get("qualifiedName") or usage.get("name") or ""
        enclosing_obj = usage.get("enclosing")
        enclosing_name = enclosing_obj.get("name", "") if isinstance(enclosing_obj, dict) else ""
        rng = usage.get("range") or {}
        pos = rng.get("start") if isinstance(rng, dict) else {}
        attributes = {"servicePurls": []}
        records.append(
            build_record(
                source=source,
                producer=producer,
                kind="usage",
                discriminator=str(usage.get("id") or content_discriminator(usage)),
                purls=(vpurl,),
                locations=tuple(
                    loc for loc in (_location(pos, sym, root),) if loc
                ),
                attributes=attributes,
                caveats=tuple(base_caveats),
            )
        )

    # --- api endpoint records ------------------------------------------------
    for ep in report.get("apiEndpoints", []) or []:
        if not isinstance(ep, dict):
            skipped.append(
                EvidenceCaveat(
                    kind="record-skipped",
                    detail="apiEndpoints carries a non-object entry; it was not turned into a record",
                )
            )
            continue
        pp = ep.get("packagePath") or ""
        handler_vpurl = _resolve_package_path(pp, module_index)
        if not handler_vpurl:
            skipped.append(
                EvidenceCaveat(
                    kind="record-skipped",
                    detail=(
                        "apiEndpoints entry "
                        f"{str(ep.get('path') or '')!r} resolves to no BOM module purl; "
                        "it was not turned into a record"
                    ),
                )
            )
            continue
        method = ep.get("method") or ""
        path_ = ep.get("path") or ""
        handler = ep.get("handler") or ""
        pos = (ep.get("range") or {}).get("start") if isinstance(ep.get("range"), dict) else {}
        records.append(
            build_record(
                source=source,
                producer=producer,
                kind="entry-point",
                discriminator=str(ep.get("id") or content_discriminator(ep)),
                purls=(handler_vpurl,),
                locations=tuple(
                    loc for loc in (_location(pos, handler or path_, root),) if loc
                ),
                # the endpoint service tag is what attributes the handler
                # purl to reached_services in the engine
                attributes={"servicePurls": [handler_vpurl]},
                caveats=tuple(base_caveats),
            )
        )

    caveats = _dedupe_caveats(base_caveats + skipped)
    return AdapterResult(status=STATUS_COMPLETED, records=records, caveats=caveats)


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
