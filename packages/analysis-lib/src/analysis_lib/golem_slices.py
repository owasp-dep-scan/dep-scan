"""golem (Go Source Inspector) report -> atom reachables-slice converter.

dep-scan's reachability engine is **purl-keyed and file-format-driven, not
slicer-aware** (see ``reachability.py``). Dropping a correctly-shaped
``*reachables.slices*.json`` whose ``purls`` carry the SAME versioned purls as
the Go BOM lights up ``FrameworkReachability`` / ``SemanticReachability``
with zero analyzer changes. This module produces that file from a golem report.

The single most important correctness detail is the **purl reconciler** (see
:func:`reconcile_purl`). golem emits **versioned** module purls
(``pkg:golang/<module>@<version>``) AND **package-level** purls with subpaths
(``pkg:golang/<module>@<version>#<subpath>``). A Go BOM keyed at module
granularity won't exact-match the ``#subpath`` form. We reconcile via THREE
forms (mirror cdxgen's ``createPurlAliasMap``): exact, version-stripped, and
subpath+qualifier+version-stripped.

**Golem JSON is lowerCamelCase** (``callGraph``, ``dataFlow``, ``apiEndpoints``,
``nodeIds``, ``sourceName``, ``sinkPurl``). Do NOT blind-copy rusi's
snake_case accessors. Callgraph nodes have NO ``qualifiedName`` — use
``label``/``name`` + ``packagePath`` + ``module``.

Public surface:
    - :func:`build_bom_purl_index` -- multi-form purl alias map from BOM components
    - :func:`reconcile_purl` -- golem purl -> BOM versioned purl (or ``None``)
    - :func:`convert_golem_report` -- golem.json + BOM -> atom-shaped slice list
    - :func:`write_slices_file` -- convenience writer
    - :func:`is_golem_report` -- shape-based report detection
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Dict, Iterable, List, Optional


# golem reports are detected by SHAPE, not ``schemaVersion``. A golem report is
# a JSON object carrying its producer identity (``tool``/``runtime``) alongside
# at least one analysis section the converter consumes (``callGraph``/
# ``dataFlow``). Note: golem JSON uses **lowerCamelCase** keys, unlike rusi's
# snake_case. This reliably distinguishes a genuine golem report from an
# atom-produced ``*-semantics.slices.json`` that reuses the same path.
GOLEM_PRODUCER_KEYS = ("tool", "runtime")
GOLEM_SECTION_KEYS = ("callGraph", "dataFlow")

# golem dataflow source/sink categories -> dep-scan SERVICE_TAGS vocabulary
# (config.py). Conservative mapping: only categories whose intent clearly maps
# to an existing service tag. Same purpose as rusi's mapping but with Go-
# appropriate category names from golem's dataflow pattern packs.
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

# SERVICE_TAG used for HTTP api_endpoint handler flows. ``api`` is a
# SERVICE_TAG (config.py) so SemanticReachability attributes the framework
# crate on the endpoint path to ``reached_services``.
GOLEM_ENDPOINT_SERVICE_TAG = "api"


# ---------------------------------------------------------------------------
# Purl parsing + reconciliation (mirrors cdxgen's createPurlAliasMap)
# ---------------------------------------------------------------------------


def _purl_without_version(purl: Optional[str]) -> str:
    """Strip version, subpath, and qualifiers from a purl.

    Mirrors cdxgen's ``purlWithoutVersion``:
    ``split("?")[0].split("#")[0].split("@")[0]``.

    For ``pkg:golang/github.com/foo/bar@v1.2.3#internal/baz`` this returns
    ``pkg:golang/github.com/foo/bar`` — the bare module purl that the Go BOM
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

    Mirrors cdxgen's ``createPurlAliasMap``. For each Go BOM component the
    index stores:
      1. the exact versioned purl (``pkg:golang/foo/bar@v1.2.3``)
      2. the version-stripped purl (``pkg:golang/foo/bar``)

    When reconciling, :func:`reconcile_purl` will also try stripping the
    subpath from the query purl (form 3), so a golem package-level
    ``pkg:golang/foo/bar@v1.2.3#internal/baz`` matches the BOM's module-level
    ``pkg:golang/foo/bar@v1.2.3`` via the version-stripped form.

    No ``-``/``_`` normalization is performed (Go module paths are literal).
    Also accepts ``extra_components`` for the metadata.component root.
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
    """Map a golem purl onto a BOM versioned purl.

    Resolution order (mirror cdxgen's ``resolveComponentPurl``):
      1. exact match in the BOM index
      2. version-stripped match (strip ``?``, ``#``, ``@``)

    Rules:
      - Non-golang / malformed / empty -> ``None``.
      - Stdlib (golem marks ``standard:true`` with empty purl) never reaches
        here (empty purl -> ``None``).
      - Not in the BOM -> ``None`` (an unmatched purl would only add noise).

    This mirrors cdxgen's own alias resolution so a golem package-level
    ``pkg:golang/foo/bar@v1.2.3#internal/baz`` matches a BOM
    ``pkg:golang/foo/bar@v1.2.3`` via the version+subpath-stripped form.
    """
    if not isinstance(golem_purl, str) or not golem_purl.startswith("pkg:golang/"):
        return None
    # exact match
    if golem_purl in bom_index:
        return bom_index[golem_purl]
    # version+subpath+qualifier stripped
    no_version = _purl_without_version(golem_purl)
    if no_version and no_version in bom_index:
        return bom_index[no_version]
    return None


def reconcile_purls(golem_purls: Iterable[str], bom_index: Dict[str, str]) -> List[str]:
    """Reconcile + de-duplicate a collection of golem purls to BOM purls.

    Returns a sorted list (deterministic) of non-None reconciled purls.
    """
    seen = set()
    out = []
    for gp in golem_purls or []:
        vp = reconcile_purl(gp, bom_index)
        if vp and vp not in seen:
            seen.add(vp)
            out.append(vp)
    return sorted(out)


# ---------------------------------------------------------------------------
# Root-reachability helpers
# ---------------------------------------------------------------------------


def _is_init_function(node_id: str) -> bool:
    """Whether a call-graph node id names a package init function.

    golem ids are SSA function strings: ``github.com/pkg.init`` and the
    numbered clones ``github.com/pkg.init#1`` a package earns per file. A
    METHOD named init -- ``(*github.com/pkg.Type).init`` -- is ordinary code
    and must not be classified as the package initializer, so anything with a
    receiver (an open paren) is rejected first.
    """
    if not node_id or "(" in node_id:
        return False
    last = node_id.rsplit(".", 1)[-1]
    return last == "init" or last.startswith("init#")


def _build_reachability_index(cg: dict) -> Dict[str, bool]:
    """nodeId -> reachableFromRoots from ``callGraph.reachability.nodes``."""
    reach: Dict[str, bool] = {}
    for rn in (cg.get("reachability") or {}).get("nodes", []) or []:
        if isinstance(rn, dict) and rn.get("nodeId"):
            reach[rn["nodeId"]] = bool(rn.get("reachableFromRoots"))
    return reach


def _packages_with_reachable_code(
    reach: Dict[str, bool], cg_nodes: Dict[str, dict]
) -> set:
    """packagePaths holding at least one reachable NON-init node.

    A package whose only reachable node is its init was merely imported --
    blank imports run init -- which is initialization plumbing, not usage.
    """
    used: set = set()
    for nid, is_reachable in reach.items():
        if not is_reachable or _is_init_function(nid):
            continue
        pp = (cg_nodes.get(nid) or {}).get("packagePath")
        if pp:
            used.add(pp)
    return used


# ---------------------------------------------------------------------------
# Module path -> purl resolution (for nodes/slices that only carry packagePath)
# ---------------------------------------------------------------------------


def _build_module_path_index(
    report_modules: Optional[Iterable[dict]],
    bom_index: Dict[str, str],
) -> Dict[str, str]:
    """Build ``module.path -> reconciled BOM purl`` from golem's modules[].

    golem nodes and dataflow slices carry ``packagePath`` (a Go import path)
    rather than always a purl. To resolve the owning module we do longest-
    prefix matching against module paths (mirror cdxgen's ``symbolModule``).
    """
    index: Dict[str, str] = {}
    for mod in report_modules or []:
        if not isinstance(mod, dict):
            continue
        path = mod.get("path", "")
        if not path:
            continue
        purl = mod.get("purl", "")
        vpurl = reconcile_purl(purl, bom_index)
        if vpurl:
            index.setdefault(path, vpurl)
    return index


def _resolve_package_path(
    package_path: Optional[str],
    module_index: Dict[str, str],
) -> Optional[str]:
    """Find the reconciled BOM purl for a Go package path via longest-prefix
    match against the module index (mirrors cdxgen's ``symbolModule``).
    """
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
    """Extract and reconcile the purl from a golem ``module`` sub-object."""
    if not isinstance(module_obj, dict):
        return None
    return reconcile_purl(module_obj.get("purl", ""), bom_index)


# ---------------------------------------------------------------------------
# Atom-shaped slice emission
# ---------------------------------------------------------------------------


def _pos_line(pos: Optional[dict]) -> int:
    try:
        return int((pos or {}).get("line") or 0)
    except (TypeError, ValueError):
        return 0


def _pos_col(pos: Optional[dict]) -> int:
    try:
        return int((pos or {}).get("column") or 0)
    except (TypeError, ValueError):
        return 0


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

    Format: ``"<versioned-purl>, <service-tag>, go, <rule_name>"``. The token
    IMMEDIATELY after the purl is always the service tag when one applies, so
    ``SemanticReachability._flow_service_purls`` positional association
    attributes the service to THIS purl.
    """
    parts: List[str] = []
    if purl:
        parts.append(purl)
    if service_tag is None:
        service_tag = GOLEM_CATEGORY_TO_SERVICE_TAG.get(category or "")
    parts.append(service_tag or category or "go")
    if service_tag:
        if category and category != service_tag:
            parts.append(category)
    if "go" not in parts[-2:] and parts[-1] != "go":
        parts.append("go")
    if rule_name:
        parts.append(rule_name)
    return ", ".join(parts)


def convert_golem_report(
    report: dict,
    bom_index: Dict[str, str],
) -> List[dict]:
    """Convert a parsed golem report into an atom-shaped reachables slice list.

    Emits four kinds of flows (all atom-shaped ``{"flows": [...], "purls":
    [...]}``):

      1. **Dataflow flows** -- one per golem ``dataFlow.slices[]`` entry.
         These carry the richest taint evidence.
      2. **Call-graph flows** -- one per call-graph edge targeting an EXTERNAL
         module (pure-call reachability). Each flow carries a 2-node path:
         enclosing caller -> external symbol call.
      3. **Usage flows** -- one per ``usages[]`` entry that resolves to a BOM
         dependency. This is often the PRIMARY signal for Go projects: golem's
         call graph can be sparse for simple apps, but the usages section is
         always populated when the app uses a dependency's symbols. Each usage
         with a resolved module purl becomes a 2-node flow: enclosing caller
         function -> external dependency symbol.
      4. **Endpoint flows** -- one per ``apiEndpoints[]`` entry.

    Deterministic: purls sorted, flows deduped by identity, final flow list
    sorted by (purls, first-node id).
    """
    if not isinstance(report, dict):
        return []

    # Build module path -> BOM purl index for packagePath resolution
    module_index = _build_module_path_index(report.get("modules"), bom_index)

    cg = report.get("callGraph") or {}
    cg_nodes = {n.get("id"): n for n in cg.get("nodes", []) if isinstance(n, dict)}
    df = report.get("dataFlow") or {}
    df_nodes = {n.get("id"): n for n in df.get("nodes", []) if isinstance(n, dict)}

    # Root reachability, when golem reported it. Absent (older golem, or no
    # call graph was built) keeps the historical behaviour: everything golem
    # observed is kept. Present, it separates application-driven evidence
    # from module-internal flows -- exactly the distinction a blank-imported,
    # never-called dependency needs to stay unreached.
    cg_reach = _build_reachability_index(cg)
    has_reachability = bool(cg_reach)
    pkgs_with_reachable_code = _packages_with_reachable_code(cg_reach, cg_nodes)

    # --- Build symbol -> reconciled purl map from call-graph nodes ---------
    # golem callgraph nodes have NO qualifiedName. We index by name AND by
    # packagePath so dataflow nodes can be attributed to the owning dependency
    # module via either signal. External nodes (``external:true`` or carrying
    # a non-main module purl) are the ones that matter for dependency-CVE
    # reachability.
    external_call_records: List[dict] = []
    # name -> purl for external symbols (used to attribute dataflow nodes)
    symbol_to_purl: Dict[str, str] = {}
    # packagePath -> purl for external packages
    pkgpath_to_purl: Dict[str, str] = {}
    for e in cg.get("edges", []) or []:
        if not isinstance(e, dict):
            continue
        tgt = cg_nodes.get(e.get("targetId")) or {}
        # Resolve the target's purl: try edge purls, then node purl, then
        # node module purl, then packagePath via module index
        vpurl = (
            reconcile_purl(e.get("sinkPurl"), bom_index)
            or _module_purl_from_obj(tgt.get("module"), bom_index)
            or reconcile_purl(tgt.get("purl"), bom_index)
            or _resolve_package_path(tgt.get("packagePath"), module_index)
        )
        if not vpurl:
            continue
        # Skip stdlib and main module targets
        if tgt.get("standard") or _is_main_module(tgt):
            continue
        # Attribution indexes are built from every external edge, reachable or
        # not: a KEPT slice can traverse an unreachable intermediate function,
        # and its nodes still need purl attribution. Only the usage evidence
        # below is gated on reachability.
        # Index by name for dataflow node matching
        tgt_name = e.get("targetName") or tgt.get("label") or tgt.get("name") or ""
        for nm in (tgt.get("name"), tgt.get("label"), tgt_name):
            if nm:
                symbol_to_purl.setdefault(nm, vpurl)
        # Index by packagePath
        pp = tgt.get("packagePath")
        if pp:
            pkgpath_to_purl.setdefault(pp, vpurl)
        # Skip targets the roots provably never reach: an edge between two
        # unreachable functions inside a dependency is library self-analysis,
        # not reachability evidence for the application.
        if has_reachability and not cg_reach.get(e.get("targetId"), False):
            continue
        # An edge into a package init runs for any import, blank imports
        # included. When the package has no reachable non-init node at all,
        # the import is the whole story -- keep the package unreached.
        if (
            has_reachability
            and _is_init_function(e.get("targetId") or "")
            and (tgt.get("packagePath") or "") not in pkgs_with_reachable_code
        ):
            continue
        # Skip edges rooted entirely in local (app) code targeting local code
        # (those are intra-app calls, not dependency reachability)
        pos = tgt.get("position") or e.get("position") or {}
        rec = {
            "callee": tgt_name,
            "purl": vpurl,
            "position": pos,
            "source": e.get("sourceName") or "",
            "rule_name": "call-graph",
        }
        external_call_records.append(rec)

    flows: List[dict] = []

    # --- 1. dataflow slice flows -----------------------------------------
    for sl in df.get("slices", []) or []:
        if not isinstance(sl, dict):
            continue
        # golem's reachableFromRoots is False only for slices that live
        # entirely in code the application never drives into. Absent (older
        # golem, or no call graph) keeps the slice: the flag is a filter, not
        # a requirement.
        if sl.get("reachableFromRoots") is False:
            continue
        flow_purls: set = set()
        flow_nodes: List[dict] = []

        # slice-level purls + source/sink purls
        for rp in sl.get("purls", []) or []:
            vp = reconcile_purl(rp, bom_index)
            if vp:
                flow_purls.add(vp)
        for key in ("sourcePurl", "sinkPurl"):
            vp = reconcile_purl(sl.get(key, ""), bom_index)
            if vp:
                flow_purls.add(vp)

        # source/sink packagePath resolution via module index
        for key in ("sourcePackagePath", "sinkPackagePath"):
            pp = sl.get(key, "")
            vp = _resolve_package_path(pp, module_index)
            if vp:
                flow_purls.add(vp)

        # source/sink names may name an external symbol directly
        for key in ("sourceName", "sinkName"):
            nm = sl.get(key, "")
            if nm in symbol_to_purl:
                flow_purls.add(symbol_to_purl[nm])

        rule_name = sl.get("ruleName") or sl.get("ruleId") or ""
        sink_category = sl.get("sinkCategory") or ""
        node_ids_list = sl.get("nodeIds", []) or []
        last_idx = len(node_ids_list) - 1

        # traverse witness nodes
        for idx, nid in enumerate(node_ids_list):
            n = df_nodes.get(nid) or {}
            # Resolve node purl: node.purl, node.module.purl, packagePath via
            # module index, or symbol name match
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
            pos = n.get("position") or {}
            # When this node names a known EXTERNAL symbol, the node represents
            # the call INTO the dependency. Tag it with the DEPENDENCY purl and
            # propagate the slice's sink category.
            tag_purl = sym_purl or npurl
            node_category = n.get("category") or (sink_category if sym_purl else "")
            is_external = sym_purl is not None
            # Map the analyzer node role to an atom label so the explainer
            # (flow_to_str / flow_to_source_sink) picks a good description.
            if is_external:
                node_label = "CALL"
            elif idx == 0:
                node_label = "METHOD_PARAMETER_IN"
            elif idx == last_idx:
                node_label = "RETURN"
            else:
                node_label = "IDENTIFIER"
            enclosing = n.get("function") or sl.get("sinkFunction") or ""
            flow_nodes.append(
                {
                    "id": nid,
                    "tags": _build_node_tags(tag_purl, node_category, rule_name),
                    "code": nm,
                    "fullName": enclosing,
                    "lineNumber": _pos_line(pos),
                    "columnNumber": _pos_col(pos),
                    "parentFileName": (pos or {}).get("filename", ""),
                    "label": node_label,
                    "name": nm,
                    "parentMethodName": enclosing,
                    "isExternal": is_external,
                }
            )

        if not flow_purls:
            continue

        # Ensure every node carries a reconciled purl in its tags so
        # SemanticReachability's positional association can fire for the slice
        # purls too
        represented = set()
        for fn in flow_nodes:
            t = fn.get("tags", "")
            for piece in t.split(","):
                piece = piece.strip()
                if piece.startswith("pkg:"):
                    represented.add(piece)
        missing = flow_purls - represented
        if missing and flow_nodes:
            sink_node = flow_nodes[-1]
            for m in sorted(missing):
                extra_tag = _build_node_tags(m, sink_category, rule_name)
                sink_node["tags"] = sink_node["tags"] + ", " + extra_tag

        flows.append({"flows": flow_nodes, "purls": sorted(flow_purls)})

    # --- 2. call-graph external-module flows -----------------------------
    # Each external-module call becomes an honest 2-node flow: the enclosing
    # caller function (source) -> the external symbol call (sink). The source
    # node carries lineNumber 0 so the explainer's consecutive same-loc dedup
    # does not eat the sink node (both share the same call-site file).
    for rec in external_call_records:
        callee = rec.get("callee") or ""
        source = rec.get("source") or ""
        pos = rec.get("position") or {}
        parent_file = (pos or {}).get("filename", "")
        flow_hash = hashlib.md5((callee + "|" + source).encode("utf-8")).hexdigest()[:16]
        caller_short = source.rsplit(".", 1)[-1] if source else callee
        callee_short = callee.rsplit(".", 1)[-1] if callee else ""
        source_node = {
            "id": "golem-cg-src-" + flow_hash,
            "tags": _build_node_tags(None, "call-graph", "call-graph"),
            "code": source or callee,
            "fullName": source,
            "lineNumber": 0,
            "columnNumber": 0,
            "parentFileName": parent_file,
            "label": "IDENTIFIER",
            "name": caller_short,
            "parentMethodName": source,
            "isExternal": False,
        }
        sink_node = {
            "id": "golem-cg-" + flow_hash,
            "tags": _build_node_tags(rec["purl"], "call-graph", "call-graph"),
            "code": callee,
            "fullName": callee,
            "lineNumber": _pos_line(pos),
            "columnNumber": _pos_col(pos),
            "parentFileName": parent_file,
            "label": "CALL",
            "name": callee_short,
            "parentMethodName": source,
            "isExternal": True,
        }
        flows.append({"flows": [source_node, sink_node], "purls": [rec["purl"]]})

    # --- 3. usage flows (PRIMARY signal for simple Go projects) ----------
    # golem's call graph can be sparse for simple apps (SSA-level edges may
    # not form), but the ``usages[]`` section is ALWAYS populated when the
    # app references or calls a dependency's symbols. Each usage with a
    # resolved module purl becomes a 2-node flow: the enclosing caller
    # function (source) -> the external symbol (sink). This mirrors cdxgen's
    # ``addUsageEvidence`` and lets the flow render in the explainer.
    for usage in report.get("usages", []) or []:
        if not isinstance(usage, dict):
            continue
        # Skip stdlib usages (no module or standard:true)
        if usage.get("standard"):
            continue
        # Resolve the usage's module purl
        vpurl = _module_purl_from_obj(usage.get("module"), bom_index) or _resolve_package_path(
            usage.get("packagePath"), module_index
        )
        if not vpurl:
            continue
        # Skip the app's own module (we only want dependency reachability)
        mod_obj = usage.get("module") or {}
        if isinstance(mod_obj, dict) and mod_obj.get("main"):
            continue
        sym = usage.get("qualifiedName") or usage.get("name") or ""
        enclosing_obj = usage.get("enclosing")
        enclosing_name = enclosing_obj.get("name", "") if isinstance(enclosing_obj, dict) else ""
        rng = usage.get("range") or {}
        pos = rng.get("start") if isinstance(rng, dict) else {}
        parent_file = (pos or {}).get("filename", "")
        flow_hash = hashlib.md5((vpurl + "|" + sym).encode("utf-8")).hexdigest()[:16]
        sym_short = sym.rsplit(".", 1)[-1] if sym else ""
        caller_short = enclosing_name.rsplit(".", 1)[-1] if enclosing_name else sym_short
        # Source node: the enclosing caller function
        source_node = {
            "id": "golem-usage-src-" + flow_hash,
            "tags": _build_node_tags(None, "call-graph", "usage"),
            "code": enclosing_name or sym,
            "fullName": enclosing_name,
            "lineNumber": 0,
            "columnNumber": 0,
            "parentFileName": parent_file,
            "label": "IDENTIFIER",
            "name": caller_short,
            "parentMethodName": enclosing_name,
            "isExternal": False,
        }
        # Sink node: the external dependency symbol
        sink_node = {
            "id": "golem-usage-" + flow_hash,
            "tags": _build_node_tags(vpurl, "call-graph", "usage"),
            "code": sym,
            "fullName": sym,
            "lineNumber": _pos_line(pos),
            "columnNumber": _pos_col(pos),
            "parentFileName": parent_file,
            "label": "CALL",
            "name": sym_short,
            "parentMethodName": enclosing_name,
            "isExternal": True,
        }
        flows.append({"flows": [source_node, sink_node], "purls": [vpurl]})

    # --- 4. apiEndpoint handler flows ------------------------------------
    # Each HTTP endpoint golem discovered becomes a flow. The handler's home
    # module purl is resolved from ``packagePath`` via the module index.
    for ep in report.get("apiEndpoints", []) or []:
        if not isinstance(ep, dict):
            continue
        pp = ep.get("packagePath") or ""
        handler_vpurl = _resolve_package_path(pp, module_index)
        if not handler_vpurl:
            continue
        method = ep.get("method") or ""
        path = ep.get("path") or ""
        framework = ep.get("framework") or ""
        handler = ep.get("handler") or ""
        pos = _range_start_pos(ep.get("range")) or {}
        rule = "endpoint" + (f"-{framework}" if framework else "")
        endpoint_code = f"{method} {path}".strip()
        ep_nodes: List[dict] = [
            {
                "id": "golem-ep-"
                + hashlib.md5((method + "|" + path + "|" + handler).encode("utf-8")).hexdigest()[
                    :16
                ],
                "tags": _build_node_tags(
                    handler_vpurl,
                    "endpoint",
                    rule,
                    service_tag=GOLEM_ENDPOINT_SERVICE_TAG,
                ),
                "code": endpoint_code,
                "fullName": handler,
                "lineNumber": _pos_line(pos),
                "columnNumber": _pos_col(pos),
                "parentFileName": (pos or {}).get("filename", ""),
                "label": "CALL",
                "name": path or handler,
                "parentMethodName": handler,
                "isExternal": True,
            }
        ]
        flows.append({"flows": ep_nodes, "purls": [handler_vpurl]})

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


def _is_main_module(node: dict) -> bool:
    """Check if a golem node/edge target is the workspace app module."""
    mod = node.get("module")
    if isinstance(mod, dict) and mod.get("main"):
        return True
    return False


def _range_start_pos(rng: Optional[dict]) -> Optional[dict]:
    """Extract the start position from a golem ``Range`` object."""
    if not isinstance(rng, dict):
        return None
    start = rng.get("start")
    return start if isinstance(start, dict) else None


def _sort_key_flows(flows: List[dict]) -> str:
    if not flows:
        return ""
    return str(flows[0].get("id", ""))


def write_slices_file(slice_path: str, flows: List[dict]) -> None:
    """Write the atom-shaped slice list atomically and deterministically."""
    os.makedirs(os.path.dirname(os.path.abspath(slice_path)) or ".", exist_ok=True)
    payload = json.dumps(flows, sort_keys=True, separators=(",", ":"))
    tmp = slice_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fp:
        fp.write(payload)
    os.replace(tmp, slice_path)


def is_golem_report(report) -> bool:
    """Return True if ``report`` has the structural shape of a golem report.

    Detection is by shape: a dict carrying a golem producer identity
    (``tool`` or ``runtime``) AND at least one analysis section we consume
    (``callGraph`` or ``dataFlow``). Note: golem JSON uses **lowerCamelCase**
    keys (``callGraph``/``dataFlow``), not rusi's snake_case
    (``call_graph``/``data_flow``). This reliably distinguishes a genuine
    golem report from an atom semantics slice that shares the path.
    """
    if not isinstance(report, dict):
        return False
    has_producer = any(isinstance(report.get(k), dict) for k in GOLEM_PRODUCER_KEYS)
    has_section = any(isinstance(report.get(k), dict) for k in GOLEM_SECTION_KEYS)
    return has_producer and has_section
