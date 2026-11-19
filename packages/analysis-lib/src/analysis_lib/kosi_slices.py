"""kosi (Kotlin Source Inspector) report -> atom reachables-slice converter.

The reachability engine is purl-keyed and reads ``*reachables.slices*.json``
files, not analyzer reports. This module turns a kosi report (schema
``kosi/1``, lowerCamelCase) into that file so Kotlin, Java-on-Kotlin and
Android projects feed ``FrameworkReachability`` and ``SemanticReachability``
the same way golem and rusi reports do.

Three kinds of evidence become flows:

1. Dataflow slices (``dataFlow.slices[]``, resolved tier). Each slice becomes
   one flow whose nodes are the slice's ``frames[]``, source first, sink last.
2. Library usages (``usages[]``). A call such as ``Request.Builder.url`` is
   joined to the file's imports to get a fully qualified name, then attributed
   to a BOM dependency.
3. Call-graph edges that end in an external, non-standard-library function.
   The resolved tier at the ``static`` call-graph mode keeps only workspace
   functions as nodes, so this is empty there and appears when a mode or
   dependency view brings dependency functions into the graph.

Attribution of a name to a BOM dependency, in order: the ``purl`` kosi itself
resolved (resolved tier, matched to the jar whose package prefix the import
carries); otherwise a package-prefix match of the fully qualified name against
the Maven group and artifact of each BOM component (see
:func:`attribute_name`). Star imports attribute nothing, and an import that
ties several artifacts attributes none. The prefix match is a heuristic and
is limited to what the coordinates reveal: a library whose Java package shares nothing with
its Maven group and artifact is not attributed, which leaves it "not
observed", never reached.

Per-function root reachability from ``callGraph.reachability[]`` (``reached``,
``distance``, ``roots``) is carried onto slice frames and call-graph nodes as
``reachableFromRoots``, ``minDepth`` and ``rootScopes``. kosi's roots are
scope names such as ``main`` or ``handlers``, not node ids, hence the name. Nothing is dropped because a function is not reached: kosi's
static call graph misses interface and callback dispatch, so ``reached: false``
is not evidence that code is unused.

Public surface:
    - :func:`build_bom_purl_index`
    - :func:`attribute_name`
    - :func:`convert_kosi_report`
    - :func:`write_slices_file`
    - :func:`is_kosi_report`
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Dict, Iterable, List, Optional, Set, Tuple

KOSI_SCHEMA_PREFIX = "kosi/"

# kosi dataflow categories -> dep-scan SERVICE_TAGS vocabulary (config.py).
# Only categories whose intent clearly maps to an existing service tag.
KOSI_CATEGORY_TO_SERVICE_TAG = {
    "sql-query": "sql",
    "sql-injection": "sql",
    "ssrf": "http",
    "network-request": "http",
    "network-connect": "http",
    "xss": "web",
    "process-exec": "rpc",
    "command-execution": "rpc",
    "process-execution": "rpc",
}

# Package segments that name a language runtime rather than a dependency; a
# Maven group never owns them, so a name under them is not attributed.
_RUNTIME_ROOTS = frozenset({"java", "javax", "kotlin", "jdk", "sun", "android", "androidx"})

# Minimum length of a Maven group's last segment before it may stand alone as
# a package root (``okhttp3`` for ``com.squareup.okhttp3``). Shorter segments
# such as ``core`` or ``api`` are shared by unrelated libraries.
_MIN_GROUP_TAIL_LEN = 5

_MAVEN_RE = re.compile(r"^pkg:maven/([^/@?#]+)/([^/@?#]+)")


def is_kosi_report(report) -> bool:
    """True when ``report`` looks like a kosi report, by shape.

    A kosi report is a JSON object whose ``schemaVersion`` is in the ``kosi/``
    family and which carries the ``tool`` block. Shape, not file name, tells it
    apart from an atom-produced ``*-semantics.slices.json`` at the same path.
    """
    if not isinstance(report, dict):
        return False
    schema = str(report.get("schemaVersion") or "")
    tool = report.get("tool")
    return schema.startswith(KOSI_SCHEMA_PREFIX) and isinstance(tool, dict)


def _purl_without_version(purl: Optional[str]) -> str:
    if not purl:
        return ""
    return purl.split("?")[0].split("#")[0].split("@")[0]


def build_bom_purl_index(
    bom_components: Optional[Iterable[dict]],
    extra_components: Optional[Iterable[dict]] = None,
) -> Dict[str, str]:
    """Map exact and version-stripped Maven purls of the BOM to the versioned
    purl. ``extra_components`` (the workspace root) is indexed whatever its
    purl type, so a flow attributed to the project itself still resolves."""
    index: Dict[str, str] = {}
    for c in list(bom_components or []):
        purl = c.get("purl", "") if isinstance(c, dict) else ""
        if isinstance(purl, str) and purl.startswith("pkg:maven/"):
            index.setdefault(purl, purl)
            index.setdefault(_purl_without_version(purl), purl)
    for c in list(extra_components or []):
        purl = c.get("purl", "") if isinstance(c, dict) else ""
        if isinstance(purl, str) and purl.startswith("pkg:"):
            index.setdefault(purl, purl)
            index.setdefault(_purl_without_version(purl), purl)
    return index


def reconcile_purl(purl: Optional[str], bom_index: Dict[str, str]) -> Optional[str]:
    """Map a purl onto the BOM's versioned purl, ignoring version and
    qualifiers; ``None`` when the BOM has no such component."""
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        return None
    if purl in bom_index:
        return bom_index[purl]
    return bom_index.get(_purl_without_version(purl))


def _package_roots(purl: str) -> List[Tuple[str, bool]]:
    """Package prefixes a Maven coordinate implies, as ``(prefix, specific)``.

    ``specific`` marks prefixes that name the artifact (``group.artifact``)
    and so beat the group-level ones when both match.
    """
    match = _MAVEN_RE.match(purl)
    if not match:
        return []
    group, artifact = match.group(1), match.group(2)
    roots: List[Tuple[str, bool]] = [(group + "." + artifact.replace("-", "."), True)]
    roots.append((group, False))
    tail = group.rsplit(".", 1)[-1]
    if "." in group and len(tail) >= _MIN_GROUP_TAIL_LEN:
        roots.append((tail, False))
    return roots


def attribute_name(name: str, bom_index: Dict[str, str]) -> Set[str]:
    """BOM purls whose coordinates match the fully qualified ``name``.

    The longest matching package prefix wins; artifact-level prefixes beat
    group-level ones. A name is attributed only when exactly one BOM artifact
    owns that best prefix: several artifacts of one group tie on a group-level
    prefix, and the name alone cannot tell them apart, so none is returned
    (a package must never be marked reached on a guess). Names under a
    language runtime root (``java``, ``kotlin``, ``android``) are never
    attributed.
    """
    if not name or name.split(".", 1)[0] in _RUNTIME_ROOTS:
        return set()
    best_key: Tuple[int, int] = (0, 0)
    best: Set[str] = set()
    for purl in sorted(set(bom_index.values())):
        for prefix, specific in _package_roots(purl):
            if name == prefix or name.startswith(prefix + "."):
                key = (1 if specific else 0, len(prefix))
                if key > best_key:
                    best_key, best = key, {purl}
                elif key == best_key:
                    best.add(purl)
    return best if len(best) == 1 else set()


def _reach_fields(entry: Optional[dict]) -> dict:
    """The root-reachability keys carried onto a flow node."""
    if not isinstance(entry, dict):
        return {}
    out: dict = {"reachableFromRoots": bool(entry.get("reached"))}
    distance = entry.get("distance")
    if isinstance(distance, int) and distance >= 0:
        out["minDepth"] = distance
    out["rootScopes"] = [r for r in entry.get("roots", []) or [] if isinstance(r, str)]
    return out


def _tags(purl: Optional[str], category: str, rule_name: str) -> str:
    """``"<purl>, <service-or-category>, kotlin, <rule>"``: the token after the
    purl is the service tag when one applies, so positional association in
    ``SemanticReachability`` attributes it to this purl."""
    parts: List[str] = []
    if purl:
        parts.append(purl)
    parts.append(KOSI_CATEGORY_TO_SERVICE_TAG.get(category or "") or category or "kotlin")
    if parts[-1] != "kotlin":
        parts.append("kotlin")
    if rule_name:
        parts.append(rule_name)
    return ", ".join(parts)


def _pos(pos: Optional[dict]) -> Tuple[int, int]:
    pos = pos if isinstance(pos, dict) else {}
    return int(pos.get("line") or 0), int(pos.get("column") or 0)


def _function_reach(cg: dict) -> Dict[str, dict]:
    """``canonicalName -> reachability fields`` for every call-graph node."""
    by_id = {e.get("nodeId"): e for e in cg.get("reachability", []) or [] if isinstance(e, dict)}
    out: Dict[str, dict] = {}
    for node in cg.get("nodes", []) or []:
        if not isinstance(node, dict):
            continue
        entry = by_id.get(node.get("id"))
        name = node.get("canonicalName")
        if entry is not None and name:
            out[name] = _reach_fields(entry)
    return out


def _qualify_usage(usage: dict, file_imports: List[dict]) -> List[str]:
    """Fully qualified candidates for a usage name, from the file's imports.

    ``Request.Builder.url`` with ``import okhttp3.Request`` becomes
    ``okhttp3.Request.Builder.url``. The first segment is matched against an
    import's alias or last segment. A wildcard import contributes nothing:
    the name alone does not say which wildcard (or the file's own package)
    owns it, so a local function would be attributed to the wildcard's
    library.
    """
    name = usage.get("name") or ""
    if not name:
        return []
    head, _, rest = name.partition(".")
    out: List[str] = []
    for imp in file_imports:
        fqn = imp.get("name") or ""
        if not fqn:
            continue
        if imp.get("star"):
            continue
        bound = imp.get("alias") or fqn.rsplit(".", 1)[-1]
        if bound == head:
            out.append(fqn + ("." + rest if rest else ""))
    return out


def _frame_nodes(
    sl: dict,
    purl_by_function: Dict[str, str],
    func_reach: Dict[str, dict],
    sink_purls: Set[str],
    rule_name: str,
) -> List[dict]:
    """Flow nodes for one slice, from its ``frames[]`` (source first)."""
    frames = [f for f in sl.get("frames", []) or [] if isinstance(f, dict)]
    last = len(frames) - 1
    category = sl.get("sinkCategory") or ""
    nodes: List[dict] = []
    for idx, fr in enumerate(frames):
        function = fr.get("function") or ""
        line = int(fr.get("line") or 0)
        role = fr.get("role") or ""
        is_sink = idx == last
        purl = None
        if is_sink and sink_purls:
            purl = sorted(sink_purls)[0]
        elif function in purl_by_function:
            purl = purl_by_function[function]
        node = {
            "id": f"{sl.get('id') or 'kosi-slice'}-f{idx}",
            "tags": _tags(purl, category if is_sink else "", rule_name),
            "code": (sl.get("sinkName") if is_sink else None) or function,
            "fullName": function,
            "lineNumber": line,
            "columnNumber": 0,
            "parentFileName": fr.get("file") or "",
            "label": "CALL" if is_sink else ("METHOD_PARAMETER_IN" if idx == 0 else "IDENTIFIER"),
            "name": function.rsplit(".", 1)[-1],
            "parentMethodName": function,
            "isExternal": bool(is_sink and sink_purls),
            "frameRole": role,
        }
        node.update(func_reach.get(function, {}))
        nodes.append(node)
    return nodes


def convert_kosi_report(report: dict, bom_index: Dict[str, str]) -> List[dict]:
    """Convert a parsed kosi report into atom-shaped reachables flows.

    Each flow is ``{"flows": [node, ...], "purls": [versioned-purl, ...]}``.
    Flows that name no BOM dependency are dropped, so a slice that only
    crosses workspace code adds nothing. The result is deduplicated and
    sorted, so the file is byte-stable across runs on the same report.
    """
    if not isinstance(report, dict):
        return []
    df = report.get("dataFlow") or {}
    cg = report.get("callGraph") or {}
    func_reach = _function_reach(cg)
    flows: List[dict] = []

    # --- 1. dataflow slices ---------------------------------------------
    for sl in df.get("slices", []) or []:
        if not isinstance(sl, dict):
            continue
        purls: Set[str] = set()
        for key in ("sourcePurl", "targetPurl"):
            vp = reconcile_purl(sl.get(key), bom_index)
            if vp:
                purls.add(vp)
        for p in sl.get("purls", []) or []:
            vp = reconcile_purl(p, bom_index)
            if vp:
                purls.add(vp)
        source_purls = attribute_name(sl.get("sourceName") or "", bom_index)
        sink_purls = attribute_name(sl.get("sinkName") or "", bom_index)
        purls |= source_purls | sink_purls
        if not purls:
            continue
        rule_name = sl.get("ruleName") or sl.get("ruleId") or ""
        purl_by_function: Dict[str, str] = {}
        if source_purls:
            purl_by_function[sl.get("sourceFunction") or ""] = sorted(source_purls)[0]
        nodes = _frame_nodes(sl, purl_by_function, func_reach, sink_purls, rule_name)
        if not nodes:
            continue
        # every purl on the flow must appear in a node tag for positional
        # attribution, so any not yet shown is appended to the sink node
        shown = {
            p.strip() for n in nodes for p in n["tags"].split(",") if p.strip().startswith("pkg:")
        }
        for missing in sorted(purls - shown):
            nodes[-1]["tags"] += ", " + _tags(missing, sl.get("sinkCategory") or "", rule_name)
        flows.append({"flows": nodes, "purls": sorted(purls)})

    # --- 2. usages ---------------------------------------------------------
    imports_by_file: Dict[str, List[dict]] = {}
    for imp in report.get("imports", []) or []:
        if isinstance(imp, dict):
            imports_by_file.setdefault(imp.get("filePath") or "", []).append(imp)
    seen_usage: Set[Tuple[str, str]] = set()
    for usage in report.get("usages", []) or []:
        if not isinstance(usage, dict):
            continue
        file_path = usage.get("filePath") or ""
        file_imports = imports_by_file.get(file_path, [])
        candidates = _qualify_usage(usage, file_imports)
        purls = set()
        qualified = ""
        for cand in candidates:
            attributed = attribute_name(cand, bom_index)
            if attributed:
                purls |= attributed
                qualified = qualified or cand
        # a resolved import purl beats the name heuristic
        for imp in file_imports:
            fqn = imp.get("name") or ""
            if qualified and fqn and qualified.startswith(fqn):
                vp = reconcile_purl(imp.get("purl"), bom_index)
                if vp:
                    purls = {vp}
                break
        if not purls:
            continue
        for purl in sorted(purls):
            ident = (purl, qualified)
            if ident in seen_usage:
                continue
            seen_usage.add(ident)
            line, col = _pos(usage.get("position"))
            digest = hashlib.md5(f"{purl}|{qualified}".encode("utf-8")).hexdigest()[:16]
            short = qualified.rsplit(".", 1)[-1]
            source_node = {
                "id": "kosi-usage-src-" + digest,
                "tags": _tags(None, "call-graph", "usage"),
                "code": file_path,
                "fullName": file_path,
                "lineNumber": 0,
                "columnNumber": 0,
                "parentFileName": file_path,
                "label": "IDENTIFIER",
                "name": os.path.basename(file_path),
                "parentMethodName": file_path,
                "isExternal": False,
            }
            sink_node = {
                "id": "kosi-usage-" + digest,
                "tags": _tags(purl, "call-graph", "usage"),
                "code": qualified,
                "fullName": qualified,
                "lineNumber": line,
                "columnNumber": col,
                "parentFileName": file_path,
                "label": "CALL",
                "name": short,
                "parentMethodName": file_path,
                "isExternal": True,
            }
            flows.append({"flows": [source_node, sink_node], "purls": [purl]})

    # --- 3. call-graph edges into external, non-stdlib functions ---------
    nodes_by_id = {n.get("id"): n for n in cg.get("nodes", []) or [] if isinstance(n, dict)}
    by_reach = {
        e.get("nodeId"): e for e in cg.get("reachability", []) or [] if isinstance(e, dict)
    }
    for edge in cg.get("edges", []) or []:
        if not isinstance(edge, dict):
            continue
        target = nodes_by_id.get(edge.get("targetId")) or {}
        source = nodes_by_id.get(edge.get("sourceId")) or {}
        if not target.get("external") or target.get("stdlib"):
            continue
        purls = attribute_name(target.get("canonicalName") or "", bom_index)
        vp = reconcile_purl(target.get("purl"), bom_index)
        if vp:
            purls = {vp}
        if not purls:
            continue
        callee = target.get("canonicalName") or ""
        caller = source.get("canonicalName") or ""
        for purl in sorted(purls):
            digest = hashlib.md5(f"{callee}|{caller}|{purl}".encode("utf-8")).hexdigest()[:16]
            src_node = {
                "id": "kosi-cg-src-" + digest,
                "tags": _tags(None, "call-graph", "call-graph"),
                "code": caller,
                "fullName": caller,
                "lineNumber": 0,
                "columnNumber": 0,
                "parentFileName": source.get("filePath") or "",
                "label": "IDENTIFIER",
                "name": caller.rsplit(".", 1)[-1],
                "parentMethodName": caller,
                "isExternal": False,
            }
            src_node.update(_reach_fields(by_reach.get(source.get("id"))))
            sink_node = {
                "id": "kosi-cg-" + digest,
                "tags": _tags(purl, "call-graph", "call-graph"),
                "code": callee,
                "fullName": callee,
                "lineNumber": int(edge.get("line") or 0),
                "columnNumber": 0,
                "parentFileName": source.get("filePath") or "",
                "label": "CALL",
                "name": callee.rsplit(".", 1)[-1],
                "parentMethodName": caller,
                "isExternal": True,
            }
            flows.append({"flows": [src_node, sink_node], "purls": [purl]})

    return _dedupe_sorted(flows)


def _dedupe_sorted(flows: List[dict]) -> List[dict]:
    """Drop flows with an identical node-id sequence and purls, then sort."""
    seen: Set[str] = set()
    unique: List[dict] = []
    for f in flows:
        ident = json.dumps(
            [[n.get("id"), n.get("lineNumber")] for n in f["flows"]] + [f["purls"]],
            sort_keys=True,
        )
        if ident in seen:
            continue
        seen.add(ident)
        unique.append(f)
    unique.sort(key=lambda f: (tuple(f["purls"]), f["flows"][0]["id"] if f["flows"] else ""))
    return unique


def write_slices_file(slice_path: str, flows: List[dict]) -> None:
    """Write the slice list atomically and deterministically."""
    os.makedirs(os.path.dirname(os.path.abspath(slice_path)) or ".", exist_ok=True)
    payload = json.dumps(flows, sort_keys=True, separators=(",", ":"))
    tmp = slice_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fp:
        fp.write(payload)
    os.replace(tmp, slice_path)
