"""rusi (Rust Source Inspector) report -> evidence records.

This module is the only code that knows the rusi report format: a
snake_case JSON object whose ``schema_version`` is a URL ending in
``report-<major>.<minor>``, carrying ``tool``/``runtime``, a ``call_graph``
and a ``data_flow``.

Four kinds of evidence become records:

1. Dataflow slices (``data_flow.slices[]``) become ``reached-flow`` records
   whose ``path`` is the slice's witness nodes in rusi's order.
2. Call-graph edges whose target names an external crate with a purl become
   ``reached-flow`` records with the caller-to-callee two-node path. The
   target purl is what the record is about: rusi stamps the external
   function with the crate it belongs to, so an unresolved workspace-local
   call (no purl) is not dependency evidence.
3. ``api_endpoints[]`` become ``entry-point`` records whose subject is the
   framework crate that serves the route. The crate holding the handler is
   named in the ``handlerPurl`` attribute and gets a ``reached-flow`` record
   of its own, so it counts as reached but not as a service.
4. ``usages[]`` become ``callsite`` records, a kind the reached sets never
   count. The crate the usage sits in is the ``callerPurl`` attribute; the
   subject is the called crate only when the call graph names that exact
   qualified symbol.

rusi emits versioned purls only for workspace packages; external crates get
unversioned ``pkg:cargo/<name>``. The Cargo BOM is keyed at versioned
purls, so the reconciliation matches by crate NAME (mirroring rusi's own
``-``/``_`` normalization and percent-encoding) onto the BOM's versioned
purls. Rust standard-library pseudo-crates (``fs``, ``std``, ``core`` ...)
never correspond to real dependencies, and a call into one is not dependency
evidence. Every other report object that makes no record (a slice or edge
that names only crates the BOM does not carry, an entry that is not a JSON
object) is counted in one ``record-skipped`` caveat per reason.

File paths are relative to the analysed directory rusi names
(``options.directory``) or the caller's source root; a file in the manifest
directory of a crate outside the workspace is spelled
``<crate>-<version>/<file>``, a file in the Cargo registry by its registry
path, and any other absolute path is left out with a
``location-outside-root`` caveat. Record ids leave out rusi's own object ids
and spell the roots the same way wherever the report was produced.

rusi's ``diagnostics`` (top level, and per section) travel with the
records: a diagnostic about the analysis running out of time or cutting
call candidates is a ``timeout``/``budget`` caveat on the producer result
and on every record, since either can hide evidence anywhere; a resolution
diagnostic (an unresolved or external call target) is an
``unresolved-call-sites`` caveat on the producer result and on the records
whose slice names, callee or usage name are exactly that target.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import unquote

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
#: knows. rusi's schema version is a URL whose last segment is
#: ``report-<major>.<minor>``.
SUPPORTED_MAJOR = 0
KNOWN_MINOR = 1

#: rusi reports are detected by SHAPE, not the opaque ``schema_version`` URL
#: prefix: a JSON object carrying its producer identity (``tool``/``runtime``)
#: alongside at least one analysis section this module consumes
#: (``call_graph``/``data_flow``). Detection by shape cleanly separates a
#: genuine rusi report from an atom semantics slice that happens to share
#: the ``<type>-semantics.slices.json`` path.
PRODUCER_NAME = "rusi"
RUSI_PRODUCER_KEYS = ("tool", "runtime")
RUSI_SECTION_KEYS = ("call_graph", "data_flow")

# Rust stdlib + rustc-internal pseudo-crates that rusi emits as unversioned
# ``pkg:cargo/<name>`` (e.g. ``pkg:cargo/fs`` for ``fs::read_to_string``).
# These never correspond to real Cargo dependencies, so they are dropped
# unconditionally. Kept conservative: only names that are DEFINITELY
# stdlib/rustc-internal, never a real crate a security analyst would care
# about. ``libc``/``hashbrown``/``cfg_if`` are deliberately excluded; they
# are real crates people depend on.
RUST_STDLIB_PSEUDO_CRATES = frozenset(
    {
        "std",
        "core",
        "alloc",
        "fs",
        "proc_macro",
        "test",
        "panic_unwind",
        "panic_abort",
        "unwind",
        "profiler_builtins",
        "rustc_std_workspace_core",
        "rustc_std_workspace_alloc",
        "rustc_std_workspace_std",
        "rustc_demangle",
        "addr2line",
        "gimli",
        "object",
        "miniz_oxide",
    }
)

# rusi dataflow source/sink categories -> dep-scan SERVICE_TAGS vocabulary
# (config.py). Conservative mapping: only categories whose intent clearly
# maps to an existing service tag.
RUSI_CATEGORY_TO_SERVICE_TAG = {
    # sinks
    "sql-query": "sql",
    "network-request": "http",
    "network-connect": "http",
    "html-response": "web",
    # sources
    "http-request": "http",
}

# Service tag for HTTP api_endpoint records; ``api`` is a SERVICE_TAG so
# SemanticReachability attributes the framework crate to reached_services.
RUSI_ENDPOINT_SERVICE_TAG = "api"


def is_rusi_report(report) -> bool:
    """True when ``report`` has the structural shape of a rusi report."""
    if not isinstance(report, dict):
        return False
    has_producer = any(isinstance(report.get(k), dict) for k in RUSI_PRODUCER_KEYS)
    has_section = any(isinstance(report.get(k), dict) for k in RUSI_SECTION_KEYS)
    return has_producer and has_section


# ---------------------------------------------------------------------------
# Purl parsing + reconciliation
# ---------------------------------------------------------------------------


def _parse_purl(purl: Optional[str]) -> Tuple[str, str]:
    """Split ``pkg:<type>/<name>[@<version>][?qualifiers]`` into (name, type).

    Returns ("", "") for non-purl / malformed input. ``name`` is URL-decoded
    and version/qualifiers stripped; only the final path segment is kept,
    which mirrors the BOM component name for type=cargo.
    """
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        return "", ""
    body = purl[len("pkg:") :]
    ptype, _, rest = body.partition("/")
    if not rest:
        return "", ptype
    rest = rest.split("?", 1)[0]
    name_segment = rest.rsplit("/", 1)[-1]
    name = name_segment.split("@", 1)[0]
    return unquote(name), ptype


def _normalize_crate_name(name: str) -> str:
    """Normalize a cargo crate name for matching.

    Cargo manifest names use ``-`` but Rust code / module paths use ``_``
    (``vulnerable-web-app`` vs ``vulnerable_web_app``); rusi's own
    ``package_purl_index`` indexes both forms. Canonical form is lowercase
    with ``_`` -> ``-``.
    """
    return (name or "").replace("_", "-").lower()


def build_bom_purl_index(
    bom_components: Optional[Iterable[dict]],
    extra_components: Optional[Iterable[dict]] = None,
) -> Dict[str, str]:
    """Build a ``normalized-crate-name -> versioned purl`` index from a BOM.

    Indexes every component whose purl parses as type ``cargo``. When a
    component's purl is missing or odd, its declared ``name`` is indexed
    when the component still looks like a cargo component (through the
    purl-prefixed ``bom-ref``). If two components share a normalized name,
    the first seen wins. ``extra_components`` accepts the metadata.component
    root, so the workspace purl is always in the index.
    """
    index: Dict[str, str] = {}
    for c in list(bom_components or []) + list(extra_components or []):
        if not isinstance(c, dict):
            continue
        purl = c.get("purl", "")
        name, ptype = _parse_purl(purl)
        if ptype != "cargo" or not name:
            cname = c.get("name", "")
            if cname and _looks_like_cargo_component(c):
                index.setdefault(_normalize_crate_name(cname), purl)
            continue
        index.setdefault(_normalize_crate_name(name), purl)
    return index


def _looks_like_cargo_component(c: dict) -> bool:
    """True when a component looks like cargo even with a missing or odd
    purl: a ``pkg:cargo/`` purl, or a ``bom-ref`` echoing the scheme."""
    purl = c.get("purl", "")
    if isinstance(purl, str) and purl.startswith("pkg:cargo/"):
        return True
    bom_ref = c.get("bom-ref", "") or ""
    return "pkg:cargo/" in str(bom_ref)


def reconcile_purl(rusi_purl: Optional[str], bom_index: Dict[str, str]) -> Optional[str]:
    """Map a rusi purl onto a BOM versioned purl by crate NAME.

    Non-cargo, malformed and empty purls map to nothing; stdlib and rustc
    pseudo-crates are dropped unconditionally; an unmatched name maps to
    nothing, because an unmatched rusi purl cannot correspond to a BOM
    component and emitting it would only add noise.
    """
    name, ptype = _parse_purl(rusi_purl)
    if ptype != "cargo" or not name:
        return None
    nkey = _normalize_crate_name(name)
    if nkey in RUST_STDLIB_PSEUDO_CRATES:
        return None
    return bom_index.get(nkey)


# ---------------------------------------------------------------------------
# Version gate
# ---------------------------------------------------------------------------


def _gate_version(report: dict) -> str:
    """The schema version text the gate can read: the tail of rusi's
    ``schema_version`` URL, without its ``report-`` prefix."""
    text = str(report.get("schema_version") or "").strip()
    tail = text.rsplit("/", 1)[-1]
    if tail.startswith("report-"):
        tail = tail[len("report-") :]
    return tail


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

    def caveats(self, base: List[EvidenceCaveat]) -> List[EvidenceCaveat]:
        if not self.left_out:
            return list(base)
        return list(base) + [self.paths.outside_root_caveat(len(self.left_out))]


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
        if not RUSI_CATEGORY_TO_SERVICE_TAG.get(category):
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


def _marker_caveats(report: dict) -> Tuple[List[EvidenceCaveat], Set[str]]:
    """The caveats rusi's diagnostics carry, in the order the report lists
    them, plus the call targets the resolution diagnostics name.

    A diagnostic whose kind or message names a timeout or a cut/budget limit
    hides evidence anywhere in the report, so it becomes a producer-level
    ``timeout``/``budget`` caveat. A resolution diagnostic names one
    unresolved call target and is collected separately, with the target it
    names, so the caveat can land on the records about that exact target.
    """
    caveats: List[EvidenceCaveat] = []
    targets: Set[str] = set()
    sections = [report.get("diagnostics")]
    for key in ("call_graph", "data_flow"):
        sections.append(as_dict(report.get(key)).get("diagnostics"))
    for group in sections:
        for diag in as_list(group):
            if not isinstance(diag, dict):
                continue
            kind = as_str(diag.get("kind"))
            message = as_str(diag.get("message"))
            haystack = f"{kind} {message}".lower()
            if "timeout" in haystack:
                caveats.append(
                    EvidenceCaveat(
                        kind="timeout",
                        detail=f"rusi diagnostic: {message}"
                        if message
                        else "rusi reported a timeout",
                    )
                )
            elif any(word in haystack for word in ("truncat", "budget", "capped", "exceeded")):
                caveats.append(
                    EvidenceCaveat(
                        kind="budget",
                        detail=f"rusi diagnostic: {message}"
                        if message
                        else "rusi reported a budget limit",
                    )
                )
            elif kind == "resolution" or "call target" in haystack:
                target = message.rsplit("call target ", 1)[-1].strip()
                if target and target != message:
                    targets.add(target)
    if targets:
        caveats.append(
            EvidenceCaveat(
                kind="unresolved-call-sites",
                detail="rusi could not resolve calls to " + ", ".join(sorted(targets)),
            )
        )
    return caveats, targets


def _unresolved_caveat(targets: Set[str], names: Iterable[Any]) -> Optional[EvidenceCaveat]:
    """The unresolved-call-sites caveat for a record about ``names``, when
    one of them is exactly a call target rusi could not resolve."""
    hits = sorted({name for name in names if isinstance(name, str) and name in targets})
    if not hits:
        return None
    return EvidenceCaveat(
        kind="unresolved-call-sites",
        detail="rusi could not resolve calls to " + ", ".join(hits),
    )


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


def _source_paths(report: dict, source_root: Optional[str]) -> SourcePaths:
    """The path mapping of one rusi report: the analysed directory rusi
    names (``options.directory``, else ``runtime.working_directory``) and the
    caller's source root as roots, and the manifest directory of every
    package outside the workspace as a ``<crate>-<version>`` prefix."""
    options = as_dict(report.get("options"))
    runtime = as_dict(report.get("runtime"))
    roots = [options.get("directory"), runtime.get("working_directory"), source_root]
    prefixes = []
    for package in as_list(report.get("packages")):
        package = as_dict(package)
        module = as_dict(package.get("module"))
        manifest = as_str(package.get("manifest_path")) or as_str(module.get("manifest_path"))
        if not manifest:
            continue
        directory = manifest.replace("\\", "/").rsplit("/", 1)[0]
        if module.get("workspace_member"):
            roots.append(directory)
            continue
        name = as_str(package.get("name")) or as_str(module.get("name"))
        version = as_str(module.get("version"))
        if name:
            prefixes.append((directory, f"{name}-{version}" if version else name))
    return SourcePaths(roots, prefixes)


#: The report sections the adapter reads, with the JSON type each must have
#: when present. A section of another type is a malformed report.
_SECTION_TYPES = (
    (("options",), dict),
    (("runtime",), dict),
    (("tool",), dict),
    (("packages",), list),
    (("usages",), list),
    (("api_endpoints",), list),
    (("diagnostics",), list),
    (("call_graph",), dict),
    (("call_graph", "nodes"), list),
    (("call_graph", "edges"), list),
    (("call_graph", "diagnostics"), list),
    (("data_flow",), dict),
    (("data_flow", "nodes"), list),
    (("data_flow", "slices"), list),
    (("data_flow", "diagnostics"), list),
)


def _section_problem(report: dict) -> Optional[str]:
    """The first consumed section of the wrong JSON type, named, or ``None``.

    A ``null`` section reads as absent. Any other value of the wrong type
    means the report is not the shape rusi writes.
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


def _is_stdlib_purl(purl: Any) -> bool:
    name, ptype = _parse_purl(purl)
    return ptype == "cargo" and _normalize_crate_name(name) in RUST_STDLIB_PSEUDO_CRATES


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
    """One rusi report as evidence records.

    ``report`` is the parsed rusi report or its JSON text. ``source`` is the
    scan-directory-relative file the report was read from.
    ``producer_version`` is the rusi tool version when the caller knows it;
    the report's own ``tool.version`` is used otherwise. ``bom_components``
    and ``extra_components`` (the metadata.component root) feed the purl
    reconciliation index. ``source_root`` is the scanned source directory
    as the caller knows it; record paths are relative to it or to the
    directory rusi names in the report, whichever holds the file. The
    result is the records, or not-assessed with the reason: a report that
    is not valid JSON, does not have the rusi shape, names a schema major
    this adapter does not read, or has a section of an unexpected type is
    never read as a smaller report.
    """
    report, parse_error = _parse_report(report)
    if parse_error or not isinstance(report, dict):
        reason = parse_error or (
            f"the report is a {type(report).__name__}, not the rusi report object"
        )
        return not_assessed(reason)
    if not is_rusi_report(report):
        return not_assessed(
            "the report does not have the rusi shape (tool/runtime identity "
            "plus a call_graph or data_flow section); it was not assessed"
        )
    problem = _section_problem(report)
    if problem:
        return not_assessed(f"the rusi report is malformed and was not assessed: {problem}")

    seen_version = as_str(report.get("schema_version")).strip()
    gate = gate_report_version(_gate_version(report), SUPPORTED_MAJOR, KNOWN_MINOR)
    if not gate.accepted:
        return not_assessed(
            f"the report schema version {seen_version or _gate_version(report)!r} is "
            f"not supported; this adapter reads rusi schema major {SUPPORTED_MAJOR} reports"
        )
    report_caveats = list(gate.caveats)

    tool = as_dict(report.get("tool"))
    version = producer_version or as_str(tool.get("version")) or "unknown"
    report_schema_version = seen_version or "unknown"
    producer = EvidenceProducer(
        name=PRODUCER_NAME, version=version, report_schema_version=report_schema_version
    )

    marker_caveats, unresolved_targets = _marker_caveats(report)
    # A marker about time or budget can hide evidence anywhere in the
    # report, so it lands on every record; the unresolved-call-site names
    # stay producer-level and land on the records about those exact targets.
    base_caveats = report_caveats + [c for c in marker_caveats if c.kind in ("timeout", "budget")]

    options = as_dict(report.get("options"))
    backend = as_str(options.get("backend")) or None
    paths = _source_paths(report, source_root)

    bom_index = build_bom_purl_index(bom_components, extra_components=extra_components)

    cg = as_dict(report.get("call_graph"))
    cg_nodes = {
        n["id"]: n
        for n in as_list(cg.get("nodes"))
        if isinstance(n, dict) and as_hashable_str(n.get("id"))
    }
    df = as_dict(report.get("data_flow"))
    df_nodes = {
        n["id"]: n
        for n in as_list(df.get("nodes"))
        if isinstance(n, dict) and as_hashable_str(n.get("id"))
    }

    def node(nodes: Dict[str, dict], node_id: Any) -> dict:
        key = as_hashable_str(node_id)
        return nodes.get(key, {}) if key else {}

    # symbol -> reconciled purl, from call-graph edges to external crates.
    # Matching is by QUALIFIED NAME only (``sqlx::query``), never the bare
    # short name (``query``): two crates can expose a same-named fn, so a
    # short-name key would mis-attribute one crate's call to the other.
    symbol_to_purl: Dict[str, str] = {}
    for e in as_list(cg.get("edges")):
        if not isinstance(e, dict):
            continue
        tgt = node(cg_nodes, e.get("target_id"))
        vpurl = reconcile_purl(tgt.get("purl"), bom_index)
        qualified = as_str(tgt.get("qualified_name"))
        if vpurl and qualified:
            symbol_to_purl.setdefault(qualified, vpurl)

    skipped = SkipTally()
    records = []

    # --- dataflow slice records -------------------------------------------
    for sl in as_list(df.get("slices")):
        if not isinstance(sl, dict):
            skipped.add("data_flow.slices entries are not JSON objects and became no record")
            continue
        flow_purls: Set[str] = set()
        service_pairs: List[Tuple[Optional[str], str]] = []
        path_nodes: List[EvidencePathNode] = []
        locations: List[EvidenceLocation] = []
        where = _Locations(paths)
        rule_name = as_str(sl.get("rule_name"))
        sink_category = as_str(sl.get("sink_category"))
        names: List[Any] = [sl.get("source_name"), sl.get("sink_name")]

        for rp in as_list(sl.get("purls")):
            vp = reconcile_purl(rp, bom_index)
            if vp:
                flow_purls.add(vp)
        for key in ("sourcePurl", "targetPurl"):
            vp = reconcile_purl(sl.get(key), bom_index)
            if vp:
                flow_purls.add(vp)
        for key in ("source_name", "sink_name"):
            nm = as_str(sl.get(key))
            if nm in symbol_to_purl:
                flow_purls.add(symbol_to_purl[nm])

        for nid in as_list(sl.get("node_ids")):
            n = node(df_nodes, nid)
            npurl = reconcile_purl(n.get("purl"), bom_index)
            nm = as_str(n.get("name"))
            names.append(nm)
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
                    method=function or as_str(sl.get("sink_function")) or None,
                    symbol=nm or None,
                )
            )
            location = where.location(pos, function)
            if location:
                locations.append(location)
        if not flow_purls:
            skipped.add(
                "data_flow.slices entries name no crate this BOM carries and became no record"
            )
            continue
        represented = {purl for purl, _ in service_pairs}
        for m in sorted(flow_purls - represented):
            service_pairs.append((m, sink_category))
        attributes = {
            "ruleId": rule_name,
            "servicePurls": _service_purls(service_pairs, flow_purls),
        }
        if backend:
            attributes["backend"] = backend
        caveats = where.caveats(base_caveats)
        unresolved = _unresolved_caveat(unresolved_targets, names)
        if unresolved:
            caveats.append(unresolved)
        records.append(
            build_record(
                source=source,
                producer=producer,
                kind="reached-flow",
                discriminator=neutral_discriminator(sl, paths, [p.to_dict() for p in path_nodes]),
                purls=tuple(sorted(flow_purls)),
                locations=tuple(locations),
                path=tuple(path_nodes),
                attributes=attributes,
                caveats=tuple(caveats),
            )
        )

    # --- call-graph external-crate records ---------------------------------
    for e in as_list(cg.get("edges")):
        if not isinstance(e, dict):
            skipped.add("call_graph.edges entries are not JSON objects and became no record")
            continue
        tgt = node(cg_nodes, e.get("target_id"))
        rpurl = as_str(tgt.get("purl"))
        # A call whose target names no crate (a workspace-local or an
        # unresolved call) or names a standard-library pseudo-crate is not
        # dependency evidence and is not a record the report fails to give.
        if not rpurl or _is_stdlib_purl(rpurl):
            continue
        vpurl = reconcile_purl(rpurl, bom_index)
        if not vpurl:
            skipped.add(
                "call_graph.edges entries call a crate this BOM does not carry and became no record"
            )
            continue
        qualified = as_str(tgt.get("qualified_name"))
        callee = qualified or as_str(tgt.get("name"))
        source_node = node(cg_nodes, e.get("source_id"))
        caller = as_str(source_node.get("qualified_name")) or as_str(source_node.get("name"))
        pos = as_dict(tgt.get("position"))
        where = _Locations(paths)
        file = where.file(as_str(pos.get("filename")) or as_str(source_node.get("file_path")))
        line = _pos_line(pos)
        if line is None:
            line = as_line(e.get("line"))
        caveats = where.caveats(base_caveats)
        unresolved = _unresolved_caveat(unresolved_targets, [callee, tgt.get("name")])
        if unresolved:
            caveats.append(unresolved)
        location = EvidenceLocation(file=file, line=line, method=callee or None) if file else None
        path = (
            EvidencePathNode(method=caller or None, symbol=caller or None),
            EvidencePathNode(file=file, line=line, method=callee or None, symbol=callee or None),
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
                attributes={"servicePurls": []},
                caveats=tuple(caveats),
            )
        )

    # --- api endpoint records ----------------------------------------------
    for ep in as_list(report.get("api_endpoints")):
        if not isinstance(ep, dict):
            skipped.add("api_endpoints entries are not JSON objects and became no record")
            continue
        fw_vpurl = reconcile_purl(ep.get("purl"), bom_index)
        handler_vpurl = bom_index.get(_normalize_crate_name(as_str(ep.get("package_path"))))
        if not fw_vpurl and not handler_vpurl:
            skipped.add("api_endpoints entries resolve to no BOM crate purl and became no record")
            continue
        path_ = as_str(ep.get("path"))
        handler = as_str(ep.get("handler"))
        where = _Locations(paths)
        location = where.location(ep.get("position"), handler or path_)
        caveats = tuple(where.caveats(base_caveats))
        ep_locations = tuple(loc for loc in (location,) if loc)
        # The entry point is the framework crate's: it is the service the
        # endpoint exposes. The crate that holds the handler is reached
        # through the endpoint but is not a service, so it is named in the
        # entry point's attributes and gets a reached-flow record of its own.
        attributes: Dict[str, Any] = {"servicePurls": [fw_vpurl] if fw_vpurl else []}
        for key, field in (("method", "method"), ("route", "path"), ("handler", "handler")):
            value = as_str(ep.get(field))
            if value:
                attributes[key] = value
        if handler_vpurl and handler_vpurl != fw_vpurl:
            attributes["handlerPurl"] = handler_vpurl
        records.append(
            build_record(
                source=source,
                producer=producer,
                kind="entry-point",
                discriminator=neutral_discriminator(ep, paths),
                purls=(fw_vpurl,) if fw_vpurl else (),
                locations=ep_locations,
                attributes=attributes,
                caveats=caveats,
            )
        )
        if handler_vpurl and handler_vpurl != fw_vpurl:
            records.append(
                build_record(
                    source=source,
                    producer=producer,
                    kind="reached-flow",
                    discriminator=neutral_discriminator(ep, paths, "handler"),
                    purls=(handler_vpurl,),
                    locations=ep_locations,
                    attributes={"servicePurls": [], "handlerOf": path_ or handler},
                    caveats=caveats,
                )
            )

    # --- usage records -------------------------------------------------------
    # A usage is a call or reference rusi saw in the workspace. It is kept as
    # a callsite record, a kind the reached sets never count: the crate the
    # usage sits in is the caller, named in the attributes, and the subject
    # is the called crate only when the call graph names that exact
    # qualified symbol.
    for usage in as_list(report.get("usages")):
        if not isinstance(usage, dict):
            skipped.add("usages entries are not JSON objects and became no record")
            continue
        name = as_str(usage.get("name"))
        where = _Locations(paths)
        location = where.location(usage.get("position"), name)
        callee_purl = symbol_to_purl.get(name)
        attributes: Dict[str, Any] = {}
        for key, field in (
            ("usageKind", "kind"),
            ("name", "name"),
            ("packagePath", "package_path"),
        ):
            value = as_str(usage.get(field))
            if value:
                attributes[key] = value
        caller_purl = reconcile_purl(usage.get("purl"), bom_index)
        if caller_purl:
            attributes["callerPurl"] = caller_purl
        caveats = where.caveats(base_caveats)
        unresolved = _unresolved_caveat(unresolved_targets, [name])
        if unresolved:
            caveats.append(unresolved)
        records.append(
            build_record(
                source=source,
                producer=producer,
                kind="callsite",
                discriminator=neutral_discriminator(usage, paths),
                purls=(callee_purl,) if callee_purl else (),
                locations=tuple(loc for loc in (location,) if loc),
                attributes=attributes or None,
                caveats=tuple(caveats),
            )
        )

    outside = paths.producer_caveat()
    caveats = _dedupe_caveats(
        marker_caveats + report_caveats + skipped.caveats() + ([outside] if outside else [])
    )
    return AdapterResult(status=STATUS_COMPLETED, records=records, caveats=caveats)


__all__ = [
    "PRODUCER_NAME",
    "SUPPORTED_MAJOR",
    "build_bom_purl_index",
    "extract",
    "is_rusi_report",
    "reconcile_purl",
]
