"""rusi (Rust Source Inspector) report -> evidence records.

This module is the only code that knows the rusi report format: a
snake_case JSON object whose ``schema_version`` is a URL ending in
``report-<major>.<minor>``, carrying ``tool``/``runtime``, a ``call_graph``
and a ``data_flow``.

Three kinds of evidence become records:

1. Dataflow slices (``data_flow.slices[]``) become ``reached-flow`` records
   whose ``path`` is the slice's witness nodes in rusi's order.
2. Call-graph edges whose target names an external crate with a purl become
   ``reached-flow`` records with the caller-to-callee two-node path. The
   target purl is what the record is about: rusi stamps the external
   function with the crate it belongs to, so an unresolved workspace-local
   call (no purl) is not dependency evidence.
3. ``api_endpoints[]`` become ``entry-point`` records.

rusi emits versioned purls only for workspace packages; external crates get
unversioned ``pkg:cargo/<name>``. The Cargo BOM is keyed at versioned
purls, so the reconciliation matches by crate NAME (mirroring rusi's own
``-``/``_`` normalization and percent-encoding) onto the BOM's versioned
purls. Rust standard-library pseudo-crates (``fs``, ``std``, ``core`` ...)
never correspond to real dependencies and are dropped. A slice or edge
whose purls name no BOM component is left out: the producer named a package
this BOM does not carry, and an unmatched purl never incremented the
reached set. An object the report itself left shapeless (not a JSON object
where one belongs) is a ``record-skipped`` caveat, never a silent drop.

rusi's ``diagnostics`` (top level, and per section) travel with the
records: a diagnostic about the analysis running out of time or cutting
call candidates is a ``timeout``/``budget`` caveat on the producer result
and on every record, since either can hide evidence anywhere; a resolution
diagnostic (an unresolved or external call target) is an
``unresolved-call-sites`` caveat on the producer result and on the
call-graph record about the target it names.

The converter this module replaces never read rusi's ``usages[]`` and never
emitted flows for it, so no usage records are built here either: emitting
them would count purls the engine never counted before.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import unquote

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
    if purl.startswith("pkg:cargo/"):
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
        tail = tail[len("report-"):]
    return tail


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


def _marker_caveats(report: dict) -> Tuple[List[EvidenceCaveat], List[str]]:
    """The caveats rusi's diagnostics carry, in the order the report lists
    them, plus the call targets the resolution diagnostics name.

    A diagnostic whose kind or message names a timeout or a cut/budget limit
    hides evidence anywhere in the report, so it becomes a producer-level
    ``timeout``/``budget`` caveat. A resolution diagnostic names one
    unresolved call target and is collected separately, with the target it
    names, so the caveat can land on the record about that target.
    """
    caveats: List[EvidenceCaveat] = []
    targets: List[str] = []
    sections = [report.get("diagnostics")]
    for key in ("call_graph", "data_flow"):
        section = report.get(key)
        if isinstance(section, dict):
            sections.append(section.get("diagnostics"))
    for group in sections:
        for diag in group or []:
            if not isinstance(diag, dict):
                continue
            kind = str(diag.get("kind") or "")
            message = str(diag.get("message") or "")
            haystack = f"{kind} {message}".lower()
            if "timeout" in haystack:
                caveats.append(EvidenceCaveat(kind="timeout", detail=f"rusi diagnostic: {message}" if message else "rusi reported a timeout"))
            elif any(word in haystack for word in ("truncat", "budget", "capped", "exceeded")):
                caveats.append(EvidenceCaveat(kind="budget", detail=f"rusi diagnostic: {message}" if message else "rusi reported a budget limit"))
            elif kind == "resolution" or "call target" in haystack:
                target = message.rsplit("call target ", 1)[-1].strip()
                if target and target != message:
                    targets.append(target)
    if targets:
        caveats.append(
            EvidenceCaveat(
                kind="unresolved-call-sites",
                detail="rusi could not resolve calls to " + ", ".join(sorted(set(targets))),
            )
        )
    return caveats, targets


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


def extract(
    report,
    *,
    source: str,
    producer_version: str = "",
    bom_components: Optional[Iterable[dict]] = None,
    extra_components: Optional[Iterable[dict]] = None,
) -> AdapterResult:
    """One rusi report as evidence records.

    ``report`` is the parsed rusi report or its JSON text. ``source`` is the
    scan-directory-relative file the report was read from.
    ``producer_version`` is the rusi tool version when the caller knows it;
    the report's own ``tool.version`` is used otherwise. ``bom_components``
    and ``extra_components`` (the metadata.component root) feed the purl
    reconciliation index. The result is the records, or not-assessed with
    the reason: a report that is not valid JSON, does not have the rusi
    shape, or names a schema major this adapter does not read is never read
    as a smaller report.
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

    seen_version = str(report.get("schema_version") or "").strip()
    gate = gate_report_version(_gate_version(report), SUPPORTED_MAJOR, KNOWN_MINOR)
    if not gate.accepted:
        return not_assessed(
            f"the report schema version {seen_version or _gate_version(report)} is "
            f"not supported; this adapter reads rusi schema major {SUPPORTED_MAJOR} reports"
        )
    report_caveats = list(gate.caveats)

    tool = report.get("tool") if isinstance(report.get("tool"), dict) else {}
    version = producer_version or str(tool.get("version") or "") or "unknown"
    report_schema_version = seen_version or "unknown"
    producer = EvidenceProducer(
        name=PRODUCER_NAME, version=version, report_schema_version=report_schema_version
    )

    marker_caveats, unresolved_targets = _marker_caveats(report)
    # A marker about time or budget can hide evidence anywhere in the
    # report, so it lands on every record; the unresolved-call-site names
    # stay producer-level and land on the records about those targets.
    base_caveats = report_caveats + [
        c for c in marker_caveats if c.kind in ("timeout", "budget")
    ]
    unresolved_caveat = next(
        (c for c in marker_caveats if c.kind == "unresolved-call-sites"), None
    )

    options = report.get("options") if isinstance(report.get("options"), dict) else {}
    backend = str(options.get("backend") or "") or None
    root = str(options.get("directory") or "")

    bom_index = build_bom_purl_index(bom_components, extra_components=extra_components)

    cg = report.get("call_graph") or {}
    cg_nodes = {n.get("id"): n for n in cg.get("nodes", []) if isinstance(n, dict)}
    df = report.get("data_flow") or {}
    df_nodes = {n.get("id"): n for n in df.get("nodes", []) if isinstance(n, dict)}

    # symbol -> reconciled purl, from call-graph edges to external crates.
    # Matching is by QUALIFIED NAME only (``sqlx::query``), never the bare
    # short name (``query``): two crates can expose a same-named fn, so a
    # short-name key would mis-attribute one crate's call to the other.
    symbol_to_purl: Dict[str, str] = {}
    for e in cg.get("edges", []) or []:
        if not isinstance(e, dict):
            continue
        tgt = cg_nodes.get(e.get("target_id")) or {}
        if not (tgt.get("external") or tgt.get("purl")):
            continue
        rpurl = tgt.get("purl") or ""
        if not rpurl:
            continue
        vpurl = reconcile_purl(rpurl, bom_index)
        if not vpurl:
            continue
        qualified = tgt.get("qualified_name") or ""
        if qualified:
            symbol_to_purl.setdefault(qualified, vpurl)

    skipped: List[EvidenceCaveat] = []
    records = []

    # --- dataflow slice records -------------------------------------------
    for sl in df.get("slices", []) or []:
        if not isinstance(sl, dict):
            skipped.append(
                EvidenceCaveat(
                    kind="record-skipped",
                    detail="data_flow.slices carries a non-object entry; it was not turned into a record",
                )
            )
            continue
        flow_purls: Set[str] = set()
        service_pairs: List[Tuple[Optional[str], str]] = []
        path_nodes: List[EvidencePathNode] = []
        rule_name = sl.get("rule_name") or ""
        sink_category = sl.get("sink_category") or ""

        for rp in sl.get("purls", []) or []:
            vp = reconcile_purl(rp, bom_index)
            if vp:
                flow_purls.add(vp)
        for key in ("sourcePurl", "targetPurl"):
            vp = reconcile_purl(sl.get(key, ""), bom_index)
            if vp:
                flow_purls.add(vp)
        for key in ("source_name", "sink_name"):
            nm = sl.get(key, "")
            if nm in symbol_to_purl:
                flow_purls.add(symbol_to_purl[nm])

        node_ids_list = sl.get("node_ids", []) or []
        for nid in node_ids_list:
            n = df_nodes.get(nid) or {}
            npurl = reconcile_purl(n.get("purl", ""), bom_index)
            nm = n.get("name") or ""
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
                    method=n.get("function") or sl.get("sink_function") or None,
                    symbol=nm or None,
                )
            )
        if not flow_purls:
            continue
        represented = {purl for purl, _ in service_pairs}
        missing = flow_purls - represented
        if missing:
            for m in sorted(missing):
                service_pairs.append((m, sink_category))
        attributes = {
            "ruleId": rule_name,
            "servicePurls": _service_purls(service_pairs, flow_purls),
        }
        if backend:
            attributes["backend"] = backend
        caveats = list(base_caveats)
        if unresolved_caveat and rule_name and rule_name in unresolved_caveat.detail:
            caveats.append(unresolved_caveat)
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
                attributes=attributes,
                caveats=tuple(caveats),
            )
        )

    # --- call-graph external-crate records ---------------------------------
    for e in cg.get("edges", []) or []:
        if not isinstance(e, dict):
            skipped.append(
                EvidenceCaveat(
                    kind="record-skipped",
                    detail="call_graph.edges carries a non-object entry; it was not turned into a record",
                )
            )
            continue
        tgt = cg_nodes.get(e.get("target_id")) or {}
        if not (tgt.get("external") or tgt.get("purl")):
            continue
        rpurl = tgt.get("purl") or ""
        if not rpurl:
            continue
        vpurl = reconcile_purl(rpurl, bom_index)
        if not vpurl:
            continue
        qualified = tgt.get("qualified_name") or ""
        callee = qualified or tgt.get("name") or ""
        source_node = cg_nodes.get(e.get("source_id")) or {}
        caller = source_node.get("qualified_name") or source_node.get("name") or ""
        pos = tgt.get("position") or {}
        file = _relative((pos or {}).get("filename") or source_node.get("file_path") or "", root)
        line = _pos_line(pos)
        if line is None and isinstance(e.get("line"), int):
            line = e["line"] or None
        attributes = {"servicePurls": []}
        caveats = list(base_caveats)
        if unresolved_caveat and callee and callee in unresolved_caveat.detail:
            caveats.append(unresolved_caveat)
        location = (
            EvidenceLocation(file=file, line=line, method=callee or None) if file else None
        )
        records.append(
            build_record(
                source=source,
                producer=producer,
                kind="reached-flow",
                discriminator=str(e.get("id") or content_discriminator(e)),
                purls=(vpurl,),
                locations=tuple(loc for loc in (location,) if loc),
                path=(
                    EvidencePathNode(method=caller or None, symbol=caller or None),
                    EvidencePathNode(
                        file=file,
                        line=line,
                        method=callee or None,
                        symbol=callee or None,
                    ),
                ),
                attributes=attributes,
                caveats=tuple(caveats),
            )
        )

    # --- api endpoint records ----------------------------------------------
    for ep in report.get("api_endpoints", []) or []:
        if not isinstance(ep, dict):
            skipped.append(
                EvidenceCaveat(
                    kind="record-skipped",
                    detail="api_endpoints carries a non-object entry; it was not turned into a record",
                )
            )
            continue
        fw_vpurl = reconcile_purl(ep.get("purl", ""), bom_index)
        pkg_path = ep.get("package_path") or ""
        handler_vpurl = bom_index.get(_normalize_crate_name(pkg_path))
        ep_purls = {p for p in (fw_vpurl, handler_vpurl) if p}
        if not ep_purls:
            continue
        method = ep.get("method") or ""
        path_ = ep.get("path") or ""
        handler = ep.get("handler") or ""
        pos = ep.get("position") or {}
        location = _location(pos, handler or path_, root)
        attributes = {"servicePurls": [fw_vpurl] if fw_vpurl else []}
        records.append(
            build_record(
                source=source,
                producer=producer,
                kind="entry-point",
                discriminator=str(ep.get("id") or content_discriminator(ep)),
                purls=tuple(sorted(ep_purls)),
                locations=tuple(loc for loc in (location,) if loc),
                attributes=attributes,
                caveats=tuple(base_caveats),
            )
        )

    caveats = _dedupe_caveats(marker_caveats + report_caveats + skipped)
    return AdapterResult(status=STATUS_COMPLETED, records=records, caveats=caveats)


__all__ = [
    "PRODUCER_NAME",
    "SUPPORTED_MAJOR",
    "build_bom_purl_index",
    "extract",
    "is_rusi_report",
    "reconcile_purl",
]
