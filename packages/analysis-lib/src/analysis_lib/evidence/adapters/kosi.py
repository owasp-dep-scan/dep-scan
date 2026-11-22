"""kosi (Kotlin Source Inspector) report -> evidence records.

This module is the only code that knows the kosi report format: a JSON
object whose ``schemaVersion`` is ``kosi/<major>[.<minor>]``, carrying a
``tool`` block and lowerCamelCase sections.

Four kinds of evidence become records:

1. Dataflow slices (``dataFlow.slices[]``, published by the resolved tier)
   become ``reached-flow`` records whose ``path`` is the slice's
   ``frames[]``, source first, sink last.
2. Library usages (``usages[]``) become ``usage`` records. A call such as
   ``Request.Builder.url`` is joined to the file's imports to get a fully
   qualified name, then attributed to a BOM dependency.
3. Call-graph edges that end in an external, non-standard-library function
   become ``reached-flow`` records with the caller-to-callee two-node path.
   The resolved tier at the ``static`` call-graph mode keeps only workspace
   functions as nodes, so this is empty there and appears when a mode or
   dependency view brings dependency functions into the graph.
4. API endpoints (``apiEndpoints[]``) become ``entry-point`` records that
   name no package: the endpoint's purl is the workspace module that
   declares it, kept as the ``modulePurl`` attribute, so a route kosi found
   is kept as attack surface without counting as a reached package.

Attribution of a name to a BOM dependency, in order: the ``purl`` kosi
itself resolved (resolved tier, matched to the jar whose package prefix the
import carries); otherwise a package-prefix match of the fully qualified
name against the Maven group and artifact of each BOM component (see
:func:`attribute_name`). Star imports attribute nothing, and an import that
ties several artifacts attributes none. The prefix match is a heuristic and
is limited to what the coordinates reveal: a library whose Java package
shares nothing with its Maven group and artifact is not attributed, which
leaves it "not observed", never reached.

Every usage that attributes to a BOM package is its own record, so each
call site keeps its location. A call into the workspace or the standard
library is not dependency evidence and makes no record. Every other report
object that makes no record (a slice, usage or edge that names only
packages the BOM does not carry, a slice without frames, an entry that is
not a JSON object) is counted in one ``record-skipped`` caveat per reason.

File paths are relative to the working directory kosi names
(``runtime.workingDirectory``) or the caller's source root; a file in a
Maven or Gradle cache is spelled by its cache path, and any other absolute
path is left out with a ``location-outside-root`` caveat. Record ids leave
out kosi's own object ids and spell the roots the same way wherever the
report was produced.

Kosi's own markers travel with the records. A non-empty
``stats.truncations`` object and the stats cap counters (``fixpointCapHits``,
``sccIterationCapHits``) mean the producer cut work short, so they become
``budget`` caveats on the producer result and on every record; a diagnostic
whose code or message names a timeout does the same as a ``timeout``
caveat. The remaining diagnostics say where the producer could not look (an
unnameable invoke stops taint, a tier that never ran its call graph), so
they become ``coverage-gap`` caveats on the producer result and on every
record: an absent flow through them means unexamined, not clean. A
call-graph edge that collapsed intermediate hops carries the collapse
information the producer stated as its ``collapsed`` attribute and a
``collapsed-edges`` caveat.
"""

from __future__ import annotations

import json
import re
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
#: knows. kosi's schema version is ``kosi/<major>[.<minor>]``.
SUPPORTED_MAJOR = 1
KNOWN_MINOR = 0

#: The ``schemaVersion`` prefix that says this is a kosi report.
KOSI_SCHEMA_PREFIX = "kosi/"

PRODUCER_NAME = "kosi"

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

# Minimum length of a Maven group's last segment before it may stand alone
# as a package root (``okhttp3`` for ``com.squareup.okhttp3``). Shorter
# segments such as ``core`` or ``api`` are shared by unrelated libraries.
_MIN_GROUP_TAIL_LEN = 5

_MAVEN_RE = re.compile(r"^pkg:maven/([^/@?#]+)/([^/@?#]+)")


def is_kosi_report(report) -> bool:
    """True when ``report`` looks like a kosi report, by shape.

    A kosi report is a JSON object whose ``schemaVersion`` is in the
    ``kosi/`` family and which carries the ``tool`` block; a report that
    names no version is judged by the ``tool`` block and an analysis
    section instead, and lands in the schema-unknown path of the version
    gate. Shape, not file name, tells it apart from an atom-produced
    ``*-semantics.slices.json`` at the same path.
    """
    if not isinstance(report, dict):
        return False
    schema = str(report.get("schemaVersion") or "")
    tool = isinstance(report.get("tool"), dict)
    if schema:
        return schema.startswith(KOSI_SCHEMA_PREFIX) and tool
    return tool and any(isinstance(report.get(k), dict) for k in ("dataFlow", "callGraph"))


# ---------------------------------------------------------------------------
# Purl parsing + reconciliation
# ---------------------------------------------------------------------------


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
    group-level ones. A name is attributed only when exactly one BOM
    artifact owns that best prefix: several artifacts of one group tie on a
    group-level prefix, and the name alone cannot tell them apart, so none
    is returned (a package must never be marked reached on a guess). Names
    under a language runtime root (``java``, ``kotlin``, ``android``) are
    never attributed.
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


def _qualify_usage(usage: dict, file_imports: List[dict]) -> List[str]:
    """Fully qualified candidates for a usage name, from the file's imports.

    ``Request.Builder.url`` with ``import okhttp3.Request`` becomes
    ``okhttp3.Request.Builder.url``. The first segment is matched against an
    import's alias or last segment. A wildcard import contributes nothing:
    the name alone does not say which wildcard (or the file's own package)
    owns it, so a local function would be attributed to the wildcard's
    library.
    """
    name = as_str(usage.get("name"))
    if not name:
        return []
    head, _, rest = name.partition(".")
    out: List[str] = []
    for imp in file_imports:
        fqn = as_str(imp.get("name"))
        if not fqn:
            continue
        if imp.get("star"):
            continue
        bound = as_str(imp.get("alias")) or fqn.rsplit(".", 1)[-1]
        if bound == head:
            out.append(fqn + ("." + rest if rest else ""))
    return out


# ---------------------------------------------------------------------------
# Version gate
# ---------------------------------------------------------------------------


def _gate_version(report: dict) -> str:
    """The schema version text the gate can read: the part of
    ``schemaVersion`` after the ``kosi/`` prefix."""
    text = str(report.get("schemaVersion") or "").strip()
    if text.startswith(KOSI_SCHEMA_PREFIX):
        return text[len(KOSI_SCHEMA_PREFIX) :]
    return text


# ---------------------------------------------------------------------------
# Record construction
# ---------------------------------------------------------------------------


def _reach_fields(entry: Optional[dict]) -> dict:
    """The root-reachability attributes a record carries, as kosi reported
    them (``reached`` becomes ``reachableFromRoots``, kosi's roots are scope
    names such as ``main``, not node ids)."""
    if not isinstance(entry, dict):
        return {}
    out: dict = {"reachableFromRoots": bool(entry.get("reached"))}
    distance = entry.get("distance")
    if isinstance(distance, int) and distance >= 0:
        out["minDepth"] = distance
    out["rootScopes"] = [r for r in entry.get("roots", []) or [] if isinstance(r, str)]
    return out


def _function_reach(cg: dict) -> Dict[str, dict]:
    """``canonicalName -> reachability attributes`` for every call-graph
    node."""
    by_id = {
        e["nodeId"]: e
        for e in as_list(cg.get("reachability"))
        if isinstance(e, dict) and as_hashable_str(e.get("nodeId"))
    }
    out: Dict[str, dict] = {}
    for node in as_list(cg.get("nodes")):
        if not isinstance(node, dict):
            continue
        node_id = as_hashable_str(node.get("id"))
        entry = by_id.get(node_id) if node_id else None
        name = as_hashable_str(node.get("canonicalName"))
        if entry is not None and name:
            out[name] = _reach_fields(entry)
    return out


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
        if not KOSI_CATEGORY_TO_SERVICE_TAG.get(category):
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


def _marker_caveats(report: dict) -> List[EvidenceCaveat]:
    """The caveats kosi's stats and diagnostics carry.

    Budget markers (the stats ``truncations`` object, the cap counters) and
    a diagnostic naming a timeout hide evidence anywhere in the report, so
    they become producer-level ``budget``/``timeout`` caveats. The other
    diagnostics say where the producer could not look, so they become
    ``coverage-gap`` caveats rather than clean silence.
    """
    caveats: List[EvidenceCaveat] = []
    stats = as_dict(report.get("stats"))
    truncations = stats.get("truncations")
    if isinstance(truncations, dict) and truncations:
        caveats.append(
            EvidenceCaveat(
                kind="budget",
                detail="kosi truncated work: " + json.dumps(truncations, sort_keys=True),
            )
        )
    for counter in ("fixpointCapHits", "sccIterationCapHits"):
        value = stats.get(counter)
        if isinstance(value, int) and not isinstance(value, bool) and value > 0:
            caveats.append(
                EvidenceCaveat(kind="budget", detail=f"kosi hit its {counter} cap {value} time(s)")
            )
    for diag in as_list(report.get("diagnostics")):
        if not isinstance(diag, dict):
            continue
        code = as_str(diag.get("code"))
        message = as_str(diag.get("message"))
        haystack = f"{code} {message}".lower()
        detail = f"kosi diagnostic {code}: {message}" if code else message
        if "timeout" in haystack:
            caveats.append(EvidenceCaveat(kind="timeout", detail=detail))
        elif any(word in haystack for word in ("truncat", "budget", "cap ")):
            caveats.append(EvidenceCaveat(kind="budget", detail=detail))
        elif code or message:
            caveats.append(EvidenceCaveat(kind="coverage-gap", detail=detail))
    return caveats


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


#: The report sections the adapter reads, with the JSON type each must have
#: when present. A section of another type is a malformed report.
_SECTION_TYPES = (
    (("runtime",), dict),
    (("tool",), dict),
    (("stats",), dict),
    (("diagnostics",), list),
    (("imports",), list),
    (("usages",), list),
    (("apiEndpoints",), list),
    (("dataFlow",), dict),
    (("dataFlow", "slices"), list),
    (("callGraph",), dict),
    (("callGraph", "nodes"), list),
    (("callGraph", "edges"), list),
    (("callGraph", "reachability"), list),
)


def _section_problem(report: dict) -> Optional[str]:
    """The first consumed section of the wrong JSON type, named, or ``None``.

    A ``null`` section reads as absent. Any other value of the wrong type
    means the report is not the shape kosi writes.
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
    """One kosi report as evidence records.

    ``report`` is the parsed kosi report or its JSON text. ``source`` is the
    scan-directory-relative file the report was read from.
    ``producer_version`` is the kosi tool version when the caller knows it;
    the report's own ``tool.version`` is used otherwise. ``bom_components``
    and ``extra_components`` (the metadata.component root) feed the purl
    reconciliation index. ``source_root`` is the scanned source directory
    as the caller knows it; record paths are relative to it or to the
    working directory kosi names in the report, whichever holds the file.
    The result is the records, or not-assessed with the reason: a report
    that is not valid JSON, does not have the kosi shape, names a schema
    major this adapter does not read, or has a section of an unexpected
    type is never read as a smaller report.
    """
    report, parse_error = _parse_report(report)
    if parse_error or not isinstance(report, dict):
        reason = parse_error or (
            f"the report is a {type(report).__name__}, not the kosi report object"
        )
        return not_assessed(reason)
    if not is_kosi_report(report):
        return not_assessed(
            "the report does not have the kosi shape (a kosi/ schemaVersion "
            "with a tool block); it was not assessed"
        )
    problem = _section_problem(report)
    if problem:
        return not_assessed(f"the kosi report is malformed and was not assessed: {problem}")

    seen_version = as_str(report.get("schemaVersion")).strip()
    gate = gate_report_version(_gate_version(report), SUPPORTED_MAJOR, KNOWN_MINOR)
    if not gate.accepted:
        return not_assessed(
            f"the report schema version {seen_version or _gate_version(report)!r} is "
            f"not supported; this adapter reads kosi schema major {SUPPORTED_MAJOR} reports"
        )
    report_caveats = list(gate.caveats)

    tool = as_dict(report.get("tool"))
    version = producer_version or as_str(tool.get("version")) or "unknown"
    report_schema_version = seen_version or "unknown"
    producer = EvidenceProducer(
        name=PRODUCER_NAME, version=version, report_schema_version=report_schema_version
    )

    marker_caveats = _marker_caveats(report)
    # Every marker kosi states (a budget it hit, a place it could not look)
    # discounts the report as a whole, so each lands on every record.
    base_caveats = report_caveats + marker_caveats

    bom_index = build_bom_purl_index(bom_components, extra_components=extra_components)
    runtime = as_dict(report.get("runtime"))
    paths = SourcePaths([runtime.get("workingDirectory"), source_root])

    df = as_dict(report.get("dataFlow"))
    cg = as_dict(report.get("callGraph"))
    func_reach = _function_reach(cg)

    skipped = SkipTally()
    records = []

    # --- dataflow slice records -------------------------------------------
    for sl in as_list(df.get("slices")):
        if not isinstance(sl, dict):
            skipped.add("dataFlow.slices entries are not JSON objects and became no record")
            continue
        purls: Set[str] = set()
        for key in ("sourcePurl", "targetPurl"):
            vp = reconcile_purl(sl.get(key), bom_index)
            if vp:
                purls.add(vp)
        for p in as_list(sl.get("purls")):
            vp = reconcile_purl(p, bom_index)
            if vp:
                purls.add(vp)
        source_purls = attribute_name(as_str(sl.get("sourceName")), bom_index)
        sink_purls = attribute_name(as_str(sl.get("sinkName")), bom_index)
        purls |= source_purls | sink_purls
        if not purls:
            skipped.add(
                "dataFlow.slices entries name no package this BOM carries and became no record"
            )
            continue
        frames = [f for f in as_list(sl.get("frames")) if isinstance(f, dict)]
        if not frames:
            skipped.add("dataFlow.slices entries carry no usable frames and became no record")
            continue
        sink_category = as_str(sl.get("sinkCategory"))
        purl_by_function: Dict[str, str] = {}
        if source_purls:
            purl_by_function[as_str(sl.get("sourceFunction"))] = sorted(source_purls)[0]

        service_pairs: List[Tuple[Optional[str], str]] = []
        path_nodes: List[EvidencePathNode] = []
        locations: List[EvidenceLocation] = []
        where = _Locations(paths)
        last = len(frames) - 1
        for idx, fr in enumerate(frames):
            function = as_str(fr.get("function"))
            line = as_line(fr.get("line"))
            file = where.file(fr.get("file"))
            is_sink = idx == last
            purl = None
            if is_sink and sink_purls:
                purl = sorted(sink_purls)[0]
            elif function in purl_by_function:
                purl = purl_by_function[function]
            if purl:
                service_pairs.append((purl, sink_category if is_sink else ""))
            path_nodes.append(
                EvidencePathNode(
                    file=file, line=line, method=function or None, symbol=function or None
                )
            )
            if file:
                locations.append(EvidenceLocation(file=file, line=line, method=function or None))
        represented = {purl for purl, _ in service_pairs}
        for m in sorted(purls - represented):
            service_pairs.append((m, sink_category))
        attributes: dict = {}
        reach = func_reach.get(as_str(frames[0].get("function")))
        if reach:
            attributes.update(reach)
        tier = sl.get("tier")
        if tier is not None:
            attributes["tier"] = tier
        if sl.get("collapsed") is not None:
            attributes["collapsed"] = sl.get("collapsed")
        attributes["servicePurls"] = _service_purls(service_pairs, purls)
        confidence = sl.get("confidence")
        records.append(
            build_record(
                source=source,
                producer=producer,
                kind="reached-flow",
                discriminator=neutral_discriminator(sl, paths, [p.to_dict() for p in path_nodes]),
                purls=tuple(sorted(purls)),
                locations=tuple(locations),
                path=tuple(path_nodes),
                confidence=confidence if isinstance(confidence, str) and confidence else None,
                attributes=attributes,
                caveats=tuple(where.caveats(base_caveats)),
            )
        )

    # --- usage records -------------------------------------------------------
    # Every usage kosi lists that attributes to a BOM package is its own
    # record, so each call site keeps its location.
    imports_by_file: Dict[str, List[dict]] = {}
    for imp in as_list(report.get("imports")):
        if isinstance(imp, dict):
            imports_by_file.setdefault(as_str(imp.get("filePath")), []).append(imp)
    for usage in as_list(report.get("usages")):
        if not isinstance(usage, dict):
            skipped.add("usages entries are not JSON objects and became no record")
            continue
        file_path = as_str(usage.get("filePath"))
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
            fqn = as_str(imp.get("name"))
            if qualified and fqn and qualified.startswith(fqn):
                vp = reconcile_purl(imp.get("purl"), bom_index)
                if vp:
                    purls = {vp}
                break
        if not purls:
            skipped.add(
                "usages entries name no import that attributes to a BOM package "
                "and became no record"
            )
            continue
        where = _Locations(paths)
        file = where.file(file_path)
        line = as_line(as_dict(usage.get("position")).get("line"))
        location = (
            EvidenceLocation(file=file, line=line, method=qualified or None) if file else None
        )
        for purl in sorted(purls):
            records.append(
                build_record(
                    source=source,
                    producer=producer,
                    kind="usage",
                    discriminator=neutral_discriminator(usage, paths),
                    purls=(purl,),
                    locations=tuple(loc for loc in (location,) if loc),
                    attributes={"servicePurls": []},
                    caveats=tuple(where.caveats(base_caveats)),
                )
            )

    # --- call-graph edge records ---------------------------------------------
    nodes_by_id = {
        n["id"]: n
        for n in as_list(cg.get("nodes"))
        if isinstance(n, dict) and as_hashable_str(n.get("id"))
    }
    by_reach = {
        e["nodeId"]: e
        for e in as_list(cg.get("reachability"))
        if isinstance(e, dict) and as_hashable_str(e.get("nodeId"))
    }

    def node(node_id: Any) -> dict:
        key = as_hashable_str(node_id)
        return nodes_by_id.get(key, {}) if key else {}

    for edge in as_list(cg.get("edges")):
        if not isinstance(edge, dict):
            skipped.add("callGraph.edges entries are not JSON objects and became no record")
            continue
        target = node(edge.get("targetId"))
        source_node = node(edge.get("sourceId"))
        # A call into the workspace or the standard library is not dependency
        # evidence and is not a record the report fails to give.
        if not target.get("external") or target.get("stdlib"):
            continue
        purls = attribute_name(as_str(target.get("canonicalName")), bom_index)
        vp = reconcile_purl(target.get("purl"), bom_index)
        if vp:
            purls = {vp}
        if not purls:
            skipped.add(
                "callGraph.edges entries call a package this BOM does not carry "
                "and became no record"
            )
            continue
        callee = as_str(target.get("canonicalName"))
        caller = as_str(source_node.get("canonicalName"))
        where = _Locations(paths)
        file = where.file(source_node.get("filePath"))
        line = as_line(edge.get("line"))
        source_id = as_hashable_str(source_node.get("id"))
        attributes = _reach_fields(by_reach.get(source_id) if source_id else None)
        collapsed = {
            key: edge[key]
            for key in ("collapsedHops", "collapsedPackages")
            if edge.get(key) is not None
        }
        caveats = where.caveats(base_caveats)
        if collapsed:
            attributes["collapsed"] = collapsed
            caveats.append(
                EvidenceCaveat(
                    kind="collapsed-edges",
                    detail=(
                        "kosi collapsed "
                        f"{collapsed.get('collapsedHops', 'unknown')} hop(s) on the call into {callee}"
                    ),
                )
            )
        attributes["servicePurls"] = []
        location = EvidenceLocation(file=file, line=line, method=callee or None) if file else None
        path = (
            EvidencePathNode(file=file, method=caller or None, symbol=caller or None),
            EvidencePathNode(file=file, line=line, method=callee or None, symbol=callee or None),
        )
        records.append(
            build_record(
                source=source,
                producer=producer,
                kind="reached-flow",
                discriminator=neutral_discriminator(edge, paths, [p.to_dict() for p in path]),
                purls=tuple(sorted(purls)),
                locations=tuple(loc for loc in (location,) if loc),
                path=path,
                attributes=attributes,
                caveats=tuple(caveats),
            )
        )

    # --- api endpoint records ------------------------------------------------
    # An endpoint is attack surface kosi found in the workspace. Its record
    # names no package: the endpoint's purl is the workspace module that
    # declares it, kept as the modulePurl attribute, so finding a route does
    # not by itself put a package in the reached sets.
    for ep in as_list(report.get("apiEndpoints")):
        if not isinstance(ep, dict):
            skipped.add("apiEndpoints entries are not JSON objects and became no record")
            continue
        attributes = {}
        for key in (
            "framework",
            "httpMethods",
            "pathTemplate",
            "handlerSymbol",
            "handlerCanonicalName",
            "authentication",
            "exported",
            "foundBy",
        ):
            value = ep.get(key)
            if value is not None and value != "" and value != []:
                attributes[key] = value
        module_purl = reconcile_purl(ep.get("purl"), bom_index)
        if module_purl:
            attributes["modulePurl"] = module_purl
        position = as_dict(ep.get("position"))
        where = _Locations(paths)
        file = where.file(position.get("filename"))
        method = as_str(ep.get("handlerCanonicalName")) or as_str(ep.get("pathTemplate"))
        location = (
            EvidenceLocation(file=file, line=as_line(position.get("line")), method=method or None)
            if file
            else None
        )
        records.append(
            build_record(
                source=source,
                producer=producer,
                kind="entry-point",
                discriminator=neutral_discriminator(ep, paths),
                locations=tuple(loc for loc in (location,) if loc),
                attributes=attributes or None,
                caveats=tuple(where.caveats(base_caveats)),
            )
        )

    outside = paths.producer_caveat()
    caveats = _dedupe_caveats(base_caveats + skipped.caveats() + ([outside] if outside else []))
    return AdapterResult(status=STATUS_COMPLETED, records=records, caveats=caveats)


__all__ = [
    "PRODUCER_NAME",
    "SUPPORTED_MAJOR",
    "attribute_name",
    "build_bom_purl_index",
    "extract",
    "is_kosi_report",
    "reconcile_purl",
]
