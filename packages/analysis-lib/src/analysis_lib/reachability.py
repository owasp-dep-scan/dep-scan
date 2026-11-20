from analysis_lib import (
    ReachabilityAnalysisKV,
    ReachabilityAnalyzer,
    ReachabilityResult,
)
from analysis_lib.config import MIN_POSTBUILD_CONFIDENCE, SERVICE_TAGS
from analysis_lib.endpoints import (
    strip_version,
    is_endpoint_filterable,
)
from custom_json_diff.lib.utils import json_load
from collections import defaultdict
from typing import Dict, Iterable, Iterator, List, Optional
import hashlib
import json
import os


def _flow_tags(flow: dict) -> List[str]:
    """Collect tags for a reachables flow.

    atom reachables slices put ``tags`` on each NODE inside
    ``flow["flows"]`` as a comma-separated string (e.g.
    ``"pkg:npm/express@4.22.2, framework, web"``); the flow object itself
    carries only ``flows`` and ``purls``
    (``ReachableFlows`` in atom's ``slicing/package.scala``), so no
    flow-level ``tags`` key is read.
    """
    tags: List[str] = []
    seen = set()

    def _add(value) -> None:
        if isinstance(value, str):
            for piece in value.split(","):
                piece = piece.strip()
                if piece and piece not in seen:
                    seen.add(piece)
                    tags.append(piece)
        elif isinstance(value, (list, tuple)):
            for item in value:
                _add(item)

    nodes = flow.get("flows")
    if isinstance(nodes, list):
        for node in nodes:
            if isinstance(node, dict):
                _add(node.get("tags"))
    return tags


def _split_tag_pieces(value) -> List[str]:
    """Flatten a node ``tags`` value (comma-string or list) into stripped
    non-empty pieces, preserving order. Atom stores a comma-string; a list is
    accepted too."""
    pieces: List[str] = []

    def _walk(v) -> None:
        if isinstance(v, str):
            for piece in v.split(","):
                piece = piece.strip()
                if piece:
                    pieces.append(piece)
        elif isinstance(v, (list, tuple)):
            for item in v:
                _walk(item)

    _walk(value)
    return pieces


def _node_service_purls(pieces: List[str], flow_purls) -> set:
    """The purls a node's tag string marks as services.

    A node's ``tags`` string interleaves purls and free-form tags in discovery
    order, e.g. ``"pkg:npm/jsonwebtoken@0.4.0, token, web,
    pkg:npm/%40codemirror/lang-json@6.0.2"``: the free-form tags describe the
    NEAREST preceding purl in that string, so ``token``/``web`` belong to
    ``jsonwebtoken`` and ``codemirror`` gets none. Flattening every node tag
    across the whole flow and applying it to EVERY flow purl leaks service
    tags onto unrelated packages, so tags are associated per node.

    Atom 4 adds one order this positional walk must also cover: for a call
    whose own tags name no purl, the callee's package URLs are appended AFTER
    them (``withPurls`` in ``ReachableSlicing.scala``), so a service tag can
    PRECEDE every purl in the string (``"web, pkg:npm/express@4.22.2"``). Such
    a tag describes the call, and the purls appended right after it are the
    callee's packages (often two versions of one library), so it applies to
    each purl in the run that directly follows it and to nothing after the
    next free-form tag.

    A node that carries a SERVICE_TAG but names no purl at all keeps the
    fallback to the flow-level ``purls`` so the signal is never lost.
    """
    node_purl_is_service: dict = {}
    current_purl = None
    pending_service = False
    for piece in pieces:
        if piece.startswith("pkg:"):
            node_purl_is_service.setdefault(piece, False)
            current_purl = piece
            if pending_service:
                node_purl_is_service[piece] = True
            continue
        # A free-form tag ends the run of purls a leading service tag covers.
        pending_service = False
        if piece in SERVICE_TAGS:
            # Attribute to the nearest preceding purl; if none came yet, the
            # pending flag hands the tag to the purls that directly follow.
            if current_purl is not None:
                node_purl_is_service[current_purl] = True
            else:
                pending_service = True
    if any(node_purl_is_service.values()):
        return {p for p, has_svc in node_purl_is_service.items() if has_svc}
    if not node_purl_is_service and any(p in SERVICE_TAGS for p in pieces):
        return set(flow_purls)
    return set()


def _flow_service_purls(flow: dict) -> set:
    """Return the set of purls in ``flow`` that carry a SERVICE_TAG on their
    OWN node. See :func:`_node_service_purls` for the association rules."""
    flow_purls = flow.get("purls") or []
    service_purls: set = set()
    nodes = flow.get("flows")
    if isinstance(nodes, list):
        for node in nodes:
            if not isinstance(node, dict):
                continue
            pieces = _split_tag_pieces(node.get("tags"))
            if not pieces:
                continue
            service_purls.update(_node_service_purls(pieces, flow_purls))
    return service_purls


def _flow_identity(flow: dict) -> bytes:
    """Stable identity hash for a reachables flow object.

    Used to dedup the same flow appearing in multiple slice files. Hashes
    the canonical JSON form so dict ordering does not matter; flows that
    differ in any value (purls, node tags, signatures, ...) hash distinctly.
    """
    return hashlib.md5(
        json.dumps(flow, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).digest()


def _iter_json_list(file_path: str):
    """Stream a top-level JSON array from ``file_path``, yielding one parsed
    element at a time.

    The reachables slices are JSON lists of ``{"flows": [...], "purls": [...]}``
    objects, capped at 1000 entries per file. Materializing the full parsed
    list costs ~3.3x the file size in RSS (each flow carries several KB of
    node body: code, signature, fullName, line/col, ...). The analyzer only
    consumes each flow's purls + node tags, so we stream the list with
    ``JSONDecoder.raw_decode``: peak RSS is roughly ``file_text_size`` plus
    ONE parsed element instead of the full tree.

    If the file is not a JSON list, the iterator yields nothing; atom
    reachables slices are always bare JSON arrays.
    """
    decoder = json.JSONDecoder()
    try:
        with open(file_path, encoding="utf-8") as fp:
            text = fp.read()
    except OSError:
        return
    n = len(text)
    idx = 0
    while idx < n and text[idx] in " \t\n\r":
        idx += 1
    if idx >= n or text[idx] != "[":
        return
    idx += 1
    while idx < n:
        while idx < n and text[idx] in " \t\n\r":
            idx += 1
        if idx >= n:
            return
        if text[idx] == "]":
            return
        try:
            obj, end = decoder.raw_decode(text, idx)
        except json.JSONDecodeError:
            return
        yield obj
        idx = end
        while idx < n and text[idx] in " \t\n\r":
            idx += 1
        if idx < n and text[idx] == ",":
            idx += 1


def _iter_unique_reachable_flows_by_file(
    slices_files: Optional[Iterable[str]],
) -> Iterator[tuple]:
    """Yield ``(slice_file, flow)`` for each unique reachables flow, the
    slice file the flow was read from included.

    atom reachables slices are bare JSON arrays, split into one
    ``slices.json`` plus ``slices_1..N.json`` files capped at 1000 flow
    objects each (``calculateReachableSliceAndPersist`` in atom's
    ``ReachableSlicing.scala``). The unsplit file is NOT simply a prefix of
    the numbered splits, so every file must be read for a complete reached
    SET. But intra-set duplication is heavy, and counting a flow twice
    inflates ``reached_purls[purl] += 1`` without changing which purls are
    reached. This iterator yields each flow once (identity == canonical
    JSON of the whole flow object), so callers can count freely and collect
    each file's purl set from the flows it actually yielded: a duplicate
    flow carries the same purls as the copy that was yielded, so the per
    file set matches a full read of the file.

    Memory: slices are streamed via ``_iter_json_list`` so the full parsed
    tree is never materialized; only the file text + one flow at a time.
    A file that is not a bare JSON array yields nothing.
    """
    seen: set = set()
    for slice_file in slices_files or []:
        if not slice_file or "reachables" not in slice_file:
            continue
        for flow in _iter_json_list(slice_file):
            if not isinstance(flow, dict):
                continue
            identity = _flow_identity(flow)
            if identity in seen:
                continue
            seen.add(identity)
            yield slice_file, flow


def _iter_unique_reachable_flows(
    slices_files: Optional[Iterable[str]],
) -> Iterator[dict]:
    """Yield each unique reachables flow across all slice files.

    See :func:`_iter_unique_reachable_flows_by_file`, which this wraps when
    the caller does not need the file each flow came from.
    """
    for _slice_file, flow in _iter_unique_reachable_flows_by_file(slices_files):
        yield flow


#: The purl type each atom slice file prefix (``<prefix>-reachables.slices``)
#: covers, by cdxgen project type and its aliases.
ATOM_SLICE_PURL_TYPES = {
    **dict.fromkeys(
        ("java", "jar", "war", "kotlin", "kt", "android", "scala", "gradle", "maven", "jvm"),
        "maven",
    ),
    **dict.fromkeys(("js", "javascript", "ts", "typescript", "nodejs", "npm", "yarn"), "npm"),
    **dict.fromkeys(("python", "py", "pypi"), "pypi"),
    **dict.fromkeys(("php", "composer"), "composer"),
    **dict.fromkeys(("ruby", "gem"), "gem"),
}


def _purl_type(purl: str) -> str:
    head = str(purl).split("/", 1)[0]
    return head[4:].lower() if head.lower().startswith("pkg:") else ""


def reached_by_analyzer(
    slices_files: Optional[Iterable[str]],
    tool_stems: Dict[str, str],
    purls_by_file: Optional[Dict[str, set]] = None,
) -> Dict[str, Dict[str, set]]:
    """What each analyzer's reachables slices put on an executed path.

    ``tool_stems`` maps each language tool's name to the file-name stem of the
    slice it writes (``go-reachables`` for golem); every other reachables file
    is atom's. Returns ``{analyzer: {"purls": set, "types": set}}`` for the
    analyzers that produced a reachables file. The purl types of a tool are
    not read from here (a tool covers one ecosystem); atom's are those its
    slice file prefixes map to (:data:`ATOM_SLICE_PURL_TYPES`), and a prefix
    that is not known contributes the purl types its flows carry.

    ``purls_by_file`` carries the per-file purl sets a reachability
    analysis pass collected while reading the same slices. A file present
    there is not parsed again; a file it does not cover is read as before.
    """
    result: Dict[str, Dict[str, set]] = {}
    for slice_file in slices_files or []:
        name = os.path.basename(str(slice_file or ""))
        if "reachables.slices" not in name:
            continue
        analyzer = "atom"
        for tool, stem in tool_stems.items():
            if name.startswith(stem):
                analyzer = tool
                break
        entry = result.setdefault(analyzer, {"purls": set(), "types": set()})
        purls = (purls_by_file or {}).get(slice_file)
        if purls is None:
            purls = set()
            for flow in _iter_json_list(slice_file):
                if isinstance(flow, dict):
                    purls.update(str(p) for p in flow.get("purls") or [])
        entry["purls"] |= purls
        if analyzer == "atom":
            mapped = ATOM_SLICE_PURL_TYPES.get(name.split("-reachables", 1)[0].lower())
            if mapped:
                entry["types"].add(mapped)
            else:
                entry["types"] |= {t for t in map(_purl_type, purls) if t}
    return result


def get_reachability_impl(
    reachability_analyzer: str, reachability_options: Optional[ReachabilityAnalysisKV]
):
    if not reachability_options:
        return NullReachability(reachability_options)
    if reachability_analyzer == "FrameworkReachability":
        return FrameworkReachability(reachability_options)
    if reachability_analyzer == "SemanticReachability":
        return SemanticReachability(reachability_options)
    return NullReachability(reachability_options)


class NullReachability(ReachabilityAnalyzer):
    """
    Dummy Reachability Analyzer
    """

    def process(self) -> ReachabilityResult:
        return ReachabilityResult(success=True)


class FrameworkReachability(ReachabilityAnalyzer):
    """
    Framework Forward Reachability Analyzer
    """

    def process(self) -> ReachabilityResult:
        analysis_options = self.analysis_options
        if not analysis_options:
            return ReachabilityResult(success=False)
        direct_purls = defaultdict(int)
        reached_purls = defaultdict(int)
        status = True
        # Collect the direct purls based on the occurrences evidence in the BOMs
        if analysis_options.bom_files:
            for bom_file in analysis_options.bom_files:
                data = json_load(bom_file)
                # For now we will also include usability slice as well
                for c in data.get("components", []):
                    purl = c.get("purl", "")
                    if c.get("evidence") and c["evidence"].get("occurrences"):
                        direct_purls[purl] += len(c["evidence"].get("occurrences"))
        # Collect the reached purls from the slices
        purls_by_file: Dict[str, set] = {}
        if analysis_options.slices_files:
            # Dedup flow-objects by identity across all slice files so
            # reached_purls[purl] += 1 is not inflated by intra-set
            # duplicates. The reached SET is unchanged; only counts drop.
            # Each file's purl set is collected on the way, so a caller that
            # needs per-file sets can take them instead of re-reading.
            for slice_file, flow in _iter_unique_reachable_flows_by_file(
                analysis_options.slices_files
            ):
                purls_by_file.setdefault(slice_file, set()).update(
                    str(p) for p in flow.get("purls") or []
                )
                for apurl in flow.get("purls") or []:
                    reached_purls[apurl] += 1
        if not direct_purls and not reached_purls:
            status = False
        return ReachabilityResult(
            success=status, direct_purls=direct_purls, reached_purls=reached_purls,
            purls_by_file=purls_by_file,
        )


class SemanticReachability(FrameworkReachability):
    """
    Semantic Reachability Analyzer
    """

    @staticmethod
    def _track_usage_targets(usage_targets, usages_object):
        # x-atom-usages values are per-file lists of line numbers: atom-tools
        # writes ``call`` and ``target`` in the same shape ("call": {file:
        # [lines]}, "target": {file: [lines]}). Anything else is ignored
        # rather than crashing the analyzer.
        if not isinstance(usages_object, dict):
            return
        for k, v in usages_object.items():
            if not isinstance(v, dict):
                continue
            for file, lines in v.items():
                usage_targets[file] = True
                if isinstance(lines, (list, tuple, set)):
                    for aline in lines:
                        usage_targets[f"{file}#{aline}"] = True

    @staticmethod
    def _track_binary_reachability(
        postbuild_purls: Dict,
        interesting_postbuild_purls: Dict[str, bool],
        reached_purls: Dict[str, int],
        endpoint_reached_purls: Optional[Dict[str, int]],
        typed_components: Dict[str, list],
    ):
        # Return early in we don't have post-build or component type information
        if not postbuild_purls or not typed_components:
            return
        frameworks = typed_components.get("framework", [])
        cryptos = typed_components.get("cryptographic-asset", [])
        # require at least one of framework or crypto to proceed
        if not frameworks and not cryptos:
            return
        versionless_purls = set()
        normalized_to_original_purl = {}
        for p in frameworks + cryptos:
            purl_no_version = strip_version(p)
            versionless_purls.add(purl_no_version)
            normalized_to_original_purl[purl_no_version] = p
        for purl in postbuild_purls:
            purl_no_version = strip_version(purl)
            if is_endpoint_filterable(purl_no_version):
                continue
            if purl_no_version in versionless_purls:
                reached_purls[normalized_to_original_purl[purl_no_version]] += 1
                # Could this be endpoint reachable.
                if endpoint_reached_purls:
                    endpoint_reached_purls[normalized_to_original_purl[purl_no_version]] += 1

    def process(self) -> ReachabilityResult:
        analysis_options = self.analysis_options
        if not analysis_options:
            return ReachabilityResult(success=False)
        direct_purls = defaultdict(int)
        reached_purls = defaultdict(int)
        reached_services = defaultdict(int)
        endpoint_reached_purls = defaultdict(int)
        postbuild_purls = {}
        interesting_postbuild_purls = {}
        typed_components = defaultdict(list)
        status = True
        # Collect the endpoint usage information from the openapi files
        usage_targets = {}
        if analysis_options.openapi_spec_files:
            for ospec in analysis_options.openapi_spec_files:
                spec_data = json_load(ospec)
                if not isinstance(spec_data, dict):
                    continue
                paths = spec_data.get("paths") or {}
                if not isinstance(paths, dict):
                    continue
                for url_prefix, path_obj in paths.items():
                    if not isinstance(path_obj, dict):
                        continue
                    for k, v in path_obj.items():
                        # Java, JavaScript, Python etc
                        if k == "x-atom-usages":
                            self._track_usage_targets(usage_targets, v)
                        # Ruby, Scala etc
                        if isinstance(v, dict) and v.get("x-atom-usages"):
                            self._track_usage_targets(usage_targets, v.get("x-atom-usages"))
        # Collect the direct purls based on the occurrences evidence in the BOMs
        if analysis_options.bom_files:
            for bom_file in analysis_options.bom_files:
                data = json_load(bom_file)
                lifecycles = data.get("metadata", {}).get("lifecycles", []) or []
                is_post_build = any(
                    [aline for aline in lifecycles if aline.get("phase") == "post-build"]
                )
                # For now we will also include usability slice as well
                for c in data.get("components", []):
                    purl = c.get("purl", "")
                    # Filter low confidence generic and file components
                    if is_post_build and (
                        purl.startswith("pkg:generic") or purl.startswith("pkg:file")
                    ):
                        confidence = None
                        identity_list_obj = c.get("evidence", {}).get("identity", [])
                        if isinstance(identity_list_obj, dict):
                            identity_list_obj = [identity_list_obj]
                        for aident in identity_list_obj:
                            if (
                                aident
                                and aident.get("confidence")
                                and aident.get("confidence") >= MIN_POSTBUILD_CONFIDENCE
                            ):
                                confidence = aident.get("confidence")
                                break
                        if confidence and confidence < MIN_POSTBUILD_CONFIDENCE:
                            continue
                    if is_post_build:
                        postbuild_purls[purl] = True
                    component_type = c.get("type")
                    typed_components[component_type].append(purl)
                    # Work harder to track frameworks. See https://github.com/CycloneDX/cdxgen/issues/1750
                    if (
                        component_type != "framework"
                        and c.get("tags")
                        and "framework" in c.get("tags")
                    ):
                        typed_components["framework"].append(purl)
                        # If this purl is also seen in a post-build SBOM, it is likely interesting
                        if postbuild_purls.get(purl):
                            interesting_postbuild_purls[purl] = True
                    if c.get("evidence") and c["evidence"].get("occurrences"):
                        direct_purls[purl] += len(c["evidence"].get("occurrences"))
                        # A component is endpoint-reachable only when one of ITS
                        # OWN occurrence locations is an atom usage target
                        # (x-atom-usages). We do not mark every framework-typed
                        # component with any occurrence as endpoint-reached just
                        # because usage_targets is globally non-empty; that
                        # over-attributes endpoints to components whose own
                        # locations are never actually used.
                        for occ in c["evidence"].get("occurrences"):
                            if not occ.get("location"):
                                continue
                            if usage_targets.get(
                                occ.get("location")
                            ) and not is_endpoint_filterable(purl):
                                endpoint_reached_purls[purl] += 1
                                if postbuild_purls.get(purl):
                                    interesting_postbuild_purls[purl] = True
        # Collect the reached purls from the slices
        purls_by_file: Dict[str, set] = {}
        if analysis_options.slices_files:
            # Dedup flow-objects by identity across all slice files so
            # reached_purls[purl] += 1 / reached_services / endpoint
            # counts are not inflated by intra-set duplicates. The reached
            # SETS are unchanged; only counts drop. Each file's purl set is
            # collected on the way, so a caller that needs per-file sets can
            # take them instead of re-reading the slices.
            for slice_file, flow in _iter_unique_reachable_flows_by_file(
                analysis_options.slices_files
            ):
                purls_by_file.setdefault(slice_file, set()).update(
                    str(p) for p in flow.get("purls") or []
                )
                # Associate SERVICE_TAGS with the purl named in the SAME node's
                # tag string (positional), instead of flattening all node tags
                # across the flow and applying them to every flow purl. This
                # stops ``web`` from leaking off ``jsonwebtoken`` onto an
                # unrelated ``codemirror`` in the same flow.
                service_purls = _flow_service_purls(flow)
                for apurl in flow.get("purls") or []:
                    reached_purls[apurl] += 1
                    # Could this be an external service
                    if apurl in service_purls:
                        reached_services[apurl] += 1
                        if postbuild_purls.get(apurl):
                            interesting_postbuild_purls[apurl] = True
                    # Could this be endpoint reachable?
                    if apurl in typed_components.get(
                        "framework", []
                    ) and not is_endpoint_filterable(apurl):
                        endpoint_reached_purls[apurl] += 1
                        if postbuild_purls.get(apurl):
                            interesting_postbuild_purls[apurl] = True
        # Support for binary reachability
        self._track_binary_reachability(
            postbuild_purls,
            interesting_postbuild_purls,
            reached_purls,
            endpoint_reached_purls if usage_targets else None,
            typed_components,
        )
        if not direct_purls and not reached_purls:
            status = False
        return ReachabilityResult(
            success=status,
            direct_purls=direct_purls,
            reached_purls=reached_purls,
            reached_services=reached_services,
            endpoint_reached_purls=endpoint_reached_purls,
            purls_by_file=purls_by_file,
        )
