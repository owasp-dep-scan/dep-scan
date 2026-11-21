"""The reachability analyzers over the evidence store.

The engine counts what the evidence records of the scan directory say:
positive records of the counted kinds put their subject purls on an
executed path, a record's ``servicePurls`` attribute and an entry point's
handler purls feed the reached-services set, and a reached purl typed
``framework`` in the BOM and not filterable is endpoint-reachable. The
records come from the store the enrichment stage wrote; the engine reads no
producer report itself. Occurrences in the BOMs, the ``x-atom-usages``
usage targets of the OpenAPI documents and the post-build binary
reachability support keep their role beside the records.
"""

from analysis_lib import (
    ReachabilityAnalysisKV,
    ReachabilityAnalyzer,
    ReachabilityResult,
)
from analysis_lib.config import MIN_POSTBUILD_CONFIDENCE
from analysis_lib.endpoints import (
    strip_version,
    is_endpoint_filterable,
)
from analysis_lib.evidence import Evidence
from analysis_lib.evidence.store import stream as stream_evidence
from custom_json_diff.lib.utils import json_load
from collections import defaultdict
from typing import Dict, Iterator, Optional
import json
import os

#: The record kinds whose positive records count as reached evidence. A
#: record of another kind (a callsite, a dependency note, a sanitizer, a
#: dead-code mark) is evidence about the package, never reached evidence.
REACHED_COUNTED_KINDS = frozenset({"reached-flow", "usage", "entry-point"})


def _reached_records(records: Iterator[Evidence]) -> Iterator[Evidence]:
    """The records that count as reached evidence, per the counting rule:
    positive polarity and one of :data:`REACHED_COUNTED_KINDS`."""
    for record in records:
        if record.polarity == "positive" and record.kind in REACHED_COUNTED_KINDS:
            yield record


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
        # Count the reached purls from the evidence records
        if analysis_options.evidence_file and os.path.isfile(analysis_options.evidence_file):
            for record in _reached_records(stream_evidence(analysis_options.evidence_file)):
                for apurl in record.subject.purls:
                    reached_purls[apurl] += 1
        if not direct_purls and not reached_purls:
            status = False
        return ReachabilityResult(
            success=status,
            direct_purls=direct_purls,
            reached_purls=reached_purls,
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
        # Count the reached purls, services and endpoint reachability from
        # the evidence records. The adapters own service attribution: a
        # record's ``servicePurls`` attribute holds exactly the purls the
        # producer marked as services, so this walk never reads tags. An
        # entry point's handler purls are its subject purls and count as
        # services without an attribute.
        if analysis_options.evidence_file and os.path.isfile(analysis_options.evidence_file):
            for record in _reached_records(stream_evidence(analysis_options.evidence_file)):
                service_purls = set((record.attributes or {}).get("servicePurls") or [])
                for apurl in record.subject.purls:
                    reached_purls[apurl] += 1
                    # Could this be an external service
                    if apurl in service_purls or record.kind == "entry-point":
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
        )
