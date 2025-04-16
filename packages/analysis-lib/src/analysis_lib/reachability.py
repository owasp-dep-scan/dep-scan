from analysis_lib import (
    ReachabilityAnalysisKV,
    ReachabilityAnalyzer,
    ReachabilityResult,
)
from analysis_lib.config import SERVICE_TAGS
from custom_json_diff.lib.utils import json_load
from collections import defaultdict
from typing import Optional


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
        if analysis_options.slices_files:
            for slice_file in analysis_options.slices_files:
                if "reachables" not in slice_file:
                    continue
                reachables = json_load(slice_file).get("reachables") or []
                for flow in reachables:
                    if len(flow.get("purls", [])) > 0:
                        for apurl in flow.get("purls"):
                            reached_purls[apurl] += 1
        if not direct_purls and not reached_purls:
            status = False
        return ReachabilityResult(
            success=status, direct_purls=direct_purls, reached_purls=reached_purls
        )


class SemanticReachability(FrameworkReachability):
    """
    Semantic Reachability Analyzer
    """

    def _track_usage_targets(self, usage_targets, usages_object):
        for k, v in usages_object.items():
            for file, lines in v.items():
                usage_targets[file] = True
                for l in lines:
                    usage_targets[f"{file}#{l}"] = True

    def _is_service_like_tag(self, tags):
        if not tags:
            return False
        return any([t for t in tags if t in SERVICE_TAGS])

    def process(self) -> ReachabilityResult:
        analysis_options = self.analysis_options
        if not analysis_options:
            return ReachabilityResult(success=False)
        direct_purls = defaultdict(int)
        reached_purls = defaultdict(int)
        reached_services = defaultdict(int)
        endpoint_reached_purls = defaultdict(int)
        typed_components = defaultdict(list)
        status = True
        # Collect the endpoint usage information from the openapi files
        usage_targets = {}
        if analysis_options.openapi_spec_files:
            for ospec in analysis_options.openapi_spec_files:
                paths = json_load(ospec).get("paths") or {}
                for url_prefix, path_obj in paths.items():
                    for k, v in path_obj.items():
                        # Java, JavaScript, Python etc
                        if k == "x-atom-usages":
                            self._track_usage_targets(usage_targets, v)
                        # Ruby, Scala etc
                        if v.get("x-atom-usages"):
                            self._track_usage_targets(
                                usage_targets, v.get("x-atom-usages")
                            )
        # Collect the direct purls based on the occurrences evidence in the BOMs
        if analysis_options.bom_files:
            for bom_file in analysis_options.bom_files:
                data = json_load(bom_file)
                # For now we will also include usability slice as well
                for c in data.get("components", []):
                    purl = c.get("purl", "")
                    typed_components[c.get("type")].append(purl)
                    if c.get("evidence") and c["evidence"].get("occurrences"):
                        if usage_targets and c.get("type") in (
                            "framework",
                            "container",
                            "platform",
                            "device-driver",
                            "firmware",
                            "machine-learning-model",
                            "cryptographic-asset",
                        ):
                            endpoint_reached_purls[purl] += 1
                        direct_purls[purl] += len(c["evidence"].get("occurrences"))
                        for occ in c["evidence"].get("occurrences"):
                            if not occ.get("location"):
                                continue
                            if usage_targets.get(occ.get("location")):
                                endpoint_reached_purls[purl] += 1
        # Collect the reached purls from the slices
        if analysis_options.slices_files:
            for slice_file in analysis_options.slices_files:
                if "reachables" not in slice_file:
                    continue
                reachables = json_load(slice_file).get("reachables") or []
                for flow in reachables:
                    if len(flow.get("purls", [])) > 0:
                        tags = flow.get("tags", []) or []
                        for apurl in flow.get("purls"):
                            reached_purls[apurl] += 1
                            # Could this be an external service
                            if self._is_service_like_tag(tags):
                                reached_services[apurl] += 1
                            # Could this be endpoint reachable?
                            if apurl in typed_components.get("framework", []):
                                endpoint_reached_purls[apurl] += 1
        if not direct_purls and not reached_purls:
            status = False
        return ReachabilityResult(
            success=status,
            direct_purls=direct_purls,
            reached_purls=reached_purls,
            reached_services=reached_services,
            endpoint_reached_purls=endpoint_reached_purls,
        )
