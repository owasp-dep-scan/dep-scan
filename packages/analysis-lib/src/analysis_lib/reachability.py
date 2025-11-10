from analysis_lib import (
    ReachabilityAnalysisKV,
    ReachabilityAnalyzer,
    ReachabilityResult,
)
from analysis_lib.config import MIN_POSTBUILD_CONFIDENCE
from analysis_lib.utils import (
    strip_version,
    is_service_like_tag,
    is_endpoint_filterable,
)
from custom_json_diff.lib.utils import json_load
from collections import defaultdict
from typing import Dict, Optional


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
                reachables = json_load(slice_file) or []
                # Backwards compatibility
                if isinstance(reachables, dict) and reachables.get("reachables"):
                    reachables = reachables.get("reachables")
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

    @staticmethod
    def _track_usage_targets(usage_targets, usages_object):
        for k, v in usages_object.items():
            for file, lines in v.items():
                usage_targets[file] = True
                for aline in lines:
                    usage_targets[f"{file}#{aline}"] = True

    @staticmethod
    def _track_binary_reachability(
        postbuild_purls: Dict,
        interesting_postbuild_purls: Dict[str, int],
        reached_purls: Dict[str, int],
        endpoint_reached_purls: Dict[str, int],
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
                    endpoint_reached_purls[
                        normalized_to_original_purl[purl_no_version]
                    ] += 1

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
                paths = json_load(ospec).get("paths") or {}
                for url_prefix, path_obj in paths.items():
                    for k, v in path_obj.items():
                        # Java, JavaScript, Python etc
                        if k == "x-atom-usages":
                            self._track_usage_targets(usage_targets, v)
                        # Ruby, Scala etc
                        if isinstance(v, dict) and v.get("x-atom-usages"):
                            self._track_usage_targets(
                                usage_targets, v.get("x-atom-usages")
                            )
        # Collect the direct purls based on the occurrences evidence in the BOMs
        if analysis_options.bom_files:
            for bom_file in analysis_options.bom_files:
                data = json_load(bom_file)
                lifecycles = data.get("metadata", {}).get("lifecycles", []) or []
                is_post_build = any(
                    [l for l in lifecycles if l.get("phase") == "post-build"]
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
                        if (
                            usage_targets
                            and c.get("type")
                            in (
                                "framework",
                                "container",
                                "platform",
                                "device-driver",
                                "firmware",
                                "machine-learning-model",
                                "cryptographic-asset",
                            )
                            and not is_endpoint_filterable(purl)
                        ):
                            endpoint_reached_purls[purl] += 1
                            if postbuild_purls.get(purl):
                                interesting_postbuild_purls[purl] = True
                        direct_purls[purl] += len(c["evidence"].get("occurrences"))
                        for occ in c["evidence"].get("occurrences"):
                            if not occ.get("location"):
                                continue
                            if usage_targets.get(
                                occ.get("location")
                            ) and not is_endpoint_filterable(purl):
                                endpoint_reached_purls[purl] += 1
        # Collect the reached purls from the slices
        if analysis_options.slices_files:
            for slice_file in analysis_options.slices_files:
                if "reachables" not in slice_file:
                    continue
                reachables = json_load(slice_file) or []
                # Backwards compatibility
                if isinstance(reachables, dict) and reachables.get("reachables"):
                    reachables = reachables.get("reachables")
                for flow in reachables:
                    if len(flow.get("purls", [])) > 0:
                        tags = flow.get("tags", []) or []
                        for apurl in flow.get("purls"):
                            reached_purls[apurl] += 1
                            # Could this be an external service
                            if is_service_like_tag(tags):
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
