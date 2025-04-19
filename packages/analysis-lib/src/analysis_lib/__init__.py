from abc import ABC, abstractmethod
from dataclasses import dataclass
import glob
from importlib.metadata import distribution
from logging import Logger
from typing import Dict, List, Optional

from rich.console import Console


def get_all_bom_files(from_dir):
    """
    Method to collect all BOM files from a given directory.
    """
    return glob.glob(f"{from_dir}/**/*bom*.json", recursive=True) + glob.glob(
        f"{from_dir}/**/*.cdx.json", recursive=True
    )


@dataclass
class VdrAnalysisKV:
    project_type: str
    init_results: List
    pkg_aliases: Optional[Dict]
    purl_aliases: Optional[Dict]
    suggest_mode: bool
    scoped_pkgs: Dict
    no_vuln_table: bool
    bom_file: Optional[str] = None
    bom_dir: Optional[str] = None
    pkg_list: Optional[List[Dict]] = None
    direct_purls: Optional[Dict] = None
    reached_purls: Optional[Dict] = None
    reached_services: Optional[Dict] = None
    endpoint_reached_purls: Optional[Dict] = None
    console: Optional[Console] = None
    logger: Optional[Logger] = None
    prebuild_purls: Optional[Dict] = None
    build_purls: Optional[Dict] = None
    postbuild_purls: Optional[Dict] = None
    operations_refs: Optional[Dict] = None
    decommission_refs: Optional[Dict] = None
    fuzzy_search: bool = False
    search_order: Optional[str] = None


@dataclass
class VDRResult:
    """
    Data class representing the result of VDR analysis.
    """

    success: bool = False
    pkg_vulnerabilities: Optional[List[Dict]] = None
    prioritized_pkg_vuln_trees: Optional[Dict] = None
    prioritized_prebuild_vuln_trees: Optional[List[Dict]] = None
    prioritized_build_vuln_trees: Optional[List[Dict]] = None
    prioritized_postbuild_vuln_trees: Optional[List[Dict]] = None
    prioritized_operations_vuln_trees: Optional[List[Dict]] = None
    prioritized_decommission_vuln_trees: Optional[List[Dict]] = None
    reached_purls: Optional[Dict[str, int]] = None
    reached_services: Optional[Dict[str, int]] = None
    endpoint_reached_purls: Optional[Dict[str, int]] = None


class Counts:
    fp_count = 0
    pkg_attention_count = 0
    critical_count = 0
    malicious_count = 0
    has_poc_count = 0
    has_reachable_poc_count = 0
    has_exploit_count = 0
    has_reachable_exploit_count = 0
    fix_version_count = 0
    wont_fix_version_count = 0
    distro_packages_count = 0
    has_os_packages = False
    has_redhat_packages = False
    has_ubuntu_packages = False
    ids_seen = {}


class XBOMAnalyzer(ABC):
    """
    Base class for analyzing xBOM

    Attributes:
        vdr_options (VdrAnalysisKV): VDR options
    """

    def __init__(self, vdr_options: VdrAnalysisKV) -> None:
        self.vdr_options = vdr_options

    @abstractmethod
    def process(self) -> VDRResult:
        """
        Perform the analysis.
        Must be implemented by subclasses.
        """
        raise NotImplementedError("Subclasses must implement this method.")


@dataclass
class ReachabilityAnalysisKV:
    project_types: List[str]
    src_dir: str
    bom_dir: Optional[str]
    bom_files: Optional[List[str]] = None
    slices_files: Optional[List[str]] = None
    openapi_spec_files: Optional[List[str]] = None
    clean_up: bool = False
    export_graph_dir: Optional[str] = None
    detect_endpoints: bool = True
    detect_crypto_libs: bool = True
    require_multi_usage: bool = False
    source_tags: Optional[List[str]] = None
    sink_tags: Optional[List[str]] = None

    def __post_init__(self):
        # Collect bom files
        if not self.bom_files and self.bom_dir:
            self.bom_files = get_all_bom_files(self.bom_dir)
        # collect available slices files
        if not self.slices_files and self.bom_dir:
            self.slices_files = glob.glob(
                f"{self.bom_dir}/**/*slices.json", recursive=True
            )
        # collect the openapi spec files
        if not self.openapi_spec_files:
            if self.src_dir:
                self.openapi_spec_files = glob.glob(
                    f"{self.src_dir}/*openapi*.json", recursive=False
                )
            elif self.bom_dir:
                self.openapi_spec_files = glob.glob(
                    f"{self.bom_dir}/*openapi*.json", recursive=False
                )


@dataclass
class ReachabilityResult:
    success: bool
    direct_purls: Optional[Dict[str, int]] = None
    reached_purls: Optional[Dict[str, int]] = None
    reached_services: Optional[Dict[str, int]] = None
    endpoint_reached_purls: Optional[Dict[str, int]] = None


class ReachabilityAnalyzer(ABC):
    """
    Base class for performing reachability analysis

    Attributes:
        analysis_options (ReachabilityAnalysisKV): Analysis options
    """

    def __init__(self, analysis_options: Optional[ReachabilityAnalysisKV]) -> None:
        self.analysis_options = analysis_options

    @abstractmethod
    def process(self) -> ReachabilityResult:
        """
        Perform the analysis.
        Must be implemented by subclasses.
        """
        raise NotImplementedError("Subclasses must implement this method.")


def get_version():
    """
    Returns the version of depscan
    """
    return (
        distribution("ds-analysis-lib").version or distribution("owasp-depscan").version
    )
