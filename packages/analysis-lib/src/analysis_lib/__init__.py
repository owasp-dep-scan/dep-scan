from abc import ABC, abstractmethod
from dataclasses import dataclass
from importlib.metadata import distribution
from logging import Logger
from typing import Dict, List, Optional

from rich.console import Console


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
        vdr_options (VdrOptions): VDR options
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


def get_version():
    """
    Returns the version of depscan
    """
    return (
        distribution("ds-analysis-lib").version or distribution("owasp-depscan").version
    )
