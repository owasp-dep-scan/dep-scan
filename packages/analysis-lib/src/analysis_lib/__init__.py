from abc import ABC, abstractmethod
from dataclasses import dataclass
from importlib.metadata import distribution
from typing import Dict, List, Optional
from logging import Logger

from rich.console import Console


@dataclass
class VdrOptions:
    project_type: str
    init_results: List
    pkg_aliases: Optional[Dict]
    purl_aliases: Optional[Dict]
    suggest_mode: bool
    scoped_pkgs: Dict
    no_vuln_table: bool
    bom_file: Optional[str]
    pkg_list: Optional[List[Dict]]
    direct_purls: Optional[Dict]
    reached_purls: Optional[Dict]
    console: Optional[Console]
    logger: Optional[Logger]


@dataclass
class VDRResult:
    """
    Data class representing the result of BOM generation.
    """

    success: bool = False
    pkg_vulnerabilities: Optional[List[Dict]] = None
    pkg_group_rows: Optional[List[Dict]] = None


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

    def __init__(self, vdr_options: VdrOptions) -> None:
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
