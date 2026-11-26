from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from importlib.metadata import distribution
from logging import Logger
from typing import Any, Dict, List, Optional
import fnmatch

from rich.console import Console

from analysis_lib.evidence.store import EVIDENCE_FILE


#: File names under a BOM directory that are scan outputs and never input
#: BOMs: the VDR and CSAF documents, the supply-chain stage's cdx-audit
#: reports and purl-scan input, the license report and cdxgen's
#: introspection report. A BOM-directory scan has the project type ``bom``,
#: so its license report is ``license-bom.json``, and a CSAF document named
#: after ``sbom-universal.cdx.json`` is ``sbom-universal.csaf.json``. Both
#: match ``*bom*.json`` when the reports directory is the BOM directory.
BOM_EXCLUDE_PATTERNS = (
    "*.vdr.json",
    "*.csaf.json",
    "*.introspection.json",
    "cdx-audit-*",
    "license-*.json",
)


def _starts_as_object(path):
    """Whether the JSON file at ``path`` opens with ``{``.

    A CycloneDX BOM is a JSON object, so a file whose first character is
    anything else (a list, a string, an empty file) is not one, whatever its
    name says. Only the opening bytes are read, so large BOMs stay cheap.
    """
    try:
        with open(path, "rb") as handle:
            head = handle.read(4096)
    except OSError:
        return False
    head = head.removeprefix(b"\xef\xbb\xbf").lstrip()
    return head.startswith(b"{")


def get_all_bom_files(from_dir):
    """
    Collect all BOM JSON files under `from_dir`, excluding the files
    :data:`BOM_EXCLUDE_PATTERNS` names and files that do not hold a JSON
    object.
    """
    base = Path(from_dir)
    include_patterns = ["*bom*.json", "*.cdx.json"]

    files = set()
    for pattern in include_patterns:
        for p in base.rglob(pattern):
            if any(fnmatch.fnmatch(p.name, exclude) for exclude in BOM_EXCLUDE_PATTERNS):
                continue
            if p.is_file() and _starts_as_object(p):
                files.add(str(p.resolve()))

    return sorted(files)


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
    severity: Optional[str] = None
    exclude_malware: bool = False
    malware_only: bool = False
    #: What this scan produced for the exploitability axes, or None when
    #: the caller grades no exploitability. An
    #: analysis_lib.findings.exploitability.ExploitabilityInputs.
    exploitability_inputs: Optional[Any] = None


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
    purl_identities: Optional[Dict[str, List]] = None
    #: The (advisory id, affects ref) -> Exploitability map the entries were
    #: graded into, or None when this run graded no exploitability.
    exploitability: Optional[Dict] = None
    #: Database rows the export left out because they named no component
    #: (an empty ``matched_by``); the caller states the count on the scan's
    #: coverage so the rows are never dropped silently.
    rows_without_component: int = 0


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
    #: Database rows whose matched_by named no component; the VDR export
    #: skips them instead of writing an affects ref that is the empty string.
    no_matched_by_count = 0
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
    evidence_file: Optional[str] = None
    openapi_spec_files: Optional[List[str]] = None
    clean_up: bool = False
    export_graph_dir: Optional[str] = None
    detect_endpoints: bool = True
    detect_crypto_libs: bool = True
    require_multi_usage: bool = False
    source_tags: Optional[List[str]] = None
    sink_tags: Optional[List[str]] = None
    #: The scan root the evidence adapters made record paths relative to;
    #: the engine spells the OpenAPI usage targets against the same root.
    #: ``src_dir`` stands in when it is not given.
    source_root: Optional[str] = None

    def __post_init__(self):
        # Collect bom files
        if not self.bom_files and self.bom_dir:
            self.bom_files = get_all_bom_files(self.bom_dir)
        # Collect available slices files
        if not self.slices_files and self.bom_dir:
            self.slices_files = sorted(
                str(p.resolve()) for p in Path(self.bom_dir).rglob("*slices*.json")
            )
        # Collect the evidence store file
        if not self.evidence_file and self.bom_dir:
            self.evidence_file = str((Path(self.bom_dir) / EVIDENCE_FILE).resolve())
        # Collect the openapi spec files
        if not self.openapi_spec_files:
            search_dir = Path(self.bom_dir) if self.bom_dir else Path(self.src_dir)
            self.openapi_spec_files = sorted(
                str(p.resolve()) for p in search_dir.glob("*openapi*.json")
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
    return distribution("ds-analysis-lib").version or distribution("owasp-depscan").version
