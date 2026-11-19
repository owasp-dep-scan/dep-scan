import contextlib
import datetime
import os
import shutil
import tempfile
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from xbom_lib import BOMResult, XBOMGenerator

BLINT_AVAILABLE = False
try:
    from blint.lib.runners import AnalysisRunner, run_sbom_mode
    from blint.config import BlintOptions, BLINTDB_IMAGE_URL
    from blint.lib.macos_bundle import find_macos_bundles, path_inside_any_bundle
    from blint.lib.utils import (
        blintdb_setup,
        export_metadata,
        find_clickonce_files,
        gen_file_list,
    )

    BLINT_AVAILABLE = True
except ImportError:
    pass

#: The files blint's review run writes into the reports directory, by the
#: name blint gives them. ``findings.json`` and ``reviews.json`` are written
#: only when there is something to report; the coverage file is always written
#: so an empty review can be told from one that never ran.
BLINT_FINDINGS_FILE = "findings.json"
BLINT_REVIEWS_FILE = "reviews.json"
BLINT_COVERAGE_FILE = "analysis-coverage.json"


@dataclass
class BlintReviewResult:
    """Outcome of one blint security review run.

    ``files`` lists the report files written under the reports directory.
    ``findings`` are the hardening and security check findings, ``reviews``
    the capability reviews.
    """

    success: bool = False
    findings: List[Dict[str, Any]] = field(default_factory=list)
    reviews: List[Dict[str, Any]] = field(default_factory=list)
    files: List[str] = field(default_factory=list)
    command_output: Optional[str] = None


def run_blint_reviews(
    src_dirs: List[str], reports_dir: str, deep: bool = False
) -> BlintReviewResult:
    """Run blint's security checks and capability reviews and keep the reports.

    The SBOM mode of blint produces no findings: ``no_reviews`` and the
    reports directory only matter to the review mode, which is what the
    ``blint`` command runs by default. This runs that mode over the same
    paths without printing its tables and writes ``findings.json``,
    ``reviews.json`` and ``analysis-coverage.json`` into ``reports_dir``.
    The per-binary metadata files blint can export are not written; the SBOM
    already carries that information.

    A failure never raises: it is returned as ``success=False`` with the
    reason, so a review problem cannot take the SBOM down with it.
    """
    if not BLINT_AVAILABLE:
        return BlintReviewResult(
            success=False, command_output="blint is not installed; no review was run."
        )
    try:
        options = BlintOptions(
            deep_mode=deep,
            no_error=True,
            no_reviews=False,
            quiet_mode=True,
            src_dir_image=list(src_dirs),
            stdout_mode=False,
            reports_dir=reports_dir,
        )
        exe_files = gen_file_list(options.src_dir_image)
        macos_bundles: List[str] = []
        for src in options.src_dir_image:
            macos_bundles += find_macos_bundles(src) or []
            exe_files += [f for f in (find_clickonce_files(src) or []) if f not in exe_files]
        exe_files = [f for f in exe_files if not path_inside_any_bundle(f, macos_bundles)]
        exe_files += macos_bundles
        runner = AnalysisRunner(export_artifacts=False, progress_disabled=True)
        findings, reviews, _fuzzables, _callgraphs = runner.start(options, exe_files)
        header = {
            "scan_id": os.environ.get("SCAN_ID", str(uuid.uuid4())),
            "created": f"{datetime.datetime.now(datetime.timezone.utc):%Y-%m-%d %H:%M:%S%z}",
        }
        files = []
        os.makedirs(reports_dir, exist_ok=True)
        # A reports directory reused by an earlier scan can hold reports from
        # it; only this run's reports may stay.
        for stale in (BLINT_FINDINGS_FILE, BLINT_REVIEWS_FILE):
            with contextlib.suppress(OSError):
                os.remove(os.path.join(reports_dir, stale))
        export_metadata(reports_dir, {**header, **runner.analysis_coverage()}, "Analysis-Coverage")
        files.append(BLINT_COVERAGE_FILE)
        if findings:
            export_metadata(reports_dir, {**header, "findings": findings}, "Findings")
            files.append(BLINT_FINDINGS_FILE)
        if reviews:
            export_metadata(reports_dir, {**header, "reviews": reviews}, "Reviews")
            files.append(BLINT_REVIEWS_FILE)
    except Exception as e:  # blint is best effort; see the docstring
        return BlintReviewResult(success=False, command_output=f"blint review failed: {e}")
    return BlintReviewResult(success=True, findings=findings, reviews=reviews, files=files)


class BlintGenerator(XBOMGenerator):
    """
    Generate xBOM using blint
    """

    def generate(self) -> BOMResult:
        """
        Generate the BOM using blint.
        """
        if not BLINT_AVAILABLE:
            return BOMResult(
                success=False,
                command_output="The required packages for binary SBOM generation are not available. Reinstall depscan using `pip install owasp-depscan[all]`.",
            )
        src_dir = self.source_dir
        bom_file = self.bom_file
        temp_reports_dir = tempfile.mkdtemp(
            prefix="blint-reports-",
            dir=os.getenv("DEPSCAN_TEMP_DIR")
            or os.getenv("RUNNER_TEMP")
            or os.getenv("AGENT_TEMPDIRECTORY"),
        )
        os.environ["BLINT_TEMP_DIR"] = temp_reports_dir
        project_type_list = self.options.get("project_type") or []
        blint_options = BlintOptions(
            deep_mode=self.options.get("deep", True),
            sbom_mode=True,
            db_mode=os.getenv("USE_BLINTDB", "") in ("true", "1"),
            no_reviews=True,
            no_error=True,
            quiet_mode=True,
            src_dir_image=src_dir.split(","),
            stdout_mode=False,
            reports_dir=temp_reports_dir,
            use_blintdb=self.options.get("use_blintdb", False),
            image_url=self.options.get("blintdb_image_url", BLINTDB_IMAGE_URL),
            sbom_output=bom_file,
        )
        blintdb_setup(blint_options)
        sbom = run_sbom_mode(blint_options)
        shutil.rmtree(temp_reports_dir, ignore_errors=True)
        review_dir = self.options.get("blint_reviews_dir")
        if review_dir:
            review = run_blint_reviews(
                src_dir.split(","), review_dir, deep=bool(self.options.get("deep", True))
            )
            if not review.success:
                if self.logger:
                    self.logger.warning(review.command_output)
                if self.options.get("fail_on_error"):
                    return BOMResult(
                        success=False, bom_obj=sbom, command_output=review.command_output
                    )
        return BOMResult(success=True, bom_obj=sbom)
