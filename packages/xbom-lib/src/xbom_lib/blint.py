import contextlib
import datetime
import json
import os
import shutil
import tempfile
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from xbom_lib import BOMResult, XBOMGenerator

BLINT_AVAILABLE = False
try:
    # blint's public API only. The engine modules behind it (runners,
    # options, file discovery) are blint's to change between releases.
    from blint.api import BlintApiError, BlintdbUnavailableError, analyze_many, sbom

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


def _write_report(reports_dir: str, name: str, document: Dict[str, Any]) -> None:
    """Write one review report the way blint's CLI names and encodes it."""
    with open(os.path.join(reports_dir, name), "w", encoding="utf-8") as handle:
        json.dump(document, handle, default=str)


def blintdb_requested(options: Dict[str, Any]) -> bool:
    """Whether the binary SBOM should match functions against blintdb.

    blintdb is a download of tens of gigabytes, so it is used only when asked
    for: an explicit ``use_blintdb`` option wins (the post-build lifecycle BOM
    sets it to False), and otherwise ``USE_BLINTDB=true`` (or ``1``) in the
    environment turns it on. blint downloads the database on first use.
    """
    if options.get("use_blintdb") is not None:
        return bool(options["use_blintdb"])
    return os.getenv("USE_BLINTDB", "").strip().lower() in ("true", "1")


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
    src_dirs: List[str],
    reports_dir: str,
    exclude: Sequence[str] = (),
) -> BlintReviewResult:
    """Run blint's security checks and capability reviews and keep the reports.

    The SBOM mode of blint produces no findings; the review mode, which is
    what the ``blint`` command runs by default, does. This runs that mode
    through ``blint.api.analyze_many`` over the same paths, without printing
    anything, and writes ``findings.json``, ``reviews.json`` and
    ``analysis-coverage.json`` into ``reports_dir``. The per-binary metadata
    blint can export is not written; the SBOM already carries it. Findings
    and reviews that blint could not attribute to an analyzed file are kept
    in the coverage report under ``unmatched`` rather than dropped.

    A failure never raises: it is returned as ``success=False`` with the
    reason, so a review problem cannot take the SBOM down with it.

    The paths are made absolute first. blint names each binary by the path
    it walked, so a relative path would leave the reports naming files
    relative to the working directory, which no reader of the reports can
    place under the scan root.

    ``exclude`` lists cdxgen-style globs anchored at each directory in
    ``src_dirs``, applied by blint's own file discovery.
    """
    src_dirs = [os.path.abspath(src) for src in src_dirs]
    # A reports directory reused by an earlier scan can hold reports from it.
    # They go before the review starts, so a review that fails or does not run
    # leaves nothing that reads as this scan's result.
    for stale in (BLINT_FINDINGS_FILE, BLINT_REVIEWS_FILE, BLINT_COVERAGE_FILE):
        with contextlib.suppress(OSError):
            os.remove(os.path.join(reports_dir, stale))
    if not BLINT_AVAILABLE:
        return BlintReviewResult(
            success=False, command_output="blint is not installed; no review was run."
        )
    try:
        batch = analyze_many(src_dirs, exclude=list(exclude), quiet=True)
        findings = [f for unit in batch.results for f in unit.findings]
        reviews = [r for unit in batch.results for r in unit.reviews]
        header = {
            "scan_id": os.environ.get("SCAN_ID", str(uuid.uuid4())),
            "created": f"{datetime.datetime.now(datetime.timezone.utc):%Y-%m-%d %H:%M:%S%z}",
        }
        coverage = {**header, **batch.coverage}
        if batch.unmatched:
            coverage["unmatched"] = batch.unmatched
        files = []
        os.makedirs(reports_dir, exist_ok=True)
        _write_report(reports_dir, BLINT_COVERAGE_FILE, coverage)
        files.append(BLINT_COVERAGE_FILE)
        if findings:
            _write_report(reports_dir, BLINT_FINDINGS_FILE, {**header, "findings": findings})
            files.append(BLINT_FINDINGS_FILE)
        if reviews:
            _write_report(reports_dir, BLINT_REVIEWS_FILE, {**header, "reviews": reviews})
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
        exclude = [str(p) for p in self.options.get("exclude_patterns") or []]
        # dep-scan hands the targets as a list so a path with a comma in it
        # survives; the comma-separated source directory is the older form.
        targets = [str(t) for t in self.options.get("blint_targets") or []] or src_dir.split(",")
        use_blintdb = blintdb_requested(self.options)
        # blint extracts archives under BLINT_TEMP_DIR; the directory is this
        # run's own and goes when the run ends.
        temp_dir = tempfile.mkdtemp(
            prefix="blint-reports-",
            dir=os.getenv("DEPSCAN_TEMP_DIR")
            or os.getenv("RUNNER_TEMP")
            or os.getenv("AGENT_TEMPDIRECTORY"),
        )
        previous_temp_dir = os.environ.get("BLINT_TEMP_DIR")
        os.environ["BLINT_TEMP_DIR"] = temp_dir
        sbom_args: Dict[str, Any] = {
            "deep": self.options.get("deep", True),
            "blintdb_image_url": self.options.get("blintdb_image_url") or None,
            "exclude": exclude,
            "output_file": bom_file,
            "quiet": True,
        }
        try:
            try:
                result = sbom(targets, use_blintdb=use_blintdb, **sbom_args)
            except BlintdbUnavailableError as e:
                # The database is an optional layer: without it the SBOM is
                # still made from the binaries' own symbols and banners, and
                # the log says the layer was missing rather than reading as
                # "no match".
                if self.logger:
                    self.logger.warning(
                        "blintdb could not be downloaded or verified, so the binary "
                        "SBOM was generated without it: %s",
                        e,
                    )
                result = sbom(targets, use_blintdb=False, **sbom_args)
        except (BlintApiError, OSError) as e:
            return BOMResult(success=False, command_output=f"blint SBOM failed: {e}")
        finally:
            if previous_temp_dir is None:
                os.environ.pop("BLINT_TEMP_DIR", None)
            else:
                os.environ["BLINT_TEMP_DIR"] = previous_temp_dir
            shutil.rmtree(temp_dir, ignore_errors=True)
        if result.bom is None:
            notes = "; ".join(result.coverage.get("notes") or []) or "blint produced no SBOM"
            return BOMResult(success=False, command_output=notes)
        return BOMResult(success=True, bom_obj=result.bom)
