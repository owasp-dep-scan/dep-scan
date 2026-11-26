"""blint's security review: when it runs and where its reports are kept.

How the review's check findings reach ``depscan.findings.json`` through the
blint adapter's records needs no blint installed and is tested in
``test_scan_directory.py``."""

import json
import logging
import os
import shutil
import sys
from types import SimpleNamespace

import pytest

from depscan.lib import bom as bom_mod
from depscan.lib import scan_directory
from xbom_lib import blint as blint_mod

pytestmark = pytest.mark.skipif(not blint_mod.BLINT_AVAILABLE, reason="blint is not installed")


@pytest.mark.parametrize(
    "options, expected",
    [
        ({}, False),
        (None, False),
        ({"techniques": ["binary-analysis"]}, True),
        ({"project_type": ["binary"]}, True),
        ({"project_type": ["apk"]}, True),
        ({"bom_engine": "BlintGenerator"}, True),
        # the post-build BOM of a lifecycle scan is not a binary review
        ({"lifecycles": ["post-build"]}, False),
        ({"project_type": ["java"], "techniques": ["source-code-analysis"]}, False),
    ],
)
def test_blint_reviews_requested(options, expected):
    assert bom_mod.blint_reviews_requested(options) is expected


class _StubGenerator:
    seen_options: dict = {}

    def __init__(self, src_dir, bom_file, logger=None, options=None):
        type(self).seen_options = options or {}
        self.bom_file = bom_file

    def generate(self):
        with open(self.bom_file, "w", encoding="utf-8") as fp:
            fp.write("{}")
        return SimpleNamespace(success=True)


def test_the_review_step_keeps_its_reports_under_analysis_blint(monkeypatch, tmp_path):
    """dep-scan's own review step hands blint the analysis/blint directory
    beside the BOM and the source paths, and reports success by writing
    nothing."""
    seen: dict[str, object] = {}

    def fake_run(src_dirs, reports_dir, exclude=()):
        seen["src_dirs"] = list(src_dirs)
        seen["reports_dir"] = reports_dir
        return blint_mod.BlintReviewResult(success=True, files=[])

    monkeypatch.setattr(blint_mod, "run_blint_reviews", fake_run)
    bom_file = tmp_path / "reports" / "sbom-universal.cdx.json"
    reasons = bom_mod._run_blint_review(str(bom_file), "src,dist", {"deep": True})
    assert reasons == []
    assert seen["reports_dir"] == str(tmp_path / "reports" / "analysis" / "blint")
    assert seen["src_dirs"] == ["src", "dist"]


def test_the_review_step_returns_the_failure_reason(monkeypatch, tmp_path):
    """A failed review hands its reason back for the manifest to record."""
    monkeypatch.setattr(
        blint_mod,
        "run_blint_reviews",
        lambda *a, **k: blint_mod.BlintReviewResult(
            success=False, command_output="blint review failed: [Errno 2] boom"
        ),
    )
    reasons = bom_mod._run_blint_review(str(tmp_path / "sbom.cdx.json"), str(tmp_path), {})
    assert reasons == ["blint review failed: [Errno 2] boom"]


def _copy_binary(tmp_path):
    source = os.path.realpath(sys.executable)
    target = tmp_path / "bins" / os.path.basename(source)
    target.parent.mkdir()
    shutil.copy(source, target)
    return target.parent


def test_real_review_keeps_reports_and_the_manifest_lists_them(tmp_path):
    reports = tmp_path / "reports" / "analysis" / "blint"
    result = blint_mod.run_blint_reviews([str(_copy_binary(tmp_path))], str(reports))
    assert result.success, result.command_output
    assert blint_mod.BLINT_COVERAGE_FILE in result.files
    coverage = json.loads((reports / blint_mod.BLINT_COVERAGE_FILE).read_text())
    assert coverage["units"]["attempted"] == 1
    entry = scan_directory.classify_file(f"analysis/blint/{blint_mod.BLINT_COVERAGE_FILE}")
    assert entry["role"] == "raw-report" and entry["producer"] == "blint"
    listed = {e["path"] for e in scan_directory.walk_files(str(tmp_path / "reports"))}
    assert f"analysis/blint/{blint_mod.BLINT_COVERAGE_FILE}" in listed


def test_real_review_leaves_an_excluded_tree_out(tmp_path):
    """The patterns reach blint's own walk: the review attempts only the
    binary outside the excluded tree."""
    source = os.path.realpath(sys.executable)
    for tree in ("kept", "test"):
        (tmp_path / "src" / tree).mkdir(parents=True)
        shutil.copy(source, tmp_path / "src" / tree / os.path.basename(source))
    reports = tmp_path / "reports"
    result = blint_mod.run_blint_reviews(
        [str(tmp_path / "src")], str(reports), exclude=["test/**"]
    )
    assert result.success, result.command_output
    coverage = json.loads((reports / blint_mod.BLINT_COVERAGE_FILE).read_text())
    assert coverage["units"]["attempted"] == 1


def test_real_generator_writes_the_sbom(tmp_path):
    bom_file = tmp_path / "bom.json"
    result = blint_mod.BlintGenerator(
        str(_copy_binary(tmp_path)), str(bom_file), options={"use_blintdb": False}
    ).generate()
    assert result.success, result.command_output
    document = json.loads(bom_file.read_text())
    assert document["bomFormat"] == "CycloneDX"
    assert result.bom_obj is not None
    assert result.bom_obj["serialNumber"] == document["serialNumber"]


_COVERAGE = {"units": {"attempted": 1, "succeeded": 1, "failed": 0, "skipped": 0}}


def _batch(findings=(), reviews=(), unmatched=()):
    from blint.api import AnalysisResult, BatchAnalysisResult

    unit = AnalysisResult(metadata={}, findings=list(findings), reviews=list(reviews))
    return BatchAnalysisResult(results=[unit], coverage=dict(_COVERAGE), unmatched=list(unmatched))


def _fake_analyze_many(seen=None, batch=None, error=None):
    def fake(paths, **kwargs):
        if seen is not None:
            seen["paths"] = list(paths)
            seen.update(kwargs)
        if error:
            raise error
        return batch if batch is not None else _batch()

    return fake


def test_review_writes_findings_and_reviews_and_drops_stale_reports(monkeypatch, tmp_path):
    finding = {"id": "CHECK_NX", "title": "NX", "severity": "high", "filename": "/s/app"}
    batch = _batch(findings=[finding], reviews=[{"id": "ENVIRONMENT_ACCESS"}])
    monkeypatch.setattr(blint_mod, "analyze_many", _fake_analyze_many(batch=batch))
    reports = tmp_path / "analysis" / "blint"
    reports.mkdir(parents=True)
    (reports / blint_mod.BLINT_FINDINGS_FILE).write_text('{"findings": [{"id": "OLD"}]}')
    result = blint_mod.run_blint_reviews([str(tmp_path)], str(reports))
    assert result.success
    document = json.loads((reports / blint_mod.BLINT_FINDINGS_FILE).read_text())
    assert [f["id"] for f in document["findings"]] == ["CHECK_NX"]
    reviews = json.loads((reports / blint_mod.BLINT_REVIEWS_FILE).read_text())
    assert [r["id"] for r in reviews["reviews"]] == ["ENVIRONMENT_ACCESS"]
    coverage = json.loads((reports / blint_mod.BLINT_COVERAGE_FILE).read_text())
    assert coverage["units"] == _COVERAGE["units"]
    assert {"scan_id", "created"} <= set(coverage)
    assert "unmatched" not in coverage


def test_a_clean_review_writes_only_the_coverage_report(monkeypatch, tmp_path):
    monkeypatch.setattr(blint_mod, "analyze_many", _fake_analyze_many())
    reports = tmp_path / "r"
    result = blint_mod.run_blint_reviews([str(tmp_path)], str(reports))
    assert result.success and result.files == [blint_mod.BLINT_COVERAGE_FILE]
    assert sorted(os.listdir(reports)) == [blint_mod.BLINT_COVERAGE_FILE]


def test_records_blint_could_not_attribute_are_kept_in_the_coverage_report(
    monkeypatch, tmp_path
):
    stray = {"id": "CHECK_PIE", "filename": "/elsewhere"}
    monkeypatch.setattr(
        blint_mod, "analyze_many", _fake_analyze_many(batch=_batch(unmatched=[stray]))
    )
    reports = tmp_path / "r"
    assert blint_mod.run_blint_reviews([str(tmp_path)], str(reports)).success
    coverage = json.loads((reports / blint_mod.BLINT_COVERAGE_FILE).read_text())
    assert coverage["unmatched"] == [stray]


def test_a_relative_review_path_is_walked_as_an_absolute_one(monkeypatch, tmp_path):
    """blint names each binary by the path it walked. A relative source
    directory is made absolute before the review starts, so the reports
    name files under the scan root rather than relative to the working
    directory, and the finding ids of a relative ``-i`` equal those of an
    absolute one."""
    seen = {}
    monkeypatch.setattr(blint_mod, "analyze_many", _fake_analyze_many(seen))
    (tmp_path / "bins").mkdir()
    monkeypatch.chdir(tmp_path)
    result = blint_mod.run_blint_reviews(["bins"], str(tmp_path / "r"))
    assert result.success
    assert seen["paths"] == [str(tmp_path / "bins")]


def test_a_review_hands_the_patterns_to_blint(monkeypatch, tmp_path):
    seen = {}
    monkeypatch.setattr(blint_mod, "analyze_many", _fake_analyze_many(seen))
    result = blint_mod.run_blint_reviews([str(tmp_path)], str(tmp_path / "r"), exclude=["test/**"])
    assert result.success
    assert seen["exclude"] == ["test/**"] and seen["quiet"] is True


def test_review_failure_is_returned_not_raised(monkeypatch, tmp_path):
    monkeypatch.setattr(
        blint_mod, "analyze_many", _fake_analyze_many(error=RuntimeError("boom"))
    )
    result = blint_mod.run_blint_reviews([str(tmp_path)], str(tmp_path / "r"))
    assert result.success is False and "boom" in (result.command_output or "")


def test_reviews_remove_the_reports_of_an_earlier_scan_before_they_start(tmp_path, monkeypatch):
    reports = tmp_path / "reports"
    reports.mkdir()
    names = (
        blint_mod.BLINT_FINDINGS_FILE,
        blint_mod.BLINT_REVIEWS_FILE,
        blint_mod.BLINT_COVERAGE_FILE,
    )
    for name in names:
        (reports / name).write_text("{}")
    monkeypatch.setattr(
        blint_mod, "analyze_many", _fake_analyze_many(error=RuntimeError("runner failed"))
    )
    result = blint_mod.run_blint_reviews([str(tmp_path)], str(reports))
    assert result.success is False
    assert [n for n in names if (reports / n).exists()] == []


def _fake_sbom(calls, fail_with_blintdb=False, bom=None, notes=None):
    from blint.api import BlintdbUnavailableError, SbomResult

    def fake(paths, **kwargs):
        calls.append({"paths": list(paths), **kwargs})
        if fail_with_blintdb and kwargs.get("use_blintdb"):
            raise BlintdbUnavailableError("no blint.db layer")
        if notes is not None:
            return SbomResult(bom=None, coverage={"notes": notes})
        return SbomResult(bom=bom or {"bomFormat": "CycloneDX"}, coverage={})

    return fake


class _RecordingLogger(logging.Logger):
    """A logger that keeps the warning messages it is given."""

    def __init__(self, name):
        super().__init__(name)
        self.warnings: list = []

    def warning(self, msg, *args, **kwargs):
        self.warnings.append(msg % args)


def _generate(monkeypatch, tmp_path, options, **fake_kwargs):
    calls: list = []
    monkeypatch.setattr(blint_mod, "sbom", _fake_sbom(calls, **fake_kwargs))
    logger = _RecordingLogger("test-blint")
    generator = blint_mod.BlintGenerator(
        str(tmp_path), str(tmp_path / "bom.json"), logger=logger, options=options
    )
    return generator.generate(), calls, logger.warnings


def test_the_generator_takes_the_target_list_and_the_patterns(monkeypatch, tmp_path):
    options = {"blint_targets": ["/a,b", "/c"], "exclude_patterns": ["test/**"]}
    result, calls, _ = _generate(monkeypatch, tmp_path, options)
    assert result.success and result.bom_obj == {"bomFormat": "CycloneDX"}
    (call,) = calls
    assert call["paths"] == ["/a,b", "/c"], "a comma in a path survives"
    assert call["exclude"] == ["test/**"]
    assert call["output_file"] == str(tmp_path / "bom.json")
    assert call["deep"] is True and call["quiet"] is True


def test_the_generator_without_a_target_list_splits_the_source_directory(monkeypatch, tmp_path):
    _, calls, _ = _generate(monkeypatch, tmp_path, {"deep": False})
    assert calls[0]["paths"] == [str(tmp_path)]
    assert calls[0]["exclude"] == [] and calls[0]["deep"] is False


def test_the_generator_restores_blint_temp_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("BLINT_TEMP_DIR", "/kept")
    seen = {}

    def fake(paths, **kwargs):
        from blint.api import SbomResult

        seen["during"] = os.environ["BLINT_TEMP_DIR"]
        assert os.path.isdir(seen["during"])
        return SbomResult(bom={}, coverage={})

    monkeypatch.setattr(blint_mod, "sbom", fake)
    assert blint_mod.BlintGenerator(str(tmp_path), str(tmp_path / "b.json")).generate().success
    assert seen["during"] != "/kept" and not os.path.exists(seen["during"])
    assert os.environ["BLINT_TEMP_DIR"] == "/kept"


@pytest.mark.parametrize(
    "env, options, expected",
    [
        (None, {}, False),
        ("true", {}, True),
        ("1", {}, True),
        ("TRUE", {}, True),
        ("false", {}, False),
        ("0", {}, False),
        # the post-build lifecycle BOM asks for no database whatever the env says
        ("true", {"use_blintdb": False}, False),
        (None, {"use_blintdb": True}, True),
    ],
)
def test_blintdb_is_used_only_when_asked_for(monkeypatch, tmp_path, env, options, expected):
    if env is None:
        monkeypatch.delenv("USE_BLINTDB", raising=False)
    else:
        monkeypatch.setenv("USE_BLINTDB", env)
    _, calls, _ = _generate(monkeypatch, tmp_path, options)
    assert calls[0]["use_blintdb"] is expected


def test_an_unavailable_blintdb_falls_back_to_an_sbom_without_it(monkeypatch, tmp_path):
    result, calls, warnings = _generate(
        monkeypatch, tmp_path, {"use_blintdb": True}, fail_with_blintdb=True
    )
    assert result.success
    assert [c["use_blintdb"] for c in calls] == [True, False]
    assert len(warnings) == 1 and "no blint.db layer" in warnings[0]


def test_a_generator_failure_is_returned_not_raised(monkeypatch, tmp_path):
    from blint.api import AnalysisFailedError

    def broken(paths, **kwargs):
        raise AnalysisFailedError("SBOM generation failed: ValueError: bad unit")

    monkeypatch.setattr(blint_mod, "sbom", broken)
    result = blint_mod.BlintGenerator(str(tmp_path), str(tmp_path / "b.json")).generate()
    assert result.success is False and "bad unit" in (result.command_output or "")


def test_nothing_to_inventory_is_a_failure_with_blints_reason(monkeypatch, tmp_path):
    result, _, _ = _generate(
        monkeypatch, tmp_path, {}, notes=["no analyzable inputs were discovered"]
    )
    assert result.success is False
    assert result.command_output == "no analyzable inputs were discovered"
