"""blint's security review: when it runs and where its reports are kept.

How the review's check findings reach ``depscan.findings.json`` through the
blint adapter's records needs no blint installed and is tested in
``test_scan_directory.py``."""

import dataclasses
import json
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
    beside the BOM, absolute source paths and the deep setting, and reports
    success by writing nothing."""
    seen: dict[str, object] = {}

    def fake_run(src_dirs, reports_dir, deep=False):
        seen["src_dirs"] = list(src_dirs)
        seen["reports_dir"] = reports_dir
        seen["deep"] = deep
        return blint_mod.BlintReviewResult(success=True, files=[])

    monkeypatch.setattr(blint_mod, "run_blint_reviews", fake_run)
    bom_file = tmp_path / "reports" / "sbom-universal.cdx.json"
    reasons = bom_mod._run_blint_review(str(bom_file), "src,dist", {"deep": True})
    assert reasons == []
    assert seen["reports_dir"] == str(tmp_path / "reports" / "analysis" / "blint")
    assert seen["src_dirs"] == ["src", "dist"]
    assert seen["deep"] is True


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


class _FakeRunner:
    def __init__(self, **kwargs):
        pass

    def start(self, options, exe_files):
        finding = {"id": "CHECK_NX", "title": "NX", "severity": "high", "filename": "/s/app"}
        return [finding], [{"id": "ENVIRONMENT_ACCESS"}], [], []

    def analysis_coverage(self):
        return {"units": {"attempted": 1, "succeeded": 1, "failed": 0, "skipped": 0}}


def test_review_writes_findings_and_reviews_and_drops_stale_reports(monkeypatch, tmp_path):
    monkeypatch.setattr(blint_mod, "AnalysisRunner", _FakeRunner)
    reports = tmp_path / "analysis" / "blint"
    reports.mkdir(parents=True)
    (reports / blint_mod.BLINT_FINDINGS_FILE).write_text('{"findings": [{"id": "OLD"}]}')
    result = blint_mod.run_blint_reviews([str(tmp_path)], str(reports))
    assert result.success
    document = json.loads((reports / blint_mod.BLINT_FINDINGS_FILE).read_text())
    assert [f["id"] for f in document["findings"]] == ["CHECK_NX"]
    assert (reports / blint_mod.BLINT_REVIEWS_FILE).is_file()


def test_a_relative_review_path_is_walked_as_an_absolute_one(monkeypatch, tmp_path):
    """blint names each binary by the path it walked. A relative source
    directory is made absolute before the review starts, so the reports
    name files under the scan root rather than relative to the working
    directory, and the finding ids of a relative ``-i`` equal those of an
    absolute one."""
    seen = {}

    class Recording(_FakeRunner):
        def start(self, options, exe_files):
            seen["dirs"] = list(options.src_dir_image)
            return super().start(options, exe_files)

    monkeypatch.setattr(blint_mod, "AnalysisRunner", Recording)
    (tmp_path / "bins").mkdir()
    monkeypatch.chdir(tmp_path)
    result = blint_mod.run_blint_reviews(["bins"], str(tmp_path / "r"))
    assert result.success
    assert seen["dirs"] == [str(tmp_path / "bins")]


def test_review_failure_is_returned_not_raised(monkeypatch, tmp_path):
    class Broken(_FakeRunner):
        def start(self, options, exe_files):
            raise RuntimeError("boom")

    monkeypatch.setattr(blint_mod, "AnalysisRunner", Broken)
    result = blint_mod.run_blint_reviews([str(tmp_path)], str(tmp_path / "r"))
    assert result.success is False and "boom" in (result.command_output or "")


@dataclasses.dataclass
class _OptionsWithoutExclude:
    src_dir_image: list
    deep_mode: bool = False
    no_error: bool = False
    no_reviews: bool = False
    quiet_mode: bool = False
    stdout_mode: bool = False
    reports_dir: str = ""
    sbom_mode: bool = False
    db_mode: bool = False
    use_blintdb: bool = False
    image_url: str = ""
    sbom_output: str = ""


@dataclasses.dataclass
class _OptionsWithExcludeField(_OptionsWithoutExclude):
    exclude: list = dataclasses.field(default_factory=list)


def _generator_run(monkeypatch, tmp_path, options_class, options):
    seen = {}

    def fake_sbom(blint_options):
        seen["options"] = blint_options
        return "sbom"

    monkeypatch.setattr(blint_mod, "BlintOptions", options_class)
    monkeypatch.setattr(blint_mod, "run_sbom_mode", fake_sbom)
    monkeypatch.setattr(blint_mod, "blintdb_setup", lambda options: None)
    generator = blint_mod.BlintGenerator(
        str(tmp_path), str(tmp_path / "bom.json"), options=options
    )
    assert generator.generate().success
    return seen["options"]


def test_the_generator_takes_the_target_list_and_the_patterns(monkeypatch, tmp_path):
    options = {"blint_targets": ["/a,b", "/c"], "exclude_patterns": ["test/**"]}
    seen = _generator_run(monkeypatch, tmp_path, _OptionsWithExcludeField, options)
    assert seen.src_dir_image == ["/a,b", "/c"], "a comma in a path survives"
    assert seen.exclude == ["test/**"]


def test_the_generator_without_a_target_list_splits_the_source_directory(monkeypatch, tmp_path):
    seen = _generator_run(monkeypatch, tmp_path, _OptionsWithExcludeField, {})
    assert seen.src_dir_image == [str(tmp_path)]
    assert seen.exclude == []


def test_the_generator_passes_no_exclude_to_a_blint_without_the_field(monkeypatch, tmp_path):
    options = {"blint_targets": ["/c"], "exclude_patterns": ["test/**"]}
    seen = _generator_run(monkeypatch, tmp_path, _OptionsWithoutExclude, options)
    assert not hasattr(seen, "exclude")


@pytest.mark.parametrize("takes_exclude", [True, False])
def test_a_review_hands_the_patterns_to_the_blint_walks_that_take_them(
    monkeypatch, tmp_path, takes_exclude
):
    calls = {}

    if takes_exclude:

        def lister(src, exclude=None):
            calls.setdefault("gen_file_list", exclude)
            return []

        def bundles(src, exclude=None):
            calls["bundles"] = exclude
            return []

        def clickonce(src, exclude=None):
            calls["clickonce"] = exclude
            return []

    else:

        def lister(src):
            calls["gen_file_list"] = "no parameter"
            return []

        def bundles(src):
            calls["bundles"] = "no parameter"
            return []

        def clickonce(src):
            calls["clickonce"] = "no parameter"
            return []

    monkeypatch.setattr(blint_mod, "gen_file_list", lister)
    monkeypatch.setattr(blint_mod, "find_macos_bundles", bundles)
    monkeypatch.setattr(blint_mod, "find_clickonce_files", clickonce)
    monkeypatch.setattr(blint_mod, "AnalysisRunner", _FakeRunner)
    result = blint_mod.run_blint_reviews([str(tmp_path)], str(tmp_path / "r"), exclude=["test/**"])
    assert result.success
    expected = ["test/**"] if takes_exclude else "no parameter"
    assert calls == {"gen_file_list": expected, "bundles": expected, "clickonce": expected}


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

    def boom(*a, **k):
        raise RuntimeError("runner failed")

    monkeypatch.setattr(blint_mod, "AnalysisRunner", boom)
    result = blint_mod.run_blint_reviews([str(tmp_path)], str(reports))
    assert result.success is False
    assert [n for n in names if (reports / n).exists()] == []
