"""Tests for the kosi report -> atom reachables-slice converter.

The fixtures under ``tests/data/kosi`` are real reports produced by the kosi
4.3.1 plugin on a two-file Kotlin sample that reads a line from stdin, passes
it to ``okhttp3.Request.Builder.url`` and to ``Runtime.exec``. The resolved
report carries two dataflow slices and call-graph reachability; the syntax
report carries usages and imports only.
"""

import json
from pathlib import Path

import pytest

from analysis_lib import ReachabilityAnalysisKV
from analysis_lib.kosi_slices import (
    attribute_name,
    build_bom_purl_index,
    convert_kosi_report,
    is_kosi_report,
    write_slices_file,
)
from analysis_lib.reachability import FrameworkReachability

DATA = Path(__file__).parent / "data" / "kosi"
OKHTTP = "pkg:maven/com.squareup.okhttp3/okhttp@4.12.0?type=jar"
UNUSED = "pkg:maven/org.apache.commons/commons-lang3@3.14.0?type=jar"
ROOT = "pkg:generic/kt2@unspecified"


def _report(name):
    return json.loads((DATA / name).read_text(encoding="utf-8"))


@pytest.fixture
def bom_index():
    components = [
        {"name": "okhttp", "version": "4.12.0", "purl": OKHTTP},
        {"name": "commons-lang3", "version": "3.14.0", "purl": UNUSED},
        {"name": "other", "purl": "pkg:npm/left-pad@1.0.0"},
    ]
    return build_bom_purl_index(components, extra_components=[{"purl": ROOT}])


def _reached(flows):
    return {p for f in flows for p in f["purls"]}


def test_is_kosi_report_by_shape():
    assert is_kosi_report(_report("kosi-resolved-report.json"))
    assert is_kosi_report(_report("kosi-syntax-report.json"))
    assert not is_kosi_report({"schemaVersion": "kosi/1"})
    assert not is_kosi_report({"tool": {"name": "x"}, "schemaVersion": "0.1"})
    assert not is_kosi_report([])


def test_index_holds_only_maven_components_and_the_root(bom_index):
    assert OKHTTP in bom_index
    assert "pkg:maven/com.squareup.okhttp3/okhttp" in bom_index
    assert ROOT in bom_index
    assert not any("left-pad" in k for k in bom_index)


def test_attribute_name_by_coordinates(bom_index):
    assert attribute_name("okhttp3.Request.Builder.url", bom_index) == {OKHTTP}
    assert attribute_name("com.squareup.okhttp3.OkHttpClient", bom_index) == {OKHTTP}
    assert attribute_name("org.apache.commons.lang3.StringUtils.trim", bom_index) == {UNUSED}


@pytest.mark.parametrize(
    "name", ["java.lang.Runtime.exec", "kotlin.io.readLine", "demo.fetch", ""]
)
def test_attribute_name_never_claims_runtime_or_unknown_packages(bom_index, name):
    assert attribute_name(name, bom_index) == set()


def test_resolved_report_emits_dataflow_flow_with_frames(bom_index):
    flows = convert_kosi_report(_report("kosi-resolved-report.json"), bom_index)
    slice_flows = [f for f in flows if any(n.get("frameRole") for n in f["flows"])]
    # the Runtime.exec slice names no dependency, only the workspace root
    assert sorted(f["purls"] for f in slice_flows) == [[ROOT], [ROOT, OKHTTP]]
    flow = next(f for f in slice_flows if OKHTTP in f["purls"])
    assert [n["frameRole"] for n in flow["flows"]][0] == "source"
    assert flow["flows"][-1]["frameRole"] == "sink"
    assert flow["flows"][-1]["code"] == "okhttp3.Request.Builder.url"
    assert OKHTTP in flow["flows"][-1]["tags"]
    assert flow["flows"][-1]["lineNumber"] == 14
    assert flow["flows"][-1]["isExternal"] is True


def test_slice_frames_carry_root_reachability(bom_index):
    flows = convert_kosi_report(_report("kosi-resolved-report.json"), bom_index)
    flow = next(f for f in flows if OKHTTP in f["purls"] and f["flows"][-1].get("frameRole"))
    by_function = {n["fullName"]: n for n in flow["flows"]}
    main = by_function["demo.main"]
    assert main["reachableFromRoots"] is True
    assert main["minDepth"] == 0
    assert main["rootScopes"] == ["main"]
    assert "rootIds" not in main
    assert by_function["demo.fetch"]["minDepth"] == 1


def test_syntax_report_attributes_usages_by_coordinates(bom_index):
    """The syntax tier resolves no import purls, so attribution rests on the
    package prefix of the import joined to the usage name."""
    flows = convert_kosi_report(_report("kosi-syntax-report.json"), bom_index)
    assert _reached(flows) == {OKHTTP}
    codes = {f["flows"][-1]["code"] for f in flows}
    assert "okhttp3.Request.Builder.url" in codes
    assert "okhttp3.OkHttpClient" in codes


def test_unused_dependency_is_not_reached(bom_index):
    for name in ("kosi-resolved-report.json", "kosi-syntax-report.json"):
        assert UNUSED not in _reached(convert_kosi_report(_report(name), bom_index))


def test_resolved_import_purl_wins_over_the_name_heuristic():
    report = _report("kosi-resolved-report.json")
    other = "pkg:maven/example.fork/okhttp-fork@1.0.0"
    for imp in report["imports"]:
        imp["purl"] = other
    index = build_bom_purl_index(
        [{"purl": OKHTTP}, {"purl": other}], extra_components=[{"purl": ROOT}]
    )
    usage_flows = [
        f
        for f in convert_kosi_report(report, index)
        if f["flows"][-1]["id"].startswith("kosi-usage-")
    ]
    assert usage_flows
    assert all(f["purls"] == [other] for f in usage_flows)


def test_empty_or_unattributable_report_yields_no_flows(bom_index):
    assert convert_kosi_report({}, bom_index) == []
    assert convert_kosi_report(None, bom_index) == []  # type: ignore[arg-type]
    assert convert_kosi_report(_report("kosi-syntax-report.json"), {}) == []


def test_conversion_is_deterministic(bom_index, tmp_path):
    report = _report("kosi-resolved-report.json")
    first, second = tmp_path / "a.json", tmp_path / "b.json"
    write_slices_file(str(first), convert_kosi_report(report, bom_index))
    write_slices_file(str(second), convert_kosi_report(report, bom_index))
    assert first.read_bytes() == second.read_bytes()


def test_slice_feeds_framework_reachability(tmp_path, bom_index):
    """The written slice file, read by the unchanged engine, marks okhttp as
    reached and leaves the unused dependency out."""
    flows = convert_kosi_report(_report("kosi-resolved-report.json"), bom_index)
    write_slices_file(str(tmp_path / "kosi-reachables.slices.json"), flows)
    (tmp_path / "bom.cdx.json").write_text(
        json.dumps(
            {"components": [{"name": "okhttp", "purl": OKHTTP}, {"name": "x", "purl": UNUSED}]}
        ),
        encoding="utf-8",
    )
    opts = ReachabilityAnalysisKV(
        project_types=["kotlin"], src_dir=str(tmp_path), bom_dir=str(tmp_path)
    )
    res = FrameworkReachability(opts).process()
    assert res.success
    reached = set((res.reached_purls or {}).keys())
    assert OKHTTP in reached
    assert UNUSED not in reached


COROUTINES = "pkg:maven/org.jetbrains.kotlinx/kotlinx-coroutines-core@1.8.0?type=jar"
SERIALIZATION = "pkg:maven/org.jetbrains.kotlinx/kotlinx-serialization-json@1.6.0?type=jar"
OKHTTP_LOGGING = "pkg:maven/com.squareup.okhttp3/logging-interceptor@4.12.0?type=jar"


def _usage_report(imports, usages):
    return {
        "schemaVersion": "kosi/1",
        "tool": {"name": "kosi"},
        "imports": [dict(i, filePath="A.kt") for i in imports],
        "usages": [dict(u, filePath="A.kt", position={"line": 3, "column": 1}) for u in usages],
    }


def test_star_import_does_not_attribute_a_local_function():
    index = build_bom_purl_index(
        [{"purl": COROUTINES}, {"purl": SERIALIZATION}], extra_components=[]
    )
    report = _usage_report(
        [{"name": "kotlinx.coroutines", "star": True}], [{"name": "doLocalWork"}]
    )
    assert convert_kosi_report(report, index) == []


def test_star_import_reaches_nothing_even_for_a_single_artifact():
    index = build_bom_purl_index([{"purl": COROUTINES}], extra_components=[])
    report = _usage_report([{"name": "kotlinx.coroutines", "star": True}], [{"name": "launch"}])
    assert convert_kosi_report(report, index) == []


def test_import_that_ties_two_artifacts_of_a_group_attributes_none():
    two = build_bom_purl_index([{"purl": OKHTTP}, {"purl": OKHTTP_LOGGING}])
    report = _usage_report([{"name": "okhttp3.Request"}], [{"name": "Request.Builder"}])
    assert convert_kosi_report(report, two) == []
    assert attribute_name("okhttp3.Request", two) == set()
    one = build_bom_purl_index([{"purl": OKHTTP}])
    assert _reached(convert_kosi_report(report, one)) == {OKHTTP}


def test_kotlinx_import_does_not_tie_unrelated_artifacts_of_the_group():
    index = build_bom_purl_index([{"purl": COROUTINES}, {"purl": SERIALIZATION}])
    report = _usage_report([{"name": "kotlinx.coroutines.launch"}], [{"name": "launch"}])
    assert convert_kosi_report(report, index) == []
