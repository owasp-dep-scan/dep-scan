"""The exclusion set and the walks of dep-scan's own that honour it.

The patterns are cdxgen's own: matched against the path relative to the
scanned path, anchored at its root (the proof table lives with the P19
excludes notes: ``test/**`` removes only the root ``test`` tree, ``*/test/**``
only one level down, ``**/test/**`` every depth).
"""

import dataclasses
import json
import os

import pytest

from depscan.lib import bom as bom_mod
from depscan.lib.exclusions import (
    ExclusionSet,
    exclude_patterns_from_args,
    kept_targets,
    project_roots,
)


def _touch(root, *parts):
    path = os.path.join(root, *parts)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("x")
    return path


def test_patterns_are_read_from_the_cdxgen_argument_string():
    args = "--exclude 'test/**' --exclude=docs/** --exclude \"types/**\" --profile research"
    assert exclude_patterns_from_args(args) == ["test/**", "docs/**", "types/**"]
    assert exclude_patterns_from_args(None) == []
    assert exclude_patterns_from_args("") == []
    assert exclude_patterns_from_args("--exclude 'unterminated") == []
    assert exclude_patterns_from_args("--exclude") == []


def test_the_set_reads_the_options_of_a_scan():
    assert ExclusionSet.from_options({"cdxgen_args": "--exclude 'a/**'"}).patterns == ("a/**",)
    assert not ExclusionSet.from_options({})
    assert not ExclusionSet.from_options(None)


@pytest.mark.parametrize(
    "pattern, path, expected",
    [
        ("test/**", "test", True),
        ("test/**", "test/a/b.bin", True),
        ("test/**", "sub/test/a.bin", False),
        ("test/**", "contrib/deep/test/a.bin", False),
        ("**/test/**", "sub/test/a.bin", True),
        ("**/test/**", "contrib/deep/test/a.bin", True),
        ("**/test/**", "test/a.bin", True),
        ("**/test/**", "sub/docs/a.bin", False),
        ("*/test/**", "sub/test/a.bin", True),
        ("*/test/**", "test/a.bin", False),
        ("*/test/**", "contrib/deep/test/a.bin", False),
        ("./test/**", "test/x", True),
        ("test", "test/x", True),
        ("*.nupkg", "a.nupkg", True),
        ("*.nupkg", "dir/a.nupkg", False),
        ("**/*.nupkg", "dir/deep/a.nupkg", True),
        ("test/**", "testing/a", False),
    ],
)
def test_patterns_match_the_way_cdxgen_matches_them(pattern, path, expected):
    assert ExclusionSet.from_patterns([pattern]).excludes(path) is expected


def test_a_path_is_judged_relative_to_the_scan_root_only(tmp_path):
    root = str(tmp_path / "proj")
    excl = ExclusionSet.from_patterns(["test/**"])
    assert excl.excludes_path(root, os.path.join(root, "test", "a.bin"))
    assert not excl.excludes_path(root, os.path.join(root, "src", "test", "a.bin"))
    # A root that itself sits under a directory called test is not excluded.
    nested = str(tmp_path / "test" / "proj")
    assert not excl.excludes_path(nested, os.path.join(nested, "a.bin"))
    # Outside the root, and the root itself, are never excluded.
    assert not excl.excludes_path(root, str(tmp_path / "elsewhere"))
    assert not excl.excludes_path(root, root)


def test_kept_targets_is_the_root_when_nothing_is_excluded(tmp_path):
    _touch(str(tmp_path), "src", "a.bin")
    excl = ExclusionSet.from_patterns(["test/**"])
    assert kept_targets(str(tmp_path), excl) == [str(tmp_path)]
    assert kept_targets(str(tmp_path), ExclusionSet()) == [str(tmp_path)]


def test_kept_targets_covers_what_is_kept_and_nothing_excluded(tmp_path):
    root = str(tmp_path)
    keep_a = _touch(root, "src", "lib", "a.bin")
    keep_b = _touch(root, "bin", "b.bin")
    top = _touch(root, "top.bin")
    _touch(root, "test", "fixtures", "x.nupkg")
    _touch(root, "src", "test", "keep-nested.bin")
    targets = kept_targets(root, ExclusionSet.from_patterns(["test/**"]))
    assert os.path.join(root, "test") not in targets
    assert not any(t.startswith(os.path.join(root, "test") + os.sep) for t in targets)
    # Every kept file is reachable through a target, and no target is the root.
    kept_files = {keep_a, keep_b, top, os.path.join(root, "src", "test", "keep-nested.bin")}
    for file in kept_files:
        assert any(file == t or file.startswith(t + os.sep) for t in targets), file
    assert root not in targets


def test_kept_targets_is_empty_when_everything_is_excluded(tmp_path):
    _touch(str(tmp_path), "test", "a.bin")
    assert kept_targets(str(tmp_path), ExclusionSet.from_patterns(["test/**"])) == []


def test_project_roots_are_the_topmost_kept_directories(tmp_path):
    root = str(tmp_path)
    _touch(root, "go", "go.mod")
    _touch(root, "go", "inner", "go.mod")
    _touch(root, "test", "fixture", "go.mod")
    assert project_roots(root, ExclusionSet(), ("go.mod",)) == [
        os.path.join(root, "go"),
        os.path.join(root, "test", "fixture"),
    ] or sorted(project_roots(root, ExclusionSet(), ("go.mod",))) == sorted(
        [os.path.join(root, "go"), os.path.join(root, "test", "fixture")]
    )
    assert project_roots(root, ExclusionSet.from_patterns(["test/**"]), ("go.mod",)) == [
        os.path.join(root, "go")
    ]
    _touch(root, "go.mod")
    assert project_roots(root, ExclusionSet(), ("go.mod",)) == [root]


# blint ---------------------------------------------------------------------


def test_blint_targets_leave_the_excluded_tree_out(tmp_path):
    root = str(tmp_path)
    _touch(root, "test", "Pkg.1.0.nupkg")
    keep = _touch(root, "bin", "tool.dll")
    options = {"cdxgen_args": "--exclude 'test/**'"}
    targets = bom_mod.blint_targets(root, options)
    assert targets == [os.path.join(root, "bin")]
    assert keep.startswith(targets[0])
    # No patterns, no change: the comma-separated entries come back as given.
    assert bom_mod.blint_targets(f"{root},{keep}", {}) == [root, keep]
    # A single file is not a scanned path and stays.
    assert bom_mod.blint_targets(keep, options) == [keep]


def test_the_blint_review_runs_over_the_filtered_targets(tmp_path, monkeypatch):
    root = str(tmp_path / "src")
    _touch(root, "test", "a.nupkg")
    _touch(root, "bin", "b.dll")
    seen = {}

    def fake_run(src_dirs, reports_dir, deep=False):
        seen["targets"] = list(src_dirs)
        return type("R", (), {"success": True, "command_output": None})()

    import xbom_lib.blint as blint_mod

    monkeypatch.setattr(blint_mod, "run_blint_reviews", fake_run)
    bom_file = str(tmp_path / "out" / "sbom.cdx.json")
    os.makedirs(os.path.dirname(bom_file))
    options = {"cdxgen_args": "--exclude 'test/**'"}
    assert bom_mod._run_blint_review(bom_file, root, options) == []
    assert seen["targets"] == [os.path.join(root, "bin")]


def test_the_exclude_argument_reaches_a_blint_that_accepts_it(tmp_path, monkeypatch):
    root = str(tmp_path / "src")
    _touch(root, "test", "a.nupkg")
    _touch(root, "bin", "b.dll")
    seen = {}

    def fake_run(src_dirs, reports_dir, deep=False, exclude=()):
        seen["exclude"] = list(exclude)
        return type("R", (), {"success": True, "command_output": None})()

    import xbom_lib.blint as blint_mod

    monkeypatch.setattr(blint_mod, "run_blint_reviews", fake_run)
    bom_file = str(tmp_path / "out" / "sbom.cdx.json")
    os.makedirs(os.path.dirname(bom_file))
    bom_mod._run_blint_review(bom_file, root, {"cdxgen_args": "--exclude 'test/**'"})
    assert seen["exclude"] == ["test/**"]


def test_the_blint_bom_inventories_only_the_kept_targets(tmp_path, monkeypatch):
    root = str(tmp_path / "src")
    _touch(root, "test", "a.nupkg")
    _touch(root, "bin", "b.dll")
    seen = {}

    class Stub:
        def __init__(self, src_dir, bom_file, logger=None, options=None):
            seen["src_dir"] = src_dir
            seen["options"] = options
            self.bom_file = bom_file

        def generate(self):
            with open(self.bom_file, "w", encoding="utf-8") as fh:
                json.dump({}, fh)
            return type("R", (), {"success": True})()

    monkeypatch.setattr(bom_mod, "BlintGenerator", Stub)
    monkeypatch.setattr(bom_mod, "_blint_generator_class", lambda: Stub)
    bom_file = str(tmp_path / "sbom.cdx.json")
    options = {"cdxgen_args": "--exclude 'test/**'", "reachability_analyzer": "off"}
    assert bom_mod.create_blint_bom(bom_file, root, options=options)
    assert seen["src_dir"] == os.path.join(root, "bin")
    assert seen["options"]["blint_targets"] == [os.path.join(root, "bin")]
    assert seen["options"]["exclude_patterns"] == ["test/**"]


def test_a_blint_scan_with_everything_excluded_names_the_cause(tmp_path):
    root = str(tmp_path / "src")
    _touch(root, "test", "a.nupkg")
    result = bom_mod.create_bom(
        str(tmp_path / "sbom.cdx.json"),
        root,
        {"project_type": ["binary"], "cdxgen_args": "--exclude 'test/**'"},
    )
    assert result.success is False
    assert "--exclude" in (result.failure_reason or "")


# language tools --------------------------------------------------------------


def _tool(name, calls):
    tool = getattr(bom_mod, f"{name.upper()}_TOOL")
    return dataclasses.replace(
        tool, run_fallback=lambda src, *a, **k: calls.append((name, src)) or None
    )


def _typed_run(tool, tmp_path, src, cdxgen_args, project_type):
    bom_file = tmp_path / "sbom.cdx.json"
    bom_file.write_text(json.dumps({"components": []}))
    options = {"project_type": [project_type], "reachability_analyzer": "SemanticReachability"}
    if cdxgen_args:
        options["cdxgen_args"] = cdxgen_args
    return bom_mod._run_reachability_tool(str(bom_file), src, options, tool)


def test_a_tool_without_an_exclude_flag_starts_on_the_one_project_root_left(tmp_path):
    src = str(tmp_path / "src")
    _touch(src, "go", "go.mod")
    _touch(src, "test", "fx", "go.mod")
    calls = []
    _typed_run(_tool("golem", calls), tmp_path, src, "--exclude 'test/**'", "go")
    assert calls == [("golem", os.path.join(src, "go"))]


def test_a_tool_starts_on_the_scan_root_when_the_patterns_remove_no_project(tmp_path):
    src = str(tmp_path / "src")
    _touch(src, "go", "go.mod")
    _touch(src, "docs", "a.md")
    calls = []
    _typed_run(_tool("golem", calls), tmp_path, src, "--exclude 'docs/**'", "go")
    assert calls == [("golem", src)]
    calls.clear()
    _typed_run(_tool("golem", calls), tmp_path, src, None, "go")
    assert calls == [("golem", src)]


def test_a_tool_is_not_started_when_every_project_is_excluded(tmp_path):
    src = str(tmp_path / "src")
    _touch(src, "test", "fx", "Cargo.toml")
    calls = []
    result = _typed_run(_tool("rusi", calls), tmp_path, src, "--exclude 'test/**'", "rust")
    assert calls == []
    assert result.status == "not-assessed"
    assert "--exclude" in result.reason


def test_a_tool_is_not_started_on_several_roots_after_a_pattern_removed_one(tmp_path):
    src = str(tmp_path / "src")
    for name in ("a", "b", "test/c"):
        _touch(src, *name.split("/"), "go.mod")
    calls = []
    result = _typed_run(_tool("golem", calls), tmp_path, src, "--exclude 'test/**'", "go")
    assert calls == []
    assert result.status == "not-assessed"


def test_the_fail_on_error_scan_refuses_a_tool_with_no_root_left(tmp_path):
    src = str(tmp_path / "src")
    _touch(src, "test", "Cargo.toml")
    bom_file = tmp_path / "sbom.cdx.json"
    bom_file.write_text(json.dumps({"components": []}))
    options = {
        "project_type": ["rust"],
        "cdxgen_args": "--exclude 'test/**'",
        "fail_on_error": True,
    }
    with pytest.raises(bom_mod.ScanFailureError):
        bom_mod._run_reachability_tool(str(bom_file), src, options, _tool("rusi", []))


def test_dosai_receives_the_patterns_when_its_runner_accepts_them(tmp_path, monkeypatch):
    import xbom_lib.dosai as dosai_mod

    seen = {}

    def fake_run(src_dir, out_dir, pattern_packs=None, logger=None, exclude=()):
        seen["exclude"] = list(exclude)
        return type("R", (), {"skipped": True, "success": False})()

    monkeypatch.setattr(dosai_mod, "run_dosai", fake_run)
    bom_mod._run_dosai_fallback(
        str(tmp_path),
        str(tmp_path),
        {"cdxgen_args": "--exclude 'test/**' --exclude 'docs/**'"},
        lambda data: True,
        json.load,
    )
    assert seen["exclude"] == ["test/**", "docs/**"]


def test_dosai_still_runs_with_a_runner_that_takes_no_patterns(tmp_path, monkeypatch):
    import xbom_lib.dosai as dosai_mod

    seen = {}

    def fake_run(src_dir, out_dir, pattern_packs=None, logger=None):
        seen["ran"] = True
        return type("R", (), {"skipped": True, "success": False})()

    monkeypatch.setattr(dosai_mod, "run_dosai", fake_run)
    bom_mod._run_dosai_fallback(
        str(tmp_path),
        str(tmp_path),
        {"cdxgen_args": "--exclude 'test/**'"},
        lambda d: True,
        json.load,
    )
    assert seen == {"ran": True}
