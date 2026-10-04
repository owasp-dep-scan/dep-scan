"""cdxgen must receive an absolute source path (cdxgen-plugins-bin#124).

depscan launches cdxgen with its working directory set to the source
directory. A relative source argument is then resolved a second time against
that directory, giving ``<src>/<src>``: a path that does not exist, so the
rusi/golem/kosi plugins analyse nothing and reachability silently degrades.
"""

import os

from xbom_lib import cdxgen as cdxgen_mod
from xbom_lib.cdxgen import cdxgen_source_arg


def test_relative_directory_becomes_absolute(monkeypatch, tmp_path):
    (tmp_path / "repo" / "app").mkdir(parents=True)
    monkeypatch.chdir(tmp_path / "repo")
    assert cdxgen_source_arg("app") == str(tmp_path / "repo" / "app")
    assert cdxgen_source_arg(".") == str(tmp_path / "repo")


def test_absolute_directory_is_unchanged(tmp_path):
    assert cdxgen_source_arg(str(tmp_path)) == str(tmp_path)


def test_non_directory_sources_pass_through():
    for value in (
        "https://github.com/owasp-dep-scan/dep-scan",
        "pkg:npm/lodash@4.17.21",
        "ubuntu:24.04",
        "does/not/exist",
    ):
        assert cdxgen_source_arg(value) == value


def test_generator_passes_absolute_source_with_project_cwd(monkeypatch, tmp_path):
    """The exact #124 shape: a repo-root-relative --src. The argument must be
    absolute while cdxgen's cwd stays the project, so the two never compound."""
    project = tmp_path / "test" / "data" / "app"
    project.mkdir(parents=True)
    monkeypatch.chdir(tmp_path)
    captured = {}

    def fake_exec_tool(args, cwd=None, *a, **k):
        captured["args"] = args
        captured["cwd"] = cwd
        return cdxgen_mod.BOMResult(success=True)

    monkeypatch.setattr(cdxgen_mod, "find_cdxgen_cmd", lambda *a, **k: "cdxgen")
    monkeypatch.setattr(cdxgen_mod, "exec_tool", fake_exec_tool)
    gen = cdxgen_mod.CdxgenGenerator(
        "test/data/app", str(tmp_path / "bom.cdx.json"), options={"project_type": ["rust"]}
    )
    gen.generate()
    assert captured["args"][-1] == str(project)
    assert os.path.isabs(captured["args"][-1])
    assert captured["cwd"] == "test/data/app"
