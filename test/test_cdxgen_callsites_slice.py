"""The callsites slice is passed and kept like the other slices.

cdxgen records every external call site in the callsites slice; dep-scan
decides which dependencies a project really uses from that evidence. The
slice path must reach cdxgen as ``--callsites-slices-file`` beside the other
``--*-slices-file`` arguments so the file is written into the reports
directory next to them instead of landing at cdxgen's default location.
"""

import os

from xbom_lib import cdxgen as cdxgen_mod
from xbom_lib.cdxgen import set_slices_args


def test_callsites_slice_file_is_passed_for_a_single_type(tmp_path):
    args = []
    set_slices_args(["python"], args, str(tmp_path))
    assert "--callsites-slices-file" in args
    index = args.index("--callsites-slices-file")
    assert args[index + 1] == os.path.join(
        str(tmp_path), "python-callsites.slices.json"
    )


def test_every_slice_including_callsites_is_passed_for_a_single_type(tmp_path):
    args = []
    set_slices_args(["java"], args, str(tmp_path))
    expected = [
        "--deps-slices-file",
        "--usages-slices-file",
        "--callsites-slices-file",
        "--data-flow-slices-file",
        "--reachables-slices-file",
        "--semantics-slices-file",
    ]
    assert [a for a in args if a.startswith("--") and a.endswith("-file")] == expected
    for flag in expected:
        value = args[args.index(flag) + 1]
        assert value.startswith(str(tmp_path) + os.sep)
        slice_type = flag[2 : -len("-slices-file")]
        assert value == os.path.join(str(tmp_path), f"java-{slice_type}.slices.json")


def test_no_slices_arguments_for_multiple_types(tmp_path):
    args = []
    set_slices_args(["python", "java"], args, str(tmp_path))
    assert args == []


def test_research_profile_generator_passes_the_callsites_path(
    monkeypatch, tmp_path
):
    """The research profile is what runs the analyzers that write the slice,
    so its argument list must name the callsites file next to the others."""
    captured = {}

    def fake_exec_tool(args, cwd=None, *a, **k):
        captured["args"] = args
        captured["cwd"] = cwd
        return cdxgen_mod.BOMResult(success=True, returncode=0)

    monkeypatch.setattr(cdxgen_mod, "find_cdxgen_cmd", lambda *a, **k: "cdxgen")
    monkeypatch.setattr(cdxgen_mod, "exec_tool", fake_exec_tool)
    bom_dir = tmp_path / "reports"
    bom_dir.mkdir()
    gen = cdxgen_mod.CdxgenGenerator(
        str(tmp_path),
        str(bom_dir / "sbom-python.cdx.json"),
        options={"project_type": ["python"], "profile": "research"},
    )
    assert gen.generate().success
    # Positive control: the fake ran and captured the argument list.
    assert captured["args"]
    args = captured["args"]
    assert "--callsites-slices-file" in args
    value = args[args.index("--callsites-slices-file") + 1]
    assert value == str(bom_dir / "python-callsites.slices.json")
    # The slice lands next to the other slices, all outside the source tree.
    for flag in ("--deps-slices-file", "--usages-slices-file", "--callsites-slices-file"):
        slice_path = args[args.index(flag) + 1]
        assert os.path.dirname(slice_path) == str(bom_dir)
