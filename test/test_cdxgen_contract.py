"""The cdxgen calling contract, exercised through a fake cdxgen.

The fake is a Python script started through ``sys.executable``, so it runs on
Windows too and needs no execute bit. It answers ``--version`` from an
environment variable, writes a minimal BOM to the ``-o`` path, an empty
document to every ``--*-slices-file`` and ``--introspect-json`` path, and
appends every invocation to a JSON record file. A test that expects cdxgen to
run asserts on that record, which is also the positive control that the fake
was called.

What is asserted here is the full argument list for each profile and
lifecycle, the version refusal, the exit-status mapping and secure mode.
"""

import json
import os
import sys

import pytest

from analysis_lib.config import SUPPORTED_BOM_PROFILES
from depscan.lib import bom as bom_mod
from xbom_lib import cdxgen as cdxgen_mod

FAKE_CDXGEN_SOURCE = r'''
import json
import os
import sys

argv = sys.argv[1:]
record = os.environ.get("FAKE_CDXGEN_RECORD")
version = os.environ.get("FAKE_CDXGEN_VERSION", "13.8.0")
exit_code = int(os.environ.get("FAKE_CDXGEN_EXIT", "0"))


def append(probe):
    if not record:
        return
    entries = []
    if os.path.exists(record):
        with open(record, encoding="utf-8") as fp:
            try:
                entries = json.load(fp)
            except ValueError:
                entries = []
    entries.append(
        {
            "argv": argv,
            "cwd": os.getcwd(),
            "probe": probe,
            "env": {
                k: v
                for k, v in os.environ.items()
                if k.startswith(("CDXGEN_", "ATOM_"))
            },
        }
    )
    with open(record, "w", encoding="utf-8") as fp:
        json.dump(entries, fp)


if "--version" in argv:
    # cdxgen 13.8.0 prints the name in bold.
    print(f"\x1b[1mCycloneDX Generator {version}\x1b[0m")
    print("Runtime: Node.js, Version: 24.0.0")
    append(probe=True)
    sys.exit(0)

if exit_code in (0, 4, 5):
    for i, arg in enumerate(argv):
        if i + 1 >= len(argv):
            break
        if arg == "-o":
            with open(argv[i + 1], "w", encoding="utf-8") as fp:
                json.dump(
                    {
                        "bomFormat": "CycloneDX",
                        "specVersion": "1.6",
                        "components": [
                            {
                                "type": "library",
                                "name": "fakedep",
                                "purl": "pkg:pypi/fakedep@1.0",
                            }
                        ],
                    },
                    fp,
                )
        if arg.endswith("-slices-file"):
            with open(argv[i + 1], "w", encoding="utf-8") as fp:
                json.dump({"columns": [], "callsites": []}, fp)
        if arg == "--introspect-json":
            with open(argv[i + 1], "w", encoding="utf-8") as fp:
                json.dump(
                    {"overall": {"score": 72, "tier": "lockfile", "confidence": "high"}},
                    fp,
                )
if exit_code == 5:
    print(
        "fail-on-error: the methods slice could not be read "
        "(tool: atom-py, exit 3)."
    )
    print(
        "fail-on-error: 1 extractor failure(s) were deferred so the BOM and "
        "the introspection report could be written; exiting 5."
    )
append(probe=False)
sys.exit(exit_code)
'''


@pytest.fixture
def fake_cdxgen(tmp_path_factory, monkeypatch):
    """Install the fake cdxgen and point every resolver at it.

    Returns the record file path; tests read the recorded invocations from
    it. The version-probe cache is cleared so one test's probe cannot answer
    another's.
    """
    base = tmp_path_factory.mktemp("fake-cdxgen")
    script = base / "fake_cdxgen.py"
    script.write_text(FAKE_CDXGEN_SOURCE, encoding="utf-8")
    record = base / "record.json"
    command = [sys.executable, str(script)]
    monkeypatch.setenv("FAKE_CDXGEN_RECORD", str(record))
    monkeypatch.delenv("FAKE_CDXGEN_VERSION", raising=False)
    monkeypatch.delenv("FAKE_CDXGEN_EXIT", raising=False)
    monkeypatch.setattr(cdxgen_mod, "find_cdxgen_cmd", lambda *a, **k: command)
    monkeypatch.setattr(bom_mod, "find_cdxgen_cmd", lambda *a, **k: command)
    cdxgen_mod._version_probe_cache.clear()
    yield record
    cdxgen_mod._version_probe_cache.clear()


def _invocations(record):
    if not os.path.exists(record):
        return []
    with open(record, encoding="utf-8") as fp:
        return json.load(fp)


def _scans(record):
    return [entry for entry in _invocations(record) if not entry["probe"]]


def _make_project(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "requirements.txt").write_text("defusedxml==0.7.1\n", encoding="utf-8")
    reports = tmp_path / "reports"
    reports.mkdir()
    return src, reports


def _options(profile, types, lifecycles, bom_file):
    return {
        "bom_engine": "CdxgenGenerator",
        "project_type": list(types),
        "profile": profile,
        "lifecycles": list(lifecycles),
        "deep": False,
        "spec_version": "1.6",
        "reachability_analyzer": "off",
    }


def _expected_argv(src, reports, profile, types, lifecycles, bom_name):
    """The argument list depscan hands cdxgen, after the command itself."""
    bom_file = str(reports / bom_name)
    args = []
    for t in types:
        args += ["-t", t]
    args += ["-o", bom_file, "--spec-version", "1.6"]
    if profile:
        args += ["--profile", profile]
        if len(types) == 1:
            for s in (
                "deps",
                "usages",
                "callsites",
                "data-flow",
                "reachables",
                "semantics",
            ):
                args += [
                    f"--{s}-slices-file",
                    os.path.join(str(reports), f"{types[0]}-{s}.slices.json"),
                ]
    args += ["--introspect", "--introspect-json", f"{bom_file}.introspection.json"]
    if len(lifecycles) == 1:
        args += ["--lifecycle", lifecycles[0]]
    args.append(str(src))
    return args


@pytest.mark.parametrize("profile", SUPPORTED_BOM_PROFILES)
@pytest.mark.parametrize("lifecycles", [[], ["pre-build"], ["build"]])
def test_argument_list_for_each_profile_and_lifecycle(
    fake_cdxgen, tmp_path, profile, lifecycles
):
    src, reports = _make_project(tmp_path)
    bom_file = reports / "sbom-python.cdx.json"
    options = _options(profile, ["python"], lifecycles, bom_file)
    result = bom_mod.create_bom(str(bom_file), str(src), options)
    assert result.success, result
    expected = _expected_argv(
        src, reports, profile, ["python"], lifecycles, "sbom-python.cdx.json"
    )
    scans = _scans(fake_cdxgen)
    # Positive control: the fake cdxgen ran once for this scan.
    assert len(scans) == 1
    assert scans[0]["argv"] == expected


def test_argument_list_for_two_project_types(fake_cdxgen, tmp_path):
    src, reports = _make_project(tmp_path)
    bom_file = reports / "sbom-python.cdx.json"
    options = _options("research", ["python", "java"], [], bom_file)
    result = bom_mod.create_bom(str(bom_file), str(src), options)
    assert result.success
    expected = _expected_argv(
        src, reports, "research", ["python", "java"], [], "sbom-python.cdx.json"
    )
    scans = _scans(fake_cdxgen)
    assert len(scans) == 1
    assert scans[0]["argv"] == expected
    # Two types share one BOM, so no slices file is pointed anywhere.
    assert not [a for a in scans[0]["argv"] if a.endswith("-slices-file")]


def test_slices_files_stay_outside_the_scanned_tree(fake_cdxgen, tmp_path):
    src, reports = _make_project(tmp_path)
    bom_file = reports / "sbom-python.cdx.json"
    options = _options("research", ["python"], [], bom_file)
    assert bom_mod.create_bom(str(bom_file), str(src), options).success
    argv = _scans(fake_cdxgen)[0]["argv"]
    slice_values = [
        argv[i + 1] for i, a in enumerate(argv) if a.endswith("-slices-file")
    ]
    assert slice_values
    for value in slice_values:
        assert os.path.dirname(value) == str(reports)
        assert not value.startswith(str(src) + os.sep)


def test_older_cdxgen_is_refused_before_it_runs(fake_cdxgen, tmp_path, monkeypatch, caplog):
    monkeypatch.setenv("FAKE_CDXGEN_VERSION", "13.3.0")
    src, reports = _make_project(tmp_path)
    bom_file = reports / "sbom-python.cdx.json"
    options = _options("research", ["python"], [], bom_file)
    with caplog.at_level("ERROR"):
        result = bom_mod.create_bom(str(bom_file), str(src), options)
    assert not result.success
    message = " ".join(r.message for r in caplog.records)
    assert "13.3.0" in message
    assert "13.8.0" in message
    assert "npm install -g @cdxgen/cdxgen@13.8.0" in message
    # The version probe ran, but no scan invocation was started.
    probes = [e for e in _invocations(fake_cdxgen) if e["probe"]]
    assert len(probes) == 1
    assert _scans(fake_cdxgen) == []


def test_unreadable_cdxgen_version_is_refused(fake_cdxgen, tmp_path, monkeypatch, caplog):
    monkeypatch.setenv("FAKE_CDXGEN_VERSION", "unknown-dev-build")
    src, reports = _make_project(tmp_path)
    bom_file = reports / "sbom-python.cdx.json"
    options = _options("research", ["python"], [], bom_file)
    with caplog.at_level("ERROR"):
        result = bom_mod.create_bom(str(bom_file), str(src), options)
    assert not result.success
    message = " ".join(r.message for r in caplog.records)
    assert "Could not read the cdxgen version" in message
    assert "npm install -g @cdxgen/cdxgen@13.8.0" in message
    assert _scans(fake_cdxgen) == []


def test_required_cdxgen_version_runs_the_scan(fake_cdxgen, tmp_path):
    src, reports = _make_project(tmp_path)
    bom_file = reports / "sbom-python.cdx.json"
    options = _options("research", ["python"], [], bom_file)
    assert bom_mod.create_bom(str(bom_file), str(src), options).success
    assert len(_scans(fake_cdxgen)) == 1


def test_path_default_cdxgen_is_version_checked(tmp_path, monkeypatch, caplog):
    """``cdxgen`` found on PATH is the command that runs, so it is probed.

    The resolver returns the literal name both when PATH resolves it and as
    its last-resort fallback; either way the version check must see it.
    """
    monkeypatch.setattr(bom_mod, "find_cdxgen_cmd", lambda *a, **k: "cdxgen")
    monkeypatch.setattr(cdxgen_mod, "find_cdxgen_cmd", lambda *a, **k: "cdxgen")
    monkeypatch.setattr(cdxgen_mod, "cdxgen_version", lambda cmd, logger=None: "13.3.0")
    src, reports = _make_project(tmp_path)
    bom_file = reports / "sbom-python.cdx.json"
    options = _options("research", ["python"], [], bom_file)
    with caplog.at_level("ERROR"):
        result = bom_mod.create_bom(str(bom_file), str(src), options)
    assert not result.success
    assert "13.3.0" in " ".join(r.message for r in caplog.records)


def test_unresolvable_cdxgen_is_refused_as_unreadable(tmp_path, monkeypatch, caplog):
    monkeypatch.setattr(bom_mod, "find_cdxgen_cmd", lambda *a, **k: False)
    monkeypatch.setattr(cdxgen_mod, "find_cdxgen_cmd", lambda *a, **k: False)
    monkeypatch.setattr(cdxgen_mod, "cdxgen_version", lambda cmd, logger=None: None)
    src, reports = _make_project(tmp_path)
    bom_file = reports / "sbom-python.cdx.json"
    options = _options("research", ["python"], [], bom_file)
    with caplog.at_level("ERROR"):
        result = bom_mod.create_bom(str(bom_file), str(src), options)
    assert not result.success
    assert "Could not read the cdxgen version" in " ".join(
        r.message for r in caplog.records
    )


def test_version_is_probed_once_for_a_lifecycle_scan(fake_cdxgen, tmp_path, monkeypatch):
    src, reports = _make_project(tmp_path)
    options = _options("research", ["python"], [], reports / "sbom-build.cdx.json")
    options.update(
        {
            "lifecycle_analysis_mode": True,
            "prebuild_bom_file": str(reports / "sbom-prebuild.cdx.json"),
            "build_bom_file": str(reports / "sbom-build.cdx.json"),
            "postbuild_bom_file": str(reports / "sbom-postbuild.cdx.json"),
            "container_bom_file": str(reports / "sbom-container.cdx.json"),
        }
    )
    # The post-build blint stage is not under test here.
    monkeypatch.setattr(bom_mod, "create_blint_bom", lambda *a, **k: False)
    result = bom_mod.create_bom(options["build_bom_file"], str(src), options)
    assert result.success
    probes = [e for e in _invocations(fake_cdxgen) if e["probe"]]
    # One probe regardless of how many lifecycle stages ran cdxgen.
    assert len(probes) == 1
    assert len(_scans(fake_cdxgen)) >= 2


@pytest.mark.parametrize(
    "exit_code,expect_success",
    [(0, True), (1, False), (2, False), (4, True), (5, False)],
)
def test_exit_status_mapping(fake_cdxgen, tmp_path, monkeypatch, exit_code, expect_success):
    monkeypatch.setenv("FAKE_CDXGEN_EXIT", str(exit_code))
    src, reports = _make_project(tmp_path)
    bom_file = reports / "sbom-python.cdx.json"
    options = _options("research", ["python"], [], bom_file)
    result = bom_mod.create_bom(str(bom_file), str(src), options)
    assert result.success is expect_success
    if expect_success:
        assert result.bom_files == [str(bom_file)]


def test_exit_four_logs_the_introspection_tier(fake_cdxgen, tmp_path, monkeypatch, caplog):
    monkeypatch.setenv("FAKE_CDXGEN_EXIT", "4")
    src, reports = _make_project(tmp_path)
    bom_file = reports / "sbom-python.cdx.json"
    options = _options("research", ["python"], [], bom_file)
    with caplog.at_level("WARNING"):
        result = bom_mod.create_bom(str(bom_file), str(src), options)
    assert result.success
    message = " ".join(r.message for r in caplog.records)
    assert "exited 4" in message
    assert "lockfile" in message
    assert "72" in message


def test_exit_five_stops_and_names_each_extractor_failure(
    fake_cdxgen, tmp_path, monkeypatch, caplog
):
    # cdxgen 13.8.0 exits 5 only under --fail-on-error, so the scan stops.
    monkeypatch.setenv("FAKE_CDXGEN_EXIT", "5")
    src, reports = _make_project(tmp_path)
    bom_file = reports / "sbom-python.cdx.json"
    options = {**_options("research", ["python"], [], bom_file), "fail_on_error": True}
    with caplog.at_level("ERROR"):
        result = bom_mod.create_bom(str(bom_file), str(src), options)
    assert not result.success
    failures = [r.message for r in caplog.records if "exited 5" in r.message]
    # One record for the one extractor; the closing summary line is not a failure.
    assert len(failures) == 1
    assert "atom-py" in failures[0]


def test_extractor_failures_skip_the_summary_line():
    output = (
        "fail-on-error: the methods slice could not be read (tool: atom-py, exit 3).\n"
        "fail-on-error: pip install failed (tool: pip).\n"
        "fail-on-error: 2 extractor failure(s) were deferred so the BOM and the "
        "introspection report could be written; exiting 5.\n"
    )
    assert bom_mod._extractor_failures(output) == [
        "fail-on-error: the methods slice could not be read (tool: atom-py, exit 3).",
        "fail-on-error: pip install failed (tool: pip).",
    ]


@pytest.mark.parametrize(
    "version,accepted",
    [
        ("13.8.0", True),
        ("13.10.0", True),
        ("14.0.0", True),
        ("13.7.9", False),
        ("13.8.0-beta.1", False),
        ("13.8.1-rc.1", True),
    ],
)
def test_cdxgen_version_comparison(fake_cdxgen, monkeypatch, version, accepted):
    monkeypatch.setenv("FAKE_CDXGEN_VERSION", version)
    cdxgen_mod._version_probe_cache.clear()
    ok, found = cdxgen_mod.check_cdxgen_version(cdxgen_mod.find_cdxgen_cmd())
    # Positive control: the ANSI-wrapped version line was read.
    assert found == version
    assert ok is accepted


def test_other_exit_status_is_named_in_the_message(fake_cdxgen, tmp_path, monkeypatch, caplog):
    monkeypatch.setenv("FAKE_CDXGEN_EXIT", "3")
    src, reports = _make_project(tmp_path)
    bom_file = reports / "sbom-python.cdx.json"
    options = _options("research", ["python"], [], bom_file)
    with caplog.at_level("ERROR"):
        result = bom_mod.create_bom(str(bom_file), str(src), options)
    assert not result.success
    assert any("status 3" in r.message for r in caplog.records)


def test_remote_repository_runs_cdxgen_in_secure_mode(fake_cdxgen, tmp_path):
    reports = tmp_path / "reports"
    reports.mkdir()
    bom_file = reports / "sbom-java.cdx.json"
    options = _options("research", ["java"], [], bom_file)
    result = bom_mod.create_bom(
        str(bom_file), "https://github.com/example/untrusted", options
    )
    assert result.success
    scans = _scans(fake_cdxgen)
    assert len(scans) == 1
    assert scans[0]["env"].get("CDXGEN_SECURE_MODE") == "true"
    # A remote source is passed through untouched.
    assert scans[0]["argv"][-1] == "https://github.com/example/untrusted"


def test_server_initiated_scan_runs_cdxgen_in_secure_mode(fake_cdxgen, tmp_path):
    src, reports = _make_project(tmp_path)
    bom_file = reports / "sbom-python.cdx.json"
    options = _options("generic", ["python"], [], bom_file)
    # The depscan server sends these options; the CLI never does.
    options["multiProject"] = True
    options["path"] = str(src)
    assert bom_mod.create_bom(str(bom_file), str(src), options).success
    scans = _scans(fake_cdxgen)
    assert len(scans) == 1
    assert scans[0]["env"].get("CDXGEN_SECURE_MODE") == "true"


def test_local_directory_scan_does_not_force_secure_mode(fake_cdxgen, tmp_path):
    src, reports = _make_project(tmp_path)
    bom_file = reports / "sbom-python.cdx.json"
    options = _options("research", ["python"], [], bom_file)
    assert bom_mod.create_bom(str(bom_file), str(src), options).success
    scans = _scans(fake_cdxgen)
    assert scans[0]["env"].get("CDXGEN_SECURE_MODE") is None


def test_introspection_report_is_written_next_to_the_bom(fake_cdxgen, tmp_path):
    src, reports = _make_project(tmp_path)
    bom_file = reports / "sbom-python.cdx.json"
    options = _options("research", ["python"], [], bom_file)
    assert bom_mod.create_bom(str(bom_file), str(src), options).success
    intro = str(bom_file) + ".introspection.json"
    assert os.path.exists(intro)
    with open(intro, encoding="utf-8") as fp:
        assert json.load(fp)["overall"]["tier"] == "lockfile"
