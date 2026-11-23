import dataclasses
import json
import os
from pathlib import Path

import pytest

from depscan.lib.bom import (
    create_empty_vdr,
    determine_spec_version,
    get_pkg_by_type,
    get_pkg_list,
    parse_bom_ref,
    update_tools_metadata,
)


def _write_bom(path, spec_version):
    path.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": spec_version}))
    return str(path)


def test_determine_spec_version_defaults_to_1_6():
    assert determine_spec_version([], fallback=None) == "1.6"


def test_determine_spec_version_uses_fallback_when_no_boms():
    assert determine_spec_version([], fallback="1.7") == "1.7"


def test_determine_spec_version_prefers_max_across_boms(tmp_path):
    files = [
        _write_bom(tmp_path / "a.json", "1.5"),
        _write_bom(tmp_path / "b.json", "1.7"),
        _write_bom(tmp_path / "c.json", "1.6"),
    ]
    # Max across SBOMs wins over the user fallback (never downgrade).
    assert determine_spec_version(files, fallback="1.4") == "1.7"


def test_determine_spec_version_two_zero_beats_one_x(tmp_path):
    files = [
        _write_bom(tmp_path / "a.json", "1.7"),
        _write_bom(tmp_path / "b.json", "2.0"),
    ]
    assert determine_spec_version(files) == "2.0"


def test_update_tools_metadata_uses_spec_version():
    bom = update_tools_metadata(None, None, "6.0.0", spec_version="1.7")
    assert bom["specVersion"] == "1.7"


def test_update_tools_metadata_defaults_spec_version():
    bom = update_tools_metadata(None, None, "6.0.0")
    assert bom["specVersion"] == "1.6"


def test_create_empty_vdr_threads_spec_version():
    vdr = create_empty_vdr([], "6.0.0", spec_version="2.0")
    assert vdr["specVersion"] == "2.0"


def test_get_pkg():
    test_bom = os.path.join(os.path.dirname(os.path.realpath(__file__)), "data", "bom.xml")
    pkg_list = get_pkg_list(test_bom)
    assert len(pkg_list) == 157
    for pkg in pkg_list:
        assert pkg["vendor"] != "maven"
        assert " " not in pkg["name"]
        assert pkg["version"]
    test_py_bom = os.path.join(os.path.dirname(os.path.realpath(__file__)), "data", "bom-py.xml")
    pkg_list = get_pkg_list(test_py_bom)
    assert len(pkg_list) == 31
    for pkg in pkg_list:
        assert pkg["vendor"] == "pypi"
        assert " " not in pkg["name"]
        assert pkg["version"]
    test_dn_bom = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "bom-dotnet.xml"
    )
    pkg_list = get_pkg_list(test_dn_bom)
    assert len(pkg_list) == 38
    for pkg in pkg_list:
        assert pkg["vendor"]
        assert " " not in pkg["name"]
        assert pkg["version"]

    test_dn_bom = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "bom-dotnet2.xml"
    )
    pkg_list = get_pkg_list(test_dn_bom)
    assert len(pkg_list) == 6
    for pkg in pkg_list:
        assert pkg["vendor"]
        assert " " not in pkg["name"]
        assert pkg["version"]


def test_parse():
    assert parse_bom_ref("pkg:maven/org.projectlombok/lombok@1.18.4?type=jar") == {
        "vendor": "org.projectlombok",
        "name": "lombok",
        "version": "1.18.4",
        "licenses": None,
    }

    assert parse_bom_ref("pkg:maven/org.projectlombok/lombok@1.18.4") == {
        "vendor": "org.projectlombok",
        "name": "lombok",
        "version": "1.18.4",
        "licenses": None,
    }

    assert parse_bom_ref("pkg:pypi/atomicwrites@1.3.0") == {
        "vendor": "pypi",
        "name": "atomicwrites",
        "version": "1.3.0",
        "licenses": None,
    }

    assert parse_bom_ref("pkg:npm/body-parser@1.18.3") == {
        "vendor": "npm",
        "name": "body-parser",
        "version": "1.18.3",
        "licenses": None,
    }

    assert parse_bom_ref("pkg:npm/@cyclonedx/cdxgen@1.10.0") == {
        "vendor": "@cyclonedx",
        "name": "cdxgen",
        "version": "1.10.0",
        "licenses": None,
    }
    assert parse_bom_ref("pkg:golang/cloud.google.com/go@v0.34.0") == {
        "vendor": "cloud.google.com",
        "name": "go",
        "version": "0.34.0",
        "licenses": None,
    }
    assert parse_bom_ref("pkg:golang/cloud.google.com/go/bigquery@v1.0.1") == {
        "vendor": "go",
        "name": "bigquery",
        "version": "1.0.1",
        "licenses": None,
    }
    assert parse_bom_ref("pkg:golang/github.com%2FAzure%2Fazure-amqp-common-go/v2@v2.1.0") == {
        "vendor": "azure-amqp-common-go",
        "name": "v2",
        "version": "2.1.0",
        "licenses": None,
    }
    assert parse_bom_ref("pkg:golang/github.com%2FAzure/go-autorest@v13.0.0%2Bincompatible") == {
        "vendor": "Azure",
        "name": "go-autorest",
        "version": "13.0.0+incompatible",
        "licenses": None,
    }
    assert parse_bom_ref(
        "pkg:golang/github.com%2Fdocker/docker@v0.7.3-0.20190327010347-be7ac8be2ae0"
    ) == {
        "vendor": "docker",
        "name": "docker",
        "version": "0.7.3-0.20190327010347-be7ac8be2ae0",
        "licenses": None,
    }


def test_get_pkg_by_type():
    test_bom = os.path.join(os.path.dirname(os.path.realpath(__file__)), "data", "bom-docker.json")
    pkg_list = get_pkg_list(test_bom)
    assert len(pkg_list) == 1824
    filtered_list = get_pkg_by_type(pkg_list, "npm")
    assert len(filtered_list) == 1823


# ---------------------------------------------------------------------------
# T5 — CycloneDX 1.7 parse/emit readiness
# ---------------------------------------------------------------------------


def test_get_pkg_list_parses_cyclonedx_1_7_xml():
    """A CycloneDX 1.7 XML BOM (cdxgen 12.8 default) must parse cleanly,
    including the licenses section under the 1.7 namespace."""
    test_bom = os.path.join(os.path.dirname(os.path.realpath(__file__)), "data", "bom-1.7.xml")
    pkg_list = get_pkg_list(test_bom)
    assert pkg_list is not None
    assert len(pkg_list) == 2
    by_name = {p["name"]: p for p in pkg_list}
    assert "lodash" in by_name
    assert by_name["lodash"]["version"] == "4.17.21"
    # Licenses must be extracted from the 1.7 namespace
    assert "MIT" in by_name["lodash"]["licenses"]
    assert "BSD-3-Clause" in by_name["django"]["licenses"]


def test_update_tools_metadata_preserves_existing_spec_version():
    """When a source BOM has specVersion 1.7, update_tools_metadata must not
    downgrade it to 1.6."""
    bom_data = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "version": 1,
        "metadata": {"tools": {}},
    }
    result = update_tools_metadata({}, bom_data, "1.0.0")
    assert result["specVersion"] == "1.7"


def test_update_tools_metadata_defaults_for_new_bom():
    """A from-scratch VDR (no source BOM) gets a valid specVersion."""
    result = update_tools_metadata(None, None, "1.0.0")
    assert result["specVersion"]  # some valid version
    assert result["bomFormat"] == "CycloneDX"


def test_export_bom_preserves_source_spec_version(tmp_path):
    """VDR specVersion must be ≥ source specVersion (never downgraded)."""
    from depscan.lib.bom import export_bom

    bom_data = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "version": 1,
        "metadata": {"tools": {"components": []}},
        "components": [],
    }
    vdr_file = str(tmp_path / "test.vdr.json")
    export_bom(bom_data, "1.0.0", [], vdr_file)
    import json

    with open(vdr_file) as f:
        vdr = json.load(f)
    assert vdr["specVersion"] == "1.7"


def test_export_bom_writes_dates_the_validator_accepts(tmp_path):
    """Naive database times become RFC 3339 UTC, and the VDR validates.

    The vulnerability database stores naive UTC times; CycloneDX date-time
    needs an offset, so without the conversion ``depscan validate`` rejects
    every VDR a scan writes.
    """
    import json

    from analysis_lib.validation import validate_document
    from depscan.lib.bom import export_bom

    bom_data = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {"tools": {"components": []}},
        "components": [
            {
                "type": "library",
                "name": "lodash",
                "version": "4.17.20",
                "purl": "pkg:npm/lodash@4.17.20",
                "bom-ref": "pkg:npm/lodash@4.17.20",
            }
        ],
    }
    vulnerabilities = [
        {
            "bom-ref": "CVE-2021-23337/pkg:npm/lodash@4.17.20",
            "id": "CVE-2021-23337",
            "published": "2021-02-15T13:15:12",
            "updated": "2021-09-02T17:16:46.123",
            "affects": [{"ref": "pkg:npm/lodash@4.17.20"}],
            "analysis": {"state": "exploitable", "firstIssued": "2021-02-15T13:15:12"},
        },
        {
            "bom-ref": "GHSA-x/pkg:npm/lodash@4.17.20",
            "id": "GHSA-35jh-r3h4-6jhm",
            "published": "",
            "updated": "2021-09-02T17:16:46+02:00",
            "affects": [{"ref": "pkg:npm/lodash@4.17.20"}],
        },
    ]
    vdr_file = tmp_path / "test.vdr.json"
    export_bom(bom_data, "1.0.0", vulnerabilities, str(vdr_file))
    vdr = json.loads(vdr_file.read_text(encoding="utf-8"))
    first, second = vdr["vulnerabilities"]
    assert first["published"] == "2021-02-15T13:15:12Z"
    assert first["updated"] == "2021-09-02T17:16:46Z"
    assert first["analysis"]["firstIssued"] == "2021-02-15T13:15:12Z"
    assert "published" not in second
    assert second["updated"] == "2021-09-02T17:16:46+02:00"
    detected, errors = validate_document(vdr)
    assert detected == "cyclonedx"
    assert errors == []


# ---------------------------------------------------------------------------
# create_bom / BomResult contract
#
# create_bom is handed the path where a BOM is *requested*. It must report back
# the documents it actually wrote, because that is not always the path it was
# given (see https://github.com/owasp-dep-scan/dep-scan/issues/517).
# ---------------------------------------------------------------------------


class _FakeGenResult:
    def __init__(self, success):
        self.success = success
        self.command_output = ""


def _fake_generator(success=True, writes=True):
    """Build a cdxgen-compatible generator class with controllable behaviour."""

    class _Gen:
        def __init__(self, src_dir, bom_file, logger=None, options=None):
            self.bom_file = bom_file

        def generate(self):
            if writes and self.bom_file:
                with open(self.bom_file, "w") as fh:
                    json.dump({"bomFormat": "CycloneDX", "specVersion": "1.6"}, fh)
            return _FakeGenResult(success)

    return _Gen


def test_create_bom_reports_the_document_it_wrote(tmp_path, monkeypatch):
    from depscan.lib import bom as bom_mod

    # The version gate probes the real cdxgen; a fake generator replaces it.
    monkeypatch.setattr(bom_mod, "_refuse_old_cdxgen", lambda logger=None: True)
    monkeypatch.setattr(bom_mod, "CdxgenGenerator", _fake_generator())
    monkeypatch.setattr(bom_mod, "run_rusi_reachability", lambda *a, **k: None)
    monkeypatch.setattr(bom_mod, "run_golem_reachability", lambda *a, **k: None)
    monkeypatch.setattr(bom_mod, "run_kosi_reachability", lambda *a, **k: None)
    monkeypatch.setattr(bom_mod, "run_dosai_reachability", lambda *a, **k: None)

    target = str(tmp_path / "sbom-rust.cdx.json")
    result = bom_mod.create_bom(target, str(tmp_path), {})

    assert result.success is True
    assert result.bom_files == [target]
    assert result.primary == target


def test_create_bom_reports_failure_when_nothing_was_written(tmp_path, monkeypatch):
    """A generator can report success and still write nothing. The requested
    path must not be handed back as if it were a real document."""
    from depscan.lib import bom as bom_mod

    monkeypatch.setattr(bom_mod, "_refuse_old_cdxgen", lambda logger=None: True)
    monkeypatch.setattr(bom_mod, "CdxgenGenerator", _fake_generator(success=True, writes=False))

    target = str(tmp_path / "sbom-rust.cdx.json")
    result = bom_mod.create_bom(target, str(tmp_path), {})

    assert result.success is False
    assert result.bom_files == []
    assert result.primary is None


def test_create_bom_reports_failure_when_generator_fails(tmp_path, monkeypatch):
    from depscan.lib import bom as bom_mod

    monkeypatch.setattr(bom_mod, "_refuse_old_cdxgen", lambda logger=None: True)
    monkeypatch.setattr(bom_mod, "CdxgenGenerator", _fake_generator(success=False, writes=False))

    result = bom_mod.create_bom(str(tmp_path / "sbom.cdx.json"), str(tmp_path), {})

    assert result.success is False
    assert result.primary is None


def test_a_failed_cdxgen_run_names_its_time_budget(tmp_path, monkeypatch, caplog):
    """A failed cdxgen invocation says what time budget was in effect.

    dep-scan itself sets CDXGEN_TIMEOUT_MS (30 minutes by default) and kills
    cdxgen at it, so the failure reason names the budget and how to raise it
    on the console and for the manifest, without claiming the budget was
    necessarily the cause.
    """
    from depscan.lib import bom as bom_mod
    from xbom_lib.cdxgen import CDXGEN_TIMEOUT_MS

    monkeypatch.setattr(bom_mod, "_refuse_old_cdxgen", lambda logger=None: True)
    monkeypatch.setattr(bom_mod, "CdxgenGenerator", _fake_generator(success=False, writes=False))
    monkeypatch.setattr(bom_mod, "run_rusi_reachability", lambda *a, **k: None)
    monkeypatch.setattr(bom_mod, "run_golem_reachability", lambda *a, **k: None)
    monkeypatch.setattr(bom_mod, "run_kosi_reachability", lambda *a, **k: None)
    monkeypatch.setattr(bom_mod, "run_dosai_reachability", lambda *a, **k: None)

    result = bom_mod.create_bom(str(tmp_path / "sbom.cdx.json"), str(tmp_path), {})

    assert result.success is False
    assert "CDXGEN_TIMEOUT_MS" in result.failure_reason
    assert CDXGEN_TIMEOUT_MS in result.failure_reason, "the reason names the budget in effect"
    assert "raise CDXGEN_TIMEOUT_MS" in result.failure_reason
    assert any(
        "CDXGEN_TIMEOUT_MS" in message for message in caplog.messages
    ), "the console names the budget too"


def test_create_bom_requires_cdxgen_server_url(tmp_path):
    from depscan.lib import bom as bom_mod

    result = bom_mod.create_bom(
        str(tmp_path / "sbom.cdx.json"),
        str(tmp_path),
        {"bom_engine": "CdxgenServerGenerator"},
    )

    assert result.success is False
    assert result.bom_files == []


def test_lifecycle_boms_report_stage_files_and_no_primary(tmp_path, monkeypatch):
    """Lifecycle analysis ignores the requested path and writes per-stage
    documents, so it must report those and never nominate one as *the* BOM."""
    from depscan.lib import bom as bom_mod

    monkeypatch.setattr(bom_mod, "create_blint_bom", lambda *a, **k: False)

    prebuild = str(tmp_path / "sbom-prebuild-rust.cdx.json")
    build = str(tmp_path / "sbom-build-rust.cdx.json")
    options = {
        "prebuild_bom_file": prebuild,
        "build_bom_file": build,
        "postbuild_bom_file": str(tmp_path / "sbom-postbuild-rust.cdx.json"),
        "container_bom_file": str(tmp_path / "sbom-container-rust.cdx.json"),
        "reachability_analyzer": "off",
    }
    result = bom_mod.create_lifecycle_boms(_fake_generator(), str(tmp_path), options)

    assert result.success is True
    assert result.bom_files == [build, prebuild]
    assert result.primary is None, "no single lifecycle document represents the project"


def test_lifecycle_boms_report_failure_when_every_stage_fails(tmp_path, monkeypatch):
    from depscan.lib import bom as bom_mod

    monkeypatch.setattr(bom_mod, "create_blint_bom", lambda *a, **k: False)

    options = {
        "prebuild_bom_file": str(tmp_path / "sbom-prebuild-rust.cdx.json"),
        "build_bom_file": str(tmp_path / "sbom-build-rust.cdx.json"),
        "postbuild_bom_file": str(tmp_path / "sbom-postbuild-rust.cdx.json"),
        "container_bom_file": str(tmp_path / "sbom-container-rust.cdx.json"),
        "reachability_analyzer": "off",
    }
    result = bom_mod.create_lifecycle_boms(
        _fake_generator(success=False, writes=False), str(tmp_path), options
    )

    assert result.success is False
    assert result.bom_files == []
    assert result.primary is None


def test_lifecycle_boms_record_a_failed_sub_run_with_its_budget(tmp_path, monkeypatch):
    """A lifecycle stage that fails and falls back leaves a named trace.

    The build stage's cdxgen run failing used to leave only a debug log; the
    scan continued on the pre-build document and the manifest read as a
    complete inventory. The failed sub-run is now kept as a not-assessed
    reason, with the cdxgen exit status and the time budget that was in
    effect.
    """
    from types import SimpleNamespace

    from depscan.lib import bom as bom_mod

    monkeypatch.setattr(bom_mod, "create_blint_bom", lambda *a, **k: False)
    monkeypatch.delenv("DEPSCAN_SOURCE_IMAGE", raising=False)

    class BuildFails:
        def __init__(self, src_dir, bom_file, logger=None, options=None):
            self.bom_file = bom_file
            self.options = options or {}

        def generate(self):
            if self.options.get("lifecycles") == ["build"]:
                return SimpleNamespace(success=False, returncode=1, command_output="boom")
            with open(self.bom_file, "w") as fh:
                json.dump({"bomFormat": "CycloneDX", "specVersion": "1.6"}, fh)
            return SimpleNamespace(success=True, returncode=0, command_output="")

    prebuild = str(tmp_path / "sbom-prebuild-rust.cdx.json")
    options = {
        "prebuild_bom_file": prebuild,
        "build_bom_file": str(tmp_path / "sbom-build-rust.cdx.json"),
        "postbuild_bom_file": str(tmp_path / "sbom-postbuild-rust.cdx.json"),
        "container_bom_file": str(tmp_path / "sbom-container-rust.cdx.json"),
        "reachability_analyzer": "off",
    }
    result = bom_mod.create_lifecycle_boms(BuildFails, str(tmp_path), options)

    assert result.success is True
    assert result.bom_files == [prebuild]
    # The stubbed blint run adds the post-build reason beside the build one.
    build_reasons = [r for r in result.not_assessed if "the build lifecycle" in r]
    assert len(build_reasons) == 1
    reason = build_reasons[0]
    assert "exited with status 1" in reason
    assert "CDXGEN_TIMEOUT_MS" in reason
    assert any("post-build" in r for r in result.not_assessed)


def test_update_tools_metadata_adds_metadata_to_a_bom_without_one():
    """CycloneDX makes metadata optional; a source BOM without it must not
    crash the VDR export."""
    bom = update_tools_metadata(
        None, {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}, "7.0.0"
    )
    assert bom["metadata"]["tools"]["components"][0]["name"] == "owasp-depscan"
    assert bom["specVersion"] == "1.6"


@pytest.mark.parametrize(
    "project_type, kosi_expected, golem_expected",
    [("go", False, True), ("kotlin", True, False), ("python", False, False)],
)
def test_lifecycle_boms_guard_each_reachability_tool_by_its_types(
    tmp_path, monkeypatch, project_type, kosi_expected, golem_expected
):
    """The lifecycle run hands the build BOM to exactly the tools the scan's
    project types select; the tools that were not selected get no adapter
    result at all, while a selected one is recorded even when it produced no
    report, as not assessed."""
    from depscan.lib import bom as bom_mod

    monkeypatch.setattr(bom_mod, "create_blint_bom", lambda *a, **k: False)
    for name in ("RUSI_TOOL", "GOLEM_TOOL", "KOSI_TOOL", "DOSAI_TOOL"):
        tool = getattr(bom_mod, name)
        monkeypatch.setattr(
            bom_mod, name, dataclasses.replace(tool, run_fallback=lambda *a, **k: None)
        )
    options = {
        "project_type": [project_type],
        "prebuild_bom_file": str(tmp_path / "sbom-prebuild.cdx.json"),
        "build_bom_file": str(tmp_path / "sbom-build.cdx.json"),
        "postbuild_bom_file": str(tmp_path / "sbom-postbuild.cdx.json"),
        "container_bom_file": str(tmp_path / "sbom-container.cdx.json"),
    }
    result = bom_mod.create_lifecycle_boms(_fake_generator(), str(tmp_path), options)
    assert ("kosi" in result.adapter_results) is kosi_expected
    assert ("golem" in result.adapter_results) is golem_expected


def test_a_pure_java_gradle_project_does_not_select_kosi():
    from depscan.lib import bom as bom_mod

    assert "gradle" not in bom_mod.KOSI_TOOL.project_types
    assert {"kotlin", "kt", "android"} <= set(bom_mod.KOSI_TOOL.project_types)


def test_a_tool_slice_from_an_earlier_scan_is_removed(tmp_path):
    from depscan.lib import bom as bom_mod

    bom_file = tmp_path / "sbom-kotlin.cdx.json"
    bom_file.write_text("{}")
    stale = tmp_path / bom_mod.KOSI_TOOL.slice_file
    stale.write_text("{}")
    # The tool applies but reachability is off: no slice may remain.
    assert (
        bom_mod.run_kosi_reachability(
            str(bom_file),
            str(tmp_path),
            options={"project_type": ["kotlin"], "reachability_analyzer": "off"},
        )
        is None
    )
    assert not stale.exists()


def test_a_tool_slice_is_removed_when_the_tool_produces_no_report(tmp_path, monkeypatch):
    from depscan.lib import bom as bom_mod

    bom_file = tmp_path / "sbom-kotlin.cdx.json"
    bom_file.write_text("{}")
    stale = tmp_path / bom_mod.KOSI_TOOL.slice_file
    stale.write_text("{}")
    monkeypatch.setattr(
        bom_mod,
        "KOSI_TOOL",
        dataclasses.replace(bom_mod.KOSI_TOOL, run_fallback=lambda *a, **k: None),
    )
    result = bom_mod.run_kosi_reachability(
        str(bom_file), str(tmp_path), options={"project_type": ["kotlin"]}
    )
    assert result is not None and result.status == "not-assessed"
    assert result.reason
    assert not stale.exists()


def test_clear_tool_outputs_removes_the_evidence_files(tmp_path):
    """The store and its index are this scan's outputs: an earlier run's files
    in a reused reports directory would be merged into the new store as if
    this scan had produced those records."""
    from depscan.lib import bom as bom_mod
    from depscan.lib.scan_directory import EVIDENCE_FILE, EVIDENCE_INDEX_FILE

    for name in (
        EVIDENCE_FILE,
        EVIDENCE_INDEX_FILE,
        "dotnet-reachables.slices.json",
        "go-reachables.slices.json",
    ):
        (tmp_path / name).write_text("[]")
    bom_mod.clear_tool_outputs(str(tmp_path))
    assert not (tmp_path / EVIDENCE_FILE).exists()
    assert not (tmp_path / EVIDENCE_INDEX_FILE).exists()
    assert not (tmp_path / "dotnet-reachables.slices.json").exists()
    assert not (tmp_path / "go-reachables.slices.json").exists()


def test_clear_tool_outputs_removes_the_semantics_reports_cdxgen_persisted(tmp_path):
    """cdxgen persists a language tool's raw report as
    ``<prefix>-semantics.slices.json``, and the tool step reads that file
    before it runs the tool. A source scan of a reused reports directory must
    not find an earlier run's report there, so the setup cleanup removes it
    with the other tool outputs, and leaves atom's own slices alone."""
    from depscan.lib import bom as bom_mod

    for name in (
        "dotnet-semantics.slices.json",
        "rust-semantics.slices.json",
        "python-semantics.slices.json",
        "python-reachables.slices.json",
    ):
        (tmp_path / name).write_text("{}")
    bom_mod.clear_tool_outputs(str(tmp_path))
    assert not (tmp_path / "dotnet-semantics.slices.json").exists()
    assert not (tmp_path / "rust-semantics.slices.json").exists()
    assert not (tmp_path / "python-semantics.slices.json").exists()
    assert (tmp_path / "python-reachables.slices.json").exists(), (
        "atom's slices of the scanned type are cleared by their own step"
    )


def test_a_tool_slice_of_another_type_is_not_removed_by_an_unrelated_tool(tmp_path):
    from depscan.lib import bom as bom_mod

    bom_file = tmp_path / "sbom-go.cdx.json"
    bom_file.write_text("{}")
    other = tmp_path / bom_mod.KOSI_TOOL.slice_file
    other.write_text("{}")
    bom_mod.run_golem_reachability(
        str(bom_file),
        str(tmp_path),
        options={"project_type": ["go"], "reachability_analyzer": "off"},
    )
    assert other.exists()


def test_the_tool_step_hands_the_scanned_source_directory_to_the_adapter(tmp_path, monkeypatch):
    """A language tool's raw report names files under the directory the tool
    scanned. The tool step passes that directory to the adapter as its
    source root, so the records' locations are made relative to it."""
    import shutil

    from analysis_lib.evidence.adapters import golem as golem_adapter
    from depscan.lib import bom as bom_mod

    seen = {}
    real_extract = golem_adapter.extract

    def spy(report, **kwargs):
        seen.update(kwargs)
        return real_extract(report, **kwargs)

    monkeypatch.setattr(golem_adapter, "extract", spy)
    recording = (
        Path(__file__).resolve().parent.parent
        / "packages"
        / "analysis-lib"
        / "tests"
        / "data"
        / "golem"
        / "golem-reachable-app.json"
    )
    bom_file = tmp_path / "sbom-go.cdx.json"
    bom_file.write_text(
        json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []})
    )
    shutil.copyfile(recording, tmp_path / "go-semantics.slices.json")
    result = bom_mod.run_golem_reachability(
        str(bom_file),
        "/src/repos/reachable-app",
        options={"project_type": ["go"], "reachability_analyzer": "SemanticReachability"},
    )
    assert result is not None and result.status == "completed", result and result.reason
    assert seen["source_root"] == "/src/repos/reachable-app"
    for record in result.records:
        for location in record.locations:
            assert not location.file.startswith("/"), location.file
