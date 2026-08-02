import json
import os

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

    monkeypatch.setattr(bom_mod, "CdxgenGenerator", _fake_generator())
    monkeypatch.setattr(bom_mod, "run_rusi_reachability", lambda *a, **k: None)
    monkeypatch.setattr(bom_mod, "run_golem_reachability", lambda *a, **k: None)
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

    monkeypatch.setattr(bom_mod, "CdxgenGenerator", _fake_generator(success=True, writes=False))

    target = str(tmp_path / "sbom-rust.cdx.json")
    result = bom_mod.create_bom(target, str(tmp_path), {})

    assert result.success is False
    assert result.bom_files == []
    assert result.primary is None


def test_create_bom_reports_failure_when_generator_fails(tmp_path, monkeypatch):
    from depscan.lib import bom as bom_mod

    monkeypatch.setattr(bom_mod, "CdxgenGenerator", _fake_generator(success=False, writes=False))

    result = bom_mod.create_bom(str(tmp_path / "sbom.cdx.json"), str(tmp_path), {})

    assert result.success is False
    assert result.primary is None


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
