"""End-to-end tests of the verb command line through ``depscan.cli.main``.

Every verb is driven the way a user drives it: ``sys.argv`` is set, ``main``
runs, the exit code and the output are asserted. Anything expensive or
external (the vulnerability database, cdxgen, the server, the doctor probes)
is stubbed with recorded calls, and each stub has a positive control proving
it ran.
"""

import json
import sys
from importlib import resources
from pathlib import Path
from types import SimpleNamespace

import pytest

from analysis_lib.findings.schemas import (
    load_schema,
    schema_names,
    schema_summaries,
    validate,
)
from depscan import api, cli
from depscan.lib import doctor as doctor_mod
from depscan.lib import pipeline, vdb_setup

DATA_DIR = Path(__file__).parent / "data"
FIXTURE_DIR = DATA_DIR / "scan-directory"
# The VDR fixture that satisfies the bundled CycloneDX schema. The scan
# directory's own django-app.vdr.json carries dep-scan's vendor extensions
# (fixed_location, insights, matched_by) and empty timestamps, which the
# strict schema rejects, so it is not a valid-by-construction input.
VDR_FIXTURE = DATA_DIR / "jinja-report.vdr.json"

MIGRATION_GUIDE = "https://depscan.readthedocs.io/migrate-v6-to-v7/"


def run_main(monkeypatch, argv):
    """Run ``main`` with ``argv`` after the program name; the exit code."""
    monkeypatch.setattr(sys, "argv", ["depscan", *argv])
    with pytest.raises(SystemExit) as excinfo:
        cli.main()
    return excinfo.value.code


# --- the top-level dispatch ------------------------------------------------------


def test_help_flag_prints_the_v7_help(monkeypatch, capsys):
    assert run_main(monkeypatch, ["-h"]) == 0
    out = capsys.readouterr().out
    assert "usage: depscan" in out
    for verb in (
        "scan",
        "report",
        "vdb",
        "doctor",
        "schema",
        "config",
        "serve",
        "validate",
        "version",
        "help",
    ):
        assert verb in out


def test_bare_depscan_is_a_usage_error(monkeypatch, capsys):
    assert run_main(monkeypatch, []) == 2
    captured = capsys.readouterr()
    assert "usage: depscan" in captured.err
    assert "{scan,report,vdb,doctor,schema,config,serve,validate,version,help}" in captured.err


def test_unknown_verb_is_a_usage_error(monkeypatch, capsys):
    assert run_main(monkeypatch, ["frobnicate"]) == 2
    assert "invalid choice: 'frobnicate'" in capsys.readouterr().err


def test_help_verb_prints_one_verbs_help(monkeypatch, capsys):
    assert run_main(monkeypatch, ["help", "schema"]) == 0
    assert "usage: depscan schema" in capsys.readouterr().out


def test_help_verb_json_prints_the_help_as_one_document(monkeypatch, capsys):
    assert run_main(monkeypatch, ["help", "--format", "json"]) == 0
    document = json.loads(capsys.readouterr().out)
    assert set(document) == {"help"}
    assert "usage: depscan" in document["help"]
    for verb in (
        "scan",
        "report",
        "vdb",
        "doctor",
        "schema",
        "config",
        "serve",
        "validate",
        "version",
        "help",
    ):
        assert verb in document["help"]


def test_help_verb_json_prints_one_verbs_help(monkeypatch, capsys):
    assert run_main(monkeypatch, ["help", "schema", "--format", "json"]) == 0
    document = json.loads(capsys.readouterr().out)
    assert "usage: depscan schema" in document["help"]


# --- v6 invocations --------------------------------------------------------------


def test_v6_invocation_exits_two_with_the_translation(monkeypatch, capsys):
    code = run_main(monkeypatch, ["--bom-dir", "x", "-o", "y"])
    assert code == 2
    err = capsys.readouterr().err
    assert "this is a dep-scan 6 command line" in err
    assert (
        "The equivalent v7 command is: depscan scan x --target-kind bom-dir --reports-dir y" in err
    )
    assert MIGRATION_GUIDE in err


def test_v6_server_invocation_names_the_serve_verb(monkeypatch, capsys):
    code = run_main(monkeypatch, ["--server", "--server-host", "0.0.0.0"])
    assert code == 2
    err = capsys.readouterr().err
    assert "The equivalent v7 command is: depscan serve --server-host 0.0.0.0" in err
    assert MIGRATION_GUIDE in err


def test_v6_invocation_without_a_translation_still_names_a_way_forward(monkeypatch, capsys):
    code = run_main(monkeypatch, ["--definitely-not-a-v6-option"])
    assert code == 2
    err = capsys.readouterr().err
    assert "this is a dep-scan 6 command line" in err
    assert "Re-run the command with a verb, for example: depscan scan --help" in err
    assert MIGRATION_GUIDE in err


# --- version ---------------------------------------------------------------------


def test_version_text(monkeypatch, capsys):
    def refuse():
        raise AssertionError("the doctor report is collected only in json mode")

    monkeypatch.setattr(doctor_mod, "doctor", refuse)
    assert run_main(monkeypatch, ["version"]) == 0
    out = capsys.readouterr().out.strip()
    assert out.startswith("depscan ")
    assert len(out.split()) == 2


def test_version_json(monkeypatch, capsys):
    calls = []

    def fake_doctor():
        calls.append(1)
        return SimpleNamespace(
            tools=[
                doctor_mod.ToolStatus(name="cdxgen", version="11.1.0"),
                doctor_mod.ToolStatus(name="rusi"),
            ]
        )

    monkeypatch.setattr(doctor_mod, "doctor", fake_doctor)
    assert run_main(monkeypatch, ["version", "--format", "json"]) == 0
    document = json.loads(capsys.readouterr().out)
    assert document["version"]
    assert document["tools"] == {"cdxgen": "11.1.0", "rusi": None}
    assert calls, "the doctor report was never collected"


# --- schema ----------------------------------------------------------------------


def test_schema_lists_the_names(monkeypatch, capsys):
    assert run_main(monkeypatch, ["schema"]) == 0
    assert capsys.readouterr().out.split() == schema_names()


def test_schema_lists_every_file_in_the_directory(monkeypatch, capsys):
    assert run_main(monkeypatch, ["schema"]) == 0
    assert capsys.readouterr().out.split() == schema_names()
    # A schema file that exists but is not listed is the regression this
    # test watches for: the fingerprint vectors file sat unlisted for a
    # release.
    directory = resources.files("analysis_lib.findings").joinpath("schemas")
    files = {item.name for item in directory.iterdir() if item.name.endswith(".json")}
    listed = {load_schema(name)["$id"].rsplit("/", 1)[-1] for name in schema_names()}
    assert listed == files


def test_schema_names_json_lists_name_id_and_title(monkeypatch, capsys):
    assert run_main(monkeypatch, ["schema", "--format", "json"]) == 0
    document = json.loads(capsys.readouterr().out)
    assert [entry["name"] for entry in document["schemas"]] == schema_names()
    for entry in document["schemas"]:
        schema = load_schema(entry["name"])
        assert entry["$id"] == schema["$id"]
        assert entry["title"] == schema["title"]
    validate("depscan-schema-output", document)


@pytest.mark.parametrize("fmt", ["text", "json"])
def test_schema_prints_one_document(monkeypatch, capsys, fmt):
    assert run_main(monkeypatch, ["schema", "finding", "--format", fmt]) == 0
    assert json.loads(capsys.readouterr().out) == load_schema("finding")


def test_schema_prints_every_published_document(monkeypatch, capsys):
    for name in schema_names():
        assert run_main(monkeypatch, ["schema", name]) == 0
        assert json.loads(capsys.readouterr().out) == load_schema(name)


def test_schema_unknown_name_exits_two(monkeypatch, capsys):
    assert run_main(monkeypatch, ["schema", "nope"]) == 2
    err = capsys.readouterr().err
    assert "unknown schema 'nope'" in err
    for name in schema_names():
        assert name in err


def test_schema_unknown_name_json_writes_the_error_document(monkeypatch, capsys):
    assert run_main(monkeypatch, ["schema", "nope", "--format", "json"]) == 2
    captured = capsys.readouterr()
    document = json.loads(captured.out)
    assert document["error"]["exitCode"] == 2
    assert document["error"]["verb"] == "schema"
    assert "unknown schema 'nope'" in document["error"]["message"]
    validate("depscan-error", document)
    # The same message goes to stderr as text, and stderr stays free of JSON.
    assert "unknown schema 'nope'" in captured.err
    with pytest.raises(ValueError):
        json.loads(captured.err)


# --- config show -----------------------------------------------------------------


@pytest.fixture
def clean_option_env(monkeypatch):
    """Remove every environment variable that feeds an internal option default."""
    from depscan.commands.config import DEST_TO_ENV

    for env_var in set(DEST_TO_ENV.values()):
        monkeypatch.delenv(env_var, raising=False)


def test_config_show_sources(monkeypatch, capsys, tmp_path, clean_option_env):
    config_file = tmp_path / "depscan.toml"
    config_file.write_text('severity = "high"\n')
    monkeypatch.setenv("DEPSCAN_RUSI_BACKEND", "compiler")
    code = run_main(
        monkeypatch,
        ["config", "show", "--reports-dir", "x", "--config", str(config_file)],
    )
    assert code == 0
    rows = {
        line.split()[0]: line for line in capsys.readouterr().out.splitlines()[1:] if line.strip()
    }
    assert "command line" in rows["reports_dir"]
    assert '"x"' in rows["reports_dir"]
    assert "environment" in rows["rust_analyzer_backend"]
    assert "depscan.toml" in rows["severity"]
    assert "default" in rows["spec_version"]


def test_config_show_json(monkeypatch, capsys, tmp_path, clean_option_env):
    config_file = tmp_path / "depscan.toml"
    config_file.write_text('severity = "high"\n')
    monkeypatch.setenv("DEPSCAN_RUSI_BACKEND", "compiler")
    code = run_main(
        monkeypatch,
        [
            "config",
            "show",
            "--reports-dir",
            "x",
            "--config",
            str(config_file),
            "--format",
            "json",
        ],
    )
    assert code == 0
    options = json.loads(capsys.readouterr().out)["options"]
    assert options["reports_dir"] == {"value": "x", "source": "command line"}
    assert options["severity"] == {"value": "high", "source": "depscan.toml"}
    assert options["rust_analyzer_backend"] == {"value": "compiler", "source": "environment"}
    assert options["spec_version"] == {"value": "1.6", "source": "default"}
    # Every internal option is listed, in the internal parser's order.
    assert list(options) == [
        "config",
        "no_banner",
        "src_dir_image",
        "reports_dir",
        "csaf",
        "csaf_version",
        "profile",
        "lifecycles",
        "techniques",
        "bom_engine",
        "vuln_analyzer",
        "reachability_analyzer",
        "rust_analyzer_backend",
        "go_analyzer_network",
        "go_analyzer_cgo",
        "dotnet_analyzer_mode",
        "suggest",
        "risk_audit",
        "fail_on_error",
        "cdxgen_args",
        "spec_version",
        "private_ns",
        "project_type",
        "exclude_types",
        "bom",
        "bom_dir",
        "search_purl",
        "custom_data",
        "report_template",
        "report_name",
        "deep_scan",
        "fuzzy_search",
        "search_order",
        "severity",
        "malware_only",
        "vdb_flavor",
        "vdb_scope",
        "vdb_time",
        "vdb_extended",
        "vdb_compression",
        "vdb_distro",
        "vdb_image",
        "vdb_offline",
        "non_universal_scan",
        "no_vuln_table",
        "server_mode",
        "server_host",
        "server_port",
        "server_allowed_hosts",
        "server_allowed_paths",
        "cdxgen_server",
        "enable_debug",
        "quiet",
        "explain",
        "explanation_mode",
        "annotate",
    ]


def test_config_show_maps_bom_profile_onto_the_internal_profile(
    monkeypatch, capsys, clean_option_env
):
    """v6's ``--profile`` is v7's ``--bom-profile``; the internal dest stays
    ``profile`` and the v7 scan profile is not an internal option."""
    code = run_main(
        monkeypatch, ["config", "show", "--bom-profile", "research", "--format", "json"]
    )
    assert code == 0
    options = json.loads(capsys.readouterr().out)["options"]
    assert options["profile"] == {"value": "research", "source": "command line"}
    assert "checks" not in options
    assert "target_kind" not in options


def test_config_command_line_wins_over_the_toml_file(
    monkeypatch, capsys, tmp_path, clean_option_env
):
    config_file = tmp_path / "depscan.toml"
    config_file.write_text('reports_dir = "/from/the/toml"\n')
    code = run_main(
        monkeypatch,
        ["config", "show", "--reports-dir", "/from/the/cli", "--config", str(config_file)],
    )
    assert code == 0
    out = capsys.readouterr().out
    assert "/from/the/cli" in out
    assert "/from/the/toml" not in out


# --- config init -----------------------------------------------------------------


def test_config_init_writes_and_refuses(monkeypatch, capsys, tmp_path, clean_option_env):
    monkeypatch.chdir(tmp_path)
    code = run_main(monkeypatch, ["config", "init", "--format", "json"])
    assert code == 0
    written = json.loads(capsys.readouterr().out)["written"]
    assert written.endswith("depscan.toml")
    config = (tmp_path / "depscan.toml").read_text()
    assert "no_banner" not in config
    assert 'profile = "generic"' in config

    code = run_main(monkeypatch, ["config", "init"])
    assert code == 1
    err = capsys.readouterr().err
    assert "already exists" in err
    assert "not overwriting" in err


# --- serve -----------------------------------------------------------------------


@pytest.fixture
def serve_stubs(monkeypatch):
    """Stub the server start and the database stage it prepares; record both."""
    calls = {"server": [], "database": 0}

    def fake_start(ctx):
        calls["server"].append(ctx)
        return 0

    def fake_database(ctx):
        calls["database"] += 1

    monkeypatch.setattr(pipeline, "start_server_mode", fake_start)
    monkeypatch.setattr(pipeline, "stage_database", fake_database)
    return calls


def test_serve_starts_the_server_with_the_given_address(monkeypatch, capsys, serve_stubs):
    code = run_main(
        monkeypatch,
        ["serve", "--server-host", "0.0.0.0", "--server-port", "9999", "--format", "json"],
    )
    assert code == 0
    captured = capsys.readouterr()
    # The startup line is the only stdout content; the database stage's own
    # logging stays on stderr, inside the stubbed server start.
    assert captured.out == '{"serve": "0.0.0.0:9999"}\n'
    # Positive controls: the server was started once, in server mode, with
    # the passed address, and the verb did not run the database stage itself
    # (start_server_mode owns it, so a stale database downloads once).
    assert len(serve_stubs["server"]) == 1
    args = serve_stubs["server"][0].args
    assert args.server_mode is True
    assert args.server_host == "0.0.0.0"
    assert args.server_port == "9999"
    assert serve_stubs["database"] == 0


def test_serve_passes_only_what_was_set(monkeypatch, capsys, serve_stubs):
    """Without --server-host the internal namespace keeps the env-backed default."""
    code = run_main(monkeypatch, ["serve"])
    assert code == 0
    captured = capsys.readouterr()
    # Text mode writes nothing to stdout; the server's own logging reports
    # the startup.
    assert captured.out == ""
    args = serve_stubs["server"][0].args
    assert args.server_mode is True
    assert args.server_host == "127.0.0.1"
    assert args.server_port == "7070"
    assert serve_stubs["database"] == 0


def test_serve_reports_a_failed_database_stage(monkeypatch, capsys, serve_stubs):
    def failing(ctx):
        raise pipeline.ScanStageError("the database could not be prepared")

    monkeypatch.setattr(pipeline, "start_server_mode", failing)
    code = run_main(monkeypatch, ["serve"])
    assert code == 1


def test_serve_returns_four_when_the_server_cannot_start(monkeypatch, capsys, serve_stubs):
    """A server that cannot run (missing packages, refused bind) exits 4."""
    monkeypatch.setattr(pipeline, "start_server_mode", lambda ctx: False)
    code = run_main(monkeypatch, ["serve"])
    assert code == 4


def test_serve_returns_four_in_json_mode_too(monkeypatch, capsys, serve_stubs):
    monkeypatch.setattr(pipeline, "start_server_mode", lambda ctx: False)
    code = run_main(monkeypatch, ["serve", "--format", "json"])
    assert code == 4
    # The startup line precedes the start attempt, so it is already on
    # stdout when the start is refused; the exit code carries the failure.
    assert capsys.readouterr().out == '{"serve": "127.0.0.1:7070"}\n'


# --- vdb -------------------------------------------------------------------------


@pytest.fixture
def vdb_home(tmp_path, monkeypatch):
    home = tmp_path.resolve() / "vdb-home"
    home.mkdir()
    import vdb.lib.config as vdb_config
    from vdb.lib import db as db_lib

    monkeypatch.setenv("VDB_HOME", str(home))
    monkeypatch.setattr(vdb_config, "DATA_DIR", str(home))
    monkeypatch.setattr(vdb_config, "VDB_BIN_FILE", str(home / "data.vdb7"))
    monkeypatch.setattr(vdb_config, "VDB_BIN_INDEX", str(home / "data.index.vdb7"))
    monkeypatch.setattr(vdb_config, "VDB_SHARDS_DIR", str(home / "shards"))
    yield home
    db_lib.reset_connections()


def test_vdb_path_json(monkeypatch, capsys, vdb_home):
    assert run_main(monkeypatch, ["vdb", "path", "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out) == {"path": str(vdb_home)}


def test_vdb_info_json(monkeypatch, capsys, vdb_home):
    from depscan import vdb_cli

    monkeypatch.setattr(
        vdb_cli.db_lib,
        "get_db_file_metadata",
        lambda: {
            "created_utc": "2026-11-14T10:00:00+00:00",
            "cve_data_count": 100,
            "cve_index_count": 99,
        },
    )
    monkeypatch.setattr(vdb_cli.db_lib, "needs_update", lambda **kw: False)
    monkeypatch.setattr(
        vdb_cli.db_cmd,
        "store_status",
        lambda store_dir=None: {"store_dir": str(vdb_home / "shards"), "shards": []},
    )
    assert run_main(monkeypatch, ["vdb", "info", "--format", "json"]) == 0
    document = json.loads(capsys.readouterr().out)
    assert document["vdbHome"] == str(vdb_home)
    assert document["mainDb"]["dataRows"] == 100
    assert document["mainDb"]["indexRows"] == 99
    assert document["shardStore"]["shards"] == []


def test_vdb_info_text(monkeypatch, capsys, vdb_home):
    from depscan import vdb_cli

    monkeypatch.setattr(vdb_cli.db_lib, "get_db_file_metadata", lambda: None)
    monkeypatch.setattr(
        vdb_cli.db_cmd,
        "store_status",
        lambda store_dir=None: {"store_dir": str(vdb_home / "shards"), "shards": []},
    )
    assert run_main(monkeypatch, ["vdb", "info"]) == 0
    out = capsys.readouterr().out
    assert f"VDB_HOME: {vdb_home}" in out
    assert "(no database found)" in out
    assert "Shard store:       empty" in out


def test_vdb_download_json(monkeypatch, capsys, vdb_home):
    from depscan.lib import vdb_setup
    from depscan.lib.config import read_vdb_image_marker

    calls = []

    def fake_download(url):
        calls.append(url)
        return {"image": url}

    monkeypatch.setattr(vdb_setup, "download_vdb_with_retries", fake_download)
    code = run_main(monkeypatch, ["vdb", "download", "--flavor", "app-only", "--format", "json"])
    assert code == 0
    document = json.loads(capsys.readouterr().out)
    assert document["image"] == "ghcr.io/appthreat/vdb7-app-only:v7.0.x-xz"
    # Positive controls: the download ran with the flavor's URL and the
    # marker records it.
    assert calls == ["ghcr.io/appthreat/vdb7-app-only:v7.0.x-xz"]
    assert read_vdb_image_marker(str(vdb_home)) == "ghcr.io/appthreat/vdb7-app-only:v7.0.x-xz"
    assert document["marker"] == str(vdb_home / ".depscan-vdb-image")


# --- the download hint names the v7 command --------------------------------------


def test_download_failure_hint_names_the_v7_command(monkeypatch, caplog):
    """The pipeline's download-failure log points at ``depscan vdb download``."""
    calls = []

    def failing_download(url):
        calls.append(url)
        raise ConnectionError("Connection broken")

    monkeypatch.setattr(
        vdb_setup, "resolve_scan_vdb_image", lambda args: ("oras://vdb", False, "app-only")
    )
    monkeypatch.setattr(vdb_setup, "vdb_download_needed", lambda url, d: (True, "stale"))
    monkeypatch.setattr(vdb_setup, "download_vdb_with_retries", failing_download)
    monkeypatch.setattr(pipeline, "VDB_USE_SHARDS", False)
    ctx = pipeline.build_context(api.scan_options(no_banner=True))
    with caplog.at_level("ERROR", logger=pipeline.LOG.name):
        with pytest.raises(pipeline.ScanStageError):
            pipeline.stage_database(ctx)
    # Positive control: the download was attempted once, with the resolved URL.
    assert calls == ["oras://vdb"]
    errors = [record.getMessage() for record in caplog.records if record.levelno == 40]
    assert any(
        "download it first with `depscan vdb download` and run the scan again" in message
        for message in errors
    )


# --- validate --------------------------------------------------------------------


def test_validate_vdr_fixture_text(monkeypatch, capsys):
    assert run_main(monkeypatch, ["validate", str(VDR_FIXTURE)]) == 0
    out = capsys.readouterr().out
    assert "[VALID]   " in out
    assert "cyclonedx" in out


def test_validate_vdr_fixture_json(monkeypatch, capsys):
    code = run_main(monkeypatch, ["validate", str(VDR_FIXTURE), "--format", "json"])
    assert code == 0
    document = json.loads(capsys.readouterr().out)
    assert document == [
        {"file": str(VDR_FIXTURE), "format": "cyclonedx", "valid": True, "errors": []}
    ]


def test_validate_invalid_document_text(monkeypatch, capsys, tmp_path):
    document = json.loads(VDR_FIXTURE.read_text())
    document["specVersion"] = "9.9"
    broken = tmp_path / "broken.vdr.json"
    broken.write_text(json.dumps(document))
    code = run_main(monkeypatch, ["validate", str(broken)])
    assert code == 1
    out = capsys.readouterr().out
    assert "[INVALID]" in out
    assert "unsupported CycloneDX specVersion '9.9'" in out


def test_validate_invalid_document_json(monkeypatch, capsys, tmp_path):
    document = json.loads(VDR_FIXTURE.read_text())
    document["specVersion"] = "9.9"
    broken = tmp_path / "broken.vdr.json"
    broken.write_text(json.dumps(document))
    code = run_main(monkeypatch, ["validate", str(broken), "--format", "json"])
    assert code == 1
    entries = json.loads(capsys.readouterr().out)
    assert entries[0]["valid"] is False
    assert entries[0]["errors"]
    assert any("specVersion" in error for error in entries[0]["errors"])


# --- doctor ----------------------------------------------------------------------


@pytest.fixture
def fixed_doctor_report(monkeypatch):
    tools = {
        name: doctor_mod.ToolStatus(name=name, path=f"/bin/{name}", source="path")
        for name in ("cdxgen", "golem", "go", "dosai", "dotnet")
    }
    report = doctor_mod.DoctorReport(
        schema_version="1",
        depscan_version="7.0.0",
        platform={"os": "linux", "arch": "x86_64", "libc": "glibc"},
        tools=list(tools.values()),
        data={
            "vulnerabilityDatabase": {
                "present": True,
                "directory": "/tmp/vdb",
                "image": "ghcr.io/appthreat/vdb7-app-only:v7.0.x-xz",
                "flavor": "app-only",
                "shards": {"enabled": False, "present": []},
                "createdUtc": "2026-11-01T00:00:00+00:00",
                "ageHours": 10.0,
                "stale": False,
                "maxAgeHours": 48,
                "cveDataCount": 100,
                "cveIndexCount": 100,
                "extendedMetadataPresent": False,
                "cveMetadataRows": 0,
            }
        },
        capabilities=doctor_mod._evaluate_capabilities(
            tools,
            {
                "vulnerabilityDatabase": {
                    "present": True,
                    "cveIndexCount": 100,
                }
            },
        ),
    )
    calls = []

    def fake_doctor():
        calls.append(1)
        return report

    monkeypatch.setattr(doctor_mod, "doctor", fake_doctor)
    return {"report": report, "calls": calls}


def test_doctor_json_through_the_registry(monkeypatch, capsys, fixed_doctor_report):
    assert run_main(monkeypatch, ["doctor", "--format", "json"]) == 0
    document = json.loads(capsys.readouterr().out)
    validate("depscan-doctor", document)
    assert document["schemaVersion"] == "1"
    # Positive control: the dispatched command collected the report once.
    assert fixed_doctor_report["calls"] == [1]


# --- report ----------------------------------------------------------------------


def test_report_json_prints_one_document(monkeypatch, capsys):
    assert run_main(monkeypatch, ["report", "--format", "json", str(FIXTURE_DIR)]) == 0
    document = json.loads(capsys.readouterr().out)
    assert set(document) == {"scanDir", "manifest", "findings"}
    assert document["manifest"]["layoutVersion"] == "1.0"
    assert len(document["findings"]) == 1
    validate("finding", document["findings"][0])


def test_report_text_still_renders_the_tables(monkeypatch, capsys):
    assert run_main(monkeypatch, ["report", str(FIXTURE_DIR)]) == 0
    out = capsys.readouterr().out
    assert "Vulnerabilities count: 1" in out
    assert "high: 1" in out


# --- the scan verb ----------------------------------------------------------------
# The scan verb's own tests live in test_v7_scan.py.


def test_scan_unknown_check_is_a_usage_error(monkeypatch, capsys):
    code = run_main(monkeypatch, ["scan", ".", "--checks", "bogus"])
    assert code == 2
    err = capsys.readouterr().err
    assert "unknown check bogus" in err
    assert "vulnerabilities" in err and "reachability" in err


def test_scan_unknown_profile_is_a_usage_error(monkeypatch, capsys):
    code = run_main(monkeypatch, ["scan", ".", "--profile", "bogus"])
    assert code == 2
    assert "invalid choice: 'bogus'" in capsys.readouterr().err


def test_config_show_reports_what_a_profile_and_checks_set(monkeypatch, capsys, clean_option_env):
    """``config show`` resolves --profile and --checks the way the scan verb
    does, so the printed options are the ones a scan would use."""
    code = run_main(
        monkeypatch,
        [
            "config",
            "show",
            "--profile",
            "deep",
            "--reachability-analyzer",
            "off",
            "--format",
            "json",
        ],
    )
    assert code == 0
    options = json.loads(capsys.readouterr().out)["options"]
    assert options["risk_audit"] == {"value": True, "source": "checks or profile"}
    assert "license" in options["project_type"]["value"]
    # The explicit option wins over the profile, and says so.
    assert options["reachability_analyzer"] == {"value": "off", "source": "command line"}


def test_config_show_refuses_an_unknown_check(monkeypatch, capsys, clean_option_env):
    code = run_main(monkeypatch, ["config", "show", "--checks", "vulnerabilitys"])
    assert code == 2
    assert "unknown check vulnerabilitys" in capsys.readouterr().err
