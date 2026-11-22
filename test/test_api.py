"""Unit tests for the public Python API in depscan.api.

The scan tests stub the database helpers and the vulnerability analyzer the
same way the pipeline tests do, so no test here touches the network or a host
database. Every stub records its calls and the tests assert the recording,
which proves the stub ran.
"""

import json
import os
import shutil
from pathlib import Path

import pytest

from depscan import api
from depscan.lib import pipeline, vdb_setup

DATA_DIR = Path(__file__).parent / "data"


def _write_bom(path, components=None):
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {"component": {"name": "app", "type": "application"}},
        "components": components
        if components is not None
        else [
            {
                "name": "time",
                "version": "0.1.45",
                "purl": "pkg:cargo/time@0.1.45",
                "bom-ref": "pkg:cargo/time@0.1.45",
                "type": "library",
            }
        ],
    }
    with open(path, "w") as fh:
        json.dump(bom, fh)
    return str(path)


# Hand-authored vulnerabilities, shaped like the objects the VDR writer
# serialises: id, bom-ref, affects refs, ratings and references ids.
VULN_REQUESTS = {
    "id": "CVE-2024-1111",
    "bom-ref": "CVE-2024-1111/pkg:pypi/requests@2.32.1",
    "affects": [{"ref": "pkg:pypi/requests@2.32.1"}],
    "ratings": [{"severity": "high", "score": 8.1, "method": "CVSSv31"}],
    "references": [{"id": "GHSA-AAAA-BBBB-CCCC"}],
}
VULN_BABEL = {
    "id": "CVE-2024-2222",
    "bom-ref": "CVE-2024-2222/pkg:npm/%40babel/core@7.21.4",
    "affects": [{"ref": "pkg:npm/%40babel/core@7.21.4"}],
    "ratings": [
        {"severity": "low", "score": 3.1, "method": "CVSSv31"},
        {"severity": "high", "score": 8.8, "method": "CVSSv31"},
    ],
    "references": [],
}


class _StubVdrResult:
    success = True
    prioritized_pkg_vuln_trees = {}
    exploitability = None

    def __init__(self, pkg_vulnerabilities, success=True):
        self.pkg_vulnerabilities = pkg_vulnerabilities
        self.success = success


@pytest.fixture
def scan_calls(monkeypatch):
    """Stub the database and the analyzer of a scan and record every call."""
    calls = {"analyzer": [], "database": []}

    monkeypatch.setattr(
        vdb_setup, "resolve_scan_vdb_image", lambda args: ("oras://vdb", False, "full")
    )
    monkeypatch.setattr(vdb_setup, "vdb_download_needed", lambda url, d: (False, ""))
    monkeypatch.setattr(vdb_setup, "configure_vdb_readonly", lambda: None)
    monkeypatch.setattr(vdb_setup, "ensure_vdb_usable", lambda: calls["database"].append(1))
    monkeypatch.setattr(pipeline, "get_pkgs_by_scope", lambda pkg_list: {})
    monkeypatch.setattr(
        pipeline,
        "get_pkg_list",
        lambda f: ([{"purl": "pkg:pypi/requests@2.32.1", "name": "requests"}], []),
    )
    monkeypatch.setattr(pipeline.ReportGenerator, "parse_and_generate_report", lambda self: None)
    monkeypatch.setattr(pipeline.console, "save_html", lambda *a, **k: None)
    monkeypatch.setattr(pipeline.console, "save_text", lambda *a, **k: None)

    class StubVDRAnalyzer:
        def __init__(self, vdr_options):
            calls["analyzer"].append(dict(vars(vdr_options)))

        def process(self):
            return _StubVdrResult([dict(VULN_REQUESTS), dict(VULN_BABEL)])

    monkeypatch.setattr(pipeline, "VDRAnalyzer", StubVDRAnalyzer)
    return calls


def _result_with_vulns(reports_dir, vulns, project_type="rust"):
    result = api.ScanResult(reports_dir=str(reports_dir))
    result.types = [api.TypeScanResult(project_type=project_type, vulnerabilities=vulns)]
    return result


# ---------------------------------------------------------------------------
# scan_options
# ---------------------------------------------------------------------------


def test_scan_options_returns_the_cli_defaults():
    from depscan.cli_options import build_parser

    defaults = vars(build_parser().parse_args([]))
    assert vars(api.scan_options()) == defaults


def test_scan_options_applies_overrides():
    options = api.scan_options(bom="bom.json", no_banner=True, search_purl="pkg:pypi/x@1")
    assert options.bom == "bom.json"
    assert options.no_banner is True
    assert options.search_purl == "pkg:pypi/x@1"
    # Untouched options keep their defaults.
    assert options.suggest is True


def test_scan_options_rejects_an_unknown_name():
    with pytest.raises(TypeError) as excinfo:
        api.scan_options(bom="bom.json", not_an_option=1)
    assert "not_an_option" in str(excinfo.value)


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------


def test_scan_returns_a_result_per_type(scan_calls, tmp_path):
    bom = _write_bom(tmp_path / "given.cdx.json")
    reports = tmp_path / "reports"
    result = api.scan(api.scan_options(bom=bom, reports_dir=str(reports), no_banner=True))

    # Positive controls: the stubbed analyzer and database guard both ran.
    assert scan_calls["analyzer"], "the matching stage never ran"
    assert scan_calls["database"], "the database stage never ran"

    assert result.reports_dir == str(reports)
    assert result.project_types == ["bom"]
    assert len(result.types) == 1
    tscan = result.types[0]
    assert tscan.project_type == "bom"
    assert tscan.bom_file == bom
    assert tscan.vdr_file == str(reports / "given.vdr.json")
    assert tscan.vulnerabilities == [VULN_REQUESTS, VULN_BABEL]
    assert result.vulnerabilities == tscan.vulnerabilities


def test_scan_result_vulnerabilities_are_what_the_vdr_file_carries(scan_calls, tmp_path):
    bom = _write_bom(tmp_path / "given.cdx.json")
    reports = tmp_path / "reports"
    result = api.scan(api.scan_options(bom=bom, reports_dir=str(reports), no_banner=True))

    vdr_file = result.types[0].vdr_file
    assert vdr_file is not None
    with open(vdr_file) as fh:
        vdr = json.load(fh)
    assert vdr["vulnerabilities"] == result.types[0].vulnerabilities


def test_scan_render_false_skips_the_rendering_but_writes_the_vdr(scan_calls, tmp_path):
    bom = _write_bom(tmp_path / "given.cdx.json")
    reports = tmp_path / "reports"
    options = api.scan_options(bom=bom, reports_dir=str(reports), no_banner=True)
    result = api.scan(options, render=False)

    assert result.types[0].vdr_file is not None
    assert os.path.exists(result.types[0].vdr_file)
    assert not os.path.exists(reports / "depscan.html")
    assert not os.path.exists(reports / "depscan.txt")
    # The console tables are rendering too, so the option is forced on.
    assert options.no_vuln_table is True
    assert result.vulnerabilities == [VULN_REQUESTS, VULN_BABEL]


def test_scan_raises_scan_error_when_a_stage_stops(tmp_path):
    with pytest.raises(api.ScanError) as excinfo:
        api.scan(
            api.scan_options(
                bom=str(tmp_path / "nope.json"), reports_dir=str(tmp_path / "reports")
            )
        )
    assert "does not exist" in str(excinfo.value)


def test_scan_error_carries_the_message_the_stage_logged(scan_calls, tmp_path, monkeypatch):
    monkeypatch.setattr(pipeline, "get_pkg_list", lambda f: ([], []))
    bom = _write_bom(tmp_path / "given.cdx.json")
    options = api.scan_options(
        bom=bom, reports_dir=str(tmp_path / "reports"), no_banner=True, fail_on_error=True
    )
    with pytest.raises(api.ScanError) as excinfo:
        api.scan(options)
    assert "No packages were found" in str(excinfo.value)


# ---------------------------------------------------------------------------
# load_scan
# ---------------------------------------------------------------------------


def test_load_scan_round_trips_a_scan(scan_calls, tmp_path):
    bom = _write_bom(tmp_path / "given.cdx.json")
    reports = tmp_path / "reports"
    result = api.scan(api.scan_options(bom=bom, reports_dir=str(reports), no_banner=True))

    loaded = api.load_scan(str(reports))
    assert loaded.reports_dir == str(reports)
    assert loaded.vulnerabilities == result.vulnerabilities
    assert loaded.types[0].vdr_file == result.types[0].vdr_file
    # A --bom scan keeps its BOM wherever the caller passed it, so the
    # reports directory records only the VDR.
    assert loaded.types[0].bom_file is None


def test_load_scan_on_an_empty_directory_raises(tmp_path):
    empty = tmp_path / "empty-reports"
    empty.mkdir()
    with pytest.raises(api.ScanError) as excinfo:
        api.load_scan(str(empty))
    assert "no VDR file" in str(excinfo.value)
    assert str(empty) in str(excinfo.value)


def test_load_scan_reads_todays_layout(tmp_path):
    reports = tmp_path / "reports"
    reports.mkdir()
    for name, vulns in (
        ("depscan-universal.vdr.json", [{"id": "CVE-1"}]),
        ("sbom-rust.vdr.json", [{"id": "CVE-2"}]),
    ):
        (reports / name).write_text(
            json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "vulnerabilities": vulns})
        )
    _write_bom(reports / "sbom-rust.cdx.json")
    # Neither a risk report nor a BOM without vulnerabilities is a VDR.
    (reports / "depscan-risk-rust.json").write_text(json.dumps({"risks": []}))
    _write_bom(reports / "sbom-java.cdx.json")

    loaded = api.load_scan(str(reports))
    assert loaded.project_types == ["bom", "rust"]
    by_type = {t.project_type: t for t in loaded.types}
    assert by_type["bom"].vulnerabilities == [{"id": "CVE-1"}]
    assert by_type["bom"].bom_file is None
    assert by_type["rust"].vulnerabilities == [{"id": "CVE-2"}]
    assert by_type["rust"].bom_file == str(reports / "sbom-rust.cdx.json")
    assert by_type["rust"].vdr_file == str(reports / "sbom-rust.vdr.json")


# ---------------------------------------------------------------------------
# query
# ---------------------------------------------------------------------------


def test_query_with_no_filters_returns_every_vulnerability():
    result = _result_with_vulns("reports", [VULN_REQUESTS, VULN_BABEL])
    assert api.query(result) == [VULN_REQUESTS, VULN_BABEL]


def test_query_purl_matches_the_exact_version_only():
    result = _result_with_vulns("reports", [VULN_REQUESTS, VULN_BABEL])
    # Only the version differs from the affected requests purl.
    assert api.query(result, purl="pkg:pypi/requests@2.32.0") == []
    assert api.query(result, purl="pkg:pypi/requests@2.32.1") == [VULN_REQUESTS]


def test_query_purl_without_a_version_matches_every_version():
    result = _result_with_vulns("reports", [VULN_REQUESTS, VULN_BABEL])
    assert api.query(result, purl="pkg:pypi/requests") == [VULN_REQUESTS]
    # The encoded and decoded spellings of a namespace are the same package.
    assert api.query(result, purl="pkg:npm/@babel/core") == [VULN_BABEL]
    assert api.query(result, purl="pkg:npm/%40babel/core") == [VULN_BABEL]


def test_query_vuln_id_matches_references_ignoring_case():
    result = _result_with_vulns("reports", [VULN_REQUESTS, VULN_BABEL])
    assert api.query(result, vuln_id="cve-2024-1111") == [VULN_REQUESTS]
    # The id appears only under references, not as the vulnerability id.
    assert api.query(result, vuln_id="ghsa-aaaa-bbbb-cccc") == [VULN_REQUESTS]
    assert api.query(result, vuln_id="CVE-2024-9999") == []


def test_query_severities_match_the_highest_rating():
    result = _result_with_vulns("reports", [VULN_REQUESTS, VULN_BABEL])
    # VULN_BABEL carries a low and a high rating; the higher score wins, so
    # a filter for the low rating must not match it.
    assert api.query(result, severities={"low"}) == []
    assert api.query(result, severities={"high"}) == [VULN_REQUESTS, VULN_BABEL]
    assert api.query(result, severities={"HIGH", "critical"}) == [VULN_REQUESTS, VULN_BABEL]
    assert api.query(result, severities={"info"}) == []


def test_query_severities_ignore_a_vulnerability_without_ratings():
    unrated = {"id": "CVE-2024-3333", "affects": [{"ref": "pkg:pypi/requests@2.32.1"}]}
    result = _result_with_vulns("reports", [VULN_REQUESTS, unrated])
    assert api.query(result, severities={"high", "unknown"}) == [VULN_REQUESTS]


def test_query_combines_filters():
    result = _result_with_vulns("reports", [VULN_REQUESTS, VULN_BABEL])
    assert api.query(result, purl="pkg:pypi/requests", vuln_id="CVE-2024-1111") == [VULN_REQUESTS]
    assert api.query(result, purl="pkg:pypi/requests", vuln_id="CVE-2024-2222") == []


# ---------------------------------------------------------------------------
# explain
# ---------------------------------------------------------------------------


def _result_with_rust_evidence(tmp_path, vulns):
    reports = tmp_path / "reports"
    reports.mkdir(exist_ok=True)
    from analysis_lib.evidence import EvidencePathNode, EvidenceProducer
    from analysis_lib.evidence.adapters import build_record
    from analysis_lib.evidence import store as evidence_store

    record = build_record(
        source="evidence.jsonl",
        producer=EvidenceProducer(name="rusi", version="9.9.9", report_schema_version="1"),
        kind="reached-flow",
        discriminator="rusi-sqlx",
        purls=("pkg:cargo/sqlx@0.6.2",),
        path=(
            EvidencePathNode(file="src/main.rs", line=11, method="main"),
            EvidencePathNode(file="src/main.rs", line=14, method="main", symbol="sqlx::query"),
        ),
    )
    evidence_store.write(str(reports / evidence_store.EVIDENCE_FILE), [record])
    return _result_with_vulns(reports, vulns, project_type="rust")


def test_explain_returns_the_rendered_text(tmp_path):
    vuln = {
        "id": "CVE-2024-SQLX",
        "affects": [{"ref": "pkg:cargo/sqlx@0.6.2"}],
        "ratings": [{"severity": "high", "score": 8.0}],
    }
    result = _result_with_rust_evidence(tmp_path, [vuln])
    text = api.explain(result)
    assert text.strip()
    assert "src/main.rs" in text
    assert "pkg:cargo/sqlx@0.6.2" in text
    # The returned text is plain, whatever console colours are in play.
    assert "\x1b" not in text


def test_explain_raises_when_nothing_can_be_explained(tmp_path):
    result = _result_with_vulns(tmp_path, [VULN_REQUESTS])
    with pytest.raises(api.ScanError) as excinfo:
        api.explain(result)
    assert "evidence store" in str(excinfo.value)


def test_explain_on_a_loaded_scan_names_what_is_missing(scan_calls, tmp_path):
    bom = _write_bom(tmp_path / "given.cdx.json")
    reports = tmp_path / "reports"
    api.scan(api.scan_options(bom=bom, reports_dir=str(reports), no_banner=True))
    loaded = api.load_scan(str(reports))
    with pytest.raises(api.ScanError) as excinfo:
        api.explain(loaded)
    # The scan wrote the (empty) store, so the message names the gates the
    # records did not meet, not a missing file.
    assert "no evidence record met the rendering gates" in str(excinfo.value)


def test_explain_endpoints_mode_names_the_missing_specification(tmp_path):
    result = _result_with_vulns(tmp_path, [VULN_REQUESTS])
    with pytest.raises(api.ScanError) as excinfo:
        api.explain(result, mode="Endpoints")
    assert "OpenAPI specification" in str(excinfo.value)


# ---------------------------------------------------------------------------
# diff
# ---------------------------------------------------------------------------


def _vuln(vid, ref, severity="high", score=7.0):
    return {
        "id": vid,
        "affects": [{"ref": ref}],
        "ratings": [{"severity": severity, "score": score}],
    }


def test_diff_reports_new_and_fixed():
    old = _result_with_vulns("reports", [_vuln("CVE-1", "pkg:pypi/a@1")])
    new = _result_with_vulns("reports", [_vuln("CVE-2", "pkg:pypi/b@1")])
    result = api.diff(old, new)
    assert [(e.id, e.ref) for e in result.new] == [("CVE-2", "pkg:pypi/b@1")]
    assert [(e.id, e.ref) for e in result.fixed] == [("CVE-1", "pkg:pypi/a@1")]
    assert result.new[0].old is None and result.fixed[0].new is None
    assert result.changed == []


def test_diff_changed_pairs_carry_both_sides():
    old = _result_with_vulns("reports", [_vuln("CVE-1", "pkg:pypi/a@1", score=5.0)])
    new = _result_with_vulns("reports", [_vuln("CVE-1", "pkg:pypi/a@1", score=9.9)])
    result = api.diff(old, new)
    assert result.new == [] and result.fixed == []
    assert len(result.changed) == 1
    entry = result.changed[0]
    assert entry.old is not None and entry.new is not None
    assert entry.old["ratings"][0]["score"] == 5.0
    assert entry.new["ratings"][0]["score"] == 9.9


def test_diff_changed_on_severity_alone():
    old = _result_with_vulns("reports", [_vuln("CVE-1", "pkg:pypi/a@1", severity="low")])
    new = _result_with_vulns("reports", [_vuln("CVE-1", "pkg:pypi/a@1", severity="critical")])
    assert len(api.diff(old, new).changed) == 1
    old = _result_with_vulns("reports", [_vuln("CVE-1", "pkg:pypi/a@1", severity="high")])
    new = _result_with_vulns("reports", [_vuln("CVE-1", "pkg:pypi/a@1", severity="high")])
    assert api.diff(old, new).changed == []


def test_diff_keys_on_the_id_and_ref_pair_not_the_purl_alone():
    """Two advisories on one package: a key of the purl alone would collapse
    them and hide the fixed advisory; the (id, ref) key keeps them apart."""
    old = _result_with_vulns(
        "reports", [_vuln("CVE-1", "pkg:pypi/a@1"), _vuln("CVE-2", "pkg:pypi/a@1")]
    )
    new = _result_with_vulns("reports", [_vuln("CVE-1", "pkg:pypi/a@1")])
    result = api.diff(old, new)
    assert [e.id for e in result.fixed] == ["CVE-2"]
    assert result.changed == []


def test_diff_keys_on_each_affected_ref():
    """One advisory affecting two components: only the component it stopped
    affecting is reported as fixed."""
    both = [
        {
            "id": "CVE-1",
            "affects": [{"ref": "pkg:pypi/a@1"}, {"ref": "pkg:pypi/b@1"}],
            "ratings": [{"severity": "high", "score": 7.0}],
        }
    ]
    only_a = [_vuln("CVE-1", "pkg:pypi/a@1")]
    result = api.diff(_result_with_vulns("reports", both), _result_with_vulns("reports", only_a))
    assert [(e.id, e.ref) for e in result.fixed] == [("CVE-1", "pkg:pypi/b@1")]
    assert result.new == [] and result.changed == []


# ---------------------------------------------------------------------------
# the server's BOM scanner
# ---------------------------------------------------------------------------


def test_build_server_bom_scanner_scans_through_the_api(monkeypatch, tmp_path):
    recorded = {}

    def fake_run_stages(options, *, render, database):
        recorded["options"] = vars(options).copy()
        recorded["render"] = render
        recorded["database"] = database
        return _result_with_vulns(tmp_path, [VULN_REQUESTS])

    monkeypatch.setattr(api, "_run_stages", fake_run_stages)
    scanner = pipeline.build_server_bom_scanner()
    vulns = scanner("bom.json", str(tmp_path / "req-reports"), "js", suggest_mode=True)

    # Positive control: the scan went through the API, not around it.
    assert recorded, "depscan.api.scan was never called"
    assert recorded["render"] is False
    # The server prepares the database once at start; a request never does.
    assert recorded["database"] is False
    options = recorded["options"]
    assert options["bom"] == "bom.json"
    assert options["reports_dir"] == str(tmp_path / "req-reports")
    assert options["project_type"] == ["js"]
    assert options["suggest"] is True
    assert options["no_banner"] is True
    # The server never ran reachability, risk audit or the CLI search order.
    assert options["reachability_analyzer"] == "off"
    assert options["risk_audit"] is False
    assert options["fail_on_error"] is False
    assert options["search_order"] is None
    assert vulns == [VULN_REQUESTS]


def test_requests_skip_the_database_stage(monkeypatch, tmp_path):
    called = []
    monkeypatch.setattr(pipeline, "stage_database", lambda ctx: called.append("database"))

    def stop_after_setup(ctx):
        called.append("finalize")
        raise pipeline.ScanStageError("stop here")

    monkeypatch.setattr(pipeline, "finalize_setup", stop_after_setup)
    options = api.scan_options(bom=str(tmp_path / "missing.json"), no_banner=True)
    monkeypatch.setattr(pipeline, "validate_scan_inputs", lambda args: [])
    with pytest.raises(api.ScanError):
        api._run_stages(options, render=False, database=False)
    # Positive control: the stages after the database stage did run.
    assert called == ["finalize"]
    called.clear()
    with pytest.raises(api.ScanError):
        api.scan(options, render=False)
    assert called == ["database", "finalize"]


def test_server_start_prepares_the_database_before_serving(monkeypatch):
    if not pipeline.SERVER_LIB:
        pytest.skip("server-lib is not installed")
    order = []
    monkeypatch.setattr(pipeline, "stage_database", lambda ctx: order.append("database"))
    monkeypatch.setattr(pipeline.simple, "run_server", lambda options: order.append("serve"))
    ctx = pipeline.build_context(api.scan_options(server_mode=True))
    pipeline.start_server_mode(ctx)
    assert order == ["database", "serve"]


def test_server_does_not_start_without_a_database(monkeypatch):
    if not pipeline.SERVER_LIB:
        pytest.skip("server-lib is not installed")
    served = []

    def no_database(ctx):
        raise pipeline.ScanStageError("no database")

    monkeypatch.setattr(pipeline, "stage_database", no_database)
    monkeypatch.setattr(pipeline.simple, "run_server", lambda options: served.append(options))
    ctx = pipeline.build_context(api.scan_options(server_mode=True))
    with pytest.raises(pipeline.ScanStageError):
        pipeline.start_server_mode(ctx)
    assert served == []


def test_query_takes_a_single_severity_name_and_refuses_an_empty_set():
    result = _result_with_vulns("reports", [_vuln("CVE-1", "pkg:pypi/a@1", severity="high")])
    assert [v["id"] for v in api.query(result, severities="high")] == ["CVE-1"]
    assert api.query(result, severities="low") == []
    with pytest.raises(ValueError):
        api.query(result, severities=set())


def test_query_ranks_severity_before_score():
    vuln = {
        "id": "CVE-1",
        "affects": [{"ref": "pkg:pypi/a@1"}],
        "ratings": [{"severity": "critical"}, {"severity": "low", "score": 2.0}],
    }
    result = _result_with_vulns("reports", [vuln])
    assert api.query(result, severities={"critical"}) == [vuln]
    assert api.query(result, severities={"low"}) == []


def test_query_purl_qualifiers_must_match_when_given():
    vuln = _vuln("CVE-1", "pkg:maven/org.a/b@1.0?type=jar")
    result = _result_with_vulns("reports", [vuln])
    assert api.query(result, purl="pkg:maven/org.a/b@1.0?type=jar") == [vuln]
    assert api.query(result, purl="pkg:maven/org.a/b@1.0?type=pom") == []
    # A purl without qualifiers matches any.
    assert api.query(result, purl="pkg:maven/org.a/b@1.0") == [vuln]


def test_unusable_database_raises_scan_error_not_system_exit(scan_calls, monkeypatch, tmp_path):
    def unusable():
        raise vdb_setup.VdbUnusableError("The vulnerability database is empty.")

    monkeypatch.setattr(vdb_setup, "ensure_vdb_usable", unusable)
    bom = Path(__file__).parent / "data" / "bom-js.json"
    options = api.scan_options(bom=str(bom), reports_dir=str(tmp_path), no_banner=True)
    with pytest.raises(api.ScanError, match="database is empty"):
        api.scan(options, render=False)


def test_vdr_file_is_none_when_no_vdr_was_written(scan_calls, monkeypatch, tmp_path):
    class NothingFound:
        def __init__(self, vdr_options):
            pass

        def process(self):
            return _StubVdrResult(None, success=False)

    monkeypatch.setattr(pipeline, "VDRAnalyzer", NothingFound)
    bom = Path(__file__).parent / "data" / "bom-js.json"
    options = api.scan_options(bom=str(bom), reports_dir=str(tmp_path), no_banner=True)
    result = api.scan(options, render=False)
    assert result.types, "the type must still be reported"
    assert all(t.vdr_file is None for t in result.types)
    assert result.vulnerabilities == []


def test_server_scanner_drops_the_console_recording(monkeypatch, tmp_path):
    def records(options, *, render, database):
        pipeline.console.record = True
        pipeline.console.print("recorded during a request")
        recorded.append(len(pipeline.console._record_buffer))
        return _result_with_vulns(tmp_path, [])

    recorded = []

    monkeypatch.setattr(api, "_run_stages", records)
    monkeypatch.setattr(pipeline.console, "record", False)
    scanner = pipeline.build_server_bom_scanner()
    scanner("bom.json", str(tmp_path), "js")
    assert pipeline.console.record is False
    # Positive control: the request did record, and the buffer was emptied.
    assert recorded and recorded[0] > 0
    assert pipeline.console._record_buffer == []
