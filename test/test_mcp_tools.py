"""The ten MCP tools, driven through the SDK's in-memory client session.

Every call goes over the protocol the way a client drives the server: the
server is built with :func:`depscan.mcp_server.server.build_server`, the
client session initializes over the in-memory transport, and the tool
result is read from the call result's text and validated against the
tool's published output schema. The scan directories are produced the way
``test/test_v7_scan.py`` produces them: a real ``api.scan`` whose database,
matching, risk audit and cdxgen process are stubbed with recorded calls,
so every document a tool reads back was written by the scan pipeline
itself.

On Windows the tmp paths keep their backslashes; every path a document
carries (scanDir, file, target) is compared in the forward-slash form
:func:`depscan.commands.output.json_path` produces, never as escaped JSON
text.
"""

import asyncio
import dataclasses
import base64
import contextlib
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from mcp import ClientSession
from mcp import types as mcp_types
from mcp.client._memory import InMemoryTransport

from analysis_lib.findings.schemas import validate
from depscan import api
from depscan.commands.output import json_path
from depscan.lib import bom as bom_mod
from depscan.lib import doctor as doctor_mod
from depscan.lib import pipeline, vdb_setup
from depscan.mcp_server import server as server_mod
from xbom_lib import cdxgen as cdxgen_mod

REPO_ROOT = Path(__file__).parent.parent
DATA_DIR = Path(__file__).parent / "data"

#: The response budget the server is specified to keep, pinned here as the
#: published number rather than imported from the implementation.
TOOL_BUDGET_BYTES = 32 * 1024

#: The tools the four later tasks own. None of them may be registered.
FORBIDDEN_TOOLS = ("get_evidence", "policy_status", "remediation_plan", "record_triage")

#: The ten tools of this prompt, in registration order.
TOOL_NAMES = (
    "scan_summary",
    "list_findings",
    "get_finding",
    "explain_finding",
    "coverage",
    "list_components",
    "diff_scans",
    "doctor",
    "vdb_status",
    "run_scan",
)

BOM_DOCUMENT = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "metadata": {"component": {"name": "app", "type": "application"}},
    "components": [
        {
            "name": "requests",
            "version": "2.32.1",
            "purl": "pkg:pypi/requests@2.32.1",
            "bom-ref": "pkg:pypi/requests@2.32.1",
            "type": "library",
        }
    ],
}

VULN_HIGH = {
    "id": "CVE-2024-1111",
    "bom-ref": "CVE-2024-1111/pkg:pypi/requests@2.32.1",
    "affects": [{"ref": "pkg:pypi/requests@2.32.1"}],
    "ratings": [{"severity": "high", "score": 8.1, "method": "CVSSv31"}],
    "fixed_location": "2.32.2",
}

VULN_LOW = {
    "id": "CVE-2024-2222",
    "bom-ref": "CVE-2024-2222/pkg:pypi/requests@2.32.1",
    "affects": [{"ref": "pkg:pypi/requests@2.32.1"}],
    "ratings": [{"severity": "low", "score": 3.7, "method": "CVSSv31"}],
}

VULN_CRITICAL = {
    "id": "CVE-2024-1111",
    "bom-ref": "CVE-2024-1111/pkg:pypi/requests@2.32.1",
    "affects": [{"ref": "pkg:pypi/requests@2.32.1"}],
    "ratings": [{"severity": "critical", "score": 9.8, "method": "CVSSv31"}],
    "fixed_location": "2.32.2",
}

VULN_NEW = {
    "id": "CVE-2024-3333",
    "bom-ref": "CVE-2024-3333/pkg:pypi/requests@2.32.1",
    "affects": [{"ref": "pkg:pypi/requests@2.32.1"}],
    "ratings": [{"severity": "medium", "score": 6.0, "method": "CVSSv31"}],
}

FULL_VDB_DATA = {
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


# --- the fixtures -------------------------------------------------------------------


class _StubVdrResult:
    success = True
    prioritized_pkg_vuln_trees = {}
    exploitability = None

    def __init__(self, pkg_vulnerabilities):
        self.pkg_vulnerabilities = pkg_vulnerabilities


@pytest.fixture
def scan_stubs(monkeypatch):
    """Stub a scan's database, matching, risk audit and cdxgen process.

    The stubs are the ones ``test/test_v7_scan.py`` uses, with two
    additions for this suite: the matching stage returns the vulnerability
    list the test placed in ``state["vulns"]`` just before running a scan,
    and the fake cdxgen records the environment it was handed, so the
    run_scan tests can prove cdxgen ran in secure mode.
    """
    calls = {"matching": [], "database": [], "cdxgen": [], "risk": []}
    state = {"vulns": [dict(VULN_HIGH)]}

    monkeypatch.setattr(
        vdb_setup, "resolve_scan_vdb_image", lambda args: ("oras://vdb", False, "app-only")
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
    monkeypatch.setattr(pipeline, "risk_audit", lambda *a, **k: calls["risk"].append(1) or {})

    def fake_exec_tool(args, *a, **k):
        # The environment the real exec_tool would hand the process: the
        # caller's env dict when it built one, the process environment
        # otherwise. This is what proves cdxgen ran in secure mode.
        calls["cdxgen"].append(
            {"args": [str(arg) for arg in args], "env": dict(k.get("env") or os.environ)}
        )
        if "-o" not in args:
            # A container pull, which no stub models; a machine without
            # docker fails it the same way.
            return cdxgen_mod.BOMResult(success=False, command_output="pull failed")
        bom_file = args[args.index("-o") + 1]
        Path(bom_file).write_text(json.dumps(BOM_DOCUMENT), encoding="utf-8")
        return cdxgen_mod.BOMResult(success=True, command_output="BOM saved")

    monkeypatch.setattr(cdxgen_mod, "find_cdxgen_cmd", lambda *a, **k: "cdxgen")
    monkeypatch.setattr(cdxgen_mod, "exec_tool", fake_exec_tool)
    monkeypatch.setattr(bom_mod, "_refuse_old_cdxgen", lambda logger=None: True)
    # The bundled-cdxgen branch keeps the local CLI generator on every
    # machine, so the real run_scan below exercises the same cdxgen process
    # path whether or not the machine running the suite has docker.
    monkeypatch.setattr(bom_mod, "_has_bundled_cdxgen", lambda: True)

    class StubVDRAnalyzer:
        def __init__(self, vdr_options):
            calls["matching"].append(vdr_options)
            self.vdr_options = vdr_options

        def process(self):
            vulns = [dict(vuln) for vuln in state["vulns"]]
            # The real analyzer grades the exploitability of its entries from
            # the inputs the pipeline hands it; the stub replaces only the
            # vulnerability search, so it runs the same grading step.
            from analysis_lib.findings.exploitability import annotate_exploitability

            graded = annotate_exploitability(vulns, self.vdr_options.exploitability_inputs)
            result = _StubVdrResult(vulns)
            result.exploitability = graded
            return result

    monkeypatch.setattr(pipeline, "VDRAnalyzer", StubVDRAnalyzer)
    monkeypatch.setattr(doctor_mod, "_vdb_status", lambda: dict(FULL_VDB_DATA))
    # The tool probes stay off, so the manifest's tools list and the
    # analyzer reasons do not depend on the machine the suite runs on.
    python_tool = doctor_mod.ToolStatus(name="python", path=sys.executable, source="runtime")
    monkeypatch.setattr(
        doctor_mod, "build_tools", lambda: ([python_tool], {"python": python_tool})
    )
    return {"calls": calls, "state": state}


@pytest.fixture
def make_scan_dir(tmp_path, scan_stubs):
    """Run one stubbed source scan and return its scan directory.

    ``vulns`` replaces what the matching stage returns, ``name`` places the
    scan under its own directory, and ``checks_not_assessed`` records
    ``check-<name>`` stages the way the scan verb does for checks a doctor
    report turned off.
    """

    def make(name, vulns=None, checks_not_assessed=None):
        if vulns is not None:
            scan_stubs["state"]["vulns"] = [dict(vuln) for vuln in vulns]
        src = tmp_path / "src"
        src.mkdir(exist_ok=True)
        (src / "app.py").write_text("import requests\n", encoding="utf-8")
        reports = tmp_path / name / "reports"
        result = api.scan(
            api.scan_options(
                src_dir_image=str(src),
                project_type=["python"],
                bom_engine="CdxgenGenerator",
                reports_dir=str(reports),
                no_banner=True,
            ),
            checks_not_assessed=checks_not_assessed,
        )
        scan_stubs["state"]["vulns"] = [dict(VULN_HIGH)]
        return Path(result.reports_dir)

    return make


@pytest.fixture
def open_session():
    """A factory for client sessions over the in-memory transport.

    The factory takes the startup roots, the ``--allow-scans`` flag and the
    roots the client announces.
    """

    @contextlib.asynccontextmanager
    async def open_(startup_roots, allow_scans=False, client_roots=None):
        sdk = server_mod.load_mcp_sdk()
        server = server_mod.build_server(sdk, tuple(startup_roots), allow_scans=allow_scans)

        async def announce_roots(context):
            return mcp_types.ListRootsResult(
                roots=[
                    mcp_types.Root(uri=Path(root).resolve().as_uri())
                    for root in client_roots or []
                ]
            )

        async with InMemoryTransport(server) as (read_stream, write_stream):
            async with ClientSession(
                read_stream, write_stream, list_roots_callback=announce_roots
            ) as session:
                await session.initialize()
                yield session

    return open_


def drive(open_session, scenario, startup_roots, **kwargs):
    """Run one scenario against a fresh session."""
    server_roots = tuple(str(root) for root in startup_roots)

    async def runner():
        async with open_session(server_roots, **kwargs) as session:
            return await scenario(session)

    return asyncio.run(runner())


async def call_document(session, name, arguments, output_schema):
    """One tool call, returning the parsed document validated against the
    tool's published output schema; a failed call fails the test here."""
    result = await session.call_tool(name, arguments)
    assert result.is_error is False, [content.text for content in result.content]
    document = json.loads(result.content[0].text)
    validate(output_schema, document)
    return document


async def call_error(session, name, arguments):
    """One tool call expected to fail; the error text the client sees."""
    result = await session.call_tool(name, arguments)
    assert result.is_error is True, [content.text for content in result.content]
    return result.content[0].text


def expected_path(path) -> str:
    """The document form of a local path: absolute with / separators."""
    document_path = json_path(os.path.realpath(str(path)))
    assert document_path is not None
    return document_path


def canonical_args(arguments):
    """The canonical argument string the spill file name digests."""
    return json.dumps(arguments, sort_keys=True, separators=(",", ":"))


def published_findings(scan_dir: Path):
    """The findings document the fixture scan wrote, as a list."""
    document = json.loads((scan_dir / "depscan.findings.json").read_text(encoding="utf-8"))
    return document["findings"]


# --- registration -------------------------------------------------------------------


async def _list_tools(session):
    listing = await session.list_tools()
    return listing


def test_the_server_lists_exactly_the_ten_tools(open_session, tmp_path):
    listing = drive(open_session, _list_tools, (tmp_path,))
    assert [tool.name for tool in listing.tools] == list(TOOL_NAMES)
    assert not [tool.name for tool in listing.tools if tool.name in FORBIDDEN_TOOLS]


async def _input_schema_failures(session):
    listing = await session.list_tools()
    return [
        tool.name
        for tool in listing.tools
        if (tool.input_schema or {}).get("$id")
        != f"urn:owasp:depscan:schema:mcp-{tool.name}-input:1"
    ]


def test_every_tool_advertises_its_published_input_schema(open_session, tmp_path):
    assert drive(open_session, _input_schema_failures, (tmp_path,)) == []


async def _descriptions(session):
    listing = await session.list_tools()
    return {tool.name: tool.description for tool in listing.tools}


def test_the_explain_finding_description_says_the_text_is_scan_wide(open_session, tmp_path):
    descriptions = drive(open_session, _descriptions, (tmp_path,))
    assert "whole scan" in descriptions["explain_finding"]
    assert "the scan's context around the finding" in descriptions["explain_finding"]


# --- scan_summary -------------------------------------------------------------------


async def _scan_summary(session, scan_dir):
    return await call_document(
        session, "scan_summary", {"scan_dir": str(scan_dir)}, "depscan-mcp-scan_summary-output"
    )


def test_scan_summary_counts_the_findings_by_category_and_severity(
    open_session, make_scan_dir, scan_stubs
):
    scan_dir = make_scan_dir("plain")
    # Positive controls: the stubbed matching and database stages ran, so
    # the counts below come from a scan the fixture really produced.
    assert scan_stubs["calls"]["matching"], "the matching stage never ran"
    assert scan_stubs["calls"]["database"], "the database guard never ran"
    document = drive(open_session, _scan_summary_target(scan_dir), (scan_dir.parent,))
    assert document["scanDir"] == expected_path(scan_dir)
    assert document["findingCount"] == 1
    assert document["countsByCategory"] == {"vulnerability": 1}
    assert document["countsBySeverity"] == {"high": 1}


def _scan_summary_target(scan_dir):
    async def scenario(session):
        return await _scan_summary(session, scan_dir)

    return scenario


def test_scan_summary_reports_the_manifest_summary(open_session, make_scan_dir):
    scan_dir = make_scan_dir("plain")
    document = drive(open_session, _scan_summary_target(scan_dir), (scan_dir.parent,))
    summary = document["manifestSummary"]
    assert summary["layoutVersion"] == "1.0"
    assert summary["projectTypes"] == ["python"]
    assert set(summary["stagesByStatus"]) == {"completed", "skipped"}
    assert summary["stagesByStatus"] == {"completed": 7, "skipped": 3}
    assert summary["stageCount"] == 10
    assert summary["inputCount"] == 1
    assert summary["fileCount"] == 4
    assert summary["startUtc"]
    assert summary["endUtc"]


def test_scan_summary_refuses_a_directory_that_is_not_a_scan(open_session, tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()

    async def scenario(session):
        return await call_error(session, "scan_summary", {"scan_dir": str(empty)})

    message = drive(open_session, scenario, (tmp_path,))
    assert "Cannot load a scan" in message
    # The error text names the confined path as the platform spells it; the
    # json_path form is for the fields of json documents only.
    assert os.path.realpath(str(empty)) in message


def test_a_corrupted_findings_document_is_a_tool_error(open_session, make_scan_dir):
    """A depscan.findings.json that is not valid JSON must not serve a
    clean summary or an empty findings page: both tools refuse and name
    the file and the parse failure."""
    scan_dir = make_scan_dir("corrupted-findings")
    (scan_dir / "depscan.findings.json").write_text("{not json at all", encoding="utf-8")

    async def scenario(session):
        summary_error = await call_error(session, "scan_summary", {"scan_dir": str(scan_dir)})
        findings_error = await call_error(session, "list_findings", {"scan_dir": str(scan_dir)})
        return summary_error, findings_error

    summary_error, findings_error = drive(open_session, scenario, (scan_dir.parent,))
    for message in (summary_error, findings_error):
        assert "Cannot load a scan" in message
        assert "depscan.findings.json" in message
        assert "not valid JSON" in message


def test_an_oversized_summary_spills_inside_the_scan_directory(open_session, make_scan_dir):
    """A summary over the response budget spills into the scan directory
    and returns the spill envelope, which the summary's output schema
    carries like every other tool's."""
    scan_dir = make_scan_dir("fat-summary")
    fat_type = "python" + "a" * (TOOL_BUDGET_BYTES + 1000)
    manifest_path = scan_dir / "depscan.manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    stage = next(s for s in manifest["stages"] if s["name"] == "inventory")
    stage["projectType"] = fat_type
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    arguments = {"scan_dir": str(scan_dir)}

    async def scenario(session):
        result = await session.call_tool("scan_summary", arguments)
        assert result.is_error is False, [content.text for content in result.content]
        envelope = json.loads(result.content[0].text)
        validate("depscan-mcp-scan_summary-output", envelope)
        return envelope

    envelope = drive(open_session, scenario, (scan_dir.parent,))
    # The envelope carries only the spill shape, never the summary shape.
    assert "scanDir" not in envelope
    assert "findingCount" not in envelope
    assert envelope["count"] == 1
    assert envelope["file"].startswith(expected_path(scan_dir) + "/mcp/")
    spilled = json.loads(Path(envelope["file"]).read_text(encoding="utf-8"))
    assert spilled["findingCount"] == 1
    # The fat type is the inventory stage's; the later stages still carry
    # the plain one, so both are listed, in first-seen order.
    assert spilled["manifestSummary"]["projectTypes"] == [fat_type, "python"]


# --- list_findings ------------------------------------------------------------------


def test_list_findings_returns_the_findings(open_session, make_scan_dir):
    scan_dir = make_scan_dir("plain")

    async def scenario(session):
        return await call_document(
            session,
            "list_findings",
            {"scan_dir": str(scan_dir)},
            "depscan-mcp-list_findings-output",
        )

    document = drive(open_session, scenario, (scan_dir.parent,))
    assert "nextCursor" not in document
    finding = document["findings"][0]
    assert finding["category"] == "vulnerability"
    assert finding["rule"] == "CVE-2024-1111"
    assert finding["severity"] == "high"
    assert finding["components"] == ["pkg:pypi/requests@2.32.1"]
    assert finding["id"].startswith("dsf1:")


def test_list_findings_pages_with_cursor_and_limit(open_session, make_scan_dir):
    scan_dir = make_scan_dir("two", vulns=[VULN_HIGH, VULN_LOW])

    async def scenario(session):
        first = await call_document(
            session,
            "list_findings",
            {"scan_dir": str(scan_dir), "limit": 1},
            "depscan-mcp-list_findings-output",
        )
        second = await call_document(
            session,
            "list_findings",
            {"scan_dir": str(scan_dir), "limit": 1, "cursor": first["nextCursor"]},
            "depscan-mcp-list_findings-output",
        )
        return first, second

    first, second = drive(open_session, scenario, (scan_dir.parent,))
    assert len(first["findings"]) == 1
    assert first["nextCursor"]
    assert len(second["findings"]) == 1
    assert "nextCursor" not in second
    rules = [first["findings"][0]["rule"], second["findings"][0]["rule"]]
    assert rules == ["CVE-2024-1111", "CVE-2024-2222"]


def test_a_page_past_the_end_is_empty_without_a_cursor(open_session, make_scan_dir):
    scan_dir = make_scan_dir("two", vulns=[VULN_HIGH, VULN_LOW])
    # The cursor format is the base64url encoding of {"o": <offset>}; the
    # offset at the end of the list asks for the page past it.
    past_end = base64.urlsafe_b64encode(b'{"o":2}').decode("ascii").rstrip("=")

    async def scenario(session):
        return await call_document(
            session,
            "list_findings",
            {"scan_dir": str(scan_dir), "limit": 1, "cursor": past_end},
            "depscan-mcp-list_findings-output",
        )

    third = drive(open_session, scenario, (scan_dir.parent,))
    assert third["findings"] == []
    assert "nextCursor" not in third


def test_list_findings_filters_by_the_finding_fields(open_session, make_scan_dir):
    scan_dir = make_scan_dir("two", vulns=[VULN_HIGH, VULN_LOW])

    async def scenario(session):
        def rules(document):
            return [finding["rule"] for finding in document["findings"]]

        async def page(**extra):
            arguments = {"scan_dir": str(scan_dir), **extra}
            return await call_document(
                session, "list_findings", arguments, "depscan-mcp-list_findings-output"
            )

        return {
            "severity_high": rules(await page(severity="high")),
            "severity_low": rules(await page(severity="low")),
            "category_vulnerability": rules(await page(category="vulnerability")),
            "category_license": rules(await page(category="license")),
            "purl_versionless": rules(await page(purl="pkg:pypi/requests")),
            "purl_versioned": rules(await page(purl="pkg:pypi/requests@2.32.1")),
            "purl_other": rules(await page(purl="pkg:npm/lodash@4.17.21")),
            "cwe": rules(await page(cwe=79)),
            "rule": rules(await page(rule="CVE-2024-2222")),
        }

    outcomes = drive(open_session, scenario, (scan_dir.parent,))
    assert outcomes["severity_high"] == ["CVE-2024-1111"]
    assert outcomes["severity_low"] == ["CVE-2024-2222"]
    assert outcomes["category_vulnerability"] == ["CVE-2024-1111", "CVE-2024-2222"]
    assert outcomes["category_license"] == []
    assert outcomes["purl_versionless"] == ["CVE-2024-1111", "CVE-2024-2222"]
    assert outcomes["purl_versioned"] == ["CVE-2024-1111", "CVE-2024-2222"]
    assert outcomes["purl_other"] == []
    assert outcomes["cwe"] == []
    assert outcomes["rule"] == ["CVE-2024-2222"]


def test_the_reachable_filter_matches_only_findings_that_record_it(open_session, make_scan_dir):
    scan_dir = make_scan_dir("two", vulns=[VULN_HIGH, VULN_LOW])
    findings_path = scan_dir / "depscan.findings.json"
    document = json.loads(findings_path.read_text(encoding="utf-8"))
    reachable, unrecorded = document["findings"]
    # The reachability a finding records lives on its exploitability reach
    # axis; a finding without a decided axis matches neither value.
    reachable["exploitability"] = {
        "axes": {
            "presence": "proven",
            "reach": "proven",
            "exposure": "unknown",
            "barrier": "unknown",
        }
    }
    unrecorded["exploitability"] = {
        "axes": {
            "presence": "proven",
            "reach": "unknown",
            "exposure": "unknown",
            "barrier": "unknown",
        }
    }
    findings_path.write_text(json.dumps(document), encoding="utf-8")

    async def scenario(session):
        async def page(**extra):
            arguments = {"scan_dir": str(scan_dir), **extra}
            return await call_document(
                session, "list_findings", arguments, "depscan-mcp-list_findings-output"
            )

        return {
            "reachable_true": [
                finding["rule"] for finding in (await page(reachable=True))["findings"]
            ],
            "reachable_false": [
                finding["rule"] for finding in (await page(reachable=False))["findings"]
            ],
        }

    outcomes = drive(open_session, scenario, (scan_dir.parent,))
    assert outcomes["reachable_true"] == [reachable["rule"]]
    assert outcomes["reachable_false"] == []


def test_the_grade_filter_matches_one_or_more_grades(open_session, make_scan_dir):
    scan_dir = make_scan_dir("graded", vulns=[VULN_HIGH, VULN_LOW])
    findings_path = scan_dir / "depscan.findings.json"
    document = json.loads(findings_path.read_text(encoding="utf-8"))
    high, ungraded = document["findings"]
    high["exploitability"] = {
        "axes": {
            "presence": "proven",
            "reach": "likely",
            "exposure": "likely",
            "barrier": "unknown",
        },
        "grade": "high",
        "rule": "anonymous-route-reached",
        "sources": {"reach": ["atom"], "exposure": ["dosai"]},
    }
    ungraded["exploitability"] = {
        "axes": {
            "presence": "likely",
            "reach": "not_assessed",
            "exposure": "not_assessed",
            "barrier": "not_assessed",
        },
        "grade": "unassessed",
        "rule": "unassessed-cap",
    }
    findings_path.write_text(json.dumps(document), encoding="utf-8")

    async def scenario(session):
        async def page(**extra):
            arguments = {"scan_dir": str(scan_dir), **extra}
            return await call_document(
                session, "list_findings", arguments, "depscan-mcp-list_findings-output"
            )

        return {
            "grade_high": [f["rule"] for f in (await page(grade=["high"]))["findings"]],
            "grade_either": [
                f["rule"] for f in (await page(grade=["high", "unassessed"]))["findings"]
            ],
        }

    outcomes = drive(open_session, scenario, (scan_dir.parent,))
    assert outcomes["grade_high"] == [high["rule"]]
    assert outcomes["grade_either"] == [high["rule"], ungraded["rule"]]


class _StubReachability:
    """A reachability engine that reports the purls the test hands it."""

    def __init__(self, reached, success=True):
        self.reached = reached
        self.success = success

    def process(self):
        return dataclasses.make_dataclass(
            "StubResult",
            [
                "success",
                "direct_purls",
                "reached_purls",
                "reached_services",
                "endpoint_reached_purls",
            ],
        )(self.success, {}, dict(self.reached), {}, {})


@pytest.fixture
def reachability_stub(monkeypatch):
    """Make a stubbed scan's reachability stage report a chosen reached set.

    The fake cdxgen also drops an atom ``python-reachables.slices.json`` next
    to the BOM, the file the enrichment stage reads to record that the atom
    analyzer ran, so the scan's findings are written by the real pipeline.
    """
    state = {"reached": {}, "success": True, "slices": True}
    write_bom = cdxgen_mod.exec_tool

    def exec_with_slices(args, *a, **k):
        result = write_bom(args, *a, **k)
        if state["slices"] and "-o" in args:
            bom_file = Path(args[args.index("-o") + 1])
            # The reach axis reads each analyzer's reached purls from its slice
            # file, so the file carries the purls the stubbed engine reports.
            (bom_file.parent / "python-reachables.slices.json").write_text(
                json.dumps([{"flows": [], "purls": sorted(state["reached"])}]), encoding="utf-8"
            )
        return result

    monkeypatch.setattr(cdxgen_mod, "exec_tool", exec_with_slices)
    monkeypatch.setattr(
        pipeline,
        "get_reachability_impl",
        lambda analyzer, options: _StubReachability(state["reached"], state["success"]),
    )
    return state


def _list_reach(open_session, scan_dir, **filters):
    async def scenario(session):
        document = await call_document(
            session,
            "list_findings",
            {"scan_dir": str(scan_dir), **filters},
            "depscan-mcp-list_findings-output",
        )
        return [finding["rule"] for finding in document["findings"]]

    return drive(open_session, scenario, (scan_dir.parent,))


VULN_UNREACHED = {
    "id": "CVE-2024-4444",
    "bom-ref": "CVE-2024-4444/pkg:pypi/urllib3@2.2.0",
    "affects": [{"ref": "pkg:pypi/urllib3@2.2.0"}],
    "ratings": [{"severity": "medium", "score": 5.0, "method": "CVSSv31"}],
}


def test_a_scan_records_reach_so_the_reachable_filter_matches_end_to_end(
    open_session, make_scan_dir, reachability_stub
):
    """The scan, not the test, writes the exploitability reach axis: a purl in
    the reached set of an analyzer that ran is likely, one absent from that
    non-empty set is unknown, and the filter reads both through the tool."""
    reachability_stub["reached"] = {"pkg:pypi/requests@2.32.1": 2}
    scan_dir = make_scan_dir("reach", vulns=[VULN_HIGH, VULN_UNREACHED])
    by_rule = {finding["rule"]: finding for finding in published_findings(scan_dir)}
    reached = by_rule["CVE-2024-1111"]["exploitability"]
    assert reached["axes"]["reach"] == "likely"
    # The analyzer names moved onto sources; the rule names the table row.
    assert reached["rule"] == "reached"
    assert reached["sources"]["reach"] == ["atom"]
    assert reached["grade"] == "moderate"
    absent = by_rule["CVE-2024-4444"]["exploitability"]
    assert absent["axes"]["reach"] == "unknown"
    for finding in by_rule.values():
        validate("finding", finding)
    assert _list_reach(open_session, scan_dir, reachable=True) == ["CVE-2024-1111"]
    # unknown is not "not reachable": the false filter matches neither finding
    assert _list_reach(open_session, scan_dir, reachable=False) == []


@pytest.mark.parametrize(
    "mode",
    ["no-slices", "engine-failed", "nothing-reached"],
)
def test_a_scan_without_usable_reachability_records_not_assessed(
    open_session, make_scan_dir, reachability_stub, mode
):
    if mode == "no-slices":
        reachability_stub["slices"] = False
        reachability_stub["reached"] = {"pkg:pypi/requests@2.32.1": 2}
    elif mode == "engine-failed":
        reachability_stub["success"] = False
    scan_dir = make_scan_dir(mode, vulns=[VULN_HIGH])
    (finding,) = published_findings(scan_dir)
    assert finding["exploitability"]["axes"]["reach"] == "not_assessed"
    # The database match keeps presence assessed, so the fixed rules cap the
    # grade at moderate instead of grading the finding unassessed.
    assert finding["exploitability"]["grade"] == "moderate"
    assert finding["exploitability"]["unassessed"] == ["reach", "exposure", "barrier"]
    assert _list_reach(open_session, scan_dir, reachable=True) == []
    assert _list_reach(open_session, scan_dir, reachable=False) == []


def test_an_unknown_filter_is_a_tool_error(open_session, make_scan_dir):
    scan_dir = make_scan_dir("plain")

    async def scenario(session):
        return await call_error(
            session, "list_findings", {"scan_dir": str(scan_dir), "filename": "x.json"}
        )

    message = drive(open_session, scenario, (scan_dir.parent,))
    assert "input schema" in message


def test_a_limit_over_the_maximum_is_a_tool_error(open_session, make_scan_dir):
    scan_dir = make_scan_dir("plain")

    async def scenario(session):
        return await call_error(
            session, "list_findings", {"scan_dir": str(scan_dir), "limit": 500}
        )

    message = drive(open_session, scenario, (scan_dir.parent,))
    assert "input schema" in message


def test_an_invalid_cursor_is_a_tool_error(open_session, make_scan_dir):
    scan_dir = make_scan_dir("plain")

    async def scenario(session):
        return await call_error(
            session, "list_findings", {"scan_dir": str(scan_dir), "cursor": "not-a-cursor"}
        )

    message = drive(open_session, scenario, (scan_dir.parent,))
    assert "invalid cursor" in message


def test_an_oversized_page_spills_inside_the_scan_directory(open_session, make_scan_dir):
    fat = dict(VULN_HIGH)
    fat["properties"] = [{"name": "depscan:probe", "value": "a" * 20000}]
    fat_low = dict(VULN_LOW)
    fat_low["properties"] = [{"name": "depscan:probe", "value": "b" * 20000}]
    scan_dir = make_scan_dir("fat", vulns=[fat, fat_low])
    arguments = {"scan_dir": str(scan_dir)}

    async def scenario(session):
        result = await session.call_tool("list_findings", arguments)
        assert result.is_error is False, [content.text for content in result.content]
        envelope = json.loads(result.content[0].text)
        validate("depscan-mcp-list_findings-output", envelope)
        return envelope

    envelope = drive(open_session, scenario, (scan_dir.parent,))
    # The envelope carries only the spill shape, never the page shape.
    assert "findings" not in envelope
    assert "nextCursor" not in envelope
    expected_name = f"list_findings-{hashlib.sha256(canonical_args(arguments).encode('utf-8')).hexdigest()}.json"
    assert envelope["file"].endswith("/mcp/" + expected_name)
    assert envelope["file"].startswith(expected_path(scan_dir) + "/mcp/")
    assert envelope["count"] == 2
    spilled_text = Path(envelope["file"]).read_text(encoding="utf-8")
    spilled = json.loads(spilled_text)
    assert spilled_text == json.dumps(spilled, indent=2) + "\n"
    assert [finding["rule"] for finding in spilled["findings"]] == [
        "CVE-2024-1111",
        "CVE-2024-2222",
    ]
    assert len(spilled_text.encode("utf-8")) > TOOL_BUDGET_BYTES


# --- get_finding --------------------------------------------------------------------


def test_get_finding_returns_one_finding(open_session, make_scan_dir):
    scan_dir = make_scan_dir("plain")
    published = published_findings(scan_dir)[0]

    async def scenario(session):
        return await call_document(
            session,
            "get_finding",
            {"scan_dir": str(scan_dir), "finding_id": published["id"]},
            "depscan-mcp-get_finding-output",
        )

    document = drive(open_session, scenario, (scan_dir.parent,))
    assert document == published


def test_get_finding_refuses_an_unknown_id(open_session, make_scan_dir):
    scan_dir = make_scan_dir("plain")
    missing = "dsf1:" + "0" * 64

    async def scenario(session):
        return await call_error(
            session, "get_finding", {"scan_dir": str(scan_dir), "finding_id": missing}
        )

    message = drive(open_session, scenario, (scan_dir.parent,))
    assert "no finding with id" in message
    assert missing in message


def test_an_oversized_finding_spills_to_a_file(open_session, make_scan_dir):
    """A single finding over the response budget spills into the scan
    directory and returns the spill envelope, validated against the
    get_finding output schema."""
    fat = dict(VULN_HIGH)
    fat["properties"] = [{"name": "depscan:probe", "value": "a" * (TOOL_BUDGET_BYTES + 1000)}]
    scan_dir = make_scan_dir("fat-finding", vulns=[fat])
    published = published_findings(scan_dir)[0]
    arguments = {"scan_dir": str(scan_dir), "finding_id": published["id"]}

    async def scenario(session):
        result = await session.call_tool("get_finding", arguments)
        assert result.is_error is False, [content.text for content in result.content]
        envelope = json.loads(result.content[0].text)
        validate("depscan-mcp-get_finding-output", envelope)
        return envelope

    envelope = drive(open_session, scenario, (scan_dir.parent,))
    # The envelope carries only the spill shape, never the finding itself.
    assert "id" not in envelope
    assert envelope["count"] == 1
    assert envelope["file"].startswith(expected_path(scan_dir) + "/mcp/")
    spilled = json.loads(Path(envelope["file"]).read_text(encoding="utf-8"))
    assert spilled == published


# --- explain_finding ----------------------------------------------------------------


def _first_published(scan_dir):
    return published_findings(scan_dir)[0]


def test_explain_finding_returns_the_finding_and_the_scan_text(open_session, make_scan_dir):
    scan_dir = make_scan_dir("plain")
    published = _first_published(scan_dir)
    # The reachables slices file is what the explanation reads; a scan that
    # ran no reachability analyzer records none, so the fixture plants one.
    (scan_dir / "python-reachables.slices.json").write_bytes(
        (DATA_DIR / "rust-reachables.slices.json").read_bytes()
    )

    async def scenario(session):
        return await call_document(
            session,
            "explain_finding",
            {"scan_dir": str(scan_dir), "finding_id": published["id"]},
            "depscan-mcp-explain_finding-output",
        )

    document = drive(open_session, scenario, (scan_dir.parent,))
    assert document["finding"] == published
    assert document["explanation"].strip()
    assert "src/main.rs" in document["explanation"]
    assert "\x1b" not in document["explanation"]


def test_explain_finding_names_what_is_missing(open_session, make_scan_dir):
    scan_dir = make_scan_dir("plain")
    published = _first_published(scan_dir)

    async def scenario(session):
        return await call_error(
            session,
            "explain_finding",
            {"scan_dir": str(scan_dir), "finding_id": published["id"]},
        )

    message = drive(open_session, scenario, (scan_dir.parent,))
    assert "reachables slices" in message


def test_an_oversized_explanation_spills_to_a_file(open_session, make_scan_dir):
    """A finding and its explanation over the response budget spill into
    the scan directory and return the spill envelope, validated against
    the explain_finding output schema."""
    fat = dict(VULN_HIGH)
    fat["properties"] = [{"name": "depscan:probe", "value": "a" * (TOOL_BUDGET_BYTES + 1000)}]
    scan_dir = make_scan_dir("fat-explain", vulns=[fat])
    published = published_findings(scan_dir)[0]
    (scan_dir / "python-reachables.slices.json").write_bytes(
        (DATA_DIR / "rust-reachables.slices.json").read_bytes()
    )
    arguments = {"scan_dir": str(scan_dir), "finding_id": published["id"]}

    async def scenario(session):
        result = await session.call_tool("explain_finding", arguments)
        assert result.is_error is False, [content.text for content in result.content]
        envelope = json.loads(result.content[0].text)
        validate("depscan-mcp-explain_finding-output", envelope)
        return envelope

    envelope = drive(open_session, scenario, (scan_dir.parent,))
    # The envelope carries only the spill shape, never the document.
    assert "finding" not in envelope
    assert "explanation" not in envelope
    assert envelope["count"] == 1
    assert envelope["file"].startswith(expected_path(scan_dir) + "/mcp/")
    spilled = json.loads(Path(envelope["file"]).read_text(encoding="utf-8"))
    assert spilled["finding"] == published
    assert spilled["explanation"].strip()


# --- coverage ------------------------------------------------------------------------


async def _coverage(session, scan_dir):
    return await call_document(
        session, "coverage", {"scan_dir": str(scan_dir)}, "depscan-mcp-coverage-output"
    )


def _coverage_target(scan_dir):
    async def scenario(session):
        return await _coverage(session, scan_dir)

    return scenario


def test_coverage_reports_stages_reasons_and_checks_not_run(open_session, make_scan_dir):
    scan_dir = make_scan_dir(
        "checked",
        checks_not_assessed=[{"name": "license", "reason": "license analysis was turned off"}],
    )
    document = drive(open_session, _coverage_target(scan_dir), (scan_dir.parent,))
    names = {stage["name"] for stage in document["stages"]}
    assert names == {
        "setup",
        "database",
        "inventory",
        "licenses",
        "risk",
        "enrichment",
        "matching",
        "vdr",
        "explain",
        "render",
        "check-license",
    }
    assert document["scanDir"] == expected_path(scan_dir)
    atoms = [entry for entry in document["notAssessedReasons"] if entry.get("analyzer") == "atom"]
    assert atoms, "the enrichment stage's not-assessed atom entry is missing"
    assert atoms[0]["stage"] == "enrichment"
    assert atoms[0]["reason"]
    assert document["checksNotRun"] == [
        {"name": "license", "reason": "license analysis was turned off"}
    ]


def test_coverage_of_a_directory_without_a_manifest_is_empty(open_session, make_scan_dir):
    scanned = make_scan_dir("plain")
    bare = scanned.parent.parent / "bare-vdr"
    bare.mkdir()
    (bare / "depscan-universal.vdr.json").write_bytes(
        (scanned / "sbom-python.vdr.json").read_bytes()
    )
    document = drive(open_session, _coverage_target(bare), (bare.parent,))
    assert document["stages"] == []
    assert document["notAssessedReasons"] == []
    assert document["checksNotRun"] == []


def test_an_oversized_coverage_report_spills_inside_the_scan_directory(
    open_session, make_scan_dir
):
    """A coverage report over the response budget spills into the scan
    directory and returns the spill envelope, whose count is the stage
    count, validated against the coverage output schema."""
    scan_dir = make_scan_dir("fat-coverage")
    manifest_path = scan_dir / "depscan.manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    stage = next(s for s in manifest["stages"] if s["name"] == "matching")
    stage["reason"] = "a" * (TOOL_BUDGET_BYTES + 1000)
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    arguments = {"scan_dir": str(scan_dir)}

    async def scenario(session):
        result = await session.call_tool("coverage", arguments)
        assert result.is_error is False, [content.text for content in result.content]
        envelope = json.loads(result.content[0].text)
        validate("depscan-mcp-coverage-output", envelope)
        return envelope

    envelope = drive(open_session, scenario, (scan_dir.parent,))
    # The envelope carries only the spill shape, never the stages.
    assert "stages" not in envelope
    assert envelope["count"] == len(manifest["stages"])
    assert envelope["file"].startswith(expected_path(scan_dir) + "/mcp/")
    spilled = json.loads(Path(envelope["file"]).read_text(encoding="utf-8"))
    assert {s["name"] for s in spilled["stages"]} == {s["name"] for s in manifest["stages"]}


# --- list_components -----------------------------------------------------------------


def test_list_components_returns_the_bom_components(open_session, make_scan_dir):
    scan_dir = make_scan_dir("plain")

    async def scenario(session):
        return await call_document(
            session,
            "list_components",
            {"scan_dir": str(scan_dir)},
            "depscan-mcp-list_components-output",
        )

    document = drive(open_session, scenario, (scan_dir.parent,))
    assert "nextCursor" not in document
    component = document["components"][0]
    assert component["name"] == "requests"
    assert component["type"] == "library"
    assert component["version"] == "2.32.1"
    assert component["purl"] == "pkg:pypi/requests@2.32.1"
    assert component["bomRef"] == "pkg:pypi/requests@2.32.1"


def test_list_components_refuses_a_scan_without_a_bom(open_session, make_scan_dir):
    scanned = make_scan_dir("plain")
    bare = scanned.parent.parent / "bare-vdr-2"
    bare.mkdir()
    (bare / "depscan-universal.vdr.json").write_bytes(
        (scanned / "sbom-python.vdr.json").read_bytes()
    )

    async def scenario(session):
        return await call_error(session, "list_components", {"scan_dir": str(bare)})

    message = drive(open_session, scenario, (bare.parent,))
    assert "records no BOM" in message


@pytest.mark.parametrize(
    ("content", "expected_in_message"),
    [
        ("{not json at all", "not valid JSON"),
        ("{}", "not a CycloneDX document"),
    ],
    ids=["not-json", "not-cyclonedx"],
)
def test_list_components_refuses_a_corrupted_bom(
    open_session, make_scan_dir, content, expected_in_message
):
    """A BOM file the scan's inventory stage recorded must not silently
    drop out of the component page: a file that does not parse, or parses
    as something else, is a tool error naming the file."""
    scan_dir = make_scan_dir("corrupted-bom")
    (scan_dir / "sbom-python.cdx.json").write_text(content, encoding="utf-8")

    async def scenario(session):
        return await call_error(session, "list_components", {"scan_dir": str(scan_dir)})

    message = drive(open_session, scenario, (scan_dir.parent,))
    assert "sbom-python.cdx.json" in message
    assert expected_in_message in message


# --- diff_scans ----------------------------------------------------------------------


def test_diff_scans_reports_new_fixed_and_changed(open_session, tmp_path, make_scan_dir):
    old_dir = make_scan_dir("old")
    new_dir = make_scan_dir("new", vulns=[VULN_CRITICAL, VULN_NEW])

    async def scenario(session):
        return await call_document(
            session,
            "diff_scans",
            {"old_scan_dir": str(old_dir), "new_scan_dir": str(new_dir)},
            "depscan-mcp-diff_scans-output",
        )

    document = drive(open_session, scenario, (tmp_path,))
    assert [entry["id"] for entry in document["new"]] == ["CVE-2024-3333"]
    assert document["new"][0]["old"] is None
    assert document["new"][0]["new"]["id"] == "CVE-2024-3333"
    assert document["fixed"] == []
    assert [entry["id"] for entry in document["changed"]] == ["CVE-2024-1111"]
    changed = document["changed"][0]
    assert changed["old"]["ratings"][0]["severity"] == "high"
    assert changed["new"]["ratings"][0]["severity"] == "critical"


def test_diff_scans_refuses_a_directory_that_is_not_a_scan(open_session, make_scan_dir):
    scanned = make_scan_dir("plain")
    empty = scanned.parent / "empty-diff"
    empty.mkdir()

    async def scenario(session):
        return await call_error(
            session,
            "diff_scans",
            {"old_scan_dir": str(scanned), "new_scan_dir": str(empty)},
        )

    message = drive(open_session, scenario, (scanned.parent,))
    assert "Cannot load a scan" in message


def test_an_oversized_diff_spills_into_the_new_scan_directory(open_session, tmp_path, make_scan_dir):
    """A diff whose entries exceed the response budget spills into the
    later scan directory, the one a reader of the diff is moving to, and
    returns the spill envelope, validated against the diff_scans output
    schema."""
    fat_high = dict(VULN_HIGH)
    fat_high["properties"] = [
        {"name": "depscan:probe", "value": "a" * (TOOL_BUDGET_BYTES + 1000)}
    ]
    fat_critical = dict(VULN_CRITICAL)
    fat_critical["properties"] = [
        {"name": "depscan:probe", "value": "b" * (TOOL_BUDGET_BYTES + 1000)}
    ]
    old_dir = make_scan_dir("fat-old", vulns=[fat_high])
    new_dir = make_scan_dir("fat-new", vulns=[fat_critical, VULN_NEW])
    arguments = {"old_scan_dir": str(old_dir), "new_scan_dir": str(new_dir)}

    async def scenario(session):
        result = await session.call_tool("diff_scans", arguments)
        assert result.is_error is False, [content.text for content in result.content]
        envelope = json.loads(result.content[0].text)
        validate("depscan-mcp-diff_scans-output", envelope)
        return envelope

    envelope = drive(open_session, scenario, (tmp_path,))
    # The envelope carries only the spill shape, never the diff groups.
    assert "new" not in envelope
    assert "fixed" not in envelope
    assert "changed" not in envelope
    # One changed pair and one new pair spilled, into the new scan.
    assert envelope["count"] == 2
    assert envelope["file"].startswith(expected_path(new_dir) + "/mcp/")
    spilled = json.loads(Path(envelope["file"]).read_text(encoding="utf-8"))
    assert [entry["id"] for entry in spilled["new"]] == ["CVE-2024-3333"]
    assert spilled["fixed"] == []
    assert [entry["id"] for entry in spilled["changed"]] == ["CVE-2024-1111"]


# --- doctor --------------------------------------------------------------------------


@pytest.fixture
def fixed_doctor_report(monkeypatch):
    """The doctor stub of the verb tests: one known report, recorded calls."""
    tools = {
        name: doctor_mod.ToolStatus(name=name, path=f"/bin/{name}", source="path")
        for name in ("cdxgen", "golem", "go", "dosai", "dotnet")
    }
    report = doctor_mod.DoctorReport(
        schema_version="1",
        depscan_version="7.0.0",
        platform={"os": "linux", "arch": "x86_64", "libc": "glibc"},
        tools=list(tools.values()),
        data={"vulnerabilityDatabase": dict(FULL_VDB_DATA)},
        capabilities=doctor_mod._evaluate_capabilities(
            tools,
            {"vulnerabilityDatabase": {"present": True, "cveIndexCount": 100}},
        ),
    )
    calls = []
    monkeypatch.setattr(doctor_mod, "doctor", lambda: calls.append(1) or report)
    return {"report": report, "calls": calls}


async def _doctor(session):
    return await call_document(session, "doctor", {}, "depscan-mcp-doctor-output")


def test_doctor_returns_the_report_document(open_session, fixed_doctor_report):
    document = drive(open_session, _doctor, ("/",))
    assert document["schemaVersion"] == "1"
    assert [tool["name"] for tool in document["tools"]] == [
        "cdxgen",
        "golem",
        "go",
        "dosai",
        "dotnet",
    ]
    # Positive control: the doctor stub produced the document.
    assert fixed_doctor_report["calls"] == [1]


def test_doctor_over_the_budget_is_an_error_without_a_scan_directory(open_session, monkeypatch):
    # A real report, so the oversized result still satisfies the output
    # schema and the budget is what refuses it.
    real = doctor_mod.doctor()
    report = dataclasses.replace(
        real, depscan_version=real.depscan_version + "+" + "a" * (TOOL_BUDGET_BYTES + 1)
    )
    monkeypatch.setattr(doctor_mod, "doctor", lambda: report)

    async def scenario(session):
        return await call_error(session, "doctor", {})

    message = drive(open_session, scenario, ("/",))
    assert str(TOOL_BUDGET_BYTES) in message
    assert "response budget" in message


# --- vdb_status ----------------------------------------------------------------------


@pytest.fixture
def vdb_home(tmp_path, monkeypatch):
    """The vdb home of the verb tests, pointed at a scratch directory."""
    import vdb.lib.config as vdb_config
    from vdb.lib import db as db_lib

    home = tmp_path / "vdb-home"
    home.mkdir()
    monkeypatch.setenv("VDB_HOME", str(home))
    monkeypatch.setattr(vdb_config, "DATA_DIR", str(home))
    monkeypatch.setattr(vdb_config, "VDB_BIN_FILE", str(home / "data.vdb7"))
    monkeypatch.setattr(vdb_config, "VDB_BIN_INDEX", str(home / "data.index.vdb7"))
    monkeypatch.setattr(vdb_config, "VDB_SHARDS_DIR", str(home / "shards"))
    yield home
    db_lib.reset_connections()


def test_vdb_status_returns_the_info_document(open_session, vdb_home, monkeypatch):
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
    monkeypatch.setattr(vdb_cli.db_lib, "metadata_rows_count", lambda: 0)
    monkeypatch.setattr(
        vdb_cli.db_cmd,
        "store_status",
        lambda store_dir=None: {
            "store_dir": str(vdb_home / "shards"),
            "shards": [],
            "coverage": "full",
            "mixed_builds": False,
            "missing_group_shards": [],
        },
    )

    async def scenario(session):
        return await call_document(session, "vdb_status", {}, "depscan-mcp-vdb_status-output")

    document = drive(open_session, scenario, (vdb_home,))
    assert document["vdbHome"] == json_path(str(vdb_home))
    assert document["mainDb"]["dataRows"] == 100
    assert document["mainDb"]["indexRows"] == 99
    assert document["shardStore"]["shards"] == []


def test_vdb_status_over_the_budget_is_an_error_without_a_scan_directory(
    open_session, monkeypatch, vdb_home
):
    from depscan import vdb_cli

    # The real info of the scratch vdb home, with an oversized home path, so
    # the result still satisfies the output schema and the budget refuses it.
    real_collect = vdb_cli._collect_info
    monkeypatch.setattr(
        vdb_cli,
        "_collect_info",
        lambda: {**real_collect(), "vdbHome": "/" + "a" * (TOOL_BUDGET_BYTES + 1)},
    )

    async def scenario(session):
        return await call_error(session, "vdb_status", {})

    message = drive(open_session, scenario, ("/",))
    assert str(TOOL_BUDGET_BYTES) in message


# --- run_scan ------------------------------------------------------------------------


def test_a_run_scan_target_starting_with_a_dash_is_a_tool_error(
    open_session, tmp_path, monkeypatch, scan_stubs
):
    """A dash-leading target that exists under a root is classified as a
    source and reaches the scan verb's parser, where argparse would call
    sys.exit(2); SystemExit is not an Exception, so it must never leave
    the tool: it fails as a tool error and the session keeps serving."""
    monkeypatch.chdir(tmp_path)
    dash_dir = tmp_path / "-dash-dir"
    dash_dir.mkdir()
    good = tmp_path / "project"
    good.mkdir()
    (good / "app.py").write_text("import requests\n", encoding="utf-8")

    async def scenario(session):
        message = await call_error(session, "run_scan", {"target": "-dash-dir"})
        document = await call_document(
            session, "run_scan", {"target": str(good)}, "depscan-mcp-run_scan-output"
        )
        return message, document["argv"]

    message, argv = drive(open_session, scenario, (tmp_path,))
    assert "do not parse as a depscan scan command line" in message
    assert "-dash-dir" in message
    # The session survived the refused call and answers the next one.
    assert argv == ["depscan", "scan", str(good)]
    assert scan_stubs["calls"]["cdxgen"] == []


def test_run_scan_dry_run_returns_the_argv_and_the_effective_options(
    open_session, tmp_path, scan_stubs
):
    target = tmp_path / "project"
    target.mkdir()
    (target / "app.py").write_text("import requests\n", encoding="utf-8")
    reports_dir = tmp_path / "dry-reports"
    arguments = {"target": str(target), "reports_dir": str(reports_dir), "profile": "ci"}

    async def scenario(session):
        return await call_document(session, "run_scan", arguments, "depscan-mcp-run_scan-output")

    document = drive(open_session, scenario, (tmp_path,))
    assert document["argv"] == [
        "depscan",
        "scan",
        str(target),
        "--reports-dir",
        str(reports_dir),
        "--profile",
        "ci",
    ]
    validate("depscan-config-show-output", document["options"])
    assert document["options"]["options"]["reports_dir"]["source"] == "command line"
    # A dry run executes nothing: no cdxgen process and no reports directory.
    assert scan_stubs["calls"]["cdxgen"] == []
    assert not reports_dir.exists()


def test_run_scan_dry_run_checks_and_explain_land_on_the_argv(open_session, tmp_path, scan_stubs):
    target = tmp_path / "project"
    target.mkdir()
    arguments = {
        "target": str(target),
        "checks": ["license", "supply-chain"],
        "reachability_analyzer": "off",
        "explain": True,
    }

    async def scenario(session):
        return await call_document(session, "run_scan", arguments, "depscan-mcp-run_scan-output")

    document = drive(open_session, scenario, (tmp_path,))
    assert document["argv"] == [
        "depscan",
        "scan",
        str(target),
        "--checks",
        "license,supply-chain",
        "--reachability-analyzer",
        "off",
        "--explain",
    ]
    assert scan_stubs["calls"]["cdxgen"] == []


def test_run_scan_execute_without_allow_scans_is_refused(open_session, tmp_path, scan_stubs):
    target = tmp_path / "project"
    target.mkdir()

    async def scenario(session):
        return await call_error(session, "run_scan", {"target": str(target), "execute": True})

    message = drive(open_session, scenario, (tmp_path,), allow_scans=False)
    assert "--allow-scans" in message
    assert scan_stubs["calls"]["cdxgen"] == [], "the refused run scanned anyway"
    assert not (tmp_path / "reports").exists()


def test_run_scan_real_run_with_allow_scans_records_secure_mode(
    open_session, tmp_path, scan_stubs
):
    target = tmp_path / "project"
    target.mkdir()
    (target / "app.py").write_text("import requests\n", encoding="utf-8")
    reports_dir = tmp_path / "real-reports"
    arguments = {"target": str(target), "execute": True, "reports_dir": str(reports_dir)}

    async def scenario(session):
        return await call_document(session, "run_scan", arguments, "depscan-mcp-run_scan-output")

    document = drive(open_session, scenario, (tmp_path,), allow_scans=True)
    assert document["target"] == json_path(os.path.abspath(str(target)))
    assert document["kind"] == "source"
    assert document["scanDir"] == expected_path(reports_dir)
    assert document["manifest"]["layoutVersion"] == "1.0"
    assert len(document["findings"]) == 1
    # Positive controls: the real run executed the stubbed cdxgen once, and
    # cdxgen received CDXGEN_SECURE_MODE=true for the whole run.
    assert len(scan_stubs["calls"]["cdxgen"]) == 1, "the scan never generated a BOM"
    env = scan_stubs["calls"]["cdxgen"][0]["env"]
    assert env.get("CDXGEN_SECURE_MODE") == "true"
    assert (reports_dir / "depscan.manifest.json").is_file()


def test_run_scan_dry_run_confines_the_target(open_session, tmp_path, scan_stubs):
    inside = tmp_path / "inside"
    inside.mkdir()
    outside_target = tmp_path / "outside" / "project"
    outside_target.mkdir(parents=True)

    async def scenario(session):
        return await call_error(session, "run_scan", {"target": str(outside_target)})

    message = drive(open_session, scenario, (inside,))
    assert "outside every allowed root" in message
    assert scan_stubs["calls"]["cdxgen"] == []


def test_run_scan_execute_refuses_a_target_that_escapes_the_roots(
    open_session, tmp_path, scan_stubs
):
    inside = tmp_path / "inside"
    inside.mkdir()
    escape = tmp_path / "outside" / "project"
    escape.mkdir(parents=True)

    async def scenario(session):
        return await call_error(
            session,
            "run_scan",
            {
                "target": os.path.join(str(inside), os.pardir, "outside", "project"),
                "execute": True,
            },
        )

    message = drive(open_session, scenario, (inside,), allow_scans=True)
    assert "'..'" in message
    assert scan_stubs["calls"]["cdxgen"] == []


def test_run_scan_confines_container_targets_that_are_paths(open_session, tmp_path, scan_stubs):
    """An existing tar archive and an OCI layout directory are container
    targets and filesystem paths, so both confine like any other path; an
    image reference stays a reference."""
    from depscan.commands.targets import detect_kind

    outside = tmp_path / "outside"
    outside.mkdir(parents=True)
    tar_file = outside / "app.tar"
    tar_file.write_bytes(b"not a real archive")
    oci_dir = outside / "oci-root"
    oci_dir.mkdir(parents=True)
    (oci_dir / "oci-layout").write_text("{}", encoding="utf-8")
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    assert detect_kind(str(tar_file))[0] == "container"
    assert detect_kind(str(oci_dir))[0] == "container"

    async def dry(session):
        return await call_error(session, "run_scan", {"target": str(tar_file)})

    async def execute(session):
        return await call_error(session, "run_scan", {"target": str(oci_dir), "execute": True})

    message = drive(open_session, dry, (allowed,))
    assert "outside every allowed root" in message
    message = drive(open_session, execute, (allowed,), allow_scans=True)
    assert "outside every allowed root" in message
    assert scan_stubs["calls"]["cdxgen"] == []

    async def reference(session):
        return await call_document(
            session, "run_scan", {"target": "alpine:3.2"}, "depscan-mcp-run_scan-output"
        )

    document = drive(open_session, reference, (allowed,))
    assert document["argv"] == ["depscan", "scan", "alpine:3.2"]


def test_run_scan_real_run_confines_the_reports_directory_whether_named_or_defaulted(
    open_session, tmp_path, monkeypatch, scan_stubs
):
    """A real run never writes outside the roots: the reports directory the
    run will write is confined whether the caller named it or the default
    (<cwd>/reports or DEPSCAN_REPORTS_DIR) chose it, and a directory outside
    the roots is refused before the scan runs."""
    allowed = tmp_path / "allowed"
    target = allowed / "project"
    target.mkdir(parents=True)
    (target / "app.py").write_text("import requests\n", encoding="utf-8")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    scans = []
    real_scan = api.scan

    def counting_scan(options, **kwargs):
        scans.append(1)
        return real_scan(options, **kwargs)

    monkeypatch.setattr(api, "scan", counting_scan)

    # With the working directory inside the roots the default lands there
    # and the run proceeds.
    monkeypatch.chdir(allowed)

    async def defaulted_inside(session):
        return await call_document(
            session,
            "run_scan",
            {"target": str(target), "execute": True},
            "depscan-mcp-run_scan-output",
        )

    document = drive(open_session, defaulted_inside, (allowed,), allow_scans=True)
    assert document["scanDir"] == expected_path(allowed / "reports")
    assert (allowed / "reports" / "depscan.manifest.json").is_file()
    assert len(scan_stubs["calls"]["cdxgen"]) == 1

    # With the working directory outside the roots the same default is
    # refused, before any scan work.
    monkeypatch.chdir(elsewhere)
    scans.clear()
    scan_stubs["calls"]["cdxgen"].clear()

    async def defaulted_outside(session):
        return await call_error(session, "run_scan", {"target": str(target), "execute": True})

    message = drive(open_session, defaulted_outside, (allowed,), allow_scans=True)
    assert "outside every allowed root" in message
    assert scans == [], "the scan ran although its reports directory was refused"
    assert scan_stubs["calls"]["cdxgen"] == []
    assert not (elsewhere / "reports").exists()

    # A caller named directory outside the roots is refused the same way.
    async def named(session):
        return await call_error(
            session,
            "run_scan",
            {"target": str(target), "execute": True, "reports_dir": str(elsewhere / "named")},
        )

    message = drive(open_session, named, (allowed,), allow_scans=True)
    assert "outside every allowed root" in message
    assert scans == []


def test_run_scan_real_run_does_not_leak_the_run_flags(
    open_session, tmp_path, monkeypatch, scan_stubs
):
    """The flags of one real run live only for that run: cdxgen runs in
    secure mode and a requested license check turns FETCH_LICENSE on, and
    the server process carries neither flag after the call."""
    monkeypatch.delenv("CDXGEN_SECURE_MODE", raising=False)
    monkeypatch.delenv("FETCH_LICENSE", raising=False)
    target = tmp_path / "project"
    target.mkdir()
    (target / "app.py").write_text("import requests\n", encoding="utf-8")
    reports_dir = tmp_path / "flag-reports"
    monkeypatch.setattr(
        pipeline,
        "get_pkg_list",
        lambda f: (
            [
                {
                    "purl": "pkg:pypi/requests@2.32.1",
                    "name": "requests",
                    "version": "2.32.1",
                    "licenses": ["CC-BY-NC-4.0"],
                }
            ],
            [],
        ),
    )
    during = {}
    real_scan = api.scan

    def recording_scan(options, **kwargs):
        during.update(
            {
                "secure": os.environ.get("CDXGEN_SECURE_MODE"),
                "license": os.environ.get("FETCH_LICENSE"),
            }
        )
        return real_scan(options, **kwargs)

    monkeypatch.setattr(api, "scan", recording_scan)
    arguments = {
        "target": str(target),
        "execute": True,
        "reports_dir": str(reports_dir),
        "checks": ["license"],
    }

    async def scenario(session):
        return await call_document(session, "run_scan", arguments, "depscan-mcp-run_scan-output")

    document = drive(open_session, scenario, (tmp_path,), allow_scans=True)
    # Positive controls: both flags were set for this run's scan, and
    # cdxgen received them in the environment it was handed.
    assert during == {"secure": "true", "license": "true"}, during
    assert len(scan_stubs["calls"]["cdxgen"]) == 1
    assert scan_stubs["calls"]["cdxgen"][0]["env"].get("CDXGEN_SECURE_MODE") == "true"
    assert scan_stubs["calls"]["cdxgen"][0]["env"].get("FETCH_LICENSE") == "true"
    # The server's environment carries neither flag after the call.
    assert os.environ.get("CDXGEN_SECURE_MODE") is None
    assert os.environ.get("FETCH_LICENSE") is None
    # The scan itself completed with the license analysis on.
    assert document["kind"] == "source"
    stages = {stage["name"]: stage for stage in document["manifest"]["stages"]}
    assert stages["licenses"]["status"] == "completed"


def test_an_oversized_scan_entry_spills_inside_its_scan_directory(
    open_session, tmp_path, scan_stubs
):
    """A real run whose scan entry exceeds the response budget spills the
    entry into the run's scan directory and returns the spill envelope,
    validated against the run_scan output schema."""
    fat = dict(VULN_HIGH)
    fat["properties"] = [{"name": "depscan:probe", "value": "a" * (TOOL_BUDGET_BYTES + 1000)}]
    scan_stubs["state"]["vulns"] = [dict(fat)]
    target = tmp_path / "project"
    target.mkdir()
    (target / "app.py").write_text("import requests\n", encoding="utf-8")
    reports_dir = tmp_path / "spill-reports"
    arguments = {"target": str(target), "execute": True, "reports_dir": str(reports_dir)}

    async def scenario(session):
        result = await session.call_tool("run_scan", arguments)
        assert result.is_error is False, [content.text for content in result.content]
        envelope = json.loads(result.content[0].text)
        validate("depscan-mcp-run_scan-output", envelope)
        return envelope

    envelope = drive(open_session, scenario, (tmp_path,), allow_scans=True)
    # The envelope carries only the spill shape, never the scan entry.
    assert "manifest" not in envelope
    assert "findings" not in envelope
    assert envelope["count"] == 1
    assert envelope["file"].startswith(expected_path(reports_dir) + "/mcp/")
    spilled = json.loads(Path(envelope["file"]).read_text(encoding="utf-8"))
    assert spilled["kind"] == "source"
    assert len(spilled["findings"]) == 1
    assert (reports_dir / "depscan.manifest.json").is_file()


# --- confinement through the tools ----------------------------------------------------


def test_a_scan_dir_outside_the_roots_is_refused(open_session, tmp_path, make_scan_dir):
    scan_dir = make_scan_dir("plain")
    allowed = tmp_path / "allowed"
    allowed.mkdir()

    async def scenario(session):
        return await call_error(session, "scan_summary", {"scan_dir": str(scan_dir)})

    message = drive(open_session, scenario, (allowed,))
    assert "outside every allowed root" in message


def test_a_dotdot_escape_is_refused_with_the_dotdot_rule(open_session, make_scan_dir):
    scan_dir = make_scan_dir("plain")
    root = scan_dir.parent
    escape = os.path.join(str(root), "reports", os.pardir, os.pardir, "elsewhere")

    async def scenario(session):
        return await call_error(session, "scan_summary", {"scan_dir": escape})

    message = drive(open_session, scenario, (root,))
    assert "'..'" in message


@pytest.mark.skipif(sys.platform == "win32", reason="the junction variant covers this on Windows")
def test_a_symlink_out_of_the_roots_is_refused(open_session, make_scan_dir):
    scan_dir = make_scan_dir("plain")
    root = scan_dir.parent
    outside = root.parent / "symlink-target"
    outside.mkdir()
    link = root / "link-to-outside"
    os.symlink(outside, link)

    async def scenario(session):
        return await call_error(session, "scan_summary", {"scan_dir": str(link)})

    message = drive(open_session, scenario, (root,))
    assert "symlink" in message


@pytest.mark.skipif(sys.platform != "win32", reason="junctions are a Windows reparse point")
def test_a_junction_out_of_the_roots_is_refused(open_session, make_scan_dir):
    import _winapi

    scan_dir = make_scan_dir("plain")
    root = scan_dir.parent
    outside = root.parent / "junction-target"
    outside.mkdir()
    junction = root / "junction-to-outside"
    getattr(_winapi, "CreateJunction")(str(outside), str(junction))

    async def scenario(session):
        return await call_error(session, "scan_summary", {"scan_dir": str(junction)})

    message = drive(open_session, scenario, (root,))
    assert "symlink" in message


def test_client_roots_add_to_the_startup_roots(open_session, tmp_path, make_scan_dir):
    scan_dir = make_scan_dir("plain")
    startup_root = tmp_path / "startup-root"
    startup_root.mkdir()
    client_root = tmp_path / "client-root"
    client_root.mkdir()

    async def served(session):
        return await _scan_summary(session, scan_dir)

    async def refused(session):
        return await call_error(session, "scan_summary", {"scan_dir": str(scan_dir)})

    # With the scan directory under no startup root, it is refused.
    message = drive(open_session, refused, (startup_root,), client_roots=())
    assert "outside every allowed root" in message
    # Announcing a root that covers the scan directory serves it: the
    # client's roots add to the startup roots.
    document = drive(
        open_session, served, (startup_root,), client_roots=(str(scan_dir.parent.parent),)
    )
    assert document["findingCount"] == 1
    # A client root that does not cover the scan directory serves nothing.
    message = drive(open_session, refused, (startup_root,), client_roots=(str(client_root),))
    assert "outside every allowed root" in message


def test_a_startup_root_is_enough_without_client_roots(open_session, make_scan_dir):
    scan_dir = make_scan_dir("plain")
    document = drive(
        open_session, _scan_summary_target(scan_dir), (scan_dir.parent,), client_roots=()
    )
    assert document["findingCount"] == 1


# --- stdout purity over the real stdio transport ---------------------------------------


def test_stdout_carries_only_jsonrpc_messages(tmp_path):
    """`depscan mcp` over real stdio: every stdout line is a JSON-RPC message."""
    command = [sys.executable, "-c", "from depscan.cli import main; main()"]
    root = tmp_path / "root"
    root.mkdir()
    initialize = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "stdout-purity-test", "version": "0.0.0"},
            },
        }
    )
    tools_list = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    process = subprocess.Popen(
        [*command, "mcp", "--allow-dir", str(root)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=str(REPO_ROOT),
    )
    stdin = process.stdin
    stdout = process.stdout
    stderr = process.stderr
    assert stdin is not None and stdout is not None and stderr is not None
    lines = []
    try:
        # The protocol wants initialize answered before anything else.
        stdin.write(initialize + "\n")
        stdin.flush()
        lines.append(stdout.readline())
        stdin.write(tools_list + "\n")
        stdin.flush()
        lines.append(stdout.readline())
        stdin.close()
        # Whatever else the server writes on stdout before it stops is held
        # to the same bar: protocol messages only.
        while True:
            line = stdout.readline()
            if not line:
                break
            lines.append(line)
        process.wait(timeout=60)
        err_text = stderr.read()
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=30)
    assert process.returncode == 0, err_text[-2000:]
    assert lines and all(lines), "the server wrote nothing on the protocol channel"
    answers = {}
    for line in lines:
        message = json.loads(line)
        assert message["jsonrpc"] == "2.0"
        if "id" in message:
            answers[message["id"]] = message
    assert 1 in answers and 2 in answers
    tools = answers[2]["result"]["tools"]
    assert [tool["name"] for tool in tools] == list(TOOL_NAMES)
    assert not [tool["name"] for tool in tools if tool["name"] in FORBIDDEN_TOOLS]
    for tool in tools:
        assert tool["inputSchema"]["$id"] == f"urn:owasp:depscan:schema:mcp-{tool['name']}-input:1"


# --- documents inside a confined scan directory ------------------------------------


def _outside(tmp_path):
    """A directory next to the scan directories, outside the roots."""
    outside = tmp_path.parent / (tmp_path.name + "-outside")
    outside.mkdir(exist_ok=True)
    return outside


def _point_inventory_at(scan_dir, relative):
    manifest_path = scan_dir / "depscan.manifest.json"
    manifest = json.loads(manifest_path.read_text())
    for stage in manifest["stages"]:
        if stage.get("name") == "inventory":
            for output in stage.get("outputs") or []:
                output["file"] = relative
    manifest_path.write_text(json.dumps(manifest))


def test_a_manifest_output_that_climbs_out_is_refused(open_session, make_scan_dir, tmp_path):
    scan_dir = make_scan_dir("climb")
    secret = _outside(tmp_path) / "secret.cdx.json"
    secret.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [{"name": "SECRET-DOTDOT", "type": "library"}],
            }
        )
    )
    _point_inventory_at(scan_dir, os.path.relpath(secret, scan_dir).replace(os.sep, "/"))

    async def scenario(session):
        return await call_error(session, "list_components", {"scan_dir": str(scan_dir)})

    message = drive(open_session, scenario, (scan_dir.parent,))
    assert "resolves outside the scan directory" in message
    assert "SECRET-DOTDOT" not in message


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
def test_a_symlinked_document_leading_out_refuses_the_scan(open_session, make_scan_dir, tmp_path):
    scan_dir = make_scan_dir("linked")
    findings = scan_dir / "depscan.findings.json"
    copy = _outside(tmp_path) / "findings.json"
    copy.write_text(findings.read_text().replace(VULN_HIGH["id"], "SECRET-LINKED"))
    findings.unlink()
    findings.symlink_to(copy)

    async def tool(session):
        return await call_error(session, "list_findings", {"scan_dir": str(scan_dir)})

    async def resource(session):
        from depscan.mcp_server.resources import scan_resource_uri

        try:
            result = await session.read_resource(scan_resource_uri(str(scan_dir), "findings"))
        except Exception as exc:  # noqa: BLE001 - the refusal is the expected path
            return str(exc)
        return result.contents[0].text

    for scenario in (tool, resource):
        message = drive(open_session, scenario, (scan_dir.parent,))
        assert "a symlink that resolves outside the allowed roots" in message
        assert "SECRET-LINKED" not in message


def test_a_finding_that_breaks_its_schema_is_a_tool_error(open_session, make_scan_dir):
    scan_dir = make_scan_dir("malformed")
    path = scan_dir / "depscan.findings.json"
    document = json.loads(path.read_text())
    document["findings"].append({"id": "x", "junk": 1})
    path.write_text(json.dumps(document))

    async def scenario(session):
        return await call_error(session, "list_findings", {"scan_dir": str(scan_dir)})

    message = drive(open_session, scenario, (scan_dir.parent,))
    assert "does not satisfy the depscan-finding schema" in message


def test_a_manifest_that_breaks_its_schema_is_a_tool_error(open_session, make_scan_dir):
    scan_dir = make_scan_dir("badmanifest")
    path = scan_dir / "depscan.manifest.json"
    manifest = json.loads(path.read_text())
    manifest["startUtc"] = 5
    path.write_text(json.dumps(manifest))

    async def scenario(session):
        return await call_error(session, "coverage", {"scan_dir": str(scan_dir)})

    message = drive(open_session, scenario, (scan_dir.parent,))
    assert "does not satisfy the depscan-manifest schema" in message


def test_the_dry_run_refuses_a_reports_dir_outside_the_roots(open_session, tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    outside = _outside(tmp_path) / "reports"

    async def scenario(session):
        return await call_error(
            session, "run_scan", {"target": str(source), "reports_dir": str(outside)}
        )

    message = drive(open_session, scenario, (tmp_path,))
    assert "an absolute path outside every allowed root" in message
