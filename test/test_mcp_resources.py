"""The resources and prompts of the ``depscan mcp`` server, driven through
the SDK's in-memory client session.

The scan directory is a real one: a scan runs over a BOM directory with the
database, the matching stage and the report rendering stubbed (the pattern
of the scan directory tests), so the resources read documents this version
of dep-scan actually wrote, finding ids included. Every prompt is rendered
through the server and checked against the tool schemas the server
advertises, so a prompt that names a tool the server does not have fails
here.
"""

import contextlib
import json
import os
import re
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest
from mcp import Client, types
from mcp.shared.exceptions import MCPError

from analysis_lib.findings.schemas import schema_names, validate
from depscan import cli
from depscan.lib import doctor as doctor_mod
from depscan.lib import pipeline, vdb_setup
from depscan.mcp_server import confinement
from depscan.mcp_server import resources as res_mod
from depscan.mcp_server import server as server_mod

pytestmark = pytest.mark.asyncio

# The VDR vulnerability the stubbed matching stage finds, and the BOM the
# scan directory is built from; the same documents the scan directory tests
# use, so the finding the fixture carries is one a real scan would write.
VULN_REQUESTS = {
    "id": "CVE-2024-1111",
    "bom-ref": "CVE-2024-1111/pkg:pypi/requests@2.32.1",
    "affects": [{"ref": "pkg:pypi/requests@2.32.1"}],
    "ratings": [{"severity": "high", "score": 8.1, "method": "CVSSv31"}],
    "fixed_location": "2.32.2",
}

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

# The doctor data state the stubbed scan is evaluated against: a present,
# fresh, populated database, as in the scan directory tests.
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


def run_main(monkeypatch, argv):
    """Run ``main`` with ``argv`` after the program name; the exit code."""
    monkeypatch.setattr(sys, "argv", ["depscan", *argv])
    with pytest.raises(SystemExit) as excinfo:
        cli.main()
    return excinfo.value.code


def mcp_tool_names():
    """The tool names, from the input schemas the server advertises."""
    return [
        name[len("depscan-mcp-") : -len("-input")]
        for name in schema_names()
        if name.startswith("depscan-mcp-") and name.endswith("-input")
    ]


@pytest.fixture
def scan_env(tmp_path, monkeypatch):
    """A scan directory a real scan wrote, inside a root, with a decoy outside.

    The scan runs through ``depscan scan`` over a BOM directory with the
    database, the matching stage and the report rendering stubbed. The
    non-empty findings document is the positive control: it exists only
    when the stubbed matching stage really ran and the scan directory
    writer really wrote.
    """
    monkeypatch.setattr(
        vdb_setup, "resolve_scan_vdb_image", lambda args: ("oras://vdb", False, "app-only")
    )
    monkeypatch.setattr(vdb_setup, "vdb_download_needed", lambda url, d: (False, ""))
    monkeypatch.setattr(vdb_setup, "configure_vdb_readonly", lambda: None)
    monkeypatch.setattr(vdb_setup, "ensure_vdb_usable", lambda: None)
    monkeypatch.setattr(pipeline, "get_pkgs_by_scope", lambda pkg_list: {})
    monkeypatch.setattr(
        pipeline,
        "get_pkg_list",
        lambda f: ([{"purl": "pkg:pypi/requests@2.32.1", "name": "requests"}], []),
    )
    monkeypatch.setattr(pipeline.ReportGenerator, "parse_and_generate_report", lambda self: None)
    monkeypatch.setattr(pipeline.console, "save_html", lambda *a, **k: None)
    monkeypatch.setattr(pipeline.console, "save_text", lambda *a, **k: None)
    monkeypatch.setattr(pipeline, "risk_audit", lambda *a, **k: {})

    class StubVDRAnalyzer:
        success = True
        prioritized_pkg_vuln_trees = {}

        def __init__(self, vdr_options):
            self.vdr_options = vdr_options

        def process(self):
            return SimpleNamespace(
                success=True,
                prioritized_pkg_vuln_trees={},
                pkg_vulnerabilities=[dict(VULN_REQUESTS)],
            )

    monkeypatch.setattr(pipeline, "VDRAnalyzer", StubVDRAnalyzer)

    tools = {
        name: doctor_mod.ToolStatus(name=name, path=f"/bin/{name}", source="path")
        for name in ("cdxgen", "golem", "go", "dosai", "dotnet")
    }
    fixed_report = doctor_mod.DoctorReport(
        schema_version="1",
        depscan_version="7.0.0",
        platform={"os": "linux", "arch": "x86_64", "libc": "glibc"},
        tools=list(tools.values()),
        data={"vulnerabilityDatabase": dict(FULL_VDB_DATA)},
        capabilities=doctor_mod._evaluate_capabilities(
            tools, {"vulnerabilityDatabase": {"present": True, "cveIndexCount": 100}}
        ),
    )
    monkeypatch.setattr(doctor_mod, "doctor", lambda: fixed_report)

    root = tmp_path / "root"
    reports = root / "reports"
    bom_dir = tmp_path / "boms"
    bom_dir.mkdir(parents=True)
    for name in ("a", "b"):
        bom = dict(BOM_DOCUMENT)
        bom["metadata"] = {"component": {"name": name, "type": "application"}}
        (bom_dir / f"{name}.cdx.json").write_text(json.dumps(bom), encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    decoy = outside / "other-scan"
    decoy.mkdir()
    (decoy / "depscan.manifest.json").write_text("{}", encoding="utf-8")
    (decoy / "depscan.findings.json").write_text("{}", encoding="utf-8")

    assert run_main(
        monkeypatch,
        ["scan", str(bom_dir), "--reports-dir", str(reports), "--no-banner"],
    ) == 0
    manifest_path = reports / "depscan.manifest.json"
    findings_path = reports / "depscan.findings.json"
    assert manifest_path.is_file(), "the scan directory was not written"
    assert findings_path.is_file(), "the findings document was not written"
    findings_document = json.loads(findings_path.read_text(encoding="utf-8"))
    findings = findings_document.get("findings") or []
    assert findings, "the stubbed scan produced no findings; the fixture is broken"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    return SimpleNamespace(
        root=root,
        scan_dir=reports,
        outside=outside,
        decoy=decoy,
        manifest=manifest,
        findings_document=findings_document,
        findings=findings,
    )


@pytest.fixture
def tools_stub(monkeypatch):
    """A stand-in for the sibling tools module the server imports when it is
    built.

    The tools piece owns ``depscan.mcp_server.tools`` and lands separately,
    so the server cannot be constructed in this worktree without a stand-in
    that imports. No test here calls a tool, so the stand-in only has to be
    importable and answer ``tools/list`` with an empty list; the resource
    reads and prompt renders in the other tests are the proof that the
    resource handlers are wired for real. The stand-in's own positive
    control is the test that asks the server for its tools and checks the
    stand-in answered.
    """
    module = ModuleType("depscan.mcp_server.tools")
    calls: list = []

    async def handle_list_tools(ctx, params):
        calls.append("list")
        return types.ListToolsResult(tools=[])

    async def handle_call_tool(ctx, params):
        calls.append(("call", str(params.name)))
        raise MCPError(
            code=types.INVALID_PARAMS,
            message="the tools module is not part of the resources piece",
        )

    setattr(module, "handle_list_tools", handle_list_tools)
    setattr(module, "handle_call_tool", handle_call_tool)
    import depscan.mcp_server as package

    monkeypatch.setattr(package, "tools", module, raising=False)
    monkeypatch.setitem(sys.modules, "depscan.mcp_server.tools", module)
    return SimpleNamespace(module=module, calls=calls)


async def test_the_tools_stand_in_answers_the_server(scan_env, tools_stub):
    """Positive control for the stand-in: the server really boots with it
    and asks it for the tool list."""
    async with mcp_client([scan_env.root]) as client:
        result = await client.list_tools()
    assert list(result.tools) == []
    assert tools_stub.calls == ["list"], "the server never asked the tools module"


def build_server(roots):
    """The real server object, built the way the verb builds it.

    The roots go through ``confinement.startup_roots`` like the verb's
    does, so they reach the handlers in their realpath form, as on macOS
    where ``/tmp`` is a symlink into ``/private``.
    """
    sdk = server_mod.load_mcp_sdk()
    return server_mod.build_server(sdk, tuple(confinement.startup_roots(roots)))


@contextlib.asynccontextmanager
async def mcp_client(roots, announced_roots=None, mode="auto"):
    """A client session connected to the server over the in-memory transport.

    ``announced_roots`` are the MCP roots the client answers a roots
    request with; without them the client announces none, and the server
    works from the startup roots alone. ``mode`` selects the connection the
    SDK negotiates: the default is the modern in-process path, and the
    handshake-era path is the one a stdio client speaks, and the one where
    a client can answer the server's roots request.
    """
    server = build_server(roots)
    if announced_roots is None:
        async with Client(server=server, mode=mode) as client:
            yield client
        return
    announced = [Path(p).resolve().as_uri() for p in announced_roots]

    async def list_roots(context):
        return types.ListRootsResult(roots=[types.Root(uri=uri) for uri in announced])

    async with Client(server=server, mode=mode, list_roots_callback=list_roots) as client:
        yield client


def read_error_text(excinfo) -> str:
    """The message a refused resource read carries."""
    return str(excinfo.value)


# --- the resource templates -------------------------------------------------------


async def test_the_three_resource_templates_are_listed(scan_env, tools_stub):
    async with mcp_client([scan_env.root]) as client:
        result = await client.list_resource_templates()
    templates = {template.uri_template: template for template in result.resource_templates}
    assert set(templates) == {
        res_mod.MANIFEST_TEMPLATE,
        res_mod.FINDINGS_TEMPLATE,
        res_mod.FINDING_TEMPLATE,
    }
    assert templates[res_mod.MANIFEST_TEMPLATE].name == "Scan manifest"
    assert templates[res_mod.FINDINGS_TEMPLATE].name == "Scan findings"
    assert templates[res_mod.FINDING_TEMPLATE].name == "Scan finding"
    for template in templates.values():
        assert template.mime_type == "application/json"
        assert "{scan_dir}" in template.uri_template
        assert template.description is not None
        assert "percent-encoded" in template.description


async def test_no_static_resources_are_listed(scan_env, tools_stub):
    async with mcp_client([scan_env.root]) as client:
        result = await client.list_resources()
    assert list(result.resources) == []


async def test_the_templates_serve_documents_the_published_schemas_define(scan_env, tools_stub):
    """The templates read the same documents the scan_summary, list_findings
    and get_finding tools return, and those tools have published schemas."""
    tools = set(mcp_tool_names())
    assert {"scan_summary", "list_findings", "get_finding"} <= tools


# --- reads inside the roots -------------------------------------------------------


async def test_the_manifest_resource_returns_the_manifest_document(scan_env, tools_stub):
    uri = res_mod.scan_resource_uri(str(scan_env.scan_dir), "manifest")
    async with mcp_client([scan_env.root]) as client:
        result = await client.read_resource(uri)
    assert len(result.contents) == 1
    content = result.contents[0]
    assert isinstance(content, types.TextResourceContents)
    assert content.mime_type == "application/json"
    assert str(content.uri) == uri
    # Parsed values are compared, never escaped JSON text.
    assert json.loads(content.text) == scan_env.manifest
    assert scan_env.manifest["layoutVersion"], "the manifest document is empty"


async def test_the_findings_resource_returns_the_findings_document(scan_env, tools_stub):
    uri = res_mod.scan_resource_uri(str(scan_env.scan_dir), "findings")
    async with mcp_client([scan_env.root]) as client:
        result = await client.read_resource(uri)
    content = result.contents[0]
    assert isinstance(content, types.TextResourceContents)
    assert content.mime_type == "application/json"
    document = json.loads(content.text)
    assert document == scan_env.findings_document
    assert document["schemaVersion"]
    assert len(document["findings"]) == len(scan_env.findings)


async def test_a_single_finding_resource_returns_that_finding(scan_env, tools_stub):
    finding = scan_env.findings[0]
    # The id is a fingerprint of this shape by schema, not by construction
    # of this test: the fixture finding is validated before it is used.
    validate("depscan-finding", finding)
    uri = res_mod.scan_resource_uri(str(scan_env.scan_dir), f"findings/{finding['id']}")
    async with mcp_client([scan_env.root]) as client:
        result = await client.read_resource(uri)
    content = result.contents[0]
    assert isinstance(content, types.TextResourceContents)
    document = json.loads(content.text)
    assert document == finding
    assert document["id"] == finding["id"]


def test_the_scan_uri_encoding_round_trips_windows_and_spaces():
    """Encoding then parsing returns the path verbatim, drive letter and
    spaces included; the round trip is string work, no filesystem."""
    for path in ("C:\\Users\\someone\\scans\\my scan", "/tmp/a scan/unicode-path"):
        for tail in ("manifest", "findings", "findings/dsf1:" + "a" * 64):
            parsed = res_mod.parse_scan_uri(res_mod.scan_resource_uri(path, tail))
            assert parsed.scan_dir == path
    assert res_mod.URI_AUTHORITY == "scan"


def test_parse_scan_uri_names_the_three_kinds():
    parsed = res_mod.parse_scan_uri("depscan://scan/%2Ftmp%2Fscan/manifest")
    assert parsed == res_mod.ParsedResourceUri(scan_dir="/tmp/scan", kind="manifest")
    parsed = res_mod.parse_scan_uri("depscan://scan/%2Ftmp%2Fscan/findings")
    assert parsed == res_mod.ParsedResourceUri(scan_dir="/tmp/scan", kind="findings")
    parsed = res_mod.parse_scan_uri("depscan://scan/%2Ftmp%2Fscan/findings/dsf1%3Aabc")
    assert parsed.finding_id == "dsf1:abc"


# --- reads outside the roots --------------------------------------------------------


async def test_an_absolute_path_outside_the_roots_is_refused_naming_the_rule(scan_env, tools_stub):
    uri = res_mod.scan_resource_uri(str(scan_env.decoy), "manifest")
    async with mcp_client([scan_env.root]) as client:
        with pytest.raises(MCPError) as excinfo:
            await client.read_resource(uri)
    message = read_error_text(excinfo)
    assert confinement.RULE_OUTSIDE in message
    assert str(scan_env.decoy) in message


async def test_a_dotdot_escape_in_a_uri_is_refused_naming_the_rule(scan_env, tools_stub):
    escape = os.path.join(
        str(scan_env.scan_dir), os.pardir, os.pardir, "outside", "other-scan"
    )
    uri = res_mod.scan_resource_uri(escape, "manifest")
    async with mcp_client([scan_env.root]) as client:
        with pytest.raises(MCPError) as excinfo:
            await client.read_resource(uri)
    assert confinement.RULE_DOTDOT in read_error_text(excinfo)


@pytest.mark.skipif(sys.platform == "win32", reason="directory symlinks need privileges there")
async def test_a_symlink_out_of_the_roots_is_refused_naming_the_rule(scan_env, tools_stub):
    link = scan_env.root / "link"
    os.symlink(scan_env.outside, link)
    uri = res_mod.scan_resource_uri(str(link), "manifest")
    async with mcp_client([scan_env.root]) as client:
        with pytest.raises(MCPError) as excinfo:
            await client.read_resource(uri)
    assert confinement.RULE_SYMLINK in read_error_text(excinfo)


async def test_an_unsupported_uri_names_the_templates(scan_env, tools_stub):
    async with mcp_client([scan_env.root]) as client:
        with pytest.raises(MCPError) as excinfo:
            await client.read_resource("file:///etc/hosts")
    message = read_error_text(excinfo)
    assert "unsupported resource URI" in message
    assert res_mod.MANIFEST_TEMPLATE in message


async def test_an_unknown_tail_is_refused_naming_the_templates(scan_env, tools_stub):
    uri = res_mod.scan_resource_uri(str(scan_env.scan_dir), "manifest/extra")
    async with mcp_client([scan_env.root]) as client:
        with pytest.raises(MCPError) as excinfo:
            await client.read_resource(uri)
    assert "unsupported resource URI" in read_error_text(excinfo)


async def test_an_empty_finding_id_segment_is_refused(scan_env, tools_stub):
    uri = res_mod.scan_resource_uri(str(scan_env.scan_dir), "findings/")
    async with mcp_client([scan_env.root]) as client:
        with pytest.raises(MCPError) as excinfo:
            await client.read_resource(uri)
    assert "unsupported resource URI" in read_error_text(excinfo)


# --- missing documents are errors, never empty reads -------------------------------


async def test_a_missing_scan_directory_inside_the_roots_is_an_error(scan_env, tools_stub):
    absent = scan_env.root / "absent"
    uri = res_mod.scan_resource_uri(str(absent), "manifest")
    async with mcp_client([scan_env.root]) as client:
        with pytest.raises(MCPError) as excinfo:
            await client.read_resource(uri)
    message = read_error_text(excinfo)
    assert str(absent) in message
    assert "does not exist" in message


async def test_a_directory_without_a_manifest_names_the_missing_file(scan_env, tools_stub):
    empty = scan_env.root / "empty-dir"
    empty.mkdir()
    manifest_uri = res_mod.scan_resource_uri(str(empty), "manifest")
    findings_uri = res_mod.scan_resource_uri(str(empty), "findings")
    async with mcp_client([scan_env.root]) as client:
        with pytest.raises(MCPError) as manifest_error:
            await client.read_resource(manifest_uri)
        with pytest.raises(MCPError) as findings_error:
            await client.read_resource(findings_uri)
    assert "depscan.manifest.json" in read_error_text(manifest_error)
    assert "depscan.findings.json" in read_error_text(findings_error)


async def test_an_unknown_finding_id_is_an_error_naming_the_id(scan_env, tools_stub):
    absent_id = "dsf1:" + "0" * 64
    uri = res_mod.scan_resource_uri(str(scan_env.scan_dir), f"findings/{absent_id}")
    async with mcp_client([scan_env.root]) as client:
        with pytest.raises(MCPError) as excinfo:
            await client.read_resource(uri)
    message = read_error_text(excinfo)
    assert absent_id in message
    assert "no finding with id" in message


# --- roots the client announces ------------------------------------------------------


async def test_client_roots_add_to_the_startup_roots(scan_env, tools_stub, tmp_path, monkeypatch):
    """A server started with no --allow-dir works from its working directory
    alone; the client's announced roots add to it, and a path under neither
    is still refused."""
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    uri = res_mod.scan_resource_uri(str(scan_env.scan_dir), "manifest")
    outside_uri = res_mod.scan_resource_uri(str(scan_env.decoy), "manifest")
    async with mcp_client(
        [str(cwd)], announced_roots=[str(scan_env.root)], mode="legacy"
    ) as client:
        # Positive control: the announced root really reached the server, so
        # the scan directory reads even though the server's cwd is elsewhere.
        result = await client.read_resource(uri)
        content = result.contents[0]
        assert isinstance(content, types.TextResourceContents)
        assert json.loads(content.text) == scan_env.manifest
        with pytest.raises(MCPError) as excinfo:
            await client.read_resource(outside_uri)
    assert confinement.RULE_OUTSIDE in read_error_text(excinfo)


# --- the prompts ---------------------------------------------------------------------


async def test_both_prompts_are_listed_with_an_optional_scan_dir_argument(scan_env, tools_stub):
    async with mcp_client([scan_env.root]) as client:
        result = await client.list_prompts()
    listed = {prompt.name: prompt for prompt in result.prompts}
    assert list(listed) == list(res_mod.PROMPT_NAMES)
    for name, prompt in listed.items():
        assert prompt.description
        arguments = prompt.arguments or []
        assert len(arguments) == 1
        argument = arguments[0]
        assert argument.name == "scan_dir"
        assert argument.required is False


async def test_triage_findings_renders_the_scan_dir_and_the_tools_in_order(scan_env, tools_stub):
    async with mcp_client([scan_env.root]) as client:
        result = await client.get_prompt(
            "triage_findings", {"scan_dir": str(scan_env.scan_dir)}
        )
    assert len(result.messages) == 1
    message = result.messages[0]
    assert message.role == "user"
    assert isinstance(message.content, types.TextContent)
    text = message.content.text
    assert str(scan_env.scan_dir) in text
    # The tools are called in the order the template lists them, and every
    # named tool is one the server's published schemas define.
    called = re.findall(r"\d+\. Call ([a-z_]+)", text)
    assert called == [
        "scan_summary",
        "list_findings",
        "get_finding",
        "explain_finding",
        "coverage",
    ]
    unknown = [name for name in called if name not in mcp_tool_names()]
    assert not unknown, f"the prompt names tools the server does not have: {unknown}"
    # Nothing the tools do not return is promised: there is no triage
    # store, remediation plan, policy gate or evidence store to write to.
    for absent in ("record_triage", "remediation_plan", "policy_status", "get_evidence"):
        assert absent not in text
    assert "The server records nothing" in text


async def test_plan_fixes_renders_the_scan_dir_and_the_tools_in_order(scan_env, tools_stub):
    async with mcp_client([scan_env.root]) as client:
        result = await client.get_prompt("plan_fixes", {"scan_dir": str(scan_env.scan_dir)})
    assert isinstance(result.messages[0].content, types.TextContent)
    text = result.messages[0].content.text
    assert str(scan_env.scan_dir) in text
    called = re.findall(r"\d+\. Call ([a-z_]+)", text)
    assert called == ["list_findings", "get_finding", "explain_finding", "coverage"]
    unknown = [name for name in called if name not in mcp_tool_names()]
    assert not unknown, f"the prompt names tools the server does not have: {unknown}"
    for absent in ("record_triage", "remediation_plan", "policy_status", "get_evidence"):
        assert absent not in text
    assert "does not apply fixes" in text


async def test_prompts_render_without_a_scan_dir_and_ask_for_one(scan_env, tools_stub):
    async with mcp_client([scan_env.root]) as client:
        for name in res_mod.PROMPT_NAMES:
            result = await client.get_prompt(name)
            assert isinstance(result.messages[0].content, types.TextContent)
            text = result.messages[0].content.text
            assert "<scan_dir>" in text
            assert str(scan_env.scan_dir) not in text
            assert "list_findings" in text
            assert f"{res_mod.SCAN_DIR_ARGUMENT} argument" in text


async def test_an_unknown_prompt_name_is_an_error_naming_the_prompts(scan_env, tools_stub):
    async with mcp_client([scan_env.root]) as client:
        with pytest.raises(MCPError) as excinfo:
            await client.get_prompt("frobnicate")
    message = read_error_text(excinfo)
    assert "unknown prompt 'frobnicate'" in message
    for name in res_mod.PROMPT_NAMES:
        assert name in message


async def test_a_prompt_argument_is_interpolated_verbatim(scan_env, tools_stub):
    tricky = f"{scan_env.scan_dir}{os.sep}with spaces"
    async with mcp_client([scan_env.root]) as client:
        result = await client.get_prompt("triage_findings", {"scan_dir": tricky})
    content = result.messages[0].content
    assert isinstance(content, types.TextContent)
    assert tricky in content.text


def test_the_prompt_texts_render_the_placeholder_directly():
    """The render helpers match what the server returns, placeholder included."""
    for name in res_mod.PROMPT_NAMES:
        spec = res_mod._PROMPTS[name]
        text = spec["render"](None)
        assert "<scan_dir>" in text
        text = spec["render"]("/tmp/scan")
        assert "/tmp/scan" in text
        assert "<scan_dir>" not in text
