"""The MCP core: the verb, the missing-extra exit, the doctor capability,
confinement, and the server construction contract.

The tests here never boot the full server: the construction test installs
stub modules in place of the real tool and resource registrations, so it
proves only that the construction path imports and delegates to whatever
is registered. The SDK-major guard follows vdb's
``test_mcp_sdk_compat.py``: the server is written against the mcp 2.x
constructor-registration API and this suite fails when the resolved SDK
drifts off it.
"""

import importlib.metadata
import inspect
import json
import os
import subprocess
import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest
from mcp.server import Server
from mcp.server.context import ServerRequestContext

from depscan.commands import build_parser
from depscan.commands import mcp as mcp_verb
from depscan.commands.output import EXIT_REQUIREMENT_NOT_MET, EXIT_USAGE
from depscan.lib import doctor as doctor_mod
from depscan.mcp_server import confinement
from depscan.mcp_server import server as server_mod

REPO_ROOT = Path(__file__).parent.parent


# --- the SDK-major guard -------------------------------------------------------


def test_mcp_sdk_is_the_2x_line():
    major = importlib.metadata.version("mcp").split(".", 1)[0]
    assert major == "2", (
        f"the mcp SDK resolved to {importlib.metadata.version('mcp')}; the "
        "server is written against the 2.x constructor-registration API. "
        "Port depscan/mcp_server/server.py or tighten the pin in "
        "pyproject.toml."
    )


def test_the_sdk_supports_constructor_registration():
    signature = inspect.signature(Server.__init__)
    for kwarg in (
        "on_list_tools",
        "on_call_tool",
        "on_list_resources",
        "on_list_resource_templates",
        "on_read_resource",
        "on_list_prompts",
        "on_get_prompt",
    ):
        assert kwarg in signature.parameters, (
            f"mcp.server.Server lost the '{kwarg}' constructor handler; the "
            "resolved mcp SDK is incompatible with this server's "
            "registration style."
        )


def test_the_request_context_carries_the_session_state():
    """Handlers read the session, the lifespan state and the request id."""
    fields = getattr(ServerRequestContext, "__dataclass_fields__", {})
    for field in ("lifespan_context", "session", "meta", "request_id"):
        assert field in fields or hasattr(ServerRequestContext, field), field


def test_the_server_module_imports_without_the_sdk():
    """Importing the server module never imports the mcp SDK.

    The verb imports this module on every run, on machines without the mcp
    extra included, so the import itself must stay SDK-free and the missing
    extra must surface only when the run path calls the loader.
    """
    probe = (
        "import sys; import depscan.mcp_server.server; "
        "print('mcp' in sys.modules)"
    )
    result = subprocess.run(
        [sys.executable, "-c", probe],
        capture_output=True,
        text=True,
        check=False,
        cwd=REPO_ROOT,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "False", result.stdout


# --- the loader and the missing extra -------------------------------------------


def test_the_loader_uses_the_real_import(monkeypatch):
    """The loader imports the SDK for real, and really fails without it."""
    sdk = server_mod.load_mcp_sdk()
    assert sdk["Server"] is Server
    assert sdk["types"] is not None
    monkeypatch.setitem(sys.modules, "mcp", None)
    with pytest.raises(ImportError) as excinfo:
        server_mod.load_mcp_sdk()
    assert "owasp-depscan[mcp]" in str(excinfo.value)


def test_missing_extra_exits_four_naming_the_extra(monkeypatch, capsys):
    """``depscan mcp`` without the mcp extra exits 4 and names the extra on
    stderr, through the real loader import."""
    args = build_parser().parse_args(["mcp"])
    monkeypatch.setitem(sys.modules, "mcp", None)
    assert mcp_verb.run(args) == EXIT_REQUIREMENT_NOT_MET == 4
    err = capsys.readouterr().err
    assert "owasp-depscan[mcp]" in err
    assert "pip install owasp-depscan[mcp]" in err
    # stdout stays empty: it is the protocol channel even on this path.
    assert capsys.readouterr().out == ""


def test_the_missing_extra_error_is_an_import_error():
    assert issubclass(server_mod.SdkMissingError, ImportError)


# --- the verb registration -------------------------------------------------------


def test_the_mcp_verb_is_registered():
    args = build_parser().parse_args(["mcp"])
    assert args.verb == "mcp"
    assert args.allow_dirs == []
    assert args.allow_scans is False


def test_the_mcp_verb_takes_allow_dirs():
    args = build_parser().parse_args(
        ["mcp", "--allow-dir", "/tmp/one", "--allow-dir", "/tmp/two"]
    )
    assert args.allow_dirs == ["/tmp/one", "/tmp/two"]


def test_the_mcp_verb_has_no_format_option():
    """stdout is the protocol channel, so there is no --format to ask for."""
    with pytest.raises(SystemExit) as excinfo:
        build_parser().parse_args(["mcp", "--format", "json"])
    assert excinfo.value.code == 2


def test_the_help_lists_the_mcp_verb(capsys):
    build_parser().print_help()
    assert "mcp" in capsys.readouterr().out


def test_a_bad_allow_dir_exits_two_naming_the_option(monkeypatch, capsys, tmp_path):
    """A root that does not exist confines nothing, so the server refuses to
    start and says which option was wrong."""
    args = build_parser().parse_args(["mcp", "--allow-dir", str(tmp_path / "absent")])
    assert mcp_verb.run(args) == EXIT_USAGE == 2
    err = capsys.readouterr().err
    assert "--allow-dir" in err
    assert str(tmp_path / "absent") in err
    assert capsys.readouterr().out == ""


# --- the doctor capability -------------------------------------------------------


def test_the_capability_table_has_the_mcp_row():
    spec = next(spec for spec in doctor_mod.CAPABILITIES if spec.name == "mcp")
    assert spec.implemented
    assert spec.issue == 631
    assert spec.requirements == ("python:mcp",)
    assert "mcp" in spec.description


def test_python_requirement_needs_the_module_importable(monkeypatch):
    """The python:<module> kind is satisfied by a find_spec lookup, and the
    lookup runs even when the module is missing."""
    calls = []
    real_find_spec = doctor_mod.util.find_spec

    def recording_find_spec(name, *args, **kwargs):
        calls.append(name)
        if name == "mcp":
            return None
        return real_find_spec(name, *args, **kwargs)

    monkeypatch.setattr(doctor_mod.util, "find_spec", recording_find_spec)
    assert doctor_mod.requirement_missing("python:mcp", {}, {}) == "python:mcp"
    assert "mcp" in calls, "the find_spec lookup never ran"


def test_python_requirement_is_satisfied_when_importable():
    """The dev and all extras install the SDK, so the lookup finds it."""
    assert doctor_mod.requirement_missing("python:mcp", {}, {}) is None


def test_python_requirement_survives_a_blocked_module(monkeypatch):
    """A module that resolves to nothing in sys.modules is missing, not a
    crash: find_spec raises for it and the requirement stays unmet."""
    monkeypatch.setitem(sys.modules, "mcp", None)
    assert doctor_mod.requirement_missing("python:mcp", {}, {}) == "python:mcp"


def test_the_python_requirement_reason_names_the_extra():
    reason = doctor_mod.requirement_reason("python:mcp", {}, {})
    assert "owasp-depscan[mcp]" in reason


def test_the_mcp_capability_is_unavailable_without_the_module(monkeypatch):
    real_find_spec = doctor_mod.util.find_spec

    def without_mcp(name, *args, **kwargs):
        if name == "mcp":
            return None
        return real_find_spec(name, *args, **kwargs)

    monkeypatch.setattr(doctor_mod.util, "find_spec", without_mcp)
    reason = doctor_mod.capability_unavailable_reason("mcp", {}, {})
    assert reason is not None
    assert "python:mcp" in reason
    assert "owasp-depscan[mcp]" in reason


def _install_probeless_doctor(monkeypatch, tools_by_name=None, data=None):
    """Silence the tool probes and the database read, keeping the real
    doctor() so the capability table runs against the real (or patched)
    module lookup. The empty tool list the report carries proves the stub
    replaced the probes."""
    tools_by_name = tools_by_name or {
        "python": doctor_mod.ToolStatus(name="python", path=sys.executable, source="runtime")
    }
    data = data or {"vulnerabilityDatabase": {"present": False}}
    monkeypatch.setattr(
        doctor_mod,
        "build_tools",
        lambda: (list(tools_by_name.values()), dict(tools_by_name)),
    )
    monkeypatch.setattr(doctor_mod, "_vdb_status", lambda: dict(data["vulnerabilityDatabase"]))


def test_the_doctor_report_reports_mcp(monkeypatch):
    """With the extra installed the report marks mcp available."""
    _install_probeless_doctor(monkeypatch)
    report = doctor_mod.doctor()
    assert [tool.name for tool in report.tools] == ["python"]
    status = {cap.name: cap for cap in report.capabilities}["mcp"]
    assert status.status == "available"
    assert status.missing == []


def test_the_doctor_report_reports_mcp_unavailable_without_the_module(monkeypatch):
    _install_probeless_doctor(monkeypatch)
    real_find_spec = doctor_mod.util.find_spec

    def without_mcp(name, *args, **kwargs):
        if name == "mcp":
            return None
        return real_find_spec(name, *args, **kwargs)

    monkeypatch.setattr(doctor_mod.util, "find_spec", without_mcp)
    report = doctor_mod.doctor()
    status = {cap.name: cap for cap in report.capabilities}["mcp"]
    assert status.status == "unavailable"
    assert status.missing == ["python:mcp"]


def test_require_mcp_exits_four_without_the_module(monkeypatch, capsys):
    _install_probeless_doctor(monkeypatch)
    calls = []
    real_find_spec = doctor_mod.util.find_spec

    def recording_without_mcp(name, *args, **kwargs):
        calls.append(name)
        if name == "mcp":
            return None
        return real_find_spec(name, *args, **kwargs)

    monkeypatch.setattr(doctor_mod.util, "find_spec", recording_without_mcp)
    assert doctor_mod.run_doctor_command(["--format", "json", "--require", "mcp"]) == 4
    assert "mcp" in calls, "the requirement lookup never ran"
    document = json.loads(capsys.readouterr().out)
    assert document["error"]["details"] == {"unmet": ["mcp"]}
    assert "mcp" in document["error"]["message"]


def test_require_mcp_exits_zero_with_the_extra_installed(monkeypatch, capsys):
    _install_probeless_doctor(monkeypatch)
    assert doctor_mod.run_doctor_command(["--require", "mcp"]) == 0
    assert "mcp" in capsys.readouterr().out


# --- confinement -----------------------------------------------------------------


@pytest.fixture
def rooted(tmp_path):
    """A root with content inside it and a secret outside it."""
    root = tmp_path / "root"
    scan = root / "scan"
    scan.mkdir(parents=True)
    (scan / "manifest.json").write_text("{}", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "secret.json"
    secret.write_text("{}", encoding="utf-8")
    return SimpleNamespace(
        root=root, scan=scan, inside_file=scan / "manifest.json", outside=outside, secret=secret
    )


def test_confine_returns_the_realpath_of_an_inside_path(rooted):
    roots = [str(rooted.root)]
    assert confinement.confine(str(rooted.scan), roots) == os.path.realpath(rooted.scan)
    assert confinement.confine(str(rooted.inside_file), roots) == os.path.realpath(
        rooted.inside_file
    )


def test_confine_accepts_the_root_itself(rooted):
    assert confinement.confine(str(rooted.root), [str(rooted.root)]) == os.path.realpath(
        rooted.root
    )


def test_confine_accepts_paths_below_a_filesystem_root(tmp_path):
    """A --allow-dir of the filesystem root confines everything below it.

    The filesystem root already ends with the separator, so appending
    another would anchor the containment at a doubled separator and refuse
    every path with the outside-root rule while the startup log names the
    root as allowed.
    """
    root = os.path.realpath(os.sep)
    assert confinement.confine(str(tmp_path), [root]) == os.path.realpath(tmp_path)


def test_confine_refuses_a_dotdot_that_escapes(rooted):
    escape = os.path.join(str(rooted.scan), os.pardir, os.pardir, "outside", "secret.json")
    with pytest.raises(confinement.PathOutsideRootsError) as excinfo:
        confinement.confine(escape, [str(rooted.root)])
    assert confinement.RULE_DOTDOT in str(excinfo.value)
    assert str(rooted.root) in str(excinfo.value)


def test_confine_allows_a_dotdot_that_stays_inside(rooted):
    (rooted.scan / "sub").mkdir()
    path = os.path.join(str(rooted.scan), "sub", os.pardir, "manifest.json")
    assert confinement.confine(path, [str(rooted.root)]) == os.path.realpath(
        rooted.inside_file
    )


@pytest.mark.skipif(sys.platform == "win32", reason="the junction variant covers this on Windows")
def test_confine_refuses_a_symlink_out_of_the_root(rooted):
    link = rooted.scan / "link.json"
    os.symlink(rooted.secret, link)
    with pytest.raises(confinement.PathOutsideRootsError) as excinfo:
        confinement.confine(str(link), [str(rooted.root)])
    assert confinement.RULE_SYMLINK in str(excinfo.value)


@pytest.mark.skipif(sys.platform == "win32", reason="directory symlinks need privileges there")
def test_confine_allows_a_symlink_within_the_root(rooted):
    target = rooted.scan / "manifest.json"
    link = rooted.scan / "link.json"
    os.symlink(target, link)
    assert confinement.confine(str(link), [str(rooted.root)]) == os.path.realpath(target)


@pytest.mark.skipif(sys.platform != "win32", reason="junctions are a Windows reparse point")
def test_confine_refuses_a_junction_out_of_the_root(rooted):
    """The Windows junction is the symlink-equivalent escape."""
    import _winapi

    junction = rooted.scan / "junction"
    getattr(_winapi, "CreateJunction")(str(rooted.outside), str(junction))
    escaped = os.path.join(str(junction), "secret.json")
    with pytest.raises(confinement.PathOutsideRootsError) as excinfo:
        confinement.confine(escaped, [str(rooted.root)])
    assert confinement.RULE_SYMLINK in str(excinfo.value)


@pytest.mark.skipif(sys.platform != "win32", reason="drive letters exist only there")
def test_confine_refuses_a_path_on_another_drive():
    roots = [r"C:\allowed\scans"]
    with pytest.raises(confinement.PathOutsideRootsError) as excinfo:
        confinement.confine(r"D:\elsewhere\scan", roots)
    assert confinement.RULE_OUTSIDE in str(excinfo.value)


def test_confine_refuses_an_absolute_path_outside_the_roots(rooted):
    with pytest.raises(confinement.PathOutsideRootsError) as excinfo:
        confinement.confine(str(rooted.secret), [str(rooted.root)])
    assert confinement.RULE_OUTSIDE in str(excinfo.value)


def test_confine_refuses_a_sibling_whose_name_shares_the_root_prefix(rooted):
    """A boundary check on the string prefix alone would let this through."""
    sibling = rooted.root.parent / (rooted.root.name + "-sibling")
    sibling.mkdir()
    secret = sibling / "secret.json"
    secret.write_text("{}", encoding="utf-8")
    with pytest.raises(confinement.PathOutsideRootsError) as excinfo:
        confinement.confine(str(secret), [str(rooted.root)])
    assert confinement.RULE_OUTSIDE in str(excinfo.value)


def test_confine_refuses_an_empty_path(rooted):
    with pytest.raises(confinement.PathOutsideRootsError) as excinfo:
        confinement.confine("", [str(rooted.root)])
    assert confinement.RULE_OUTSIDE in str(excinfo.value)


def test_confine_refuses_everything_without_roots(rooted):
    with pytest.raises(confinement.PathOutsideRootsError):
        confinement.confine(str(rooted.inside_file), [])


def test_startup_roots_are_the_realpaths_of_the_allow_dirs(rooted):
    links_root = rooted.root.parent / "links-root"
    os.symlink(rooted.root, links_root)
    roots = confinement.startup_roots([str(links_root), str(rooted.outside)])
    assert roots == [os.path.realpath(rooted.root), os.path.realpath(rooted.outside)]
    os.unlink(links_root)


def test_startup_roots_default_to_the_working_directory(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    assert confinement.startup_roots([]) == [os.path.realpath(tmp_path)]


def test_startup_roots_refuse_a_missing_directory(tmp_path):
    with pytest.raises(confinement.PathOutsideRootsError) as excinfo:
        confinement.startup_roots([str(tmp_path / "absent")])
    assert "--allow-dir" in str(excinfo.value)


def test_effective_roots_add_the_client_roots_to_the_startup_roots(rooted):
    startup = tuple(confinement.startup_roots([str(rooted.root)]))
    merged = confinement.effective_roots(startup, [str(rooted.outside)])
    assert merged == (os.path.realpath(rooted.root), os.path.realpath(rooted.outside))


def test_effective_roots_keep_the_startup_roots_when_the_client_has_none(rooted):
    startup = tuple(confinement.startup_roots([str(rooted.root)]))
    assert confinement.effective_roots(startup, []) == startup


def test_effective_roots_do_not_duplicate_a_root(rooted):
    startup = tuple(confinement.startup_roots([str(rooted.root)]))
    assert confinement.effective_roots(startup, [str(rooted.root)]) == startup


def test_client_roots_reads_the_session(rooted):
    """The client's file:// roots become local paths; a client that cannot
    answer the roots request contributes nothing."""
    import asyncio

    class RecordingSession:
        """A stand-in for the SDK session's roots request."""

        def __init__(self, roots, fail=False):
            self.roots = roots
            self.fail = fail
            self.asked = False

        async def list_roots(self):
            self.asked = True
            if self.fail:
                raise RuntimeError("the client does not support roots")
            return SimpleNamespace(roots=self.roots)

    session = RecordingSession([SimpleNamespace(uri=rooted.root.resolve().as_uri())])
    merged = asyncio.run(server_mod.client_roots(SimpleNamespace(session=session)))
    assert merged == (os.path.realpath(rooted.root),)
    assert session.asked, "the client session was never asked for its roots"

    refusing = RecordingSession([], fail=True)
    assert asyncio.run(server_mod.client_roots(SimpleNamespace(session=refusing))) == ()

    empty = RecordingSession([])
    assert asyncio.run(server_mod.client_roots(SimpleNamespace(session=empty))) == ()


def test_effective_roots_for_merges_the_session_roots(rooted):
    import asyncio

    startup = tuple(confinement.startup_roots([str(rooted.root)]))

    class RootsSession:
        def __init__(self, roots):
            self.roots = roots

        async def list_roots(self):
            return SimpleNamespace(roots=self.roots)

    session = RootsSession([SimpleNamespace(uri=rooted.outside.resolve().as_uri())])
    ctx = SimpleNamespace(session=session)
    merged = asyncio.run(server_mod.effective_roots_for(ctx, startup))
    assert merged == (os.path.realpath(rooted.root), os.path.realpath(rooted.outside))


# --- the construction contract ----------------------------------------------------


def _install_stub_modules(monkeypatch, calls):
    """Stub the tool and resource modules the construction path imports.

    Each stub records its calls; the resource stub answers every handler
    with its own name, so a passing test proves the handler wired to the
    stub and that its result passes through unchanged.
    """

    async def tool_list(ctx, params):
        calls.append("tools.handle_list_tools")
        return "tools-list-result"

    async def tool_call(ctx, params):
        calls.append(("tools.handle_call_tool", params.name))
        raise confinement.PathOutsideRootsError(
            f"refusing /etc: {confinement.RULE_OUTSIDE}"
        )

    tools_stub = types.ModuleType("depscan.mcp_server.tools")
    setattr(tools_stub, "handle_list_tools", tool_list)
    setattr(tools_stub, "handle_call_tool", tool_call)

    resources_stub = types.ModuleType("depscan.mcp_server.resources")
    for name in (
        "handle_list_resources",
        "handle_list_resource_templates",
        "handle_read_resource",
        "handle_list_prompts",
        "handle_get_prompt",
    ):
        async def handler(ctx, params, _name=name):
            calls.append(_name)
            return _name + "-result"

        setattr(resources_stub, name, handler)

    import depscan.mcp_server as package

    monkeypatch.setattr(package, "tools", tools_stub, raising=False)
    monkeypatch.setattr(package, "resources", resources_stub, raising=False)
    monkeypatch.setitem(sys.modules, "depscan.mcp_server.tools", tools_stub)
    monkeypatch.setitem(sys.modules, "depscan.mcp_server.resources", resources_stub)
    return tools_stub, resources_stub


def test_construction_imports_the_tool_and_resource_modules():
    """The modules load inside build_server, not at module import.

    The check runs in a subprocess because importing the sibling modules
    anywhere in this process, as the tools and resources tests do, binds
    them onto the package for every later check in it. The delegates test
    below boots the server with stand-in modules and proves the
    construction path calls them.
    """
    probe = (
        "import sys; import depscan.mcp_server.server; "
        "print('depscan.mcp_server.tools' in sys.modules, "
        "'depscan.mcp_server.resources' in sys.modules)"
    )
    result = subprocess.run(
        [sys.executable, "-c", probe],
        capture_output=True,
        text=True,
        check=False,
        cwd=REPO_ROOT,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "False False", result.stdout


def test_the_construction_contract_delegates_and_converts_errors(monkeypatch):
    """The registered handlers call the stub modules, results pass through
    and a refusal becomes an isError result naming the rule."""
    calls = []
    _install_stub_modules(monkeypatch, calls)
    sdk = server_mod.load_mcp_sdk()
    server = server_mod.build_server(sdk, ("/some/root",), allow_scans=False)

    async def exercise():
        handlers = server._request_handlers
        for method in (
            "tools/list",
            "tools/call",
            "resources/list",
            "resources/templates/list",
            "resources/read",
            "prompts/list",
            "prompts/get",
        ):
            assert method in handlers, method
        tools_list = await handlers["tools/list"].handler(None, None)
        assert tools_list == "tools-list-result"
        error_result = await handlers["tools/call"].handler(
            None, SimpleNamespace(name="get_finding")
        )
        assert error_result.is_error
        assert confinement.RULE_OUTSIDE in error_result.content[0].text
        resources_read = await handlers["resources/read"].handler(None, None)
        assert resources_read == "handle_read_resource-result"

    import asyncio

    asyncio.run(exercise())
    assert ("tools.handle_call_tool", "get_finding") in calls
    assert "handle_read_resource" in calls


def test_the_lifespan_state_carries_the_startup_configuration(monkeypatch):
    """The handlers reach the startup roots and allow_scans through the
    lifespan, so the server holds no mutable global."""
    import asyncio

    calls = []
    _install_stub_modules(monkeypatch, calls)
    sdk = server_mod.load_mcp_sdk()
    server = server_mod.build_server(sdk, ("/some/root",), allow_scans=True)

    async def exercise():
        async with server.lifespan(server) as state:
            return state

    assert asyncio.run(exercise()) == {
        "startup_roots": ("/some/root",),
        "allow_scans": True,
    }
