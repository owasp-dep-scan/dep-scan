"""Tests of the ``depscan serve`` verb and the server stages it drives.

The verb's json document and its error paths are driven through
``depscan.cli.main`` the way a user drives them, with the server start and
the database stage stubbed by recorded calls. The pipeline-level tests drive
:func:`depscan.lib.pipeline.start_server_mode` and the download status site
directly, against a fake server package, so the startup hook's ordering and
the spinner suppression are observable without a running server.
"""

import argparse
import contextlib
import json
import socket
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from depscan import api, cli
from depscan.lib import pipeline


def run_main(monkeypatch, argv):
    """Run ``main`` with ``argv`` after the program name; the exit code."""
    monkeypatch.setattr(sys, "argv", ["depscan", *argv])
    with pytest.raises(SystemExit) as excinfo:
        cli.main()
    return excinfo.value.code


def _free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


class _FakeServerOptions:
    """Stands in for ServerOptions; records the values it was built with."""

    def __init__(self, **kwargs):
        self.kwargs = kwargs


class _FakeSimple:
    """Stands in for server_lib.simple: a registerable app, a recorded run.

    The default run models the real start: the server binds its port, the
    serving hooks run, and the connection of the announcement probe is
    accepted. A run without hooks skips the probe wait, the way the real
    server never announces in text mode.
    """

    def __init__(self):
        self.hooks = []
        self.run_calls = []
        self.order = []
        self.app = SimpleNamespace(before_serving=self.register)

    def register(self, func):
        self.hooks.append(func)
        return func

    def run_server(self, options):
        self.run_calls.append(options)
        host = options.kwargs["server_host"]
        port = int(options.kwargs["server_port"])
        self.order.append("run_server")
        with socket.socket() as listener:
            listener.bind((host, port))
            listener.listen(1)
            self.order.append("listening")
            for hook in self.hooks:
                hook()
            if self.hooks:
                listener.settimeout(5)
                connection, _ = listener.accept()
                connection.close()
                self.order.append("connected")
                # The probe announces as soon as its connection succeeds;
                # the pause keeps this run inside the server while it does.
                time.sleep(0.05)
            self.order.append("served")
        return None


@pytest.fixture
def fake_server(monkeypatch):
    """Install a fake server package and stub the database stage; record both."""
    fake = _FakeSimple()
    calls = {"database": []}
    monkeypatch.setattr(pipeline, "SERVER_LIB", fake, raising=False)
    monkeypatch.setattr(pipeline, "simple", fake, raising=False)
    monkeypatch.setattr(pipeline, "ServerOptions", _FakeServerOptions, raising=False)
    monkeypatch.setattr(pipeline, "stage_database", lambda ctx: calls["database"].append(ctx))
    return fake, calls


# --- the vdb download status spinner ---------------------------------------------


class _StatusStub:
    """A stand-in console that records the status calls made on it."""

    def __init__(self, is_terminal):
        self.is_terminal = is_terminal
        self.calls = []

    def status(self, message, **kwargs):
        self.calls.append((message, kwargs))

        @contextlib.contextmanager
        def running():
            yield "running-status"

        return running()


def test_download_status_draws_on_a_terminal(monkeypatch):
    stub = _StatusStub(is_terminal=True)
    monkeypatch.setattr(pipeline, "log_console", stub)
    monkeypatch.delattr(pipeline.logger_lib, "suppress_spinner", raising=False)

    with pipeline._vdb_download_status("Downloading") as status:
        assert status == "running-status"
    # Positive control: the console's status was entered with the message.
    assert len(stub.calls) == 1
    message, kwargs = stub.calls[0]
    assert "Downloading" in message
    assert kwargs["spinner"] == pipeline.SPINNER


def test_download_status_suppresses_on_a_plain_stream(monkeypatch, capsys):
    stub = _StatusStub(is_terminal=False)
    monkeypatch.setattr(pipeline, "log_console", stub)
    monkeypatch.delattr(pipeline.logger_lib, "suppress_spinner", raising=False)

    with pipeline._vdb_download_status("Downloading") as status:
        assert status is None
    # Nothing was drawn: the console's status was never asked for.
    assert stub.calls == []
    assert capsys.readouterr().out == ""


def test_download_status_uses_the_logger_helper_when_present(monkeypatch):
    """The logger owns when a spinner may draw; its helper decides."""
    helper_calls = []

    @contextlib.contextmanager
    def fake_suppress_spinner(console, message, **kwargs):
        helper_calls.append((console, message, kwargs))
        yield "helper-status"

    monkeypatch.setattr(
        pipeline.logger_lib, "suppress_spinner", fake_suppress_spinner, raising=False
    )
    stub = _StatusStub(is_terminal=False)
    monkeypatch.setattr(pipeline, "log_console", stub)

    with pipeline._vdb_download_status("Downloading") as status:
        assert status == "helper-status"
    # Positive control: the helper was reached, with the console, the
    # message and the spinner keyword, and the console was not consulted.
    assert len(helper_calls) == 1
    console, message, kwargs = helper_calls[0]
    assert console is stub
    assert "Downloading" in message
    assert kwargs["spinner"] == pipeline.SPINNER
    assert stub.calls == []


def test_stage_database_asks_for_the_download_status(tmp_path, monkeypatch):
    """The download branch of the database stage runs behind the status."""
    from depscan.lib import vdb_setup

    calls = {}
    monkeypatch.setattr(
        vdb_setup, "resolve_scan_vdb_image", lambda args: ("oras://vdb-img", False, "app-only")
    )
    monkeypatch.setattr(vdb_setup, "vdb_download_needed", lambda url, data_dir: (True, "stale"))
    monkeypatch.setattr(
        vdb_setup,
        "download_vdb_with_retries",
        lambda url: calls.setdefault("download", url),
    )
    monkeypatch.setattr(vdb_setup, "configure_vdb_readonly", lambda: None)
    monkeypatch.setattr(vdb_setup, "ensure_vdb_usable", lambda: None)
    monkeypatch.setattr(pipeline, "VDB_USE_SHARDS", False)

    def recording_status(message):
        calls["status"] = message

        @contextlib.contextmanager
        def none_status():
            yield None

        return none_status()

    monkeypatch.setattr(pipeline, "_vdb_download_status", recording_status)
    ctx = pipeline.build_context(
        argparse.Namespace(risk_audit=False, enable_debug=False, vdb_offline=False)
    )

    pipeline.stage_database(ctx)

    # Positive controls: the status was asked for the download, and the
    # download itself ran.
    assert "Downloading the latest vulnerability database" in calls["status"]
    assert calls["download"] == "oras://vdb-img"


# --- the startup announcement -----------------------------------------------------


def test_wait_until_listening_announces_only_on_a_real_listener(monkeypatch):
    monkeypatch.setattr(pipeline, "ANNOUNCE_TIMEOUT_SECONDS", 0.4)
    announced = []
    port = _free_port()
    # A port that was just closed answers nothing.
    pipeline._wait_until_listening("127.0.0.1", port, lambda: announced.append(True), threading.Event())
    assert announced == []
    # Positive control: the same probe announces against a real listener.
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", port))
        listener.listen(1)
        pipeline._wait_until_listening(
            "127.0.0.1", port, lambda: announced.append(True), threading.Event()
        )
    assert announced == [True]


def test_serve_prints_the_serving_document_once_the_port_accepts(
    monkeypatch, capsys, fake_server
):
    """The document prints from the startup machinery, after the bind."""
    fake, calls = fake_server
    port = _free_port()
    code = run_main(monkeypatch, ["serve", "--format", "json", "--server-port", str(port)])
    assert code == 0
    # The announcement probe connected only after the listening socket
    # existed, so the document never precedes the listener.
    order = fake.order
    assert order.index("connected") > order.index("listening")
    assert order.index("connected") > order.index("run_server")
    # The document is the only stdout content, and it carries the passed port.
    document = json.loads(capsys.readouterr().out)
    assert document == {
        "serving": {
            "host": "127.0.0.1",
            "port": str(port),
            "url": f"http://127.0.0.1:{port}",
        }
    }
    # Positive controls: the fake start ran once with the passed port, and
    # the database stage it owns ran before the server started.
    assert len(fake.run_calls) == 1
    assert fake.run_calls[0].kwargs["server_port"] == str(port)
    assert len(calls["database"]) == 1


def test_start_server_mode_raises_when_the_server_packages_are_missing(monkeypatch):
    monkeypatch.setattr(pipeline, "SERVER_LIB", None, raising=False)
    ctx = pipeline.build_context(api.scan_options(server_mode=True))
    with pytest.raises(pipeline.ServerRequirementError) as excinfo:
        pipeline.start_server_mode(ctx)
    assert "required packages" in str(excinfo.value)


def test_start_server_mode_raises_when_the_bind_is_refused(monkeypatch, fake_server):
    fake, calls = fake_server
    # run_server returns False only for the non-local bind refusal, and the
    # refusal happens before the serving hooks run.
    monkeypatch.setattr(fake, "run_server", lambda options: False)
    ctx = pipeline.build_context(api.scan_options(server_mode=True))
    with pytest.raises(pipeline.ServerRequirementError) as excinfo:
        pipeline.start_server_mode(ctx)
    assert "non-local host" in str(excinfo.value)


# --- the stdout contract of the verb ----------------------------------------------


@pytest.mark.parametrize("extra", [[], ["--format", "json"]])
def test_serve_moves_the_server_banners_to_stderr(monkeypatch, capsys, fake_server, extra):
    fake, calls = fake_server
    port = _free_port()
    original = fake.run_server

    def run_with_banner(options):
        original(options)
        print(" * Serving Quart app 'dep-scan server'")
        return None

    monkeypatch.setattr(fake, "run_server", run_with_banner)
    code = run_main(monkeypatch, ["serve", "--server-port", str(port), *extra])
    assert code == 0
    captured = capsys.readouterr()
    assert "Serving Quart app" in captured.err
    if "--format" in extra:
        document = json.loads(captured.out)
        assert "serving" in document
    else:
        assert captured.out == ""


def test_serve_reports_an_unexpected_start_failure_in_json(monkeypatch, capsys, fake_server):
    fake, calls = fake_server

    def failing(options):
        raise OSError("address already in use")

    monkeypatch.setattr(fake, "run_server", failing)
    code = run_main(monkeypatch, ["serve", "--format", "json"])
    assert code == 1
    captured = capsys.readouterr()
    # The failure never leaves stdout without its document, and the socket
    # that never listened announced nothing before it.
    document = json.loads(captured.out)
    assert document["error"]["exitCode"] == 1
    assert document["error"]["verb"] == "serve"
    assert "address already in use" in document["error"]["message"]
    assert "address already in use" in captured.err
