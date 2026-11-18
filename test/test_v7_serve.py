"""Tests of the ``depscan serve`` verb and the server stages it drives.

The verb's json document and its error paths are driven through
``depscan.cli.main`` the way a user drives them, with the server start and
the database stage stubbed by recorded calls. The pipeline-level tests drive
:func:`depscan.lib.pipeline.start_server_mode` and the download status site
directly, against a fake server package, so the startup hook's ordering and
the spinner suppression are observable without a running server.
"""

import argparse
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


class _FakeResponse:
    """A stand-in response for the fake app's after_request handlers."""

    def __init__(self):
        self.headers = {}


class _FakeSimple:
    """Stands in for server_lib.simple, in the real server's order.

    The serving hooks run before the socket binds, as hypercorn runs them,
    and responses flow through the app's after_request handlers, which is
    how the announcement's marker reaches the wire. The port may already be
    held by another listener, in which case the bind here fails the way the
    real bind does.
    """

    def __init__(self):
        self.hooks = []
        self.after_handlers = []
        self.run_calls = []
        self.order = []
        self.app = SimpleNamespace(
            before_serving=self._register_hook,
            after_request=self._register_after,
        )

    def _register_hook(self, func):
        self.hooks.append(func)
        return func

    def _register_after(self, func):
        self.after_handlers.append(func)
        return func

    def _answer_probe(self, connection):
        connection.settimeout(2)
        try:
            if not connection.recv(1024):
                return
            response = _FakeResponse()
            for handler in self.after_handlers:
                response = handler(response)
            headers = "".join(f"{name}: {value}\r\n" for name, value in response.headers.items())
            connection.sendall(
                b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n"
                + headers.encode()
                + b"\r\n{}"
            )
        except OSError:
            pass

    def run_server(self, options):
        self.run_calls.append(options)
        host = options.kwargs["server_host"]
        port = int(options.kwargs["server_port"])
        self.order.append("run_server")
        for hook in self.hooks:
            hook()
        with socket.socket() as listener:
            listener.bind((host, port))
            listener.listen(1)
            self.order.append("listening")
            if self.hooks:
                listener.settimeout(5)
                for _ in range(3):
                    try:
                        connection, _ = listener.accept()
                    except OSError:
                        break
                    self.order.append("connected")
                    self._answer_probe(connection)
                # The probe announces as soon as its answer carries the
                # marker; the pause keeps this run inside the server while
                # it does.
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


def test_stage_database_downloads_behind_a_quiet_status(monkeypatch, capsys):
    """On a redirected stderr the download status draws nothing and stops cleanly."""
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
    # IS_CI false takes the branch that stops the status early.
    monkeypatch.setattr(pipeline, "IS_CI", False)
    ctx = pipeline.build_context(
        argparse.Namespace(risk_audit=False, enable_debug=False, vdb_offline=False)
    )

    pipeline.stage_database(ctx)

    assert calls["download"] == "oras://vdb-img"
    captured = capsys.readouterr()
    assert "Downloading the latest vulnerability database" not in captured.err
    assert captured.out == ""


# --- the startup announcement -----------------------------------------------------


def _listening_socket(port) -> socket.socket:
    """A listening socket on the port, for the HTTP answerers below."""
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(1)
    return listener


def _serve_http_answers(listener: socket.socket, headers: bytes, ready):
    """Serve plain HTTP answers with the given extra headers until closed."""
    listener.settimeout(5)
    ready.set()
    try:
        while True:
            connection, _ = listener.accept()
            connection.recv(1024)
            connection.sendall(b"HTTP/1.0 200 OK\r\n" + headers + b"\r\n{}")
            connection.close()
    except OSError:
        return


def test_wait_until_listening_announces_only_on_the_marked_listener(monkeypatch):
    monkeypatch.setattr(pipeline, "ANNOUNCE_TIMEOUT_SECONDS", 1.0)
    announced = []
    marker = "dep-scan-hand-check"
    # A listener without this process's marker is not the server this
    # process started, whatever its port answers.
    foreign = _listening_socket(_free_port())
    foreign_ready = threading.Event()
    try:
        threading.Thread(
            target=_serve_http_answers,
            args=(foreign, b"Content-Length: 2\r\n", foreign_ready),
            daemon=True,
        ).start()
        assert foreign_ready.wait(2)
        pipeline._wait_until_listening(
            "127.0.0.1",
            foreign.getsockname()[1],
            marker,
            lambda: announced.append("foreign"),
            threading.Event(),
        )
        assert announced == []
        # Positive control: the listener carrying the marker is ours.
        ours = _listening_socket(_free_port())
        try:
            ours_ready = threading.Event()
            threading.Thread(
                target=_serve_http_answers,
                args=(
                    ours,
                    f"{pipeline._SERVING_MARKER_HEADER}: {marker}\r\nContent-Length: 2\r\n".encode(),
                    ours_ready,
                ),
                daemon=True,
            ).start()
            assert ours_ready.wait(2)
            pipeline._wait_until_listening(
                "127.0.0.1",
                ours.getsockname()[1],
                marker,
                lambda: announced.append("ours"),
                threading.Event(),
            )
            assert announced == ["ours"]
        finally:
            ours.close()
    finally:
        foreign.close()


def test_serve_prints_the_serving_document_once_the_port_accepts(monkeypatch, capsys, fake_server):
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
            "port": port,
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


def test_serve_never_announces_over_a_port_squatter(monkeypatch, capsys, fake_server):
    """A port another process holds never produces a serving document.

    The real failure of an occupied port is the bind error, and the
    squatter's listener must not be mistaken for this server's, however
    fast the announcement's first connection lands on it.
    """
    fake, calls = fake_server
    port = _free_port()
    squatter = _listening_socket(port)
    try:
        squatter_ready = threading.Event()
        threading.Thread(
            target=_serve_http_answers,
            args=(squatter, b"Content-Length: 2\r\n", squatter_ready),
            daemon=True,
        ).start()
        assert squatter_ready.wait(2)

        def failing_start(options):
            for hook in fake.hooks:
                hook()
            # The real startup machinery runs between the hook and the
            # bind, giving the announcement thread its scheduling window.
            time.sleep(0.2)
            raise OSError("[Errno 48] Address already in use")

        monkeypatch.setattr(fake, "run_server", failing_start)
        code = run_main(monkeypatch, ["serve", "--format", "json", "--server-port", str(port)])
        assert code == 1
        captured = capsys.readouterr()
        # The whole stdout is one document, the bind error. The squatter's
        # answers carry no marker, so no serving document may name it.
        document = json.loads(captured.out)
        assert document["error"]["exitCode"] == 1
        assert document["error"]["verb"] == "serve"
        assert "Address already in use" in document["error"]["message"]
    finally:
        squatter.close()


def test_serve_reports_an_unexpected_start_failure_in_json(monkeypatch, capsys, fake_server):
    fake, calls = fake_server

    def failing(options):
        raise OSError("address already in use")

    monkeypatch.setattr(fake, "run_server", failing)
    code = run_main(monkeypatch, ["serve", "--format", "json"])
    assert code == 1
    captured = capsys.readouterr()
    # The failure never leaves stdout without its document, and a start
    # whose hooks never ran announced nothing before it.
    document = json.loads(captured.out)
    assert document["error"]["exitCode"] == 1
    assert document["error"]["verb"] == "serve"
    assert "address already in use" in document["error"]["message"]
    assert "address already in use" in captured.err
