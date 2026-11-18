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
import sys

import pytest

from depscan import cli
from depscan.lib import pipeline


def run_main(monkeypatch, argv):
    """Run ``main`` with ``argv`` after the program name; the exit code."""
    monkeypatch.setattr(sys, "argv", ["depscan", *argv])
    with pytest.raises(SystemExit) as excinfo:
        cli.main()
    return excinfo.value.code


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
