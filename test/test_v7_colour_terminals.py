"""Colour, emoji and spinner rules for the two dep-scan consoles.

Colour follows the stream unless the user asked otherwise: NO_COLOR set to
any non-empty value turns colour off everywhere, FORCE_COLOR or an explicit
CONSOLE_COLOR_SCHEME other than ``auto`` turns it on even for a redirected
stream, and with none of them set rich detects colour support per stream.
Emoji follow
DISABLE_CONSOLE_EMOJI and stay off on a non-terminal. Progress bars and
spinners stay off whenever stderr is not a terminal.
"""

import io
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from depscan.lib import logger

REPO_ROOT = Path(__file__).resolve().parents[1]

COLOUR_VARS = ("NO_COLOR", "FORCE_COLOR", "CONSOLE_COLOR_SCHEME", "DISABLE_CONSOLE_EMOJI")


class _FakeTty(io.StringIO):
    """In-memory stream that claims to be a terminal."""

    def isatty(self):
        return True


@pytest.fixture(autouse=True)
def _known_colour_environment(monkeypatch):
    """Give every test a known colour environment to reason about."""
    for name in (*COLOUR_VARS, "COLORTERM"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")


@pytest.mark.parametrize(
    ("environ", "expected"),
    [
        ({}, {"color_system": "auto"}),
        ({"NO_COLOR": "1"}, {"color_system": None}),
        # Any non-empty value counts, including one that reads as false.
        ({"NO_COLOR": "0"}, {"color_system": None}),
        ({"NO_COLOR": ""}, {"color_system": "auto"}),
        ({"FORCE_COLOR": "1"}, {"color_system": "auto", "force_terminal": True}),
        ({"CONSOLE_COLOR_SCHEME": "256"}, {"color_system": "256"}),
        ({"CONSOLE_COLOR_SCHEME": "truecolor"}, {"color_system": "truecolor"}),
        # Explicit but unknown: colour is still asked for, rich picks the system.
        (
            {"CONSOLE_COLOR_SCHEME": "bogus"},
            {"color_system": "auto", "force_terminal": True},
        ),
        ({"CONSOLE_COLOR_SCHEME": ""}, {"color_system": "auto"}),
        # NO_COLOR wins over the variables that ask for colour.
        (
            {"NO_COLOR": "1", "FORCE_COLOR": "1", "CONSOLE_COLOR_SCHEME": "256"},
            {"color_system": None},
        ),
    ],
)
def test_colour_arguments_follow_the_user(monkeypatch, environ, expected):
    for name in COLOUR_VARS:
        monkeypatch.delenv(name, raising=False)
    for name, value in environ.items():
        monkeypatch.setenv(name, value)
    assert logger._color_arguments() == expected


def test_stderr_as_a_file_is_plain_by_default():
    stderr = _run_console_child({})
    assert b"\x1b" not in stderr
    # Emoji are off for the non-terminal stream, so the shortcode stays text.
    assert b":thumbs_up:" in stderr


def test_force_colour_reaches_stderr_as_a_file():
    stderr = _run_console_child({"FORCE_COLOR": "1"})
    assert b"\x1b[" in stderr


def test_explicit_scheme_reaches_stderr_as_a_file():
    """CONSOLE_COLOR_SCHEME set explicitly forces colour, as before."""
    stderr = _run_console_child({"CONSOLE_COLOR_SCHEME": "256"})
    assert b"\x1b[" in stderr


def test_terminal_gets_colour_by_default_and_no_color_removes_it(monkeypatch):
    monkeypatch.setattr(logger, "IS_CI", False)
    tty = _FakeTty()
    logger._build_console(tty).print("[bold red]scan failed[/bold red]")
    assert "\x1b[" in tty.getvalue()

    monkeypatch.setenv("NO_COLOR", "1")
    quiet_tty = _FakeTty()
    logger._build_console(quiet_tty).print("[bold red]scan failed[/bold red]")
    assert "\x1b[" not in quiet_tty.getvalue()


def test_no_color_beats_the_colour_variables_on_a_terminal(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setenv("FORCE_COLOR", "1")
    monkeypatch.setenv("CONSOLE_COLOR_SCHEME", "256")
    quiet_tty = _FakeTty()
    logger._build_console(quiet_tty).print("[bold red]scan failed[/bold red]")
    assert "\x1b[" not in quiet_tty.getvalue()


def test_unknown_scheme_still_colours_a_terminal(monkeypatch):
    """An explicit but invalid scheme asks for colour, rich picks the system."""
    monkeypatch.setenv("CONSOLE_COLOR_SCHEME", "bogus")
    tty = _FakeTty()
    console = logger._build_console(tty)
    console.print("[bold red]scan failed[/bold red]")
    assert "\x1b[" in tty.getvalue()


def test_dumb_terminal_still_colours_when_asked(monkeypatch):
    """TERM=dumb auto-detects no colour, but FORCE_COLOR asks on purpose."""
    monkeypatch.setenv("TERM", "dumb")
    monkeypatch.setenv("FORCE_COLOR", "1")
    stream = io.StringIO()
    console = logger._build_console(stream)
    console.print("[bold red]scan failed[/bold red]")
    assert "\x1b[" in stream.getvalue()


def test_emoji_follow_the_terminal_and_the_disable_variable(monkeypatch):
    monkeypatch.setattr(logger, "IS_CI", False)
    tty = _FakeTty()
    logger._build_console(tty).print(":thumbs_up: hello")
    assert ":thumbs_up:" not in tty.getvalue()

    monkeypatch.setenv("DISABLE_CONSOLE_EMOJI", "1")
    plain_tty = _FakeTty()
    logger._build_console(plain_tty).print(":thumbs_up: hello")
    assert ":thumbs_up:" in plain_tty.getvalue()


def test_emoji_are_off_for_a_non_terminal(monkeypatch):
    monkeypatch.setattr(logger, "IS_CI", False)
    stream = io.StringIO()
    logger._build_console(stream).print(":thumbs_up: hello")
    assert ":thumbs_up:" in stream.getvalue()


def test_spinners_enabled_follows_stderr():
    assert logger.spinners_enabled(io.StringIO()) is False
    assert logger.spinners_enabled(_FakeTty()) is True


def test_progress_disabled_keeps_the_small_run_rule(monkeypatch):
    import depscan.lib.package_query.metadata as metadata

    monkeypatch.setattr(metadata, "spinners_enabled", lambda: True)
    assert metadata._progress_disabled(9) is True
    assert metadata._progress_disabled(10) is False


def test_console_status_is_quiet_for_a_redirected_stderr(monkeypatch):
    drawn = []

    def fake_status(*args, **kwargs):
        drawn.append((args, kwargs))
        raise AssertionError("rich status must not start for a redirected stderr")

    monkeypatch.setattr(logger, "log_console", SimpleNamespace(status=fake_status))
    monkeypatch.setattr(logger, "spinners_enabled", lambda: False)
    with logger.console_status("Generating BOM", spinner="dots") as status:
        status.update("Still generating")
    assert drawn == []
    # Exceptions the guarded work raises still propagate.
    with pytest.raises(RuntimeError), logger.console_status("Working"):
        raise RuntimeError("boom")


def test_console_status_spins_for_a_terminal(monkeypatch):
    recorded = {}
    marker = object()

    def fake_status(*args, **kwargs):
        recorded["args"] = args
        recorded["kwargs"] = kwargs
        return marker

    monkeypatch.setattr(logger, "log_console", SimpleNamespace(status=fake_status))
    monkeypatch.setattr(logger, "spinners_enabled", lambda: True)
    assert logger.console_status("Generating BOM", spinner="dots") is marker
    assert recorded == {"args": ("Generating BOM",), "kwargs": {"spinner": "dots"}}


def test_bom_spins_through_the_console_status_helper(monkeypatch, tmp_path):
    """The blint BOM generator runs inside the gated status context."""
    from depscan.lib import bom

    entered = []

    def spy_status(message, **kwargs):
        entered.append((message, kwargs))
        return logger._QuietStatus()

    class StubGenerator:
        def __init__(self, src_dir, bom_file, logger=None, options=None):
            self.bom_file = bom_file

        def generate(self):
            Path(self.bom_file).write_text("{}", encoding="utf-8")
            return SimpleNamespace(success=True)

    monkeypatch.setattr(bom, "console_status", spy_status)
    monkeypatch.setattr(bom, "BlintGenerator", StubGenerator)
    assert bom.create_blint_bom(str(tmp_path / "bom.json"), str(tmp_path)) is True
    assert entered == [
        (f"Generating BOM for the source '{tmp_path}' with blint.", {"spinner": bom.SPINNER})
    ]


def test_bom_has_no_ungated_spinner_sites():
    """Every spinner in bom.py draws through console_status."""
    from depscan.lib import bom

    source = Path(bom.__file__).read_text(encoding="utf-8")
    assert "log_console.status" not in source


def _run_console_child(extra_env):
    """Import the logger in a fresh interpreter and print to stderr.

    The child's streams are pipes, so both count as redirected streams, and
    the colour variables are set only by ``extra_env``. TERM is dropped so
    the child cannot inherit a terminal description from the caller.
    """
    script = (
        "import sys\n"
        "from depscan.lib import logger\n"
        "logger.log_console.print('[bold red]scan failed[/bold red]')\n"
        "logger.log_console.print(':thumbs_up: done')\n"
    )
    dropped = COLOUR_VARS + ("TERM", "COLORTERM", "CI", "CONTINUOUS_INTEGRATION")
    env = {name: value for name, value in os.environ.items() if name not in dropped}
    env.update(extra_env)
    env["PYTHONPATH"] = str(REPO_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    result = subprocess.run(
        [sys.executable, "-c", script],
        env=env,
        capture_output=True,
        cwd=REPO_ROOT,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
    return result.stderr
