import logging
import os
import random
import re
import sys

from rich.console import Console
from rich.highlighter import RegexHighlighter
from rich.logging import RichHandler
from rich.theme import Theme


class CustomHighlighter(RegexHighlighter):
    base_style = "depscan."
    highlights = [
        r"(?P<method>([\w-]+\.)+[\w-]+[^<>:(),]?)",
        r"(?P<path>(\w+\/.*\.[\w:]+))",
        r"(?P<params>[(]([\w,-]+\.)+?[\w-]+[)]$)",
        r"(?P<opers>(unresolvedNamespace|unresolvedSignature|init|operators|operator|clinit))",
    ]


custom_theme = Theme(
    {
        "depscan.path": "#7c8082",
        "depscan.params": "#5a7c90",
        "depscan.opers": "#7c8082",
        "depscan.method": "#FF753D",
        "info": "#5A7C90",
        "warning": "#FF753D",
        "danger": "bold red",
    }
)

IS_CI = os.getenv("CI") or os.getenv("CONTINUOUS_INTEGRATION")

# rich only accepts these color-system names (or None); anything else raises
# KeyError while constructing the Console, i.e. at import time.
VALID_COLOR_SYSTEMS = ("auto", "standard", "256", "truecolor", "windows")


def _color_arguments():
    """Decide the colour arguments for the dep-scan consoles.

    Colour follows the stream unless the user asked otherwise. NO_COLOR set to
    any non-empty value turns colour off on every stream, including a real
    terminal. FORCE_COLOR set to any non-empty value, or an explicitly set
    CONSOLE_COLOR_SCHEME, turns colour on even when the stream is not a
    terminal: the named scheme when valid, otherwise rich's own detection of
    the best colour system. With none of the variables set, rich detects
    colour support per stream, so a file or a pipe receives plain text.
    """
    if os.getenv("NO_COLOR", ""):
        return {"color_system": None}
    scheme = os.getenv("CONSOLE_COLOR_SCHEME") or ""
    if scheme and scheme in VALID_COLOR_SYSTEMS:
        # The scheme goes to rich directly and bypasses detection, so it
        # holds for redirected streams too: that is what setting it
        # explicitly means.
        return {"color_system": scheme}
    if not scheme and not os.getenv("FORCE_COLOR", ""):
        return {"color_system": "auto"}
    if os.getenv("TERM", "").strip().lower() in ("dumb", "unknown"):
        # rich would auto-detect no colour support on a terminal that calls
        # itself dumb, but the request for colour here is explicit, so keep a
        # plain 16-colour system instead of none.
        return {"color_system": "standard", "force_terminal": True}
    return {"color_system": "auto", "force_terminal": True}


def _is_terminal(stream=None):
    """Whether the given stream (stderr by default) is a terminal.

    ``isatty`` raises ValueError on a closed stream, which happens during test
    teardown; a closed stream is not a terminal.
    """
    if stream is None:
        stream = sys.stderr
    try:
        return stream.isatty()
    except ValueError:
        return False


def _emoji_enabled(file):
    """Whether emoji shortcodes render on the console for ``file``.

    Emoji follow DISABLE_CONSOLE_EMOJI and are also off when the stream is
    not a terminal: an emoji pasted into a redirected stream is noise for the
    agent or script reading it.
    """
    if os.getenv("DISABLE_CONSOLE_EMOJI", "") in ("true", "1"):
        return False
    if not _is_terminal(file):
        return False
    return not (sys.platform == "win32" and IS_CI)


def _build_console(file=None, **overrides):
    """Build a rich console with dep-scan's colour, emoji and width rules.

    Both dep-scan consoles go through this builder so they always agree on
    the colour, emoji and CI-width rules. A console built without ``file``
    pins no stream: rich writes to the current ``sys.stdout`` on every call,
    so a harness that replaces that stream after import (pytest's capsys,
    for example) keeps capturing the console's output. The emoji decision is
    still made here, against ``sys.stdout``, and does not follow the
    replacement.
    """
    kwargs = dict(
        file=file,
        log_time=False,
        log_path=False,
        theme=custom_theme,
        width=140 if IS_CI else None,
        highlight=not IS_CI,
        tab_size=2,
        highlighter=CustomHighlighter(),
        emoji=_emoji_enabled(file if file is not None else sys.stdout),
    )
    kwargs.update(_color_arguments())
    kwargs.update(overrides)
    return Console(**kwargs)


# The stdout console pins no file, so it follows the current sys.stdout at
# write time; the stderr console below is built with its stream and stays on
# it.
console = _build_console(record=sys.platform == "win32")

# Logs, warnings and progress print on stderr so the stdout console carries
# only rendered output (tables, summaries, explanations) and its HTML and
# text exports stay free of log lines. The same theme and colour rules apply;
# this console records nothing because no report exports it.
log_console = _build_console(sys.stderr)


def spinners_enabled(stream=None):
    """Whether progress bars and spinners may draw.

    A spinner or progress bar animates by erasing and redrawing itself, which
    only a terminal can do, so they stay off whenever stderr is redirected.
    The check is on the real stream: it does not follow FORCE_COLOR, which
    only decides colour.
    """
    return _is_terminal(stream)


class _QuietStatus:
    """Stand-in for a rich spinner when stderr is not a terminal.

    The context yields itself and ``update`` accepts the same arguments as
    the rich status object without drawing anything, so callers that use
    ``status.update`` mid-way keep working unchanged.
    """

    def update(self, *args, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False


def console_status(*args, **kwargs):
    """Show a status message with a spinner on stderr.

    On a redirected stderr nothing is drawn: the message would only repeat
    once per refresh into the file or pipe a caller is capturing.
    """
    if spinners_enabled():
        return log_console.status(*args, **kwargs)
    return _QuietStatus()


logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[
        RichHandler(
            console=log_console,
            markup=True,
            show_path=False,
            enable_link_path=False,
        )
    ],
)
LOG = logging.getLogger(__name__)

# Set logging level
if os.getenv("SCAN_DEBUG_MODE") == "debug":
    LOG.setLevel(logging.DEBUG)

DEBUG = logging.DEBUG
for log_name, log_obj in logging.Logger.manager.loggerDict.items():
    # loggerDict also contains PlaceHolder entries for intermediate dotted
    # names (e.g. "depscan.lib" when only "depscan.lib.a" was ever created);
    # those cannot be muted and must be skipped.
    if not log_name.startswith("depscan") and isinstance(log_obj, logging.Logger):
        log_obj.disabled = True

SPINNER = os.getenv(
    "DEPSCAN_SPINNER",
    random.choice(
        [
            "pong",
            "arrow3",
            "bouncingBall",
            "dots2",
            "material",
            "shark",
            "simpleDotsScrolling",
            "toggle9",
        ]
    ),
)

# Support for thought logging
tlogger = None


def thought_log(s):
    if s and tlogger and tlogger.isEnabledFor(DEBUG):
        s = re.sub(r"([.!?])?$", ".", s)
        tlogger.debug(s)


def thought_begin():
    thought_log("<think>")


def thought_end():
    thought_log("</think>")


if os.getenv("DEPSCAN_THINK_MODE", "") in ("true", "1"):
    tlogger = logging.getLogger("depscan_thoughts")
    tlogger.setLevel(DEBUG)
    file_handler = logging.FileHandler(
        os.getenv("DEPSCAN_THOUGHT_LOG", os.path.join(os.getcwd(), "depscan-thoughts.log"))
    )
    file_handler.setLevel(DEBUG)
    formatter = logging.Formatter("%(message)s")
    file_handler.setFormatter(formatter)
    tlogger.addHandler(file_handler)
