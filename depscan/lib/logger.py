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

console = Console(
    log_time=False,
    log_path=False,
    theme=custom_theme,
    color_system=os.getenv("CONSOLE_COLOR_SCHEME", "256"),
    width=140 if IS_CI else None,
    highlight=not IS_CI,
    tab_size=2,
    highlighter=CustomHighlighter(),
    record=sys.platform == "win32",
    emoji=os.getenv("DISABLE_CONSOLE_EMOJI", "") not in ("true", "1"),
)

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[
        RichHandler(
            console=console,
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
    if not log_name.startswith("depscan"):
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
        os.getenv(
            "DEPSCAN_THOUGHT_LOG", os.path.join(os.getcwd(), "depscan-thoughts.log")
        )
    )
    file_handler.setLevel(DEBUG)
    formatter = logging.Formatter("%(message)s")
    file_handler.setFormatter(formatter)
    tlogger.addHandler(file_handler)
