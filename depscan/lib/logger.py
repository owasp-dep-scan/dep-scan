# This file is part of Scan.

import logging
import os

from rich.console import Console
from rich.highlighter import RegexHighlighter
from rich.logging import RichHandler
from rich.theme import Theme


class CustomHighlighter(RegexHighlighter):
    base_style = "atom."
    highlights = [
        r"(?P<method>([\w-]+\.)+[\w-]+[^<>:(),]?)",
        r"(?P<path>(\w+\/.*\.[\w:]+))",
        r"(?P<params>[(]([\w,-]+\.)+?[\w-]+[)]$)",
        r"(?P<opers>(unresolvedNamespace|unresolvedSignature|init|operators|operator|clinit))",
    ]


custom_theme = Theme(
    {
        "atom.path": "#7c8082",
        "atom.params": "#5a7c90",
        "atom.opers": "#7c8082",
        "atom.method": "#FF753D",
        "info": "#5A7C90",
        "warning": "#FF753D",
        "danger": "bold red",
    }
)

console = Console(
    log_time=False,
    log_path=False,
    theme=custom_theme,
    width=int(os.getenv("COLUMNS", "270")),
    color_system="256",
    force_terminal=True,
    highlight=True,
    highlighter=CustomHighlighter(),
    record=True,
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
for _ in ("httpx", "oras"):
    logging.getLogger(_).disabled = True

# Set logging level
if os.getenv("SCAN_DEBUG_MODE") == "debug" or os.getenv("AT_DEBUG_MODE") == "debug":
    LOG.setLevel(logging.DEBUG)

DEBUG = logging.DEBUG
