# This file is part of Scan.

# Scan is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# Scan is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with Scan.  If not, see <https://www.gnu.org/licenses/>.

import logging
import os

from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

custom_theme = Theme({"info": "cyan", "warning": "purple4", "danger": "bold red"})
console = Console(
    log_time=False,
    log_path=False,
    theme=custom_theme,
    width=int(os.getenv("COLUMNS", 270)),
    color_system="256",
    force_terminal=True,
    record=True,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[
        RichHandler(
            console=console, markup=True, show_path=False, enable_link_path=False
        )
    ],
)
LOG = logging.getLogger(__name__)

# Set logging level
if os.getenv("SCAN_DEBUG_MODE") == "debug":
    LOG.setLevel(logging.DEBUG)

DEBUG = logging.DEBUG
