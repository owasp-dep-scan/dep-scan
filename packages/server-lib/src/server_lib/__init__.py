from dataclasses import dataclass
from logging import Logger
from typing import Callable, List, Optional

from rich.console import Console


@dataclass
class ServerOptions:
    server_host: str = "127.0.0.1"
    server_port: int = 7070
    cdxgen_server: Optional[str] = None
    allowed_hosts: Optional[List[str]] = None
    allowed_paths: Optional[List[str]] = None
    console: Optional[Console] = None
    logger: Optional[Logger] = None
    ca_certs: Optional[str] = None
    certfile: Optional[str] = None
    keyfile: Optional[str] = None
    debug: bool = False
    # Maximum request body size in bytes. None means no limit is configured
    # (Flask leaves MAX_CONTENT_LENGTH unset); a non-int value such as the raw
    # env string breaks Werkzeug's per-request size comparison.
    max_content_length: Optional[int] = 100 * 1024 * 1024  # 100MB
    # Hack
    create_bom: Optional[Callable] = None
    # Scans one BOM file for a request: takes the BOM path, a reports
    # directory under the server's temporary directory, the requested project
    # type and the suggest/fuzzy flags, and returns the list of VDR
    # vulnerability objects for the response. Injected by depscan because
    # this package cannot import it.
    scan_bom: Optional[Callable] = None
    custom_data_directory: Optional[str] = None
