from dataclasses import dataclass
from typing import Callable, Dict, List, Optional
from logging import Logger
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
    max_content_length: int = 100 * 1024 * 1024  # 100MB
    # Hack
    create_bom: Optional[Callable] = None
