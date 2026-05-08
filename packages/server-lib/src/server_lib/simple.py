import contextlib
import ipaddress
import json
import os
import socket
import tempfile
from hmac import compare_digest
from urllib.parse import urlparse

from analysis_lib import VdrAnalysisKV
from analysis_lib.utils import get_pkg_list
from analysis_lib.vdr import VDRAnalyzer
from custom_json_diff.lib.utils import file_write
from quart import Quart, request
from rich.console import Console
from server_lib import ServerOptions
from vdb.lib import search
from vdb.lib.npm import NpmSource

app = Quart(f"dep-scan server ({__name__})", static_folder=None)
app.config.from_prefixed_env(prefix="DEPSCAN_SERVER")
app.config["PROVIDE_AUTOMATIC_OPTIONS"] = True


def get_allowed_git_schemes(default_schemes=None):
    if default_schemes is None:
        default_schemes = {"http", "https", "git", "git+http", "git+https"}
    env_var_value = os.getenv("DEPSCAN_SERVER_ALLOWED_GIT_SCHEMES")
    if env_var_value is not None:
        return {scheme.strip() for scheme in env_var_value.split(",") if scheme.strip()}
    return default_schemes


allowed_git_schemes = get_allowed_git_schemes()

# Dict mapping project type to the audit source
type_audit_map = {
    "nodejs": NpmSource(),
    "js": NpmSource(),
    "javascript": NpmSource(),
    "ts": NpmSource(),
    "typescript": NpmSource(),
    "npm": NpmSource(),
}
npm_app_info = {"name": "owasp-depscan-server", "version": "6.2.0"}

console = Console(
    log_time=False,
    log_path=False,
    color_system=os.getenv("CONSOLE_COLOR_SCHEME", "256"),
    tab_size=2,
    emoji=os.getenv("DISABLE_CONSOLE_EMOJI", "") not in ("true", "1"),
)

MAX_PROJECT_TYPES = 32
MAX_PROJECT_TYPE_LENGTH = 64
DEFAULT_MAX_BOM_FILE_SIZE = 100 * 1024 * 1024

UPLOAD_SIZE_LIMIT_MESSAGE = "BOM file exceeds the configured size limit."


def _is_truthy(value):
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in ("true", "1", "yes", "on")


def _is_local_host(host: str | None) -> bool:
    if not host:
        return False
    if host in (
        "127.0.0.1",
        "localhost",
        "0000:0000:0000:0000:0000:0000:0000:0001",
        "0:0:0:0:0:0:0:1",
        "::1",
    ):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _is_allowed_scan_path(path: str, allowed_paths: list[str]) -> bool:
    try:
        real_path = os.path.realpath(path)
    except (OSError, ValueError):
        return False
    for allowed_path in allowed_paths:
        try:
            real_allowed_path = os.path.realpath(allowed_path)
            if os.path.commonpath((real_path, real_allowed_path)) == real_allowed_path:
                return True
        except (OSError, ValueError):
            continue
    return False


def _get_config_int(config, *keys: str, default: int, logger=None) -> int:
    for key in keys:
        value = config.get(key)
        if value in (None, ""):
            continue
        try:
            return int(value)
        except (TypeError, ValueError):
            if logger:
                logger.warning("Ignoring invalid integer config for %s: %r", key, value)
    return default


def _is_private_or_local_ip(ip_text: str) -> bool:
    ip_obj = ipaddress.ip_address(ip_text)
    return any(
        (
            ip_obj.is_private,
            ip_obj.is_loopback,
            ip_obj.is_link_local,
            ip_obj.is_multicast,
            ip_obj.is_reserved,
            ip_obj.is_unspecified,
        )
    )


def _is_private_target(hostname: str | None) -> bool:
    if not hostname:
        return True
    host = hostname.strip("[]")
    try:
        return _is_private_or_local_ip(host)
    except ValueError:
        pass
    try:
        addr_info = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return True
    resolved_ips = {entry[4][0] for entry in addr_info if entry[4]}
    return not resolved_ips or any(_is_private_or_local_ip(ip_text) for ip_text in resolved_ips)


def _validate_remote_url(url: str, allowed_schemes: set[str], allow_private_urls: bool):
    parsed = urlparse(url)
    if not parsed.scheme or parsed.scheme not in allowed_schemes:
        return False, "URL scheme is not allowed."
    if not parsed.hostname:
        return False, "URL host is required."
    if not allow_private_urls and _is_private_target(parsed.hostname):
        return False, "URL host resolves to a private, loopback, or otherwise restricted address."
    return True, ""


def _parse_project_types(project_type_value: str) -> list[str]:
    project_types = []
    for project_type in (item.strip() for item in project_type_value.split(",")):
        if not project_type:
            continue
        if len(project_type) > MAX_PROJECT_TYPE_LENGTH:
            raise ValueError("project type is too long")
        if not all(ch.isalnum() or ch in ("-", "_", ".", "+") for ch in project_type):
            raise ValueError("project type contains unsupported characters")
        project_types.append(project_type)
        if len(project_types) > MAX_PROJECT_TYPES:
            raise ValueError("too many project types were supplied")
    if not project_types:
        raise ValueError("project type is required")
    return project_types


def _load_bom_data(bom_file_path: str, max_bytes: int):
    try:
        if max_bytes and os.path.getsize(bom_file_path) > max_bytes:
            return None, UPLOAD_SIZE_LIMIT_MESSAGE
        with open(bom_file_path, encoding="utf-8") as bom_fp:
            bom_data = json.load(bom_fp)
    except (FileNotFoundError, OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None, "Unable to read the BOM file."
    if not isinstance(bom_data, dict) or bom_data.get("bomFormat") != "CycloneDX":
        return None, "Uploaded file is not a valid CycloneDX BOM."
    return bom_data, ""


def _read_upload_with_limit(upload, max_bytes: int):
    declared_size = getattr(upload, "content_length", None)
    if declared_size not in (None, ""):
        with contextlib.suppress(TypeError, ValueError):
            if max_bytes and int(declared_size) > max_bytes:
                return None, UPLOAD_SIZE_LIMIT_MESSAGE

    stream = getattr(upload, "stream", None) or upload
    reader = getattr(stream, "read", None)
    if not callable(reader):
        return None, "Unable to read uploaded file."

    if not max_bytes:
        return reader(), ""

    max_bytes = int(max_bytes)
    bytes_remaining = max_bytes + 1
    chunks = []
    while bytes_remaining > 0:
        chunk = reader(min(65536, bytes_remaining))
        if not chunk:
            break
        if isinstance(chunk, str):
            chunk = chunk.encode("utf-8")
        elif not isinstance(chunk, bytes):
            chunk = bytes(chunk)
        chunks.append(chunk)
        bytes_remaining -= len(chunk)
    upload_content = b"".join(chunks)
    if len(upload_content) > max_bytes:
        return None, UPLOAD_SIZE_LIMIT_MESSAGE
    return upload_content, ""


def _get_request_api_key() -> str | None:
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header.removeprefix("Bearer ").strip()
    return request.headers.get("X-API-Key")


def audit(project_type, pkg_list):
    """
    Method to audit packages using remote source such as npm advisory

    :param project_type: Project type
    :param pkg_list: List of packages
    :return: Results
    """
    results = type_audit_map[project_type].bulk_search(app_info=npm_app_info, pkg_list=pkg_list)
    return results


@app.get("/")
async def index():
    """
    :return: An empty dictionary
    """
    return {}


@app.before_request
async def enforce_allowlists():
    logger_instance = app.config.get("LOGGER_INSTANCE")
    configured_api_key = app.config.get("API_KEY")
    if configured_api_key:
        request_api_key = _get_request_api_key()
        if not request_api_key or not compare_digest(str(configured_api_key), request_api_key):
            if logger_instance:
                logger_instance.warning("Blocked request with missing or invalid API key.")
            return {"error": "true", "message": "Authentication required"}, 401
    is_testing = bool(os.getenv("PYTEST_CURRENT_TEST"))
    if is_testing:
        client_host = request.headers.get("X-Test-Remote-Addr")
    else:
        client_host = request.remote_addr
    allowed_hosts = app.config.get("ALLOWED_HOSTS")
    if allowed_hosts is not None:
        if not client_host or client_host not in allowed_hosts:
            if logger_instance:
                logger_instance.warning(f"Blocked request from unauthorized host: {client_host}")
            return {"error": "true", "message": "Host not allowed"}, 403
    if request.path == "/scan":
        allowed_paths = app.config.get("ALLOWED_PATHS")
        if allowed_paths is not None:
            path = None
            if request.args.get("path"):
                path = request.args.get("path")
            elif request.method == "POST":
                json_data = await request.get_json(silent=True)
                if isinstance(json_data, dict) and "path" in json_data:
                    path = json_data["path"]
            if path:
                if not _is_allowed_scan_path(path, allowed_paths):
                    if logger_instance:
                        logger_instance.warning(f"Blocked request for path: {path}")
                    return {"error": "true", "message": "Path not allowed"}, 403


@app.after_request
async def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    if request.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.route("/scan", methods=["GET", "POST"])
async def run_scan():
    """
    :return: A JSON response containing the SBOM file path and a list of
    vulnerabilities found in the scanned packages
    """
    logger_instance = app.config.get("LOGGER_INSTANCE")
    q = request.args
    params = await request.get_json(silent=True)
    if not isinstance(params, dict):
        params = {}
    uploaded_bom_file = await request.files
    create_bom = app.config.get("create_bom")
    allow_private_urls = _is_truthy(app.config.get("ALLOW_PRIVATE_URLS"))
    max_bom_file_size = _get_config_int(
        app.config,
        "MAX_BOM_FILE_SIZE",
        "MAX_CONTENT_LENGTH",
        default=DEFAULT_MAX_BOM_FILE_SIZE,
        logger=logger_instance,
    )
    url = None
    path = None
    multi_project = None
    project_type = None
    results = []
    profile = "generic"
    deep = False
    suggest_mode = _is_truthy(q.get("suggest"))
    fuzzy_search = _is_truthy(q.get("fuzzy_search"))
    temp_paths = []
    if q.get("url"):
        url = q.get("url")
    if q.get("path"):
        path = q.get("path")
    if q.get("multiProject"):
        multi_project = _is_truthy(q.get("multiProject"))
    if q.get("deep"):
        deep = _is_truthy(q.get("deep"))
    if q.get("type"):
        project_type = q.get("type")
    if q.get("profile"):
        profile = q.get("profile")
    if not url and params.get("url"):
        url = params.get("url")
    if not path and params.get("path"):
        path = params.get("path")
    if multi_project is None and params.get("multiProject") is not None:
        multi_project = _is_truthy(params.get("multiProject"))
    if not deep and params.get("deep") is not None:
        deep = _is_truthy(params.get("deep"))
    if not project_type and params.get("type"):
        project_type = params.get("type")
    if params.get("profile"):
        profile = params.get("profile")

    if not path and not url and (uploaded_bom_file.get("file", None) is None):
        return {
            "error": "true",
            "message": "path or url or a bom file upload is required",
        }, 400
    if not project_type:
        return {"error": "true", "message": "project type is required"}, 400
    try:
        project_type_list = _parse_project_types(project_type)
    except ValueError as exc:
        return {"error": "true", "message": str(exc)}, 400
    cdxgen_server = app.config.get("CDXGEN_SERVER_URL")
    bom_file_path = None
    if uploaded_bom_file.get("file", None) is not None:
        bom_file = uploaded_bom_file["file"]
        bom_file_suffix = str(bom_file.filename).rsplit(".", maxsplit=1)[-1]
        if bom_file_suffix not in ("json", "cdx", "bom"):
            return (
                {
                    "error": "true",
                    "message": "The uploaded file must be a valid JSON.",
                },
                400,
                {"Content-Type": "application/json"},
            )
        bom_file_content_raw, bom_read_error = _read_upload_with_limit(bom_file, max_bom_file_size)
        if bom_read_error:
            return (
                {
                    "error": "true",
                    "message": bom_read_error,
                },
                400,
                {"Content-Type": "application/json"},
            )
        if isinstance(bom_file_content_raw, bytes):
            try:
                bom_file_content = bom_file_content_raw.decode("utf-8")
            except UnicodeDecodeError:
                return (
                    {
                        "error": "true",
                        "message": "The uploaded file must be valid UTF-8 JSON.",
                    },
                    400,
                    {"Content-Type": "application/json"},
                )
        else:
            bom_file_content = str(bom_file_content_raw)
        try:
            bom_data = json.loads(bom_file_content)
            if not isinstance(bom_data, dict) or bom_data.get("bomFormat") != "CycloneDX":
                return {
                    "error": "true",
                    "message": "Uploaded file is not a valid CycloneDX BOM.",
                }, 400
        except (json.JSONDecodeError, KeyError):
            return (
                {
                    "error": "true",
                    "message": "The uploaded file must be a valid JSON.",
                },
                400,
                {"Content-Type": "application/json"},
            )
        if logger_instance:
            logger_instance.debug("Processing uploaded file")
        tmp_bom_file = tempfile.NamedTemporaryFile(delete=False, suffix=f".bom.{bom_file_suffix}")
        path = tmp_bom_file.name
        tmp_bom_file.close()
        temp_paths.append(path)
        file_write(path, bom_file_content)
    if url:
        is_valid_url, validation_message = _validate_remote_url(
            url, allowed_git_schemes, allow_private_urls
        )
        if not is_valid_url:
            return {"error": "true", "message": validation_message}, 400
    # Path points to a project directory
    # Bug# 233. Path could be a url
    try:
        if url or (path and os.path.isdir(path)):
            if url and not path and not cdxgen_server:
                return (
                    {
                        "error": "true",
                        "message": "cdxgen server is required to generate SBOM for url.",
                    },
                    400,
                    {"Content-Type": "application/json"},
                )
            with tempfile.NamedTemporaryFile(delete=False, suffix=".bom.json") as bfp:
                temp_paths.append(bfp.name)
                if create_bom:
                    bom_status = create_bom(
                        bfp.name,
                        path,
                        {
                            "url": url,
                            "path": path,
                            "project_type": project_type_list,
                            "multiProject": multi_project,
                            "cdxgen_server": cdxgen_server,
                            "profile": profile,
                            "deep": deep,
                        },
                    )
                    if bom_status:
                        if logger_instance:
                            logger_instance.debug(
                                "BOM file was generated successfully at %s", bfp.name
                            )
                        bom_file_path = bfp.name
                    elif logger_instance:
                        logger_instance.debug("Problem generating the SBOM for %s %s", url, path)
        # Path points to a SBOM file
        elif path and os.path.exists(path):
            bom_file_path = path
        # Direct purl-based lookups are not supported yet.
        if bom_file_path is not None:
            pkg_list, _ = get_pkg_list(bom_file_path)
            # Here we are assuming there will be only one type
            if len(project_type_list) == 1 and project_type_list[0] in type_audit_map:
                audit_results = audit(project_type_list[0], pkg_list)
                if audit_results:
                    results = results + audit_results
            if not pkg_list:
                if logger_instance:
                    logger_instance.debug("Empty package search attempted!")
            else:
                if logger_instance:
                    logger_instance.debug("Scanning %d oss dependencies for issues", len(pkg_list))
            bom_data, bom_error = _load_bom_data(bom_file_path, max_bom_file_size)
            if not bom_data:
                return (
                    {"error": "true", "message": bom_error},
                    400,
                    {"Content-Type": "application/json"},
                )
            options = VdrAnalysisKV(
                project_type,
                results,
                pkg_aliases={},
                purl_aliases={},
                suggest_mode=suggest_mode,
                scoped_pkgs={},
                no_vuln_table=True,
                bom_file=bom_file_path,
                pkg_list=[],
                direct_purls={},
                reached_purls={},
                console=console,
                logger=logger_instance,
                fuzzy_search=fuzzy_search,
            )
            vdr_result = VDRAnalyzer(vdr_options=options).process()
            if vdr_result.success:
                pkg_vulnerabilities = vdr_result.pkg_vulnerabilities
                if pkg_vulnerabilities:
                    bom_data["vulnerabilities"] = pkg_vulnerabilities
                return json.dumps(bom_data), 200, {"Content-Type": "application/json"}
            if bom_data:
                return json.dumps(bom_data), 200, {"Content-Type": "application/json"}
        return (
            {
                "error": "true",
                "message": "Unable to generate SBOM. Check your input path or url.",
            },
            500,
            {"Content-Type": "application/json"},
        )
    finally:
        cleanup_temp(*temp_paths)


def cleanup_temp(*temp_files):
    for temp_file in temp_files:
        if not temp_file:
            continue
        candidate = getattr(temp_file, "name", temp_file)
        if not candidate:
            continue
        with contextlib.suppress(FileNotFoundError, OSError, TypeError):
            os.remove(candidate)


def run_server(options: ServerOptions):
    app.config["CDXGEN_SERVER_URL"] = options.cdxgen_server
    app.config["LOGGER_INSTANCE"] = options.logger
    app.config.setdefault("API_KEY", os.getenv("DEPSCAN_SERVER_API_KEY"))
    app.config.setdefault("ALLOW_PRIVATE_URLS", os.getenv("DEPSCAN_SERVER_ALLOW_PRIVATE_URLS"))
    app.config.setdefault(
        "ALLOW_UNAUTHENTICATED_BIND",
        os.getenv("DEPSCAN_SERVER_ALLOW_UNAUTHENTICATED_BIND"),
    )
    if options.allowed_hosts:
        app.config["ALLOWED_HOSTS"] = [h.strip() for h in options.allowed_hosts if h]
    if options.allowed_paths:
        app.config["ALLOWED_PATHS"] = [os.path.realpath(p) for p in options.allowed_paths if p]
    if options.max_content_length:
        app.config["MAX_CONTENT_LENGTH"] = options.max_content_length
    # Dirty hack to get access to the create_bom function
    if options.create_bom:
        app.config["create_bom"] = options.create_bom
    if options.custom_data_directory:
        if options.logger:
            options.logger.info(
                f"Loading custom vulnerability data from {options.custom_data_directory}"
            )
        search.load_custom_data(options.custom_data_directory)
    logger = options.logger
    if logger:
        logger.info(f"dep-scan server running on {options.server_host}:{options.server_port}")
    if not _is_local_host(options.server_host) and not app.config.get("API_KEY"):
        if not _is_truthy(app.config.get("ALLOW_UNAUTHENTICATED_BIND")):
            if logger:
                logger.error(
                    "Refusing to bind dep-scan server to a non-local host without DEPSCAN_SERVER_API_KEY or DEPSCAN_SERVER_ALLOW_UNAUTHENTICATED_BIND=true."
                )
            return False
        if logger:
            logger.warning("Server listening on non-local host without built-in authentication.")
    app.run(
        host=options.server_host,
        port=options.server_port,
        debug=options.debug,
        use_reloader=False,
        ca_certs=options.ca_certs,
        certfile=options.certfile,
        keyfile=options.keyfile,
    )
