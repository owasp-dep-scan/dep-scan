import os

from quart import request, Quart
import tempfile

from analysis_lib import VdrAnalysisKV
from analysis_lib.vdr import VDRAnalyzer
from server_lib import ServerOptions

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


@app.get("/")
async def index():
    """
    :return: An empty dictionary
    """
    return {}


@app.before_request
async def enforce_allowlists():
    LOG = app.config.get("LOGGER_INSTANCE")
    is_testing = bool(os.getenv("PYTEST_CURRENT_TEST"))
    if is_testing:
        client_host = request.headers.get("X-Test-Remote-Addr")
    else:
        client_host = request.remote_addr
    allowed_hosts = app.config.get("ALLOWED_HOSTS")
    if allowed_hosts is not None:
        if not client_host or client_host not in allowed_hosts:
            if LOG:
                LOG.warning(f"Blocked request from unauthorized host: {client_host}")
            return {"error": "true", "message": "Host not allowed"}, 403
    if request.path == "/scan":
        allowed_paths = app.config.get("ALLOWED_PATHS")
        if allowed_paths is not None:
            path = None
            if request.args.get("path"):
                path = request.args.get("path")
            elif request.method == "POST":
                json_data = await request.get_json(silent=True)
                if json_data and "path" in json_data:
                    path = json_data["path"]
            if path:
                try:
                    real_path = os.path.realpath(path)
                    if not any(
                        real_path.startswith(os.path.realpath(a)) for a in allowed_paths
                    ):
                        if LOG:
                            LOG.warning(f"Blocked request for path: {path}")
                        return {"error": "true", "message": "Path not allowed"}, 403
                except (OSError, ValueError):
                    return {"error": "true", "message": "Invalid path"}, 403


@app.after_request
async def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = (
        "max-age=31536000; includeSubDomains"
    )
    return response


@app.route("/scan", methods=["GET", "POST"])
async def run_scan():
    """
    :return: A JSON response containing the SBOM file path and a list of
    vulnerabilities found in the scanned packages
    """
    LOG = app.config.get("LOGGER_INSTANCE")
    q = request.args
    params = await request.get_json()
    uploaded_bom_file = await request.files
    create_bom = app.config.get("create_bom")
    url = None
    path = None
    multi_project = None
    project_type = None
    results = []
    profile = "generic"
    deep = False
    suggest_mode = True if q.get("suggest") in ("true", "1") else False
    fuzzy_search = True if q.get("fuzzy_search") in ("true", "1") else False
    if q.get("url"):
        url = q.get("url")
    if q.get("path"):
        path = q.get("path")
    if q.get("multiProject"):
        multi_project = q.get("multiProject", "").lower() in ("true", "1")
    if q.get("deep"):
        deep = q.get("deep", "").lower() in ("true", "1")
    if q.get("type"):
        project_type = q.get("type")
    if q.get("profile"):
        profile = q.get("profile")
    if params is not None:
        if not url and params.get("url"):
            url = params.get("url")
        if not path and params.get("path"):
            path = params.get("path")
        if not multi_project and params.get("multiProject"):
            multi_project = params.get("multiProject", "").lower() in (
                "true",
                "1",
            )
        if not deep and params.get("deep"):
            deep = params.get("deep", "").lower() in (
                "true",
                "1",
            )
        if not project_type and params.get("type"):
            project_type = params.get("type")
        if not profile and params.get("profile"):
            profile = params.get("profile")

    if not path and not url and (uploaded_bom_file.get("file", None) is None):
        return {
            "error": "true",
            "message": "path or url or a bom file upload is required",
        }, 400
    if not project_type:
        return {"error": "true", "message": "project type is required"}, 400
    cdxgen_server = app.config.get("CDXGEN_SERVER_URL")
    bom_file_path = None
    tmp_bom_file = None
    if uploaded_bom_file.get("file", None) is not None:
        bom_file = uploaded_bom_file["file"]
        bom_file_suffix = str(bom_file.filename).rsplit(".", maxsplit=1)[-1]
        if bom_file_suffix not in (".json", ".cdx", ".bom"):
            return (
                {
                    "error": "true",
                    "message": "The uploaded file must be a valid JSON.",
                },
                400,
                {"Content-Type": "application/json"},
            )
        bom_file_content = bom_file.read().decode("utf-8")
        try:
            _ = json.loads(bom_file_content)
            if (
                not isinstance(bom_data, dict)
                or bom_data.get("bomFormat") != "CycloneDX"
            ):
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
        if LOG:
            LOG.debug("Processing uploaded file")
        tmp_bom_file = tempfile.NamedTemporaryFile(
            delete=False, suffix=f".bom.{bom_file_suffix}"
        )
        path = tmp_bom_file.name
        file_write(path, bom_file_content)
    if url:
        parsed = urlparse(url)
        if not parsed.scheme or parsed.scheme not in allowed_git_schemes:
            return {"error": "true", "message": "URL scheme is not allowed."}, 400
    # Path points to a project directory
    # Bug# 233. Path could be a url
    if url or (path and os.path.isdir(path)):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bom.json") as bfp:
            project_type_list = project_type.split(",")
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
                    if LOG:
                        LOG.debug("BOM file was generated successfully at %s", bfp.name)
                    bom_file_path = bfp.name

    # Path points to a SBOM file
    else:
        if os.path.exists(path):
            bom_file_path = path
    # Direct purl-based lookups are not supported yet.
    if bom_file_path is not None:
        pkg_list, _ = get_pkg_list(bom_file_path)
        # Here we are assuming there will be only one type
        if project_type in type_audit_map:
            audit_results = audit(project_type, pkg_list)
            if audit_results:
                results = results + audit_results
        if not pkg_list:
            if LOG:
                LOG.debug("Empty package search attempted!")
        else:
            if LOG:
                LOG.debug("Scanning %d oss dependencies for issues", len(pkg_list))
        bom_data = json_load(bom_file_path)
        if not bom_data:
            cleanup_temp(tmp_bom_file)
            return (
                {
                    "error": "true",
                    "message": "Unable to generate SBOM. Check your input path or url.",
                },
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
            logger=LOG,
            fuzzy_search=fuzzy_search,
        )
        vdr_result = VDRAnalyzer(vdr_options=options).process()
        if vdr_result.success:
            pkg_vulnerabilities = vdr_result.pkg_vulnerabilities
            if pkg_vulnerabilities:
                bom_data["vulnerabilities"] = pkg_vulnerabilities
            cleanup_temp(tmp_bom_file)
            return json.dumps(bom_data), 200, {"Content-Type": "application/json"}
    cleanup_temp(tmp_bom_file)
    return (
        {
            "error": "true",
            "message": "Unable to generate SBOM. Check your input path or url.",
        },
        500,
        {"Content-Type": "application/json"},
    )


def cleanup_temp(tmp_bom_file):
    if tmp_bom_file:
        os.remove(tmp_bom_file)


def run_server(options: ServerOptions):
    app.config["CDXGEN_SERVER_URL"] = options.cdxgen_server
    app.config["LOGGER_INSTANCE"] = options.logger
    if options.allowed_hosts:
        app.config["ALLOWED_HOSTS"] = [h.strip() for h in options.allowed_hosts if h]
    if options.allowed_paths:
        app.config["ALLOWED_PATHS"] = [
            os.path.realpath(p) for p in options.allowed_paths if p
        ]
    if options.max_content_length:
        app.config["MAX_CONTENT_LENGTH"] = options.max_content_length
    # Dirty hack to get access to the create_bom function
    if options.create_bom:
        app.config["create_bom"] = options.create_bom
    logger = options.logger
    if logger:
        logger.info(
            f"dep-scan server running on {options.server_host}:{options.server_port}"
        )
        if options.server_host not in (
            "127.0.0.1",
            "0000:0000:0000:0000:0000:0000:0000:0001",
            "0:0:0:0:0:0:0:1",
            "::1",
        ):
            logger.warning(
                "Server listening on non-local host without built-in authentication."
            )
    app.run(
        host=options.server_host,
        port=options.server_port,
        debug=options.debug,
        use_reloader=False,
        ca_certs=options.ca_certs,
        certfile=options.certfile,
        keyfile=options.keyfile,
    )
