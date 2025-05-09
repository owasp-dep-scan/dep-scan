import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from logging import Logger
from typing import Any, Dict, List, Optional, Tuple

import httpx

from xbom_lib import BOMResult, XBOMGenerator

cdxgen_server_headers = {
    "Content-Type": "application/json",
    "Accept-Encoding": "gzip",
}

# cdxgen timeout. Increased to 30 minutes
CDXGEN_TIMEOUT_MS = os.getenv("CDXGEN_TIMEOUT_MS", str(int(30 * 60 * 1000)))

# version of cdxgen to use
CDXGEN_IMAGE_VERSION = os.getenv("CDXGEN_IMAGE_VERSION", "latest")
CDXGEN_IMAGE_ROLLING_VERSION = os.getenv("CDXGEN_IMAGE_ROLLING_VERSION", "v11")

# cdxgen default image to use
DEFAULT_IMAGE_NAME = (
    "default-secure"
    if os.getenv("CDXGEN_SECURE_MODE", "") in ("true", "1")
    else "default"
)

# cdxgen official image namespaces
OFFICIAL_IMAGE_NAMESPACES = (
    "ghcr.io/cyclonedx/",
    "ghcr.io/appthreat/",
    "ghcr.io/owasp-dep-scan/",
)

PROJECT_TYPE_IMAGE = {
    "default": f"ghcr.io/cyclonedx/cdxgen:{CDXGEN_IMAGE_VERSION}",
    "deno": f"ghcr.io/cyclonedx/cdxgen-deno:{CDXGEN_IMAGE_VERSION}",
    "bun": f"ghcr.io/cyclonedx/cdxgen-bun:{CDXGEN_IMAGE_VERSION}",
    "default-secure": f"ghcr.io/cyclonedx/cdxgen-secure:{CDXGEN_IMAGE_VERSION}",
    "java": f"ghcr.io/cyclonedx/cdxgen-temurin-java21:{CDXGEN_IMAGE_VERSION}",
    "java24": f"ghcr.io/cyclonedx/cdxgen:{CDXGEN_IMAGE_VERSION}",
    "android": f"ghcr.io/cyclonedx/cdxgen:{CDXGEN_IMAGE_VERSION}",
    "java8": f"ghcr.io/cyclonedx/cdxgen-temurin-java8:{CDXGEN_IMAGE_VERSION}",
    "java11-slim": f"ghcr.io/cyclonedx/cdxgen-java11-slim:{CDXGEN_IMAGE_VERSION}",
    "java11": f"ghcr.io/cyclonedx/cdxgen-java11:{CDXGEN_IMAGE_VERSION}",
    "java17": f"ghcr.io/cyclonedx/cdxgen-java17:{CDXGEN_IMAGE_VERSION}",
    "java17-slim": f"ghcr.io/cyclonedx/cdxgen-java17-slim:{CDXGEN_IMAGE_VERSION}",
    "java21": f"ghcr.io/cyclonedx/cdxgen-temurin-java21:{CDXGEN_IMAGE_VERSION}",
    "node20": f"ghcr.io/cyclonedx/cdxgen-node20:{CDXGEN_IMAGE_VERSION}",
    "python39": f"ghcr.io/cyclonedx/cdxgen-python39:{CDXGEN_IMAGE_VERSION}",
    "python310": f"ghcr.io/cyclonedx/cdxgen-python310:{CDXGEN_IMAGE_VERSION}",
    "python311": f"ghcr.io/cyclonedx/cdxgen-python311:{CDXGEN_IMAGE_VERSION}",
    "python312": f"ghcr.io/cyclonedx/cdxgen-python312:{CDXGEN_IMAGE_VERSION}",
    "python": f"ghcr.io/cyclonedx/cdxgen-python312:{CDXGEN_IMAGE_VERSION}",
    "swift": f"ghcr.io/cyclonedx/cdxgen-debian-swift6:{CDXGEN_IMAGE_VERSION}",
    "swift6": f"ghcr.io/cyclonedx/cdxgen-debian-swift6:{CDXGEN_IMAGE_VERSION}",
    "ruby26": f"ghcr.io/cyclonedx/cdxgen-debian-ruby26:{CDXGEN_IMAGE_ROLLING_VERSION}",
    "ruby33": f"ghcr.io/cyclonedx/cdxgen-debian-ruby33:{CDXGEN_IMAGE_ROLLING_VERSION}",
    "ruby34": f"ghcr.io/cyclonedx/cdxgen-debian-ruby34:{CDXGEN_IMAGE_ROLLING_VERSION}",
    "ruby": f"ghcr.io/cyclonedx/cdxgen-debian-ruby34:{CDXGEN_IMAGE_ROLLING_VERSION}",
    "dotnet-core": f"ghcr.io/cyclonedx/cdxgen-debian-dotnet6:{CDXGEN_IMAGE_VERSION}",
    "dotnet-framework": f"ghcr.io/cyclonedx/cdxgen-debian-dotnet6:{CDXGEN_IMAGE_VERSION}",
    "dotnet6": f"ghcr.io/cyclonedx/cdxgen-debian-dotnet6:{CDXGEN_IMAGE_VERSION}",
    "dotnet7": f"ghcr.io/cyclonedx/cdxgen-dotnet7:{CDXGEN_IMAGE_VERSION}",
    "dotnet8": f"ghcr.io/cyclonedx/cdxgen-debian-dotnet8:{CDXGEN_IMAGE_VERSION}",
    "dotnet9": f"ghcr.io/cyclonedx/cdxgen-debian-dotnet9:{CDXGEN_IMAGE_VERSION}",
    "dotnet": f"ghcr.io/cyclonedx/cdxgen-debian-dotnet9:{CDXGEN_IMAGE_VERSION}",
}


def get_env_options_value(options: Dict, k: str, default: Optional[str] = None) -> str:
    return os.getenv(k.upper(), options.get(k.lower(), default))


def get_image_for_type(options: Dict, project_type: str | list | None) -> str:
    if not project_type:
        return DEFAULT_IMAGE_NAME
    project_types: list[str] = (
        project_type if isinstance(project_type, list) else [project_type]
    )
    ptype = project_types[0] if len(project_types) == 1 else DEFAULT_IMAGE_NAME
    default_img = PROJECT_TYPE_IMAGE.get(ptype, PROJECT_TYPE_IMAGE[DEFAULT_IMAGE_NAME])
    return get_env_options_value(
        options,
        f"cdxgen_image_{ptype}",
        default_img,
    )


def needs_latest_image(image_name):
    return any(
        image_name.startswith(ns) for ns in OFFICIAL_IMAGE_NAMESPACES
    ) or image_name.endswith((":latest", ":master", ":main", ":v11"))


def resource_path(relative_path):
    """
    Determine the absolute path of a resource file based on its relative path.

    :param relative_path: Relative path of the resource file.
    :return: Absolute path of the resource file
    """
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.dirname(__file__)
    return os.path.join(base_path, relative_path)


def exec_tool(
    args: List[str],
    cwd: Optional[str] = None,
    env: Optional[Dict] = None,
    stdout: int = subprocess.PIPE,
    logger: Optional[Logger] = None,
) -> BOMResult:
    """
    Convenience method to invoke cli tools

    :param args: Command line arguments
    :param cwd: Working directory
    :param env: Environment variables
    :param stdout: Specifies stdout of command
    :param logger: Logger object
    """
    if env is None:
        env = os.environ.copy()
    result = BOMResult(success=True)
    try:
        if logger and stdout != subprocess.DEVNULL:
            logger.debug("Executing '%s'", " ".join(args))
        cp = subprocess.run(
            args,
            stdout=stdout,
            stderr=subprocess.STDOUT,
            cwd=cwd,
            env=env,
            shell=sys.platform == "win32",
            encoding="utf-8",
            check=False,
        )
        result.command_output = cp.stdout
        if logger and stdout != subprocess.DEVNULL:
            logger.debug(cp.stdout)
    except Exception as e:
        result.success = False
        result.command_output = f"Exception while running cdxgen: {e}"
    return result


def find_cdxgen_cmd(use_bin=True, logger: Optional[Logger] = None):
    if use_bin:
        cdxgen_cmd = os.environ.get("CDXGEN_CMD", "cdxgen")
        if not shutil.which(cdxgen_cmd):
            local_bin = resource_path(
                os.path.join(
                    "local_bin",
                    "cdxgen.exe" if sys.platform == "win32" else "cdxgen",
                )
            )
            if not os.path.exists(local_bin):
                if logger:
                    logger.info(
                        "%s command not found. Please install using npm install "
                        "@cyclonedx/cdxgen or set PATH variable",
                        cdxgen_cmd,
                    )
                return False
            cdxgen_cmd = local_bin
            # Set the plugins directory as an environment variable
            os.environ["CDXGEN_PLUGINS_DIR"] = resource_path("local_bin")
            return cdxgen_cmd
        else:
            return cdxgen_cmd
    else:
        lbin = os.getenv("APPDATA") if sys.platform == "win32" else "local_bin"
        local_bin = resource_path(
            os.path.join(
                f"{lbin}\\npm\\" if sys.platform == "win32" else "local_bin",
                "cdxgen" if sys.platform != "win32" else "cdxgen.cmd",
            )
        )
        if not os.path.exists(local_bin):
            if logger:
                logger.info(
                    "%s command not found. Please install using npm install "
                    "@cyclonedx/cdxgen or set PATH variable",
                    local_bin,
                )
            return None
        cdxgen_cmd = local_bin
        # Set the plugins directory as an environment variable
        os.environ["CDXGEN_PLUGINS_DIR"] = (
            resource_path("local_bin")
            if sys.platform != "win32"
            else resource_path(
                os.path.join(
                    lbin,
                    "\\npm\\node_modules\\@cyclonedx\\cdxgen\\node_modules\\@cyclonedx\\cdxgen-plugins-bin\\plugins",
                )
            )
        )
        return cdxgen_cmd


def set_slices_args(project_type_list, args, dir):
    if len(project_type_list) == 1:
        for s in ("deps", "usages", "data-flow", "reachables", "semantics"):
            args.append(f"--{s}-slices-file")
            args.append(os.path.join(dir, f"{project_type_list[0]}-{s}.slices.json"))


class CdxgenGenerator(XBOMGenerator):
    """
    Concrete implementation of XBOMGenerator using cdxgen.
    """

    def generate(self) -> BOMResult:
        """
        Generate the BOM using the cdxgen tool.
        """
        options = self.options
        project_type_list = self.options.get("project_type", [])
        techniques = self.options.get("techniques", []) or []
        lifecycles = self.options.get("lifecycles", []) or []
        env = os.environ.copy()
        # Implement the BOM generation logic using cdxgen.
        cdxgen_cmd = find_cdxgen_cmd(logger=self.logger)
        if not cdxgen_cmd:
            cdxgen_cmd = find_cdxgen_cmd(False, logger=self.logger)
        if not cdxgen_cmd:
            cdxgen_cmd = "cdxgen"
        project_type_args: list[str] = [f"-t {item}" for item in project_type_list]
        technique_args: list[str] = [f"--technique {item}" for item in techniques]
        args: list[str] = [cdxgen_cmd]
        args = args + (" ".join(project_type_args).split())
        args = args + ["-o", self.bom_file]
        if technique_args:
            args = args + (" ".join(technique_args).split())
        if options.get("deep"):
            args.append("--deep")
        if options.get("profile"):
            args.append("--profile")
            args.append(options.get("profile", ""))
            set_slices_args(project_type_list, args, os.path.dirname(self.bom_file))
            if options.get("profile") not in ("generic",):
                # This would help create openapi spec file inside the reports directory
                env["ATOM_TOOLS_WORK_DIR"] = os.path.realpath(
                    os.path.dirname(self.bom_file)
                )
                env["ATOM_TOOLS_OPENAPI_FILENAME"] = (
                    f"{project_type_list[0]}-openapi.json"
                )
        if options.get("cdxgen_args"):
            args += shlex.split(options.get("cdxgen_args", ""))
        if len(lifecycles) == 1:
            args = args + ["--lifecycle", lifecycles[0]]
        # Bug #233 - Source directory could be None when working with url
        if self.source_dir:
            args.append(self.source_dir)
        # Setup cdxgen thought logging
        if self.options.get("explain"):
            env["CDXGEN_THINK_MODE"] = "true"
        # Manage cdxgen temp directory
        cdxgen_temp_dir = None
        if not os.getenv("CDXGEN_TEMP_DIR"):
            cdxgen_temp_dir = tempfile.mkdtemp(
                prefix="cdxgen-temp-", dir=os.getenv("DEPSCAN_TEMP_DIR")
            )
            env["CDXGEN_TEMP_DIR"] = cdxgen_temp_dir
        env["CDXGEN_TIMEOUT_MS"] = CDXGEN_TIMEOUT_MS
        if cdxgen_cmd:
            bom_result = exec_tool(
                args,
                self.source_dir
                if not any(
                    t in project_type_list for t in ("docker", "oci", "container")
                )
                and self.source_dir
                and os.path.isdir(self.source_dir)
                else None,
                env,
                logger=self.logger,
            )
        else:
            bom_result = BOMResult(
                success=False, command_output="Unable to locate cdxgen command."
            )
        if cdxgen_temp_dir:
            shutil.rmtree(cdxgen_temp_dir, ignore_errors=True)
        return bom_result


class CdxgenServerGenerator(CdxgenGenerator):
    """
    cdxgen generator that use a local cdxgen server for execution.
    """

    def generate(self) -> BOMResult:
        """
        Generate the BOM with cdxgen server.
        """
        options = self.options
        cdxgen_server = self.options.get("cdxgen_server")
        if not cdxgen_server:
            return BOMResult(
                success=False,
                command_output="Pass the `--cdxgen-server` argument to use the cdxgen server for BOM generation.",
            )
        project_type_list = self.options.get("project_type", [])
        src_dir = self.source_dir
        if not src_dir and self.options.get("path"):
            src_dir = self.options.get("path")
        with httpx.Client(http2=True, base_url=cdxgen_server, timeout=180) as client:
            sbom_url = f"{cdxgen_server}/sbom"
            if self.logger:
                self.logger.debug("Invoking cdxgen server at %s", sbom_url)
            try:
                r = client.post(
                    sbom_url,
                    json={
                        **options,
                        "url": options.get("url", ""),
                        "path": options.get("path", src_dir),
                        "type": ",".join(project_type_list),
                        "multiProject": options.get("multiProject", ""),
                    },
                    headers=cdxgen_server_headers,
                )
                if r.status_code == httpx.codes.OK:
                    try:
                        json_response = r.json()
                        if json_response:
                            with open(self.bom_file, "w", encoding="utf-8") as fp:
                                json.dump(json_response, fp)
                            return BOMResult(success=os.path.exists(self.bom_file))
                    except Exception as je:
                        return BOMResult(
                            success=False,
                            command_output=f"Unable to generate SBOM via cdxgen server due to {str(je)}",
                        )
                else:
                    return BOMResult(
                        success=False,
                        command_output=f"Unable to generate SBOM via cdxgen server due to {str(r.status_code)}",
                    )
            except Exception as e:
                if self.logger:
                    self.logger.error(e)
        return BOMResult(
            success=False,
            command_output="Unable to generate SBOM with cdxgen server. Trying to generate one locally.",
        )


class CdxgenImageBasedGenerator(CdxgenGenerator):
    """
    cdxgen generator that use container images for execution.
    """

    def __init__(
        self,
        source_dir: str,
        bom_file: str,
        logger: Optional[Logger] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(source_dir, bom_file, logger, options)
        cdxgen_temp_dir = os.getenv("CDXGEN_TEMP_DIR")
        if not cdxgen_temp_dir:
            cdxgen_temp_dir = tempfile.mkdtemp(
                prefix="cdxgen-temp-", dir=os.getenv("DEPSCAN_TEMP_DIR")
            )
            os.environ["CDXGEN_TEMP_DIR"] = cdxgen_temp_dir
        self.cdxgen_temp_dir = cdxgen_temp_dir

    def _container_run_cmd(self) -> Tuple[str, List[str]]:
        """
        Generate a container run command for the given project type, source directory, and output file
        """
        project_type_list = self.options.get("project_type", []) or []
        techniques = self.options.get("techniques") or []
        lifecycles = self.options.get("lifecycles") or []
        image_output_dir = "/reports"
        app_input_dir = "/app"
        container_command = get_env_options_value(self.options, "DOCKER_CMD", "docker")
        image_name = get_image_for_type(self.options, project_type_list)
        run_command_args = [
            container_command,
            "run",
            "--rm",
            "--quiet",
            "--workdir",
            app_input_dir,
        ]
        output_file = os.path.basename(self.bom_file)
        output_dir = os.path.realpath(os.path.dirname(self.bom_file))
        # Setup environment variables
        for k, _ in os.environ.items():
            if (
                k.startswith("CDXGEN_")
                or k.startswith("GIT")
                or k in ("FETCH_LICENSE",)
            ):
                run_command_args += ["-e", k]
        run_command_args += ["-e", f"CDXGEN_TIMEOUT_MS={CDXGEN_TIMEOUT_MS}"]
        # Enabling license fetch will improve metadata such as tags and description
        # These will help with semantic reachability analysis
        if self.options.get("profile") not in ("generic",):
            # This would help create openapi spec file inside the reports directory
            run_command_args += ["-e", f"ATOM_TOOLS_WORK_DIR={image_output_dir}"]
            run_command_args += [
                "-e",
                f"ATOM_TOOLS_OPENAPI_FILENAME={project_type_list[0]}-openapi.json",
            ]
        run_command_args += ["-e", "CDXGEN_IN_CONTAINER=true"]
        # Do not repeat the sponsorship banner. Please note that cdxgen and depscan are separate projects, so they ideally require separate sponsorships.
        run_command_args += ["-e", "CDXGEN_NO_BANNER=true"]
        # Do not repeat the CDXGEN_DEBUG_MODE environment variable
        if os.getenv("SCAN_DEBUG_MODE") == "debug" and not os.getenv(
            "CDXGEN_DEBUG_MODE"
        ):
            run_command_args += ["-e", "CDXGEN_DEBUG_MODE=debug"]
        # Extra args like --platform=linux/amd64
        if os.getenv("DEPSCAN_DOCKER_ARGS"):
            run_command_args += os.getenv("DEPSCAN_DOCKER_ARGS", "").split(" ")
        # Setup volume mounts
        # Mount source directory as /app
        if os.path.isdir(self.source_dir):
            run_command_args += [
                "-v",
                f"{os.path.realpath(self.source_dir)}:{app_input_dir}:rw",
            ]
        else:
            run_command_args.append(self.source_dir)
        run_command_args += ["-v", f"{self.cdxgen_temp_dir}:/tmp:rw"]
        run_command_args += [
            "-v",
            f"{output_dir}:{image_output_dir}:rw",
        ]
        # Mount the home directory as /root. Can be used for performance reasons.
        if self.options.get("insecure_mount_home"):
            run_command_args += ["-v", f"""{os.path.expanduser("~")}:/root:r"""]
        run_command_args.append(image_name)
        # output file mapped to the inside the image
        run_command_args += ["-o", f"{image_output_dir}/{output_file}"]
        # cdxgen args
        technique_args = [f"--technique {item}" for item in techniques]
        if technique_args:
            run_command_args += " ".join(technique_args).split()
        project_type_args = [f"-t {item}" for item in project_type_list]
        if project_type_args:
            run_command_args += " ".join(project_type_args).split()
        if self.options.get("profile"):
            run_command_args.append("--profile")
            run_command_args.append(self.options.get("profile", ""))
            set_slices_args(project_type_list, run_command_args, image_output_dir)
        if len(lifecycles) == 1:
            run_command_args += ["--lifecycle", lifecycles[0]]
        if self.options.get("deep", "") in ("true", "1"):
            run_command_args.append("--deep")
        if self.options.get("cdxgen_args"):
            run_command_args += shlex.split(self.options.get("cdxgen_args", ""))
        return image_name, run_command_args

    def generate(self) -> BOMResult:
        """
        Generate the BOM with official container images.
        """
        container_command = get_env_options_value(self.options, "DOCKER_CMD", "docker")
        if not shutil.which(container_command):
            return BOMResult(
                success=False,
                command_output=f"{container_command} command not found. Pass `--bom-engine CdxgenGenerator` to force depscan to use the local cdxgen CLI.",
            )
        image_name, run_command_args = self._container_run_cmd()
        # Should we pull the most recent image
        if needs_latest_image(image_name):
            if self.logger:
                self.logger.debug(
                    f"Pulling the image {image_name} using {container_command}."
                )
            exec_tool(
                [container_command, "pull", "--quiet", image_name], logger=self.logger
            )
        if self.logger:
            self.logger.debug(f"Executing {' '.join(run_command_args)}")
        bom_result = exec_tool(
            run_command_args, cwd=None, env=os.environ.copy(), logger=self.logger
        )
        if self.cdxgen_temp_dir:
            shutil.rmtree(self.cdxgen_temp_dir, ignore_errors=True)
        return bom_result
