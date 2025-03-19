import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from urllib.parse import unquote_plus

import httpx
from custom_json_diff.lib.utils import json_load, json_dump
from defusedxml.ElementTree import parse

from depscan.lib.logger import LOG
from depscan.lib.utils import cleanup_license_string

BLINT_AVAILABLE = False
try:
    from blint.lib.runners import run_sbom_mode
    from blint.config import BlintOptions, BLINTDB_IMAGE_URL
    from blint.lib.utils import blintdb_setup

    BLINT_AVAILABLE = True
except ImportError:
    pass

headers = {
    "Content-Type": "application/json",
    "Accept-Encoding": "gzip",
}


def exec_tool(args, cwd=None, stdout=subprocess.PIPE):
    """
    Convenience method to invoke cli tools

    :param args: Command line arguments
    :param cwd: Working directory
    :param stdout: Specifies stdout of command
    """
    try:
        LOG.info("⚡︎ Generting BOM with cdxgen")
        LOG.debug('Executing "%s"', " ".join(args))
        cp = subprocess.run(
            args,
            stdout=stdout,
            stderr=subprocess.STDOUT,
            cwd=cwd,
            env=os.environ.copy(),
            shell=sys.platform == "win32",
            encoding="utf-8",
            check=False,
        )
        LOG.debug(cp.stdout)
    except Exception as e:
        LOG.exception(e)


def parse_bom_ref(bomstr, licenses=None):
    """
    Method to parse bom ref string into individual constituents

    :param bomstr: Bom ref string
    :param licenses: Licenses
    :return Dict containing group, name, and version for the package
    """
    if bomstr:
        bomstr = unquote_plus(bomstr)
    tmpl = bomstr.split("/")
    vendor = ""
    name_ver = []
    if len(tmpl) == 2:
        # Just name and version
        vendor = tmpl[0]
        name_ver = tmpl[1].split("@")
    elif len(tmpl) == 3:
        vendor = tmpl[1]
        name_ver = tmpl[-1].split("@")
    elif len(tmpl) > 3:
        vendor = tmpl[-2]
        name_ver = tmpl[-1].split("@")
    vendor = vendor.replace("pkg:", "")
    # If name starts with @ this will make sure the name still gets captured
    if len(name_ver) >= 2:
        name = name_ver[-2]
        version = name_ver[-1]
    else:
        name = name_ver[0]
        version = "*"
    if "?" in version:
        version = version.split("?")[0]
    if version.startswith("v"):
        version = version[1:]
    return {
        "vendor": vendor,
        "name": name,
        "version": version,
        "licenses": licenses,
    }


def get_licenses(ele):
    """
    Retrieve licenses from xml

    :param ele: An XML element
    :return A list of extracted licenses
    """
    license_list = []
    namespace = "{http://cyclonedx.org/schema/bom/1.5}"
    for data in ele.findall(
        f"{namespace}licenses/{namespace}license/{namespace}id"
    ):
        license_list.append(data.text)
    if not license_list:
        for data in ele.findall(
            f"{namespace}licenses/{namespace}license/{namespace}name"
        ):
            if data is not None and data.text:
                ld_list = [data.text]
                if "http" in data.text:
                    ld_list = [
                        os.path.basename(data.text)
                        .replace(".txt", "")
                        .replace(".html", "")
                    ]
                elif "/" in data.text:
                    ld_list = [cleanup_license_string(data.text)]
                for ld in ld_list:
                    license_list.append(ld.strip().upper())
    return license_list


def get_package(component_ele, licenses):
    """
    Retrieve package from xml

    :param component_ele: The XML element representing a component.
    :param licenses: A list of licenses associated with the component.
    :return: A dictionary containing the package information
    """
    bom_ref = component_ele.attrib.get("bom-ref")
    pkg = {
        "licenses": licenses,
        "vendor": "",
        "name": "",
        "version": "",
        "scope": "",
    }
    if bom_ref and "/" in bom_ref:
        pkg = parse_bom_ref(bom_ref, licenses)
    for ele in component_ele.iter():
        if ele.tag.endswith("group") and ele.text:
            pkg["vendor"] = ele.text
        if ele.tag.endswith("name") and ele.text and not pkg["name"]:
            pkg["name"] = ele.text
        if ele.tag.endswith("version") and ele.text:
            version = ele.text
            if version.startswith("v"):
                version = version[1:]
            pkg["version"] = version
        if ele.tag.endswith("purl") and ele.text and not pkg.get("vendor"):
            purl = ele.text
            namespace = purl.split("/")[0].replace("pkg:", "")
            pkg["vendor"] = namespace
    return pkg


def get_pkg_list_json(jsonfile):
    """
    Method to extract packages from a bom json file

    :param jsonfile: Path to a bom json file.
    return List of dicts representing extracted packages
    """
    pkgs = []
    if bom_data := json_load(jsonfile, log=LOG):
        if bom_data.get("components"):
            for comp in bom_data.get("components"):
                licenses, vendor, url = get_license_vendor_url(comp)
                pkgs.append({**comp, "vendor": vendor, "licenses": licenses, "url": url})
        return pkgs


def get_license_vendor_url(comp):
    licenses = []
    vendor = comp.get("group") or ""
    if comp.get("licenses"):
        for lic in comp.get("licenses"):
            license_obj = lic
            # licenses has list of dict with either license
            # or expression as key Only license is supported
            # for now
            if lic.get("license"):
                license_obj = lic.get("license")
            if license_obj.get("id"):
                licenses.append(license_obj.get("id"))
            elif license_obj.get("name"):
                licenses.append(
                    cleanup_license_string(
                        license_obj.get("name")
                    )
                )
    url = ""
    for aref in comp.get("externalReferences", []):
        if aref.get("type") == "vcs":
            url = aref.get("url", "")
            break
    return licenses, vendor, url


def get_pkg_list(xmlfile):
    """Method to parse the bom xml file and convert into packages list

    :param xmlfile: BOM xml file to parse
    :return list of package dict
    """
    if xmlfile.endswith(".json"):
        return get_pkg_list_json(xmlfile)
    pkgs = []
    try:
        et = parse(xmlfile)
        root = et.getroot()
        for child in root:
            if child.tag.endswith("components"):
                for ele in child.iter():
                    if ele.tag.endswith("component"):
                        licenses = get_licenses(ele)
                        pkgs.append(get_package(ele, licenses))
    except Exception as pe:
        LOG.debug("Unable to parse %s %s", xmlfile, pe)
        LOG.warning(
            "Unable to produce Software Bill-of-Materials for this project. "
            "Execute the scan after installing the dependencies!"
        )
    return pkgs


def get_pkg_by_type(pkg_list, pkg_type):
    """Method to filter packages based on package type

    :param pkg_list: List of packages
    :param pkg_type: Package type to filter
    :return List of packages matching pkg_type
    """
    if not pkg_list:
        return []
    return [
        pkg
        for pkg in pkg_list
        if pkg.get("purl", "").startswith("pkg:" + pkg_type)
    ]


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


def find_cdxgen_cmd(use_bin=True):
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
                LOG.warning(
                    "%s command not found. Please install using npm install "
                    "@cyclonedx/cdxgen or set PATH variable",
                    cdxgen_cmd,
                )
                return False
            try:
                cdxgen_cmd = local_bin
                # Set the plugins directory as an environment variable
                os.environ["CDXGEN_PLUGINS_DIR"] = resource_path("local_bin")
                return cdxgen_cmd
            except Exception:
                return None
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
            LOG.warning(
                "%s command not found. Please install using npm install "
                "@cyclonedx/cdxgen or set PATH variable",
                local_bin,
            )
            return None
        try:
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
        except Exception:
            return None


def create_bom(project_type: str | list, bom_file, src_dir=".", deep=False, options=None):
    """
    Method to create BOM file by executing cdxgen command

    :param project_type: Project type
    :param bom_file: BOM file
    :param src_dir: Source directory
    :param deep: A boolean flag indicating whether to perform a deep scan.
    :param options: Additional options for generating the BOM file.
    :returns: True if the command was executed. False if the executable was
    not found.
    """
    if not options:
        options = {}
    # Make project_type a list
    if isinstance(project_type, str):
        project_type = [project_type]
    # For binaries, generate an sbom with blint directly
    techniques = options.get("techniques") or []
    lifecycles = options.get("lifecycles") or []
    if (project_type[0] in ("binary", "apk") or (techniques and "binary-analysis" in techniques)
            or (lifecycles and "post-build" in lifecycles)):
        return create_blint_bom(bom_file, src_dir, options=options)
    cdxgen_server = options.get("cdxgen_server")
    # Generate SBOM by calling cdxgen server
    if cdxgen_server:
        # Fallback to universal if no project type was provided
        if not project_type:
            project_type = ["universal"]
        if not src_dir and options.get("path"):
            src_dir = options.get("path")
        with httpx.Client(
            http2=True, base_url=cdxgen_server, timeout=180
        ) as client:
            sbom_url = f"{cdxgen_server}/sbom"
            LOG.debug("Invoking cdxgen server at %s", sbom_url)
            try:
                r = client.post(
                    sbom_url,
                    json={
                        "url": options.get("url", ""),
                        "path": options.get("path", src_dir),
                        "type": options.get("type", ",".join(project_type)),
                        "multiProject": options.get("multiProject", ""),
                    },
                    headers=headers,
                )
                if r.status_code == httpx.codes.OK:
                    try:
                        json_response = r.json()
                        if json_response:
                            json_dump(bom_file, json_response, log=LOG)
                            return os.path.exists(bom_file)
                    except Exception as je:
                        LOG.error(je)
                        LOG.info(
                            "Unable to generate SBOM with cdxgen server. "
                            "Trying to generate one locally."
                        )
                else:
                    LOG.warning(
                        "Unable to generate SBOM via cdxgen server due to %s",
                        r.status_code,
                    )
            except Exception as e:
                LOG.error(e)
                LOG.info(
                    "Unable to generate SBOM with cdxgen server. Trying to "
                    "generate one locally."
                )
    cdxgen_cmd = find_cdxgen_cmd()
    if not cdxgen_cmd:
        cdxgen_cmd = find_cdxgen_cmd(False)
    if any(t in project_type for t in ("docker", "oci", "container")):
        LOG.info(
            "Generating Software Bill-of-Materials for the container image %s. "
            "This might take a few mins ...",
            src_dir,
        )
    project_type_args = [f"-t {item}" for item in project_type]
    technique_args = [f"--technique {item}" for item in techniques]
    args = [cdxgen_cmd, "-r"]
    args = args + project_type_args
    args = args + ["-o", bom_file]
    if technique_args:
        args = args + technique_args
    if deep:
        args.append("--deep")
        LOG.info("About to perform deep scan. This could take a while ...")
    if options.get("profile"):
        args.append("--profile")
        args.append(options.get("profile"))
        if options.get("profile") != "generic":
            LOG.debug("BOM Profile: %s", options.get("profile"))
    if options.get("cdxgen_args"):
        args += shlex.split(options.get("cdxgen_args"))
    # Bug #233 - Source directory could be None when working with url
    if src_dir:
        args.append(src_dir)
    if cdxgen_cmd:
        exec_tool(
            args,
            src_dir
            if any(t in project_type for t in ("docker", "oci", "container"))
               and src_dir
               and os.path.isdir(src_dir)
            else None,
        )
    else:
        LOG.warning("Unable to locate cdxgen command.")
    return os.path.exists(bom_file)


def create_blint_bom(bom_file, src_dir=".", options=None):
    """
    Method to create BOM file by using blint

    :param bom_file: BOM file
    :param src_dir: Source directory
    :param options: Additional options for generating the BOM file.
    :returns: True if the bom was generated successfully. False otherwise.
    """
    if options is None:
        options = {}
    if not BLINT_AVAILABLE:
        LOG.warning(
            "The required packages for binary SBOM generation are not available. Reinstall depscan using `pip install owasp-depscan[all]`.")
        return False
    temp_reports_dir = tempfile.mkdtemp(prefix="blint-reports-")
    blint_options = BlintOptions(deep_mode=True, sbom_mode=True, db_mode=True,
                                 no_reviews=True, no_error=True, quiet_mode=True,
                                 src_dir_image=src_dir.split(","), stdout_mode=False, reports_dir=temp_reports_dir,
                                 use_blintdb=True, image_url=options.get("blintdb_image_url", BLINTDB_IMAGE_URL),
                                 sbom_output=bom_file)
    LOG.debug("Getting ready to prepare blintdb")
    blintdb_setup(blint_options)
    LOG.info(f"About to scan the directory {src_dir} with blint. This might take a while ...")
    sbom = run_sbom_mode(blint_options)
    if sbom and len(sbom.components):
        LOG.debug(
            f"SBOM from blint includes {len(sbom.components)} components and {len(sbom.dependencies)} dependencies.")
    else:
        LOG.debug("Received an empty BOM from blint.")
    shutil.rmtree(temp_reports_dir, ignore_errors=True)
    return os.path.exists(bom_file)
