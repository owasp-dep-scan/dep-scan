import os
import shutil
import sys
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from urllib.parse import unquote_plus

from custom_json_diff.lib.utils import json_load, json_dump
from defusedxml.ElementTree import parse
from xbom_lib.blint import BlintGenerator
from xbom_lib.cdxgen import (
    CdxgenGenerator,
    CdxgenImageBasedGenerator,
    CdxgenServerGenerator,
)
from depscan.lib.logger import LOG, SPINNER, console
from depscan.lib.utils import cleanup_license_string
from typing import Dict, Optional


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
    for data in ele.findall(f"{namespace}licenses/{namespace}license/{namespace}id"):
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
            for comp in bom_data.get("components", []):
                licenses, vendor, url = get_license_vendor_url(comp)
                pkgs.append(
                    {**comp, "vendor": vendor, "licenses": licenses, "url": url}
                )
        return pkgs


def get_license_vendor_url(comp):
    licenses = []
    vendor = comp.get("group") or ""
    if comp.get("licenses"):
        for lic in comp.get("licenses"):
            license_obj = lic
            if lic.get("license"):
                license_obj = lic.get("license")
            if license_obj.get("id"):
                licenses.append(license_obj.get("id"))
            elif license_obj.get("name"):
                licenses.append(cleanup_license_string(license_obj.get("name")))
    url = ""
    for aref in comp.get("externalReferences", []):
        if aref.get("type") in (
            "vcs",
            "issue-tracker",
            "website",
            "bom",
            "source-distribution",
            "distribution",
            "distribution-intake",
            "build-system",
            "model-card",
            "evidence",
            "formulation",
        ):
            url = aref.get("url", "")
            break
    return licenses, vendor, url


# Unused
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
        pkg for pkg in pkg_list if pkg.get("purl", "").startswith("pkg:" + pkg_type)
    ]


def create_bom(bom_file, src_dir=".", options=None):
    """
    Method to create BOM file by executing cdxgen command

    :param bom_file: BOM file
    :param src_dir: Source directory
    :param options: Additional options for generating the BOM file.
    :returns: True if the command was executed. False if the executable was
    not found.
    """
    if not options:
        options = {}
    # Get the various options and filenames
    techniques = options.get("techniques") or []
    lifecycles = options.get("lifecycles") or []
    project_type_list = options.get("project_type") or []
    bom_engine = options.get("bom_engine", "")
    lifecycle_analysis_mode = options.get("lifecycle_analysis_mode", False)
    # Detect if blint needs to be used for the given project type, technique, and lifecycle.
    # For binaries, generate an sbom with blint directly
    if (
        bom_engine == "BlintGenerator"
        or "binary-analysis" in techniques
        or "post-build" in lifecycles
        or any([t in ("binary", "apk") for t in project_type_list])
    ):
        return create_blint_bom(bom_file, src_dir, options=options)
    cdxgen_server = options.get("cdxgen_server")
    cdxgen_lib = CdxgenGenerator

    # Should we call cdxgen server
    if cdxgen_server or bom_engine == "CdxgenServerGenerator":
        if not cdxgen_server:
            LOG.error(
                "Pass the `--cdxgen-server` argument to use the cdxgen server for BOM generation. Alternatively, use `--bom-engine auto` or `--bom-engine CdxgenGenerator`."
            )
            return False
        cdxgen_lib = CdxgenServerGenerator
    else:
        # Prefer the new image based generators if docker command is available in auto mode
        if bom_engine == "CdxgenImageBasedGenerator":
            cdxgen_lib = CdxgenImageBasedGenerator
        elif bom_engine == "auto":
            # Prefer local CLI while scanning container images
            if any(
                [
                    t in ("docker", "podman", "oci", "os", "hardware")
                    for t in project_type_list
                ]
            ):
                cdxgen_lib = CdxgenGenerator
                if lifecycle_analysis_mode:
                    LOG.warning(
                        "Lifecycle analysis is not supported for oci and os project types."
                    )
                    lifecycle_analysis_mode = True
            elif (
                shutil.which(os.getenv("DOCKER_CMD", "docker"))
                and sys.platform != "win32"
            ):
                cdxgen_lib = CdxgenImageBasedGenerator
    # We now have the cdxgen library to use.
    # For lifecycle analysis, we need to generate multiple BOM files
    if lifecycle_analysis_mode:
        return create_lifecycle_boms(cdxgen_lib, src_dir, options)
    # Invoke the cdxgen library directly
    with console.status(
        f"Generating BOM for the source '{src_dir}' with cdxgen.", spinner=SPINNER
    ):
        bom_result = cdxgen_lib(
            src_dir, bom_file, logger=LOG, options=options
        ).generate()
        if not bom_result.success:
            LOG.info(
                "The cdxgen invocation was unsuccessful. Try generating the BOM separately."
            )
            LOG.debug(bom_result.command_output)
        return bom_result.success and os.path.exists(bom_file)


def create_blint_bom(
    bom_file: str, src_dir: str = ".", options: Optional[Dict] = None
) -> bool:
    """
    Method to create BOM file by using blint

    :param bom_file: BOM file
    :param src_dir: Source directory
    :param options: Additional options for generating the BOM file.
    :returns: True if the bom was generated successfully. False otherwise.
    """
    if options is None:
        options = {}
    reachability_analyzer = options.get("reachability_analyzer")
    # The side effect is that we will almost always run blint in deep mode
    if reachability_analyzer != "off" and not options.get("deep"):
        options["deep"] = True
    blint_lib = BlintGenerator(src_dir, bom_file, logger=LOG, options=options)
    with console.status(
        f"Generating BOM for the source '{src_dir}' with blint.", spinner=SPINNER
    ):
        bom_result = blint_lib.generate()
        if not bom_result.success:
            LOG.info(
                "The blint invocation was unsuccessful. Try generating the BOM separately."
            )
        return bom_result.success and os.path.exists(bom_file)


def create_lifecycle_boms(cdxgen_lib, src_dir, options):
    """
    Method to create multiple BOM files for each lifecycle

    :param cdxgen_lib: cdxgen library to use
    :param src_dir: Source directory
    :param options: Additional options for generating the BOM files
    """
    lifecycles = options.get("lifecycles", []) or []
    if lifecycles:
        LOG.warning(
            "Ignoring the `lifecycles` argument, as it is not required for lifecycle analysis."
        )
    any_success = False
    prebuild_bom_file = options.get("prebuild_bom_file")
    build_bom_file = options.get("build_bom_file")
    postbuild_bom_file = options.get("postbuild_bom_file")
    container_bom_file = options.get("container_bom_file")
    reachability_analyzer = options.get("reachability_analyzer")
    with console.status(
        f"Generating lifecycle-specific BOMs for {src_dir}.", spinner=SPINNER
    ) as status:
        # Start with build BOM generation.
        # This would help atom compute reachable slices from a build perspective without getting confused
        # about the pre-build state.
        status.update(f"Generating build BOM for '{src_dir}' with cdxgen.")
        coptions = {**options, "deep": "true", "lifecycles": ["build"]}
        # We must also run it under research profile to help the reachability analyzer
        # This logic could get refactored in the future
        if reachability_analyzer != "off" and options.get("profile") != "research":
            coptions["profile"] = "research"
        bom_result = cdxgen_lib(
            src_dir, build_bom_file, logger=LOG, options=coptions
        ).generate()
        if not bom_result.success or not os.path.exists(build_bom_file):
            LOG.debug(
                "The cdxgen invocation was unsuccessful. Trying pre-build lifecycle."
            )
            LOG.debug(bom_result.command_output)
        else:
            any_success = True
        # pre-build
        status.update(f"Now generating pre-build BOM for '{src_dir}' with cdxgen.")
        coptions = {**options, "deep": "false", "lifecycles": ["pre-build"]}
        bom_result = cdxgen_lib(
            src_dir, prebuild_bom_file, logger=LOG, options=coptions
        ).generate()
        if not bom_result.success or not os.path.exists(prebuild_bom_file):
            LOG.debug(
                "The cdxgen invocation was unsuccessful. Trying the build lifecycle."
            )
            LOG.debug(bom_result.command_output)
        else:
            any_success = True
        # container bom. For this we need the image name.
        container_image_name = os.getenv("DEPSCAN_SOURCE_IMAGE") or options.get(
            "source_image"
        )
        if container_image_name:
            status.update(f"Generating container BOM for '{src_dir}' with cdxgen.")
            coptions = {**options, "deep": "true", "project_type": ["oci"]}
            if container_image_name == src_dir:
                LOG.info(
                    "Set the environment variable DEPSCAN_SOURCE_IMAGE to the name of the container image to include its components."
                )
            bom_result = cdxgen_lib(
                container_image_name, container_bom_file, logger=LOG, options=coptions
            ).generate()
            if not bom_result.success or not os.path.exists(container_bom_file):
                LOG.debug(
                    "The cdxgen invocation was unsuccessful. Trying for the next lifecycle."
                )
                LOG.debug(bom_result.command_output)
            else:
                any_success = True
        else:
            LOG.debug(
                "Set the environment variable DEPSCAN_SOURCE_IMAGE to the name of the container image to include its components."
            )
        status.update("Preparing blint for post-build BOM generation.")
    # post-build BOM with blint
    coptions = {
        **options,
        "deep": False,
        "use_blintdb": False,
        "lifecycles": ["post-build"],
    }
    # What if the build directory is different to the source
    build_dir = os.getenv("DEPSCAN_BUILD_DIR") or options.get("build_dir") or src_dir
    res = create_blint_bom(postbuild_bom_file, build_dir, options=coptions)
    if not res or not os.path.exists(postbuild_bom_file):
        LOG.debug(
            "The blint invocation was unsuccessful. Try building this project prior to invoking depscan. Alternatively, check if this project generates binary artefacts."
        )
    else:
        any_success = True
    return any_success


def create_empty_vdr(pkg_list, ds_version):
    components = pkg_list or []
    bom_data = update_tools_metadata(None, None, ds_version)
    return {**bom_data, "components": components}


def update_tools_metadata(tools, bom_data, ds_version):
    """
    Helper function to add depscan information as metadata
    :param tools: Tools section of the SBOM
    :param bom_data: SBOM data
    :param ds_version: depscan version
    :return: None
    """
    if not bom_data:
        now_utc = datetime.now(timezone.utc)
        bom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": now_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
        }
    components = tools.get("components", []) if tools else []
    needs_ds_component = (
        len([c for c in components if c.get("name") == "owasp-depscan"]) == 0
    )
    if needs_ds_component:
        ds_purl = f"pkg:pypi/owasp-depscan@{ds_version}"
        components.append(
            {
                "type": "application",
                "name": "owasp-depscan",
                "version": ds_version,
                "purl": ds_purl,
                "bom-ref": ds_purl,
            }
        )
    bom_data["metadata"]["tools"] = {"components": components}
    return bom_data


def export_bom(bom_data, ds_version, pkg_vulnerabilities, vdr_file):
    """
    Exports the Bill of Materials (BOM) data along with package vulnerabilities
    to a Vulnerability Data Report (VDR) file.

    :param bom_data: SBOM data
    :param ds_version: depscan version
    :param pkg_vulnerabilities: Package vulnerabilities
    :param vdr_file: VDR file path
    """
    # Add depscan information as metadata
    metadata = bom_data.get("metadata", {})
    tools = metadata.get("tools", {})
    bom_version = str(bom_data.get("version", 0))
    # Update the version
    if bom_version.isdigit():
        bom_data["version"] = int(bom_version) + 1
    # Update the tools section
    if isinstance(tools, dict):
        bom_data = update_tools_metadata(tools, bom_data, ds_version)
    bom_data = trim_vdr_bom_data(bom_data)
    bom_data["vulnerabilities"] = pkg_vulnerabilities
    json_dump(
        vdr_file,
        bom_data,
        compact=True,
        error_msg=f"Unable to generate VDR file at {vdr_file}",
    )


def trim_vdr_bom_data(bom_data):
    components = bom_data.get("components")
    if not components:
        return bom_data
    metadata = bom_data.get("metadata")
    if metadata and metadata.get("properties"):
        del metadata["properties"]
        bom_data["metadata"] = metadata
    new_components = {}
    component_identities = defaultdict(list)
    for comp in components:
        identity_evidences = comp.get("evidence", {}).get("identity", []) or []
        if isinstance(identity_evidences, dict):
            identity_evidences = [identity_evidences]
        for p in (
            "properties",
            "signature",
            "url",
            "vendor",
            "licenses",  # We need a better logic to retain licenses here
        ):
            if comp.get(p) is not None:
                del comp[p]
        ref = comp.get("bom-ref") or comp.get("purl")
        # This is an error condition really
        if not ref:
            continue
        component_identities[ref] += identity_evidences
        if not new_components.get(ref):
            new_components[ref] = comp
    vdr_components = []
    for ref, comp in new_components.items():
        identity_evidences = component_identities[ref]
        comp["evidence"] = {"identity": identity_evidences}
        vdr_components.append(comp)
    bom_data["components"] = vdr_components
    for p in (
        "annotations",
        "signature",
    ):
        if bom_data.get(p):
            del bom_data[p]
    return bom_data


def annotate_vdr(vdr_file, txt_report_file):
    if (
        not vdr_file
        or not txt_report_file
        or not os.path.exists(vdr_file)
        or not os.path.exists(txt_report_file)
    ):
        return
    vdr = json_load(vdr_file)
    metadata = vdr.get("metadata", {})
    # Some cyclonedx sbom don't containg tools.components
    if "components" in metadata.get("tools"):
        tools = metadata.get("tools", {}).get("components", {})
    else:
        tools = {}
    with open(txt_report_file, errors="ignore", encoding="utf-8") as txt_fp:
        report = txt_fp.read()
        annotations = vdr.get("annotations", []) or []
        depscan_annotation = {
            "subjects": [vdr.get("serialNumber")],
            "annotator": {"component": tools[-1] if len(tools) > 0 else {}},
            "timestamp": metadata.get("timestamp"),
            "text": report,
        }
        annotations.append(depscan_annotation)
    vdr["annotations"] = annotations
    json_dump(
        vdr_file,
        vdr,
        compact=True,
        error_msg=f"Unable to add annotations to the VDR file at {vdr_file}",
    )
