import os
import shutil
from urllib.parse import unquote_plus

from blint.cyclonedx.spec import CycloneDX
from custom_json_diff.lib.utils import json_load, json_dump
from defusedxml.ElementTree import parse

from depscan.lib.logger import console, LOG, SPINNER
from depscan.lib.utils import cleanup_license_string
from xbom_lib.blint import BlintGenerator
from xbom_lib.cdxgen import CdxgenGenerator, CdxgenImageBasedGenerator, CdxgenServerGenerator

headers = {"Content-Type": "application/json", "Accept-Encoding": "gzip", }


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
    return {"vendor": vendor, "name": name, "version": version, "licenses": licenses, }


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
        for data in ele.findall(f"{namespace}licenses/{namespace}license/{namespace}name"):
            if data is not None and data.text:
                ld_list = [data.text]
                if "http" in data.text:
                    ld_list = [os.path.basename(data.text).replace(".txt", "").replace(".html", "")]
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
    pkg = {"licenses": licenses, "vendor": "", "name": "", "version": "", "scope": "", }
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
                licenses.append(cleanup_license_string(license_obj.get("name")))
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
        LOG.warning("Unable to produce Software Bill-of-Materials for this project. "
                    "Execute the scan after installing the dependencies!")
    return pkgs


def get_pkg_by_type(pkg_list, pkg_type):
    """Method to filter packages based on package type

    :param pkg_list: List of packages
    :param pkg_type: Package type to filter
    :return List of packages matching pkg_type
    """
    if not pkg_list:
        return []
    return [pkg for pkg in pkg_list if pkg.get("purl", "").startswith("pkg:" + pkg_type)]


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
    # For binaries, generate an sbom with blint directly
    techniques = options.get("techniques") or []
    lifecycles = options.get("lifecycles") or []
    project_type = options.get("project_type") or []
    bom_engine = options.get("bom_engine", "")
    # Detect if blint needs to be used for the given project type, technique, and lifecycle.
    if bom_engine == "BlintGenerator" or "binary-analysis" in techniques or "post-build" in lifecycles:
        return create_blint_bom(bom_file, src_dir, options=options)
    cdxgen_server = options.get("cdxgen_server")
    cdxgen_lib = CdxgenGenerator
    # Generate SBOM by calling cdxgen server
    if cdxgen_server or bom_engine == "CdxgenServerGenerator":
        if not cdxgen_server:
            LOG.error(
                "Pass the `--cdxgen-server` argument to use the cdxgen server for BOM generation. Alternatively, use `--bom-engine auto` or `--bom-engine CdxgenGenerator`.")
            return False
        cdxgen_lib = CdxgenServerGenerator
    else:
        # Prefer the new image based generators if docker command is available in auto mode
        if bom_engine == "CdxgenImageBasedGenerator":
            cdxgen_lib = CdxgenImageBasedGenerator
        elif bom_engine == "auto":
            # Prefer local CLI while scanning container images
            if any([t in ("docker", "podman", "oci") for t in project_type]):
                cdxgen_lib = CdxgenGenerator
            elif shutil.which(os.getenv("DOCKER_CMD", "docker")):
                cdxgen_lib = CdxgenImageBasedGenerator
    with console.status(f"Generating BOM for the source {src_dir} with cdxgen.", spinner=SPINNER):
        bom_result = cdxgen_lib(src_dir, bom_file, logger=LOG, options=options).generate()
        if not bom_result.success:
            LOG.info("The cdxgen invocation was unsuccessful. Try generating the BOM separately.")
            LOG.debug(bom_result.command_output)
        return bom_result.success and os.path.exists(bom_file)


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
    blint_lib = BlintGenerator(src_dir, bom_file, logger=LOG, options=options)
    with console.status(f"Generating BOM for the source {src_dir} with blint.", spinner=SPINNER):
        bom_result = blint_lib.generate()
        if not bom_result.success:
            LOG.info("The blint invocation was unsuccessful. Try generating the BOM separately.")
        elif bom_result.bom_obj and isinstance(bom_result.bom_obj, CycloneDX):
            if not bom_result.bom_obj.components and not bom_result.bom_obj.dependencies:
                LOG.info("Empty SBOM received from blint.")
            else:
                LOG.debug(
                    f"BOM from blint includes {len(bom_result.bom_obj.components)} components and {len(bom_result.bom_obj.dependencies)} dependencies.")
        return bom_result.success and os.path.exists(bom_file)
