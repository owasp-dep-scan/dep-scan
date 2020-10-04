import json
import logging
import os
import shutil
import subprocess
import xml
from urllib.parse import unquote_plus

from defusedxml.ElementTree import parse

from depscan.lib.utils import cleanup_license_string

logging.basicConfig(
    level=logging.INFO, format="%(levelname)s [%(asctime)s] %(message)s"
)
LOG = logging.getLogger(__name__)


def exec_tool(args, cwd=None, stdout=subprocess.PIPE):
    """
    Convenience method to invoke cli tools

    Args:
      args cli command and args
    """
    try:
        LOG.debug('⚡︎ Executing "{}"'.format(" ".join(args)))
        subprocess.run(
            args,
            stdout=stdout,
            stderr=subprocess.STDOUT,
            cwd=cwd,
            env=os.environ,
            check=False,
            shell=False,
            encoding="utf-8",
        )
    except Exception as e:
        LOG.exception(e)


def parse_bom_ref(bomstr, licenses=None):
    """Method to parse bom ref string into individual constituents

    :param bomstr: Bom ref string
    :param licenses: Licenses
    :return dict containing group, name and version for the package
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
    """"""
    license_list = []
    namespace = "{http://cyclonedx.org/schema/bom/1.2}"
    for data in ele.findall("{0}licenses/{0}license/{0}id".format(namespace)):
        license_list.append(data.text)
    if not license_list:
        for data in ele.findall("{0}licenses/{0}license/{0}name".format(namespace)):
            if data and data.text:
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


def get_package(componentEle, licenses):
    """"""
    bom_ref = componentEle.attrib.get("bom-ref")
    pkg = {"licenses": licenses, "vendor": "", "name": "", "version": "", "scope": ""}
    if bom_ref:
        pkg = parse_bom_ref(bom_ref, licenses)
    for ele in componentEle.iter():
        if ele.tag.endswith("group") and ele.text:
            pkg["vendor"] = ele.text
        elif ele.tag.endswith("name") and ele.text and not pkg["name"]:
            pkg["name"] = ele.text
        if ele.tag.endswith("version") and ele.text:
            version = ele.text
            if version.startswith("v"):
                version = version[1:]
            pkg["version"] = version
    return pkg


def get_pkg_list_json(jsonfile):
    """Method to extract packages from a bom json file"""
    pkgs = []
    with open(jsonfile) as fp:
        bom_data = json.load(fp)
        if bom_data and bom_data.get("components"):
            for comp in bom_data.get("components"):
                licenses = []
                vendor = comp.get("group")
                if not vendor:
                    vendor = ""
                if comp.get("licenses"):
                    for lic in comp.get("licenses"):
                        license_obj = lic
                        # licenses has list of dict with either license or expression as key
                        # Only license is supported for now
                        if lic.get("license"):
                            license_obj = lic.get("license")
                        if license_obj.get("id"):
                            licenses.append(license_obj.get("id"))
                        elif license_obj.get("name"):
                            licenses.append(
                                cleanup_license_string(license_obj.get("name"))
                            )
                pkgs.append({**comp, "vendor": vendor, "licenses": licenses})
        return pkgs


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
    except xml.etree.ElementTree.ParseError as pe:
        LOG.debug("Unable to parse {} {}".format(xmlfile, pe))
        LOG.warning(
            "Unable to produce Software Bill-of-Materials for this project. Execute the scan after installing the dependencies!"
        )
    return pkgs


def create_bom(project_type, bom_file, src_dir="."):
    """Method to create BOM file by executing cdxgen command

    :param project_type: Project type
    :param bom_file: BOM file
    :param src_dir: Source directory

    :returns True if the command was executed. False if the executable was not found.
    """
    cdxgen_cmd = os.environ.get("CDXGEN_CMD", "cdxgen")
    if not shutil.which(cdxgen_cmd):
        LOG.warning(
            "{} command not found. Please install using npm install @appthreat/cdxgen or set PATH variable".format(
                cdxgen_cmd
            )
        )
        return False
    args = [cdxgen_cmd, "-r", "-t", project_type, "-o", bom_file, src_dir]
    exec_tool(args)
    return os.path.exists(bom_file)
