from defusedxml.ElementTree import parse

import logging
import os
import shutil
import subprocess
import xml

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
        LOG.info('⚡︎ Executing "{}"'.format(" ".join(args)))
        subprocess.run(
            args,
            stdout=stdout,
            stderr=subprocess.STDOUT,
            cwd=cwd,
            check=False,
            shell=False,
            encoding="utf-8",
        )
    except Exception as e:
        LOG.exception(e)


def parse_bom_ref(bomstr):
    """Method to parse bom ref string into individual constituents

    :param bomstr: Bom ref string

    :return dict containing group, name and version for the package
    """
    tmpl = bomstr.split("/")
    group = ""
    version = "*"
    name_ver = ""
    if len(tmpl) == 2:
        # Just name and version
        if "@" in tmpl[1]:
            name_ver = tmpl[1].split("@")
    elif len(tmpl) == 3:
        group = tmpl[1]
        if "@" in tmpl[2]:
            name_ver = tmpl[2].split("@")
    name = name_ver[0]
    version = name_ver[1]
    if "?" in version:
        version = version.split("?")[0]
    return {"group": group, "name": name, "version": version}


def get_pkg_list(xmlfile):
    """Method to parse the bom xml file and convert into packages list

    :param xmlfile: BOM xml file to parse
    :return list of package dict
    """
    pkgs = []
    try:
        et = parse(xmlfile)
        root = et.getroot()
        for child in root:
            if child.tag.endswith("components"):
                for ele in child.iter():
                    if ele.tag.endswith("component"):
                        bom_ref = ele.attrib.get("bom-ref")
                        if bom_ref:
                            pkgs.append(parse_bom_ref(bom_ref))
    except xml.etree.ElementTree.ParseError as pe:
        LOG.warning("Unable to parse {} {}".format(xmlfile, pe))
    return pkgs


def create_bom(bom_file, src_dir="."):
    """Method to create BOM file by executing cdxgen command

    :param src_dir: Source directory
    :param True if the command was executed. False if the executable was not found.
    """
    cdxgen_cmd = os.environ.get("CDXGEN_CMD", "cdxgen")
    if not shutil.which(cdxgen_cmd):
        LOG.warning(
            "{} command not found. Please install using npm install @appthreat/cdxgen or set PATH variable".format(
                cdxgen_cmd
            )
        )
        return False
    with open(bom_file, mode="w") as fp:
        args = [cdxgen_cmd, "-o", fp.name, src_dir]
        exec_tool(args)
        return True
