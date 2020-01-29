from defusedxml.ElementTree import parse


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
    et = parse(xmlfile)
    root = et.getroot()
    for child in root:
        if child.tag.endswith("components"):
            for ele in child.iter():
                if ele.tag.endswith("component"):
                    bom_ref = ele.attrib.get("bom-ref")
                    if bom_ref:
                        pkgs.append(parse_bom_ref(bom_ref))
    return pkgs
