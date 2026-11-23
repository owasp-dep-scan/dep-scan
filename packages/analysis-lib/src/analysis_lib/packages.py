"""Read packages, dependency trees and lifecycle maps from CycloneDX BOMs.

bom_components is the component filter of one parsed BOM document the
loader keeps; get_pkg_list and get_all_pkg_list extract the package list of
one BOM file or a directory of BOMs through it; the lifecycle helpers split
purls into pre-build, build and post-build maps and track executable
properties; the retrieve_* helpers return the BOM's dependency tree and OCI
properties.

This module only reads finished BOM JSON. It does not generate BOMs (cdxgen
owns that), match vulnerabilities, or inspect reachability slices.
"""

import os
from collections import defaultdict

from analysis_lib import get_all_bom_files
from custom_json_diff.lib.utils import json_load


def retrieve_bom_dependency_tree(bom_file, bom_dir):
    """
    Method to retrieve the dependency tree from CycloneDX SBOM files

    :param bom_file: BOM file
    :param bom_dir: BOM directory
    :return: Dependency tree as a list
    """
    if not bom_file and not bom_dir:
        return []
    dependencies = []
    if bom_dir:
        bom_files = get_all_bom_files(bom_dir)
    else:
        bom_files = [bom_file]
    for file_path in bom_files:
        if bom_data := json_load(file_path):
            dependencies += bom_data.get("dependencies", [])
    return dependencies


def retrieve_oci_properties(bom_file, bom_dir):
    """
    Retrieves OCI properties from from CycloneDX SBOM files

    :param bom_file: BOM file
    :param bom_dir: BOM directory

    :return: A dictionary containing the retrieved OCI properties.
    :rtype: dict
    """
    props = {}
    if not bom_file and not bom_dir:
        return props
    if bom_dir:
        bom_files = get_all_bom_files(bom_dir)
    else:
        bom_files = [bom_file]
    for file_path in bom_files:
        if bom_data := json_load(file_path):
            for p in bom_data.get("metadata", {}).get("properties", []):
                if p.get("name", "").startswith("oci:image:"):
                    props[p.get("name")] = p.get("value")
    return props


def bom_components(bom_data):
    """
    The components of one parsed BOM document the package loader keeps.

    This walk is the loader's filter alone: every top-level component that
    is not ``data``, each component nested below one that is neither
    ``application`` nor ``data``, and each such component below the root
    ``metadata.component``. ``get_pkg_list`` enriches exactly these with
    the vendor, license and URL fields; a caller that needs the components
    a document contributes without loading a file gets the same set here. A
    document that is not a JSON object, or whose component lists are null,
    of the wrong type or hold non-objects, keeps nothing.

    :param bom_data: A parsed BOM document.
    :return: A generator of the kept component dicts, metadata components
        first.
    """
    if not isinstance(bom_data, dict):
        return
    metadata = bom_data.get("metadata")
    if isinstance(metadata, dict):
        root = metadata.get("component")
        for mcomp in _component_children(root):
            yield mcomp
    components = bom_data.get("components")
    for comp in components if isinstance(components, list) else []:
        if not isinstance(comp, dict) or comp.get("type", "") in ("data",):
            continue
        yield comp
        for nc in _component_children(comp):
            yield nc


def _component_children(component):
    """The components nested below ``component`` that the loader keeps:
    each child that is neither an ``application`` nor a ``data``
    component. A parent that is not an object keeps none."""
    if not isinstance(component, dict):
        return
    children = component.get("components")
    for child in children if isinstance(children, list) else []:
        if isinstance(child, dict) and child.get("type", "") not in ("application", "data"):
            yield child


def get_pkg_list(jsonfile):
    """
    Method to extract packages from a bom json file

    :param jsonfile: Path to a bom json file.
    return List of dicts representing extracted packages
    """
    pkgs = []
    lifecycles = []
    if bom_data := json_load(jsonfile):
        # Collect the lifecycles listed in the BOM
        if isinstance(bom_data.get("metadata"), dict):
            lifecycles = bom_data["metadata"].get("lifecycles") or []
        for comp in bom_components(bom_data):
            licenses, vendor, url = get_vendor_url(comp)
            pkgs.append({**comp, "vendor": vendor, "licenses": licenses, "url": url})
    return pkgs, lifecycles


def get_all_pkg_list(from_dir):
    """
    Method to extract packages from a bom json file

    :param from_dir: Path to a directory containing bom json files.
    return List of dicts representing extracted packages
    """
    bom_files = get_all_bom_files(from_dir)
    unique_packages = []
    seen_bom_refs = set()
    # Retain the identity evidences to identify the file to patch
    component_identities = defaultdict(list)
    for file_path in bom_files:
        pkg_list, lifecycles = get_pkg_list(file_path)
        lifecycle_mode = get_lifecycle(lifecycles)
        for pkg in pkg_list:
            identity_evidences = pkg.get("evidence", {}).get("identity", []) or []
            if isinstance(identity_evidences, dict):
                identity_evidences = [identity_evidences]
            purl = pkg.get("purl")
            # Ignore unversioned components in post-build
            if lifecycle_mode == "post-build" and purl and "@" not in purl:
                continue
            bom_ref = pkg.get("bom-ref") or purl
            if not bom_ref:
                continue
            component_identities[bom_ref] += identity_evidences
            if bom_ref not in seen_bom_refs:
                unique_packages.append(pkg)
                seen_bom_refs.add(bom_ref)
    for comp in unique_packages:
        ref = comp.get("bom-ref") or comp.get("purl")
        identity_evidences = component_identities[ref]
        comp["evidence"] = {"identity": identity_evidences}
    return unique_packages


def get_vendor_url(comp):
    licenses = []
    vendor = comp.get("group") or ""
    if comp.get("licenses"):
        for lic in comp.get("licenses"):
            license_obj = lic
            if isinstance(lic, str):
                continue
            if lic.get("license"):
                license_obj = lic.get("license")
            if license_obj.get("id"):
                licenses.append(license_obj.get("id"))
    url = ""
    for aref in comp.get("externalReferences", []):
        if aref.get("type") == "vcs":
            url = aref.get("url", "")
            break
    return licenses, vendor, url


def get_lifecycle(lifecycles):
    lifecycle_mode = "pre-build"
    if not lifecycles or not isinstance(lifecycles, list):
        return "pre-build"
    for aline in lifecycles:
        phase = aline.get("phase", "")
        if phase == "build":
            lifecycle_mode = "build"
        if phase == "post-build":
            lifecycle_mode = "post-build"
            break
    return lifecycle_mode


def versionify_postbuild_purls(prebuild_purls, build_purls, postbuild_purls):
    matcher_purls = {}
    mpostbuild_purls = {}
    for p in prebuild_purls.keys():
        matcher_purls[p.split("@")[0]] = p
    for p in build_purls.keys():
        matcher_purls[p.split("@")[0]] = p
    for k, v in postbuild_purls.items():
        if matcher_purls.get(k):
            mpostbuild_purls[matcher_purls.get(k)] = v
        else:
            mpostbuild_purls[k] = v
    return mpostbuild_purls


def track_executables(
    file_path, pkg, executable_purls, setuid_executable_purls, setgid_executable_purls
):
    if not pkg or not pkg.get("type", "") == "file" or not pkg.get("properties"):
        return
    props = pkg.get("properties")
    ref = pkg.get("purl") or pkg.get("bom-ref")
    if not ref:
        return
    for p in props:
        if p.get("name", "") == "internal:is_executable" and p["value"] == "true":
            executable_purls[ref].append(file_path)
        if p.get("name", "") == "internal:has_setuid" and p["value"] == "true":
            setuid_executable_purls[ref].append(file_path)
        if p.get("name", "") == "internal:has_setgid" and p["value"] == "true":
            setgid_executable_purls[ref].append(file_path)


def get_lifecycle_pkgs(file_path):
    prebuild_purls = {}
    build_purls = {}
    postbuild_purls = {}
    executable_purls = defaultdict(list)
    setuid_executable_purls = defaultdict(list)
    setgid_executable_purls = defaultdict(list)
    purl_identities = defaultdict(list)
    lifecycle_mode = "pre-build"
    populate_dict = prebuild_purls
    if file_path and os.path.exists(file_path):
        pkg_list, lifecycles = get_pkg_list(file_path)
        lifecycle_mode = get_lifecycle(lifecycles)
        if lifecycle_mode == "pre-build":
            populate_dict = prebuild_purls
        elif lifecycle_mode == "build":
            populate_dict = build_purls
        elif lifecycle_mode == "post-build":
            populate_dict = postbuild_purls
        for pkg in pkg_list:
            ref = pkg.get("purl") or pkg.get("bom-ref")
            if not ref:
                continue
            identity_evidences = pkg.get("evidence", {}).get("identity", []) or []
            if isinstance(identity_evidences, dict):
                identity_evidences = [identity_evidences]
            purl_identities[ref] += identity_evidences
            if not populate_dict.get(ref):
                populate_dict[ref] = []
            populate_dict[ref].append(file_path)
            track_executables(
                file_path,
                pkg,
                executable_purls,
                setuid_executable_purls,
                setgid_executable_purls,
            )
    # Include version numbers to postbuild purls
    postbuild_purls = versionify_postbuild_purls(prebuild_purls, build_purls, postbuild_purls)
    return (
        prebuild_purls,
        build_purls,
        postbuild_purls,
        executable_purls,
        setuid_executable_purls,
        setgid_executable_purls,
        purl_identities,
    )


def get_all_lifecycle_pkgs(from_dir):
    prebuild_purls = {}
    build_purls = {}
    postbuild_purls = {}
    executable_purls = {}
    setuid_executable_purls = {}
    setgid_executable_purls = {}
    purl_identities = {}
    if from_dir and os.path.exists(from_dir):
        bom_files = get_all_bom_files(from_dir)
        for file_path in bom_files:
            pre, build, post, exe, uid, gid, identities = get_lifecycle_pkgs(file_path)
            prebuild_purls |= pre
            build_purls |= build
            postbuild_purls |= post
            executable_purls |= exe
            setuid_executable_purls |= uid
            setgid_executable_purls |= gid
            purl_identities |= identities
    # Include version numbers to postbuild purls
    postbuild_purls = versionify_postbuild_purls(prebuild_purls, build_purls, postbuild_purls)
    return (
        prebuild_purls,
        build_purls,
        postbuild_purls,
        executable_purls,
        setuid_executable_purls,
        setgid_executable_purls,
        purl_identities,
    )
