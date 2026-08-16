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
    resource_path as xbom_resource_path,
)
from depscan.cli_options import DEFAULT_SPEC_VERSION
from depscan.lib.config import (
    DOSAI_PATTERN_PACKS_DEFAULT,
    DOSAI_REACHABLES_SLICE_FILE,
    GOLEM_DEFAULT_CALLGRAPH_MODE,
    GOLEM_DEFAULT_DATAFLOW_MODE,
    GOLEM_REACHABLES_SLICE_FILE,
    RUSI_DEFAULT_BACKEND,
    RUSI_DEFAULT_CALLGRAPH_MODE,
    RUSI_DEFAULT_DATAFLOW_MODE,
    RUSI_REACHABLES_SLICE_FILE,
)
from depscan.lib.logger import LOG, SPINNER, console
from depscan.lib.utils import cleanup_license_string
from dataclasses import dataclass, field
from typing import Dict, List, Optional


class ScanFailureError(RuntimeError):
    """A recoverable-by-default failure surfaced by ``--fail-on-error``.

    Issue #523 showed that unreadable reachability reports and swallowed
    exceptions silently downgrade a scan (missing warnings, degraded VDR).
    Paths that normally degrade keep their behaviour; when the option
    ``fail_on_error`` is set they raise this error instead so the scan aborts
    with a non-zero exit code.
    """


@dataclass(frozen=True)
class BomResult:
    """What a BOM generation attempt actually produced.

    ``create_bom`` takes the path where a BOM is *requested*, but that is an
    instruction, not a promise: lifecycle analysis ignores it entirely and
    writes up to five differently named documents instead. When this returned
    a bare ``bool`` the caller could only learn "something was written
    somewhere" and had no choice but to assume the path it asked for was the
    path that got written, which it then had to disprove by stat'ing the
    filesystem. Report what was written instead.

    There is deliberately no ``__bool__``: callers must say whether they mean
    ``result.success`` or "did I get a document to work with", because those
    are different questions and conflating them is what caused #517.

    :param success: True when at least one BOM document was written.
    :param bom_files: Every document written, verified to exist.
    :param primary: The single BOM representing the project, when the run
        produced one. ``None`` for lifecycle runs, which produce per-stage
        documents rather than one project BOM.
    """

    success: bool
    bom_files: List[str] = field(default_factory=list)
    primary: Optional[str] = None


def _has_bundled_cdxgen() -> bool:
    """Return True if we are inside a frozen bundle that ships cdxgen.

    Used by the BOM-engine picker to keep the SEA (standalone) binary from
    reaching out to a cdxgen container image when cdxgen is already bundled
    under ``local_bin/`` at the bundle root (``sys._MEIPASS``).
    """
    meipass = getattr(sys, "_MEIPASS", None)
    if not meipass:
        return False
    local_bin = xbom_resource_path(
        os.path.join(
            "local_bin",
            "cdxgen.exe" if sys.platform == "win32" else "cdxgen",
        )
    )
    return os.path.exists(local_bin)


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
    # Extract the XML namespace from the element tag so the parser is
    # version-agnostic. CycloneDX XML embeds the spec version in the namespace
    # URI (…/schema/bom/1.5 | 1.6 | 1.7 | 2.0). Hardcoding a single version
    # silently misses licenses on newer BOMs.
    namespace = ""
    if ele.tag.startswith("{"):
        namespace = ele.tag.split("}", 1)[0] + "}"
    for data in ele.findall(f"{namespace}licenses/{namespace}license/{namespace}id"):
        license_list.append(data.text)
    if not license_list:
        for data in ele.findall(f"{namespace}licenses/{namespace}license/{namespace}name"):
            if data is not None and data.text:
                ld_list = [data.text]
                if "http" in data.text:
                    ld_list = [
                        os.path.basename(data.text).replace(".txt", "").replace(".html", "")
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
                pkgs.append({**comp, "vendor": vendor, "licenses": licenses, "url": url})
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
        if root is None:
            return pkgs
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
    return [pkg for pkg in pkg_list if pkg.get("purl", "").startswith("pkg:" + pkg_type)]


def create_bom(bom_file, src_dir=".", options=None) -> BomResult:
    """
    Method to create BOM file by executing cdxgen command

    :param bom_file: Path where the BOM is requested to be written. Honoured by
        the cdxgen and blint paths; lifecycle analysis ignores it and writes
        per-stage documents instead, so always read the paths back from the
        returned :class:`BomResult` rather than assuming this one exists.
    :param src_dir: Source directory
    :param options: Additional options for generating the BOM file.
    :returns: A :class:`BomResult` describing the documents written. Falsy when
        nothing was produced.
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
        blint_ok = create_blint_bom(bom_file, src_dir, options=options)
        return BomResult(
            success=blint_ok,
            bom_files=[bom_file] if blint_ok else [],
            primary=bom_file if blint_ok else None,
        )
    cdxgen_server = options.get("cdxgen_server")
    cdxgen_lib = CdxgenGenerator

    # Should we call cdxgen server
    if cdxgen_server or bom_engine == "CdxgenServerGenerator":
        if not cdxgen_server:
            LOG.error(
                "Pass the `--cdxgen-server` argument to use the cdxgen server for BOM generation. Alternatively, use `--bom-engine auto` or `--bom-engine CdxgenGenerator`."
            )
            return BomResult(success=False)
        cdxgen_lib = CdxgenServerGenerator
    else:
        # Prefer the new image based generators if docker command is available in auto mode
        if bom_engine == "CdxgenImageBasedGenerator":
            cdxgen_lib = CdxgenImageBasedGenerator
        elif bom_engine == "auto":
            # Prefer local CLI while scanning container images
            if any(
                [t in ("docker", "podman", "oci", "os", "hardware") for t in project_type_list]
            ):
                cdxgen_lib = CdxgenGenerator
                if lifecycle_analysis_mode:
                    LOG.warning(
                        "Lifecycle analysis is not supported for oci and os project types."
                    )
                    lifecycle_analysis_mode = True
            elif _has_bundled_cdxgen():
                # Inside a PyInstaller `--onefile` bundle we ship cdxgen under
                # local_bin/. Use it instead of pulling a cdxgen container
                # image: the whole point of the SEA binary is to work with no
                # Node.js, no Docker and no network pull for BOM generation.
                cdxgen_lib = CdxgenGenerator
            elif shutil.which(os.getenv("DOCKER_CMD", "docker")) and sys.platform != "win32":
                cdxgen_lib = CdxgenImageBasedGenerator
    # We now have the cdxgen library to use.
    # For lifecycle analysis, we need to generate multiple BOM files
    if lifecycle_analysis_mode:
        return create_lifecycle_boms(cdxgen_lib, src_dir, options)
    # Invoke the cdxgen library directly
    with console.status(
        f"Generating BOM for the source '{src_dir}' with cdxgen.", spinner=SPINNER
    ):
        bom_result = cdxgen_lib(src_dir, bom_file, logger=LOG, options=options).generate()
        if not bom_result.success:
            LOG.info("The cdxgen invocation was unsuccessful. Try generating the BOM separately.")
            LOG.debug(bom_result.command_output)
            return BomResult(success=False)
        # cdxgen can report success without writing anything, so the requested
        # path only counts once it is on disk.
        if not os.path.exists(bom_file):
            LOG.debug("cdxgen reported success but `%s` was not written.", bom_file)
            return BomResult(success=False)
        # Rust reachability via rusi: emits rust-reachables.slices.json next to
        # the BOM so the existing purl-keyed pipeline picks it up. No-op for
        # non-rust projects or when reachability is off / rusi is absent.
        run_rusi_reachability(bom_file, src_dir, options=options)
        # Go reachability via golem: emits go-reachables.slices.json next to
        # the BOM. No-op for non-go projects or when reachability is off /
        # golem is absent.
        run_golem_reachability(bom_file, src_dir, options=options)
        # .NET reachability via dosai: emits dotnet-reachables.slices.json next
        # to the BOM. No-op for non-dotnet projects or when reachability is off
        # / dosai is absent. PRIMARY path consumes the cdxgen-persisted
        # combined native report; direct-spawn is only a fallback.
        run_dosai_reachability(bom_file, src_dir, options=options)
        return BomResult(success=True, bom_files=[bom_file], primary=bom_file)


def _load_rusi_report(path, is_report_ok, json_load, require_report=False, fail_on_error=False):
    """Load a rusi report JSON, or return None.

    When ``require_report`` is set, a file that is not a rusi report (e.g. an
    atom-produced semantics slice that happens to share the path) is rejected
    by validating its structural SHAPE -- this is how we tell cdxgen's
    persisted rusi report apart from any other ``*-semantics.slices.json``.
    When not required (direct-rusi fallback), a shape mismatch only warns.
    """
    if not path or not os.path.exists(path):
        return None
    try:
        data = json_load(path, log=LOG)
    except Exception as e:
        if fail_on_error:
            raise ScanFailureError(f"Could not read rusi report {path}: {e}") from e
        LOG.debug("Could not read rusi report %s: %s", path, e)
        return None
    if not isinstance(data, dict):
        return None
    if not is_report_ok(data):
        if require_report:
            return None
        LOG.warning("rusi report shape was not recognized; conversion may be incomplete.")
    return data


def _run_rusi_fallback(src_dir, bom_dir, options, is_report_ok, json_load):
    """Invoke rusi directly when cdxgen did not produce a report. Returns the
    parsed report or None. Kept as a fallback so reachability still works when
    cdxgen/plugins are unavailable."""
    fail_on_error = bool(options.get("fail_on_error"))
    try:
        from xbom_lib.rusi import run_rusi
    except ImportError as e:
        if fail_on_error:
            raise ScanFailureError(f"rusi runner unavailable: {e}") from e
        LOG.debug("rusi runner unavailable: %s", e)
        return None
    report_path = os.path.join(bom_dir, "rusi.json")
    # Backend safety gate (per rusi THREAT_MODEL). ``stable`` is parsing-only
    # and safe on untrusted repos; ``compiler`` builds the target and is only
    # enabled via explicit ``--rust-analyzer-backend compiler`` or ``--deep``.
    backend = options.get("rust_analyzer_backend") or RUSI_DEFAULT_BACKEND
    if options.get("deep_scan") or options.get("deep"):
        backend = "compiler"
    with console.status(f"Running rusi Rust reachability on '{src_dir}'.", spinner=SPINNER):
        res = run_rusi(
            src_dir,
            report_path,
            backend=backend,
            callgraph_mode=RUSI_DEFAULT_CALLGRAPH_MODE,
            dataflow_mode=RUSI_DEFAULT_DATAFLOW_MODE,
            logger=LOG,
        )
    if res.skipped or not res.success or not os.path.exists(report_path):
        if fail_on_error:
            raise ScanFailureError(
                f"rusi reachability failed (skipped={res.skipped}, "
                f"success={res.success}, report={report_path}); no slices were produced."
            )
        return None
    return _load_rusi_report(
        report_path, is_report_ok, json_load, require_report=False, fail_on_error=fail_on_error
    )


def run_rusi_reachability(
    bom_file: str,
    src_dir: str,
    options: Optional[Dict] = None,
) -> bool:
    """Run rusi + the slice converter for a Rust project and drop the
    atom-shaped reachables slice next to the BOM.

    No-op (returns False) unless the project is Rust AND reachability is on.
    Gracefully degrades when the rusi binary is missing (warns, returns False,
    never raises) so non-Rust and binary-less environments are unaffected.

    This is the ONLY wiring point for rusi reachability: the existing
    purl-keyed reachability pipeline discovers ``*reachables.slices*.json``
    files by glob, so emitting ``rust-reachables.slices.json`` in the BOM dir
    lights up FrameworkReachability/SemanticReachability with zero engine
    changes.
    """
    if not options:
        return False
    project_type_list: List[str] = options.get("project_type") or []
    # cdxgen labels Cargo projects "rust"; accept the "cargo"/"crates" aliases
    # too so an alternate project-type token never silently skips reachability
    # (mirrors the "go"/"golang" acceptance in run_golem_reachability).
    if not any(pt in ("rust", "cargo", "crates") for pt in project_type_list):
        return False
    if options.get("reachability_analyzer") == "off":
        return False
    if not bom_file or not os.path.exists(bom_file):
        return False
    # Lazy imports so non-Rust scans never pay the import cost and tests that
    # monkeypatch the binary can run in isolation.
    try:
        from analysis_lib.rusi_slices import (
            build_bom_purl_index,
            convert_rusi_report,
            is_rusi_report,
            write_slices_file,
        )
        from custom_json_diff.lib.utils import json_load as _json_load
    except ImportError as e:
        if options.get("fail_on_error"):
            raise ScanFailureError(f"rusi reachability dependencies unavailable: {e}") from e
        LOG.debug("rusi reachability dependencies unavailable: %s", e)
        return False

    bom_dir = os.path.dirname(os.path.abspath(bom_file))
    slice_path = os.path.join(bom_dir, RUSI_REACHABLES_SLICE_FILE)
    prefix = project_type_list[0] if project_type_list else "rust"

    # Prefer the rusi report cdxgen already produced. Under ``--profile
    # research`` cdxgen runs rusi via evinse for rust and (cdxgen >= 12.5.1)
    # persists the full raw rusi report to the ``--semantics-slices-file`` path
    # -- which depscan's set_slices_args passes as
    # ``<bomdir>/<type>-semantics.slices.json``. Consuming that means depscan
    # need NOT invoke rusi itself when cdxgen + plugins are available, and it
    # reads the FULL original report (call graph + data-flow slices), not the
    # projected subset cdxgen embeds in the SBOM.
    cdxgen_report_path = os.path.join(bom_dir, f"{prefix}-semantics.slices.json")
    report = _load_rusi_report(
        cdxgen_report_path,
        is_rusi_report,
        _json_load,
        require_report=True,
        fail_on_error=bool(options.get("fail_on_error")),
    )
    if report is not None:
        LOG.debug(
            "rusi reachability: using cdxgen-produced report at %s",
            cdxgen_report_path,
        )
    else:
        # Fallback: cdxgen did not produce a rusi report (plugins unavailable,
        # or reachability invoked without cdxgen). Invoke rusi directly.
        report = _run_rusi_fallback(src_dir, bom_dir, options, is_rusi_report, _json_load)
    if report is None:
        if options.get("fail_on_error"):
            raise ScanFailureError(
                "No rusi report was available for this Rust project; reachability "
                "slices were not produced."
            )
        LOG.debug("No rusi report available; reachability via rusi skipped.")
        return False

    bom_data = _json_load(bom_file, log=LOG) or {}
    components = bom_data.get("components", []) or []
    # Include the metadata.component (workspace root) so the versioned
    # workspace purl is always in the reconciliation index.
    extra = []
    meta_comp = (bom_data.get("metadata") or {}).get("component")
    if isinstance(meta_comp, dict):
        extra.append(meta_comp)
    bom_index = build_bom_purl_index(components, extra_components=extra)
    flows = convert_rusi_report(report, bom_index)
    write_slices_file(slice_path, flows)
    LOG.debug("rusi reachability: wrote %d flows to %s", len(flows), slice_path)
    return True


def _load_golem_report(path, is_report_ok, json_load, require_report=False, fail_on_error=False):
    """Load a golem report JSON, or return None.

    When ``require_report`` is set, a file that is not a golem report (e.g. an
    atom-produced semantics slice that happens to share the path) is rejected
    by validating its structural SHAPE (``callGraph``/``dataFlow`` +
    ``tool``/``runtime``) -- this is how we tell cdxgen's persisted golem report
    apart from any other ``*-semantics.slices.json``. When not required (direct-
    golem fallback), a shape mismatch only warns.
    """
    if not path or not os.path.exists(path):
        return None
    try:
        data = json_load(path, log=LOG)
    except Exception as e:
        if fail_on_error:
            raise ScanFailureError(f"Could not read golem report {path}: {e}") from e
        LOG.debug("Could not read golem report %s: %s", path, e)
        return None
    if not isinstance(data, dict):
        return None
    if not is_report_ok(data):
        if require_report:
            return None
        LOG.warning("golem report shape was not recognized; conversion may be incomplete.")
    return data


def _run_golem_fallback(src_dir, bom_dir, options, is_report_ok, json_load):
    """Invoke golem directly when cdxgen did not produce a report. Returns the
    parsed report or None. Kept as a fallback so reachability still works when
    cdxgen/plugins are unavailable."""
    fail_on_error = bool(options.get("fail_on_error"))
    try:
        from xbom_lib.golem import run_golem
    except ImportError as e:
        if fail_on_error:
            raise ScanFailureError(f"golem runner unavailable: {e}") from e
        LOG.debug("golem runner unavailable: %s", e)
        return None
    report_path = os.path.join(bom_dir, "golem.json")
    network_mode = options.get("go_analyzer_network") or "auto"
    deep = bool(options.get("deep_scan") or options.get("deep"))
    with console.status(f"Running golem Go reachability on '{src_dir}'.", spinner=SPINNER):
        res = run_golem(
            src_dir,
            report_path,
            callgraph_mode=GOLEM_DEFAULT_CALLGRAPH_MODE,
            dataflow_mode=GOLEM_DEFAULT_DATAFLOW_MODE,
            network_mode=network_mode,
            deep=deep,
            logger=LOG,
        )
    if res.skipped or not res.success or not os.path.exists(report_path):
        if fail_on_error:
            raise ScanFailureError(
                f"golem reachability failed (skipped={res.skipped}, "
                f"success={res.success}, report={report_path}); no slices were produced."
            )
        return None
    return _load_golem_report(
        report_path, is_report_ok, json_load, require_report=False, fail_on_error=fail_on_error
    )


def run_golem_reachability(
    bom_file: str,
    src_dir: str,
    options: Optional[Dict] = None,
) -> bool:
    """Run golem + the slice converter for a Go project and drop the
    atom-shaped reachables slice next to the BOM.

    No-op (returns False) unless the project is Go AND reachability is on.
    Gracefully degrades when the golem binary or Go toolchain is missing
    (warns, returns False, never raises) so non-Go and binary-less
    environments are unaffected.

    This is the ONLY wiring point for golem reachability: the existing
    purl-keyed reachability pipeline discovers ``*reachables.slices*.json``
    files by glob, so emitting ``go-reachables.slices.json`` in the BOM dir
    lights up FrameworkReachability/SemanticReachability with zero engine
    changes.
    """
    if not options:
        return False
    project_type_list: List[str] = options.get("project_type") or []
    if not any(pt in ("go", "golang") for pt in project_type_list):
        return False
    if options.get("reachability_analyzer") == "off":
        return False
    if not bom_file or not os.path.exists(bom_file):
        return False
    try:
        from analysis_lib.golem_slices import (
            build_bom_purl_index,
            convert_golem_report,
            is_golem_report,
            write_slices_file,
        )
        from custom_json_diff.lib.utils import json_load as _json_load
    except ImportError as e:
        if options.get("fail_on_error"):
            raise ScanFailureError(f"golem reachability dependencies unavailable: {e}") from e
        LOG.debug("golem reachability dependencies unavailable: %s", e)
        return False

    bom_dir = os.path.dirname(os.path.abspath(bom_file))
    slice_path = os.path.join(bom_dir, GOLEM_REACHABLES_SLICE_FILE)
    prefix = project_type_list[0] if project_type_list else "go"

    # Prefer the golem report cdxgen already produced. Under ``--profile
    # research`` cdxgen runs golem and (when the sibling cdxgen persistence
    # change lands) persists the full raw golem report to the
    # ``--semantics-slices-file`` path -- which depscan's set_slices_args
    # passes as ``<bomdir>/<type>-semantics.slices.json``.
    cdxgen_report_path = os.path.join(bom_dir, f"{prefix}-semantics.slices.json")
    report = _load_golem_report(
        cdxgen_report_path,
        is_golem_report,
        _json_load,
        require_report=True,
        fail_on_error=bool(options.get("fail_on_error")),
    )
    if report is not None:
        LOG.debug(
            "golem reachability: using cdxgen-produced report at %s",
            cdxgen_report_path,
        )
    else:
        # Fallback: cdxgen did not produce a golem report (plugins unavailable,
        # or reachability invoked without cdxgen). Invoke golem directly.
        report = _run_golem_fallback(src_dir, bom_dir, options, is_golem_report, _json_load)
    if report is None:
        if options.get("fail_on_error"):
            raise ScanFailureError(
                "No golem report was available for this Go project; reachability "
                "slices were not produced."
            )
        LOG.debug("No golem report available; reachability via golem skipped.")
        return False

    bom_data = _json_load(bom_file, log=LOG) or {}
    components = bom_data.get("components", []) or []
    extra = []
    meta_comp = (bom_data.get("metadata") or {}).get("component")
    if isinstance(meta_comp, dict):
        extra.append(meta_comp)
    bom_index = build_bom_purl_index(components, extra_components=extra)
    flows = convert_golem_report(report, bom_index)
    write_slices_file(slice_path, flows)
    LOG.debug("golem reachability: wrote %d flows to %s", len(flows), slice_path)
    return True


def _load_dosai_report(path, is_report_ok, json_load, require_report=False, fail_on_error=False):
    """Load a dosai report JSON, or return None.

    When ``require_report`` is set, a file that is not a dosai report (e.g. an
    atom-produced semantics slice that happens to share the path) is rejected
    by validating its structural SHAPE (``Metadata.Tool == "Dosai"`` plus a
    ``methods``/``dataflows`` OR ``Slices``/``PackageReachability`` key) -- this
    is how we tell cdxgen's persisted combined dosai report apart from any other
    ``*-semantics.slices.json``. When not required (direct-dosai fallback), a
    shape mismatch only warns.
    """
    if not path or not os.path.exists(path):
        return None
    try:
        data = json_load(path, log=LOG)
    except Exception as e:
        if fail_on_error:
            raise ScanFailureError(f"Could not read dosai report {path}: {e}") from e
        LOG.debug("Could not read dosai report %s: %s", path, e)
        return None
    if not isinstance(data, dict):
        return None
    if not is_report_ok(data):
        if require_report:
            return None
        LOG.warning("dosai report shape was not recognized; conversion may be incomplete.")
    return data


def _load_dosai_artifact(path, label, json_load, fail_on_error):
    """Read one raw dosai artifact (methods or dataflows), or return None.

    ``json_load`` swallows ``JSONDecodeError`` and returns ``{}`` (issue #523),
    so a corrupt artifact looks exactly like an empty one. A file with bytes on
    disk that parses to nothing is therefore treated as unreadable, which under
    ``fail_on_error`` aborts the scan instead of quietly downgrading the VDR.
    A genuinely empty artifact stays soft: the caller fails only when both
    artifacts are missing. Every degraded outcome is warned about, since the
    scan then continues with less reachability data than the user asked for.
    """
    if not path or not os.path.exists(path):
        LOG.warning(
            "dosai did not produce a %s report. Reachability analysis will be incomplete.",
            label,
        )
        return None
    try:
        data = json_load(path, log=LOG)
    except Exception as e:
        if fail_on_error:
            raise ScanFailureError(f"Could not read dosai {label} report {path}: {e}") from e
        LOG.warning(
            "Could not read the dosai %s report %s: %s. Reachability analysis will be incomplete.",
            label,
            path,
            e,
        )
        return None
    if not data:
        if fail_on_error and os.path.getsize(path) > 0:
            raise ScanFailureError(f"dosai {label} report {path} was unreadable or empty.")
        LOG.warning(
            "The dosai %s report %s is empty or unreadable. Reachability analysis will be incomplete.",
            label,
            path,
        )
    return data


def _run_dosai_fallback(src_dir, bom_dir, options, is_report_ok, json_load):
    """Invoke dosai directly when cdxgen did not produce a report. Returns the
    parsed combined report ``{Metadata, methods, dataflows}`` or None. Kept as a
    fallback so reachability still works when cdxgen/plugins are unavailable."""
    fail_on_error = bool(options.get("fail_on_error"))
    try:
        from xbom_lib.dosai import run_dosai
    except ImportError as e:
        if fail_on_error:
            raise ScanFailureError(f"dosai runner unavailable: {e}") from e
        LOG.debug("dosai runner unavailable: %s", e)
        return None
    pattern_packs = options.get("dotnet_pattern_packs") or DOSAI_PATTERN_PACKS_DEFAULT
    with console.status(f"Running dosai .NET reachability on '{src_dir}'.", spinner=SPINNER):
        res = run_dosai(
            src_dir,
            bom_dir,
            pattern_packs=pattern_packs,
            logger=LOG,
        )
    if res.skipped or not res.success:
        if fail_on_error:
            raise ScanFailureError(
                f"dosai reachability failed (skipped={res.skipped}, "
                f"success={res.success}); no report was produced."
            )
        return None
    # Assemble a combined report from the two persisted raw artifacts (source
    # of truth). Each may be missing if dosai produced only one. NOTE:
    # json_load swallows JSONDecodeError and returns {} (issue #523), so an
    # unreadable artifact is indistinguishable from an empty one here -- under
    # fail-on-error both must abort the scan.
    methods = _load_dosai_artifact(res.methods_path, "methods", json_load, fail_on_error)
    dataflows = _load_dosai_artifact(res.dataflows_path, "dataflows", json_load, fail_on_error)
    if not methods and not dataflows:
        if fail_on_error:
            raise ScanFailureError(
                "dosai produced no usable methods/dataflows slices; reachability "
                "would silently degrade (issue #523)."
            )
        return None
    # prefer the dataflows Metadata (richest), else methods
    meta = (
        (dataflows or {}).get("Metadata") or (methods or {}).get("Metadata") or {"Tool": "Dosai"}
    )
    combined = {"Metadata": meta, "methods": methods or {}, "dataflows": dataflows or {}}
    return _load_dosai_report_value(combined, is_report_ok)


def _load_dosai_report_value(data, is_report_ok):
    """Validate an already-parsed combined dosai report dict (no file read)."""
    if not isinstance(data, dict):
        return None
    if not is_report_ok(data):
        LOG.warning("dosai report shape was not recognized; conversion may be incomplete.")
    return data


def run_dosai_reachability(
    bom_file: str,
    src_dir: str,
    options: Optional[Dict] = None,
) -> bool:
    """Run dosai + the slice converter for a .NET project and drop the
    atom-shaped reachables slice next to the BOM.

    No-op (returns False) unless the project is .NET AND reachability is on.
    Gracefully degrades when the dosai binary or .NET runtime is missing (warns,
    returns False, never raises) so non-.NET and binary-less environments are
    unaffected.

    PRIMARY path: consume the combined native dosai report cdxgen already
    persisted at ``<bomdir>/<prefix>-semantics.slices.json`` (validated by
    ``is_dosai_report``). Under ``--profile research`` cdxgen runs dosai and
    persists ``{Metadata, methods, dataflows}`` there, so depscan need NOT
    re-spawn dosai when cdxgen + plugins are available, and reads the FULL
    native report, not the projected subset cdxgen embeds in the SBOM.

    FALLBACK path: if the persisted report is absent/invalid, spawn dosai
    directly via :func:`xbom_lib.dosai.run_dosai` (dataflows + methods) and
    persist the raw artifacts.

    Reachability verdict: the atom projection (:func:`convert_dosai_report`)
    faithfully carries every native-reachable purl in its flows' ``purls``, so
    the existing purl-keyed engine picks them up unchanged. The native facts
    (:func:`extract_native_reachability`) are also stashed for VEX/advanced
    analysis. This is the ONLY wiring point for dosai reachability.
    """
    if not options:
        return False
    project_type_list: List[str] = options.get("project_type") or []
    # cdxgen labels .csproj projects "dotnet"; accept csharp/nuget aliases too
    # so an alternate project-type token never silently skips reachability.
    if not any(pt in ("dotnet", "csharp", "nuget") for pt in project_type_list):
        return False
    if options.get("reachability_analyzer") == "off":
        return False
    if not bom_file or not os.path.exists(bom_file):
        return False
    try:
        from analysis_lib.dosai_slices import (
            build_bom_purl_index,
            convert_dosai_report,
            extract_native_reachability,
            is_dosai_report,
            write_slices_file,
        )
        from custom_json_diff.lib.utils import json_load as _json_load
    except ImportError as e:
        if options.get("fail_on_error"):
            raise ScanFailureError(f"dosai reachability dependencies unavailable: {e}") from e
        LOG.debug("dosai reachability dependencies unavailable: %s", e)
        return False

    bom_dir = os.path.dirname(os.path.abspath(bom_file))
    slice_path = os.path.join(bom_dir, DOSAI_REACHABLES_SLICE_FILE)
    prefix = project_type_list[0] if project_type_list else "dotnet"

    # PRIMARY: prefer the combined dosai report cdxgen already produced.
    cdxgen_report_path = os.path.join(bom_dir, f"{prefix}-semantics.slices.json")
    report = _load_dosai_report(
        cdxgen_report_path,
        is_dosai_report,
        _json_load,
        require_report=True,
        fail_on_error=bool(options.get("fail_on_error")),
    )
    if report is not None:
        LOG.debug(
            "dosai reachability: using cdxgen-produced report at %s",
            cdxgen_report_path,
        )
    else:
        # FALLBACK: cdxgen did not produce a dosai report (plugins unavailable,
        # or reachability invoked without cdxgen). Invoke dosai directly.
        report = _run_dosai_fallback(src_dir, bom_dir, options, is_dosai_report, _json_load)
    if report is None:
        if options.get("fail_on_error"):
            raise ScanFailureError(
                "No dosai report was available for this .NET project; reachability "
                "slices were not produced and the VDR would silently downgrade "
                "(issue #523)."
            )
        LOG.debug("No dosai report available; reachability via dosai skipped.")
        return False

    bom_data = _json_load(bom_file, log=LOG) or {}
    components = bom_data.get("components", []) or []
    extra = []
    meta_comp = (bom_data.get("metadata") or {}).get("component")
    if isinstance(meta_comp, dict):
        extra.append(meta_comp)
    bom_index = build_bom_purl_index(components, extra_components=extra)

    # Stash the native reachability facts (the truth) as a sidecar for
    # VEX/advanced analysis. The verdict itself flows through the atom
    # projection below via the existing purl-keyed engine loop.
    facts_path = os.path.join(bom_dir, "dotnet-reachability.facts.json")
    try:
        facts = extract_native_reachability(report, bom_index)
        json_dump(facts_path, facts, compact=True)
    except Exception as e:
        if options.get("fail_on_error"):
            raise ScanFailureError(
                f"Could not persist dosai native reachability facts to {facts_path}: {e}"
            ) from e
        LOG.debug("Could not persist dosai native reachability facts: %s", e)

    flows = convert_dosai_report(report, bom_index)
    write_slices_file(slice_path, flows)
    LOG.debug("dosai reachability: wrote %d flows to %s", len(flows), slice_path)
    return True


def create_blint_bom(bom_file: str, src_dir: str = ".", options: Optional[Dict] = None) -> bool:
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
    with console.status(f"Generating BOM for the source '{src_dir}' with blint.", spinner=SPINNER):
        bom_result = blint_lib.generate()
        if not bom_result.success:
            LOG.info("The blint invocation was unsuccessful. Try generating the BOM separately.")
        return bom_result.success and os.path.exists(bom_file)


def create_lifecycle_boms(cdxgen_lib, src_dir, options) -> BomResult:
    """
    Method to create multiple BOM files for each lifecycle

    :param cdxgen_lib: cdxgen library to use
    :param src_dir: Source directory
    :param options: Additional options for generating the BOM files
    :returns: A :class:`BomResult` listing the per-stage documents written. Its
        ``primary`` is always None: a lifecycle run produces per-stage
        documents, not one BOM representing the project.
    """
    lifecycles = options.get("lifecycles", []) or []
    if lifecycles:
        LOG.warning(
            "Ignoring the `lifecycles` argument, as it is not required for lifecycle analysis."
        )
    # Every stage document actually written, in the order produced.
    written_bom_files = []
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
        bom_result = cdxgen_lib(src_dir, build_bom_file, logger=LOG, options=coptions).generate()
        if not bom_result.success or not os.path.exists(build_bom_file):
            if options.get("fail_on_error"):
                # Falling back to the pre-build stage silently downgrades the
                # lifecycle result, which is exactly what the flag forbids.
                raise ScanFailureError(
                    "The cdxgen invocation failed for the build lifecycle BOM and "
                    "--fail-on-error is set."
                )
            LOG.debug("The cdxgen invocation was unsuccessful. Trying pre-build lifecycle.")
            LOG.debug(bom_result.command_output)
        else:
            written_bom_files.append(build_bom_file)
        # pre-build
        status.update(f"Now generating pre-build BOM for '{src_dir}' with cdxgen.")
        coptions = {**options, "deep": "false", "lifecycles": ["pre-build"]}
        bom_result = cdxgen_lib(
            src_dir, prebuild_bom_file, logger=LOG, options=coptions
        ).generate()
        if not bom_result.success or not os.path.exists(prebuild_bom_file):
            LOG.debug("The cdxgen invocation was unsuccessful. Trying the build lifecycle.")
            LOG.debug(bom_result.command_output)
        else:
            written_bom_files.append(prebuild_bom_file)
        # container bom. For this we need the image name.
        container_image_name = os.getenv("DEPSCAN_SOURCE_IMAGE") or options.get("source_image")
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
                LOG.debug("The cdxgen invocation was unsuccessful. Trying for the next lifecycle.")
                LOG.debug(bom_result.command_output)
            else:
                written_bom_files.append(container_bom_file)
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
        written_bom_files.append(postbuild_bom_file)
    any_success = bool(written_bom_files)
    # Rust reachability via rusi: run once against the source and drop the
    # slice next to the build BOM (the bom_dir the reachability engine scans).
    # No-op for non-rust projects, when reachability is off, or when rusi is
    # absent.
    if any_success and any(
        pt in ("rust", "cargo", "crates") for pt in (options.get("project_type") or [])
    ):
        run_rusi_reachability(build_bom_file, src_dir, options=options)
    # Go reachability via golem: run once against the source and drop the
    # slice next to the build BOM (the bom_dir the reachability engine scans).
    # No-op for non-go projects, when reachability is off, or when golem is
    # absent.
    if any_success and any(pt in ("go", "golang") for pt in (options.get("project_type") or [])):
        run_golem_reachability(build_bom_file, src_dir, options=options)
    # .NET reachability via dosai: run once against the source and drop the
    # slice next to the build BOM (the bom_dir the reachability engine scans).
    # No-op for non-dotnet projects, when reachability is off, or when dosai is
    # absent.
    if any_success and any(
        pt in ("dotnet", "csharp", "nuget") for pt in (options.get("project_type") or [])
    ):
        run_dosai_reachability(build_bom_file, src_dir, options=options)
    # `primary` stays None: no single one of these documents represents the
    # project, so nothing downstream may treat one as "the" BOM.
    return BomResult(success=any_success, bom_files=written_bom_files)


def _spec_version_sort_key(spec_version):
    """Sort key for a CycloneDX specVersion string like ``1.6`` / ``2.0``."""
    major, _, minor = str(spec_version or "").partition(".")
    try:
        return (int(major), int(minor or 0))
    except ValueError:
        return (0, 0)


def determine_spec_version(bom_files=None, fallback=None):
    """Determine the CycloneDX specVersion to use for a from-scratch VDR.

    Prefers the **highest** specVersion found across the given SBOMs (so a
    lifecycle analysis that mixes, say, a 1.6 and a 1.7 BOM emits the VDR at
    1.7 and never downgrades component data). Falls back to the user-supplied
    ``fallback`` (the ``--spec-version`` value) and finally the default.
    """
    versions = []
    for bom_file in bom_files or []:
        data = json_load(bom_file, log=LOG) or {}
        if spec := data.get("specVersion"):
            versions.append(str(spec))
    if versions:
        return max(versions, key=_spec_version_sort_key)
    return fallback or DEFAULT_SPEC_VERSION


def create_empty_vdr(pkg_list, ds_version, spec_version=None):
    components = pkg_list or []
    bom_data = update_tools_metadata(None, None, ds_version, spec_version=spec_version)
    return {**bom_data, "components": components}


def update_tools_metadata(tools, bom_data, ds_version, spec_version=None):
    """
    Helper function to add depscan information as metadata
    :param tools: Tools section of the SBOM
    :param bom_data: SBOM data
    :param ds_version: depscan version
    :param spec_version: CycloneDX specVersion for a from-scratch VDR (user
        ``--spec-version`` input or the max across the source SBOMs). Only used
        when ``bom_data`` is empty; an existing BOM keeps its own specVersion.
    :return: None
    """
    if not bom_data:
        now_utc = datetime.now(timezone.utc)
        bom_data = {
            "bomFormat": "CycloneDX",
            # Spec for from-scratch VDRs (no source BOM). Driven by the user's
            # --spec-version or the max spec across source SBOMs, defaulting to
            # DEFAULT_SPEC_VERSION. When a source BOM exists, export_bom
            # preserves its specVersion verbatim (never downgraded).
            "specVersion": spec_version or DEFAULT_SPEC_VERSION,
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": now_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
        }
    components = tools.get("components", []) if tools else []
    needs_ds_component = len([c for c in components if c.get("name") == "owasp-depscan"]) == 0
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
    if metadata and "components" in metadata.get("tools"):
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
