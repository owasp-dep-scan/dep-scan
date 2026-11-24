import glob
import inspect
import os
import re
import shutil
import sys
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from urllib.parse import unquote_plus

from analysis_lib.evidence.adapters import AdapterResult, not_assessed
from custom_json_diff.lib.utils import json_load, json_dump
from defusedxml.ElementTree import parse
from xbom_lib.cdxgen import (
    CDXGEN_MIN_VERSION,
    CdxgenGenerator,
    CdxgenImageBasedGenerator,
    CdxgenServerGenerator,
    as_command_list,
    cdxgen_install_hint,
    cdxgen_timeout_hint,
    check_cdxgen_version,
    deep_enabled,
    find_cdxgen_cmd,
    resource_path as xbom_resource_path,
)
from depscan.cli_options import DEFAULT_SPEC_VERSION
from depscan.lib.config import (
    DOSAI_PATTERN_PACKS_DEFAULT,
    DOSAI_REACHABLES_SLICE_FILE,
    GOLEM_DEFAULT_CALLGRAPH_MODE,
    GOLEM_DEFAULT_DATAFLOW_MODE,
    GOLEM_REACHABLES_SLICE_FILE,
    KOSI_DEFAULT_BACKEND,
    KOSI_REACHABLES_SLICE_FILE,
    RUSI_DEFAULT_BACKEND,
    RUSI_DEFAULT_CALLGRAPH_MODE,
    RUSI_DEFAULT_DATAFLOW_MODE,
    RUSI_REACHABLES_SLICE_FILE,
    SEMANTIC_REACHABILITY_ANALYZER,
    UNIVERSAL_SCAN_TYPE,
)
from depscan.lib.exclusions import ExclusionSet, kept_targets, project_roots
from depscan.lib.logger import LOG, SPINNER, console_status
from depscan.lib.utils import cleanup_license_string
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple


def _blint_generator_class() -> type:
    """The BlintGenerator class, imported on first use.

    Importing blint pulls in the binary analysis machinery (lief and
    friends) and costs a large part of a second, and only binary BOM
    generation needs it, so a command that never produces a binary BOM
    skips that import. A caller that set ``BlintGenerator`` on this module
    (tests stub it there) wins over the import.
    """
    generator = globals().get("BlintGenerator")
    if generator is not None:
        return generator
    from xbom_lib.blint import BlintGenerator

    return BlintGenerator


def __getattr__(name: str):
    """Resolve ``BlintGenerator`` on first use instead of at import time."""
    if name == "BlintGenerator":
        return _blint_generator_class()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


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
    :param extractor_failures: cdxgen exit status 5 messages, one per
        extractor that failed while the BOM was still written. Kept so a
        later stage can record the affected parts as not assessed instead of
        counting them as clean.
    :param not_assessed: reasons parts of the analysis did not run, such as
        an atom run that ATOM_TIMEOUT stopped. Reachability over an incomplete
        slice set is not a clean result, so these are kept for the scan
        instead of being logged and forgotten.
    :param adapter_results: the evidence adapter result of every language tool
        this run produced or read a report for, keyed by tool name. The
        enrichment stage merges their records into the evidence store.
    :param introspection_gate_missed: the documents cdxgen wrote with exit
        status 4 (an introspection score below its gate). The inventory
        stage logs their fidelity tier from the introspection records.
    :param failure_reason: why nothing was produced, for the manifest's
        inventory stage. Set when the generator failed; a cdxgen failure
        names the CDXGEN_TIMEOUT_MS budget that was in effect, because
        dep-scan sets that budget and a run stopped at it looks like any
        other failure from here.
    :param review_not_assessed: why a requested blint binary review did not
        assess, kept so the scan records a failed review stage instead of a
        console warning nobody reads back.
    """

    success: bool
    bom_files: List[str] = field(default_factory=list)
    primary: Optional[str] = None
    extractor_failures: List[str] = field(default_factory=list)
    not_assessed: List[str] = field(default_factory=list)
    adapter_results: Dict[str, AdapterResult] = field(default_factory=dict)
    introspection_gate_missed: List[str] = field(default_factory=list)
    failure_reason: Optional[str] = None
    review_not_assessed: List[str] = field(default_factory=list)


# cdxgen exit statuses that still deliver a usable BOM. 4 means the
# introspection score missed the gate (the BOM and both reports exist).
# 5 is not one of them: cdxgen only exits 5 when --fail-on-error was passed
# and an extractor failed; the failure is deferred until the BOM and reports
# are written (bin/cdxgen.js and lib/core/deferredExit.js, v13.8.0), but the
# user asked for the scan to stop, so depscan treats it as a failed BOM.
CDXGEN_PARTIAL_EXIT_CODES = (4,)
# One line per deferred extractor failure, as cdxgen 13.8.0 prints it:
# "fail-on-error: <detail> (tool: <tool>, exit <n>)." The closing summary
# line has no "(tool: ...)" part.
_EXTRACTOR_FAILURE_RE = re.compile(r"^fail-on-error: .* \(tool: [^)]*\)\.$")


def _extractor_failures(command_output: Optional[str]) -> List[str]:
    """The deferred extractor failures cdxgen printed for exit status 5.

    cdxgen writes one ``fail-on-error: <detail> (tool: <tool>, exit N).``
    line per failed extractor after the reports are written.
    """
    if not command_output:
        return []
    return [
        line.strip()
        for line in command_output.splitlines()
        if _EXTRACTOR_FAILURE_RE.match(line.strip())
    ]


# The line cdxgen prints when ATOM_TIMEOUT stopped atom (the dispatcher exits
# 124 and executeAtom in lib/inventory/atomUtils.js, v13.8.0, reports it). cdxgen
# itself goes on and exits 0 or 4, so this line in its output is the only
# signal that reaches dep-scan.
_ATOM_TIMEOUT_LINE_RE = re.compile(r"^WARN: atom did not finish within .+ and was stopped")
ATOM_TIMEOUT_REASON = (
    "atom did not finish within its timeout and was stopped; the reachability "
    "slices are missing or incomplete"
)


def _atom_not_assessed(bom_result) -> List[str]:
    """The reasons atom's slices must not be read as complete.

    A run that ATOM_TIMEOUT stopped leaves no slices or partial ones, which
    the reachability analyzers would otherwise count as zero reachable flows.
    One reason is returned however many atom runs timed out.
    """
    command_output = getattr(bom_result, "command_output", None) or ""
    for line in command_output.splitlines():
        if _ATOM_TIMEOUT_LINE_RE.match(line.strip()):
            return [ATOM_TIMEOUT_REASON]
    return []


def _cdxgen_failure_reason(bom_result, stage: str) -> str:
    """Why a failed cdxgen run produced no document, for console and manifest.

    The exit status is named when the process exited on its own, and so is
    the CDXGEN_TIMEOUT_MS budget that was in effect: dep-scan itself sets it
    (30 minutes by default) and stops cdxgen at it, and a run stopped at the
    budget is indistinguishable from any other failure from here, so the
    text says what was in effect without claiming the cause.
    """
    returncode = getattr(bom_result, "returncode", None)
    status = f"exited with status {returncode}" if returncode is not None else "did not finish"
    return (
        f"cdxgen {status} while generating the {stage} BOM, so no document was written. "
        f"{cdxgen_timeout_hint()}. Set the SCAN_DEBUG_MODE=debug environment variable to see the cdxgen output."
    )


def _cdxgen_exit_verdict(bom_result, bom_file: str, stage: str) -> List[str]:
    """Interpret a finished cdxgen run from its exit status.

    Returns the extractor failures to remember; logs everything the status
    means. A status of 0 or 4 delivers a usable BOM. Status 5 (only returned
    under --fail-on-error) and any other status are reported as a failed
    generation, so the scan stops rather than continuing as if nothing was
    found.
    """
    returncode = getattr(bom_result, "returncode", None)
    if returncode in (None, 0):
        return []
    if returncode == 4:
        # The fidelity tier is logged from the introspection record once
        # cdxgen's adapter has read the report (BomResult's
        # introspection_gate_missed names the BOM).
        LOG.warning(
            "cdxgen exited 4 for the %s BOM: the introspection score is below the gate.",
            stage,
        )
        return []
    if returncode == 5:
        failures = _extractor_failures(bom_result.command_output)
        for failure in failures:
            LOG.error(
                "cdxgen exited 5 for the %s BOM under --fail-on-error: an extractor failed. %s",
                stage,
                failure,
            )
        if not failures:
            LOG.error(
                "cdxgen exited 5 for the %s BOM under --fail-on-error: an extractor failed, but cdxgen did not name it.",
                stage,
            )
        return failures
    LOG.error("%s", _cdxgen_failure_reason(bom_result, stage))
    return []


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
    return List of dicts representing extracted packages. Empty when the
    file is missing, unreadable or contains no components.
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


def _refuse_old_cdxgen(logger=None) -> bool:
    """Refuse a local cdxgen older than the pinned minimum.

    Returns True when the command that would run is acceptable. The literal
    ``cdxgen`` is what the generator executes when nothing else resolves, so
    it is probed like any other command; a probe that cannot read a version
    is a refusal. The container and server generators never call this: their
    cdxgen is pinned at build time or runs elsewhere.
    """
    cdxgen_cmd = (
        find_cdxgen_cmd(logger=logger) or find_cdxgen_cmd(False, logger=logger) or "cdxgen"
    )
    accepted, version = check_cdxgen_version(cdxgen_cmd, logger=logger)
    if accepted:
        return True
    if version is None:
        LOG.error(
            "Could not read the cdxgen version from '%s'. dep-scan needs cdxgen %s or newer. "
            "Install it with `%s` and, if needed, point CDXGEN_CMD at it.",
            " ".join(as_command_list(cdxgen_cmd)),
            CDXGEN_MIN_VERSION,
            cdxgen_install_hint(),
        )
    else:
        LOG.error(
            "cdxgen %s was found, but dep-scan needs %s or newer. Install it with `%s` and, if needed, point CDXGEN_CMD at it.",
            version,
            CDXGEN_MIN_VERSION,
            cdxgen_install_hint(),
        )
    return False


def _local_cdxgen_preferred() -> bool:
    """Whether ``--bom-engine auto`` should run a local cdxgen before the image.

    True when ``CDXGEN_CMD`` is set (the user named the command, so it is used
    and refused with the usual message if it is too old), or when a cdxgen
    command that dep-scan can find reports at least the minimum version. A
    local cdxgen that is missing, unreadable or too old is not preferred, and
    the container image stays the fallback.
    """
    if os.getenv("CDXGEN_CMD", "").strip():
        return True
    cdxgen_cmd = find_cdxgen_cmd() or find_cdxgen_cmd(False)
    if not cdxgen_cmd:
        return False
    accepted, _version = check_cdxgen_version(cdxgen_cmd)
    return accepted


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
    lifecycles = options.get("lifecycles") or []
    project_type_list = options.get("project_type") or []
    bom_engine = options.get("bom_engine", "")
    lifecycle_analysis_mode = options.get("lifecycle_analysis_mode", False)
    # The blint BOM path is for targets that are binaries: a binary or apk
    # project type, an explicitly chosen blint engine, or the post-build
    # stage of a lifecycle run. The binary-analysis technique alone (the
    # binary check on a source scan) must not take it: replacing the cdxgen
    # inventory with a blint-written one loses every source component and
    # with them the vulnerability findings, so on a source scan the check
    # runs blint's security review beside the cdxgen BOM instead
    # (:func:`_run_blint_review`).
    blint_bom = (
        bom_engine == "BlintGenerator"
        or "post-build" in lifecycles
        or any([t in ("binary", "apk") for t in project_type_list])
    )
    if blint_bom:
        targets = blint_targets(src_dir, options)
        if not targets:
            return BomResult(
                success=False,
                failure_reason=(
                    "every path below the scan path matches an --exclude pattern, "
                    "so blint had nothing to inventory"
                ),
            )
        blint_ok = create_blint_bom(bom_file, src_dir, options=options, targets=targets)
        review_not_assessed = (
            _run_blint_review(bom_file, src_dir, options)
            if blint_ok and blint_reviews_requested(options)
            else []
        )
        return BomResult(
            success=blint_ok,
            bom_files=[bom_file] if blint_ok else [],
            primary=bom_file if blint_ok else None,
            review_not_assessed=review_not_assessed,
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
            elif _local_cdxgen_preferred():
                # A cdxgen the user named, or one new enough on this machine,
                # runs before the container image: the image pulls a large
                # layer and ignores the local setup.
                cdxgen_lib = CdxgenGenerator
            elif shutil.which(os.getenv("DOCKER_CMD", "docker")) and sys.platform != "win32":
                cdxgen_lib = CdxgenImageBasedGenerator
    # We now have the cdxgen library to use.
    # A local cdxgen CLI is the one binary whose version dep-scan does not
    # control, so it is checked before the first run; the container image and
    # the cdxgen server are pinned or remote and skip the check.
    if cdxgen_lib is CdxgenGenerator and not _refuse_old_cdxgen(logger=LOG):
        return BomResult(
            success=False,
            failure_reason=(
                f"the local cdxgen command was refused; dep-scan needs cdxgen "
                f"{CDXGEN_MIN_VERSION} or newer"
            ),
        )
    # A technique the binary check appended narrows cdxgen's inventory to
    # file-level components (no manifest parsing), which is the opposite of
    # what the check wants on a source scan: the review runs beside the full
    # inventory instead. The user's own --technique values pass through
    # untouched; only the check-appended ones are kept out.
    check_appended = options.get("check_appended_techniques") or []
    generator_options = options
    if check_appended:
        kept = [t for t in (options.get("techniques") or []) if t not in check_appended]
        generator_options = {**options, "techniques": kept or None}
    # For lifecycle analysis, we need to generate multiple BOM files
    if lifecycle_analysis_mode:
        return create_lifecycle_boms(cdxgen_lib, src_dir, generator_options)
    # Invoke the cdxgen library directly
    with console_status(
        f"Generating BOM for the source '{src_dir}' with cdxgen.", spinner=SPINNER
    ):
        bom_result = cdxgen_lib(
            src_dir, bom_file, logger=LOG, options=generator_options
        ).generate()
        extractor_failures: List[str] = []
        not_assessed: List[str] = []
        if bom_result.success:
            extractor_failures = _cdxgen_exit_verdict(bom_result, bom_file, "project")
            not_assessed = _atom_not_assessed(bom_result)
            for reason in not_assessed:
                LOG.warning("Not assessed: %s", reason)
        # Exit status 4 still delivers the BOM; any other failure, 5 included,
        # leaves nothing the user asked to scan.
        partial_ok = getattr(bom_result, "returncode", None) in (
            None,
            0,
            *CDXGEN_PARTIAL_EXIT_CODES,
        )
        if not bom_result.success or not partial_ok:
            reason = _cdxgen_failure_reason(bom_result, "project")
            if not bom_result.success:
                # The verdict above interprets finished runs only; a run that
                # never finished (stopped at the time budget, missing command)
                # has this reason as its only console message.
                LOG.error("%s", reason)
            LOG.info("The cdxgen invocation was unsuccessful. Try generating the BOM separately.")
            LOG.debug(bom_result.command_output)
            return BomResult(success=False, failure_reason=reason)
        # cdxgen can report success without writing anything, so the requested
        # path only counts once it is on disk.
        if not os.path.exists(bom_file):
            LOG.debug("cdxgen reported success but `%s` was not written.", bom_file)
            return BomResult(
                success=False,
                failure_reason=(
                    f"cdxgen reported success but the project BOM was not written "
                    f"at {os.path.basename(bom_file)}"
                ),
            )
        # Each language tool whose project types select it runs (or reads the
        # report cdxgen persisted) and hands its raw report to its evidence
        # adapter. No converted reachables slice is written: the enrichment
        # stage merges the adapter results into the evidence store.
        adapter_results: Dict[str, AdapterResult] = {}
        for name, runner in _reachability_runners().items():
            result = runner(bom_file, src_dir, options=options)
            if result is not None:
                adapter_results[name] = result
        # The binary check on a source scan: blint reviews the binaries the
        # tree holds beside the cdxgen inventory, and the review's findings
        # reach the evidence store from its reports.
        review_not_assessed = (
            _run_blint_review(bom_file, src_dir, options)
            if blint_reviews_requested(options)
            else []
        )
        return BomResult(
            success=True,
            bom_files=[bom_file],
            primary=bom_file,
            extractor_failures=extractor_failures,
            not_assessed=not_assessed,
            adapter_results=adapter_results,
            introspection_gate_missed=(
                [bom_file] if getattr(bom_result, "returncode", None) == 4 else []
            ),
            review_not_assessed=review_not_assessed,
        )


def _load_tool_report(
    tool, path, is_report_ok, json_load, require_report=False, fail_on_error=False
):
    """Load a reachability tool's report JSON, or return None.

    When ``require_report`` is set, a file that is not a *tool* report (e.g.
    an atom-produced semantics slice that happens to share the path) is
    rejected by validating its structural shape -- this is how we tell
    cdxgen's persisted report apart from any other
    ``*-semantics.slices.json``. When not required (the direct-run
    fallback), a shape mismatch only warns.
    """
    if not path or not os.path.exists(path):
        return None
    try:
        data = json_load(path, log=LOG)
    except Exception as e:
        if fail_on_error:
            raise ScanFailureError(f"Could not read {tool} report {path}: {e}") from e
        LOG.debug("Could not read %s report %s: %s", tool, path, e)
        return None
    if not isinstance(data, dict):
        return None
    if not is_report_ok(data):
        if require_report:
            return None
        LOG.warning("%s report shape was not recognized; conversion may be incomplete.", tool)
    return data


def _load_rusi_report(path, is_report_ok, json_load, require_report=False, fail_on_error=False):
    """Load a rusi report JSON, or return None."""
    return _load_tool_report("rusi", path, is_report_ok, json_load, require_report, fail_on_error)


def _load_golem_report(path, is_report_ok, json_load, require_report=False, fail_on_error=False):
    """Load a golem report JSON, or return None."""
    return _load_tool_report("golem", path, is_report_ok, json_load, require_report, fail_on_error)


def _load_dosai_report(path, is_report_ok, json_load, require_report=False, fail_on_error=False):
    """Load a dosai report JSON, or return None."""
    return _load_tool_report("dosai", path, is_report_ok, json_load, require_report, fail_on_error)


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


def _load_dosai_report_value(data, is_report_ok):
    """Validate an already-parsed combined dosai report dict (no file read)."""
    if not isinstance(data, dict):
        return None
    if not is_report_ok(data):
        LOG.warning("dosai report shape was not recognized; conversion may be incomplete.")
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
    report_path = os.path.join(analysis_report_dir(bom_dir, "rusi"), "rusi.json")
    # Backend safety gate (per rusi THREAT_MODEL). ``stable`` is parsing-only
    # and safe on untrusted repos; ``compiler`` builds the target and is only
    # enabled via explicit ``--rust-analyzer-backend compiler`` or ``--deep``.
    backend = options.get("rust_analyzer_backend") or RUSI_DEFAULT_BACKEND
    if options.get("deep_scan") or options.get("deep"):
        backend = "compiler"
    with console_status(f"Running rusi Rust reachability on '{src_dir}'.", spinner=SPINNER):
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
    report_path = os.path.join(analysis_report_dir(bom_dir, "golem"), "golem.json")
    network_mode = options.get("go_analyzer_network") or "auto"
    deep = bool(options.get("deep_scan") or options.get("deep"))
    # cgo stays off unless the operator opted in with --go-analyzer-cgo; with
    # cgo off, packages that need cgo are not loaded and their reachability is
    # missing.
    allow_cgo = bool(options.get("go_analyzer_cgo"))
    with console_status(f"Running golem Go reachability on '{src_dir}'.", spinner=SPINNER):
        res = run_golem(
            src_dir,
            report_path,
            callgraph_mode=GOLEM_DEFAULT_CALLGRAPH_MODE,
            dataflow_mode=GOLEM_DEFAULT_DATAFLOW_MODE,
            network_mode=network_mode,
            deep=deep,
            allow_cgo=allow_cgo,
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


def _run_kosi_fallback(src_dir, bom_dir, options, is_report_ok, json_load):
    """Invoke kosi directly. cdxgen does not persist a kosi report next to
    the BOM, so for Kotlin this is the normal path, not only a fallback.
    The syntax backend reads source only and never starts Gradle or Maven."""
    fail_on_error = bool(options.get("fail_on_error"))
    try:
        from xbom_lib.kosi import run_kosi
    except ImportError as e:
        if fail_on_error:
            raise ScanFailureError(f"kosi runner unavailable: {e}") from e
        LOG.debug("kosi runner unavailable: %s", e)
        return None
    report_path = os.path.join(analysis_report_dir(bom_dir, "kosi"), "kosi.json")
    with console_status(f"Running kosi Kotlin reachability on '{src_dir}'.", spinner=SPINNER):
        res = run_kosi(src_dir, report_path, backend=KOSI_DEFAULT_BACKEND, logger=LOG)
    if res.skipped or not res.success or not os.path.exists(report_path):
        if fail_on_error:
            raise ScanFailureError(
                f"kosi reachability failed (skipped={res.skipped}, "
                f"success={res.success}, report={report_path}); no slices were produced."
            )
        return None
    return _load_tool_report(
        "kosi",
        report_path,
        is_report_ok,
        json_load,
        require_report=False,
        fail_on_error=fail_on_error,
    )


def _run_dosai_fallback(src_dir, bom_dir, options, is_report_ok, json_load):
    """Invoke dosai directly when cdxgen did not produce a report. Returns the
    parsed combined report ``{Metadata, methods, dataflows}`` or None. Kept as
    a fallback so reachability still works when cdxgen/plugins are
    unavailable."""
    fail_on_error = bool(options.get("fail_on_error"))
    try:
        from xbom_lib.dosai import run_dosai
    except ImportError as e:
        if fail_on_error:
            raise ScanFailureError(f"dosai runner unavailable: {e}") from e
        LOG.debug("dosai runner unavailable: %s", e)
        return None
    pattern_packs = options.get("dotnet_pattern_packs") or DOSAI_PATTERN_PACKS_DEFAULT
    # dosai takes the patterns itself (``--exclude``, relative to its path).
    exclusion_args = _accepted_exclude_argument(run_dosai, options)
    with console_status(f"Running dosai .NET reachability on '{src_dir}'.", spinner=SPINNER):
        res = run_dosai(
            src_dir,
            analysis_report_dir(bom_dir, "dosai"),
            pattern_packs=pattern_packs,
            logger=LOG,
            **exclusion_args,
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


def _import_rusi_adapter():
    """Lazily import the rusi evidence adapter, the only code that knows the
    rusi report format."""
    from analysis_lib.evidence.adapters import rusi

    return rusi


def _import_golem_adapter():
    """Lazily import the golem evidence adapter, the only code that knows the
    golem report format."""
    from analysis_lib.evidence.adapters import golem

    return golem


def _import_kosi_adapter():
    """Lazily import the kosi evidence adapter, the only code that knows the
    kosi report format."""
    from analysis_lib.evidence.adapters import kosi

    return kosi


def _import_dosai_adapter():
    """Lazily import the dosai evidence adapter, the only code that knows the
    dosai report format."""
    from analysis_lib.evidence.adapters import dosai

    return dosai


def _semantics_report_names(project_types: List[str], default_prefix: str) -> Tuple[str, ...]:
    """The ``<prefix>-semantics.slices.json`` names cdxgen persists a tool's
    raw report to, for the scan's project types and the tool's default.

    Names keep their first-seen order, so the prefix cdxgen was actually
    given is looked for first.
    """
    names: List[str] = []
    for prefix in [*project_types, default_prefix]:
        name = f"{prefix}-semantics.slices.json"
        if name not in names:
            names.append(name)
    return tuple(names)


def _language_report_names(default_prefix: str, analysis_relative: str):
    """The report names ``tool`` reads from a BOM directory: the names cdxgen
    uses for its persisted report, then the raw report dep-scan's own direct
    run writes under ``analysis/<producer>/``."""
    analysis_relative = analysis_relative.replace(os.sep, "/")

    def report_names(project_types: List[str]) -> Tuple[str, ...]:
        return (*_semantics_report_names(project_types, default_prefix), analysis_relative)

    return report_names


#: The scan-directory directory of the raw reports, spelled with forward
#: slashes for the report names the adapters search by.
ANALYSIS_DIR_STR = "analysis"


def _dosai_report_names(project_types: List[str]) -> Tuple[str, ...]:
    """The dosai report names a BOM directory may hold, in the order they are
    looked at: the two raw artifacts of dep-scan's own direct run, a combined
    report under ``analysis/dosai/``, the report cdxgen persists under the
    research BOM profile, and the cdxgen evinse name."""
    names = [
        os.path.join(ANALYSIS_DIR_STR, "dosai", "dotnet-dataflows.json"),
        os.path.join(ANALYSIS_DIR_STR, "dosai", "dotnet-methods.json"),
        *_semantics_report_names(project_types, "dotnet"),
        "csharp-data-flow.slices.json",
    ]
    return tuple(name.replace(os.sep, "/") for name in names)


@dataclass(frozen=True)
class ReachabilityTool:
    """The parts of a reachability analyzer that differ per language tool.

    :func:`_run_reachability_tool` walks the same steps for every tool: find
    the tool's report (the one cdxgen persisted, else a direct run through
    the fallback) and hand it to the tool's evidence adapter, which returns
    the records. Everything specific to one tool is described here and
    nowhere else.
    """

    name: str
    #: Project-type tokens that select this tool; cdxgen's label plus the
    #: aliases depscan accepts, so an alternate token never silently skips
    #: reachability.
    project_types: tuple
    default_prefix: str
    #: The converted reachables slice this tool's earlier runs wrote. Nothing
    #: writes it any more; the name stays so a stale file of an earlier run
    #: is cleared instead of read.
    slice_file: str
    #: Lazy import of the evidence adapter behind the shared interface.
    import_adapter: Callable
    #: Direct run when cdxgen produced no report.
    run_fallback: Callable
    #: Raised (under ``--fail-on-error``) or recorded when no report was found.
    no_report_error: str
    #: The raw report names this tool reads from a BOM directory, as
    #: directory-relative forward-slash paths, in look-up order.
    report_names: Callable[[List[str]], Tuple[str, ...]]
    #: The place of the raw report a direct fallback run leaves behind, as a
    #: directory-relative forward-slash path. It names the records' source
    #: when the scan ran the tool itself.
    fallback_source: str = ""
    #: The purl type that selects this tool on a universal-typed scan, whose
    #: type token names no language. Empty for a tool the purl of a
    #: component cannot select.
    purl_type: str = ""
    #: File names (or ``*.ext`` suffixes) that mark a directory as a project
    #: of this tool's language. A tool with no exclusion argument of its own
    #: is started on a project root that survives the ``--exclude``
    #: patterns instead of the scan root; empty for a tool that takes the
    #: patterns itself.
    project_markers: tuple = ()


def _remove_tool_slice(path: str) -> None:
    """Delete one tool slice file if it exists."""
    try:
        os.remove(path)
        LOG.debug("Removed the reachability slice %s left by an earlier run.", path)
    except FileNotFoundError:
        pass
    except OSError as e:
        LOG.debug("Could not remove the reachability slice %s: %s", path, e)


def _remove_tool_outputs(directory: str, tool: "ReachabilityTool") -> None:
    """Delete what ``tool`` wrote into ``directory`` on an earlier run.

    The converted reachables slice and its split parts (``<base>-<n>.json``)
    read as this scan's reachability evidence when present, so a run that
    does not produce them must not find them there. The converted slices are
    no longer written; the names stay for the cleanup.
    """
    primary = os.path.join(directory, tool.slice_file)
    _remove_tool_slice(primary)
    base, ext = os.path.splitext(primary)
    for part in glob.glob(glob.escape(base) + "-*" + ext):
        if part[len(base) + 1 : len(part) - len(ext)].isdigit():
            _remove_tool_slice(part)


def clear_tool_outputs(directory: str) -> None:
    """Delete every language tool's converted slices, the raw reports cdxgen
    persisted for the tools, and the evidence files left in ``directory``.

    A source scan writes these in the reports directory it generates the BOM
    into. When that directory is reused, a later scan whose project types do
    not run a tool would otherwise read the earlier run's files as its own
    and report the tool as completed, and an earlier store would be merged
    into this scan's records. cdxgen persists a tool's raw report as
    ``<prefix>-semantics.slices.json``, which the tool step reads before it
    runs the tool itself, so a report an earlier run left there would stand
    in for a report this run never produced. A BOM directory the user
    supplies is an input and is never cleared.
    """
    from depscan.lib.scan_directory import EVIDENCE_FILE, EVIDENCE_INDEX_FILE

    if not directory or not os.path.isdir(directory):
        return
    for tool in _REACHABILITY_TOOLS:
        _remove_tool_outputs(directory, tool)
    for name in (EVIDENCE_FILE, EVIDENCE_INDEX_FILE):
        _remove_tool_slice(os.path.join(directory, name))
    for path in glob.glob(os.path.join(glob.escape(directory), "*-semantics.slices.json")):
        _remove_tool_slice(path)


def _doctor_tool_version(analyzer: str, options: Dict) -> str:
    """The version the doctor report read for ``analyzer``, or the empty
    string when there is none. The adapters prefer the version the report
    itself states; this is the caller's best effort beside it."""
    report = options.get("doctor_report")
    if report is None:
        return ""
    status = (report.tools_by_name() or {}).get(analyzer)
    return str(status.version or "") if status is not None else ""


def _extract_report_records(
    tool: "ReachabilityTool",
    report,
    source: str,
    bom_data: Dict,
    options: Dict,
    fail_on_error: bool,
    source_root: Optional[str] = None,
) -> AdapterResult:
    """Hand one raw report to the tool's evidence adapter, the only code
    that knows the report format.

    The BOM components and the metadata.component root go in for the purl
    reconciliation; dosai takes the built alias index instead.
    ``source_root`` is the scanned source directory, which the adapters
    make the report's file paths relative to. An adapter
    result that is not assessed reads as a downgrade the user asked to hear
    about: under ``--fail-on-error`` it raises, elsewhere it is returned and
    recorded.
    """
    adapter = tool.import_adapter()
    producer_version = _doctor_tool_version(tool.name, options)
    components = bom_data.get("components", []) or []
    extra = []
    meta_comp = (bom_data.get("metadata") or {}).get("component")
    if isinstance(meta_comp, dict):
        extra.append(meta_comp)
    if tool.name == "dosai":
        bom_index = adapter.build_bom_purl_index(components, extra_components=extra)
        result = adapter.extract(
            report,
            source=source,
            producer_version=producer_version,
            bom_index=bom_index,
            source_root=source_root,
        )
    else:
        result = adapter.extract(
            report,
            source=source,
            producer_version=producer_version,
            bom_components=components,
            extra_components=extra,
            source_root=source_root,
        )
    if result.status != "completed" and fail_on_error and result.reason:
        raise ScanFailureError(f"{tool.name} reachability was not assessed: {result.reason}")
    return result


def _bom_carries_purl_type(bom_file: Optional[str], purl_type: str) -> bool:
    """Whether a BOM's components carry a purl of the given type.

    An unreadable or missing BOM selects nothing. Only the purl prefix is
    read, so a component with no purl at all never selects a tool."""
    if not bom_file or not os.path.isfile(bom_file):
        return False
    bom_data = json_load(bom_file, log=LOG) or {}
    prefix = f"pkg:{purl_type}/"
    return any(
        isinstance(component.get("purl"), str) and component["purl"].startswith(prefix)
        for component in bom_data.get("components", []) or []
    )


def _run_reachability_tool(bom_file, src_dir, options, tool) -> Optional[AdapterResult]:
    """Run one reachability tool and hand its raw report to its adapter.

    Returns None when the tool did not apply: the project type does not
    select it, reachability is off, or there is no BOM to reconcile against.
    Otherwise the tool's :class:`AdapterResult` comes back, completed with
    the records or not assessed with the reason. Gracefully degrades when the
    tool is missing, so other languages and binary-less environments are
    unaffected; ``--fail-on-error`` turns every degradation into a
    :class:`ScanFailureError`.

    The raw report keeps the place it was found at and nothing else is
    written: the enrichment stage merges the adapter's records into the
    evidence store.
    """
    if not options:
        return None
    project_type_list: List[str] = options.get("project_type") or []
    if not any(pt in tool.project_types for pt in project_type_list):
        # A universal scan names no language, but its BOM's components do:
        # the tool applies when they carry its purl type. cdxgen is invoked
        # with the universal type too, so its own dispatch never reaches the
        # language analysis either; this gate is what runs it at all. Only
        # semantic reachability starts a language tool this way: the
        # default analyzer reads cdxgen's usage records and must not turn
        # a universal scan of a large tree into a multi-minute analysis.
        if not (
            tool.purl_type
            and options.get("reachability_analyzer") == SEMANTIC_REACHABILITY_ANALYZER
            and UNIVERSAL_SCAN_TYPE in project_type_list
            and _bom_carries_purl_type(bom_file, tool.purl_type)
        ):
            return None
    if bom_file:
        # A slice left by an earlier scan must not outlive a run where this
        # tool does not produce one, or the analyzer would read as completed.
        _remove_tool_outputs(os.path.dirname(os.path.abspath(bom_file)), tool)
    if options.get("reachability_analyzer") == "off":
        return None
    if not bom_file or not os.path.exists(bom_file):
        return None
    fail_on_error = bool(options.get("fail_on_error"))
    from custom_json_diff.lib.utils import json_load as _json_load

    bom_dir = os.path.dirname(os.path.abspath(bom_file))
    prefix = project_type_list[0] if project_type_list else tool.default_prefix

    # PRIMARY: prefer the report cdxgen already produced. Under ``--profile
    # research`` cdxgen runs the tool and persists the FULL raw report to the
    # ``--semantics-slices-file`` path -- which depscan's set_slices_args
    # passes as ``<bomdir>/<type>-semantics.slices.json``. Consuming that
    # means depscan need NOT re-spawn the tool when cdxgen + plugins are
    # available, and it reads the FULL original report (call graph + data-flow
    # slices), not the projected subset cdxgen embeds in the SBOM.
    cdxgen_report_path = os.path.join(bom_dir, f"{prefix}-semantics.slices.json")
    report = _load_tool_report(
        tool.name,
        cdxgen_report_path,
        _is_report_ok(tool),
        _json_load,
        require_report=True,
        fail_on_error=fail_on_error,
    )
    source = f"{prefix}-semantics.slices.json"
    if report is not None:
        LOG.debug(
            "%s reachability: using cdxgen-produced report at %s",
            tool.name,
            cdxgen_report_path,
        )
    else:
        # FALLBACK: cdxgen did not produce a report (plugins unavailable, or
        # reachability invoked without cdxgen). Run the tool directly; it
        # writes its raw report under analysis/<producer>/.
        target, skipped_reason = _fallback_target(tool, src_dir, options)
        if skipped_reason:
            LOG.warning("%s reachability was not assessed: %s", tool.name, skipped_reason)
            if fail_on_error:
                raise ScanFailureError(skipped_reason)
            return not_assessed(skipped_reason)
        report = tool.run_fallback(target, bom_dir, options, _is_report_ok(tool), _json_load)
        source = tool.fallback_source
    if report is None:
        if fail_on_error:
            raise ScanFailureError(tool.no_report_error)
        # The doctor table is the single source of what each analyzer needs;
        # when it explains the missing report, say so. The step itself
        # degrades exactly as it did before the table was consulted.
        reason = _capability_unavailable_reason(tool.name, options)
        if reason:
            LOG.warning("%s reachability was not assessed: %s", tool.name, reason)
        else:
            LOG.debug("No %s report available; reachability via %s skipped.", tool.name, tool.name)
        return not_assessed(reason or tool.no_report_error)

    bom_data = _json_load(bom_file, log=LOG) or {}
    result = _extract_report_records(
        tool, report, source, bom_data, options, fail_on_error, source_root=src_dir
    )
    if result.status == "completed":
        LOG.debug(
            "%s reachability: the adapter built %d records from %s",
            tool.name,
            len(result.records),
            source,
        )
    else:
        LOG.warning("%s reachability was not assessed: %s", tool.name, result.reason)
    return result


def _accepted_exclude_argument(runner: Callable, options) -> Dict[str, Any]:
    """``{"exclude": patterns}`` when the scan has ``--exclude`` patterns and
    ``runner`` accepts an ``exclude`` parameter, else nothing. The check is
    on the installed signature, so a runner or tool without the parameter
    still works and the caller's own target filtering stays the guard."""
    exclusions = ExclusionSet.from_options(options)
    if exclusions and "exclude" in inspect.signature(runner).parameters:
        return {"exclude": list(exclusions.patterns)}
    return {}


def _fallback_target(tool: "ReachabilityTool", src_dir, options) -> Tuple[str, Optional[str]]:
    """The directory a fallback run of ``tool`` starts on, and the reason no
    run can start.

    Without ``--exclude`` patterns (or for a tool that takes them itself)
    this is the scan root. A tool that has no exclusion argument analyses
    whatever sits below the directory it is given, so with patterns it is
    given the one project root the patterns leave, and a scan root that is a
    project itself stays the target. No surviving root, or several of them
    after a pattern removed one (one run covers one directory), gives a
    reason instead of a run that would read excluded trees.
    """
    exclusions = ExclusionSet.from_options(options)
    if not exclusions or not tool.project_markers or not os.path.isdir(src_dir):
        return src_dir, None
    everything = ExclusionSet()
    all_roots = project_roots(src_dir, everything, tool.project_markers, _skipped_dirs())
    kept = project_roots(src_dir, exclusions, tool.project_markers, _skipped_dirs())
    if kept == all_roots:
        return src_dir, None
    if not kept:
        return src_dir, (
            f"every {tool.name} project below the scan path matches an --exclude pattern, "
            "so there is nothing to analyse"
        )
    if len(kept) == 1:
        return kept[0], None
    return src_dir, (
        f"the --exclude patterns remove some of the {len(all_roots)} {tool.name} projects "
        f"below the scan path and {len(kept)} remain; {tool.name} analyses one directory "
        "per run, so scan one project directory or exclude none of them"
    )


def _skipped_dirs() -> Tuple[str, ...]:
    """Directory names no walk of dep-scan's own enters (VCS data and
    dependency caches)."""
    return (".git", "node_modules", ".hg", ".svn")


def _is_report_ok(tool: "ReachabilityTool") -> Callable:
    """The report-shape check of ``tool``'s adapter, used to tell the report
    cdxgen persisted apart from any other file that shares the path. Every
    adapter names it after its own report, as ``is_<tool>_report``."""
    return getattr(tool.import_adapter(), f"is_{tool.name}_report")


RUSI_TOOL = ReachabilityTool(
    name="rusi",
    # cdxgen labels Cargo projects "rust"; accept "cargo"/"crates" aliases.
    project_types=("rust", "cargo", "crates"),
    purl_type="cargo",
    project_markers=("Cargo.toml",),
    default_prefix="rust",
    slice_file=RUSI_REACHABLES_SLICE_FILE,
    import_adapter=_import_rusi_adapter,
    run_fallback=_run_rusi_fallback,
    no_report_error=(
        "No rusi report was available for this Rust project; reachability was not assessed."
    ),
    report_names=_language_report_names("rust", "analysis/rusi/rusi.json"),
    fallback_source=os.path.join(ANALYSIS_DIR_STR, "rusi", "rusi.json").replace(os.sep, "/"),
)

GOLEM_TOOL = ReachabilityTool(
    name="golem",
    project_types=("go", "golang"),
    purl_type="golang",
    project_markers=("go.mod", "go.work"),
    default_prefix="go",
    slice_file=GOLEM_REACHABLES_SLICE_FILE,
    import_adapter=_import_golem_adapter,
    run_fallback=_run_golem_fallback,
    no_report_error=(
        "No golem report was available for this Go project; reachability was not assessed."
    ),
    report_names=_language_report_names("go", "analysis/golem/golem.json"),
    fallback_source=os.path.join(ANALYSIS_DIR_STR, "golem", "golem.json").replace(os.sep, "/"),
)

KOSI_TOOL = ReachabilityTool(
    name="kosi",
    # cdxgen labels Kotlin projects "kotlin" (alias "kt") and Android ones
    # "android". Pure-Java Gradle builds are left to atom.
    project_types=("kotlin", "kt", "android"),
    # kosi keeps the project-type gate alone, with no purl type: Kotlin and
    # plain Java components share the maven purl type, so a purl cannot tell
    # them apart, and a wrong kosi run over a Java build costs more than the
    # run a universal scan of a Kotlin project misses.
    project_markers=(
        "build.gradle",
        "build.gradle.kts",
        "settings.gradle",
        "settings.gradle.kts",
        "pom.xml",
    ),
    default_prefix="kotlin",
    slice_file=KOSI_REACHABLES_SLICE_FILE,
    import_adapter=_import_kosi_adapter,
    run_fallback=_run_kosi_fallback,
    no_report_error=(
        "No kosi report was available for this Kotlin project; reachability was not assessed."
    ),
    report_names=_language_report_names("kotlin", "analysis/kosi/kosi.json"),
    fallback_source=os.path.join(ANALYSIS_DIR_STR, "kosi", "kosi.json").replace(os.sep, "/"),
)

DOSAI_TOOL = ReachabilityTool(
    name="dosai",
    # cdxgen labels .csproj projects "dotnet"; accept csharp/nuget aliases.
    project_types=("dotnet", "csharp", "nuget"),
    purl_type="nuget",
    default_prefix="dotnet",
    slice_file=DOSAI_REACHABLES_SLICE_FILE,
    import_adapter=_import_dosai_adapter,
    run_fallback=_run_dosai_fallback,
    no_report_error=(
        "No dosai report was available for this .NET project; reachability "
        "was not assessed and the VDR would silently downgrade (issue #523)."
    ),
    report_names=_dosai_report_names,
    fallback_source=os.path.join(ANALYSIS_DIR_STR, "dosai", "dotnet-dataflows.json").replace(
        os.sep, "/"
    ),
)


#: Every reachability tool, for the code that reasons about the set rather
#: than one tool: which analyzers a scan's project types could use.
_REACHABILITY_TOOLS = (RUSI_TOOL, GOLEM_TOOL, KOSI_TOOL, DOSAI_TOOL)


def reachability_analyzers_for_types(project_types: List[str]) -> List[str]:
    """The reachability analyzers a scan with these project types could use.

    atom applies to every scan, because every language can carry reachables
    slices. A language tool applies when one of the scan's project types
    selects it, and a BOM directory or universal scan can hold packages of
    any language, so every analyzer applies to those. The tool tables above
    stay the only place that knows which type selects which tool.
    """
    from depscan.lib.config import UNIVERSAL_SCAN_TYPE

    types = list(project_types or [])
    analyzers = ["atom"]
    aggregate = any(t in ("bom", UNIVERSAL_SCAN_TYPE) for t in types)
    for tool in _REACHABILITY_TOOLS:
        if aggregate or any(t in tool.project_types for t in types):
            analyzers.append(tool.name)
    return analyzers


def reachability_slice_files() -> Dict[str, str]:
    """The converted reachables slice name of each language tool, by tool
    name.

    No tool writes these files. The names let the stale-output cleanup
    remove a file an earlier dep-scan version left, and keep atom's adapter
    from reading such a file as atom's own output.
    """
    return {tool.name: tool.slice_file for tool in _REACHABILITY_TOOLS}


def analysis_report_dir(bom_dir: str, producer: str) -> str:
    """The ``analysis/<producer>/`` directory for one tool's raw reports.

    dep-scan keeps the raw reports of the tools it runs itself here, next to
    the BOM they were produced for; the manifest records them as raw-report
    files. Reports cdxgen writes stay where cdxgen puts them.
    """
    from depscan.lib.scan_directory import ANALYSIS_DIR

    directory = os.path.join(bom_dir, ANALYSIS_DIR, producer)
    os.makedirs(directory, exist_ok=True)
    return directory


def _find_named_report(bom_dir, tool, tool_types, fail_on_error):
    """The first of ``tool``'s known report names that holds a readable raw
    report, as (parsed report, directory-relative name)."""
    from custom_json_diff.lib.utils import json_load as _json_load

    is_report_ok = _is_report_ok(tool)
    for relative in tool.report_names(tool_types):
        path = os.path.join(bom_dir, *relative.split("/"))
        data = _load_tool_report(
            tool.name,
            path,
            is_report_ok,
            _json_load,
            require_report=True,
            fail_on_error=fail_on_error,
        )
        if data is not None:
            return data, relative
    return None, ""


def _find_dosai_report(bom_dir, tool_types, fail_on_error):
    """The dosai report a BOM directory holds, as (report, relative name).

    The two raw artifacts of a direct run are assembled into the combined
    report the adapter reads, exactly as the fallback run assembles its own;
    a combined report under ``analysis/dosai/``, the one cdxgen persists, and
    the cdxgen evinse name are handed over as they are.
    """
    from custom_json_diff.lib.utils import json_load as _json_load

    adapter = _import_dosai_adapter()
    dataflows_relative = os.path.join(ANALYSIS_DIR_STR, "dosai", "dotnet-dataflows.json")
    methods_relative = os.path.join(ANALYSIS_DIR_STR, "dosai", "dotnet-methods.json")
    dataflows_path = os.path.join(bom_dir, *dataflows_relative.split("/"))
    methods_path = os.path.join(bom_dir, *methods_relative.split("/"))
    if os.path.isfile(dataflows_path) or os.path.isfile(methods_path):
        methods = _load_dosai_artifact(
            methods_path if os.path.isfile(methods_path) else None,
            "methods",
            _json_load,
            fail_on_error,
        )
        dataflows = _load_dosai_artifact(
            dataflows_path if os.path.isfile(dataflows_path) else None,
            "dataflows",
            _json_load,
            fail_on_error,
        )
        if not methods and not dataflows:
            return None, ""
        meta = (
            (dataflows or {}).get("Metadata")
            or (methods or {}).get("Metadata")
            or {"Tool": "Dosai"}
        )
        combined = {"Metadata": meta, "methods": methods or {}, "dataflows": dataflows or {}}
        source = dataflows_relative if os.path.isfile(dataflows_path) else methods_relative
        return combined, source
    candidates = []
    analysis_dir = os.path.join(bom_dir, ANALYSIS_DIR_STR, "dosai")
    raw_names = {os.path.basename(dataflows_path), os.path.basename(methods_path)}
    if os.path.isdir(analysis_dir):
        for name in sorted(os.listdir(analysis_dir)):
            if name.endswith(".json") and name not in raw_names:
                candidates.append(os.path.join(ANALYSIS_DIR_STR, "dosai", name))
    candidates.extend(name for name in _dosai_report_names(tool_types) if "/" not in name)
    for relative in candidates:
        relative = relative.replace(os.sep, "/")
        path = os.path.join(bom_dir, *relative.split("/"))
        data = _load_tool_report(
            "dosai",
            path,
            adapter.is_dosai_report,
            _json_load,
            require_report=True,
            fail_on_error=fail_on_error,
        )
        if data is not None:
            return data, relative
    return None, ""


def _bom_data_for_tool(bom_files, tool, fail_on_error):
    """The parsed BOM document whose components the tool's records are
    reconciled against: the BOM whose name names one of the tool's project
    types, else the first BOM of the scan."""
    from custom_json_diff.lib.utils import json_load as _json_load

    chosen = None
    for path in bom_files or []:
        lowered = os.path.basename(str(path)).lower()
        if any(f"-{t}" in lowered or lowered.startswith(f"sbom-{t}") for t in tool.project_types):
            chosen = path
            break
    if chosen is None:
        chosen = next(iter(bom_files or []), None)
    if not chosen:
        return {}
    try:
        return _json_load(chosen, log=LOG) or {}
    except Exception as e:  # noqa: BLE001 - the scan degrades, it does not crash
        if fail_on_error:
            raise ScanFailureError(f"Could not read the BOM {chosen} for {tool.name}: {e}") from e
        LOG.warning("Could not read the BOM %s for %s: %s", chosen, tool.name, e)
        return {}


def discover_reachability_reports(
    bom_dir: str,
    project_types: List[str],
    options: Optional[Dict] = None,
    bom_files: Optional[List[str]] = None,
    source_root: Optional[str] = None,
) -> Dict[str, AdapterResult]:
    """Run every language tool's adapter over the raw report a BOM directory
    holds, keyed by tool name.

    ``source_root`` is the scanned source directory when the scan knows one;
    the adapters make the reports' file paths relative to it, and to the
    root a report states itself.

    A BOM-directory scan runs no tool: the analysis ran when the data was
    generated, and the adapters read the reports the directory carries. A
    tool whose report is not there is not assessed with the reason, naming
    what was looked for, or the doctor's reason when it explains why no
    report can be on this machine. Reachability off leaves the map empty.
    """
    from depscan.lib.config import UNIVERSAL_SCAN_TYPE

    if not bom_dir or not os.path.isdir(bom_dir) or not options:
        return {}
    if options.get("reachability_analyzer") == "off":
        return {}
    types = list(project_types or [])
    aggregate = any(t in ("bom", UNIVERSAL_SCAN_TYPE) for t in types)
    fail_on_error = bool(options.get("fail_on_error"))
    results: Dict[str, AdapterResult] = {}
    for tool in _REACHABILITY_TOOLS:
        tool_types = [t for t in types if t in tool.project_types]
        if not (aggregate or tool_types):
            continue
        if tool.name == "dosai":
            report, source = _find_dosai_report(bom_dir, tool_types, fail_on_error)
        else:
            report, source = _find_named_report(bom_dir, tool, tool_types, fail_on_error)
        if report is None:
            reason = _capability_unavailable_reason(tool.name, options)
            if not reason:
                reason = (
                    f"no {tool.name} report was found in the BOM directory "
                    f"(looked for {', '.join(tool.report_names(tool_types))})"
                )
            LOG.warning("%s reachability was not assessed: %s", tool.name, reason)
            results[tool.name] = not_assessed(reason)
            continue
        bom_data = _bom_data_for_tool(bom_files, tool, fail_on_error)
        results[tool.name] = _extract_report_records(
            tool, report, source, bom_data, options, fail_on_error, source_root=source_root
        )
        LOG.debug(
            "%s reachability: the adapter built %d records from %s",
            tool.name,
            len(results[tool.name].records),
            source,
        )
    return results


def _capability_unavailable_reason(analyzer: str, options: Dict) -> Optional[str]:
    """Why an analyzer's capability cannot run here, from the doctor report.

    ``options`` carries the report the scan collected once at setup. Without
    it the check cannot answer, which reads as available: the step then
    behaves exactly as before this lookup existed.
    """
    from depscan.lib import doctor as doctor_lib

    report = options.get("doctor_report")
    if report is None:
        return None
    capability = doctor_lib.ANALYZER_CAPABILITIES.get(analyzer)
    if capability is None:
        return None
    return doctor_lib.capability_unavailable_reason(
        capability, report.tools_by_name(), report.data
    )


def run_rusi_reachability(
    bom_file: str,
    src_dir: str,
    options: Optional[Dict] = None,
) -> Optional[AdapterResult]:
    """Run rusi for a Rust project and hand its raw report to the adapter.

    Returns None unless the project is Rust AND reachability is on. Gracefully
    degrades when the rusi binary is missing (a not-assessed result with the
    reason, never raises) so non-Rust and binary-less environments are
    unaffected.
    """
    return _run_reachability_tool(bom_file, src_dir, options, RUSI_TOOL)


def run_golem_reachability(
    bom_file: str,
    src_dir: str,
    options: Optional[Dict] = None,
) -> Optional[AdapterResult]:
    """Run golem for a Go project and hand its raw report to the adapter.

    Returns None unless the project is Go AND reachability is on. Gracefully
    degrades when the golem binary or Go toolchain is missing (a not-assessed
    result with the reason, never raises) so non-Go and binary-less
    environments are unaffected.
    """
    return _run_reachability_tool(bom_file, src_dir, options, GOLEM_TOOL)


def run_kosi_reachability(
    bom_file: str,
    src_dir: str,
    options: Optional[Dict] = None,
) -> Optional[AdapterResult]:
    """Run kosi for a Kotlin project and hand its raw report to the adapter.

    Returns None unless the project is Kotlin AND reachability is on.
    Gracefully degrades when the kosi binary is missing (a not-assessed
    result with the reason, never raises) so non-Kotlin and binary-less
    environments are unaffected.
    """
    return _run_reachability_tool(bom_file, src_dir, options, KOSI_TOOL)


def run_dosai_reachability(
    bom_file: str,
    src_dir: str,
    options: Optional[Dict] = None,
) -> Optional[AdapterResult]:
    """Run dosai for a .NET project and hand its raw report to the adapter.

    Returns None unless the project is .NET AND reachability is on. Gracefully
    degrades when the dosai binary or .NET runtime is missing (a not-assessed
    result with the reason, never raises) so non-.NET and binary-less
    environments are unaffected. The PRIMARY path consumes the cdxgen-persisted
    combined report; the direct-spawn fallback assembles one from the two raw
    artifacts it leaves under ``analysis/dosai/``.
    """
    return _run_reachability_tool(bom_file, src_dir, options, DOSAI_TOOL)


def _reachability_runners() -> Dict[str, Callable]:
    """The run helper of every reachability tool, keyed by name, in the order
    the BOM step runs them. Built at call time so the helpers are looked up
    as they are now, which is what tests and callers that replace one of
    them rely on."""
    return {
        "rusi": run_rusi_reachability,
        "golem": run_golem_reachability,
        "kosi": run_kosi_reachability,
        "dosai": run_dosai_reachability,
    }


def blint_reviews_requested(options: Optional[Dict]) -> bool:
    """Whether the scan asked for blint's security review of the binaries.

    The binary check (``--checks binary``, which sets the binary-analysis
    technique), a binary or apk project type and an explicit blint BOM engine
    all ask for it. The post-build BOM that lifecycle analysis adds does not:
    it is a side input to a source scan, not a request to review binaries.
    """
    options = options or {}
    project_types = options.get("project_type") or []
    return bool(
        options.get("bom_engine") == "BlintGenerator"
        or "binary-analysis" in (options.get("techniques") or [])
        or any(t in ("binary", "apk") for t in project_types)
    )


def _run_blint_review(bom_file: str, src_dir: str, options: Optional[Dict]) -> List[str]:
    """Run blint's security and capability review and keep its reports.

    The review writes ``findings.json``, ``reviews.json`` and
    ``analysis-coverage.json`` under ``analysis/blint/`` beside the BOM,
    which is where the blint evidence adapter reads them, so the review's
    findings reach the evidence store and ``depscan.findings.json``.
    dep-scan drives the review itself rather than leaving it to the BOM
    generator, so the cdxgen path of a source scan and the blint path of a
    binary target share one step whose outcome the scan can record. A
    failure never raises; its reason comes back for the manifest.

    Returns the reasons the review did not assess, empty when it ran.
    """
    from xbom_lib.blint import run_blint_reviews

    review_dir = analysis_report_dir(os.path.dirname(os.path.abspath(bom_file)), "blint")
    targets = blint_targets(src_dir, options)
    if not targets:
        LOG.info("The blint review has no target: every path matches an --exclude pattern.")
        return []
    with console_status(f"Running blint's binary review on '{src_dir}'.", spinner=SPINNER):
        review = run_blint_reviews(
            targets,
            review_dir,
            deep=deep_enabled(options or {}),
            **_accepted_exclude_argument(run_blint_reviews, options),
        )
    if review.success:
        return []
    LOG.warning("%s", review.command_output)
    return [review.command_output or "the blint review failed without a reason"]


def blint_targets(src_dir: str, options: Optional[Dict]) -> List[str]:
    """The paths dep-scan hands blint for a comma-separated ``src_dir``.

    With ``--exclude`` patterns in the cdxgen arguments, each directory is
    replaced by the directories and files that together cover everything
    the patterns keep, so blint's own walk never reaches an excluded tree
    (see :func:`depscan.lib.exclusions.kept_targets`). Without patterns the
    entries come back unchanged. An empty list means nothing is left.
    """
    entries = [entry for entry in src_dir.split(",") if entry]
    exclusions = ExclusionSet.from_options(options)
    if not exclusions:
        return entries
    targets: List[str] = []
    for entry in entries:
        if os.path.isdir(entry):
            targets.extend(kept_targets(entry, exclusions, _blint_ignored_dirs()))
        else:
            targets.append(entry)
    return targets


def _blint_ignored_dirs() -> Tuple[str, ...]:
    """The directory names blint never enters, lower-cased as blint compares
    them; empty when blint is not installed."""
    try:
        from blint.config import ignore_directories
    except ImportError:
        return ()
    return tuple(ignore_directories)


def create_blint_bom(
    bom_file: str,
    src_dir: str = ".",
    options: Optional[Dict] = None,
    targets: Optional[List[str]] = None,
) -> bool:
    """
    Method to create BOM file by using blint

    :param bom_file: BOM file
    :param src_dir: Source directory
    :param options: Additional options for generating the BOM file.
    :param targets: The paths to inventory, as :func:`blint_targets` returns
        them; computed from ``src_dir`` and the ``--exclude`` patterns when
        not given.
    :returns: True if the bom was generated successfully. False otherwise.
    """
    if options is None:
        options = {}
    reachability_analyzer = options.get("reachability_analyzer")
    # The side effect is that we will almost always run blint in deep mode
    if reachability_analyzer != "off" and not options.get("deep"):
        options["deep"] = True
    generator_options = dict(options)
    if targets is None:
        targets = blint_targets(src_dir, options)
    if not targets:
        LOG.warning("The blint BOM has no target: every path matches an --exclude pattern.")
        return False
    # The target list rides along as a list too, so a path with a comma in
    # it survives; the patterns are for a blint that filters its own walk.
    generator_options["blint_targets"] = list(targets)
    generator_options["exclude_patterns"] = list(ExclusionSet.from_options(options).patterns)
    blint_lib = _blint_generator_class()(
        ",".join(targets), bom_file, logger=LOG, options=generator_options
    )
    with console_status(f"Generating BOM for the source '{src_dir}' with blint.", spinner=SPINNER):
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
    extractor_failures: List[str] = []
    not_assessed: List[str] = []
    introspection_gate_missed: List[str] = []
    prebuild_bom_file = options.get("prebuild_bom_file")
    build_bom_file = options.get("build_bom_file")
    postbuild_bom_file = options.get("postbuild_bom_file")
    container_bom_file = options.get("container_bom_file")
    reachability_analyzer = options.get("reachability_analyzer")

    def stage_usable(bom_result, stage_file, stage) -> bool:
        """Whether one lifecycle stage produced a document worth scanning.

        Exit status 4 still counts: the BOM and its introspection reports are
        written. Exit status 5 does not, because cdxgen only returns it under
        --fail-on-error; the failures are logged and kept in
        ``extractor_failures``. Reasons the stage's slice set is incomplete
        (an atom timeout) are kept in ``not_assessed``.
        """
        if not bom_result.success:
            _record_stage_failure(bom_result, stage_file, stage)
            return False
        extractor_failures.extend(_cdxgen_exit_verdict(bom_result, stage_file, stage))
        if getattr(bom_result, "returncode", None) == 4:
            introspection_gate_missed.append(stage_file)
        for reason in _atom_not_assessed(bom_result):
            if reason not in not_assessed:
                not_assessed.append(reason)
                LOG.warning("Not assessed: %s", reason)
        if getattr(bom_result, "returncode", None) not in (
            None,
            0,
            *CDXGEN_PARTIAL_EXIT_CODES,
        ):
            _record_stage_failure(bom_result, stage_file, stage)
            return False
        if not os.path.exists(stage_file):
            reason = f"cdxgen reported success but the {stage} lifecycle BOM was not written"
            not_assessed.append(reason)
            LOG.warning("Not assessed: %s", reason)
            return False
        return True

    def _record_stage_failure(bom_result, stage_file, stage) -> None:
        """Keep why one lifecycle stage's document is missing.

        A stage that falls away (the scan continues on the other stages'
        documents) must leave a named trace, or the inventory reads as a
        whole: the reason carries the cdxgen exit status and the time budget
        that was in effect, like the single-document path's failure reason.
        """
        reason = _cdxgen_failure_reason(bom_result, f"{stage} lifecycle")
        not_assessed.append(reason)
        LOG.warning("Not assessed: %s", reason)

    with console_status(
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
        if not stage_usable(bom_result, build_bom_file, "build"):
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
        if not stage_usable(bom_result, prebuild_bom_file, "pre-build"):
            LOG.debug("The cdxgen invocation was unsuccessful. Trying the build lifecycle.")
            LOG.debug(bom_result.command_output)
        else:
            written_bom_files.append(prebuild_bom_file)
        # container bom. For this we need the image name.
        container_image_name = os.getenv("DEPSCAN_SOURCE_IMAGE") or options.get("source_image")
        if container_image_name:
            status.update(f"Generating container BOM for '{src_dir}' with cdxgen.")
            # Not deep and without slices: a deep oci run makes atom parse
            # every source file of every package installed in the image,
            # which ran for over an hour on dep-scan's own image and timed
            # out with no container BOM at all. Reachability reads the
            # source stage's slices, never the image's, and the image's
            # packages are listed without the deep pass.
            coptions = {
                **options,
                "deep": "false",
                "slices": False,
                "project_type": ["oci"],
            }
            if container_image_name == src_dir:
                LOG.info(
                    "Set the environment variable DEPSCAN_SOURCE_IMAGE to the name of the container image to include its components."
                )
            bom_result = cdxgen_lib(
                container_image_name, container_bom_file, logger=LOG, options=coptions
            ).generate()
            if not stage_usable(bom_result, container_bom_file, "container"):
                LOG.warning(
                    "No container BOM was generated for the image %s, so its "
                    "packages are missing from this scan.",
                    container_image_name,
                )
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
    review_not_assessed: List[str] = []
    if not res or not os.path.exists(postbuild_bom_file):
        reason = (
            "the post-build lifecycle BOM was not generated; the blint invocation "
            "was unsuccessful. Try building this project prior to invoking depscan, "
            "or check that it generates binary artefacts"
        )
        not_assessed.append(reason)
        LOG.debug(
            "The blint invocation was unsuccessful. Try building this project prior to invoking depscan. Alternatively, check if this project generates binary artefacts."
        )
    else:
        written_bom_files.append(postbuild_bom_file)
        if blint_reviews_requested(options):
            # The binary check on a lifecycle scan reviews the built
            # artefacts beside the post-build document they went into.
            review_not_assessed = _run_blint_review(postbuild_bom_file, build_dir, options)
    any_success = bool(written_bom_files)
    # Each language tool whose project types select it runs once against the
    # source; its raw report goes to the evidence adapter, whose result rides
    # back to the enrichment stage on the BOM result.
    adapter_results: Dict[str, AdapterResult] = {}
    if any_success:
        for name, runner in _reachability_runners().items():
            result = runner(build_bom_file, src_dir, options=options)
            if result is not None:
                adapter_results[name] = result
    # `primary` stays None: no single one of these documents represents the
    # project, so nothing downstream may treat one as "the" BOM.
    return BomResult(
        success=any_success,
        bom_files=written_bom_files,
        extractor_failures=extractor_failures,
        not_assessed=not_assessed,
        adapter_results=adapter_results,
        introspection_gate_missed=introspection_gate_missed,
        review_not_assessed=review_not_assessed,
    )


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
    # A source BOM may have no metadata block at all; CycloneDX makes it
    # optional.
    metadata = bom_data.get("metadata")
    if not isinstance(metadata, dict):
        metadata = bom_data["metadata"] = {}
    metadata["tools"] = {"components": components}
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
    bom_data["vulnerabilities"] = [
        _with_rfc3339_dates(vuln) if isinstance(vuln, dict) else vuln
        for vuln in pkg_vulnerabilities or []
    ]
    json_dump(
        vdr_file,
        bom_data,
        compact=True,
        error_msg=f"Unable to generate VDR file at {vdr_file}",
    )


#: The date-time fields of a CycloneDX vulnerability, and of its analysis.
_VULN_DATE_FIELDS = ("created", "published", "updated", "rejected")
_ANALYSIS_DATE_FIELDS = ("firstIssued", "lastUpdated")


def to_rfc3339(value):
    """A CycloneDX ``date-time`` string for ``value``, or None.

    CycloneDX date-times are RFC 3339 and carry a timezone. The vulnerability
    database stores naive UTC times ("2021-09-02T17:16:46"), so a value
    without an offset is read as UTC and written with a ``Z``. A value that
    is empty or cannot be read as a date returns None, and the caller drops
    the field rather than write a document that fails its own schema.
    """
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value.strip():
        text = value.strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    if parsed.utcoffset() == timezone.utc.utcoffset(None):
        return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return parsed.isoformat(timespec="seconds")


def _with_rfc3339_dates(vuln):
    """The vulnerability with every date-time field in RFC 3339 form."""
    for key in _VULN_DATE_FIELDS:
        if key in vuln:
            converted = to_rfc3339(vuln[key])
            if converted:
                vuln[key] = converted
            else:
                del vuln[key]
    analysis = vuln.get("analysis")
    if isinstance(analysis, dict):
        for key in _ANALYSIS_DATE_FIELDS:
            if key in analysis:
                converted = to_rfc3339(analysis[key])
                if converted:
                    analysis[key] = converted
                else:
                    del analysis[key]
    return vuln


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
