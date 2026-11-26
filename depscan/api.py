"""The public Python API for running and inspecting dep-scan scans.

``scan`` runs the same stage pipeline the ``depscan`` command runs, in the
same order, and returns a :class:`ScanResult` instead of exiting the process.
``load_scan`` rebuilds a result from a reports directory a scan wrote,
``query`` filters the vulnerabilities of a result, ``explain`` returns the
text the ``--explain`` rendering produces and ``diff` compares two results.

The command line (the verb dispatch in ``depscan.cli``) and the depscan
server call these functions; they do not drive the pipeline directly. This
module imports from
:mod:`depscan.lib.pipeline`; the pipeline never imports this module.

The API is new in 7.0 and may change before the 7.0.0 release.
"""

import glob
import os
import re
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Tuple

from custom_json_diff.lib.utils import json_load
from vdb.lib.utils import parse_purl

from depscan.cli_options import build_parser
from depscan.lib import explainer, pipeline, scan_directory
from depscan.lib import doctor as doctor_lib
from depscan.lib.config import DEPSCAN_DEFAULT_VDR_FILE
from depscan.lib.doctor import DoctorReport
from depscan.lib.logger import LOG, console

__all__ = [
    "DiffEntry",
    "DoctorReport",
    "ScanDiff",
    "ScanError",
    "ScanResult",
    "TypeScanResult",
    "diff",
    "doctor",
    "explain",
    "load_scan",
    "query",
    "scan",
    "scan_options",
]


class ScanError(RuntimeError):
    """A scan stopped early, or a result could not be read.

    ``scan`` raises this when a pipeline stage decides the scan must stop;
    the message is the one the stage logged. ``load_scan`` and ``explain``
    raise it when their input is missing what they need. The API never
    returns a result with zero vulnerabilities in place of a stopped scan.
    """


@dataclass
class TypeScanResult:
    """What one project type of a scan produced.

    ``bom_file`` is the CycloneDX BOM the type was scanned from and
    ``vdr_file`` the vulnerability report written for it; either is None when
    the scan produced no such file (a single-purl scan writes neither, and no
    BOM file is written for a ``--bom`` scan whose input lives elsewhere).
    ``vulnerabilities`` is the list written to that VDR, in write order.
    """

    project_type: str
    bom_file: Optional[str] = None
    vdr_file: Optional[str] = None
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class ScanResult:
    """The outcome of one scan.

    ``reports_dir`` is the directory the scan wrote its files to.
    ``project_types`` lists every project type the scan ran for, including
    types that were skipped with a log message after producing nothing.
    ``types`` holds one :class:`TypeScanResult` per type that produced
    results, in scan order. ``manifest`` is the scan directory's manifest
    document and ``findings`` the array of ``depscan.findings.json``; both
    are set for a scan of this version and for a manifest-backed
    :func:`load_scan`, and carry the earlier values (None and []) when a
    directory without a manifest is loaded. ``findings_version`` is the
    findings document's ``schemaVersion`` as read, or None without one.
    """

    reports_dir: str
    project_types: List[str] = field(default_factory=list)
    types: List[TypeScanResult] = field(default_factory=list)
    manifest: Optional[Dict[str, Any]] = None
    findings: List[Dict[str, Any]] = field(default_factory=list)
    findings_version: Optional[str] = None

    @property
    def vulnerabilities(self) -> List[Dict[str, Any]]:
        """Every vulnerability of every type, in type then write order."""
        return [vuln for tscan in self.types for vuln in tscan.vulnerabilities]


@dataclass
class DiffEntry:
    """One (vulnerability id, affected ref) pair that differs between results.

    ``old`` and ``new`` are the vulnerability objects carrying the pair on
    each side; ``old`` is None for a new pair and ``new`` is None for a
    fixed one. ``ref`` is None for a vulnerability that names no affected
    ref.
    """

    id: str
    ref: Optional[str]
    old: Optional[Dict[str, Any]] = None
    new: Optional[Dict[str, Any]] = None


@dataclass
class ScanDiff:
    """The difference between two scan results, one entry per pair.

    ``new`` holds the pairs only in the new result and ``fixed`` those only
    in the old one. ``changed`` holds the pairs present on both sides whose
    highest rating differs in severity or score. See :func:`diff` for the
    key.
    """

    new: List[DiffEntry] = field(default_factory=list)
    fixed: List[DiffEntry] = field(default_factory=list)
    changed: List[DiffEntry] = field(default_factory=list)


def scan_options(**overrides) -> Any:
    """Return the command line defaults as an ``argparse.Namespace``.

    The defaults are exactly what ``depscan`` itself parses from an empty
    command line, so every option of the CLI can be overridden by its
    ``dest`` name, for example ``bom``, ``reports_dir``, ``search_purl`` or
    ``no_banner``.

    :param overrides: option names mapped to their values.
    :returns: The default options with the overrides applied.
    :raises TypeError: When an override name is not an option ``dest``; the
        exception names the offending key.
    """
    options = build_parser().parse_args([])
    known = vars(options)
    for name, value in overrides.items():
        if name not in known:
            raise TypeError(
                f"Unknown scan option {name!r}. scan_options accepts the "
                "depscan command line option names, for example 'bom', "
                "'reports_dir', 'search_purl' or 'no_banner'."
            )
        setattr(options, name, value)
    return options


def doctor() -> DoctorReport:
    """Collect the tools, data and capabilities report for this machine.

    The report locates every tool a scan may call and reads each version
    with the tool's own version option, inspects the vulnerability database
    read-only and evaluates the capability table against what it found. It
    never prompts and never downloads anything; a missing tool or database
    is a reported state, so the call always returns a report.

    :returns: The :class:`DoctorReport`; ``to_dict()`` produces the JSON
        document and ``to_text()`` the text rendering the command prints.
    """
    return doctor_lib.doctor()


def scan(
    options,
    *,
    render: bool = True,
    doctor_report: Optional[DoctorReport] = None,
    checks_not_assessed: Optional[List[Dict[str, Any]]] = None,
) -> ScanResult:
    """Run a scan with the given options and return its result.

    This runs the stages the ``depscan`` command runs, in the same order,
    including the console, quiet and debug handling of the CLI, and writes
    the same files to ``options.reports_dir``: the BOM documents, the VDR
    files, the license reports and the cdx-audit reports and ``depscan.toml.sample``, plus
    the scan directory's own ``depscan.findings.json`` and
    ``depscan.manifest.json``.

    With ``render=False`` the rendering is skipped (the console tables, the
    HTML and text reports, the template report, the explanation, the CSAF
    export and the ``--annotate`` annotations of the VDR, which all live in
    the rendering stages); everything the other stages write, the VDR and
    BOM files included, is still written. Skipping
    the console tables forces ``no_vuln_table`` on the given options, because
    the tables are part of the rendering.

    ``doctor_report`` is a report a caller already collected; the scan reuses
    it instead of probing the machine a second time. ``checks_not_assessed``
    lists checks, as ``{"name": ..., "reason": ...}`` dictionaries, that a
    caller decided cannot run; each is recorded in the manifest as a
    ``check-<name>`` stage with status ``not-assessed``. Both travel only
    through these keywords: every value of the options namespace is copied
    into the manifest and the sample config, so a report object must never
    land there.

    :param options: An ``argparse.Namespace`` from the CLI parser or from
        :func:`scan_options`.
    :param render: Render the console and report output (the default).
    :param doctor_report: Reuse this :class:`DoctorReport` instead of
        collecting one.
    :param checks_not_assessed: Check entries to record as not assessed.
    :returns: The :class:`ScanResult` of the scan, carrying the manifest and
        findings of the scan directory it wrote.
    :raises ScanError: When a stage stops the scan, with the message the
        stage logged. The function never calls ``sys.exit`` and never
        returns a result in place of a stopped scan. A scan that stopped
        partway still leaves its directory with a manifest naming the
        failed stage.
    """
    return _run_stages(
        options,
        render=render,
        database=True,
        write_scan_dir=True,
        doctor_report=doctor_report,
        checks_not_assessed=checks_not_assessed,
    )


def _run_stages(
    options,
    *,
    render: bool,
    database: bool,
    write_scan_dir: bool = False,
    doctor_report: Optional[DoctorReport] = None,
    checks_not_assessed: Optional[List[Dict[str, Any]]] = None,
) -> ScanResult:
    """Run the scan stages; see :func:`scan`.

    ``database=False`` skips the database stage, and ``write_scan_dir=False``
    leaves the scan directory unwritten. Only the server uses these: it
    prepares the database once when it starts, so a request never downloads
    or replaces the database the server is reading, and a request's output is
    the response rather than a directory. ``doctor_report`` and
    ``checks_not_assessed`` see :func:`scan`.
    """
    if not render:
        options.no_vuln_table = True
    ctx = pipeline.build_context(options)
    ctx.write_scan_dir = write_scan_dir
    if doctor_report is not None:
        ctx.doctor_report = doctor_report
    pipeline.configure_output(ctx)
    written = None
    try:
        # We have everything needed to start the composition analysis. There are many approaches to implementing an SCA tool.
        # Our style of analysis is comparable to that of an intelligent Hubble telescope or a rover—examining the same subject through multiple optics, colors, and depths to gain a deeper understanding.
        # We begin by iterating over the project types provided or assumed.
        pipeline.stage_setup(ctx)
        _record_checks_not_assessed(ctx, checks_not_assessed)
        if database:
            _stage(ctx, "database", pipeline.stage_database, ctx, capabilities=["vulnerabilities"])
        pipeline.finalize_setup(ctx)
        for project_type in ctx.project_types:
            tscan = pipeline.TypeScan(project_type=project_type)
            if not _stage(
                ctx,
                "inventory",
                pipeline.stage_inventory,
                ctx,
                tscan,
                project_type=project_type,
                capabilities=_inventory_capabilities(options, project_type),
                skipped_reason="the type produced no BOM or packages to scan",
                failed_reason=lambda: tscan.inventory_error,
                record_extra=lambda: {
                    "notAssessed": list(tscan.not_assessed),
                    "outputs": _inventory_outputs(ctx, tscan),
                },
            ):
                continue
            # A requested blint review that failed ran during the inventory;
            # its failure is a stage of its own beside the inventory that
            # kept going, so a review problem never leaves only a warning.
            for reason in tscan.review_not_assessed:
                if ctx.scan_dir is not None:
                    ctx.scan_dir.record_stage(
                        "binary-review",
                        "failed",
                        project_type=project_type,
                        reason=reason,
                        capabilities=["binary"],
                    )
            ctx.scans.append(tscan)
            _stage(
                ctx,
                "licenses",
                pipeline.stage_analysis_licenses,
                ctx,
                tscan,
                project_type=project_type,
                capabilities=["license"],
                skipped_reason="license analysis was not requested",
                record_extra=lambda: {
                    "notAssessed": [tscan.license_not_assessed]
                    if tscan.license_not_assessed
                    else []
                },
            )
            _stage(
                ctx,
                "risk",
                pipeline.stage_analysis_risk,
                ctx,
                tscan,
                project_type=project_type,
                skipped_reason="the supply-chain audit was not requested",
                failed_reason=lambda: tscan.risk_error,
                not_assessed_reason=lambda: tscan.risk_not_assessed,
                record_extra=lambda: {
                    "notAssessed": list(tscan.audit_caveats),
                    "outputs": [
                        output
                        for outputs in (
                            _relative_output(ctx, path) for path in tscan.audit_output_files
                        )
                        for output in outputs
                    ]
                },
            )
            pipeline.announce_scan_targets(ctx, tscan)
            _stage(
                ctx,
                "enrichment",
                pipeline.stage_enrichment,
                ctx,
                tscan,
                project_type=project_type,
                capabilities=["reachability"],
                outputs=_evidence_output(),
                skipped=bool(options.reachability_analyzer == "off"),
                skipped_reason="reachability analysis is off",
                record_extra=lambda: {"analyzers": _analyzer_entries(ctx, tscan)},
            )
            _stage(
                ctx,
                "matching",
                pipeline.stage_matching,
                ctx,
                tscan,
                project_type=project_type,
                capabilities=["vulnerabilities"],
                record_extra=lambda: {"notAssessed": _matching_not_assessed(tscan)},
            )
            _stage(
                ctx,
                "vdr",
                pipeline.stage_analysis_vdr,
                ctx,
                tscan,
                project_type=project_type,
                record_extra=lambda: {"outputs": _vdr_outputs(ctx, tscan)},
            )
            if render:
                _stage(
                    ctx,
                    "explain",
                    pipeline.stage_render_explain,
                    ctx,
                    tscan,
                    project_type=project_type,
                    skipped=bool(not options.explain),
                    skipped_reason="the explanation was not requested",
                    record_extra=lambda: {
                        "notAssessed": [tscan.explain_not_assessed]
                        if tscan.explain_not_assessed
                        else []
                    },
                )
        if render:
            _stage(ctx, "render", pipeline.stage_render_reports, ctx)
    except BaseException as exc:
        # The manifest of a scan that stopped partway names the failed stage
        # and carries the files written before it. Writing it must not hide
        # the error that stopped the scan.
        try:
            pipeline.finish_scan_directory(ctx)
        except Exception as write_exc:  # noqa: BLE001 - the original error wins
            LOG.error("The scan directory manifest could not be written: %s", write_exc)
        if isinstance(exc, pipeline.ScanStageError):
            raise ScanError(str(exc) or "The scan stopped early.") from exc
        raise
    written = pipeline.finish_scan_directory(ctx) if write_scan_dir else None
    result = _result_from_context(ctx)
    if written is not None:
        result.manifest = written.get("manifest")
        result.findings = written.get("findings") or []
    return result


def _stage(
    ctx,
    name,
    func,
    *args,
    project_type=None,
    capabilities=(),
    analyzers=None,
    outputs=None,
    skipped=False,
    skipped_reason=None,
    record_extra=None,
    failed_reason=None,
    not_assessed_reason=None,
):
    """Run one stage and record what it did in the scan directory's manifest.

    ``skipped`` marks a stage whose conditions were not met, and a stage
    that returns False after producing nothing is recorded the same way with
    the same reason. A stage that stops the scan is recorded as failed with
    the reason it logged, and the error moves on to the caller, which writes
    the manifest before re-raising.

    ``record_extra`` is called at record time so a stage can add fields that
    are only known once it has run, for example the inventory stage's
    not-assessed reasons. ``failed_reason`` is called after a stage that
    degrades instead of stopping the scan; a reason it returns records the
    stage as failed while the scan goes on. ``not_assessed_reason`` is called
    after a stage that returns False; a reason it returns records the stage
    as not assessed: the work was requested but nothing in the scan could be
    analysed by it.
    """
    scan_dir = ctx.scan_dir
    if scan_dir is None:
        return func(*args)

    def record(status, reason=None):
        # record_extra may override any field, for a value that is only
        # known once the stage has run.
        kwargs = {
            "project_type": project_type,
            "reason": reason,
            "capabilities": list(capabilities),
            "analyzers": analyzers,
            "outputs": outputs,
        }
        kwargs.update(record_extra() if record_extra else {})
        scan_dir.record_stage(name, status, **kwargs)

    try:
        result = func(*args)
    except BaseException as exc:
        record("failed", str(exc) or f"the stage stopped the scan ({type(exc).__name__})")
        raise
    degraded = failed_reason() if failed_reason else None
    unassessed = not_assessed_reason() if not_assessed_reason and result is False else None
    if degraded:
        record("failed", degraded)
    elif unassessed:
        record("not-assessed", unassessed)
    elif result is False or skipped:
        record("skipped", skipped_reason or "the stage had nothing to do")
    else:
        record("completed")
    return result


def _record_checks_not_assessed(ctx, checks_not_assessed):
    """Record the checks a caller turned off as manifest stage entries.

    Each entry becomes a ``check-<name>`` stage with status ``not-assessed``,
    the caller's reason and the capability named, so the manifest shows the
    check was considered and refused rather than silently absent. A scan that
    writes no scan directory (the server path) records nothing; it passes no
    entries anyway.
    """
    if not checks_not_assessed or ctx.scan_dir is None:
        return
    for entry in checks_not_assessed:
        name = str(entry.get("name") or "")
        if not name:
            continue
        ctx.scan_dir.record_stage(
            f"check-{name}",
            "not-assessed",
            reason=entry.get("reason"),
            capabilities=[name],
        )


def _analyzer_entries(ctx, tscan):
    """The enrichment stage's analyzer entries, from the adapters' results."""
    options = tscan.reachability_options
    if options is None:
        # Reachability was off, so the stage is recorded as skipped and no
        # analyzer had anything to contribute.
        return []
    return scan_directory.analyzer_entries(
        ctx.doctor_report, [tscan.project_type], tscan.adapter_results
    )


def _matching_not_assessed(tscan):
    """The not-assessed lines the matching stage's manifest entry carries.

    The usage records whose components the scan did not load graded
    nothing, and the database rows that name no component are left out of
    the VDR and the findings; the counts say so on the entry, so neither is
    dropped silently."""
    lines = []
    if tscan.ungraded_usage_records:
        lines.append(
            f"{tscan.ungraded_usage_records} cdxgen usage records grade nothing: "
            "their components are not in the loaded package list"
        )
    rows = getattr(tscan.vdr_result, "rows_without_component", 0) or 0
    if rows:
        lines.append(
            f"{rows} vulnerability rows named no component and are not in the VDR or the findings"
        )
    return lines


def _inventory_capabilities(options, project_type: str) -> List[str]:
    """The capabilities the inventory stage's analyzer runs consult.

    The BOM generation step looks these up through the doctor table before
    running a reachability analyzer, and the entry names the same
    capabilities. A scan given a BOM or a BOM directory generates no BOM and
    runs no analyzer, so it consults nothing.
    """
    if options.bom or options.bom_dir or options.search_purl:
        return []
    from depscan.lib.bom import reachability_analyzers_for_types

    analyzers = reachability_analyzers_for_types([project_type])
    return [
        doctor_lib.ANALYZER_CAPABILITIES[name]
        for name in analyzers
        if name != "atom" and name in doctor_lib.ANALYZER_CAPABILITIES
    ]


def _evidence_output():
    """The enrichment stage's evidence output entry.

    The stage always writes the store, even empty, so the layout is uniform.
    """
    return [{"file": scan_directory.EVIDENCE_FILE, "status": "completed"}]


def _relative_output(ctx, path):
    """A file inside the scan directory as a completed stage output, or no
    output for a file elsewhere (another drive on Windows included); those
    keep their place and the manifest's inputs record them."""
    if not (path and ctx.reports_dir and os.path.isfile(path)):
        return []
    absolute_reports = os.path.abspath(ctx.reports_dir)
    if not os.path.abspath(path).startswith(absolute_reports + os.sep):
        return []
    relative = os.path.relpath(path, ctx.reports_dir).replace(os.sep, "/")
    return [{"file": relative, "status": "completed"}]


def _inventory_outputs(ctx, tscan):
    """The BOM documents a type's inventory stage produced, as stage outputs.

    A scan that generated its documents lists every one the generator wrote
    inside the scan directory, a lifecycle run's per-stage documents
    included, so the outputs name what actually landed on disk. A scan
    handed its BOMs as input (a BOM file or BOM directory target) names only
    the single document it settled on, and only when that lives in the scan
    directory: its other documents are inputs, not outputs.
    """
    args = ctx.args
    generated = not (
        getattr(args, "search_purl", None) or getattr(args, "bom", None) or ctx.bom_dir_mode
    )
    if generated:
        outputs = []
        for path in tscan.bom_files or []:
            outputs.extend(_relative_output(ctx, path))
        return outputs
    return _relative_output(ctx, tscan.bom_file)


def _vdr_outputs(ctx, tscan):
    """The VDR file a type's analysis stage wrote, as a stage output.

    Recorded when the stage has run, so the manifest maps the file to the
    project type that produced it, which the file name alone does not always
    carry. The VDR is always written into the reports directory.
    """
    return _relative_output(ctx, tscan.vdr_file)


def _result_from_context(ctx) -> ScanResult:
    """Build the public result from a finished scan context."""
    types = []
    for tscan in ctx.scans:
        vulnerabilities: List[Dict[str, Any]] = []
        vdr_result = tscan.vdr_result
        if (
            vdr_result is not None
            and vdr_result.success
            and vdr_result.pkg_vulnerabilities is not None
        ):
            # The VDR writer serialises this very list, so the in-memory
            # objects are what the VDR file carries.
            vulnerabilities = list(vdr_result.pkg_vulnerabilities)
        types.append(
            TypeScanResult(
                project_type=tscan.project_type,
                bom_file=tscan.bom_file,
                vdr_file=tscan.vdr_file
                if tscan.vdr_file and os.path.isfile(tscan.vdr_file)
                else None,
                vulnerabilities=vulnerabilities,
            )
        )
    return ScanResult(
        reports_dir=ctx.reports_dir,
        project_types=list(ctx.project_types),
        types=types,
    )


def load_scan(reports_dir: str) -> ScanResult:
    """Rebuild a :class:`ScanResult` from a reports directory of a scan.

    Two layouts are read, and the manifest decides which path runs. When the
    directory carries ``depscan.manifest.json``, the manifest-backed path
    runs: the project types, the files and the stage results come from the
    manifest, the vulnerabilities from the VDR files it lists, and the
    findings from ``depscan.findings.json``. A scan of this version always
    takes this path. A manifest whose layout major this dep-scan does not
    know is refused with an error naming both versions, and a manifest that
    shows the matching stage did not complete is refused too, so a skipped
    or failed scan never loads as one with no vulnerabilities. A
    manifest-backed scan that found no vulnerabilities loads as a result
    with none, because the manifest shows matching completed.

    Without a manifest, the older layout path runs, and the directory is
    read exactly as versions before the scan directory read it: every JSON
    file directly in the directory that is a CycloneDX document carrying a
    ``vulnerabilities`` array is treated as a VDR written by :func:`scan`
    (the VDR names are the BOM name with ``.cdx.json`` replaced by
    ``.vdr.json``, the BOM name itself when it does not end in
    ``.cdx.json``, and ``depscan-universal.vdr.json`` for a BOM directory
    scan). The BOM file of a type is the sibling ``<stem>.cdx.json`` when it
    exists; a ``--bom`` scan keeps its input BOM wherever the caller passed
    it, so no BOM file is recorded for it. The project type is
    ``sbom-<type>``'s type for generated BOMs, ``bom`` for the BOM directory
    VDR, and otherwise the file stem, which is the best those file names
    carry. Such a directory cannot hold the scan of a clean project, because
    those scans wrote no VDR.

    :param reports_dir: A scan directory written by :func:`scan`.
    :returns: The rebuilt result, carrying the manifest and findings when
        the manifest path ran.
    :raises ScanError: When the directory cannot be read as a scan: no VDR
        file was found, the layout version is not supported, or the manifest
        shows matching did not complete. An empty result is never returned
        in place of a missing one.
    """
    reports_dir = str(reports_dir)
    if not os.path.isdir(reports_dir):
        raise ScanError(f"Cannot load a scan from '{reports_dir}': the directory does not exist.")
    manifest = scan_directory.read_manifest(reports_dir)
    if manifest is not None:
        return _load_manifest_scan(reports_dir, manifest)
    return _load_vdr_scan(reports_dir)


def _manifest_output(reports_dir: str, relative: str) -> str:
    """A manifest output's path, refused when it leads out of the scan."""
    try:
        return scan_directory.output_path(reports_dir, relative)
    except ValueError as exc:
        raise ScanError(f"Cannot load a scan from '{reports_dir}': {exc}") from exc


def _load_manifest_scan(reports_dir: str, manifest: Dict[str, Any]) -> ScanResult:
    """Read a scan directory that carries a manifest.

    The manifest lists the files; the VDR and BOM entries of it name what
    each project type produced. This is the path every scan of this version
    loads through.
    """
    try:
        scan_directory.check_layout_version(manifest)
    except ValueError as exc:
        raise ScanError(str(exc)) from exc
    assessed = scan_directory.matching_completed_types(manifest)
    if not assessed:
        raise ScanError(
            f"Cannot load a scan from '{reports_dir}': the manifest shows "
            "the matching stage did not complete, so the directory holds no "
            "assessed vulnerability result."
        )
    by_type: Dict[str, TypeScanResult] = {}
    order: List[str] = []
    for project_type, relative in scan_directory.stage_outputs(manifest, "inventory"):
        if project_type not in assessed:
            continue
        path = _manifest_output(reports_dir, relative)
        if os.path.isfile(path):
            by_type[project_type] = TypeScanResult(project_type=project_type, bom_file=path)
            if project_type not in order:
                order.append(project_type)
    outside = scan_directory.stage_outputs(manifest, "vdr", status="not-assessed")
    if outside:
        raise ScanError(
            f"Cannot load a scan from '{reports_dir}': the VDR file "
            f"'{outside[0][1]}' was written outside the scan directory."
        )
    for project_type, relative in scan_directory.stage_outputs(manifest, "vdr"):
        path = _manifest_output(reports_dir, relative)
        if not os.path.isfile(path):
            raise ScanError(
                f"Cannot load a scan from '{reports_dir}': the manifest "
                f"lists the VDR file '{relative}', which does not exist."
            )
        data = json_load(path)
        if not (
            isinstance(data, dict)
            and data.get("bomFormat") == "CycloneDX"
            and "vulnerabilities" in data
        ):
            raise ScanError(
                f"Cannot load a scan from '{reports_dir}': the manifest "
                f"lists '{relative}' as a VDR, but it is not a CycloneDX "
                "document with vulnerabilities."
            )
        filename = relative.rsplit("/", 1)[-1]
        stem = (
            filename[: -len(".vdr.json")]
            if filename.endswith(".vdr.json")
            else filename[: -len(".json")]
        )
        project_type = project_type or _type_from_vdr_name(filename, stem)
        if project_type in by_type and by_type[project_type].vdr_file:
            raise ScanError(
                f"Cannot load a scan from '{reports_dir}': the manifest "
                f"lists two VDR files for project type '{project_type}'."
            )
        existing = by_type.get(project_type)
        by_type[project_type] = TypeScanResult(
            project_type=project_type,
            bom_file=existing.bom_file if existing else None,
            vdr_file=path,
            vulnerabilities=list(data.get("vulnerabilities") or []),
        )
        if project_type not in order:
            order.append(project_type)
    # Types whose scan found no vulnerabilities wrote no VDR; the manifest
    # showing their matching completed is what makes them loadable as
    # empty. A type whose matching did not complete is listed in
    # project_types, as a scan lists a type it skipped, but gets no result.
    for project_type in assessed:
        if project_type not in by_type:
            by_type[project_type] = TypeScanResult(project_type=project_type)
            order.append(project_type)
    types = [by_type[project_type] for project_type in order if project_type in by_type]
    all_types = scan_directory.project_types(manifest)
    try:
        findings_document = scan_directory.read_findings(reports_dir)
    except ValueError as exc:
        raise ScanError(f"Cannot load a scan from '{reports_dir}': {exc}") from exc
    return ScanResult(
        reports_dir=reports_dir,
        project_types=all_types + [t for t in order if t not in all_types],
        types=types,
        manifest=manifest,
        findings=(findings_document or {}).get("findings") or [],
        findings_version=(findings_document or {}).get("schemaVersion"),
    )


def _load_vdr_scan(reports_dir: str) -> ScanResult:
    """Read a directory without a manifest, the way older scans wrote them.

    This is the layout path: the VDR files are recognised by name and
    content, and nothing else is known about the scan that wrote them.
    """
    types = []
    for entry in sorted(os.listdir(reports_dir)):
        # Slices files can be large and are never VDRs.
        if not entry.endswith(".json") or entry.endswith(".slices.json"):
            continue
        path = os.path.join(reports_dir, entry)
        if not os.path.isfile(path):
            continue
        data = json_load(path)
        if not (
            isinstance(data, dict)
            and data.get("bomFormat") == "CycloneDX"
            and "vulnerabilities" in data
        ):
            continue
        stem = (
            entry[: -len(".vdr.json")] if entry.endswith(".vdr.json") else entry[: -len(".json")]
        )
        bom_file = os.path.join(reports_dir, f"{stem}.cdx.json")
        types.append(
            TypeScanResult(
                project_type=_type_from_vdr_name(entry, stem),
                bom_file=bom_file if os.path.isfile(bom_file) else None,
                vdr_file=path,
                vulnerabilities=list(data.get("vulnerabilities") or []),
            )
        )
    if not types:
        raise ScanError(
            f"Cannot load a scan from '{reports_dir}': no VDR file was found. "
            "A scan writes VDR files such as 'depscan-universal.vdr.json' or "
            "'<bom>.vdr.json' into its reports directory; single-purl scans "
            "write none."
        )
    return ScanResult(
        reports_dir=reports_dir,
        project_types=[tscan.project_type for tscan in types],
        types=types,
    )


def _type_from_vdr_name(filename: str, stem: str) -> str:
    """Recover the project type from a VDR file name, as far as it carries one."""
    if filename == DEPSCAN_DEFAULT_VDR_FILE:
        return "bom"
    if stem.startswith("sbom-"):
        return stem[len("sbom-") :]
    return stem


def query(
    result: ScanResult,
    *,
    purl: Optional[str] = None,
    vuln_id: Optional[str] = None,
    severities=None,
) -> List[Dict[str, Any]]:
    """Return the vulnerabilities of a result that match every given filter.

    ``purl`` matches a vulnerability whose ``affects`` refers to that package
    URL; a purl without a version matches every version, and the comparison
    follows purl semantics (``pkg:npm/@babel/core`` and
    ``pkg:npm/%40babel/core`` are the same package). ``vuln_id`` matches the
    vulnerability ``id`` or an id under ``references``, ignoring case.
    ``severities`` is a CycloneDX severity name or a set of them
    (``critical``, ``high``, ``medium``, ``low``, ``info``, ``none``,
    ``unknown``) matched against the vulnerability's highest rating: the most
    severe rating, and of those the one with the greatest score. A
    vulnerability without ratings matches no severity filter, and an empty
    set raises ``ValueError``.

    When ``purl`` carries qualifiers or a subpath, the affected ref must carry
    the same ones; a ``purl`` without them matches any.

    :param result: A result from :func:`scan` or :func:`load_scan`.
    :param purl: Package URL to match, with or without version.
    :param vuln_id: Vulnerability id to match, ignoring case.
    :param severities: A severity name or names to match against the highest
        rating.
    :returns: The matching VDR vulnerability objects, in result order.
    """
    wanted_purl_obj = parse_purl(purl) if purl else None
    if isinstance(severities, str):
        severities = {severities}
    wanted_severities = None
    if severities is not None:
        wanted_severities = {str(name).strip().lower() for name in severities}
        if not wanted_severities:
            raise ValueError("severities is empty; pass None to match every severity.")
    matches = []
    for tscan in result.types:
        for vuln in tscan.vulnerabilities:
            if purl and not _affects_purl(vuln, purl, wanted_purl_obj):
                continue
            if vuln_id and not _matches_vuln_id(vuln, vuln_id):
                continue
            if wanted_severities is not None and not _matches_severities(vuln, wanted_severities):
                continue
            matches.append(vuln)
    return matches


def _affects_purl(vuln, wanted_purl: str, wanted_purl_obj) -> bool:
    """Tell whether one of the vulnerability's ``affects`` refs is the purl."""
    for affect in vuln.get("affects") or []:
        if not isinstance(affect, dict):
            continue
        ref = affect.get("ref")
        if not isinstance(ref, str) or not ref:
            continue
        if ref == wanted_purl:
            return True
        ref_obj = parse_purl(ref)
        if not ref_obj or not wanted_purl_obj:
            continue
        identity = (
            str(ref_obj.get("type") or "").lower(),
            ref_obj.get("namespace"),
            ref_obj.get("name"),
        )
        wanted_identity = (
            str(wanted_purl_obj.get("type") or "").lower(),
            wanted_purl_obj.get("namespace"),
            wanted_purl_obj.get("name"),
        )
        if identity != wanted_identity:
            continue
        # A purl without a version matches every version of the package.
        if wanted_purl_obj.get("version") is not None and ref_obj.get(
            "version"
        ) != wanted_purl_obj.get("version"):
            continue
        wanted_qualifiers = wanted_purl_obj.get("qualifiers") or {}
        ref_qualifiers = ref_obj.get("qualifiers") or {}
        if any(ref_qualifiers.get(k) != v for k, v in wanted_qualifiers.items()):
            continue
        if wanted_purl_obj.get("subpath") and ref_obj.get("subpath") != wanted_purl_obj.get(
            "subpath"
        ):
            continue
        return True
    return False


def _matches_vuln_id(vuln, vuln_id: str) -> bool:
    """Match the vulnerability id or a reference id, ignoring case."""
    wanted = str(vuln_id).strip().lower()
    if str(vuln.get("id") or "").strip().lower() == wanted:
        return True
    for reference in vuln.get("references") or []:
        if (
            isinstance(reference, dict)
            and str(reference.get("id") or "").strip().lower() == wanted
        ):
            return True
    return False


# CycloneDX severity names, most severe first.
_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info", "none", "unknown")


def _severity_rank(name: str) -> int:
    return _SEVERITY_ORDER.index(name) if name in _SEVERITY_ORDER else len(_SEVERITY_ORDER)


def _highest_rating(vuln) -> Optional[Dict[str, Any]]:
    """Return the most severe rating, the greatest score among equals.

    A rating without a numeric score ranks below a scored one of the same
    severity.
    """
    best = None
    best_key = None
    for rating in vuln.get("ratings") or []:
        if not isinstance(rating, dict):
            continue
        score = rating.get("score")
        numeric = (
            score if isinstance(score, (int, float)) and not isinstance(score, bool) else None
        )
        severity = str(rating.get("severity") or "").strip().lower()
        key = (
            -_severity_rank(severity),
            numeric is not None,
            numeric if numeric is not None else -1.0,
        )
        if best_key is None or key > best_key:
            best, best_key = rating, key
    return best


def _matches_severities(vuln, wanted_severities) -> bool:
    rating = _highest_rating(vuln)
    if rating is None:
        return False
    return str(rating.get("severity") or "").strip().lower() in wanted_severities


def explain(result: ScanResult, *, mode: str = "EndpointsAndReachables", prompts_file=None) -> str:
    """Run the explanation of the ``--explain`` rendering and return its text.

    The explanation runs for every project type of the result, reading the
    evidence store and the OpenAPI specifications from
    ``result.reports_dir`` (the in-scan ``--explain`` rendering reads the
    same store; a scan result records only the reports directory). The endpoint reachability maps the
    in-scan explanation uses are not persisted, so flows render without the
    endpoint markers. ``prompts_file`` receives the LLM prompts in the
    ``LLMPrompts`` mode, exactly as the ``--explain`` rendering writes them.

    The text is captured from the console the explainer renders on, with
    colour codes stripped, so it is the same content the CLI prints.

    :param result: A result from :func:`scan` or :func:`load_scan`.
    :param mode: One of the ``--explanation-mode`` values.
    :param prompts_file: File the ``LLMPrompts`` mode writes its prompts to.
    :returns: The rendered explanation.
    :raises ScanError: When the explanation would be empty; the message names
        what is missing. An empty explanation is never returned as if there
        were nothing to explain.
    """
    texts = []
    for tscan in result.types:
        # The explainer reads these three attributes of the analyzer result;
        # the reachability maps are not written to disk today.
        vdr_result = SimpleNamespace(
            pkg_vulnerabilities=tscan.vulnerabilities,
            endpoint_reached_purls={},
            reached_services={},
        )
        was_quiet = console.quiet
        console.quiet = False
        console.begin_capture()
        try:
            explainer.explain(
                tscan.project_type,
                result.reports_dir,
                result.reports_dir,
                tscan.vdr_file,
                vdr_result,
                mode,
                prompts_file,
            )
        finally:
            text = console.end_capture()
            console.quiet = was_quiet
        texts.append(text)
    combined = "\n".join(texts)
    if not combined.strip():
        raise ScanError(_explain_missing_message(result, mode))
    return _ANSI_RE.sub("", combined)


# Style escapes the captured console render carries when colours are on.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _explain_missing_message(result: ScanResult, mode: str) -> str:
    """Name what an empty explanation is missing, based on its mode."""
    reports_dir = result.reports_dir
    store = os.path.join(str(reports_dir), scan_directory.EVIDENCE_FILE)
    specs = glob.glob(os.path.join(str(reports_dir), "*openapi*.json"))
    if mode == "Endpoints":
        if not specs:
            return (
                f"The explanation for mode '{mode}' produced no output: no "
                f"OpenAPI specification (*openapi*.json) was found under "
                f"'{reports_dir}'. Generate one with cdxgen --spec and re-run."
            )
    elif not os.path.isfile(store):
        return (
            f"The explanation for mode '{mode}' produced no output: no "
            f"evidence store ({scan_directory.EVIDENCE_FILE}) was found "
            f"under '{reports_dir}'. Run a reachability analysis with this "
            "version, which writes the store, and re-run."
        )
    return (
        f"The explanation for mode '{mode}' produced no output: the inputs "
        f"under '{reports_dir}' were read but no evidence record met the "
        "rendering gates, so there is nothing to explain at this fidelity."
    )


def diff(old: ScanResult, new: ScanResult) -> ScanDiff:
    """Compare two scan results by (vulnerability id, affected ref).

    Every vulnerability is keyed by the pair of its ``id`` and the ``ref`` of
    each of its ``affects`` entries (``(id, None)`` when it names no affected
    ref), so an advisory affecting two components gives two pairs. A pair
    only in ``new`` goes to :attr:`ScanDiff.new`, a pair only in ``old`` to
    :attr:`ScanDiff.fixed`, and a pair on both sides whose highest rating
    differs in severity or score to :attr:`ScanDiff.changed`. An advisory
    that stops affecting one of two components therefore shows one fixed
    entry for that component and nothing for the other.

    :param old: The earlier result.
    :param new: The later result.
    :returns: The :class:`ScanDiff` between the two results.
    """
    old_map = _vulns_by_key(old)
    new_map = _vulns_by_key(new)
    result = ScanDiff()
    for key, vuln in new_map.items():
        previous = old_map.get(key)
        if previous is None:
            result.new.append(DiffEntry(id=key[0], ref=key[1], new=vuln))
        elif _rating_signature(vuln) != _rating_signature(previous):
            result.changed.append(DiffEntry(id=key[0], ref=key[1], old=previous, new=vuln))
    for key, vuln in old_map.items():
        if key not in new_map:
            result.fixed.append(DiffEntry(id=key[0], ref=key[1], old=vuln))
    return result


def _vulns_by_key(result: ScanResult) -> Dict[Tuple[str, Optional[str]], Dict[str, Any]]:
    """Map every (id, affects ref) key of a result to its vulnerability."""
    vuln_map: Dict[Tuple[str, Optional[str]], Dict[str, Any]] = {}
    for vuln in result.vulnerabilities:
        vuln_id = str(vuln.get("id") or "")
        refs = [
            affect.get("ref")
            for affect in vuln.get("affects") or []
            if isinstance(affect, dict) and affect.get("ref")
        ]
        for ref in refs or [None]:
            vuln_map.setdefault((vuln_id, ref), vuln)
    return vuln_map


def _rating_signature(vuln) -> Tuple[str, Any]:
    """The (severity, score) of the highest rating, its change detector."""
    rating = _highest_rating(vuln) or {}
    severity = str(rating.get("severity") or "").strip().lower()
    score = rating.get("score")
    return (severity, score if isinstance(score, (int, float)) else None)
