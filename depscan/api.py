"""The public Python API for running and inspecting dep-scan scans.

``scan`` runs the same stage pipeline the ``depscan`` command runs, in the
same order, and returns a :class:`ScanResult` instead of exiting the process.
``load_scan`` rebuilds a result from a reports directory a scan wrote,
``query`` filters the vulnerabilities of a result, ``explain`` returns the
text the ``--explain`` rendering produces and ``diff` compares two results.

The CLI (``depscan.cli.run_depscan``) and the depscan server call these
functions; they do not drive the pipeline directly. This module imports from
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
from depscan.lib import explainer, pipeline
from depscan.lib.config import DEPSCAN_DEFAULT_VDR_FILE
from depscan.lib.logger import console

__all__ = [
    "ScanDiff",
    "ScanError",
    "ScanResult",
    "TypeScanResult",
    "diff",
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
    results, in scan order.
    """

    reports_dir: str
    project_types: List[str] = field(default_factory=list)
    types: List[TypeScanResult] = field(default_factory=list)

    @property
    def vulnerabilities(self) -> List[Dict[str, Any]]:
        """Every vulnerability of every type, in type then write order."""
        return [vuln for tscan in self.types for vuln in tscan.vulnerabilities]


@dataclass
class ScanDiff:
    """The difference between two scan results.

    ``new`` holds the vulnerability objects whose key exists only in the new
    result, ``fixed`` those only in the old one. ``changed`` holds
    ``(old, new)`` pairs of the same vulnerability whose highest severity or
    score differs. See :func:`diff` for the key.
    """

    new: List[Dict[str, Any]] = field(default_factory=list)
    fixed: List[Dict[str, Any]] = field(default_factory=list)
    changed: List[Tuple[Dict[str, Any], Dict[str, Any]]] = field(default_factory=list)


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


def scan(options, *, render: bool = True) -> ScanResult:
    """Run a scan with the given options and return its result.

    This runs the stages the ``depscan`` command runs, in the same order,
    including the console, quiet and debug handling of the CLI, and writes
    the same files to ``options.reports_dir``: the BOM documents, the VDR
    files, the license and risk reports and ``depscan.toml.sample``.

    With ``render=False`` the rendering is skipped (the console tables, the
    HTML and text reports, the template report, the explanation and the CSAF
    export, which all live in the rendering stages); everything the other
    stages write, the VDR and BOM files included, is still written. Skipping
    the console tables forces ``no_vuln_table`` on the given options, because
    the tables are part of the rendering.

    :param options: An ``argparse.Namespace`` from the CLI parser or from
        :func:`scan_options`.
    :param render: Render the console and report output (the default).
    :returns: The :class:`ScanResult` of the scan.
    :raises ScanError: When a stage stops the scan, with the message the
        stage logged. The function never calls ``sys.exit`` and never
        returns a result in place of a stopped scan.
    """
    if not render:
        options.no_vuln_table = True
    ctx = pipeline.build_context(options)
    pipeline.configure_output(ctx)
    try:
        # We have everything needed to start the composition analysis. There are many approaches to implementing an SCA tool.
        # Our style of analysis is comparable to that of an intelligent Hubble telescope or a rover—examining the same subject through multiple optics, colors, and depths to gain a deeper understanding.
        # We begin by iterating over the project types provided or assumed.
        pipeline.stage_setup(ctx)
        pipeline.stage_database(ctx)
        pipeline.finalize_setup(ctx)
        for project_type in ctx.project_types:
            tscan = pipeline.TypeScan(project_type=project_type)
            if not pipeline.stage_inventory(ctx, tscan):
                continue
            ctx.scans.append(tscan)
            pipeline.stage_analysis_licenses(ctx, tscan)
            pipeline.stage_analysis_risk(ctx, tscan)
            pipeline.announce_scan_targets(ctx, tscan)
            pipeline.stage_enrichment(ctx, tscan)
            pipeline.stage_matching(ctx, tscan)
            pipeline.stage_analysis_vdr(ctx, tscan)
            if render:
                pipeline.stage_render_explain(ctx, tscan)
        if render:
            pipeline.stage_render_reports(ctx)
    except pipeline.ScanStageError as exc:
        raise ScanError(str(exc) or "The scan stopped early.") from exc
    return _result_from_context(ctx)


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
                vdr_file=tscan.vdr_file,
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

    Today's layout is read, nothing else: every JSON file directly in the
    directory that is a CycloneDX document carrying a ``vulnerabilities``
    array is treated as a VDR written by :func:`scan` (the VDR names are the
    BOM name with ``.cdx.json`` replaced by ``.vdr.json``, the BOM name
    itself when it does not end in ``.cdx.json``, and
    ``depscan-universal.vdr.json`` for a BOM directory scan). The BOM file of
    a type is the sibling ``<stem>.cdx.json`` when it exists; a ``--bom``
    scan keeps its input BOM wherever the caller passed it, so no BOM file is
    recorded for it. The project type is ``sbom-<type>``'s type for generated
    BOMs, ``bom`` for the BOM directory VDR, and otherwise the file stem,
    which is the best today's file names carry. The scan directory with its
    manifest is a later addition and is not read.

    :param reports_dir: A reports directory written by :func:`scan`.
    :returns: The rebuilt result.
    :raises ScanError: When the directory holds no VDR file. An empty result
        is never returned in place of a missing one.
    """
    reports_dir = str(reports_dir)
    if not os.path.isdir(reports_dir):
        raise ScanError(f"Cannot load a scan from '{reports_dir}': the directory does not exist.")
    types = []
    for entry in sorted(os.listdir(reports_dir)):
        if not entry.endswith(".json"):
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
    ``severities`` is a set of CycloneDX severity names (``critical``,
    ``high``, ``medium``, ``low``, ``info``, ``none``, ``unknown``) matched
    against the vulnerability's highest rating: the rating with the greatest
    score, or the most severe rating when no rating carries a score. A
    vulnerability without ratings matches no severity filter.

    :param result: A result from :func:`scan` or :func:`load_scan`.
    :param purl: Package URL to match, with or without version.
    :param vuln_id: Vulnerability id to match, ignoring case.
    :param severities: Severity names to match against the highest rating.
    :returns: The matching VDR vulnerability objects, in result order.
    """
    wanted_purl_obj = parse_purl(purl) if purl else None
    wanted_severities = {str(name).strip().lower() for name in severities} if severities else None
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
        if wanted_purl_obj.get("version") is None or ref_obj.get("version") == wanted_purl_obj.get(
            "version"
        ):
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
    """Return the rating with the greatest score, most severe on a tie.

    Ratings without a numeric score rank below those with one.
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
            numeric is not None,
            numeric if numeric is not None else -1.0,
            -_severity_rank(severity),
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
    reachables slices and OpenAPI specifications from ``result.reports_dir``
    (the ``--explain`` rendering reads them from the BOM directory, which for
    a ``--bom`` or ``--bom-dir`` scan is where those files live; a scan result
    records only the reports directory). The endpoint reachability maps the
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
    slices = glob.glob(
        os.path.join(str(reports_dir), "**", "*reachables.slices*.json"), recursive=True
    )
    specs = glob.glob(os.path.join(str(reports_dir), "*openapi*.json"))
    if mode == "Endpoints":
        if not specs:
            return (
                f"The explanation for mode '{mode}' produced no output: no "
                f"OpenAPI specification (*openapi*.json) was found under "
                f"'{reports_dir}'. Generate one with cdxgen --spec and re-run."
            )
    elif not slices:
        return (
            f"The explanation for mode '{mode}' produced no output: no "
            f"reachables slices file (*reachables.slices*.json) was found "
            f"under '{reports_dir}'. Run a reachability analysis or copy the "
            "slices file into the reports directory."
        )
    return (
        f"The explanation for mode '{mode}' produced no output: the inputs "
        f"under '{reports_dir}' were read but no flow met the rendering "
        "gates, so there is nothing to explain at this fidelity."
    )


def diff(old: ScanResult, new: ScanResult) -> ScanDiff:
    """Compare two scan results by vulnerability.

    Every vulnerability is keyed by the pair (its ``id``, the ``ref`` of each
    of its ``affects`` entries; a vulnerability naming no affected ref keys on
    ``(id, None)``). A key only in ``new`` goes to :attr:`ScanDiff.new`, a key
    only in ``old`` to :attr:`ScanDiff.fixed`, and a key on both sides whose
    highest severity or score differs to :attr:`ScanDiff.changed` as an
    ``(old, new)`` pair. One vulnerability object appears once per list no
    matter how many components it affects.

    :param old: The earlier result.
    :param new: The later result.
    :returns: The :class:`ScanDiff` between the two results.
    """
    old_map = _vulns_by_key(old)
    new_map = _vulns_by_key(new)
    result = ScanDiff()
    added_new: set = set()
    added_fixed: set = set()
    added_changed: set = set()
    for key, vuln in new_map.items():
        previous = old_map.get(key)
        if previous is None:
            if id(vuln) not in added_new:
                result.new.append(vuln)
                added_new.add(id(vuln))
        elif _rating_signature(vuln) != _rating_signature(previous):
            pair_id = (id(previous), id(vuln))
            if pair_id not in added_changed:
                result.changed.append((previous, vuln))
                added_changed.add(pair_id)
    for key, vuln in old_map.items():
        if key not in new_map and id(vuln) not in added_fixed:
            result.fixed.append(vuln)
            added_fixed.add(id(vuln))
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
