"""The MCP tools: one thin layer per tool over the dep-scan API and the
verb json documents.

Every tool validates its arguments against its published input schema
(``depscan-mcp-<tool>-input``), confines every path it takes with
:mod:`depscan.mcp_server.confinement`, and returns one JSON document that
validates against its published output schema. A tool failure is an
exception; :mod:`depscan.mcp_server.server` turns it into an ``isError``
result whose text names the rule or the input that was refused, so a
failure is never an empty or silent success.

Paths: the scan directories, the run_scan target and the spill files all
resolve, with :func:`os.path.realpath`, inside the effective roots (the
``--allow-dir`` roots the server started with plus the roots the client
announced). The effective roots are read from the request context through
:func:`depscan.mcp_server.server.effective_roots_for` on every call, so a
client that widens or narrows its roots mid-session is honoured on the
next request.

Response budget: a result may carry at most 32 KB of JSON, measured on the
compact serialization of the whole document. The list tools
(``list_findings``, ``list_components``) page first, with the ``cursor``
and ``limit`` arguments; a page that is still over the budget is written
with ``indent=2`` to ``<scan-dir>/mcp/<tool>-<sha256 of the canonical
arguments>.json`` and the tool returns the file path and the item count
instead. The single-document tools spill the same way when a scan
directory is known; ``doctor``, ``vdb_status`` and the run_scan dry run
have none, so an oversized result there is a tool error naming the budget.
The item count of a spilled result is the number of entries the document
carries: the findings or components of a page, the findings a summary
counts, the stages of a coverage report, the diff entries, or one for a
single finding or a scan entry.
"""

import argparse
import base64
import contextlib
import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, NoReturn, Optional, Tuple

from analysis_lib.findings.schemas import SchemaValidationError, load_schema, validate
from mcp import types
from vdb.lib.utils import parse_purl

from depscan import api
from depscan.commands import checks as checks_table
from depscan.commands.config import _option_sources
from depscan.commands.output import json_path
from depscan.commands.scan import (
    _apply_target_options,
    _inventory_skip_requirements,
    _json_target,
    _resolve_targets,
    add_scan_options,
    resolved_namespace,
    scan_namespace,
)
from depscan.commands.targets import detect_kind
from depscan.lib import scan_directory
from depscan.mcp_server import confinement
from depscan.mcp_server import server as server_mod

__all__ = ["ToolError", "TOOL_BUDGET_BYTES", "handle_call_tool", "handle_list_tools"]

#: The response budget of one tool result, in bytes of compact JSON.
TOOL_BUDGET_BYTES = 32 * 1024

#: The page size bounds of the list tools.
DEFAULT_LIMIT = 50
MAX_LIMIT = 200

#: The run_scan target kinds that always name a filesystem path, and are
#: therefore confined. A purl, a git URL and a container image reference
#: are references, not paths, and are handed to the scan machinery as
#: given.
_FILESYSTEM_TARGET_KINDS = ("source", "bom", "bom-dir", "binary", "android")

#: The target kinds that are references most of the time but name a local
#: file or directory when one exists: an existing tar archive or OCI
#: layout directory is a container target, an existing .ipa file an ios
#: target, and both are paths the scan reads, so they confine like any
#: other path. A reference that names no local file is not confined.
_PATH_WHEN_EXISTS_TARGET_KINDS = ("container", "ios")

#: The exploitability reach values that mean a finding is reachable, and
#: those that mean it is not. ``unknown`` and ``not_assessed`` record no
#: reachability and match neither value of the ``reachable`` filter.
_REACHABLE_REACH_VALUES = ("proven", "likely")
_UNREACHABLE_REACH_VALUES = ("unlikely", "refuted")


class ToolError(ValueError):
    """A tool call that cannot be served.

    The message is what the client shows: it names the refused input, the
    confinement rule, or the missing file, never an empty result in its
    place.
    """


@dataclass(frozen=True)
class ToolSpec:
    """One tool: its name, its description and its input schema name.

    ``run`` takes the validated arguments, the effective roots and the
    ``allow_scans`` startup flag, and returns ``(document, items,
    spill_dir)``: the result document, the entries its item count counts,
    and the directory a spill file may be written into, when one exists.
    """

    name: str
    description: str
    schema_name: str
    run: Callable[..., Tuple[Dict[str, Any], List[Any], Optional[str]]]


def _spec(name: str, description: str, run) -> ToolSpec:
    return ToolSpec(
        name=name,
        description=description,
        schema_name=f"depscan-mcp-{name}-input",
        run=run,
    )


# --- the tool implementations -----------------------------------------------------


def _confined(args: Dict[str, Any], roots: Tuple[str, ...], key: str) -> str:
    """The realpath of the path argument ``key``, inside the roots.

    The confinement error passes through unchanged: its message already
    names the rule that refused the path and lists the roots.
    """
    return confinement.confine(str(args[key]), roots)


def _loaded_scan(scan_dir: str, roots: Tuple[str, ...]) -> api.ScanResult:
    """The scan result of a confined scan directory.

    A directory that cannot be read as a scan is a tool error carrying
    api.load_scan's message, which names the directory and the file or
    manifest entry that was missing. A symlink inside the directory that
    leads out of the roots refuses the whole directory before anything in
    it is read.
    """
    confinement.confine_contents(scan_dir, roots)
    try:
        result = api.load_scan(scan_dir)
    except api.ScanError as exc:
        raise ToolError(str(exc)) from exc
    _check_documents(scan_dir, result)
    return result


def _check_documents(scan_dir: str, result: api.ScanResult) -> None:
    """Refuse a scan whose manifest or findings break their schemas.

    The tools reshape these documents into their own outputs, so a
    hand-edited or corrupted manifest or finding would otherwise surface as
    an output that breaks the tool's published schema, or as an attribute
    error, instead of an error naming the file.
    """
    if result.manifest is not None:
        try:
            validate("depscan-manifest", result.manifest)
        except SchemaValidationError as exc:
            raise ToolError(
                f"the manifest of the scan at {json_path(scan_dir)} does not "
                f"satisfy the depscan-manifest schema: {exc}"
            ) from exc
    version = result.findings_version
    if version is not None and str(version) != scan_directory.FINDINGS_SCHEMA_VERSION:
        raise ToolError(
            f"the findings of the scan at {json_path(scan_dir)} use findings "
            f"schema version {version}, and this dep-scan reads version "
            f"{scan_directory.FINDINGS_SCHEMA_VERSION}; scan the project again"
        )
    for index, finding in enumerate(result.findings or []):
        try:
            validate("depscan-finding", finding)
        except SchemaValidationError as exc:
            raise ToolError(
                f"finding {index} of the scan at {json_path(scan_dir)} does "
                f"not satisfy the depscan-finding schema: {exc}"
            ) from exc


def _finding_by_id(result: api.ScanResult, finding_id: str) -> Dict[str, Any]:
    for finding in result.findings:
        if isinstance(finding, dict) and finding.get("id") == finding_id:
            return finding
    raise ToolError(
        f"no finding with id {finding_id!r} in the scan at "
        f"{json_path(result.reports_dir)}; list_findings returns the ids the scan carries"
    )


def _counts(findings: List[Dict[str, Any]], field: str) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for finding in findings:
        value = str(finding.get(field) or "unknown")
        counts[value] = counts.get(value, 0) + 1
    return counts


def _manifest_summary(manifest: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """The manifest's summary, or None for a scan directory without one."""
    if manifest is None:
        return None
    stages = manifest.get("stages") or []
    by_status: Dict[str, int] = {}
    for stage in stages:
        status = str(stage.get("status") or "unknown")
        by_status[status] = by_status.get(status, 0) + 1
    return {
        "layoutVersion": str(manifest.get("layoutVersion") or ""),
        "depscanVersion": str(manifest.get("depscanVersion") or ""),
        "startUtc": manifest.get("startUtc"),
        "endUtc": manifest.get("endUtc"),
        "projectTypes": scan_directory.project_types(manifest),
        "stageCount": len(stages),
        "stagesByStatus": by_status,
        "inputCount": len(manifest.get("inputs") or []),
        "fileCount": len(manifest.get("files") or []),
    }


def scan_summary_tool(args, roots, allow_scans=False, allow_propose=False):
    """The manifest summary, the finding counts and the server's grants of
    one scan directory."""
    scan_dir = _confined(args, roots, "scan_dir")
    result = _loaded_scan(scan_dir, roots)
    findings = [finding for finding in result.findings if isinstance(finding, dict)]
    document = {
        "scanDir": json_path(scan_dir),
        "manifestSummary": _manifest_summary(result.manifest),
        "findingCount": len(findings),
        "countsByCategory": _counts(findings, "category"),
        "countsBySeverity": _counts(findings, "severity"),
        "grants": {"allowScans": bool(allow_scans), "allowPropose": bool(allow_propose)},
    }
    return document, findings, scan_dir


def _reach_of(finding: Dict[str, Any]) -> str:
    """The finding's recorded reach, lowercased; empty when none."""
    exploitability = finding.get("exploitability")
    axes = exploitability.get("axes") if isinstance(exploitability, dict) else None
    if not isinstance(axes, dict):
        return ""
    return str(axes.get("reach") or "").strip().lower()


def _matches_reachable(finding: Dict[str, Any], wanted: bool) -> bool:
    reach = _reach_of(finding)
    if wanted:
        return reach in _REACHABLE_REACH_VALUES
    return reach in _UNREACHABLE_REACH_VALUES


def _grade_of(finding: Dict[str, Any]) -> str:
    """The finding's recorded exploitability grade, lowercased; empty when none."""
    exploitability = finding.get("exploitability")
    if not isinstance(exploitability, dict):
        return ""
    return str(exploitability.get("grade") or "").strip().lower()


def _matches_grade(finding: Dict[str, Any], wanted: List[str]) -> bool:
    return _grade_of(finding) in wanted


def _matches_purl(finding: Dict[str, Any], wanted_purl: str) -> bool:
    """Whether one of the finding's components is the package URL.

    The comparison is api.query's purl matching, applied to the finding's
    ``components``: a purl without a version matches every version, and
    qualifiers and subpaths must match when the wanted purl carries them.
    """
    wanted_obj = parse_purl(wanted_purl)
    affects = [{"ref": component} for component in finding.get("components") or []]
    return api._affects_purl({"affects": affects}, wanted_purl, wanted_obj)


def _filtered_findings(args: Dict[str, Any], findings: List[Dict[str, Any]]):
    """The findings that match every filter the call carried.

    Only the finding schema's fields filter; the input schema refuses any
    other argument name before this runs, so no filter is ever silently
    ignored.
    """
    matched = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        if "category" in args and finding.get("category") != args["category"]:
            continue
        if "severity" in args and finding.get("severity") != args["severity"]:
            continue
        if "purl" in args and not _matches_purl(finding, str(args["purl"])):
            continue
        if "cwe" in args and args["cwe"] not in (finding.get("cwes") or []):
            continue
        if "rule" in args and finding.get("rule") != args["rule"]:
            continue
        if "reachable" in args and not _matches_reachable(finding, bool(args["reachable"])):
            continue
        if "grade" in args and not _matches_grade(finding, [str(g) for g in args["grade"]]):
            continue
        matched.append(finding)
    return matched


def _decode_cursor(cursor: str) -> int:
    """The page offset a cursor carries.

    The cursor is the base64url encoding of ``{"o": <offset>}``; anything
    else is a tool error, so a stale or hand-made cursor is named rather
    than silently read as page zero.
    """
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
        offset = payload["o"]
    except (ValueError, KeyError, TypeError) as exc:
        raise ToolError(
            f"invalid cursor {cursor!r}: the cursor is the base64url "
            "encoding of {'o': <offset>}, as a previous call's nextCursor carried it"
        ) from exc
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise ToolError(f"invalid cursor {cursor!r}: the offset must be a non-negative integer")
    return offset


def _encode_cursor(offset: int) -> str:
    payload = json.dumps({"o": offset}, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def _page_offset(args: Dict[str, Any]) -> int:
    if "cursor" not in args:
        return 0
    return _decode_cursor(str(args["cursor"]))


def _page_limit(args: Dict[str, Any]) -> int:
    limit = args.get("limit", DEFAULT_LIMIT)
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_LIMIT:
        raise ToolError(f"limit must be an integer between 1 and {MAX_LIMIT}; got {limit!r}")
    return limit


def list_findings_tool(args, roots, allow_scans=False, allow_propose=False):
    """One page of the scan's findings, filtered by the finding fields."""
    del allow_scans, allow_propose
    scan_dir = _confined(args, roots, "scan_dir")
    result = _loaded_scan(scan_dir, roots)
    matched = _filtered_findings(
        args, [finding for finding in result.findings if isinstance(finding, dict)]
    )
    limit = _page_limit(args)
    offset = _page_offset(args)
    page = matched[offset : offset + limit]
    document: Dict[str, Any] = {"findings": page}
    if offset + len(page) < len(matched):
        document["nextCursor"] = _encode_cursor(offset + len(page))
    return document, page, scan_dir


def get_finding_tool(args, roots, allow_scans=False, allow_propose=False):
    """One finding of the scan, exactly as the finding schema defines it."""
    del allow_scans, allow_propose
    scan_dir = _confined(args, roots, "scan_dir")
    result = _loaded_scan(scan_dir, roots)
    finding = _finding_by_id(result, str(args["finding_id"]))
    return finding, [finding], scan_dir


def explain_finding_tool(args, roots, allow_scans=False, allow_propose=False):
    """One finding plus the text api.explain renders for the scan.

    The explanation covers the whole scan in this version, whatever the
    finding named; the tool description says so, and so does the output
    schema.
    """
    del allow_scans, allow_propose
    scan_dir = _confined(args, roots, "scan_dir")
    result = _loaded_scan(scan_dir, roots)
    finding = _finding_by_id(result, str(args["finding_id"]))
    mode = str(args.get("mode") or "EndpointsAndReachables")
    try:
        text = api.explain(result, mode=mode)
    except api.ScanError as exc:
        raise ToolError(str(exc)) from exc
    document = {"finding": finding, "explanation": text}
    return document, [finding], scan_dir


def coverage_tool(args, roots, allow_scans=False, allow_propose=False):
    """A scan directory's stages, not-assessed reasons and checks not run."""
    del allow_scans, allow_propose
    scan_dir = _confined(args, roots, "scan_dir")
    result = _loaded_scan(scan_dir, roots)
    manifest = result.manifest
    stages = list((manifest or {}).get("stages") or [])
    not_assessed: List[Dict[str, Any]] = []
    for stage in stages:
        for reason in stage.get("notAssessed") or []:
            not_assessed.append({"stage": str(stage.get("name")), "reason": str(reason)})
        for analyzer in stage.get("analyzers") or []:
            if not isinstance(analyzer, dict) or analyzer.get("status") != "not-assessed":
                continue
            entry: Dict[str, Any] = {
                "stage": str(stage.get("name")),
                "analyzer": str(analyzer.get("name")),
                "reason": str(analyzer.get("reason")),
            }
            not_assessed.append(entry)
    checks_not_run: List[Dict[str, Any]] = []
    for stage in stages:
        name = str(stage.get("name") or "")
        if not name.startswith("check-") or stage.get("status") != "not-assessed":
            continue
        entry = {"name": name[len("check-") :]}
        if stage.get("reason"):
            entry["reason"] = str(stage["reason"])
        checks_not_run.append(entry)
    document = {
        "scanDir": json_path(scan_dir),
        "stages": stages,
        "notAssessedReasons": not_assessed,
        "checksNotRun": checks_not_run,
    }
    return document, stages, scan_dir


def _component_entry(component: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The identity fields of one CycloneDX component, in camelCase.

    A component without a name or a type cannot be represented in the
    published shape and is skipped; a CycloneDX BOM always carries both.
    """
    name = component.get("name")
    comp_type = component.get("type")
    if not name or not comp_type:
        return None
    entry: Dict[str, Any] = {"name": str(name), "type": str(comp_type)}
    if component.get("version"):
        entry["version"] = str(component["version"])
    if component.get("purl"):
        entry["purl"] = str(component["purl"])
    if component.get("bom-ref"):
        entry["bomRef"] = str(component["bom-ref"])
    return entry


def _bom_files(scan_dir: str, result: api.ScanResult) -> List[str]:
    """The BOM files the scan directory records, in scan order.

    The inventory stage's outputs name the BOM each project type settled
    on; a result type's own bom_file covers the older layout, which
    recovers the BOM from the VDR's sibling file name. A scan directory
    that records no BOM is a tool error, never an empty component list.
    """
    paths: List[str] = []
    seen = set()
    for _project_type, relative in scan_directory.stage_outputs(
        result.manifest or {}, "inventory"
    ):
        try:
            path = scan_directory.output_path(scan_dir, relative)
        except ValueError as exc:
            raise ToolError(str(exc)) from exc
        if os.path.isfile(path) and path not in seen:
            seen.add(path)
            paths.append(path)
    for tscan in result.types:
        if tscan.bom_file and os.path.isfile(tscan.bom_file) and tscan.bom_file not in seen:
            seen.add(tscan.bom_file)
            paths.append(tscan.bom_file)
    if not paths:
        raise ToolError(
            f"the scan at {json_path(scan_dir)} records no BOM the "
            "list_components tool could read: no completed inventory stage "
            "output and no BOM file of a scan result"
        )
    return paths


def _bom_components(scan_dir: str, result: api.ScanResult) -> List[Dict[str, Any]]:
    """The BOM components of the scan, in BOM order, deduplicated.

    Every BOM file ``_bom_files`` returns is a document the scan recorded
    as the BOM of one of its project types, so each one must read as a
    CycloneDX document. A file that does not parse, or parses as something
    else, is a tool error naming the file, never a silent skip that would
    read back as a clean component page.
    """
    components: List[Dict[str, Any]] = []
    seen = set()
    for bom_file in _bom_files(scan_dir, result):
        try:
            with open(bom_file, encoding="utf-8") as fp:
                data = json.load(fp)
        except json.JSONDecodeError as exc:
            raise ToolError(
                f"the BOM file at {json_path(bom_file)} is unreadable: it is "
                f"not valid JSON ({exc})"
            ) from exc
        if not (isinstance(data, dict) and data.get("bomFormat") == "CycloneDX"):
            raise ToolError(
                f"the BOM file at {json_path(bom_file)} is unreadable: it is "
                "not a CycloneDX document, so it is not a BOM the scan's "
                "inventory stage settled on"
            )
        for component in data.get("components") or []:
            if not isinstance(component, dict):
                continue
            entry = _component_entry(component)
            if entry is None:
                continue
            key = entry.get("bomRef") or entry.get("purl") or (entry["name"], entry.get("version"))
            if key in seen:
                continue
            seen.add(key)
            components.append(entry)
    return components


def list_components_tool(args, roots, allow_scans=False, allow_propose=False):
    """One page of the scan's BOM components."""
    del allow_scans, allow_propose
    scan_dir = _confined(args, roots, "scan_dir")
    result = _loaded_scan(scan_dir, roots)
    components = _bom_components(scan_dir, result)
    limit = _page_limit(args)
    offset = _page_offset(args)
    page = components[offset : offset + limit]
    document: Dict[str, Any] = {"components": page}
    if offset + len(page) < len(components):
        document["nextCursor"] = _encode_cursor(offset + len(page))
    return document, page, scan_dir


def diff_scans_tool(args, roots, allow_scans=False, allow_propose=False):
    """The new, fixed and changed vulnerability pairs between two scans."""
    del allow_scans, allow_propose
    old_scan_dir = _confined(args, roots, "old_scan_dir")
    new_scan_dir = _confined(args, roots, "new_scan_dir")
    old_result = _loaded_scan(old_scan_dir, roots)
    new_result = _loaded_scan(new_scan_dir, roots)
    diff = api.diff(old_result, new_result)

    def entries(group):
        return [
            {"id": entry.id, "ref": entry.ref, "old": entry.old, "new": entry.new}
            for entry in group
        ]

    document = {
        "new": entries(diff.new),
        "fixed": entries(diff.fixed),
        "changed": entries(diff.changed),
    }
    items = [*document["new"], *document["fixed"], *document["changed"]]
    # An oversized diff spills into the later scan directory, the one a
    # reader of the diff is moving to.
    return document, items, new_scan_dir


def doctor_tool(args, roots, allow_scans=False, allow_propose=False):
    """The doctor report document for this machine."""
    del args, roots, allow_scans
    document = api.doctor().to_dict()
    return document, [document], None


def vdb_status_tool(args, roots, allow_scans=False, allow_propose=False):
    """The vdb info document for this machine."""
    del args, roots, allow_scans
    from depscan import vdb_cli

    document = vdb_cli._info_document(vdb_cli._collect_info())
    return document, [document], None


# --- run_scan ----------------------------------------------------------------------


def _scan_argv(args: Dict[str, Any]) -> List[str]:
    """The ``depscan scan`` argument vector the tool's arguments describe."""
    argv = ["depscan", "scan", str(args["target"])]
    if args.get("reports_dir"):
        argv += ["--reports-dir", str(args["reports_dir"])]
    if args.get("profile"):
        argv += ["--profile", str(args["profile"])]
    if args.get("checks"):
        argv += ["--checks", ",".join(str(check) for check in args["checks"])]
    if args.get("reachability_analyzer"):
        argv += ["--reachability-analyzer", str(args["reachability_analyzer"])]
    if args.get("explain"):
        argv.append("--explain")
    return argv


class _ScanArgsParser(argparse.ArgumentParser):
    """A scan-argument parser whose errors are tool errors, not exits.

    argparse's own error calls ``sys.exit(2)`` after printing the usage,
    and ``SystemExit`` is not an ``Exception``: it would pass through
    ``handle_call_tool``'s isError conversion and the verb's handler and
    stop the whole server process. A target the scan verb itself would
    reject, a dash-leading one most of all, has to fail as a tool error
    that names what did not parse.
    """

    def error(self, message: str) -> NoReturn:
        raise ToolError(
            f"the run_scan target and options do not parse as a depscan "
            f"scan command line: {message}"
        )


def _parsed_scan_args(argv: List[str]) -> argparse.Namespace:
    """The scan verb's parsed namespace for the argv the tool built.

    The same parser the scan verb registers, so the config show machinery
    sees exactly what ``depscan scan`` would have parsed.
    """
    parser = _ScanArgsParser(prog="depscan scan", add_help=False)
    add_scan_options(parser)
    return parser.parse_args(argv[2:])


def _options_document(scan_args: argparse.Namespace) -> Dict[str, Any]:
    """The effective options, as ``depscan config show --format json`` writes them."""
    resolution = checks_table.resolve(scan_args)
    internal, set_by = resolved_namespace(scan_args, resolution)
    return {"options": _option_sources(scan_args, internal, set_by)}


@contextlib.contextmanager
def _run_environment(license_requested: bool):
    """The environment of one real run: secure cdxgen, license only if asked.

    A real run_scan hands cdxgen a caller-chosen target, so cdxgen runs in
    secure mode for the whole run, the way the depscan server path does for
    untrusted sources. The license check turns on through FETCH_LICENSE,
    exactly as the scan verb sets it. The server process outlives the run,
    so both variables are restored afterwards: one run's checks never leak
    into the next call's options.
    """
    saved = {name: os.environ.get(name) for name in ("CDXGEN_SECURE_MODE", "FETCH_LICENSE")}
    os.environ["CDXGEN_SECURE_MODE"] = "true"
    if license_requested:
        os.environ["FETCH_LICENSE"] = "true"
    try:
        yield
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _confined_target(target: str, roots: Tuple[str, ...]) -> str:
    """The target's realpath when it names a filesystem path, inside the roots.

    Every kind the detection classifies as a path must resolve inside the
    roots, in the dry run as well as the real run, because the argv the dry
    run returns is the command the server would run. A purl and a git URL
    are never paths. A container target usually names an image reference,
    but an existing tar archive or OCI layout directory is one too, and an
    ios target is an existing .ipa file, so those confine when the target
    names a local file or directory and pass through as references when it
    does not.
    """
    kind, _reason = detect_kind(target)
    names_a_path = kind in _FILESYSTEM_TARGET_KINDS or (
        kind in _PATH_WHEN_EXISTS_TARGET_KINDS and os.path.exists(target)
    )
    if not names_a_path:
        return target
    return confinement.confine(target, roots)


def _scan_entry(
    target: str, kind: Optional[str], internal: argparse.Namespace, resolution
) -> Dict[str, Any]:
    """One scan: the scan entry of the scans document, or the refused entry.

    This runs the same stage pipeline the scan verb runs, with the same
    namespace the config show machinery resolved, and never runs a project's
    install or build steps: it does no more than ``depscan scan`` does. A
    scan that stopped early leaves its manifest on disk and reports the
    entry with no findings; an unexpected error reports the refused entry
    with the error message, the way the scans document does.
    """
    try:
        result = api.scan(
            internal,
            checks_not_assessed=resolution.not_assessed or None,
        )
    except api.ScanError:
        reports_dir = str(internal.reports_dir)
        return {
            "target": _json_target(target),
            "kind": kind,
            "scanDir": json_path(reports_dir),
            "manifest": scan_directory.read_manifest(reports_dir),
            "findings": [],
        }
    except Exception as exc:  # noqa: BLE001 - the entry reports the failure
        message = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
        return {"target": _json_target(target), "kind": None, "error": message}
    return {
        "target": _json_target(target),
        "kind": kind,
        "scanDir": json_path(result.reports_dir),
        "manifest": result.manifest,
        "findings": result.findings,
    }


def run_scan_tool(args, roots, allow_scans=False, allow_propose=False):
    """The dry run of a scan, or, with --allow-scans and execute, the scan."""
    del allow_propose
    target = str(args["target"])
    if args.get("execute"):
        if not allow_scans:
            raise ToolError(
                "run_scan cannot execute a real scan: the server was not "
                "started with --allow-scans, and the tool's arguments cannot "
                "turn real scans on. Only the person who starts the server "
                "can widen this default."
            )
        _confined_target(target, roots)
        argv = _scan_argv(args)
        scan_args = _parsed_scan_args(argv)
        entries, refusal = _resolve_targets(scan_args)
        if refusal is not None:
            raise ToolError(refusal.message)
        if not entries:
            raise ToolError(f"the target {target} was never resolved to a kind")
        given_target, kind, target_refusal = entries[0]
        if target_refusal is not None or kind is None:
            return (
                {
                    "target": _json_target(given_target),
                    "kind": None,
                    "error": target_refusal or "the target was refused",
                },
                [],
                None,
            )
        resolution = checks_table.resolve(
            scan_args, skip_requirements=_inventory_skip_requirements([kind])
        )
        # The real run builds the namespace the way the scan verb does, so
        # the requested checks land the same way, the license pseudo type
        # included; the environment the builder and the scan touch is
        # restored afterwards, so one run's flags never leak into the next
        # call. The dry run below stops before any of this.
        with _run_environment("license" in resolution.checks):
            internal = scan_namespace(scan_args, resolution=resolution)
            _apply_target_options(internal, given_target, kind, scan_args, resolution)
            # The scan directory the run will write must resolve inside the
            # roots, whether the caller named it or the default chose it
            # (<cwd>/reports, or DEPSCAN_REPORTS_DIR): a real run never
            # writes outside them.
            internal.reports_dir = confinement.confine(str(internal.reports_dir), roots)
            entry = _scan_entry(given_target, kind, internal, resolution)
        spill_dir = entry.get("scanDir")
        if spill_dir:
            try:
                spill_dir = confinement.confine(spill_dir, roots)
            except confinement.PathOutsideRootsError:
                spill_dir = None
        return entry, [entry], spill_dir
    _confined_target(target, roots)
    if args.get("reports_dir"):
        # The argv the dry run returns is the command the server would run,
        # so a reports directory the real run would refuse is refused here.
        confinement.confine(str(args["reports_dir"]), roots)
    argv = _scan_argv(args)
    document = {"argv": argv, "options": _options_document(_parsed_scan_args(argv))}
    return document, [document], None


# --- decisions ----------------------------------------------------------------------


def get_decisions_tool(args, roots, allow_scans=False, allow_propose=False):
    """The decisions of one scan directory: the entries with their status,
    the stale and expired ones, and the last gate result.

    The decisions file is the one the scan recorded, found the way
    ``depscan report`` finds it (relative to the scanned source root, the
    scan directory or its parent), and read only inside the allowed roots.
    A recorded file that cannot be found, or that changed since the scan,
    is named in ``warnings``.
    """
    del allow_scans, allow_propose
    from depscan.lib import decisions as decisions_lib

    scan_dir = _confined(args, roots, "scan_dir")
    result = _loaded_scan(scan_dir, roots)
    record, found = decisions_lib.locate_recorded_file(result.manifest, scan_dir)
    document = {
        "scanDir": json_path(scan_dir),
        "decisions": record,
        "entries": [],
        "stale": [],
        "expired": [],
        "proposals": [],
        "gate": _read_gate(scan_dir),
    }
    if record is not None and found is None:
        document["warnings"] = [
            f"the decisions file the scan recorded ({record['file']}) cannot be found"
        ]
    if found is not None:
        listing = api.triage_entries(file=confinement.confine(found, roots), scan_dir=scan_dir)
        for key in ("entries", "stale", "expired", "proposals"):
            document[key] = listing[key]
        if record.get("sha256") and record["sha256"] != _file_digest(found):
            document["warnings"] = [
                f"the decisions file {record['file']} changed since the scan; the entries "
                "are listed as the file is now"
            ]
    return document, [document], scan_dir


def _file_digest(path: str) -> str:
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def _read_gate(scan_dir: str):
    """The scan directory's last gate result, None when it holds none."""
    gate_path = os.path.join(scan_dir, scan_directory.EXPECTATIONS_FILE)
    if not os.path.isfile(gate_path):
        return None
    with open(gate_path, encoding="utf-8") as handle:
        return json.load(handle)


def _proposal_file(scan_root: str, roots) -> Tuple[str, bool]:
    """The decisions file a proposal about the scan at ``scan_root`` goes
    into, and whether the tool may create it.

    The file is the one the scanned project resolves to: the file the scan
    recorded, found the way ``depscan report`` finds it, or else the one the
    environment, the configuration files or the project's own
    ``.depscan/decisions.toml`` name. It must be a ``.toml`` file inside the
    roots. The only file the tool creates is ``.depscan/decisions.toml``
    under the scanned source root; any other missing file is refused.
    """
    from depscan.lib import decisions as decisions_lib

    manifest = scan_directory.read_manifest(scan_root) or {}
    source_root = decisions_lib.manifest_source_root(manifest)
    record, found = decisions_lib.locate_recorded_file(manifest, scan_root)
    if found is None and record is not None:
        raise ToolError(
            f"the decisions file the scan recorded ({record['file']}) cannot be found, so "
            "the proposal has nowhere to go; ask the person running the server to restore it"
        )
    if found is None:
        found, _selected_by = decisions_lib.resolve_decisions_path(None, source_root)
    default = (
        os.path.join(source_root, decisions_lib.DEFAULT_DECISIONS_FILE) if source_root else None
    )
    path = found or default
    if path is None:
        raise ToolError(
            f"the scan at {json_path(scan_root)} names no source directory and no decisions "
            "file, so there is no project file to propose into"
        )
    path = confinement.confine(path, roots)
    if not path.endswith(".toml"):
        raise ToolError(
            f"the decisions file {json_path(path)} is not a .toml file; propose_triage "
            "writes only into a decisions file"
        )
    may_create = default is not None and os.path.realpath(path) == os.path.realpath(default)
    if not os.path.isfile(path) and not may_create:
        raise ToolError(
            f"the decisions file {json_path(path)} does not exist, and propose_triage "
            "creates no file other than .depscan/decisions.toml under the scanned project"
        )
    return path, may_create


def propose_triage_tool(args, roots, allow_scans=False, allow_propose=False):
    """Write one triage proposal into the scanned project's decisions file.

    The tool writes proposals only, through the function ``depscan triage
    set --proposed-by`` uses: the entry carries proposed_by and never an
    author or an approver, it is appended beside any person's decision with
    the same selector, and it replaces only the same proposer's earlier
    proposal for that selector. It changes nothing until a person runs
    ``depscan triage review``. The server must have been started with
    --allow-propose, and the file must resolve inside the allowed roots.
    """
    del allow_scans
    if not allow_propose:
        raise ToolError(
            "propose_triage cannot write: the server was not started with "
            "--allow-propose, and the tool's arguments cannot turn proposals "
            "on. Only the person who starts the server can widen this "
            "default."
        )
    if not args.get("scan_dir"):
        raise ToolError(
            "the proposal needs scan_dir: the scan whose project the proposal is about; "
            "the tool writes into that project's decisions file"
        )
    scan_root = confinement.confine(str(args["scan_dir"]), roots)
    confinement.confine_contents(scan_root, roots)
    file, may_create = _proposal_file(scan_root, roots)
    try:
        written = api.triage_set(
            file=file,
            state=str(args["state"]),
            proposed_by=str(args["proposed_by"]),
            finding=args.get("finding"),
            advisory=args.get("advisory"),
            purl=args.get("purl"),
            version_range=args.get("version_range"),
            justification=args.get("justification"),
            detail=args.get("detail"),
            expires=args.get("expires"),
            create=may_create,
        )
    except api.TriageApiError as exc:
        raise ToolError(f"the proposal cannot be written: {exc}") from exc
    document = {
        "decisionsFile": json_path(file),
        "result": "proposed" if written["result"] == "added" else "updated",
        "entry": written["entry"],
    }
    return document, [document], None


# --- the registry -------------------------------------------------------------------


TOOL_SPECS: Tuple[ToolSpec, ...] = (
    _spec(
        "scan_summary",
        "Summarise a dep-scan scan directory: the manifest summary and the "
        "counts of its findings by category and severity.",
        scan_summary_tool,
    ),
    _spec(
        "list_findings",
        "List the findings of a dep-scan scan directory, one page at a time, "
        "filtered by category, severity, purl, CWE, rule id or recorded "
        "reachability. Pass nextCursor from the previous page to read on. "
        "A finding whose exploitability carries a witness names the id of "
        "the evidence record whose witness path the reach verdict names.",
        list_findings_tool,
    ),
    _spec(
        "get_finding",
        "Read one finding of a dep-scan scan directory by its fingerprint id "
        "(dsf1 followed by the SHA-256 hex digest the finding's id carries).",
        get_finding_tool,
    ),
    _spec(
        "explain_finding",
        "Read one finding of a dep-scan scan directory together with the "
        "explanation dep-scan renders for it. The explanation is rendered "
        "for the whole scan in this version, not for the finding alone; "
        "read it as the scan's context around the finding.",
        explain_finding_tool,
    ),
    _spec(
        "coverage",
        "Report a dep-scan scan directory's coverage: the manifest's stage "
        "entries, the reasons parts of the analysis did not run, and the "
        "checks the scan did not run.",
        coverage_tool,
    ),
    _spec(
        "list_components",
        "List the components of a dep-scan scan's BOM, one page at a time. "
        "Pass nextCursor from the previous page to read on.",
        list_components_tool,
    ),
    _spec(
        "diff_scans",
        "Compare two dep-scan scan directories: the vulnerability pairs the "
        "later scan added, fixed, or changed in severity or score.",
        diff_scans_tool,
    ),
    _spec(
        "doctor",
        "Report the tools, data and capabilities dep-scan sees on this "
        "machine, as the depscan doctor command does. A missing tool or "
        "database is a reported state, not an error.",
        doctor_tool,
    ),
    _spec(
        "vdb_status",
        "Report the local vulnerability database and shard store state, as "
        "the depscan vdb info command does.",
        vdb_status_tool,
    ),
    _spec(
        "run_scan",
        "Plan or run one dep-scan scan. A dry run by default: it returns the "
        "depscan scan command and the effective options and executes "
        "nothing. A real run needs the server started with --allow-scans "
        "and execute set to true; it scans only targets inside the allowed "
        "roots, never runs a project's install or build steps, and runs "
        "cdxgen in secure mode.",
        run_scan_tool,
    ),
    _spec(
        "get_decisions",
        "Read the triage decisions of a dep-scan scan directory: every "
        "entry with its status (live, proposal, expired, stale), what it "
        "matches, and the last gate result the scan recorded.",
        get_decisions_tool,
    ),
    _spec(
        "propose_triage",
        "Propose one triage decision about a finding of a scan, as a "
        "proposal a person approves with depscan triage review. The proposal "
        "goes into the decisions file the scanned project resolves to; the "
        "tool creates no file other than .depscan/decisions.toml under the "
        "project. The server must be started with --allow-propose; the tool "
        "never writes an approved decision, never sets an author or an "
        "approver, and never changes a person's decision.",
        propose_triage_tool,
    ),
)

_SPEC_BY_NAME = {spec.name: spec for spec in TOOL_SPECS}


# --- the MCP handlers ---------------------------------------------------------------


async def handle_list_tools(ctx, params) -> types.ListToolsResult:
    """Every tool this server serves, with its published input schema."""
    del ctx, params
    tools = [
        types.Tool(
            name=spec.name,
            description=spec.description,
            inputSchema=load_schema(spec.schema_name),
        )
        for spec in TOOL_SPECS
    ]
    return types.ListToolsResult(tools=tools)


async def handle_call_tool(ctx, params) -> types.CallToolResult:
    """One tool call, validated, confined, paged and budgeted."""
    spec = _SPEC_BY_NAME.get(params.name)
    if spec is None:
        raise ToolError(
            f"unknown tool {params.name!r}; this server serves: "
            f"{', '.join(spec.name for spec in TOOL_SPECS)}"
        )
    args = dict(params.arguments or {})
    try:
        validate(spec.schema_name, args)
    except SchemaValidationError as exc:
        raise ToolError(
            f"the arguments do not satisfy the {spec.name} input schema: {exc}"
        ) from exc
    state = ctx.lifespan_context
    startup_roots = tuple(state.get("startup_roots") or ())
    allow_scans = bool(state.get("allow_scans"))
    allow_propose = bool(state.get("allow_propose"))
    roots = await server_mod.effective_roots_for(ctx, startup_roots)
    document, items, spill_dir = spec.run(
        args, roots, allow_scans=allow_scans, allow_propose=allow_propose
    )
    try:
        validate(f"depscan-mcp-{spec.name}-output", document)
    except SchemaValidationError as exc:
        raise ToolError(
            f"the {spec.name} result does not satisfy its published output "
            f"schema, so it is withheld: {exc}"
        ) from exc
    return _document_result(params.name, args, document, items, spill_dir, roots)


def _within_budget(document: Dict[str, Any]) -> bool:
    serialized = json.dumps(document, separators=(",", ":"))
    return len(serialized.encode("utf-8")) <= TOOL_BUDGET_BYTES


def _spill_path(tool_name: str, args: Dict[str, Any], scan_dir: str) -> str:
    canonical = json.dumps(args, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return os.path.join(scan_dir, "mcp", f"{tool_name}-{digest}.json")


def _document_result(
    tool_name: str,
    args: Dict[str, Any],
    document: Dict[str, Any],
    items: List[Any],
    spill_dir: Optional[str],
    roots: Tuple[str, ...],
) -> types.CallToolResult:
    """The result of one tool call, over the response budget or within it.

    An oversized result is written with indent=2 into the scan directory's
    ``mcp`` directory, whose path is confined again on the way in, and the
    tool returns the file path and the item count. Without a scan directory
    to spill into the oversize is a tool error naming the budget.
    """
    if _within_budget(document):
        text = json.dumps(document, separators=(",", ":"))
        return types.CallToolResult(content=[types.TextContent(type="text", text=text)])
    if spill_dir is None:
        raise ToolError(
            f"the {tool_name} result exceeds the {TOOL_BUDGET_BYTES}-byte "
            "response budget and there is no scan directory to spill it into; "
            "narrow the request or scan a smaller target"
        )
    spill_file = _spill_path(tool_name, args, spill_dir)
    confinement.confine(spill_file, roots)
    scan_directory.atomic_write_json(spill_file, document)
    envelope = {"file": json_path(spill_file), "count": len(items)}
    text = json.dumps(envelope, separators=(",", ":"))
    return types.CallToolResult(content=[types.TextContent(type="text", text=text)])
