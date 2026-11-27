"""The decisions file as the scan, report and triage verbs use it.

One path serves every caller. :func:`parse_options` checks the command-line
decisions options once per run (``--decisions``, ``--fail-on``, ``--vex``,
``--baseline`` and ``--config``). :func:`load_for_target` resolves and loads
the decisions one scan applies, and :func:`load_for_saved_scan` the
decisions ``depscan report`` applies to a scan directory. Both return a
:class:`RunDecisions`, which :func:`apply_run_decisions` applies to plain
finding documents: it clears what an earlier application left, marks the
baseline, applies the triage and evaluates the gate, and returns the
``depscan.expectations.json`` document. :func:`block_lines` renders that
document as the console block, so the scan and the report print the same
lines. The selection rules, the loader and the gate live in
:mod:`analysis_lib.findings.decisions`; nothing here duplicates them.
"""

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from analysis_lib.findings import decisions as decision_lib
from analysis_lib.findings.decisions import (
    BaselineSpec,
    Decisions,
    DecisionsError,
    TriageEntry,
    parse_rfc3339,
)

from depscan.lib.scan_directory import EXPECTATIONS_FILE, recorded_path

#: The environment variable that names a decisions file.
DECISIONS_ENV = "DEPSCAN_DECISIONS"

#: The location of a user's depscan configuration, consulted for the
#: decisions key when the project file does not name one.
USER_CONFIG = os.path.join("~", ".config", "depscan", "depscan.toml")

#: The decisions file of a project, relative to its root.
DEFAULT_DECISIONS_FILE = os.path.join(".depscan", "decisions.toml")


class DecisionsUsageError(ValueError):
    """A decisions file, VEX document or decisions option the verb refuses.

    The message is the one the verb prints; the exit code is 2.
    """


# --- resolution ------------------------------------------------------------------


def project_config_path(config: Optional[str] = None) -> str:
    """The project depscan.toml a run reads: ``--config`` when given, then
    ``DEPSCAN_CONFIG``, then ``$PWD/.config/depscan.toml``."""
    return (
        config
        or os.getenv("DEPSCAN_CONFIG")
        or os.path.join(os.getcwd(), ".config", "depscan.toml")
    )


def _config_decisions_key(path: str) -> Optional[str]:
    """The decisions file a depscan.toml names, if it does.

    The sectioned ``[scan] decisions`` key is the documented place; a flat
    ``decisions`` key is read too, because the configuration file's keys are
    flat today. A relative value resolves against the file's directory, the
    way ``exploitability_rules`` does.
    """
    import tomllib

    try:
        with open(path, "rb") as handle:
            document = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return None
    scan_section = document.get("scan")
    value = scan_section.get("decisions") if isinstance(scan_section, dict) else None
    if value is None:
        value = document.get("decisions")
    if not isinstance(value, str) or not value.strip():
        return None
    value = value.strip()
    if not os.path.isabs(value):
        value = os.path.join(
            os.path.dirname(os.path.abspath(path)), *value.replace("\\", "/").split("/")
        )
    return value


def resolve_decisions_path(
    option_value: Optional[str], target_dir: Optional[str], *, config: Optional[str] = None
) -> Tuple[Optional[str], str]:
    """Which decisions file applies, and what selected it.

    The precedence is the command line, then the environment, then the
    project ``depscan.toml`` (``config``, see :func:`project_config_path`),
    then the user's, then ``target_dir``'s own ``.depscan/decisions.toml``
    when it exists.

    :returns: ``(path, selected_by)`` where ``selected_by`` is one of
        option, environment, project-config, user-config or default, and the
        path is None when nothing applies.
    """
    if option_value:
        return str(option_value), "option"
    from_env = os.getenv(DECISIONS_ENV)
    if from_env:
        return from_env, "environment"
    for selected_by, config_path in (
        ("project-config", project_config_path(config)),
        ("user-config", os.path.expanduser(USER_CONFIG)),
    ):
        if os.path.isfile(config_path):
            named = _config_decisions_key(config_path)
            if named:
                return named, selected_by
    if target_dir and os.path.isdir(target_dir):
        default = os.path.join(target_dir, DEFAULT_DECISIONS_FILE)
        if os.path.isfile(default):
            return default, "default"
    return None, "default"


def resolve_recorded(file: str, scan_dir: str) -> str:
    """Where a path the manifest recorded lies on this machine: an absolute
    record as it stands, a relative one against the scan directory and
    nothing else, so the working directory never chooses the file."""
    if os.path.isabs(file) or re.match(r"^[A-Za-z]:/", file):
        return os.path.normpath(file)
    return os.path.normpath(os.path.join(os.path.abspath(scan_dir), *file.split("/")))


def manifest_source_root(manifest: Optional[Dict[str, Any]], scan_dir: str) -> Optional[str]:
    """The scanned source directory, absolute, or None when the scan read a
    BOM, a BOM directory or a purl instead.

    The manifest's ``sourceRoot`` is relative to the scan directory and
    resolves against it. A manifest without it names the directory only in
    its inputs, as the user gave it; a relative input there is relative to
    a working directory nobody recorded, so it is not used.
    """
    manifest = manifest or {}
    if isinstance(manifest.get("sourceRoot"), str) and manifest["sourceRoot"]:
        return resolve_recorded(manifest["sourceRoot"], scan_dir)
    options = manifest.get("options") or {}
    if any(options.get(key) for key in ("bom", "bom_dir", "search_purl")):
        return None
    for entry in manifest.get("inputs") or []:
        if isinstance(entry, dict) and entry.get("type") == "dir" and entry.get("path"):
            path = os.path.expanduser(str(entry["path"]))
            return os.path.normpath(path) if os.path.isabs(path) else None
    return None


def file_digest(path: str) -> Optional[str]:
    """The SHA-256 hex digest of a file, None when it cannot be read."""
    try:
        with open(path, "rb") as handle:
            return hashlib.sha256(handle.read()).hexdigest()
    except OSError:
        return None


@dataclass
class RecordedFile:
    """A file a scan recorded, located on this machine: the path as the
    manifest records it, where it resolves, whether it exists there, and
    whether its digest still matches the record."""

    file: str
    path: str
    sha256: Optional[str] = None
    exists: bool = False
    digest_matches: bool = False


def locate_recorded(entry: Dict[str, Any], scan_dir: str) -> RecordedFile:
    """Locate one recorded file (the decisions file or a VEX document)
    against the scan directory; see :func:`resolve_recorded`."""
    file = str(entry.get("file"))
    path = resolve_recorded(file, scan_dir)
    located = RecordedFile(file=file, path=path, sha256=entry.get("sha256"))
    if os.path.isfile(path):
        located.exists = True
        located.digest_matches = not located.sha256 or file_digest(path) == located.sha256
    return located


def manifest_record(manifest: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """The manifest's decisions record, None when the scan had no decisions
    work."""
    record = (manifest or {}).get("decisions")
    return record if isinstance(record, dict) else None


def locate_recorded_file(
    manifest: Optional[Dict[str, Any]], scan_dir: str
) -> Tuple[Optional[Dict[str, Any]], Optional[RecordedFile]]:
    """The decisions file a scan recorded, located against the scan
    directory.

    :returns: ``(record, located)``: the manifest's decisions record, None
        when the scan had no decisions work, and the decisions file it
        names, None when the scan read no file.
    """
    record = manifest_record(manifest)
    if record is None or not isinstance(record.get("file"), str):
        return record, None
    return record, locate_recorded(record, scan_dir)


def _same_file(first: str, second: str) -> bool:
    return os.path.normcase(os.path.realpath(first)) == os.path.normcase(os.path.realpath(second))


@dataclass
class SavedScanFile:
    """The decisions file a re-evaluation of a saved scan reads.

    ``path`` is the file, None when none applies, with ``selected_by``;
    ``recorded`` is the file the scan recorded, located against the scan
    directory, None when it read none; ``missing`` is set when the file the
    scan recorded is the one that applies and cannot be found. ``warnings``
    say how the file differs from the one the scan read.
    """

    path: Optional[str] = None
    selected_by: str = "default"
    record: Optional[Dict[str, Any]] = None
    recorded: Optional[RecordedFile] = None
    missing: bool = False
    warnings: List[str] = field(default_factory=list)


def resolve_for_saved_scan(
    manifest: Optional[Dict[str, Any]],
    scan_dir: str,
    *,
    option: Optional[str] = None,
    config: Optional[str] = None,
) -> SavedScanFile:
    """Which decisions file applies to a saved scan, the one resolution
    ``depscan report`` and the server's decisions tools share.

    A file the command line, the environment or a configuration file names
    wins. When it is not the file the scan recorded, a warning names both.
    Otherwise the recorded file applies, resolved against the scan directory
    only: a scan never picks up a file because of the working directory a
    report runs from. A recorded file whose digest changed is applied as it
    is now, with a warning; one that cannot be found sets ``missing``.
    """
    record, recorded = locate_recorded_file(manifest, scan_dir)
    resolved = SavedScanFile(record=record, recorded=recorded)
    path, selected_by = resolve_decisions_path(option, None, config=config)
    if path:
        resolved.path, resolved.selected_by = path, selected_by
        if recorded is not None and not _same_file(path, recorded.path):
            resolved.warnings.append(
                f"this run evaluates the decisions file {path} (selected by {selected_by}); "
                f"the scan used {recorded.path}"
            )
        elif recorded is not None and recorded.exists and not recorded.digest_matches:
            resolved.warnings.append(
                f"the decisions file {path} changed since the scan; the gate was evaluated "
                "with the file as it is now"
            )
        return resolved
    if recorded is None or record is None:
        return resolved
    resolved.selected_by = str(record.get("selectedBy") or "default")
    if not recorded.exists:
        resolved.missing = True
        resolved.warnings.append(
            f"the decisions file the scan recorded ({recorded.file}, relative to the scan "
            f"directory) cannot be found at {recorded.path}"
        )
        return resolved
    resolved.path = recorded.path
    if not recorded.digest_matches:
        resolved.warnings.append(
            f"the decisions file {recorded.path} changed since the scan; the gate was "
            "evaluated with the file as it is now"
        )
    return resolved


# --- loading ---------------------------------------------------------------------


class GateUnavailableError(RuntimeError):
    """The scan recorded a gate that a report cannot evaluate: the files it
    read are gone and it saved no gate result. The verb exits 1."""


@dataclass
class DecisionOptions:
    """The decisions options of one command line, checked once per run.

    ``named`` is the decisions file ``--decisions`` named, loaded; the other
    files resolve per target. ``fail_on`` keeps the ``--fail-on``
    expressions as given and ``vex_files`` each ``--vex`` document with its
    digest, for the manifest's record. A relative ``--baseline`` resolves
    against the working directory the command ran in.
    """

    decisions: Optional[str] = None
    config: Optional[str] = None
    cli_expects: List[Any] = field(default_factory=list)
    fail_on: List[str] = field(default_factory=list)
    vex_entries: List[TriageEntry] = field(default_factory=list)
    vex_files: List[Tuple[str, str]] = field(default_factory=list)
    baseline: Optional[str] = None
    cwd: str = field(default_factory=os.getcwd)
    named: Optional[Decisions] = None


@dataclass
class RunDecisions:
    """The decisions one scan or report applies.

    ``decisions`` is the decisions file with the VEX statements added, or
    None when neither applies. ``baseline`` is the baseline in effect, with
    ``baseline_dir`` the directory a relative reference resolves against.
    ``fail_on`` and ``vex_files`` are the ``--fail-on`` expressions and the
    VEX documents in effect, which :meth:`record_for` records beside the
    decisions file. ``warnings`` say what the reader must know about how
    the files were found. ``saved`` is the gate result a scan saved, kept
    when a file it recorded cannot be found.
    """

    decisions: Optional[Decisions] = None
    cli_expects: List[Any] = field(default_factory=list)
    fail_on: List[str] = field(default_factory=list)
    vex_files: List[Tuple[str, str]] = field(default_factory=list)
    baseline: Optional[BaselineSpec] = None
    baseline_dir: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    saved: Optional[Dict[str, Any]] = None

    @property
    def active(self) -> bool:
        """Whether the run has decisions work: a decisions file, VEX
        statements, command-line expectations or a baseline."""
        return bool(self.decisions is not None or self.cli_expects or self.baseline)

    @property
    def triage(self) -> List[TriageEntry]:
        return list(self.decisions.triage) if self.decisions is not None else []

    def record_for(self, scan_dir: str) -> Optional[Dict[str, Any]]:
        """The decisions record of the manifest and of the expectations
        document written into ``scan_dir``: the decisions file, each VEX
        document and the ``--fail-on`` expressions, the files recorded by
        :func:`recorded_path` with their digests. None when the run read no
        file and had no expression."""
        record: Dict[str, Any] = {}
        decisions = self.decisions
        if decisions is not None and decisions.path:
            record["file"] = recorded_path(str(decisions.path), scan_dir)
            record["sha256"] = decisions.digest
            record["selectedBy"] = decisions.selected_by
        if self.vex_files:
            record["vex"] = [
                {"file": recorded_path(path, scan_dir), "sha256": digest}
                for path, digest in self.vex_files
            ]
        if self.fail_on:
            record["failOn"] = list(self.fail_on)
        return record or None


def parse_options(
    *,
    verb: str,
    decisions: Optional[str] = None,
    fail_on: Sequence[str] = (),
    vex: Sequence[str] = (),
    baseline: Optional[str] = None,
    config: Optional[str] = None,
) -> DecisionOptions:
    """Check the decisions options of a command line.

    :raises DecisionsUsageError: When a ``--fail-on`` expression, a VEX
        document or the named decisions file cannot be used.
    """
    options = DecisionOptions(decisions=decisions, config=config, baseline=baseline)
    try:
        for index, expression in enumerate(fail_on or ()):
            options.cli_expects.append(decision_lib.parse_fail_on(expression, index=index))
            options.fail_on.append(str(expression))
        for vex_file in vex or ():
            entries, digest = read_vex_document(str(vex_file))
            options.vex_entries.extend(entries)
            options.vex_files.append((os.path.abspath(str(vex_file)), digest))
        if decisions:
            options.named = decision_lib.load_decisions(str(decisions), selected_by="option")
    except DecisionsError as exc:
        raise DecisionsUsageError(f"depscan {verb}: {exc}") from exc
    return options


def _load(path: str, selected_by: str, verb: str) -> Decisions:
    try:
        return decision_lib.load_decisions(path, selected_by=selected_by)
    except DecisionsError as exc:
        raise DecisionsUsageError(f"depscan {verb}: {exc}") from exc


def _run_decisions(
    options: DecisionOptions,
    loaded: Optional[Decisions],
    *,
    cli_expects: Optional[List[Any]] = None,
    fail_on: Optional[List[str]] = None,
    vex: Optional[Tuple[List[TriageEntry], List[Tuple[str, str]]]] = None,
) -> RunDecisions:
    """Combine a loaded file with the command-line options, or with the
    expressions and VEX documents a saved scan recorded."""
    run = RunDecisions(
        cli_expects=list(options.cli_expects if cli_expects is None else cli_expects),
        fail_on=list(options.fail_on if fail_on is None else fail_on),
    )
    vex_entries, run.vex_files = (
        vex
        if vex is not None
        else (
            options.vex_entries,
            list(options.vex_files),
        )
    )
    if loaded is not None:
        run.decisions = Decisions(
            triage=list(loaded.triage),
            expects=list(loaded.expects),
            requires=list(loaded.requires),
            baseline=loaded.baseline,
            path=loaded.path,
            digest=loaded.digest,
            selected_by=loaded.selected_by,
        )
    if vex_entries:
        if run.decisions is None:
            run.decisions = Decisions()
        run.decisions.triage.extend(vex_entries)
    if options.baseline:
        run.baseline = BaselineSpec(scan=str(options.baseline))
        run.baseline_dir = options.cwd
    elif loaded is not None and loaded.baseline is not None:
        run.baseline = loaded.baseline
        run.baseline_dir = os.path.dirname(os.path.abspath(loaded.path)) if loaded.path else None
    return run


def load_for_target(
    options: DecisionOptions,
    *,
    target_dir: Optional[str] = None,
    verb: str = "scan",
) -> RunDecisions:
    """The decisions one scan applies.

    The file is the one ``--decisions`` named, or the one
    :func:`resolve_decisions_path` finds for ``target_dir``, the scanned
    directory (None for a target that is not one: an image, a BOM or a purl
    has no repository to hold a file).

    :raises DecisionsUsageError: When the file cannot be read or breaks its
        schema.
    """
    loaded = options.named
    if loaded is None:
        path, selected_by = resolve_decisions_path(None, target_dir, config=options.config)
        if path:
            loaded = _load(path, selected_by, verb)
    return _run_decisions(options, loaded)


def _recorded_vex(
    record: Optional[Dict[str, Any]], scan_dir: str, verb: str
) -> Tuple[List[TriageEntry], List[Tuple[str, str]], List[str], bool]:
    """The VEX documents a saved scan recorded, read again: the entries,
    the files with their digests, the warnings, and whether one is
    missing."""
    entries: List[TriageEntry] = []
    files: List[Tuple[str, str]] = []
    warnings: List[str] = []
    missing = False
    for item in (record or {}).get("vex") or []:
        if not isinstance(item, dict) or not isinstance(item.get("file"), str):
            continue
        located = locate_recorded(item, scan_dir)
        if not located.exists:
            missing = True
            warnings.append(
                f"the VEX document the scan recorded ({located.file}, relative to the scan "
                f"directory) cannot be found at {located.path}"
            )
            continue
        try:
            statements, digest = read_vex_document(located.path)
        except DecisionsError as exc:
            raise DecisionsUsageError(f"depscan {verb}: {exc}") from exc
        if not located.digest_matches:
            warnings.append(
                f"the VEX document {located.path} changed since the scan; the gate was "
                "evaluated with the document as it is now"
            )
        entries.extend(statements)
        files.append((located.path, digest))
    return entries, files, warnings, missing


def load_for_saved_scan(
    options: DecisionOptions,
    manifest: Optional[Dict[str, Any]],
    scan_dir: str,
    saved: Optional[Dict[str, Any]] = None,
    *,
    verb: str = "report",
) -> RunDecisions:
    """The decisions a re-evaluation of a saved scan applies.

    The decisions file is the one :func:`resolve_for_saved_scan` picks. The
    ``--fail-on`` expressions and the VEX documents the scan recorded are
    applied again, unless this run names its own. A recorded file that
    cannot be found is named in ``warnings`` and the gate result the scan
    saved is kept in ``saved``, whole: the report shows that result and
    exits with its code.

    :raises DecisionsUsageError: When a file cannot be read or breaks its
        schema.
    :raises GateUnavailableError: When a file the scan recorded cannot be
        found and the scan saved no gate result either, so the gate the scan
        recorded cannot be evaluated.
    """
    resolution = resolve_for_saved_scan(
        manifest, scan_dir, option=options.decisions, config=options.config
    )
    record = resolution.record
    warnings = list(resolution.warnings)
    missing = resolution.missing
    loaded = options.named
    if loaded is None and resolution.path:
        loaded = _load(resolution.path, resolution.selected_by, verb)
    vex = None
    if not options.vex_entries:
        entries, files, vex_warnings, vex_missing = _recorded_vex(record, scan_dir, verb)
        vex, missing = (entries, files), missing or vex_missing
        warnings.extend(vex_warnings)
    cli_expects = fail_on = None
    if not options.cli_expects and record and record.get("failOn"):
        fail_on = [str(expression) for expression in record["failOn"]]
        try:
            cli_expects = [
                decision_lib.parse_fail_on(expression, index=index)
                for index, expression in enumerate(fail_on)
            ]
        except DecisionsError as exc:
            raise DecisionsUsageError(f"depscan {verb}: {exc}") from exc
    if missing:
        if saved is None:
            raise GateUnavailableError(
                "; ".join(warnings)
                + f", and the scan directory holds no {EXPECTATIONS_FILE}, so the gate "
                "the scan recorded cannot be evaluated; pass --decisions to evaluate it "
                "with a file"
            )
        warnings.append("the gate result the scan saved is shown, and its exit code stands")
        if options.cli_expects or options.vex_entries or options.baseline:
            warnings.append(
                "the --fail-on, --vex and --baseline options of this run were not "
                "evaluated, because the decisions the scan applied cannot be read"
            )
        run = RunDecisions(warnings=warnings, saved=saved)
        return run
    run = _run_decisions(options, loaded, cli_expects=cli_expects, fail_on=fail_on, vex=vex)
    if record is None and loaded is None and saved is not None and not run.active:
        # A manifest that predates the record of --fail-on still has the
        # gate result its scan saved.
        warnings.append(
            "the scan recorded no decisions and this run names none; the gate result "
            "the scan saved is shown"
        )
        run.saved = saved
    run.warnings = warnings
    return run


# --- VEX documents ---------------------------------------------------------------


def load_vex_decisions(path: str) -> List[TriageEntry]:
    """The triage decisions of a VEX document; see :func:`read_vex_document`."""
    return read_vex_document(path)[0]


def read_vex_document(path: str) -> Tuple[List[TriageEntry], str]:
    """Load a CycloneDX VEX or OpenVEX document as triage decisions.

    The document is itself the record of a decision, so every statement
    applies at once as a live entry: its author and its source name the
    document (``VEX document <file name>``), which keeps it apart from the
    decisions people entered. CycloneDX statements take the analysis state,
    justification and responses from the entry; OpenVEX statements map
    their status and justification onto the CycloneDX vocabulary. A
    statement that names no finding this tool can read is reported as stale
    when the decisions are applied, and never silently dropped.

    :returns: The entries and the SHA-256 hex digest of the bytes read.
    :raises DecisionsError: When the file cannot be read as either format.
    """
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
        document = json.loads(raw.decode("utf-8-sig"))
    except (OSError, ValueError) as exc:
        raise DecisionsError(f"the VEX document '{path}' cannot be read: {exc}") from exc
    if not isinstance(document, dict):
        raise DecisionsError(f"the VEX document '{path}' is not a JSON object")
    name = f"VEX document {os.path.basename(path)}"
    if document.get("bomFormat") == "CycloneDX" or (
        isinstance(document.get("$schema"), str) and "cyclonedx" in document["$schema"].lower()
    ):
        statements = _cyclonedx_statements(document)
    elif isinstance(document.get("statements"), list):
        statements = _openvex_statements(document)
    else:
        raise DecisionsError(
            f"the VEX document '{path}' is neither a CycloneDX document nor an "
            "OpenVEX document: no bomFormat of CycloneDX and no statements array"
        )
    entries = [
        TriageEntry(index=index, author=name, source=name, **statement)
        for index, statement in enumerate(statements, start=1)
    ]
    return entries, hashlib.sha256(raw).hexdigest()


def _cyclonedx_component_purls(document: Dict[str, Any]) -> Dict[str, str]:
    """Map a CycloneDX document's bom-refs to the purls they name, the
    component tree included."""
    refs: Dict[str, str] = {}

    def walk(components: Any) -> None:
        for component in components if isinstance(components, list) else []:
            if not isinstance(component, dict):
                continue
            ref, purl = component.get("bom-ref"), component.get("purl")
            if isinstance(ref, str) and isinstance(purl, str) and ref not in refs:
                refs[ref] = purl
            walk(component.get("components"))

    walk(document.get("components"))
    metadata = document.get("metadata")
    if isinstance(metadata, dict):
        walk(metadata.get("components"))
    return refs


def _cyclonedx_statements(document: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The statements of a CycloneDX VEX document, one per affected
    component. The analysis values are the CycloneDX vocabulary already; the
    component is named by a bom-ref the component tree resolves to a purl."""
    refs = _cyclonedx_component_purls(document)
    statements: List[Dict[str, Any]] = []
    for vuln in document.get("vulnerabilities") or []:
        if not isinstance(vuln, dict):
            continue
        analysis = vuln.get("analysis")
        if (
            not isinstance(analysis, dict)
            or analysis.get("state") not in decision_lib.TRIAGE_STATES
        ):
            continue
        justification = analysis.get("justification")
        detail = analysis.get("detail")
        affects = [
            affect["ref"]
            for affect in vuln.get("affects") or []
            if isinstance(affect, dict) and isinstance(affect.get("ref"), str)
        ]
        for ref in affects or [""]:
            statements.append(
                {
                    "state": str(analysis["state"]),
                    "advisory": str(vuln.get("id") or "").strip() or None,
                    "purl": refs.get(ref, ref if str(ref).startswith("pkg:") else None),
                    "justification": justification
                    if justification in decision_lib.JUSTIFICATIONS
                    else None,
                    "responses": [
                        str(value)
                        for value in analysis.get("response") or []
                        if value in decision_lib.RESPONSES
                    ],
                    "detail": str(detail) if detail else None,
                }
            )
    return statements


#: OpenVEX status to CycloneDX state.
_OPENVEX_STATUS = {
    "not_affected": "not_affected",
    "affected": "exploitable",
    "fixed": "resolved",
    "under_investigation": "in_triage",
}

#: OpenVEX justification to CycloneDX justification.
_OPENVEX_JUSTIFICATION = {
    "component_not_present": "code_not_present",
    "vulnerable_code_not_present": "code_not_present",
    "vulnerable_code_not_in_execute_path": "code_not_reachable",
    "vulnerable_code_cannot_be_controlled_by_adversary": "requires_environment",
    "inline_mitigations_already_exist": "protected_by_mitigating_control",
}


def _openvex_statements(document: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The statements of an OpenVEX document, one per product. A product
    that names no purl still becomes an entry, whose selector matches
    nothing and which the application reports as stale."""
    statements: List[Dict[str, Any]] = []
    for statement in document.get("statements") or []:
        if not isinstance(statement, dict):
            continue
        state = _OPENVEX_STATUS.get(str(statement.get("status") or ""))
        if state is None:
            continue
        vulnerability = statement.get("vulnerability")
        if isinstance(vulnerability, dict):
            vulnerability = vulnerability.get("name")
        advisory = str(vulnerability or "").strip() or None
        detail = statement.get("detail")
        timestamp, expires = statement.get("timestamp"), statement.get("expires")
        products = statement.get("products") or []
        for product in [products] if isinstance(products, str) else products:
            if isinstance(product, dict):
                product = product.get("id")
            statements.append(
                {
                    "state": state,
                    "advisory": advisory,
                    "purl": product
                    if isinstance(product, str) and product.startswith("pkg:")
                    else None,
                    "justification": _OPENVEX_JUSTIFICATION.get(
                        str(statement.get("justification") or "")
                    ),
                    "detail": str(detail) if detail else None,
                    "created": timestamp
                    if isinstance(timestamp, str) and parse_rfc3339(timestamp)
                    else None,
                    "expires": expires
                    if isinstance(expires, str) and parse_rfc3339(expires)
                    else None,
                }
            )
    return statements


# --- applying --------------------------------------------------------------------


def apply_run_decisions(
    run: RunDecisions,
    findings: List[Dict[str, Any]],
    *,
    stages: Sequence[Dict[str, Any]],
    vulns: Iterable[Dict[str, Any]],
    source: str,
    scan_dir: str,
) -> Dict[str, Any]:
    """Apply the decisions to plain finding documents and evaluate the gate.

    The findings are changed in place: the triage and baseline fields an
    earlier application left are cleared first, so a saved scan reflects
    the decisions file as it is now. ``vulns`` are the VDR entries the
    advisory aliases come from, which the rule and advisory selectors match
    through. ``stages`` are the manifest stages the requirements read.
    ``scan_dir`` is the scan directory the document describes, which the
    decisions record's paths are relative to.

    :returns: The ``depscan.expectations.json`` document.
    :raises analysis_lib.findings.decisions.BaselineError: When the baseline
        cannot be read or does not match its digest.
    """
    decisions = run.decisions if run.decisions is not None else Decisions()
    alias_map = decision_lib.alias_map_from_vulns(vulns)
    baseline_ids = None
    baseline_document = None
    if run.baseline is not None:
        baseline_ids = decision_lib.read_baseline(run.baseline, base_dir=run.baseline_dir)
        baseline_document = {
            "scan": run.baseline.scan,
            "digest": run.baseline.digest,
            "findings": len(baseline_ids),
        }
    new, existing = decision_lib.apply_baseline(findings, baseline_ids)
    application = decision_lib.apply_triage(findings, decisions.triage, alias_map=alias_map)
    evaluation = decision_lib.evaluate_gate(
        findings,
        stages,
        decisions,
        cli_expects=run.cli_expects,
        has_baseline=baseline_ids is not None,
        baseline_document=baseline_document,
        decisions_document=run.record_for(scan_dir),
        application=application,
        new=new,
        existing=existing,
        alias_map=alias_map,
    )
    document = evaluation.to_document(
        evaluated_utc=datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
        source=source,
    )
    if run.warnings:
        document["warnings"] = list(run.warnings)
    return document


def gate_exit(document: Optional[Dict[str, Any]]) -> int:
    """The exit code a gate result adds to a run: 4 when a required
    capability was not assessed, 3 when a fail-action expectation matched,
    else 0."""
    return decision_lib.gate_exit_from_document(document) if document else 0


def combine_run_exit(exit_codes: List[int]) -> int:
    """The exit code of a run of one or more scans, or of a scan and its
    gate.

    Codes 1 and 2 keep their meaning and win over the gate codes; 4 wins
    over 3, because a gate over missing coverage cannot be trusted; the
    highest remaining code stands.
    """
    if 2 in exit_codes:
        return 2
    if 1 in exit_codes:
        return 1
    return max(exit_codes) if exit_codes else 0


# --- the console block -----------------------------------------------------------


def _recorded_label(file: str) -> str:
    if os.path.isabs(file) or re.match(r"^[A-Za-z]:/", file):
        return file
    return f"{file}, relative to the scan directory"


_STATUS_WORDS = {"pass": "pass", "fail": "FAIL", "warn": "warn", "not_evaluated": "not evaluated"}


def block_lines(document: Dict[str, Any], findings_count: int) -> List[str]:
    """The decisions and gate block, as plain lines, from an expectations
    document: the file, the warnings, the triage counts, the expired,
    stale, pending and shadowed entries with their handles, and every gate
    result with its id and the findings it matched. The scan and the report
    print these lines, and the saved console reports carry them."""
    lines: List[str] = []
    record = document.get("decisions") or {}
    if record.get("file"):
        lines.append(
            f"Decisions file: {_recorded_label(record['file'])} "
            f"(selected by {record.get('selectedBy')})"
        )
    for vex in record.get("vex") or []:
        lines.append(f"VEX document: {_recorded_label(vex['file'])}")
    for expression in record.get("failOn") or []:
        lines.append(f"--fail-on {expression}")
    for warning in document.get("warnings") or []:
        lines.append(f"Warning: {warning}")
    summary = document.get("summary") or {}
    lines.append(
        f"Findings: {findings_count}, suppressed by decisions: {summary.get('suppressed', 0)}"
    )
    if document.get("baseline") is not None:
        lines.append(
            f"New against the baseline: {summary.get('new', 0)}, "
            f"existing: {summary.get('existing', 0)}"
        )
    triage = document.get("triage") or {}
    for report in triage.get("expired") or []:
        described = TriageEntry(index=0, state="", **report["selector"]).describe()
        lines.append(
            f"Expired decision {report['handle']} ({described}) expired "
            f"{report.get('expires')}: would match {len(report['findings'])} finding(s)"
        )
    for report in triage.get("stale") or []:
        described = TriageEntry(index=0, state="", **report["selector"]).describe()
        lines.append(
            f"Stale decision {report['handle']} ({described}): matches no finding in this scan"
        )
    for report in triage.get("shadowed") or []:
        described = TriageEntry(index=0, state="", **report["selector"]).describe()
        lines.append(
            f"Shadowed decision {report['handle']} ({described}): another "
            f"decision decides {len(report['findings'])} finding(s) it matches"
        )
    for report in triage.get("proposals") or []:
        described = TriageEntry(index=0, state="", **report["selector"]).describe()
        lines.append(
            f"Pending proposal {report['handle']} ({described}): "
            f"{report['state']} proposed by {report.get('proposedBy')}, approve with "
            f"depscan triage review --approve {report['handle']}"
        )
    for result in document.get("results") or []:
        line = f"Gate {_STATUS_WORDS.get(result['status'], result['status'])}: {result['id']}"
        if result.get("kind") == "require":
            line += f" (require {result.get('capability')}"
            if result.get("projectType"):
                line += f" for {result['projectType']}"
            line += ")"
        elif result.get("description"):
            line += f" ({result['description']})"
        if result.get("findings"):
            line += f", matched {len(result['findings'])} finding(s)"
        if result.get("reason"):
            line += f": {result['reason']}"
        lines.append(line)
    exit_code = gate_exit(document)
    lines.append(
        "Gate exit code: "
        + (
            str(exit_code)
            if exit_code
            else "0 (no fail-action expectation matched and no requirement failed)"
        )
    )
    return lines


def print_block(document: Optional[Dict[str, Any]], findings_count: int) -> None:
    """Print the decisions and gate block on the console. The lines are
    escaped, because selectors and reasons are file content and never
    console markup."""
    if not document:
        return
    from rich.markup import escape

    from depscan.lib.logger import console

    console.print()
    console.rule("Decisions and gate")
    for line in block_lines(document, findings_count):
        console.print(escape(line))
