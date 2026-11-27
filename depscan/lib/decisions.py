"""The decisions file as the scan and report verbs use it.

This module resolves which decisions file applies to a run (the command
line, the environment, the project or user ``depscan.toml``, or the scanned
directory's own ``.depscan/decisions.toml``), loads the VEX documents the
``--vex`` option names into triage decisions, and maps a gate result onto
the run's exit code beside the scan's own. The selection, loading and
validation all live in :mod:`analysis_lib.findings.decisions`; nothing here
duplicates them.
"""

import json
import os
from typing import Any, Dict, List, Optional, Tuple

from analysis_lib.findings.decisions import DecisionsError, _parse_rfc3339

from depscan.lib.logger import LOG

#: The environment variable that names a decisions file.
DECISIONS_ENV = "DEPSCAN_DECISIONS"

#: The location of a user's depscan configuration, consulted for the
#: decisions key when the project file does not name one.
USER_CONFIG = os.path.join("~", ".config", "depscan", "depscan.toml")


class DecisionsUsageError(ValueError):
    """A decisions file, VEX document or baseline option the verb refuses.

    The message is the one the verb prints; the exit code is 2.
    """


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
    value = None
    if isinstance(scan_section, dict):
        value = scan_section.get("decisions")
    if value is None:
        value = document.get("decisions")
    if not isinstance(value, str) or not value.strip():
        return None
    value = value.strip()
    if not os.path.isabs(value):
        value = os.path.join(os.path.dirname(os.path.abspath(path)), *value.replace("\\", "/").split("/"))
    return value


def resolve_decisions_path(
    option_value: Optional[str], target_dir: Optional[str]
) -> Tuple[Optional[str], str]:
    """Which decisions file applies, and what selected it.

    The precedence is the command line, then the environment, then the
    project ``depscan.toml``, then the user's, then the scanned directory's
    own ``.depscan/decisions.toml``. A target that is not a directory reads
    a file only when one is named: an image, a BOM or a purl has no
    repository to hold one.

    :returns: ``(path, selected_by)`` where ``selected_by`` is one of
        option, environment, project-config, user-config or default, and the
        path is None when nothing applies.
    """
    if option_value:
        return option_value, "option"
    from_env = os.getenv(DECISIONS_ENV)
    if from_env:
        return from_env, "environment"
    project_config = os.getenv("DEPSCAN_CONFIG") or os.path.join(os.getcwd(), ".config", "depscan.toml")
    if os.path.isfile(project_config):
        from_config = _config_decisions_key(project_config)
        if from_config:
            return from_config, "project-config"
    user_config = os.path.expanduser(USER_CONFIG)
    if os.path.isfile(user_config):
        from_user = _config_decisions_key(user_config)
        if from_user:
            return from_user, "user-config"
    if target_dir and os.path.isdir(target_dir):
        default = os.path.join(target_dir, ".depscan", "decisions.toml")
        if os.path.isfile(default):
            return default, "default"
    return None, "default"


def load_decisions_for_run(
    option_value: Optional[str],
    target_dir: Optional[str],
    *,
    vex_files: Optional[List[str]] = None,
) -> Optional[Any]:
    """Load the decisions a scan or report applies, VEX documents included.

    :raises DecisionsUsageError: When a named file or a VEX document cannot
        be read or breaks its schema; the verb exits 2 with the message.
    """
    from analysis_lib.findings.decisions import DecisionsError, load_decisions

    path, selected_by = resolve_decisions_path(option_value, target_dir)
    decisions = None
    if path:
        try:
            decisions = load_decisions(path, selected_by=selected_by)
        except DecisionsError as exc:
            raise DecisionsUsageError(f"depscan: {exc}") from exc
    if vex_files:
        entries = []
        for vex_file in vex_files:
            try:
                entries.extend(load_vex_decisions(vex_file))
            except DecisionsError as exc:
                raise DecisionsUsageError(f"depscan: {exc}") from exc
        if decisions is None:
            from analysis_lib.findings.decisions import Decisions

            decisions = Decisions(selected_by=selected_by)
        decisions.triage.extend(entries)
    return decisions


def load_vex_decisions(path: str) -> List[Any]:
    """Load a CycloneDX VEX or OpenVEX document as triage decisions.

    Every statement becomes an entry whose ``proposed_by`` names the
    document, so it applies like a person-entered decision: the document is
    itself the record of a decision. CycloneDX statements take the analysis
    state, justification and responses from the entry; OpenVEX statements
    map their status and justification onto the CycloneDX vocabulary. A
    statement that names no finding this tool can read is reported as stale
    when the decisions are applied, and never silently dropped.

    :raises analysis_lib.findings.decisions.DecisionsError: When the file
        cannot be read as either format.
    """
    try:
        with open(path, encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, ValueError) as exc:
        raise DecisionsError(f"the VEX document '{path}' cannot be read: {exc}") from exc
    if not isinstance(document, dict):
        raise DecisionsError(f"the VEX document '{path}' is not a JSON object")
    name = os.path.basename(path)
    if document.get("bomFormat") == "CycloneDX" or (
        isinstance(document.get("$schema"), str) and "cyclonedx" in document["$schema"].lower()
    ):
        entries = _cyclonedx_vex_entries(document, name)
    elif isinstance(document.get("statements"), list):
        entries = _openvex_entries(document, name)
    else:
        raise DecisionsError(
            f"the VEX document '{path}' is neither a CycloneDX document nor an "
            "OpenVEX document: no bomFormat of CycloneDX and no statements array"
        )
    for entry in entries:
        entry.source = f"VEX document {name}"
    return entries


def _cyclonedx_component_purls(document: Dict[str, Any]) -> Dict[str, str]:
    """Map a CycloneDX document's bom-refs to the purls they name, the
    component tree included."""
    refs: Dict[str, str] = {}

    def walk(components: Any) -> None:
        if not isinstance(components, list):
            return
        for component in components:
            if not isinstance(component, dict):
                continue
            ref = component.get("bom-ref")
            purl = component.get("purl")
            if isinstance(ref, str) and isinstance(purl, str) and ref not in refs:
                refs[ref] = purl
            walk(component.get("components"))

    walk(document.get("components"))
    metadata = document.get("metadata")
    if isinstance(metadata, dict):
        walk(metadata.get("components"))
    return refs


def _cyclonedx_vex_entries(document: Dict[str, Any], name: str) -> List[Any]:
    """The triage entries of a CycloneDX VEX document.

    The statement's analysis values are the CycloneDX vocabulary already, so
    they carry over as they stand; the affected component is named by a
    bom-ref that the document's component tree resolves to a purl.
    """
    from analysis_lib.findings.decisions import (
        JUSTIFICATIONS,
        RESPONSES,
        TriageEntry,
        TRIAGE_STATES,
    )

    entries: List[Any] = []
    for index, vuln in enumerate(document.get("vulnerabilities") or []):
        if not isinstance(vuln, dict):
            continue
        analysis = vuln.get("analysis")
        if not isinstance(analysis, dict) or not analysis.get("state"):
            continue
        state = str(analysis["state"])
        if state not in TRIAGE_STATES:
            continue
        justification = analysis.get("justification")
        if justification is not None and justification not in JUSTIFICATIONS:
            justification = None
        responses = [
            str(value) for value in analysis.get("response") or [] if value in RESPONSES
        ]
        advisories = str(vuln.get("id") or "").strip()
        refs = _cyclonedx_component_purls(document)
        affects = [
            affect.get("ref")
            for affect in vuln.get("affects") or []
            if isinstance(affect, dict) and isinstance(affect.get("ref"), str)
        ]
        detail = analysis.get("detail")
        for ref in affects or [""]:
            purl = refs.get(ref, ref if str(ref).startswith("pkg:") else None)
            entry = TriageEntry(
                index=len(entries) + 1,
                state=state,
                advisory=advisories or None,
                purl=purl,
                justification=justification,
                responses=responses,
                detail=str(detail) if detail else None,
                author=name,
                proposed_by=f"VEX document {name}",
            )
            entries.append(entry)
    return entries


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


def _openvex_entries(document: Dict[str, Any], name: str) -> List[Any]:
    """The triage entries of an OpenVEX document.

    A statement's products are package URLs when they name one; a product
    that names no purl still becomes an entry, whose selector matches
    nothing and which the application reports as stale, so the document's
    reader sees what the tool could not place.
    """
    from analysis_lib.findings.decisions import TriageEntry

    entries: List[Any] = []
    for statement in document.get("statements") or []:
        if not isinstance(statement, dict):
            continue
        status = str(statement.get("status") or "")
        state = _OPENVEX_STATUS.get(status)
        if state is None:
            continue
        vulnerability = statement.get("vulnerability")
        advisories = None
        if isinstance(vulnerability, dict):
            advisories = str(vulnerability.get("name") or "").strip() or None
        elif isinstance(vulnerability, str):
            advisories = vulnerability.strip() or None
        justification = _OPENVEX_JUSTIFICATION.get(str(statement.get("justification") or ""))
        detail = statement.get("detail")
        timestamp = statement.get("timestamp")
        created = str(timestamp) if isinstance(timestamp, str) and _parse_rfc3339(timestamp) else None
        expires = statement.get("expires")
        products = statement.get("products") or []
        if isinstance(products, str):
            products = [products]
        for product in products:
            purl = None
            if isinstance(product, dict):
                product = product.get("id")
            if isinstance(product, str) and product.startswith("pkg:"):
                purl = product
            entry = TriageEntry(
                index=len(entries) + 1,
                state=state,
                advisory=advisories,
                purl=purl,
                justification=justification,
                detail=str(detail) if detail else None,
                author=name,
                proposed_by=f"VEX document {name}",
                created=created,
                expires=str(expires) if isinstance(expires, str) and _parse_rfc3339(expires) else None,
            )
            entries.append(entry)
    return entries


def gate_exit(document: Optional[Dict[str, Any]]) -> int:
    """The exit code a gate result adds to a run: 4 when a required
    capability was not assessed, 3 when a fail-action expectation matched,
    else 0."""
    from analysis_lib.findings.decisions import gate_exit_from_document

    if not document:
        return 0
    return gate_exit_from_document(document)


def combine_exit(scan_exit: int, gate_exit_code: int) -> int:
    """The exit code of one scan whose gate ran.

    A scan that stopped (1) or was misused (2) keeps its code and wins over
    the gate; otherwise the gate's code is the scan's.
    """
    if scan_exit in (1, 2):
        return scan_exit
    return gate_exit_code


def combine_run_exit(exit_codes: List[int]) -> int:
    """The exit code of a run of several scans.

    Codes 1 and 2 keep their meaning and win over the gate codes, as for a
    single scan; 4 wins over 3, because a gate over missing coverage cannot
    be trusted; the highest remaining code stands.
    """
    if 2 in exit_codes:
        return 2
    if 1 in exit_codes:
        return 1
    return max(exit_codes) if exit_codes else 0


def log_decisions_summary(decisions) -> None:
    """Log what the run loaded, so a reader of the log sees the file and its
    selection."""
    if decisions is None:
        return
    if decisions.path:
        LOG.info(
            "Decisions file %s selected by %s: %d triage entries, %d expectations, "
            "%d requirements",
            decisions.path,
            decisions.selected_by,
            len(decisions.triage),
            len(decisions.expects),
            len(decisions.requires),
        )
    else:
        LOG.info(
            "Decisions from the command line: %d expectations", len(decisions.expects)
        )
