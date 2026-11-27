"""The decisions file: triage decisions, the baseline and the gate.

One file per repository, ``.depscan/decisions.toml``, holds three kinds of
statement people make about findings: triage decisions keyed by finding or
advisory and package, the baseline that marks every finding new or existing,
and the expectations the gate evaluates. This module is the one loader, the
one selector grammar and the one evaluator for that file, shared by the scan
pipeline, ``depscan report``, ``depscan triage`` and the ``get_decisions``
server tool, so a decision reads the same everywhere and the CI line and the
file are one language.

Matching uses the finding identities the scan already carries: ``dsf1``
fingerprints for findings and ``comparable_purl`` with the version handling
the purl parsing gives for components. Nothing here invents a second scheme.
The JSON Schema ``depscan-decisions`` is the contract for the parsed file;
:func:`load_decisions` refuses a file that breaks it, naming the key, the
line and the valid values, the way a configuration error is reported.

The gate evaluation reads the findings document and the manifest stages of
one scan directory and produces the ``depscan-expectations`` document. It
never changes a finding: triage decisions are applied to findings by
:func:`apply_triage` before the gate runs, and suppressed findings stay in
the findings document with their triage state.
"""

import hashlib
import json
import os
import re
import tomllib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from analysis_lib.findings.fingerprint import normalise_purl, normalise_rule
from analysis_lib.findings.schemas import validation_errors
from analysis_lib.findings.vdr_convert import comparable_purl

#: The published name of the decisions file schema.
DECISIONS_SCHEMA = "depscan-decisions"

#: The published name of the gate result schema.
EXPECTATIONS_SCHEMA = "depscan-expectations"

#: The findings document inside a scan directory.
FINDINGS_FILE = "depscan.findings.json"

#: The gate result file inside a scan directory.
EXPECTATIONS_FILE = "depscan.expectations.json"

#: The triage states of the CycloneDX 1.7 vocabulary.
TRIAGE_STATES = (
    "resolved",
    "resolved_with_pedigree",
    "exploitable",
    "in_triage",
    "false_positive",
    "not_affected",
)

#: The states that suppress a finding from the gate. ``in_triage`` and
#: ``exploitable`` never suppress; ``resolved_with_pedigree`` is kept out of
#: this tuple until the maintainer confirms it belongs with ``resolved``,
#: because a pedigree that is not verified is not a shipped fix.
SUPPRESSING_STATES = ("not_affected", "false_positive", "resolved")

#: The CycloneDX 1.7 impact analysis justifications.
JUSTIFICATIONS = (
    "code_not_present",
    "code_not_reachable",
    "requires_configuration",
    "requires_dependency",
    "requires_environment",
    "protected_by_compiler",
    "protected_at_runtime",
    "protected_at_perimeter",
    "protected_by_mitigating_control",
)

#: The CycloneDX 1.7 responses.
RESPONSES = ("can_not_fix", "will_not_fix", "update", "rollback", "workaround_available")

#: CycloneDX severity names, most severe first, for the severity floor.
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info", "unknown")

#: The exploitability grades, most severe first, for the grade floor.
GRADE_ORDER = ("critical", "high", "moderate", "low", "shielded", "unassessed")

#: The producer confidences, most confident first, for the confidence floor.
CONFIDENCE_ORDER = ("high", "medium", "low")

#: The reach axis values each reach selector matches. A reach assessed as
#: ``unknown`` (analyzers ran, the package was not observed) matches none,
#: because an unobserved package is not a refuted one.
REACH_SELECTOR_VALUES = {
    "reached": frozenset({"proven", "likely"}),
    "not_reached": frozenset({"unlikely", "refuted"}),
    "not_assessed": frozenset({"not_assessed"}),
}

#: The selector keys of an expect entry and the --fail-on grammar, in the
#: order the documentation lists them.
SELECTOR_KEYS = (
    "category",
    "severity",
    "grade",
    "reach",
    "malware",
    "rule",
    "purl",
    "confidence",
    "new",
)

#: The finding categories, mirrored from the fingerprint module's table.
CATEGORIES = (
    "vulnerability",
    "malware",
    "memory-safety",
    "supply-chain",
    "binary-hardening",
    "mobile",
    "code",
    "license",
    "crypto",
    "health",
)


class DecisionsError(ValueError):
    """A decisions file, a VEX input or a baseline reference was refused.

    The message names every problem, each with its key, its 1-based line in
    the file and, for a constrained value, the valid values. A caller shows
    the message as it stands; nothing needs to be assembled from the
    attributes.
    """


class BaselineError(DecisionsError):
    """A baseline reference could not be read or its digest did not match.

    The scan stops with this reason instead of turning every finding into a
    new one.
    """


@dataclass
class TriageEntry:
    """One triage decision: a selector plus the CycloneDX analysis values
    and the people in the decision."""

    index: int
    state: str
    finding: Optional[str] = None
    advisory: Optional[str] = None
    purl: Optional[str] = None
    version_range: Optional[str] = None
    justification: Optional[str] = None
    responses: List[str] = field(default_factory=list)
    detail: Optional[str] = None
    author: Optional[str] = None
    approver: Optional[str] = None
    proposed_by: Optional[str] = None
    created: Optional[str] = None
    expires: Optional[str] = None
    #: Where the entry came from: the decisions file, or the name of the VEX
    #: document it was loaded from.
    source: str = "decisions file"

    @property
    def is_proposal(self) -> bool:
        """Whether this entry is a proposal: proposed by someone, and neither
        approved nor entered by a person."""
        return bool(self.proposed_by) and not self.approver and not self.author

    @property
    def suppresses(self) -> bool:
        """Whether a live entry with this state suppresses findings from the
        gate."""
        return self.state in SUPPRESSING_STATES

    def selector_document(self) -> Dict[str, Any]:
        """The selector as the file carries it, for reports and listings."""
        selector: Dict[str, Any] = {}
        if self.finding:
            selector["finding"] = self.finding
        if self.advisory:
            selector["advisory"] = self.advisory
        if self.purl:
            selector["purl"] = self.purl
        if self.version_range:
            selector["version_range"] = self.version_range
        return selector

    def to_triage_document(self) -> Dict[str, Any]:
        """The triage object this decision writes into a finding, the shape
        the finding schema's triage object publishes."""
        document: Dict[str, Any] = {"state": self.state}
        if self.justification:
            document["justification"] = self.justification
        if self.responses:
            document["responses"] = list(self.responses)
        if self.detail:
            document["detail"] = self.detail
        if self.author:
            document["author"] = self.author
        if self.approver:
            document["approver"] = self.approver
        if self.proposed_by:
            document["proposed_by"] = self.proposed_by
        if self.expires:
            document["expires"] = self.expires
        return document

    def describe(self) -> str:
        """A one-line description of the selector, for messages."""
        if self.finding:
            return f"finding {self.finding}"
        parts = [f"advisory {self.advisory}", f"purl {self.purl}"]
        if self.version_range:
            parts.append(f"range {self.version_range}")
        return ", ".join(parts)


@dataclass
class ExpectEntry:
    """One expectation the gate evaluates: selectors combined with AND, and
    the action to take when they match."""

    id: str
    action: str
    selectors: Dict[str, Any] = field(default_factory=dict)
    description: Optional[str] = None
    #: Whether the entry came from the decisions file or --fail-on.
    from_command_line: bool = False


@dataclass
class RequireEntry:
    """One capability that must have been assessed, optionally for one
    project type."""

    capability: str
    id: str = ""
    description: Optional[str] = None
    project_type: Optional[str] = None

    def __post_init__(self):
        if not self.id:
            derived = f"require-{self.capability}"
            if self.project_type:
                derived = f"{derived}-{self.project_type}"
            self.id = derived


@dataclass
class BaselineSpec:
    """The baseline reference: a scan directory or a findings file, relative
    to the decisions file when it came from there."""

    scan: str
    digest: Optional[str] = None


@dataclass
class Decisions:
    """The loaded decisions: the triage entries, the baseline and the gate."""

    triage: List[TriageEntry] = field(default_factory=list)
    expects: List[ExpectEntry] = field(default_factory=list)
    requires: List[RequireEntry] = field(default_factory=list)
    baseline: Optional[BaselineSpec] = None
    #: The file the decisions were loaded from, None for a document built
    #: from command-line options only.
    path: Optional[str] = None
    #: The SHA-256 hex digest of that file.
    digest: Optional[str] = None
    #: What selected the file: default, option, environment, project-config
    #: or user-config.
    selected_by: str = "default"

    @property
    def has_gate(self) -> bool:
        """Whether a gate would run: any expectation or requirement exists."""
        return bool(self.expects or self.requires)

    @property
    def has_decisions(self) -> bool:
        """Whether anything would change or be checked: any triage entry, a
        baseline or a gate."""
        return bool(self.triage or self.baseline or self.has_gate)


def _parse_rfc3339(value: str) -> Optional[datetime]:
    """Parse an RFC 3339 date-time; a naive value is read as UTC."""
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def is_expired(expires: Optional[str], now: Optional[datetime] = None) -> bool:
    """Whether the expiry date-time is in the past. A value that cannot be
    parsed never counts as expired; the schema refuses it at load time."""
    if not expires:
        return False
    parsed = _parse_rfc3339(expires)
    if parsed is None:
        return False
    return parsed < (now or datetime.now(timezone.utc))


# --- loading ----------------------------------------------------------------------


_HEADER = re.compile(r"^\s*\[\[?([A-Za-z0-9_.-]+)\]\]?")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PURL = re.compile(r"^pkg:", re.IGNORECASE)
_DSF = re.compile(r"^dsf1:[0-9a-f]{64}$")


def _table_entry_spans(text: str) -> Dict[Tuple[str, int], int]:
    """Map each top-level table occurrence to its 0-based line.

    The key is the table name with its occurrence number among the tables of
    that name, so ``("triage", 2)`` is the third ``[[triage]]`` header.
    """
    spans: Dict[Tuple[str, int], int] = {}
    counts: Dict[str, int] = {}
    for index, line in enumerate(text.splitlines()):
        match = _HEADER.match(line)
        if not match:
            continue
        name = match.group(1)
        occurrence = counts.get(name, 0)
        counts[name] = occurrence + 1
        spans[(name, occurrence)] = index
    return spans


def _line_for_path(text: str, path: Sequence[Any]) -> Optional[int]:
    """The 1-based line a document path is written on.

    ``("triage", 2, "state")`` is the ``state`` key of the third
    ``[[triage]]`` entry; a key that appears on no line of the entry, a
    missing required key among them, reports the entry's header line.
    """
    lines = text.splitlines()
    if not path:
        return 1
    name = str(path[0])
    spans = _table_entry_spans(text)
    occurrences = sorted(index for (table, index) in spans if table == name)
    if not occurrences:
        return None
    occurrence = path[1] if len(path) > 1 and isinstance(path[1], int) else 0
    if occurrence >= len(occurrences):
        return None
    start = spans[(name, occurrence)]
    ends = [line for line in spans.values() if line > start]
    end = min(ends) if ends else len(lines)
    if len(path) > 2 and isinstance(path[2], str):
        key_line = re.compile(rf"^\s*{re.escape(path[2])}\s*=")
        for index in range(start, end):
            if key_line.match(lines[index]):
                return index + 1
    return start + 1


def _valid_values_at(schema: Dict[str, Any], path: Sequence[Any]) -> List[str]:
    """The enum values of the subschema a document path points at, so an
    invalid value can be refused with the values it could have been."""
    node: Any = schema
    for part in path:
        if isinstance(part, int):
            items = node.get("items") if isinstance(node, dict) else None
            if isinstance(items, dict):
                node = items
                continue
            return []
        properties = node.get("properties") if isinstance(node, dict) else None
        if not isinstance(properties, dict) or part not in properties:
            return []
        node = properties[part]
    values = node.get("enum") if isinstance(node, dict) else None
    return [str(value) for value in values] if values else []


def _schema_error_messages(text: str, schema: Dict[str, Any], errors: Sequence[Any]) -> List[str]:
    """Every schema violation as a one-line message with its key, line and
    valid values."""
    messages = []
    for error in errors:
        path = list(error.path)
        message = error.message
        line = _line_for_path(text, path)
        # An additional-properties violation names the unexpected key in its
        # message instead of its path; the key's own line is the report.
        if line is not None and "Additional properties are not allowed" in message:
            for name in re.findall(r"'([^']+)'", message):
                keyed = _line_for_path(text, [*path, name])
                if keyed != line:
                    line = keyed
                    break
        where = "/".join(str(part) for part in path) or "<file>"
        prefix = f"line {line}: " if line else ""
        valid = _valid_values_at(schema, path)
        if valid:
            message = f"{message}; valid values: {', '.join(valid)}"
        messages.append(f"{prefix}{where}: {message}")
    return messages


def _decode_error_message(exc: tomllib.TOMLDecodeError) -> str:
    """A TOML syntax error, passed through with its own line information."""
    return f"the decisions file is not valid TOML: {exc}"


def _check_semantics(document: Dict[str, Any], text: str) -> List[str]:
    """The checks the schema cannot express: the CycloneDX rule that a
    not_affected state carries a justification, that the date-times the
    runtime parses later are parseable, and that every version range is a
    range the vers grammar reads."""
    problems = []
    for index, entry in enumerate(document.get("triage") or []):
        if entry.get("state") == "not_affected" and not entry.get("justification"):
            line = _line_for_path(text, ("triage", index, "state"))
            problems.append(
                f"line {line}: triage/{index}/justification: a not_affected state needs a "
                f"justification; valid values: {', '.join(JUSTIFICATIONS)}"
            )
        for key in ("created", "expires"):
            value = entry.get(key)
            if isinstance(value, str) and _parse_rfc3339(value) is None:
                line = _line_for_path(text, ("triage", index, key))
                problems.append(
                    f"line {line}: triage/{index}/{key}: {value!r} is not an RFC 3339 date-time"
                )
        version_range = entry.get("version_range")
        if isinstance(version_range, str) and not vers_range_is_valid(version_range):
            line = _line_for_path(text, ("triage", index, "version_range"))
            problems.append(
                f"line {line}: triage/{index}/version_range: {version_range!r} is not a "
                "vers range, for example vers:npm/>=4.17.0|<4.17.21"
            )
    for index, entry in enumerate(document.get("expect") or []):
        version_range = entry.get("version_range")
        if isinstance(version_range, str) and not vers_range_is_valid(version_range):
            line = _line_for_path(text, ("expect", index, "version_range"))
            problems.append(
                f"line {line}: expect/{index}/version_range: {version_range!r} is not a "
                "vers range, for example vers:npm/>=4.17.0|<4.17.21"
            )
    return problems


def parse_decisions_document(text: str) -> Dict[str, Any]:
    """Parse the TOML text and validate it against the published schema.

    Raises :class:`DecisionsError` naming every problem, each with its key,
    line and valid values, when the file is not usable.
    """
    try:
        document = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise DecisionsError(_decode_error_message(exc)) from exc
    schema = _load_schema_document(DECISIONS_SCHEMA)
    problems = _schema_error_messages(text, schema, validation_errors(DECISIONS_SCHEMA, document))
    problems.extend(_check_semantics(document, text))
    if problems:
        raise DecisionsError("the decisions file was refused:\n" + "\n".join(problems))
    return document


def _entry_from_document(index: int, entry: Dict[str, Any]) -> TriageEntry:
    return TriageEntry(
        index=index + 1,
        state=str(entry["state"]),
        finding=entry.get("finding"),
        advisory=entry.get("advisory"),
        purl=entry.get("purl"),
        version_range=entry.get("version_range"),
        justification=entry.get("justification"),
        responses=[str(value) for value in entry.get("responses") or []],
        detail=entry.get("detail"),
        author=entry.get("author"),
        approver=entry.get("approver"),
        proposed_by=entry.get("proposed_by"),
        created=entry.get("created"),
        expires=entry.get("expires"),
    )


def decisions_from_document(document: Dict[str, Any], *, path: Optional[str] = None) -> Decisions:
    """Build the loaded decisions from a validated document.

    The caller is responsible for validation, through
    :func:`parse_decisions_document` or the published schema; the command
    line builds documents this way too, without a file behind them.
    """
    triage = [
        _entry_from_document(index, entry)
        for index, entry in enumerate(document.get("triage") or [])
    ]
    expects = [
        ExpectEntry(
            id=str(entry["id"]),
            action=str(entry["action"]),
            selectors={key: entry[key] for key in SELECTOR_KEYS if key in entry},
            description=entry.get("description"),
        )
        for entry in document.get("expect") or []
    ]
    requires = [
        RequireEntry(
            capability=str(entry["capability"]),
            id=str(entry["id"]) if entry.get("id") else "",
            description=entry.get("description"),
            project_type=entry.get("project_type"),
        )
        for entry in document.get("require") or []
    ]
    baseline = None
    if isinstance(document.get("baseline"), dict):
        baseline = BaselineSpec(
            scan=str(document["baseline"]["scan"]),
            digest=document["baseline"].get("digest"),
        )
    return Decisions(
        triage=triage, expects=expects, requires=requires, baseline=baseline, path=path
    )


def load_decisions(path: str, *, selected_by: str = "default") -> Decisions:
    """Load and validate the decisions file at ``path``.

    :param path: The file to read.
    :param selected_by: Recorded on the decisions, saying what picked the
        file: default, option, environment, project-config or user-config.
    :returns: The loaded decisions, carrying the file's SHA-256 digest.
    :raises DecisionsError: When the file cannot be read or breaks its
        schema; the message names every problem with its key and line.
    """
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError as exc:
        raise DecisionsError(
            f"the decisions file '{path}' cannot be read: {exc.strerror or exc}"
        ) from exc
    text = raw.decode("utf-8")
    document = parse_decisions_document(text)
    decisions = decisions_from_document(document, path=path)
    decisions.digest = hashlib.sha256(raw).hexdigest()
    decisions.selected_by = selected_by
    return decisions


def _load_schema_document(name: str) -> Dict[str, Any]:
    from analysis_lib.findings.schemas import load_schema

    return load_schema(name)


# --- selectors --------------------------------------------------------------------


def purl_identity(purl: str) -> str:
    """The type, namespace and name of a purl, folded the way finding
    fingerprints fold them: percent-encoding, qualifiers, subpath and version
    out, packageurl's per-type normalisation in."""
    return normalise_purl(purl)


def _purl_head(purl: str) -> str:
    """A comparable purl without its version segment.

    The version starts after the slash that ends the namespace and name, so
    an ``@`` inside a namespace (an npm scoped package) never reads as a
    version marker.
    """
    comparable = comparable_purl(purl)
    slash = comparable.rfind("/")
    at = comparable.find("@", slash + 1)
    return comparable[:at] if at != -1 else comparable


def purl_version(purl: str) -> Optional[str]:
    """The decoded version of a purl, None when it names none."""
    comparable = comparable_purl(purl)
    slash = comparable.rfind("/")
    at = comparable.find("@", slash + 1)
    if at == -1:
        return None
    return comparable[at + 1 :] or None


def vers_range_matches(version: Optional[str], version_range: str) -> bool:
    """Whether a version is inside a vers-syntax range.

    A version the range grammar cannot compare never matches, so a range
    that cannot be read narrows instead of matching everything.
    """
    if not version:
        return False
    from vdb.lib.vers import vers_compare

    return bool(vers_compare(version, version_range))


def vers_range_is_valid(version_range: str) -> bool:
    """Whether a vers range parses. Used to refuse a range at load time.

    The file grammar requires the full vers form with its scheme, so a
    range is unambiguous about which ecosystem's version rules compare it;
    a bare constraint list is refused with the vers example in the message.
    """
    from vdb.lib.vers import VersionRange, VersError

    try:
        VersionRange.from_string(version_range.strip())
    except VersError:
        return False
    return True


def _identity_equal(component: str, selector_purl: str) -> bool:
    """Whether two purls name the same package.

    The fingerprint normalisation folds percent-encoding, qualifiers and the
    per-type case rules packageurl applies; NuGet ids are case-insensitive
    in a way packageurl keeps, and comparable_purl folds their case, so a
    nuget pair compares in its comparable form.
    """
    try:
        if purl_identity(component) == purl_identity(selector_purl):
            return True
    except ValueError:
        pass
    if comparable_purl(component).lower().startswith("pkg:nuget/"):
        return _purl_head(component) == _purl_head(selector_purl)
    return False


def _component_matches_purl(
    component: str, selector_purl: str, version_range: Optional[str]
) -> bool:
    """Whether one component purl satisfies a selector purl.

    The identity (type, namespace, name) must be equal after normalisation.
    A version in the selector pins the component's version exactly, and a
    version range narrows further.
    """
    if not _identity_equal(component, selector_purl):
        return False
    selector_version = purl_version(selector_purl)
    if selector_version is not None and purl_version(component) != selector_version:
        return False
    if version_range and not vers_range_matches(purl_version(component), version_range):
        return False
    return True


def _floor_matches(value: Optional[str], floor: str, order: Sequence[str]) -> bool:
    """Whether a value is at a floor or more severe. A value outside the
    order, an absent value included, never matches."""
    if value not in order or floor not in order:
        return False
    return order.index(value) <= order.index(floor)


def _reach_of(finding: Dict[str, Any]) -> Optional[str]:
    """The reach axis value of a finding, None without an exploitability
    assessment."""
    exploitability = finding.get("exploitability")
    if not isinstance(exploitability, dict):
        return None
    axes = exploitability.get("axes")
    if not isinstance(axes, dict):
        return None
    return axes.get("reach")


def finding_matches_selectors(
    finding: Dict[str, Any],
    selectors: Dict[str, Any],
    *,
    alias_ids: Optional[Set[str]] = None,
    has_baseline: bool = False,
) -> bool:
    """Whether one finding document matches every selector.

    ``alias_ids`` are the advisory ids the finding answers to, its own rule
    id included, lower-cased; without them only the rule id itself is
    compared. ``has_baseline`` says the run compared with a baseline, which
    the ``new`` selector needs; without one the selector matches nothing and
    the gate reports the entry as not evaluated, so a selector the caller
    cannot satisfy never passes silently.
    """
    for key, value in selectors.items():
        if value is None:
            continue
        if key == "category":
            if finding.get("category") != value:
                return False
        elif key == "severity":
            if not _floor_matches(finding.get("severity"), str(value), SEVERITY_ORDER):
                return False
        elif key == "grade":
            grade = (finding.get("exploitability") or {}).get("grade") or "unassessed"
            if not _floor_matches(grade, str(value), GRADE_ORDER):
                return False
        elif key == "reach":
            # A finding graded without a reach axis, exploitability absent
            # included, was not assessed for reach.
            reach = _reach_of(finding) or "not_assessed"
            if reach not in REACH_SELECTOR_VALUES.get(str(value), frozenset()):
                return False
        elif key == "malware":
            if (finding.get("category") == "malware") is not bool(value):
                return False
        elif key == "rule":
            wanted = {normalise_rule(str(rule)).lower() for rule in value}
            rule = normalise_rule(str(finding.get("rule") or "")).lower()
            if rule not in wanted and not (alias_ids and (wanted & alias_ids)):
                return False
        elif key == "purl":
            components = finding.get("components") or []
            if not any(
                _component_matches_purl(str(component), str(value), selectors.get("version_range"))
                for component in components
            ):
                return False
        elif key == "confidence":
            if not _floor_matches(finding.get("confidence"), str(value), CONFIDENCE_ORDER):
                return False
        elif key == "new":
            if not has_baseline:
                return False
            if (finding.get("baseline") == "new") is not bool(value):
                return False
    return True


def alias_ids_for_vuln(vuln: Dict[str, Any]) -> Set[str]:
    """Every advisory id a VDR entry answers to, lower-cased: its own id,
    the reference ids that name advisories and the advisory titles."""
    ids = set()
    primary = str(vuln.get("id") or "").strip()
    if primary:
        ids.add(normalise_rule(primary).lower())
    for reference in vuln.get("references") or []:
        if isinstance(reference, dict) and reference.get("id"):
            ids.add(normalise_rule(str(reference["id"])).lower())
    for advisory in vuln.get("advisories") or []:
        if not isinstance(advisory, dict):
            continue
        for token in str(advisory.get("title") or "").split():
            if re.match(r"^(CVE|GHSA)-", token, re.IGNORECASE):
                ids.add(normalise_rule(token).lower())
    return ids


def alias_map_key(rule: str) -> str:
    """The alias map's key for a rule id."""
    return normalise_rule(rule.strip()).lower()


def alias_map_from_vulns(vulns: Iterable[Dict[str, Any]]) -> Dict[str, Set[str]]:
    """Map every VDR entry's own id to the advisory ids it answers to.

    The findings document does not carry the reference ids, so the map is
    built from the VDR entries beside it and handed to matching; a caller
    without VDR entries passes no map and only exact rule ids match.
    """
    return {alias_map_key(str(vuln.get("id") or "")): alias_ids_for_vuln(vuln) for vuln in vulns}


def entry_matches_finding(
    entry: TriageEntry, finding: Dict[str, Any], *, alias_map: Optional[Dict[str, Set[str]]] = None
) -> bool:
    """Whether one triage decision selects one finding.

    A ``finding`` selector compares the dsf1 id exactly. An ``advisory``
    selector names the advisory id or an alias and needs ``purl``; it
    matches vulnerability findings whose rule or an alias is the advisory
    and whose components satisfy the purl and its optional version range.
    """
    if entry.finding:
        return finding.get("id") == entry.finding
    if finding.get("category") != "vulnerability":
        return False
    rule_key = alias_map_key(str(finding.get("rule") or ""))
    aliases = (alias_map or {}).get(rule_key) or {rule_key}
    if alias_map_key(entry.advisory or "") not in aliases:
        return False
    components = finding.get("components") or []
    return any(
        _component_matches_purl(str(component), str(entry.purl), entry.version_range)
        for component in components
    )


# --- applying triage ----------------------------------------------------------------


@dataclass
class EntryReport:
    """One triage entry the reader should look at, with what it matched."""

    entry: TriageEntry
    findings: List[str] = field(default_factory=list)

    def to_document(self) -> Dict[str, Any]:
        """The ``entryReport`` shape the expectations schema publishes."""
        document: Dict[str, Any] = {
            "index": self.entry.index,
            "selector": self.entry.selector_document(),
            "state": self.entry.state,
            "findings": list(self.findings),
        }
        if self.entry.author:
            document["author"] = self.entry.author
        if self.entry.approver:
            document["approver"] = self.entry.approver
        if self.entry.proposed_by:
            document["proposedBy"] = self.entry.proposed_by
        if self.entry.expires:
            document["expires"] = self.entry.expires
        return document


@dataclass
class TriageApplication:
    """What applying the triage decisions did to one findings list.

    ``applied`` counts the live decisions that set at least one finding,
    ``suppressed_ids`` the findings a live decision suppresses from the gate.
    Proposals set nothing and are listed as pending; expired decisions
    suppress nothing and name what they would have matched; a decision that
    matched nothing is stale.
    """

    applied: int = 0
    suppressed_ids: List[str] = field(default_factory=list)
    expired: List[EntryReport] = field(default_factory=list)
    stale: List[EntryReport] = field(default_factory=list)
    proposals: List[EntryReport] = field(default_factory=list)

    @property
    def suppressed(self) -> int:
        return len(self.suppressed_ids)

    def to_document(self) -> Dict[str, Any]:
        """The ``triage`` object the expectations document carries."""
        return {
            "applied": self.applied,
            "suppressed": self.suppressed,
            "expired": [report.to_document() for report in self.expired],
            "stale": [report.to_document() for report in self.stale],
            "proposals": [report.to_document() for report in self.proposals],
        }


def apply_triage(
    findings: List[Dict[str, Any]],
    entries: Sequence[TriageEntry],
    *,
    alias_map: Optional[Dict[str, Set[str]]] = None,
    now: Optional[datetime] = None,
) -> TriageApplication:
    """Apply the triage decisions to a findings list, in place.

    Every live decision, one that a person entered or approved and that has
    not expired, sets the ``triage`` object of each finding it selects; a
    state in :data:`SUPPRESSING_STATES` marks the finding suppressed from
    the gate. Proposals set nothing. Expired decisions suppress nothing and
    are reported with the findings they would have matched. Decisions that
    select nothing are reported as stale with their selector. Nothing is
    deleted: a suppressed finding stays in the list with its triage state.
    """
    application = TriageApplication()
    for entry in entries:
        matched = [
            finding
            for finding in findings
            if entry_matches_finding(entry, finding, alias_map=alias_map)
        ]
        if entry.is_proposal:
            application.proposals.append(
                EntryReport(entry=entry, findings=[str(f.get("id")) for f in matched])
            )
            continue
        if is_expired(entry.expires, now):
            application.expired.append(
                EntryReport(entry=entry, findings=[str(f.get("id")) for f in matched])
            )
            continue
        if not matched:
            application.stale.append(EntryReport(entry=entry))
            continue
        document = entry.to_triage_document()
        for finding in matched:
            finding["triage"] = document
            if entry.suppresses and finding.get("id") not in application.suppressed_ids:
                application.suppressed_ids.append(str(finding.get("id")))
        application.applied += 1
    return application


# --- baseline -----------------------------------------------------------------------


def read_baseline(spec: BaselineSpec, *, base_dir: Optional[str] = None) -> Set[str]:
    """The finding ids of a baseline findings document.

    ``spec.scan`` is a scan directory, whose ``depscan.findings.json`` is
    read, or the findings file itself. A relative path resolves against
    ``base_dir``, the decisions file's directory; an absolute path, a
    Windows drive included, is used as given. The optional digest is checked
    before the file is parsed, so a mismatch is refused as a digest problem
    and not as a parse failure.

    :raises BaselineError: When the file cannot be read, the digest does not
        match, or the document is not a findings document. A scan stops on
        this instead of marking every finding new.
    """
    scan = str(spec.scan).replace("\\", "/")
    if os.path.isabs(scan):
        path = scan
    elif base_dir:
        path = os.path.join(base_dir, *scan.split("/"))
    else:
        path = scan
    if os.path.isdir(path):
        path = os.path.join(path, FINDINGS_FILE)
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError as exc:
        raise BaselineError(
            f"the baseline '{spec.scan}' cannot be read ({exc.strerror or exc}); a scan "
            "with an unreadable baseline stops instead of marking every finding new"
        ) from exc
    if spec.digest:
        actual = hashlib.sha256(raw).hexdigest()
        if actual != spec.digest.lower():
            raise BaselineError(
                f"the baseline '{spec.scan}' does not match its recorded digest: the file "
                f"digest is {actual}, the decisions file names {spec.digest}"
            )
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise BaselineError(
            f"the baseline '{spec.scan}' is not a findings document: {exc}"
        ) from exc
    findings = document.get("findings") if isinstance(document, dict) else None
    if not isinstance(findings, list):
        raise BaselineError(
            f"the baseline '{spec.scan}' is not a findings document: no findings array"
        )
    return {
        finding["id"]
        for finding in findings
        if isinstance(finding, dict) and isinstance(finding.get("id"), str)
    }


def apply_baseline(findings: List[Dict[str, Any]], baseline_ids: Set[str]) -> Tuple[int, int]:
    """Mark every finding new or existing against the baseline ids, in
    place, and return the new and existing counts. A finding the baseline
    does not contain is new."""
    new = 0
    existing = 0
    for finding in findings:
        state = "existing" if finding.get("id") in baseline_ids else "new"
        finding["baseline"] = state
        if state == "new":
            new += 1
        else:
            existing += 1
    return new, existing


# --- the gate -----------------------------------------------------------------------


@dataclass
class ExpectationResult:
    """One expect or require entry's gate result."""

    kind: str
    id: str
    status: str
    findings: List[str] = field(default_factory=list)
    action: Optional[str] = None
    description: Optional[str] = None
    reason: Optional[str] = None
    capability: Optional[str] = None
    project_type: Optional[str] = None
    stages: List[Dict[str, Any]] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)

    def to_document(self) -> Dict[str, Any]:
        document: Dict[str, Any] = {
            "kind": self.kind,
            "id": self.id,
            "status": self.status,
            "findings": list(self.findings),
            "evidence": list(self.evidence),
        }
        if self.action:
            document["action"] = self.action
        if self.description:
            document["description"] = self.description
        if self.reason:
            document["reason"] = self.reason
        if self.capability:
            document["capability"] = self.capability
        if self.project_type:
            document["projectType"] = self.project_type
        if self.stages:
            document["stages"] = list(self.stages)
        return document


@dataclass
class GateEvaluation:
    """The gate's outcome over one scan directory."""

    results: List[ExpectationResult] = field(default_factory=list)
    triage: TriageApplication = field(default_factory=TriageApplication)
    baseline_document: Optional[Dict[str, Any]] = None
    decisions_document: Optional[Dict[str, Any]] = None
    suppressed: int = 0
    new: int = 0
    existing: int = 0

    @property
    def failed(self) -> List[ExpectationResult]:
        return [result for result in self.results if result.status == "fail"]

    @property
    def warned(self) -> List[ExpectationResult]:
        return [result for result in self.results if result.status == "warn"]

    @property
    def require_not_assessed(self) -> int:
        return sum(
            1 for result in self.results if result.kind == "require" and result.status == "fail"
        )

    @property
    def not_evaluated(self) -> int:
        return sum(1 for result in self.results if result.status == "not_evaluated")

    @property
    def exit_code(self) -> int:
        """The gate's exit code: 4 when a required capability was not
        assessed, because a gate over missing coverage cannot be trusted;
        else 3 when a fail-action expectation matched; else 0. Warnings and
        not-evaluated entries never change the code."""
        if any(result.kind == "require" and result.status == "fail" for result in self.results):
            return 4
        if any(
            result.kind == "expect" and result.action == "fail" and result.status == "fail"
            for result in self.results
        ):
            return 3
        return 0

    def summary_document(self) -> Dict[str, Any]:
        """The ``summary`` object the expectations document carries.

        ``fail`` counts the expect entries whose action failed, not the
        requirements; a requirement that was not assessed is
        ``requireNotAssessed``, and the two never merge.
        """
        return {
            "expect": sum(1 for result in self.results if result.kind == "expect"),
            "require": sum(1 for result in self.results if result.kind == "require"),
            "fail": sum(
                1 for result in self.results if result.kind == "expect" and result.status == "fail"
            ),
            "warn": sum(
                1 for result in self.results if result.kind == "expect" and result.status == "warn"
            ),
            "notEvaluated": self.not_evaluated,
            "requireNotAssessed": self.require_not_assessed,
            "suppressed": self.suppressed,
            "new": self.new,
            "existing": self.existing,
        }

    def to_document(self, *, evaluated_utc: str, source: str) -> Dict[str, Any]:
        """The full ``depscan-expectations`` document."""
        return {
            "schemaVersion": "1",
            "evaluatedUtc": evaluated_utc,
            "source": source,
            "decisions": self.decisions_document,
            "baseline": self.baseline_document,
            "summary": self.summary_document(),
            "results": [result.to_document() for result in self.results],
            "triage": self.triage.to_document(),
        }


def _require_result(entry: RequireEntry, stages: Sequence[Dict[str, Any]]) -> ExpectationResult:
    """Evaluate one require entry against the manifest stages.

    A capability is assessed for a project type when the manifest shows a
    stage carrying it that completed and, when the stage records the
    analyzers that were to produce it, at least one of those analyzers
    completed: an enrichment stage whose every reachability analyzer was
    not assessed did not assess reachability, whatever its own status says.
    A stage that failed, was skipped or was recorded as not assessed fails
    the requirement, and a requirement naming a project type no stage ran
    for is not evaluated rather than failed, because nothing was scanned to
    assess.
    """
    result = ExpectationResult(
        kind="require",
        id=entry.id,
        status="pass",
        capability=entry.capability,
        project_type=entry.project_type,
        evidence=["depscan.manifest.json"],
    )
    relevant = [
        stage
        for stage in stages
        if entry.capability in (stage.get("capabilities") or [])
        and (entry.project_type is None or stage.get("projectType") == entry.project_type)
    ]
    if entry.project_type is not None and not any(
        stage.get("projectType") == entry.project_type for stage in stages
    ):
        result.status = "not_evaluated"
        result.reason = f"no stage ran for project type '{entry.project_type}'"
        return result
    if not relevant:
        result.status = "fail"
        result.reason = (
            f"the {entry.capability} capability was not assessed: no manifest stage recorded it"
        )
        return result
    result.stages = [
        {
            "name": str(stage.get("name")),
            "status": str(stage.get("status")),
            "projectType": stage.get("projectType"),
        }
        for stage in relevant
    ]
    unassessed: List[str] = []
    for stage in relevant:
        analyzers_for_capability = [
            analyzer
            for analyzer in stage.get("analyzers") or []
            if isinstance(analyzer, dict) and analyzer.get("capability") == entry.capability
        ]
        if analyzers_for_capability:
            completed = [a for a in analyzers_for_capability if a.get("status") == "completed"]
            if not completed:
                names = ", ".join(str(a.get("name")) for a in analyzers_for_capability)
                unassessed.append(f"{stage.get('name')}: no analyzer assessed it ({names})")
            continue
        if stage.get("status") != "completed":
            listed = f"{stage.get('name')} ({stage.get('status')}"
            if stage.get("projectType"):
                listed += f", {stage['projectType']}"
            unassessed.append(listed + ")")
    if unassessed:
        result.status = "fail"
        result.reason = f"the {entry.capability} capability was not assessed: " + "; ".join(
            unassessed
        )
    return result


def _matches_with_aliases(
    finding: Dict[str, Any],
    selectors: Dict[str, Any],
    alias_map: Optional[Dict[str, Set[str]]],
    has_baseline: bool,
) -> bool:
    """Selector matching for a finding, using the alias map when it names
    the finding's rule."""
    ids = None
    rule_key = alias_map_key(str(finding.get("rule") or ""))
    if alias_map and rule_key in alias_map:
        ids = alias_map[rule_key]
    return finding_matches_selectors(finding, selectors, alias_ids=ids, has_baseline=has_baseline)


def evaluate_gate(
    findings: List[Dict[str, Any]],
    stages: Sequence[Dict[str, Any]],
    decisions: Decisions,
    *,
    cli_expects: Sequence[ExpectEntry] = (),
    has_baseline: bool = False,
    baseline_document: Optional[Dict[str, Any]] = None,
    decisions_document: Optional[Dict[str, Any]] = None,
    application: Optional[TriageApplication] = None,
    suppressed: int = 0,
    new: int = 0,
    existing: int = 0,
    alias_map: Optional[Dict[str, Set[str]]] = None,
) -> GateEvaluation:
    """Evaluate the gate over one scan's findings and manifest stages.

    ``findings`` is the scan's findings document array, with the triage and
    baseline states already applied. A finding whose triage state suppresses
    it is out of the gate: no expect entry matches it, whatever its other
    fields. ``stages`` is the manifest's stage array. The expect entries
    come from the decisions file with the ``--fail-on`` entries appended;
    the require entries come from the file. An entry selecting on ``new``
    without a baseline is not evaluated, with the reason, rather than
    passed or failed.

    :returns: The :class:`GateEvaluation`, whose ``exit_code`` is the exit
        code the gate adds to the run.
    """
    if application is None:
        application = TriageApplication()
    evaluation = GateEvaluation(
        triage=application,
        baseline_document=baseline_document,
        decisions_document=decisions_document,
        suppressed=suppressed,
        new=new,
        existing=existing,
    )
    for entry in [*decisions.expects, *cli_expects]:
        result = ExpectationResult(
            kind="expect",
            id=entry.id,
            status="pass",
            action=entry.action,
            description=entry.description,
            evidence=["depscan.findings.json"],
        )
        if "new" in entry.selectors and not has_baseline:
            result.status = "not_evaluated"
            result.reason = (
                "the entry selects on new, and the run has no baseline: add [baseline] "
                "to the decisions file or pass --baseline"
            )
            evaluation.results.append(result)
            continue
        result.findings = [
            str(finding.get("id"))
            for finding in findings
            if not _finding_is_suppressed(finding)
            and _matches_with_aliases(finding, entry.selectors, alias_map, has_baseline)
        ]
        if not result.findings:
            result.status = "pass"
        elif entry.action == "fail":
            result.status = "fail"
        else:
            result.status = "warn"
        evaluation.results.append(result)
    for entry in decisions.requires:
        evaluation.results.append(_require_result(entry, stages))
    return evaluation


def _finding_is_suppressed(finding: Dict[str, Any]) -> bool:
    """Whether a live decision suppresses the finding from the gate: its
    triage state is one of the suppressing states. The triage object lands
    on a finding only through a live decision, so its state alone is the
    verdict."""
    triage = finding.get("triage")
    return isinstance(triage, dict) and triage.get("state") in SUPPRESSING_STATES


# --- the VDR rendering of decisions ---------------------------------------------------

#: The VDR properties that carry the people and expiry of a decision, beside
#: the CycloneDX analysis object the state and justification go into.
TRIAGE_PROPERTY_PREFIX = "depscan:triage:"


def annotate_vdr_analysis(
    vulns: List[Dict[str, Any]],
    entries: Sequence[TriageEntry],
    *,
    alias_map: Optional[Dict[str, Set[str]]] = None,
    now: Optional[datetime] = None,
) -> int:
    """Write the live triage decisions into the VDR entries' analysis
    objects, in place, and return how many entries carry one.

    CycloneDX puts the analysis on the vulnerability entry, so an entry with
    two affected components carries the first live decision matched on any
    of its pairs; the per-pair truth, one triage object per finding, lives
    in the findings document, which every renderer of decisions reads. The
    author, approver, proposer and expiry travel as ``depscan:triage:*``
    properties on the entry, because the CycloneDX analysis object has no
    fields for them. Proposals and expired decisions annotate nothing.
    """
    annotated = 0
    for vuln in vulns:
        refs = [
            affect.get("ref")
            for affect in vuln.get("affects") or []
            if isinstance(affect, dict) and affect.get("ref")
        ]
        if not refs:
            continue
        rule = str(vuln.get("id") or "")
        matched: Optional[TriageEntry] = None
        for ref in refs:
            virtual = {
                "id": "",
                "category": "vulnerability",
                "rule": rule,
                "components": [str(ref)],
            }
            for entry in entries:
                if entry.is_proposal or is_expired(entry.expires, now):
                    continue
                if entry_matches_finding(entry, virtual, alias_map=alias_map):
                    matched = entry
                    break
            if matched is not None:
                break
        if matched is None:
            continue
        analysis: Dict[str, Any] = {"state": matched.state}
        if matched.justification:
            analysis["justification"] = matched.justification
        if matched.responses:
            analysis["response"] = list(matched.responses)
        if matched.detail:
            analysis["detail"] = matched.detail
        vuln["analysis"] = analysis
        properties = [
            prop
            for prop in vuln.get("properties") or []
            if isinstance(prop, dict)
            and not str(prop.get("name") or "").startswith(TRIAGE_PROPERTY_PREFIX)
        ]
        for key, value in (
            ("author", matched.author),
            ("approver", matched.approver),
            ("proposed-by", matched.proposed_by),
            ("expires", matched.expires),
        ):
            if value:
                properties.append({"name": f"{TRIAGE_PROPERTY_PREFIX}{key}", "value": str(value)})
        vuln["properties"] = properties
        annotated += 1
    return annotated


def gate_exit_from_document(document: Dict[str, Any]) -> int:
    """The exit code a written expectations document stands for: 4 when a
    required capability was not assessed, 3 when a fail-action expectation
    matched, else 0. The same rule :attr:`GateEvaluation.exit_code` applies,
    read back from the file."""
    summary = document.get("summary") or {}
    if summary.get("requireNotAssessed"):
        return 4
    if summary.get("fail"):
        return 3
    return 0


# --- the command-line expression ----------------------------------------------------


def parse_fail_on(expression: str, *, index: int = 0) -> ExpectEntry:
    """Parse one ``--fail-on`` expression into an expect entry.

    The expression is the file's selector grammar as ``key=value`` pairs
    joined by commas, for example ``category=vulnerability,grade=high``. The
    list-valued ``rule`` selector takes ids joined by ``|``. The action is
    always ``fail``: ``--fail-on`` exists to stop a build.

    :raises DecisionsError: With the key and the valid values when a pair is
        not a selector, or a value is not one the selector takes.
    """
    pairs = [pair for pair in expression.split(",") if pair.strip()]
    if not pairs:
        raise DecisionsError(
            "--fail-on is empty; the grammar is key=value pairs joined by commas, "
            "for example grade=high,reach=reached"
        )
    expect_schema = _load_schema_document(DECISIONS_SCHEMA)["properties"]["expect"]["items"][
        "properties"
    ]
    selectors: Dict[str, Any] = {}
    for pair in pairs:
        key, sep, value = pair.partition("=")
        key = key.strip()
        value = value.strip()
        if not sep or not key or not value:
            raise DecisionsError(
                f"--fail-on: {pair!r} is not a key=value pair; the grammar is key=value "
                "pairs joined by commas, for example grade=high,reach=reached"
            )
        if key == "version_range":
            if not vers_range_is_valid(value):
                raise DecisionsError(
                    f"--fail-on: version_range {value!r} is not a vers range, for example "
                    "vers:npm/>=4.17.0|<4.17.21"
                )
            selectors[key] = value
            continue
        if key not in SELECTOR_KEYS:
            raise DecisionsError(
                f"--fail-on: {key!r} is not a selector; valid values: {', '.join(SELECTOR_KEYS)}"
            )
        if key == "rule":
            selectors[key] = [item.strip() for item in value.split("|") if item.strip()]
            if not selectors[key]:
                raise DecisionsError("--fail-on: rule needs at least one id")
            continue
        if key in ("malware", "new"):
            lowered = value.lower()
            if lowered not in ("true", "false"):
                raise DecisionsError(f"--fail-on: {key} takes true or false, got {value!r}")
            selectors[key] = lowered == "true"
            continue
        valid = expect_schema.get(key, {}).get("enum")
        if valid and value not in valid:
            raise DecisionsError(
                f"--fail-on: {key} takes one of {', '.join(str(item) for item in valid)}, "
                f"got {value!r}"
            )
        selectors[key] = value
    return ExpectEntry(
        id=f"cli-{index + 1}",
        action="fail",
        selectors=selectors,
        description=f"the --fail-on expression: {expression}",
        from_command_line=True,
    )
