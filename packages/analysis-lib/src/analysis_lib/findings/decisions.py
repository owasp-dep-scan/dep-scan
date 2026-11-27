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
from datetime import date, datetime, time, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple, Union

from analysis_lib.findings.fingerprint import normalise_purl, normalise_rule
from analysis_lib.findings.schemas import load_schema, validation_errors
from analysis_lib.findings.vdr_convert import comparable_purl, finding_from_vdr
from analysis_lib.helpers import vers_scheme_for_purl

#: The published name of the decisions file schema.
DECISIONS_SCHEMA = "depscan-decisions"

#: The findings document inside a scan directory.
FINDINGS_FILE = "depscan.findings.json"

# The enums come from the published schema, so the code and the contract
# cannot drift apart. The schema lists the severities, grades and
# confidences most severe (or most confident) first, the order the floors
# compare in.
_PROPERTIES = load_schema(DECISIONS_SCHEMA)["properties"]
_TRIAGE_KEYS = _PROPERTIES["triage"]["items"]["properties"]
_EXPECT_KEYS = _PROPERTIES["expect"]["items"]["properties"]

#: The triage states of the CycloneDX 1.7 vocabulary.
TRIAGE_STATES = tuple(_TRIAGE_KEYS["state"]["enum"])

#: The states that suppress a finding from the gate. ``in_triage`` and
#: ``exploitable`` never suppress; ``resolved_with_pedigree`` is kept out of
#: this tuple until the maintainer confirms it belongs with ``resolved``,
#: because a pedigree that is not verified is not a shipped fix.
SUPPRESSING_STATES = ("not_affected", "false_positive", "resolved")

#: The CycloneDX 1.7 impact analysis justifications.
JUSTIFICATIONS = tuple(_TRIAGE_KEYS["justification"]["enum"])

#: The CycloneDX 1.7 responses.
RESPONSES = tuple(_TRIAGE_KEYS["responses"]["items"]["enum"])

#: CycloneDX severity names, most severe first, for the severity floor.
SEVERITY_ORDER = tuple(_EXPECT_KEYS["severity"]["enum"])

#: The exploitability grades, most severe first, for the grade floor.
GRADE_ORDER = tuple(_EXPECT_KEYS["grade"]["enum"])

#: The producer confidences, most confident first, for the confidence floor.
CONFIDENCE_ORDER = tuple(_EXPECT_KEYS["confidence"]["enum"])

#: The capabilities a ``[[require]]`` entry can name: the ones a scan stage
#: records in the manifest when it assessed them.
REQUIRE_CAPABILITIES = tuple(_PROPERTIES["require"]["items"]["properties"]["capability"]["enum"])

#: The reach axis values each reach selector matches. A reach assessed as
#: ``unknown`` (analyzers ran, the package was not observed) matches none,
#: because an unobserved package is not a refuted one.
REACH_SELECTOR_VALUES = {
    "reached": frozenset({"proven", "likely"}),
    "not_reached": frozenset({"unlikely", "refuted"}),
    "not_assessed": frozenset({"not_assessed"}),
}

#: The selector keys of an expect entry and the --fail-on grammar, in the
#: order the documentation lists them. ``version_range`` narrows ``purl``
#: and is not a selector on its own.
SELECTOR_KEYS = (
    "category",
    "severity",
    "grade",
    "reach",
    "malware",
    "rule",
    "purl",
    "version_range",
    "confidence",
    "new",
)

#: The ``--checks`` names no stage assesses yet. A requirement on one of
#: them could never pass, so the loader refuses it with that reason.
UNASSESSED_CAPABILITIES = ("memory-safety", "mobile", "code", "crypto")

#: The finding categories an advisory selects: a malware advisory is still
#: an advisory id matched against a package.
ADVISORY_CATEGORIES = ("vulnerability", "malware")


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
        """Whether this entry is a proposal: it has ``proposed_by`` and no
        ``approver``. An ``author`` alone never approves a proposal."""
        return bool(self.proposed_by) and not self.approver

    @property
    def suppresses(self) -> bool:
        """Whether a live entry with this state suppresses findings from the
        gate."""
        return self.state in SUPPRESSING_STATES

    @property
    def handle(self) -> str:
        """The entry's handle; see :func:`entry_handle`."""
        return entry_handle(self)

    def _present(self, keys: Sequence[str]) -> Dict[str, Any]:
        return {key: getattr(self, key) for key in keys if getattr(self, key)}

    def selector_document(self) -> Dict[str, Any]:
        """The selector as the file carries it, for reports and listings."""
        return self._present(("finding", "advisory", "purl", "version_range"))

    def to_triage_document(self) -> Dict[str, Any]:
        """The triage object this decision writes into a finding, the shape
        the finding schema's triage object publishes."""
        return {"state": self.state} | self._present(
            (
                "justification",
                "responses",
                "detail",
                "author",
                "approver",
                "proposed_by",
                "expires",
            )
        )

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
            self.id = require_id(self.capability, self.project_type)


def require_id(capability: str, project_type: Optional[str] = None) -> str:
    """The id a require entry without one takes: ``require-<capability>``,
    with ``-<project type>`` when it names one."""
    return f"require-{capability}-{project_type}" if project_type else f"require-{capability}"


def entry_handle(entry: TriageEntry) -> str:
    """The stable handle of a triage entry: ``tr-`` and the first ten hex
    digits of the SHA-256 of its canonical selector, with ``proposed_by``
    added for a proposal.

    The handle does not move when other entries are added or removed, so a
    command given a handle acts on the entry that was listed. Two live
    entries with the same selector share a handle; a command that edits by
    handle refuses one that names more than one entry.
    """
    canonical = {key: str(value).strip() for key, value in entry.selector_document().items()}
    if entry.finding:
        canonical["finding"] = canonical["finding"].lower()
    if entry.advisory:
        canonical["advisory"] = alias_map_key(canonical["advisory"])
    if entry.purl:
        canonical["purl"] = _identity_with_version(canonical["purl"])
    if entry.is_proposal:
        canonical["proposed_by"] = str(entry.proposed_by)
    payload = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return "tr-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:10]


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


_HEADER = re.compile(r"^\s*\[\[?\s*([A-Za-z0-9_-]+)\s*\]\]?")
_MULTILINE_DELIMITERS = ('"""', "'''")
_VERS_EXAMPLE = "for example vers:npm/>=4.17.0|<4.17.21"
_DATE_HINT = (
    'write it as a quoted RFC 3339 date-time with an offset, for example "2026-12-31T00:00:00Z"'
)

#: A problem found in the document: its path and the message without the
#: line, which is added when the problems are reported.
Problem = Tuple[Tuple[Any, ...], str]


def _code_lines(lines: Sequence[str]) -> List[bool]:
    """For each line, whether it starts outside a multi-line string, so a
    header or key written inside a string body is never read as one."""
    flags = []
    delimiter: Optional[str] = None
    for line in lines:
        flags.append(delimiter is None)
        if delimiter is None and line.lstrip().startswith("#"):
            continue
        position = 0
        while True:
            if delimiter is None:
                found = [(line.find(d, position), d) for d in _MULTILINE_DELIMITERS]
                found = [item for item in found if item[0] != -1]
                if not found:
                    break
                index, delimiter = min(found)
            else:
                index = line.find(delimiter, position)
                if index == -1:
                    break
                delimiter = None
            position = index + 3
    return flags


def _line_for_path(text: str, path: Sequence[Any]) -> Optional[int]:
    """The 1-based line a document path is written on.

    ``("triage", 2, "state")`` is the ``state`` key of the third
    ``[[triage]]`` entry and ``("baseline", "digest")`` the ``digest`` key of
    the ``[baseline]`` table. A key that appears on no line of its table, a
    missing required key among them, reports the table's header line. An
    array written inline (``triage = [{...}]``) reports the line of its key.
    """
    if not path:
        return 1
    lines = text.splitlines()
    code = _code_lines(lines)
    name = str(path[0])
    headers: List[int] = []
    tables: List[int] = []
    for index, line in enumerate(lines):
        match = _HEADER.match(line) if code[index] else None
        if match:
            tables.append(index)
            if match.group(1) == name:
                headers.append(index)
    rest = list(path[1:])
    if headers:
        occurrence = rest.pop(0) if rest and isinstance(rest[0], int) else 0
        if occurrence >= len(headers):
            return None
        start = headers[occurrence]
        end = min((line for line in tables if line > start), default=len(lines))
    else:
        start, end, rest = 0, min(tables, default=len(lines)), [name]
    if rest and isinstance(rest[0], str):
        key_line = re.compile(rf"^\s*{re.escape(rest[0])}\s*=")
        for index in range(start, end):
            if code[index] and key_line.match(lines[index]):
                return index + 1
        if not headers:
            return None
    return start + 1


def _selector_problem(entry: Any) -> str:
    """Why a triage entry's selector is refused: it needs ``finding``, or
    ``advisory`` with ``purl``, and never both."""
    keys = set(entry) if isinstance(entry, dict) else set()
    if "finding" in keys and keys & {"advisory", "purl"}:
        return "takes finding, or advisory with purl, not both"
    if "advisory" in keys:
        return "an advisory selector needs purl"
    if "purl" in keys:
        return "a purl selector needs advisory"
    return "needs a selector: finding, or advisory with purl"


def _schema_problems(document: Dict[str, Any]) -> List[Tuple[Tuple[Any, ...], str, List[Any]]]:
    """Every schema violation as its path, its message with the valid values,
    and the path whose line reports it."""
    errors = validation_errors(DECISIONS_SCHEMA, document)
    typed = {tuple(error.path) for error in errors if error.validator == "type"}
    problems = []
    for error in errors:
        path = tuple(error.path)
        line_path = list(path)
        valid = [str(value) for value in (error.schema.get("enum") or [])]
        if error.validator == "enum":
            if path in typed:
                continue
            message = f"{error.instance!r} is not a valid value"
        elif error.validator == "oneOf" and path[:1] == ("triage",):
            message = _selector_problem(error.instance)
        elif error.validator == "anyOf" and path[:1] == ("expect",):
            message = "needs at least one selector"
            valid = [key for key in SELECTOR_KEYS if key != "version_range"]
        elif error.validator == "dependentRequired":
            message = "version_range narrows purl and needs purl"
        elif error.validator == "required" and "then" in error.schema_path:
            message = (
                "needs author: an entry without proposed_by is a person's decision and "
                "names who made it"
            )
        else:
            message = error.message
            # An additional-properties violation names the unexpected key in
            # its message instead of its path; the key's own line reports it.
            if error.validator == "additionalProperties":
                line_path.extend(re.findall(r"'([^']+)'", message)[:1])
                valid = list(error.schema.get("properties") or [])
        if valid:
            message = f"{message}; valid values: {', '.join(valid)}"
        problems.append((path, message, line_path))
    return problems


def _strings_for_dates(value: Any, path: Tuple[Any, ...], problems: List[Problem]) -> Any:
    """The document with every TOML offset date-time written as its RFC 3339
    string, the form the schema validates. A TOML local date, local time or
    local date-time has no offset and cannot be compared with the clock, so
    it is refused with the quoted form to write instead."""
    if isinstance(value, dict):
        return {
            key: _strings_for_dates(item, (*path, key), problems) for key, item in value.items()
        }
    if isinstance(value, list):
        return [
            _strings_for_dates(item, (*path, index), problems) for index, item in enumerate(value)
        ]
    if isinstance(value, datetime) and value.tzinfo is not None:
        return value.isoformat().replace("+00:00", "Z")
    if isinstance(value, (date, time)):
        problems.append(
            (path, f"{value.isoformat()} is a TOML date without an offset; {_DATE_HINT}")
        )
    return value


def version_range_problem(version_range: str, purl: Optional[str] = None) -> Optional[str]:
    """Why a vers range cannot be used, or None when it can.

    The range must parse as a vers range with its scheme, every constraint
    must name a version (one with a digit, or ``*``), and with a purl the
    scheme must be the one that compares that package type's versions, so a
    pypi range never compares npm versions.
    """
    from vdb.lib.vers import VersError, VersionRange

    try:
        parsed = VersionRange.from_string(version_range.strip())
    except VersError:
        return f"{version_range!r} is not a vers range, {_VERS_EXAMPLE}"
    for constraint in parsed.constraints:
        text = str(constraint.version)
        if constraint.comparator != "*" and not any(char.isdigit() for char in text):
            return f"{version_range!r} names {text!r}, which is not a version; {_VERS_EXAMPLE}"
    if purl:
        expected = vers_scheme_for_purl(purl)
        purl_type = purl.split(":", 1)[-1].split("/", 1)[0].lower()
        if parsed.scheme not in (expected, purl_type):
            return (
                f"{version_range!r} uses the {parsed.scheme} scheme, and {purl} is a "
                f"{purl_type} package; write the range as vers:{expected}/..."
            )
    return None


def vers_range_is_valid(version_range: str) -> bool:
    """Whether a vers range can be used on its own; see
    :func:`version_range_problem`."""
    return version_range_problem(version_range) is None


def _list_of_tables(document: Dict[str, Any], name: str) -> List[Tuple[int, Dict[str, Any]]]:
    """The entries of an array of tables that are tables, with their index."""
    entries = document.get(name)
    if not isinstance(entries, list):
        return []
    return [(index, entry) for index, entry in enumerate(entries) if isinstance(entry, dict)]


def _semantic_problems(document: Dict[str, Any]) -> List[Problem]:
    """The checks the schema cannot express: the CycloneDX rule that a
    not_affected state carries a justification, that the date-times the
    runtime parses later are parseable, that every version range reads and
    suits its purl, that a requirement names a capability a stage assesses,
    and that expect and require ids are unique."""
    problems: List[Problem] = []
    seen: Dict[str, str] = {}
    for kind in ("triage", "expect", "require"):
        for index, entry in _list_of_tables(document, kind):
            purl = entry.get("purl") if isinstance(entry.get("purl"), str) else None
            if isinstance(entry.get("version_range"), str):
                if problem := version_range_problem(entry["version_range"], purl):
                    problems.append(((kind, index, "version_range"), problem))
            if kind == "triage":
                if entry.get("state") == "not_affected" and not entry.get("justification"):
                    message = "a not_affected state needs a justification; valid values: "
                    problems.append(
                        (("triage", index, "justification"), message + ", ".join(JUSTIFICATIONS))
                    )
                for key in ("created", "expires"):
                    if isinstance(entry.get(key), str) and _parse_rfc3339(entry[key]) is None:
                        message = f"{entry[key]!r} is not an RFC 3339 date-time; {_DATE_HINT}"
                        problems.append((("triage", index, key), message))
                continue
            if entry.get("capability") in UNASSESSED_CAPABILITIES:
                message = (
                    f"dep-scan does not assess {entry['capability']} yet, so no scan can meet "
                    f"this requirement; valid values: {', '.join(REQUIRE_CAPABILITIES)}"
                )
                problems.append(((kind, index, "capability"), message))
            identifier = entry.get("id") or (
                require_id(str(entry.get("capability")), entry.get("project_type"))
                if kind == "require"
                else None
            )
            if isinstance(identifier, str) and identifier in seen:
                message = f"the id {identifier!r} is already used by {seen[identifier]}"
                problems.append(((kind, index, "id"), message + "; every entry needs its own id"))
            elif isinstance(identifier, str):
                seen[identifier] = f"{kind}/{index}"
    return problems


def _document_problems(document: Dict[str, Any]) -> List[Tuple[Tuple[Any, ...], str, List[Any]]]:
    """Every problem of a parsed document: the checks of
    :func:`_semantic_problems`, then the schema violations at paths those
    checks did not already report, each as its path, its message and the
    path whose line reports it."""
    problems = [(path, message, list(path)) for path, message in _semantic_problems(document)]
    covered = {path for path, _, _ in problems}
    return problems + [
        problem for problem in _schema_problems(document) if problem[0] not in covered
    ]


def parse_decisions_document(text: str) -> Dict[str, Any]:
    """Parse the TOML text and validate it against the published schema.

    A leading byte order mark is ignored. TOML offset date-times become
    their RFC 3339 strings, the form the schema and the findings carry.

    Raises :class:`DecisionsError` naming every problem, in line order, each
    with its key, line and valid values, when the file is not usable.
    """
    text = text.removeprefix("\ufeff")
    try:
        parsed = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise DecisionsError(f"the decisions file is not valid TOML: {exc}") from exc
    dates: List[Problem] = []
    document = _strings_for_dates(parsed, (), dates)
    covered = {path for path, _ in dates}
    problems = [(path, message, list(path)) for path, message in dates] + [
        problem for problem in _document_problems(document) if problem[0] not in covered
    ]
    if problems:
        lines = sorted(
            ((_line_for_path(text, line_path) or 0), "/".join(map(str, path)) or "<file>", message)
            for path, message, line_path in problems
        )
        raise DecisionsError(
            "the decisions file was refused:\n"
            + "\n".join(
                f"line {line}: {where}: {message}" if line else f"{where}: {message}"
                for line, where, message in lines
            )
        )
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

    :param path: The file to read, UTF-8 with or without a byte order mark.
    :param selected_by: Recorded on the decisions, saying what picked the
        file: default, option, environment, project-config or user-config.
    :returns: The loaded decisions, carrying the SHA-256 digest of the
        file's bytes.
    :raises DecisionsError: When the file cannot be read, is not UTF-8 text
        or breaks its schema; the message names every problem with its key
        and line.
    """
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError as exc:
        raise DecisionsError(
            f"the decisions file '{path}' cannot be read: {exc.strerror or exc}"
        ) from exc
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise DecisionsError(
            f"the decisions file '{path}' is not UTF-8 text: the byte at offset {exc.start} "
            "cannot be decoded; save the file as UTF-8"
        ) from exc
    decisions = decisions_from_document(parse_decisions_document(text), path=path)
    decisions.digest = hashlib.sha256(raw).hexdigest()
    decisions.selected_by = selected_by
    return decisions


# --- selectors --------------------------------------------------------------------


def _split_purl(purl: str) -> Tuple[str, Optional[str]]:
    """A comparable purl split into its head and its decoded version, None
    when it names none.

    The version starts after the slash that ends the namespace and name, so
    an ``@`` inside a namespace (an npm scoped package) never reads as a
    version marker.
    """
    comparable = comparable_purl(purl)
    at = comparable.find("@", comparable.rfind("/") + 1)
    if at == -1:
        return comparable, None
    return comparable[:at], comparable[at + 1 :] or None


def _identity_with_version(purl: str) -> str:
    """A purl folded the way fingerprints fold it, with its version kept."""
    head, version = _split_purl(purl)
    try:
        head = normalise_purl(purl)
    except ValueError:
        pass
    return f"{head}@{version}" if version else head


def purl_version(purl: str) -> Optional[str]:
    """The decoded version of a purl, None when it names none."""
    return _split_purl(purl)[1]


def vers_range_matches(version: Optional[str], version_range: str) -> bool:
    """Whether a version is inside a vers-syntax range.

    A version the range grammar cannot compare never matches, so a range
    that cannot be read narrows instead of matching everything.
    """
    if not version:
        return False
    from vdb.lib.vers import vers_compare

    return bool(vers_compare(version, version_range))


def _identity_equal(component: str, selector_purl: str) -> bool:
    """Whether two purls name the same package.

    The fingerprint normalisation folds percent-encoding, qualifiers and the
    per-type case rules packageurl applies; NuGet ids are case-insensitive
    in a way packageurl keeps, and comparable_purl folds their case, so a
    nuget pair compares in its comparable form.
    """
    try:
        if normalise_purl(component) == normalise_purl(selector_purl):
            return True
    except ValueError:
        pass
    if comparable_purl(component).lower().startswith("pkg:nuget/"):
        return _split_purl(component)[0] == _split_purl(selector_purl)[0]
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
    alias_map: Optional[Dict[str, Set[str]]] = None,
    has_baseline: bool = False,
) -> bool:
    """Whether one finding document matches every selector.

    ``alias_map`` (see :func:`alias_map_from_vulns`) lets the ``rule``
    selector match an alias of the finding's advisory; without it only the
    rule id itself is compared. ``has_baseline`` says the run compared with a baseline, which
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
            if not {alias_map_key(str(rule)) for rule in value} & _aliases_of(finding, alias_map):
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


def _aliases_of(finding: Dict[str, Any], alias_map: Optional[Dict[str, Set[str]]]) -> Set[str]:
    """The advisory ids a finding answers to, lower-cased: its rule id and
    the aliases the map holds for it."""
    rule_key = alias_map_key(str(finding.get("rule") or ""))
    return {rule_key} | (alias_map or {}).get(rule_key, set())


def entry_matches_finding(
    entry: TriageEntry, finding: Dict[str, Any], *, alias_map: Optional[Dict[str, Set[str]]] = None
) -> bool:
    """Whether one triage decision selects one finding.

    A ``finding`` selector compares the dsf1 id exactly. An ``advisory``
    selector names the advisory id or an alias and needs ``purl``; it
    matches vulnerability and malware findings whose rule or an alias is
    the advisory and whose components satisfy the purl and its optional
    version range.
    """
    if entry.finding:
        return finding.get("id") == entry.finding
    if finding.get("category") not in ADVISORY_CATEGORIES:
        return False
    if alias_map_key(entry.advisory or "") not in _aliases_of(finding, alias_map):
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
            "handle": self.entry.handle,
            "selector": self.entry.selector_document(),
            "state": self.entry.state,
            "findings": list(self.findings),
        }
        people = self.entry._present(("author", "approver", "proposed_by", "expires"))
        if "proposed_by" in people:
            people["proposedBy"] = people.pop("proposed_by")
        return document | people


@dataclass
class TriageApplication:
    """What applying the triage decisions did to one findings list.

    Each finding takes one winning decision (see :func:`apply_triage`).
    ``winners`` pairs every finding that has one with it, in findings order,
    and ``ranked`` lists the live decisions in precedence order. ``applied``
    counts the decisions that won at least one finding; ``suppressed_ids``
    holds one id per finding whose winner suppresses it, so two findings that
    share a fingerprint count twice. Proposals set nothing and are pending;
    expired decisions suppress nothing and name what they would have
    matched; a live decision that matched nothing is stale, and one that lost
    a finding to a decision of higher precedence is shadowed there.
    """

    applied: int = 0
    suppressed_ids: List[str] = field(default_factory=list)
    expired: List[EntryReport] = field(default_factory=list)
    stale: List[EntryReport] = field(default_factory=list)
    proposals: List[EntryReport] = field(default_factory=list)
    shadowed: List[EntryReport] = field(default_factory=list)
    winners: List[Tuple[Dict[str, Any], TriageEntry]] = field(default_factory=list)
    ranked: List[TriageEntry] = field(default_factory=list)

    @property
    def suppressed(self) -> int:
        """How many findings a decision suppresses from the gate."""
        return len(self.suppressed_ids)

    def to_document(self) -> Dict[str, Any]:
        """The ``triage`` object the expectations document carries."""
        return {
            "applied": self.applied,
            "suppressed": self.suppressed,
            "expired": [report.to_document() for report in self.expired],
            "stale": [report.to_document() for report in self.stale],
            "proposals": [report.to_document() for report in self.proposals],
            "shadowed": [report.to_document() for report in self.shadowed],
        }


def apply_triage(
    findings: List[Dict[str, Any]],
    entries: Sequence[TriageEntry],
    *,
    alias_map: Optional[Dict[str, Set[str]]] = None,
    now: Optional[datetime] = None,
) -> TriageApplication:
    """Apply the triage decisions to a findings list, in place.

    The ``triage`` object of every finding is removed first, so applying the
    decisions file again, to the saved findings of an earlier scan, reflects
    the file as it is now. A live decision is one that is not a proposal and
    has not expired. Each finding takes one winner among the live decisions
    that select it: a ``finding`` selector beats an ``advisory`` selector,
    and among selectors of the same kind the first in ``entries`` order
    wins. The winner sets the finding's ``triage`` object; a state in
    :data:`SUPPRESSING_STATES` suppresses the finding from the gate. Every
    other live decision that selects the finding is reported as shadowed.
    Nothing is deleted: a suppressed finding stays in the list.
    """
    application = TriageApplication()
    for finding in findings:
        finding.pop("triage", None)
    live: List[Tuple[TriageEntry, List[Dict[str, Any]]]] = []
    for entry in entries:
        matched = [
            finding
            for finding in findings
            if entry_matches_finding(entry, finding, alias_map=alias_map)
        ]
        ids = [str(finding.get("id")) for finding in matched]
        if entry.is_proposal:
            application.proposals.append(EntryReport(entry=entry, findings=ids))
        elif is_expired(entry.expires, now):
            application.expired.append(EntryReport(entry=entry, findings=ids))
        elif not matched:
            application.stale.append(EntryReport(entry=entry))
        else:
            live.append((entry, matched))
    # sorted() is stable, so file order breaks ties within a selector kind.
    live.sort(key=lambda pair: 0 if pair[0].finding else 1)
    application.ranked = [entry for entry, _ in live]
    won: Dict[int, TriageEntry] = {}
    lost: Dict[int, List[str]] = {}
    for entry, matched in live:
        for finding in matched:
            if won.setdefault(id(finding), entry) is not entry:
                lost.setdefault(id(entry), []).append(str(finding.get("id")))
    application.applied = len({id(entry) for entry in won.values()})
    for finding in findings:
        entry = won.get(id(finding))
        if entry is None:
            continue
        finding["triage"] = entry.to_triage_document()
        application.winners.append((finding, entry))
        if entry.suppresses:
            application.suppressed_ids.append(str(finding.get("id")))
    application.shadowed = [
        EntryReport(entry=entry, findings=lost[id(entry)])
        for entry in entries
        if id(entry) in lost
    ]
    return application


# --- baseline -----------------------------------------------------------------------


def read_baseline(spec: BaselineSpec, *, base_dir: Optional[str] = None) -> Set[str]:
    """The finding ids of a baseline findings document.

    ``spec.scan`` is a scan directory, whose ``depscan.findings.json`` is
    read, or the findings file itself. A relative path resolves against
    ``base_dir``, the decisions file's directory for a ``[baseline]`` table,
    and against the working directory when ``base_dir`` is None, the case of
    a ``--baseline`` value. An absolute path, a Windows drive path included
    on every platform, is used as given. The optional digest is checked
    before the file is parsed, so a mismatch is refused as a digest problem
    and not as a parse failure.

    :raises BaselineError: When the file cannot be read, the digest does not
        match, or the document is not a findings document. A scan stops on
        this instead of marking every finding new.
    """
    scan = str(spec.scan).replace("\\", "/")
    if os.path.isabs(scan) or re.match(r"^[A-Za-z]:/", scan):
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


def apply_baseline(
    findings: List[Dict[str, Any]], baseline_ids: Optional[Set[str]]
) -> Tuple[int, int]:
    """Mark every finding new or existing against the baseline ids, in
    place, and return the new and existing counts. A finding the baseline
    does not contain is new. With no baseline (None) the ``baseline`` field
    of every finding is removed, so the saved findings of an earlier scan
    never keep marks the current run did not make."""
    new = 0
    existing = 0
    for finding in findings:
        if baseline_ids is None:
            finding.pop("baseline", None)
            continue
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
        for key, value in (
            ("action", self.action),
            ("description", self.description),
            ("reason", self.reason),
            ("capability", self.capability),
            ("projectType", self.project_type),
            ("stages", self.stages),
        ):
            if value:
                document[key] = value
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
    def exit_code(self) -> int:
        """The gate's exit code, :func:`gate_exit_from_document` of the
        summary. Warnings and not-evaluated entries never change it."""
        return gate_exit_from_document({"summary": self.summary_document()})

    def summary_document(self) -> Dict[str, Any]:
        """The ``summary`` object the expectations document carries.

        ``fail`` counts the expect entries whose action failed, not the
        requirements; a requirement that was not assessed is
        ``requireNotAssessed``, and the two never merge.
        """

        def count(kind: Optional[str], status: str) -> int:
            return sum(
                1 for r in self.results if r.kind == (kind or r.kind) and r.status == status
            )

        return {
            "expect": sum(1 for result in self.results if result.kind == "expect"),
            "require": sum(1 for result in self.results if result.kind == "require"),
            "fail": count("expect", "fail"),
            "warn": count("expect", "warn"),
            "notEvaluated": count(None, "not_evaluated"),
            "requireNotAssessed": count("require", "fail"),
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
            key: str(stage[name])
            for key, name in (
                ("name", "name"),
                ("status", "status"),
                ("projectType", "projectType"),
            )
            if stage.get(name)
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
    suppressed: Optional[int] = None,
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
        suppressed=application.suppressed if suppressed is None else suppressed,
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
            and finding_matches_selectors(
                finding, entry.selectors, alias_map=alias_map, has_baseline=has_baseline
            )
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
    triage state is one of the suppressing states. :func:`apply_triage`
    removes every triage object before it writes the winners, so on applied
    findings the object is always the current file's decision."""
    triage = finding.get("triage")
    return isinstance(triage, dict) and triage.get("state") in SUPPRESSING_STATES


# --- the VDR rendering of decisions ---------------------------------------------------

#: The VDR properties that carry the people and expiry of a decision, beside
#: the CycloneDX analysis object the state and justification go into.
TRIAGE_PROPERTY_PREFIX = "depscan:triage:"


def _vdr_findings(vulns: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The findings the VDR entries convert to, one per advisory and
    component, skipping a pair the conversion refuses."""
    findings = []
    for vuln in vulns:
        for affect in vuln.get("affects") or []:
            try:
                finding = finding_from_vdr(vuln, str(affect["ref"]), producer_version="")
            except (KeyError, TypeError, ValueError):
                continue
            findings.append(finding.to_dict())
    return findings


def annotate_vdr_analysis(
    vulns: List[Dict[str, Any]],
    triage: Union[TriageApplication, Sequence[TriageEntry]],
    *,
    alias_map: Optional[Dict[str, Set[str]]] = None,
    now: Optional[datetime] = None,
) -> int:
    """Write the winning triage decisions into the VDR entries' analysis
    objects, in place, and return how many entries carry one.

    ``triage`` is the :class:`TriageApplication` :func:`apply_triage`
    returned for the scan's findings. Given the triage entries instead, they
    are applied to the findings the VDR entries convert to, with the ids,
    categories and components the findings document gives them, so the VDR
    and the findings agree before the findings are built. ``alias_map`` and
    ``now`` are used in that case only.

    CycloneDX puts the analysis on the vulnerability entry, so an entry with
    two affected components carries the highest-precedence winner among its
    pairs; the per-pair truth, one triage object per finding, lives in the
    findings document. The author, approver, proposer and expiry travel as
    ``depscan:triage:*`` properties on the entry, because the CycloneDX
    analysis object has no fields for them. Proposals, expired and shadowed
    decisions annotate nothing.
    """
    if not isinstance(triage, TriageApplication):
        triage = apply_triage(_vdr_findings(vulns), triage, alias_map=alias_map, now=now)
    rank = {id(entry): position for position, entry in enumerate(triage.ranked)}
    by_pair: Dict[Tuple[str, str], TriageEntry] = {}
    for finding, entry in triage.winners:
        for component in finding.get("components") or []:
            by_pair[
                (alias_map_key(str(finding.get("rule") or "")), comparable_purl(str(component)))
            ] = entry
    annotated = 0
    for vuln in vulns:
        rule = alias_map_key(str(vuln.get("id") or ""))
        candidates = [
            by_pair[key]
            for affect in vuln.get("affects") or []
            if isinstance(affect, dict)
            and affect.get("ref")
            and (key := (rule, comparable_purl(str(affect["ref"])))) in by_pair
        ]
        if not candidates:
            continue
        matched = min(candidates, key=lambda entry: rank.get(id(entry), len(rank)))
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
    """The exit code an expectations document stands for: 4 when a required
    capability was not assessed, because a gate over missing coverage cannot
    be trusted; else 3 when a fail-action expectation matched; else 0."""
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
    list-valued ``rule`` selector takes ids joined by ``|``, and ``malware``
    and ``new`` take true or false. The entry is checked by the same schema
    and checks as an ``[[expect]]`` entry of the file. The action is always
    ``fail``: ``--fail-on`` exists to stop a build. The entry's id is
    ``fail-on:<n>``, a form the file's id pattern cannot produce, so it never
    collides with an id in the file.

    :raises DecisionsError: With the key and the valid values when a pair is
        not a selector, or a value is not one the selector takes.
    """
    grammar = (
        "the grammar is key=value pairs joined by commas, for example grade=high,reach=reached"
    )
    entry: Dict[str, Any] = {"id": "fail-on", "action": "fail"}
    for pair in [pair for pair in expression.split(",") if pair.strip()] or [""]:
        key, sep, value = (part.strip() for part in pair.partition("="))
        if not sep or not key or not value:
            raise DecisionsError(f"--fail-on: {pair!r} is not a key=value pair; {grammar}")
        if key not in SELECTOR_KEYS:
            raise DecisionsError(
                f"--fail-on: {key!r} is not a selector; valid values: {', '.join(SELECTOR_KEYS)}"
            )
        if key == "rule":
            entry[key] = [item.strip() for item in value.split("|") if item.strip()]
        elif key in ("malware", "new") and value.lower() in ("true", "false"):
            entry[key] = value.lower() == "true"
        else:
            entry[key] = value
    problems = _document_problems({"expect": [entry]})
    if problems:
        raise DecisionsError(
            "--fail-on: "
            + "; ".join(
                f"{path[2]} {message}" if len(path) > 2 else message
                for path, message, _ in problems
            )
        )
    entry["id"] = f"fail-on:{index + 1}"
    entry["description"] = f"the --fail-on expression: {expression}"
    return decisions_from_document({"expect": [entry]}).expects[0]
