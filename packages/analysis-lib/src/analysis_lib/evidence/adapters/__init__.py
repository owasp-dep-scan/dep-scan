"""The contract every evidence adapter follows.

An adapter turns one producer's report into evidence records, and it is the
only code that knows that report's format. Every adapter exposes one entry
point, ``extract(report, *, source, producer_version, ...)``, and returns an
:class:`AdapterResult`. The result is either the records the report yielded
or a not-assessed result whose reason says what stood in the way: a missing
tool, an unsupported report schema version, a truncated or malformed
report. None of those ever read as zero findings. A report object that
cannot become a record is counted in a ``record-skipped`` caveat that names
the reason and how many objects it covers.

The helpers here are the parts every adapter shares: the schema version
gate, the witness path cap, the caveat helpers, the type-safe readers for
report values, the source path mapping that keeps record paths relative
and takes the root and home directories out of stored text, the
root-neutral and machine-neutral discriminators, the cdxgen tool version
gate the cdxgen and tracebom adapters share, and the record builder that
computes ids.
The per-producer modules own everything format-specific.
"""

import functools
import posixpath
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from analysis_lib.evidence import (
    CAVEAT_KINDS,
    EVIDENCE_SCHEMA_VERSION,
    Evidence,
    EvidenceCaveat,
    EvidenceLocation,
    EvidencePathNode,
    EvidenceProducer,
    EvidenceSubject,
    KINDS,
    MAX_PATH_NODES,
    POLARITIES,
    content_discriminator,
    record_id,
)

#: The two states an adapter result can end in. ``completed`` means the
#: adapter read the report and built the records it could; ``not-assessed``
#: means the adapter could not assess the report at all, with the reason.
STATUS_COMPLETED = "completed"
STATUS_NOT_ASSESSED = "not-assessed"


@dataclass
class AdapterResult:
    """What one adapter made of one report.

    ``caveats`` are the producer-level caveats: the ones that apply to the
    report as a whole rather than to a single record, such as a schema
    drift or a truncation the producer itself reported. The adapter also
    lands each of them on every record it applies to.
    """

    status: str
    reason: Optional[str] = None
    records: List[Evidence] = field(default_factory=list)
    caveats: List[EvidenceCaveat] = field(default_factory=list)


def not_assessed(reason: str) -> AdapterResult:
    """The result for a report that could not be assessed, with the reason.

    This is the only way to report nothing: an empty record list from a
    completed run means the producer genuinely found nothing, while this
    result says the analysis never got far enough to find anything.
    """
    return AdapterResult(status=STATUS_NOT_ASSESSED, reason=reason)


@dataclass
class VersionGate:
    """The outcome of the report schema version check.

    ``accepted`` is False only for a version this adapter cannot read at
    all, and ``reason`` then names the version seen. A gate that accepted a
    drifted report carries the caveat the reader should see.
    """

    accepted: bool
    reason: Optional[str] = None
    caveats: List[EvidenceCaveat] = field(default_factory=list)


def gate_report_version(
    report_version: Any,
    supported_major: int,
    known_minor: int,
    *,
    holder: str = "report",
    noun: str = "schema version",
) -> VersionGate:
    """The schema version gate every adapter applies to its report.

    A report that names no version is accepted with a ``schema-unknown``
    caveat, since the report shape itself still decides whether it can be
    read. A version whose major does not parse as a number (``v6``,
    ``latest``) is refused: the major is what says whether the report can
    be read, and an unreadable one cannot say it. A newer minor of the
    supported major is accepted with a ``schema-minor`` caveat. A different
    major is refused with a reason naming the version seen, and the adapter
    returns a not-assessed result with that reason. A number given where a
    string belongs (``5.1``) is read as its text.

    ``holder`` and ``noun`` name what was read in the reasons and caveats
    (``the report names no schema version``); an adapter that gates on a
    tool version a BOM states passes ``holder="BOM"`` and
    ``noun="cdxgen version"``, so the text says what the gate read.
    """
    if report_version is None or isinstance(report_version, bool):
        text = ""
    elif isinstance(report_version, (str, int, float)):
        text = str(report_version).strip()
    else:
        return VersionGate(
            False,
            reason=(
                f"the {holder} {noun} is a {type(report_version).__name__}, not a version string"
            ),
        )
    if not text:
        return VersionGate(
            True,
            caveats=[
                EvidenceCaveat(kind="schema-unknown", detail=f"the {holder} names no {noun}")
            ],
        )
    parts = text.split(".")
    if not parts[0].isdigit():
        return VersionGate(
            False,
            reason=(
                f"the {holder} {noun} {text!r} names no numeric major version; "
                f"this adapter reads major {supported_major} {holder}s"
            ),
        )
    major = int(parts[0])
    if major != supported_major:
        return VersionGate(
            False,
            reason=(
                f"the {holder} {noun} {text} is not supported; "
                f"this adapter reads major {supported_major} {holder}s"
            ),
        )
    minor = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    if minor > known_minor:
        return VersionGate(
            True,
            caveats=[
                EvidenceCaveat(
                    kind="schema-minor",
                    detail=(
                        f"the {holder} names {noun} {text}; "
                        f"this adapter knows {supported_major}.{known_minor} and earlier"
                    ),
                )
            ],
        )
    return VersionGate(True)


def _tool_entries(bom: dict) -> List[dict]:
    """The tool objects a BOM's ``metadata.tools`` lists, in either the
    CycloneDX 1.5 list form or the 1.6 ``components`` form."""
    tools = as_dict(bom.get("metadata")).get("tools")
    entries = tools if isinstance(tools, list) else as_list(as_dict(tools).get("components"))
    return [entry for entry in entries if isinstance(entry, dict)]


def cdxgen_tool(bom: dict) -> Tuple[bool, Any]:
    """Whether a BOM's ``metadata.tools`` names cdxgen, and the version
    value it gives (``None`` when it gives none)."""
    for entry in _tool_entries(bom):
        if as_str(entry.get("name")) == "cdxgen":
            return True, entry.get("version")
    return False, None


def _tool_names(bom: dict) -> str:
    """The tools a BOM's ``metadata.tools`` lists, as ``name version`` text,
    or ``no tool``."""
    names = []
    for entry in _tool_entries(bom):
        name = as_str(entry.get("name"))
        if name:
            names.append(f"{name} {as_str(entry.get('version'))}".strip())
    return ", ".join(names) or "no tool"


def gate_cdxgen_tool_version(
    bom: dict, supported_major: int, known_minor: int, output: str
) -> Tuple[VersionGate, str]:
    """The cdxgen tool version gate the cdxgen and tracebom adapters apply,
    on the version the BOM's own ``metadata.tools`` names, never the
    locally installed cdxgen.

    Another major is refused and a newer minor accepted with a
    ``schema-minor`` caveat, as :func:`gate_report_version` does. A BOM
    that names cdxgen with no version is accepted with a ``schema-unknown``
    caveat, and so is a BOM another tool wrote, with the caveat naming the
    tools it lists; ``output`` names what cdxgen writes that the adapter
    reads (``BOM``, ``tracebom``). The second value is the version text
    for the producer block, ``unknown`` when the BOM names none."""
    named, version = cdxgen_tool(bom)
    if not named:
        return (
            VersionGate(
                True,
                caveats=[
                    EvidenceCaveat(
                        kind="schema-unknown",
                        detail=(
                            f"the BOM's metadata.tools names {_tool_names(bom)} and no cdxgen; "
                            f"this adapter reads the shapes cdxgen's {output} writes"
                        ),
                    )
                ],
            ),
            "unknown",
        )
    gate = gate_report_version(
        version, supported_major, known_minor, holder="BOM", noun="cdxgen version"
    )
    text = ""
    if isinstance(version, str):
        text = version.strip()
    elif isinstance(version, (int, float)) and not isinstance(version, bool):
        text = str(version)
    return gate, text or "unknown"


def cap_path(
    nodes: List[EvidencePathNode],
) -> Tuple[List[EvidencePathNode], Optional[EvidenceCaveat]]:
    """The witness path a record carries, at most :data:`MAX_PATH_NODES`
    nodes.

    A longer path keeps its first nodes, in the producer's order, and the
    truncation comes back as the caveat to record alongside it. A path
    within the cap comes back unchanged with no caveat.
    """
    if len(nodes) <= MAX_PATH_NODES:
        return nodes, None
    return (
        nodes[:MAX_PATH_NODES],
        EvidenceCaveat(
            kind="path-truncated",
            detail=f"kept the first {MAX_PATH_NODES} of {len(nodes)} witness nodes",
        ),
    )


def add_caveat(record: Evidence, kind: str, detail: str) -> None:
    """Attach one caveat to a record, unless the very same caveat is
    already on it."""
    if kind not in CAVEAT_KINDS:
        raise ValueError(f"unknown caveat kind {kind!r}; known kinds: {', '.join(CAVEAT_KINDS)}")
    caveat = EvidenceCaveat(kind=kind, detail=detail)
    if caveat not in record.caveats:
        record.caveats.append(caveat)


# ---------------------------------------------------------------------------
# Type-safe readers for report values
# ---------------------------------------------------------------------------


def as_list(value: Any) -> list:
    """``value`` when it is a JSON array, an empty list otherwise."""
    return value if isinstance(value, list) else []


def as_dict(value: Any) -> dict:
    """``value`` when it is a JSON object, an empty dict otherwise."""
    return value if isinstance(value, dict) else {}


def as_str(value: Any) -> str:
    """``value`` when it is a string, the empty string otherwise."""
    return value if isinstance(value, str) else ""


def as_line(value: Any) -> Optional[int]:
    """A line number the schema can carry: an integer from 1 up, or a string
    of digits naming one. Anything else (zero, a negative number, a boolean,
    a float, text) is no line."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 1 else None
    if isinstance(value, str) and value.strip().isdigit():
        number = int(value.strip())
        return number if number >= 1 else None
    return None


def as_hashable_str(value: Any) -> Optional[str]:
    """A non-empty string usable as a lookup key, or ``None`` for any other
    value (a list or object where an id belongs is no id)."""
    return value if isinstance(value, str) and value else None


# ---------------------------------------------------------------------------
# Skipped objects
# ---------------------------------------------------------------------------


class SkipTally:
    """Counts the report objects that became no record, per reason.

    Each reason becomes one ``record-skipped`` caveat that names the count,
    so a report with thousands of edges into packages the BOM does not carry
    says so in one line instead of thousands, and no object disappears
    without being counted.
    """

    def __init__(self) -> None:
        self._counts: Dict[str, int] = {}

    def add(self, reason: str, count: int = 1) -> None:
        """Count ``count`` objects under ``reason``, a sentence fragment that
        reads after the count (``"call-graph edges name no BOM package"``)."""
        if count > 0:
            self._counts[reason] = self._counts.get(reason, 0) + count

    def caveats(self) -> List[EvidenceCaveat]:
        """One caveat per reason, in the order the reasons were first seen."""
        return [
            EvidenceCaveat(kind="record-skipped", detail=f"{count} {reason}")
            for reason, count in self._counts.items()
        ]


# ---------------------------------------------------------------------------
# Source paths
# ---------------------------------------------------------------------------

_DRIVE_RE = re.compile(r"^[A-Za-z]:(/|$)")

#: Package caches whose layout names the package and version, so a file in
#: one has a stable spelling that does not depend on the machine. Each entry
#: is the directory marker and the number of path segments after it that
#: are dropped from the stable form (a Gradle cache keeps a content hash
#: directory between the version and the file).
_PACKAGE_CACHES: Tuple[Tuple[str, Optional[int]], ...] = (
    ("/pkg/mod/", None),
    ("/.cargo/registry/src/", 0),
    ("/.nuget/packages/", None),
    ("/.m2/repository/", None),
    ("/caches/modules-2/files-2.1/", 3),
)


def _slashes(path: str) -> str:
    return path.replace("\\", "/")


def is_absolute_path(path: str) -> bool:
    """Whether ``path`` (forward slashes) is absolute on POSIX or Windows."""
    return path.startswith("/") or bool(_DRIVE_RE.match(path))


def _normalize_dir(path: str) -> str:
    text = _slashes(path.strip())
    if not text:
        return ""
    normalized = posixpath.normpath(text)
    return "" if normalized == "." else normalized.rstrip("/") or "/"


def _under(path: str, directory: str) -> Optional[str]:
    """The part of ``path`` below ``directory``, or ``None`` when it is not
    below it. Windows drive paths compare without case."""
    if _DRIVE_RE.match(directory):
        path_cmp, dir_cmp = path.casefold(), directory.casefold()
    else:
        path_cmp, dir_cmp = path, directory
    if dir_cmp == "/":
        return path[1:] or None
    if path_cmp.startswith(dir_cmp + "/"):
        return path[len(directory) + 1 :] or None
    return None


def _cache_form(path: str) -> Optional[str]:
    """The stable spelling of a file inside a package cache, or ``None``."""
    for marker, drop_after_version in _PACKAGE_CACHES:
        idx = path.rfind(marker)
        if idx < 0:
            continue
        rest = path[idx + len(marker) :]
        if marker == "/.cargo/registry/src/":
            # <index directory>/<crate>-<version>/<file>
            rest = rest.split("/", 1)[1] if "/" in rest else ""
        elif drop_after_version:
            # <group>/<artifact>/<version>/<hash>/<file>
            parts = rest.split("/")
            if len(parts) > drop_after_version + 1:
                parts = parts[:drop_after_version] + parts[drop_after_version + 1 :]
            rest = "/".join(parts)
        if rest and "/" in rest:
            return rest
    return None


class SourcePaths:
    """Maps the file paths a report names onto record paths.

    A record path is relative to the scanned source root and uses forward
    slashes. ``roots`` are the directories the report or the caller name as
    that root, tried longest first; ``prefixes`` are directories the report
    itself ties to a package, each with the label a file below it is
    spelled under (``github.com/example/lib@v1.0.0/lib.go`` for a Go module
    the report places outside the root). A file inside a package cache gets
    the cache's own package and version spelling. Any other absolute path
    cannot be made relative: :meth:`relative` returns ``None`` and counts
    each distinct path once, and the record that would have carried it carries a
    ``location-outside-root`` caveat instead.

    :meth:`neutral` rewrites the same directories inside any report value,
    so a discriminator computed from it is the same whichever directory the
    report was produced in.
    """

    def __init__(
        self,
        roots: Iterable[Any] = (),
        prefixes: Iterable[Tuple[Any, str]] = (),
    ) -> None:
        seen = set()
        self._roots: List[str] = []
        for root in roots:
            normalized = _normalize_dir(root) if isinstance(root, str) else ""
            if normalized and is_absolute_path(normalized) and normalized not in seen:
                seen.add(normalized)
                self._roots.append(normalized)
        self._roots.sort(key=len, reverse=True)
        self._prefixes: List[Tuple[str, str]] = []
        for directory, label in prefixes:
            normalized = _normalize_dir(directory) if isinstance(directory, str) else ""
            if normalized and is_absolute_path(normalized) and label and normalized not in seen:
                seen.add(normalized)
                self._prefixes.append((normalized, label))
        self._prefixes.sort(key=lambda pair: len(pair[0]), reverse=True)
        self._dropped: set = set()

    @property
    def dropped(self) -> int:
        """How many distinct file paths could not be made relative."""
        return len(self._dropped)

    def relative(self, file: Any) -> Optional[str]:
        """The record path of ``file``, or ``None`` when the report names no
        file or names one that cannot be made relative."""
        if not isinstance(file, str) or not file.strip():
            return None
        text = _slashes(file.strip())
        if not is_absolute_path(text):
            normalized = posixpath.normpath(text)
            if normalized == "." or normalized.startswith("../") or normalized == "..":
                self._dropped.add(text)
                return None
            return normalized
        text = posixpath.normpath(text)
        # A prefix is a package directory, which can sit inside the root
        # (a vendored module) and is then still spelled from the root.
        for root in self._roots:
            below = _under(text, root)
            if below is not None:
                return below
        for directory, label in self._prefixes:
            below = _under(text, directory)
            if below is not None:
                return f"{label}/{below}"
        cached = _cache_form(text)
        if cached is not None:
            return cached
        self._dropped.add(text)
        return None

    def neutral(self, value: Any) -> Any:
        """``value`` with every root and package directory spelled the same
        whichever directory the report was produced in: the roots become
        ``<root>`` and a package directory becomes its label, inside every
        string at any depth, with backslashes read as forward slashes."""
        if isinstance(value, str):
            text = _slashes(value)
            for root in self._roots:
                text = _replace_dir(text, root, "<root>")
            for directory, label in self._prefixes:
                text = _replace_dir(text, directory, label)
            return text
        if isinstance(value, list):
            return [self.neutral(item) for item in value]
        if isinstance(value, dict):
            return {key: self.neutral(item) for key, item in value.items()}
        return value

    def absolute_form(self, path: str) -> Optional[str]:
        """The stable spelling of one absolute path with no side effect on
        :attr:`dropped`: its relative path when a root or a package
        directory holds it (``.`` for a root itself), its package cache
        spelling, or ``None``."""
        text = posixpath.normpath(_slashes(path.strip()))
        for root in self._roots:
            if (text.casefold() if _DRIVE_RE.match(root) else text) == (
                root.casefold() if _DRIVE_RE.match(root) else root
            ):
                return "."
            below = _under(text, root)
            if below is not None:
                return below
        for directory, label in self._prefixes:
            below = _under(text, directory)
            if below is not None:
                return f"{label}/{below}"
        return _cache_form(text)

    def stable(self, value: Any) -> Any:
        """``value`` spelled the same on every machine, for hashing into a
        discriminator; never stored.

        A string that is one absolute path becomes its relative path when a
        root or package directory holds it, its package cache spelling, or
        ``<outside>/`` plus its file name when nothing holds it, so neither
        the scan root nor a home directory changes the hash. Any other
        string has the roots and package directories rewritten as
        :meth:`neutral` does and every home directory (``/home/<user>``,
        ``/Users/<user>``, ``C:\\Users\\<user>``) spelled ``~``."""
        if isinstance(value, str):
            text = _slashes(value).strip()
            if is_absolute_path(text):
                form = self.absolute_form(text)
                if form is not None:
                    return form
                return "<outside>/" + posixpath.basename(posixpath.normpath(text))
            return _HOME_RE.sub("~", self.neutral(value))
        if isinstance(value, list):
            return [self.stable(item) for item in value]
        if isinstance(value, dict):
            return {key: self.stable(item) for key, item in value.items()}
        return value

    def redact(self, value: Any) -> Any:
        """``value`` with the scan root and home directories taken out of
        every string, at any depth, for storing as a record attribute.

        A root followed by a path becomes that path relative to the root
        (``python3 /src/app.py`` reads ``python3 app.py``), a root on its
        own becomes ``.``, and a home directory becomes ``~``, in either
        slash spelling. The rest of the text is kept as given: a value that
        names no root and no home directory (a URL path, a system library
        path) carries neither a user name nor the checkout path."""
        if isinstance(value, str):
            text = value
            for root in self._roots:
                text = _strip_dir(text, root)
            return _HOME_RE.sub("~", text)
        if isinstance(value, list):
            return [self.redact(item) for item in value]
        if isinstance(value, dict):
            return {key: self.redact(item) for key, item in value.items()}
        return value

    def outside_root_caveat(self, count: int) -> EvidenceCaveat:
        """The caveat a record carries for ``count`` files it left out."""
        return EvidenceCaveat(
            kind="location-outside-root",
            detail=(
                f"{count} file path(s) the producer named lie outside the source root "
                "and no package directory; the record leaves them out"
            ),
        )

    def producer_caveat(self) -> Optional[EvidenceCaveat]:
        """The producer-level caveat for every file left out so far."""
        if not self.dropped:
            return None
        return EvidenceCaveat(
            kind="location-outside-root",
            detail=(
                f"{self.dropped} file path(s) the producer named lie outside the source "
                "root and no package directory; the records leave them out"
            ),
        )


#: A home directory inside any text: ``/home/<user>``, ``/Users/<user>``
#: or a Windows ``<drive>:\\Users\\<user>`` in either slash spelling. The
#: match starts at the beginning of the text or after a character that
#: cannot end a path segment, so ``http://host/home/x`` is not a home.
_HOME_RE = re.compile(
    r"(?<![A-Za-z0-9_.~/\\-])(?:/home/|/Users/|(?i:[A-Z]:[\\/]users[\\/]))"
    r"[^/\\\s\"'<>|:;,]+"
)


def _strip_dir(text: str, directory: str) -> str:
    """``text`` with ``directory`` (forward slashes) taken out wherever it
    starts a path, in either slash spelling: ``<directory>/x`` reads ``x``
    and the directory on its own reads ``.``."""
    flags = re.IGNORECASE if _DRIVE_RE.match(directory) else 0
    spellings = {directory, directory.replace("/", "\\")}
    for spelling in sorted(spellings, key=len, reverse=True):
        lead = r"(?<![A-Za-z0-9_.~/\\-])" + re.escape(spelling)
        text = re.sub(lead + r"[/\\]+", "", text, flags=flags)
        text = re.sub(lead + r"(?=$|[^A-Za-z0-9_.~/\\-])", ".", text, flags=flags)
    return text


def _replace_dir(text: str, directory: str, replacement: str) -> str:
    flags = re.IGNORECASE if _DRIVE_RE.match(directory) else 0
    return re.sub(
        re.escape(directory) + r"(?=/|$|[^A-Za-z0-9_.-])", replacement, text, flags=flags
    )


#: Report keys that carry a producer's own object ids. They are left out of
#: a root-neutral discriminator: producers derive them from absolute paths
#: (golem hashes the file name into long ids), so they change with the
#: directory the report was produced in.
_ID_KEY_RE = re.compile(r"(^id$|^ids$|Ids?$|_ids?$)")


def _without_ids(value: Any) -> Any:
    if isinstance(value, list):
        return [_without_ids(item) for item in value]
    if isinstance(value, dict):
        return {
            key: _without_ids(item)
            for key, item in value.items()
            if not (isinstance(key, str) and _ID_KEY_RE.search(key))
        }
    return value


def neutral_discriminator(obj: Any, paths: SourcePaths, *extra: Any) -> str:
    """A discriminator for a report object that stays the same whichever
    directory the report was produced in.

    It is :func:`content_discriminator` over the object with the producer's
    id fields left out and the roots rewritten by :meth:`SourcePaths.neutral`,
    plus any ``extra`` values the caller adds to keep objects apart that
    would otherwise agree (the record's relative witness path, the report
    half an entry came from).
    """
    return content_discriminator([paths.neutral(_without_ids(obj)), *paths.neutral(list(extra))])


def stable_discriminator(obj: Any, paths: SourcePaths, *extra: Any) -> str:
    """A discriminator for a report object that is the same on every
    machine: :func:`content_discriminator` over the object and any
    ``extra`` values spelled by :meth:`SourcePaths.stable`.

    Unlike :func:`neutral_discriminator` it keeps the producer's id fields
    (an adapter whose producer derives no id from a path passes them in
    as content) and it spells a path outside every root by its file name,
    so neither the scan root nor the home directory moves the id."""
    return content_discriminator([paths.stable(obj), *paths.stable(list(extra))])


#: The ``record-skipped`` reason for a report object nested deeper than the
#: interpreter can walk. The adapter counts the object and reads the rest.
TOO_DEEP_REASON = "report objects nest deeper than the adapter reads and became no record"


def guard_extract(producer: str) -> Callable:
    """Wrap an adapter's ``extract`` so that a report of an unexpected shape
    that the per-entry checks did not catch returns a not-assessed result
    with the reason instead of raising or returning a partial result.

    A report nested deeper than the interpreter's recursion limit, or one
    too large for memory, is such a shape too. Adapters that can read the
    rest of a report around one over-deep object count that object as a
    skip with :data:`TOO_DEEP_REASON` themselves; this wrapper is the last
    line for the cases no per-object check covers."""

    def decorate(fn: Callable[..., "AdapterResult"]) -> Callable[..., "AdapterResult"]:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> "AdapterResult":
            try:
                return fn(*args, **kwargs)
            except (AttributeError, KeyError, IndexError, TypeError, ValueError) as exc:
                return not_assessed(
                    f"the {producer} report has a shape this adapter cannot read "
                    f"({type(exc).__name__}: {exc}); it was not assessed"
                )
            except RecursionError:
                return not_assessed(
                    f"the {producer} report nests its values deeper than this adapter "
                    "reads; it was not assessed"
                )
            except MemoryError:
                return not_assessed(
                    f"the {producer} report is too large to read in memory; it was not assessed"
                )

        return wrapper

    return decorate


def build_record(
    *,
    source: str,
    producer: EvidenceProducer,
    kind: str,
    discriminator: str,
    polarity: str = "positive",
    purls: Tuple[str, ...] = (),
    component_ref: Optional[str] = None,
    locations: Tuple[EvidenceLocation, ...] = (),
    path: Tuple[EvidencePathNode, ...] = (),
    confidence: Optional[str] = None,
    attributes: Optional[dict] = None,
    caveats: Tuple[EvidenceCaveat, ...] = (),
) -> Evidence:
    """One record, with the id, the path cap and the caveats applied.

    Everything the producer stated is kept as given: the confidence string,
    the attributes, the purls. The id comes from the record's identity
    parts and the discriminator, which is the producer's own object id when
    the report names one and :func:`content_discriminator` of the report
    object when it does not. A path longer than the cap is truncated and
    the truncation caveat is appended to the record's caveats.
    """
    if kind not in KINDS:
        raise ValueError(f"unknown record kind {kind!r}; known kinds: {', '.join(KINDS)}")
    if polarity not in POLARITIES:
        raise ValueError(f"unknown polarity {polarity!r}; known: {', '.join(POLARITIES)}")
    path_nodes, truncated = cap_path(list(path))
    record_caveats = list(caveats)
    if truncated is not None:
        record_caveats.append(truncated)
    location_list = list(locations)
    first = location_list[0] if location_list else None
    return Evidence(
        schema_version=EVIDENCE_SCHEMA_VERSION,
        id=record_id(producer.name, kind, purls, first, discriminator),
        producer=producer,
        kind=kind,
        polarity=polarity,
        subject=EvidenceSubject(purls=list(purls), component_ref=component_ref),
        source=source,
        locations=location_list,
        caveats=record_caveats,
        path=path_nodes or None,
        confidence=confidence,
        attributes=attributes,
    )


__all__ = [
    "AdapterResult",
    "SkipTally",
    "SourcePaths",
    "as_dict",
    "as_hashable_str",
    "as_line",
    "as_list",
    "as_str",
    "guard_extract",
    "is_absolute_path",
    "neutral_discriminator",
    "stable_discriminator",
    "TOO_DEEP_REASON",
    "STATUS_COMPLETED",
    "STATUS_NOT_ASSESSED",
    "VersionGate",
    "add_caveat",
    "build_record",
    "cdxgen_tool",
    "gate_cdxgen_tool_version",
    "cap_path",
    "content_discriminator",
    "gate_report_version",
    "not_assessed",
]
