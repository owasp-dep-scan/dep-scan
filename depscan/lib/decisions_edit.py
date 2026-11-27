"""Editing the decisions file in place, with its comments and order kept.

``depscan triage`` and the server's ``propose_triage`` write the file
through this module. :func:`load` reads the file once: the bytes give the
digest, the published schema validates the text, and tomlkit keeps the
comments and the entry order for the edit. :func:`save` serialises the
edited document, validates it again, and replaces the file through a
temporary file and a rename, refusing when the file changed since it was
read, so two writers never lose each other's edit silently. A file the edit
would break is never written.
"""

import hashlib
import os
import tempfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import tomlkit
from tomlkit.items import Table

from analysis_lib.findings.decisions import (
    DecisionsError,
    TriageEntry,
    decisions_from_document,
    parse_decisions_document,
)

#: The selector keys of a triage entry, in the order the file carries them.
SELECTOR_KEYS = ("finding", "advisory", "purl", "version_range")


class TriageEditError(ValueError):
    """The edit cannot be made: the file cannot be read or does not parse,
    the entry named does not exist, or the file changed since it was read."""


@dataclass
class LoadedFile:
    """A decisions file read for an edit: the tomlkit document, its triage
    entries as the loader reads them (in the same order as the tables), and
    the digest of the bytes read, None for a file that did not exist."""

    path: str
    document: Any
    entries: List[TriageEntry] = field(default_factory=list)
    digest: Optional[str] = None

    @property
    def tables(self) -> List[Table]:
        array = self.document.get("triage")
        return list(array) if array is not None else []


def _digest(path: str) -> Optional[str]:
    try:
        with open(path, "rb") as handle:
            return hashlib.sha256(handle.read()).hexdigest()
    except FileNotFoundError:
        return None


def _new_document() -> Any:
    document = tomlkit.document()
    document.add(tomlkit.comment("Decisions about findings: triage decisions, the baseline"))
    document.add(tomlkit.comment("and the expectations the gate evaluates."))
    document.add(tomlkit.comment("Reviewed in pull requests; not part of depscan.toml."))
    return document


def load(path: str, *, create: bool = False) -> LoadedFile:
    """Read the decisions file at ``path`` for an edit.

    A missing file is an empty document when ``create`` is set.

    :raises TriageEditError: When the file is missing and ``create`` is not
        set, is not UTF-8 text, or breaks its schema; the message names the
        key and the line.
    """
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except FileNotFoundError:
        if create:
            return LoadedFile(path=path, document=_new_document())
        raise TriageEditError(f"the decisions file '{path}' does not exist") from None
    except OSError as exc:
        raise TriageEditError(
            f"the decisions file '{path}' cannot be read: {exc.strerror or exc}"
        ) from exc
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise TriageEditError(
            f"the decisions file '{path}' is not UTF-8 text: the byte at offset {exc.start} "
            "cannot be decoded; save the file as UTF-8"
        ) from exc
    try:
        entries = decisions_from_document(parse_decisions_document(text)).triage
    except DecisionsError as exc:
        raise TriageEditError(f"{path}: {exc}") from exc
    if text and not text.endswith("\n"):
        # The last entry's serialization then carries the line break an
        # appended entry needs; the file is untouched until the save.
        text += "\n"
    return LoadedFile(
        path=path,
        document=tomlkit.loads(text),
        entries=entries,
        digest=hashlib.sha256(raw).hexdigest(),
    )


def save(loaded: LoadedFile) -> List[TriageEntry]:
    """Validate the edited document and replace the file with it.

    :returns: The triage entries of the file as written.
    :raises TriageEditError: When the edit would leave a file a scan
        refuses, or the file changed on disk since :func:`load` read it.
    """
    text = tomlkit.dumps(loaded.document)
    try:
        entries = decisions_from_document(parse_decisions_document(text)).triage
    except DecisionsError as exc:
        raise TriageEditError(f"the edit would leave a file a scan refuses: {exc}") from exc
    path = loaded.path
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=directory, delete=False, suffix=".tmp"
    )
    try:
        with handle:
            handle.write(text)
        if _digest(path) != loaded.digest:
            raise TriageEditError(
                f"the decisions file '{path}' changed since it was read; run the command "
                "again to edit the file as it is now"
            )
        os.replace(handle.name, path)
    except BaseException:
        try:
            os.unlink(handle.name)
        except OSError:
            pass
        raise
    return entries


def selector_of(table: Any) -> Dict[str, str]:
    """The selector keys a table or mapping carries, as strings."""
    return {key: str(table[key]) for key in SELECTOR_KEYS if key in table}


def find_handle(loaded: LoadedFile, handle: str) -> int:
    """The 0-based position of the one entry with ``handle``.

    :raises TriageEditError: When no entry has it, or more than one does
        (two entries with the same selector share a handle).
    """
    positions = [index for index, entry in enumerate(loaded.entries) if entry.handle == handle]
    if not positions:
        raise TriageEditError(
            f"no triage entry in '{loaded.path}' has the handle {handle}; depscan triage "
            "list prints the handles"
        )
    if len(positions) > 1:
        raise TriageEditError(
            f"the handle {handle} names {len(positions)} entries of '{loaded.path}' with the "
            "same selector; edit the file to keep one of them"
        )
    return positions[0]


def write_entry(
    loaded: LoadedFile, *, selector: Dict[str, str], fields: Dict[str, Any]
) -> Tuple[str, int, List[TriageEntry]]:
    """Add the entry, or replace the one it supersedes, and save.

    A proposal (``fields`` carries ``proposed_by``) replaces only a proposal
    with the same selector and the same ``proposed_by``; any other entry,
    a person's decision above all, is left alone and the proposal is
    appended. A live entry replaces the first live entry with the same
    selector, as a whole: fields the new entry does not name do not survive.
    Otherwise the entry is appended.

    :returns: ``("added" or "updated", 0-based position, entries as
        written)``.
    """
    proposed_by = fields.get("proposed_by")
    target = None
    for position, (table, entry) in enumerate(zip(loaded.tables, loaded.entries)):
        if selector_of(table) != selector:
            continue
        if proposed_by is not None:
            if entry.is_proposal and entry.proposed_by == proposed_by:
                target = position
                break
        elif not entry.is_proposal:
            target = position
            break
    values = {**selector, **{key: value for key, value in fields.items() if value is not None}}
    if target is None:
        table = tomlkit.table()
        for key, value in values.items():
            table[key] = value
        if "triage" not in loaded.document:
            loaded.document["triage"] = tomlkit.aot()
        loaded.document["triage"].append(table)
        return "added", len(loaded.tables) - 1, save(loaded)
    table = loaded.tables[target]
    for key in list(table.keys()):
        del table[key]
    for key, value in values.items():
        table[key] = value
    return "updated", target, save(loaded)


def approve_entry(loaded: LoadedFile, position: int, approver: str) -> List[TriageEntry]:
    """Approve the proposal at ``position``: the approver is recorded, and
    becomes the author when the proposal names none.

    :raises TriageEditError: When the entry is not a proposal.
    """
    entry = loaded.entries[position]
    if not entry.is_proposal:
        raise TriageEditError(
            f"triage entry {entry.handle} is not a proposal awaiting approval: only an "
            "entry with proposed_by and no approver can be approved"
        )
    table = loaded.tables[position]
    table["approver"] = approver
    if "author" not in table:
        table["author"] = approver
    return save(loaded)


def remove_entry(loaded: LoadedFile, position: int) -> None:
    """Remove the entry at ``position``, whatever kind it is, and save."""
    loaded.document["triage"].remove(loaded.tables[position])
    save(loaded)


def entry_document(entry: TriageEntry) -> Dict[str, Any]:
    """One entry as the JSON document the listings and results carry."""
    document: Dict[str, Any] = {"index": entry.index, "handle": entry.handle}
    document.update(entry.selector_document())
    for key in ("state", "justification", "detail", "author", "approver", "created", "expires"):
        if getattr(entry, key):
            document[key] = str(getattr(entry, key))
    if entry.responses:
        document["responses"] = list(entry.responses)
    if entry.proposed_by:
        document["proposedBy"] = str(entry.proposed_by)
    return document
