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
import stat
import tempfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import tomlkit
from tomlkit.items import Table

from analysis_lib.findings.decisions import (
    DecisionsError,
    TriageEntry,
    decisions_from_document,
    entry_handle,
    parse_decisions_document,
)
from depscan.lib.decisions import file_digest


class TriageEditError(ValueError):
    """The edit cannot be made: the file cannot be read or does not parse,
    the entry named does not exist, or the file changed since it was read."""


@dataclass
class LoadedFile:
    """A decisions file read for an edit: the tomlkit document, its triage
    entries as the loader reads them (in the same order as the tables), and
    the digest of the bytes read, None for a file that did not exist.
    ``newline`` and ``bom`` record the file's line endings and whether it
    started with a UTF-8 byte order mark, so the save writes them back."""

    path: str
    document: Any
    entries: List[TriageEntry] = field(default_factory=list)
    digest: Optional[str] = None
    newline: str = "\n"
    bom: bool = False

    @property
    def tables(self) -> List[Table]:
        array = self.document.get("triage")
        return list(array) if array is not None else []


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
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TriageEditError(
            f"the decisions file '{path}' is not UTF-8 text: the byte at offset {exc.start} "
            "cannot be decoded; save the file as UTF-8"
        ) from exc
    bom = text.startswith("\ufeff")
    if bom:
        text = text[1:]
    # tomlkit edits a document with one kind of line ending; the file's own
    # kind is restored when it is written.
    newline = "\r\n" if b"\r\n" in raw else "\n"
    text = text.replace("\r\n", "\n")
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
        newline=newline,
        bom=bom,
    )


def _duplicate_handles(entries: List[TriageEntry]) -> List[str]:
    """The handles more than one entry carries, in file order."""
    seen: Dict[str, int] = {}
    for entry in entries:
        seen[entry.handle] = seen.get(entry.handle, 0) + 1
    return [handle for handle, count in seen.items() if count > 1]


def _new_file_mode() -> int:
    """The mode a newly created file gets under the process umask."""
    umask = os.umask(0)
    os.umask(umask)
    return 0o666 & ~umask


def save(loaded: LoadedFile) -> List[TriageEntry]:
    """Validate the edited document and replace the file with it.

    The file keeps its line endings, its byte order mark and its mode. A
    path that is a symbolic link is followed: the target is replaced, in
    its own directory, and the link stays. The bytes that reach the disk
    are the bytes validated.

    :returns: The triage entries of the file as written.
    :raises TriageEditError: When the edit would leave a file a scan
        refuses, would leave two entries with one handle, or the file
        changed on disk since :func:`load` read it.
    """
    text = tomlkit.dumps(loaded.document)
    if loaded.newline != "\n":
        text = text.replace("\r\n", "\n").replace("\n", loaded.newline)
    data = (("\ufeff" if loaded.bom else "") + text).encode("utf-8")
    try:
        entries = decisions_from_document(
            parse_decisions_document(data.decode("utf-8-sig"))
        ).triage
    except DecisionsError as exc:
        raise TriageEditError(f"the edit would leave a file a scan refuses: {exc}") from exc
    duplicates = _duplicate_handles(entries)
    if duplicates:
        raise TriageEditError(
            f"the edit would leave more than one entry with the handle "
            f"{', '.join(duplicates)} in '{loaded.path}', and a handle must name one entry; "
            "edit the file to keep one of them"
        )
    path = os.path.realpath(loaded.path)
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    try:
        mode = stat.S_IMODE(os.stat(path).st_mode)
    except FileNotFoundError:
        mode = _new_file_mode()
    handle = tempfile.NamedTemporaryFile(mode="wb", dir=directory, delete=False, suffix=".tmp")
    try:
        with handle:
            handle.write(data)
        os.chmod(handle.name, mode)
        if file_digest(path) != loaded.digest:
            raise TriageEditError(
                f"the decisions file '{loaded.path}' changed since it was read; run the "
                "command again to edit the file as it is now"
            )
        os.replace(handle.name, path)
    except BaseException:
        try:
            os.unlink(handle.name)
        except OSError:
            pass
        raise
    return entries


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


def _append_table(loaded: LoadedFile, table: Table) -> None:
    """Append a table to the triage array with a blank line on each side,
    the way a person would add one, whatever follows the array."""
    document = loaded.document
    if "triage" not in document:
        text = document.as_string()
        if text.strip() and not text.endswith("\n\n"):
            document.add(tomlkit.nl())
        document["triage"] = tomlkit.aot()
    array = document["triage"]
    if len(array) and not array[-1].as_string().endswith("\n\n"):
        array[-1].add(tomlkit.nl())
    array.append(table)
    if not tomlkit.dumps(document).endswith(table.as_string()):
        table.add(tomlkit.nl())


def write_entry(
    loaded: LoadedFile, *, selector: Dict[str, str], fields: Dict[str, Any]
) -> Tuple[str, int, List[TriageEntry]]:
    """Add the entry, or replace the one it supersedes, and save.

    The entry to replace is found by handle, so a selector that differs only
    in the case of the advisory or in the spelling of the purl replaces the
    entry it would otherwise shadow. A proposal (``fields`` carries
    ``proposed_by``) replaces only the same proposer's proposal with that
    handle; a person's decision is left alone and the proposal is appended
    beside it. A live entry replaces the live entry with that handle, as a
    whole: fields the new entry does not name do not survive. Otherwise the
    entry is appended.

    :returns: ``("added" or "updated", 0-based position, entries as
        written)``.
    """
    proposed_by = fields.get("proposed_by")
    handle = entry_handle(
        TriageEntry(
            index=0, state=str(fields.get("state") or ""), proposed_by=proposed_by, **selector
        )
    )
    target = None
    for position, entry in enumerate(loaded.entries):
        if entry.handle == handle and entry.is_proposal == (proposed_by is not None):
            target = position
            break
    values = {**selector, **{key: value for key, value in fields.items() if value is not None}}
    if target is None:
        table = tomlkit.table()
        for key, value in values.items():
            table[key] = value
        _append_table(loaded, table)
        return "added", len(loaded.tables) - 1, save(loaded)
    table = loaded.tables[target]
    for key in list(table.keys()):
        del table[key]
    for key, value in values.items():
        table[key] = value
    return "updated", target, save(loaded)


def approve_entry(
    loaded: LoadedFile, position: int, approver: str
) -> Tuple[List[TriageEntry], int, Optional[TriageEntry]]:
    """Approve the proposal at ``position``: the approver is recorded, and
    becomes the author when the proposal names none.

    The approved entry is a decision from then on. When a decision with the
    same selector already exists, the approved one replaces it, because the
    approver has just decided the finding: the earlier decision is removed,
    so no two decisions share a handle and the approved one applies.

    :returns: The entries as written, the approved entry's position among
        them, and the decision it replaced, None when it replaced none.
    :raises TriageEditError: When the entry is not a proposal.
    """
    entry = loaded.entries[position]
    if not entry.is_proposal:
        raise TriageEditError(
            f"triage entry {entry.handle} is not a proposal awaiting approval: only an "
            "entry with proposed_by and no approver can be approved"
        )
    table = loaded.tables[position]
    approved_handle = entry_handle(
        TriageEntry(index=0, state=entry.state, **entry.selector_document())
    )
    replaced = None
    for other_position, other in enumerate(loaded.entries):
        if (
            other_position != position
            and not other.is_proposal
            and (other.handle == approved_handle)
        ):
            replaced = other
            loaded.document["triage"].remove(loaded.tables[other_position])
            break
    table["approver"] = approver
    if "author" not in table:
        table["author"] = approver
    entries = save(loaded)
    new_position = next(
        index
        for index, written in enumerate(entries)
        if written.handle == approved_handle and not written.is_proposal
    )
    return entries, new_position, replaced


def remove_entry(loaded: LoadedFile, position: int) -> None:
    """Remove the entry at ``position``, whatever kind it is, and save."""
    loaded.document["triage"].remove(loaded.tables[position])
    save(loaded)


def entry_document(entry: TriageEntry) -> Dict[str, Any]:
    """One entry as the JSON document the listings and results carry. The
    keys are camelCase, as in every JSON document dep-scan writes."""
    document: Dict[str, Any] = {"index": entry.index, "handle": entry.handle}
    for key, value in entry.selector_document().items():
        document["versionRange" if key == "version_range" else key] = value
    for key in ("state", "justification", "detail", "author", "approver", "created", "expires"):
        if getattr(entry, key):
            document[key] = str(getattr(entry, key))
    if entry.responses:
        document["responses"] = list(entry.responses)
    if entry.proposed_by:
        document["proposedBy"] = str(entry.proposed_by)
    return document
