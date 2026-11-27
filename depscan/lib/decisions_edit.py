"""Editing the decisions file in place, with its comments and order kept.

``depscan triage`` and the server's ``propose_triage`` write the file
through this module: tomlkit loads the document, the edit changes one entry
or appends one, and the save serialises with the comments and the entry
order intact, validates the result against the published decisions schema,
and writes it atomically. A file the edit would break is never written.
"""

import os
import tempfile
from typing import Any, Dict, List, Optional

import tomlkit
from tomlkit.items import Table

from analysis_lib.findings.decisions import parse_decisions_document


class TriageEditError(ValueError):
    """The edit cannot be made: the entry named does not exist, or a
    required value is missing."""


def load_document(path: str) -> Any:
    """Load the decisions file as a tomlkit document, preserving comments.

    A file that does not end with a newline is loaded with one added, so
    the last entry's serialization carries the line break an appended entry
    needs; the file on disk is otherwise untouched until the save.
    """
    with open(path, encoding="utf-8") as handle:
        text = handle.read()
    if text and not text.endswith("\n"):
        text += "\n"
    return tomlkit.loads(text)


def triage_tables(document: Any) -> List[Table]:
    """The ``[[triage]]`` entries of a tomlkit document, in file order."""
    array = document.get("triage")
    if array is None:
        return []
    return list(array)


def _selector_of(table: Table) -> Dict[str, Any]:
    return {
        key: str(table[key])
        for key in ("finding", "advisory", "purl", "version_range")
        if key in table
    }


def _new_document() -> Any:
    document = tomlkit.document()
    document.add(tomlkit.comment("Decisions about findings: triage decisions, the baseline"))
    document.add(tomlkit.comment("and the expectations the gate evaluates."))
    document.add(tomlkit.comment("Reviewed in pull requests; not part of depscan.toml."))
    return document


def save_document(path: str, document: Any) -> None:
    """Serialise, validate against the published schema, and write.

    The validation runs on the serialised text, exactly what the file will
    hold, so a file this module writes is always a file a scan can load.
    """
    text = tomlkit.dumps(document)
    parse_decisions_document(text)
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=directory, delete=False, suffix=".tmp"
    )
    try:
        with handle:
            handle.write(text)
        os.replace(handle.name, path)
    except BaseException:
        try:
            os.unlink(handle.name)
        except OSError:
            pass
        raise


def set_entry(
    path: str,
    *,
    selector: Dict[str, Any],
    fields: Dict[str, Any],
    create: bool = True,
) -> str:
    """Add or update the triage entry ``selector`` names.

    An entry with the same selector is updated in place: its fields take
    the new values, its comments and position stay. Otherwise a new entry is
    appended, in a new file when ``create`` is set and the file does not
    exist. The saved file is validated against the published schema before
    it is written.

    :returns: ``"updated"`` or ``"added"``.
    :raises TriageEditError: When the file is missing and ``create`` is
        false, or the selector is empty.
    """
    if not selector:
        raise TriageEditError(
            "the entry needs a selector: a finding id, or an advisory and a purl"
        )
    if os.path.isfile(path):
        document = load_document(path)
    elif create:
        document = _new_document()
    else:
        raise TriageEditError(f"the decisions file '{path}' does not exist")
    target: Optional[Table] = None
    for table in triage_tables(document):
        if _selector_of(table) == selector:
            target = table
            break
    if target is None:
        table = tomlkit.table()
        for key, value in selector.items():
            table[key] = value
        for key, value in fields.items():
            if value is not None:
                table[key] = value
        if "triage" not in document:
            document["triage"] = tomlkit.aot()
        document["triage"].append(table)
        save_document(path, document)
        return "added"
    for key, value in fields.items():
        if value is None:
            if key in target:
                del target[key]
            continue
        target[key] = value
    save_document(path, document)
    return "updated"


def entry_at(path: str, index: int) -> tuple[Any, Table]:
    """The tomlkit document and the triage entry at the 1-based position,
    the handle ``depscan triage list`` prints.

    :raises TriageEditError: When the file has no such entry.
    """
    if not os.path.isfile(path):
        raise TriageEditError(f"the decisions file '{path}' does not exist")
    document = load_document(path)
    tables = triage_tables(document)
    if index < 1 or index > len(tables):
        raise TriageEditError(
            f"the decisions file '{path}' has no triage entry {index}; it holds {len(tables)}"
        )
    return document, tables[index - 1]


def approve_entry(path: str, index: int, approver: str) -> str:
    """Approve the proposal at ``index``, naming the person who approved.

    The entry must be a proposal, proposed by someone and neither approved
    nor entered by a person; a person's own entry needs no approval.

    :raises TriageEditError: When the entry is not a proposal.
    """
    document, table = entry_at(path, index)
    if not table.get("proposed_by") or table.get("approver") or table.get("author"):
        raise TriageEditError(
            f"triage entry {index} is not a proposal awaiting approval: only an entry "
            "with proposed_by and neither approver nor author can be approved"
        )
    table["approver"] = approver
    save_document(path, document)
    return str(table["state"])


def remove_entry(path: str, index: int) -> Dict[str, Any]:
    """Remove the entry at ``index``, whatever kind it is, and return its
    document as it stood."""
    document, table = entry_at(path, index)
    removed = entry_document(table, index=index)
    document["triage"].remove(table)
    save_document(path, document)
    return removed


def entry_document(table: Any, *, index: int) -> Dict[str, Any]:
    """One entry as the JSON document the listings carry. ``table`` is a
    tomlkit table or a plain mapping of the entry's fields."""
    document: Dict[str, Any] = {"index": index}
    document.update(_selector_of(table))
    for key in ("state", "justification", "detail", "author", "approver", "created", "expires"):
        if key in table:
            document[key] = str(table[key])
    if "responses" in table:
        document["responses"] = [str(value) for value in table["responses"]]
    if "proposed_by" in table:
        document["proposedBy"] = str(table["proposed_by"])
    return document
