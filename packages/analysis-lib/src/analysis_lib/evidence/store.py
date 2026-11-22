"""Reading and writing ``evidence.jsonl`` and ``evidence.index.json``.

The store file holds one record per line, sorted by id, UTF-8, compact
JSON. Writing goes through a temporary file and a rename, so a reader sees
either the previous store or the complete new one, and two writes of the
same records produce identical bytes.

Exact duplicates collapse: the enrichment stage re-merges and rewrites the
store once per project type, so the same record can arrive twice. Copies
that differ only in their caveats (one run of a producer hit a timeout or a
budget the other did not report) become one record carrying every caveat
of every copy, so no caveat is lost to whichever copy arrived last. Records
whose ids match but whose other contents differ do not collapse; they keep
their identity. The group's members are ordered by their canonical JSON,
the first keeps the bare id and the ones after it get a ``-2``, ``-3``
suffix, so a rerun renames the same records the same way and nothing is
dropped.

Reads stream one record at a time: the reachability engine walks the whole
store once per scan and never needs it in memory at once.

The index maps components and findings to the records about them.
``byComponent`` keys are comparable purl forms, so a reached key and an
``affects`` ref spelled differently still land on the same entry;
``byFinding`` maps each finding id to the records whose subject purls
include any of the finding's component purls.
"""

import contextlib
import json
import os
import tempfile
from dataclasses import replace
from typing import Any, Dict, Iterable, Iterator, List

from analysis_lib.evidence import Evidence

#: The file names of the store, as the scan directory layout names them.
EVIDENCE_FILE = "evidence.jsonl"
EVIDENCE_INDEX_FILE = "evidence.index.json"

#: The index document's shape version, separate from the record's.
INDEX_SCHEMA_VERSION = "1"


def canonical_record(record: Evidence) -> str:
    """The record's canonical JSON: sorted keys, compact separators.

    This is the byte form of every store line, and the form the collision
    suffix rule and the duplicate rule compare records by.
    """
    return json.dumps(record.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def merge(base: Iterable[Evidence], incoming: Iterable[Evidence]) -> List[Evidence]:
    """The records written so far plus the records of this round.

    Merging only concatenates; :func:`finalize` applies the duplicate,
    caveat and collision rules at write time, so the rules hold for the file
    no matter how many rounds were merged.
    """
    return [*base, *incoming]


def _canonical_without_caveats(record: Evidence) -> str:
    data = record.to_dict()
    data.pop("caveats", None)
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _fold_caveats(copies: List[Evidence]) -> Evidence:
    """One record for copies that differ only in caveats.

    The copies are taken in canonical order; the first copy's caveats keep
    their order and every caveat a later copy adds follows, each once.
    """
    copies = sorted(copies, key=canonical_record)
    caveats = []
    seen = set()
    for record in copies:
        for caveat in record.caveats:
            key = (caveat.kind, caveat.detail)
            if key in seen:
                continue
            seen.add(key)
            caveats.append(caveat)
    if len(caveats) == len(copies[0].caveats):
        return copies[0]
    return replace(copies[0], caveats=caveats)


def finalize(records: Iterable[Evidence]) -> List[Evidence]:
    """The records as the store carries them: deduped, caveats merged,
    collisions suffixed, sorted by id.

    Records with the same id and the same canonical JSON collapse to one.
    Records with the same id that differ only in their caveats become one
    record holding the caveats of all of them. Records with the same id and
    other differences all survive: the group is ordered by canonical JSON,
    the first member keeps the bare id and each later member takes a ``-2``,
    ``-3`` suffix. The rules are deterministic, so a rerun of the same
    records writes the same file.
    """
    seen: Dict[str, Dict[str, List[Evidence]]] = {}
    for record in records:
        group = seen.setdefault(record.id, {})
        group.setdefault(_canonical_without_caveats(record), []).append(record)
    final: List[Evidence] = []
    for record_id, group in seen.items():
        members = sorted((_fold_caveats(copies) for copies in group.values()), key=canonical_record)
        final.append(members[0])
        for suffix, record in enumerate(members[1:], start=2):
            final.append(replace(record, id=f"{record_id}-{suffix}"))
    final.sort(key=lambda record: record.id)
    return final


def write(path: str, records: Iterable[Evidence]) -> int:
    """Write the records to ``path`` atomically and return how many were
    written.

    The file is created (with its parent directories) even for an empty
    record set, so a scan with no reachability evidence still produces the
    uniform layout. Lines end with a line feed on every platform, so the
    bytes a store write produces do not depend on the writing system. A
    failure part-way leaves the previous file intact and removes the
    temporary file.
    """
    final = finalize(records)
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    tmp = tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        newline="\n",
        dir=directory,
        prefix=os.path.basename(path) + ".",
        suffix=".tmp",
        delete=False,
    )
    try:
        with tmp as fp:
            for record in final:
                fp.write(canonical_record(record) + "\n")
        os.replace(tmp.name, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp.name)
        raise
    return len(final)


def stream(path: str) -> Iterator[Evidence]:
    """Yield the records of the store file one line at a time.

    The file is never materialized: a caller that stops iterating has read
    no further lines. A blank line is skipped; a line that is not a JSON
    object raises, because a damaged store must never read as a smaller
    store.
    """
    with open(path, encoding="utf-8") as fp:
        for line in fp:
            line = line.strip()
            if not line:
                continue
            yield Evidence.from_dict(json.loads(line))


def read(path: str) -> List[Evidence]:
    """Every record of the store file, in file order (id order for a store
    this module wrote)."""
    return list(stream(path))


def build_index(records: Iterable[Evidence], findings: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """The index document for the given records and findings.

    ``findings`` are the finding dictionaries of ``depscan.findings.json``,
    each with its ``id`` and ``components`` purls. A finding whose
    components match nothing still gets its (empty) entry, so the index
    says explicitly that no record backs it. Keys come back sorted, and the
    id lists under them are sorted.
    """
    from analysis_lib.findings.vdr_convert import comparable_purl

    by_component: Dict[str, set] = {}
    for record in records:
        for purl in record.subject.purls:
            ids = by_component.setdefault(comparable_purl(purl), set())
            ids.add(record.id)
    by_finding: Dict[str, List[str]] = {}
    for finding in findings:
        finding_id = str(finding.get("id") or "")
        keys = {comparable_purl(str(purl)) for purl in finding.get("components") or []}
        matched: set = set()
        for key in keys:
            matched.update(by_component.get(key, ()))
        by_finding[finding_id] = sorted(matched)
    return {
        "schemaVersion": INDEX_SCHEMA_VERSION,
        "byComponent": {key: sorted(ids) for key, ids in sorted(by_component.items())},
        "byFinding": dict(sorted(by_finding.items())),
    }


def write_index(path: str, index: Dict[str, Any]) -> None:
    """Write the index document to ``path`` through a temporary file and a
    rename, with sorted keys, so two writes of one index are identical."""
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    tmp = tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        newline="\n",
        dir=directory,
        prefix=os.path.basename(path) + ".",
        suffix=".tmp",
        delete=False,
    )
    try:
        with tmp as fp:
            json.dump(index, fp, indent=2, sort_keys=True)
            fp.write("\n")
        os.replace(tmp.name, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp.name)
        raise


__all__ = [
    "EVIDENCE_FILE",
    "EVIDENCE_INDEX_FILE",
    "INDEX_SCHEMA_VERSION",
    "build_index",
    "canonical_record",
    "finalize",
    "merge",
    "read",
    "stream",
    "write",
    "write_index",
]
