"""blint review reports -> evidence records.

This module is the only code that knows the blint review report formats:
the ``findings.json``, ``reviews.json`` and ``analysis-coverage.json``
documents a blint review writes beside the BOM. The reports name no schema
version of their own, so the version gate runs on the blint tool version
the caller passes (the blint-written BOM's ``metadata.tools`` names it),
and the gate's caveats say so; the locally installed blint package is
never asked.

Two kinds of output become records, both ``presence`` records about the
binary the report names:

1. Security check findings become records with polarity ``negative``: a
   blint finding is a check the analysis ran whose property the binary
   lacks, so the polarity follows from what a finding is and is never
   sniffed from the rule id.
2. Capability reviews become records with polarity ``positive``: the
   review states what the binary does import, with one location per
   evidence symbol so symbol presence is per symbol. A review whose
   evidence is empty keeps one location for the file.

Subject purls come from the BOM component the binary reconciles to. A
component matches when its name, or the name in its purl (version,
qualifiers and subpath removed, percent-decoding applied, the subpath's
last segment included), is the binary's file name or the name blint's own
SBOM gives that file: a ``.dll`` loses its suffix and a ``.rlib`` is named
by its crate. No reconciliation means the record is still written with
empty purls and its location carries it. Every non-path value an entry
carries is kept in the record's attributes as given, with the ``evidence``
object's paths neutralized and home directories taken out of every
string.

The coverage document's failed and skipped unit counts (a number, or a
string of digits) become ``coverage-gap`` caveats on the producer result
and on every record. Every report object that cannot become a record or
a part of one (an entry that is not a JSON object, an evidence list that
is not a list, a ``filename`` that is not a string, a unit count that is
not a number, a coverage document of the wrong shape, an entry nested
deeper than the adapter reads) is counted in one ``record-skipped``
caveat per reason. A
malformed required findings document instead yields a not-assessed result
with the reason, never a partial read.

A scan whose review produced only the coverage file completed and found
nothing to report: that call is ``completed`` with zero records. A call
with no document at all cannot claim the analysis ran and is not assessed.

Binary paths are stored relative to the source root through
``SourcePaths``. A path that cannot be made relative (a Windows drive path
with no matching root) reaches no location and no id, is counted in a
``location-outside-root`` caveat, and leaves its basename behind in the
record's attributes (``fileName``), so a finding built from the record
still names its binary. Record ids hash the path fields in their relative
spelling rather than as written (a path no root holds is left out), and
keep the rule ``id`` and blint's own ``finding_id``, a content hash of the
rule, the binary's digest and the evidence locator that tells apart the
repeats blint numbers itself; the same report produced in another
directory gives the same ids.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import unquote

from analysis_lib.evidence import (
    Evidence,
    EvidenceCaveat,
    EvidenceLocation,
    EvidenceProducer,
)
from analysis_lib.evidence.adapters import (
    AdapterResult,
    STATUS_COMPLETED,
    SkipTally,
    SourcePaths,
    TOO_DEEP_REASON,
    as_str,
    build_record,
    gate_report_version,
    guard_extract,
    not_assessed,
    stable_discriminator,
)

#: The blint tool major this adapter reads, and the newest minor it knows.
#: The gate runs on the tool version because the reports carry no schema
#: version of their own.
SUPPORTED_MAJOR = 4
KNOWN_MINOR = 0

PRODUCER_NAME = "blint"

#: The path-carrying fields of a findings or reviews entry. They are stored
#: relative through :class:`SourcePaths`, never absolute, and the location
#: (not the attributes) carries the binary's ``filename``.
_PATH_FIELDS = ("filename", "exe_name")


def _parse_document(document: Any) -> Tuple[Optional[Any], Optional[str]]:
    """A report as a parsed value, accepting JSON text as well as an
    already-parsed object."""
    if isinstance(document, (str, bytes)):
        try:
            return json.loads(document), None
        except RecursionError:
            return None, "the report nests its values deeper than this adapter reads"
        except ValueError as e:
            return None, f"the report is not valid JSON: {e}"
    return document, None


def _basename(path: Any) -> str:
    """A path's last segment, reading either separator."""
    text = as_str(path).replace("\\", "/").strip()
    return text.rsplit("/", 1)[-1] if text else ""


def _purl_names(purl: str) -> List[str]:
    """The name-bearing parts of a purl, percent-decoded: the name (the
    last segment of its path, without the ``@version``) and the last
    segment of its subpath, the two places a binary's file name can sit in
    a purl a binary SBOM writes (``pkg:generic/plain-libc-demo.elf``,
    ``pkg:generic/libfoo%2B%2B.so``, ``pkg:nuget/MyApp@1.2.0``)."""
    head, _, subpath = purl.partition("#")
    path = head.split("?", 1)[0].partition(":")[2].lstrip("/")
    names = []
    if "/" in path:
        last = path.rsplit("/", 1)[-1]
        name = last.rsplit("@", 1)[0] if "@" in last else last
        if name:
            names.append(unquote(name))
    subpath = subpath.strip("/")
    if subpath:
        names.append(unquote(subpath.rsplit("/", 1)[-1]))
    return names


def _binary_names(basename: str) -> List[str]:
    """The names a binary's file can carry in a BOM: the file name itself,
    and the name blint's own SBOM gives it (a ``.dll`` without the suffix,
    compared without case as Windows names are; a ``.rlib`` as its crate
    name, ``libfoo-1a2b.rlib`` reading ``foo``)."""
    names = [basename]
    lowered = basename.lower()
    if lowered.endswith(".dll") and len(basename) > 4:
        names.append(basename[:-4])
    if lowered.endswith(".rlib"):
        names.append(basename.split("-")[0].removeprefix("lib").removesuffix(".rlib"))
    return names


def _binary_subject(filename: Any, components: List[dict]) -> Tuple[List[str], Optional[str]]:
    """The subject of a binary's records: the purls of every component its
    basename matches, and the first match's ``bom-ref``.

    A component matches when its name is the binary's basename or one of
    the name-bearing parts of its purl is. A binary that matches nothing
    reconciles to no subject: the purls stay empty and the record's
    location carries it.
    """
    basename = _basename(filename)
    purls: List[str] = []
    component_ref: Optional[str] = None
    if basename:
        exact = basename
        folded = {name.casefold() for name in _binary_names(basename)[1:]}

        def matches(name: str) -> bool:
            return bool(name) and (name == exact or name.casefold() in folded)

        for component in components:
            if not isinstance(component, dict):
                continue
            purl = as_str(component.get("purl"))
            if not matches(as_str(component.get("name"))) and not (
                purl and any(matches(name) for name in _purl_names(purl))
            ):
                continue
            if purl and purl not in purls:
                purls.append(purl)
            ref = as_str(component.get("bom-ref"))
            if component_ref is None and ref:
                component_ref = ref
    return sorted(purls), component_ref


def _coverage_caveats(
    coverage_document: Any, coverage_source: Optional[str], skipped: SkipTally
) -> List[EvidenceCaveat]:
    """The ``coverage-gap`` caveats of a coverage document.

    ``units.failed`` and ``units.skipped`` above zero each become one
    caveat naming the count, because either means a part of the scan had
    no analysis. A coverage document that cannot be read is counted as a
    skipped object, never as clean silence.
    """
    if coverage_document is None:
        return []
    document, error = _parse_document(coverage_document)
    if error is not None or not isinstance(document, dict):
        shape = error or (
            f"the coverage document is a {type(document).__name__}, not the coverage report object"
        )
        skipped.add(f"{shape}; its failure and skip counts were not read")
        return []
    units = document.get("units")
    if units is None:
        return []
    if not isinstance(units, dict):
        skipped.add(
            f"the coverage document's units is a {type(units).__name__}, expected an "
            "object; its failure and skip counts were not read"
        )
        return []
    where = f" {coverage_source}" if coverage_source else ""
    caveats = []
    for key in ("failed", "skipped"):
        value = units.get(key)
        if isinstance(value, str) and value.strip().isdigit():
            value = int(value.strip())
        elif value is not None and (not isinstance(value, int) or isinstance(value, bool)):
            skipped.add(
                f"coverage units {key} counts are not numbers and were not read as a coverage gap"
            )
            continue
        if isinstance(value, int) and value > 0:
            caveats.append(
                EvidenceCaveat(
                    kind="coverage-gap",
                    detail=(
                        f"blint's coverage report{where} names {value} {key} analysis unit(s)"
                    ),
                )
            )
    return caveats


def _dedupe_caveats(caveats: List[EvidenceCaveat]) -> List[EvidenceCaveat]:
    out: List[EvidenceCaveat] = []
    seen = set()
    for caveat in caveats:
        key = (caveat.kind, caveat.detail)
        if key in seen:
            continue
        seen.add(key)
        out.append(caveat)
    return out


@guard_extract(PRODUCER_NAME)
def extract(
    findings_document,
    *,
    source: str,
    producer_version: str = "",
    reviews_document=None,
    reviews_source: Optional[str] = None,
    coverage_document=None,
    coverage_source: Optional[str] = None,
    bom_components: Optional[Iterable[dict]] = None,
    extra_components: Optional[Iterable[dict]] = None,
    source_root: Optional[str] = None,
) -> AdapterResult:
    """The blint review reports of one scan as evidence records.

    ``findings_document`` is the parsed ``findings.json`` (or its JSON
    text) and is the report the result is assessed on; a malformed one is
    a not-assessed result. ``reviews_document`` and ``coverage_document``
    are the parsed ``reviews.json`` and ``analysis-coverage.json``, each
    optional the way blint writes them only when non-empty; a malformed
    companion is counted as skipped caveats rather than sinking the
    findings. ``source``, ``reviews_source`` and ``coverage_source`` are
    the scan-directory-relative file names of the three documents.
    ``producer_version`` is the blint tool version (the blint-written
    BOM's ``metadata.tools`` names it) and gates the reports. The
    components feed the binary-to-component reconciliation. ``source_root``
    is the scanned directory; binary paths are stored relative to it.
    """
    if findings_document is None and reviews_document is None and coverage_document is None:
        return not_assessed("no blint report was given; the blint analysis was not assessed")

    skipped = SkipTally()
    finding_entries: List[Any] = []
    if findings_document is not None:
        findings, error = _parse_document(findings_document)
        if error is not None or not isinstance(findings, dict):
            reason = error or (
                f"the findings document is a {type(findings).__name__}, "
                "not the findings report object"
            )
            return not_assessed(
                f"the blint findings report is malformed and was not assessed: {reason}"
            )
        entries = findings.get("findings")
        if entries is not None and not isinstance(entries, list):
            return not_assessed(
                "the blint findings report is malformed and was not assessed: "
                f"the findings document's findings value is a {type(entries).__name__}, "
                "expected an array"
            )
        finding_entries = entries or []

    gate = gate_report_version(
        producer_version, SUPPORTED_MAJOR, KNOWN_MINOR, holder="BOM", noun="blint version"
    )
    if not gate.accepted:
        return not_assessed(
            f"the blint tool version {producer_version!r} is not supported; "
            f"this adapter reads blint {SUPPORTED_MAJOR}.x reports"
        )
    # The producer block names the version text the gate read: a number
    # given where a string belongs reads as its text, the way the gate
    # itself reads it, and anything else reads as unnamed.
    version_text = as_str(producer_version)
    if not version_text and isinstance(producer_version, (int, float)):
        if not isinstance(producer_version, bool):
            version_text = str(producer_version)
    # The reports name no schema version of their own, so the record says
    # so: the gated tool version is the producer version's business and
    # never reads as a report schema version.
    producer = EvidenceProducer(
        name=PRODUCER_NAME,
        version=version_text or "unknown",
        report_schema_version="unknown",
    )

    coverage_caveats = _coverage_caveats(coverage_document, coverage_source, skipped)
    base_caveats = list(gate.caveats) + coverage_caveats

    paths = SourcePaths([source_root])
    components = list(bom_components or []) + list(extra_components or [])
    records: List[Evidence] = []

    def entry_record(
        entry: dict, polarity: str, locations: List[EvidenceLocation], record_source: str
    ) -> None:
        """One presence record for one findings or reviews entry, with the
        producer's non-path values kept as given and the path fields stored
        in their relative spelling."""
        attributes: Dict[str, Any] = {
            key: paths.redact(value) for key, value in entry.items() if key not in _PATH_FIELDS
        }
        exe_name = paths.relative(entry.get("exe_name"))
        if exe_name is not None:
            attributes["exe_name"] = exe_name
        filename = entry.get("filename")
        if (
            "fileName" not in attributes
            and isinstance(filename, str)
            and filename.strip()
            and paths.relative(filename) is None
        ):
            # The location was left out because the path sits outside the
            # root; the basename keeps the record usable without carrying
            # an absolute path anywhere.
            attributes["fileName"] = _basename(filename)
        if entry.get("evidence") is not None:
            attributes["evidence"] = paths.redact(paths.neutral(entry["evidence"]))
        if filename is not None and not isinstance(filename, str):
            skipped.add(
                "entries name a filename that is not a string and carry no location or file name"
            )
        # The discriminator hashes the path fields relativized (or left out
        # when no relative form exists), so a report produced in another
        # directory gives the same id. The rule id and blint's finding_id
        # stay in it: neither depends on the directory, and finding_id is
        # what tells apart the repeats blint numbers itself.
        discriminator_object = dict(entry)
        left_out = 0
        for key in _PATH_FIELDS:
            relative = paths.relative(entry.get(key))
            if relative is None:
                discriminator_object.pop(key, None)
                if isinstance(entry.get(key), str) and entry[key].strip():
                    left_out += 1
            else:
                discriminator_object[key] = relative
        record_caveats = tuple(base_caveats)
        if left_out:
            record_caveats += (paths.outside_root_caveat(left_out),)
        purls, component_ref = _binary_subject(entry.get("filename"), components)
        confidence = as_str(entry.get("confidence")) or None
        records.append(
            build_record(
                source=record_source,
                producer=producer,
                kind="presence",
                polarity=polarity,
                discriminator=stable_discriminator(discriminator_object, paths),
                purls=tuple(purls),
                component_ref=component_ref,
                locations=tuple(locations),
                confidence=confidence,
                attributes=attributes,
                caveats=record_caveats,
            )
        )

    for entry in finding_entries:
        if not isinstance(entry, dict):
            skipped.add("findings entries are not JSON objects and became no record")
            continue
        binary = paths.relative(entry.get("filename"))
        locations = [EvidenceLocation(file=binary)] if binary else []
        try:
            entry_record(entry, "negative", locations, source)
        except RecursionError:
            skipped.add(TOO_DEEP_REASON)

    if reviews_document is not None:
        if reviews_source is None:
            reviews_source = source
        reviews, error = _parse_document(reviews_document)
        if error is not None or not isinstance(reviews, dict):
            reason = error or (
                f"the reviews document is a {type(reviews).__name__}, "
                "not the reviews report object"
            )
            skipped.add(f"{reason}; its entries became no records")
        else:
            entries = reviews.get("reviews")
            if entries is not None and not isinstance(entries, list):
                skipped.add(
                    f"the reviews document's reviews value is a {type(entries).__name__}, "
                    "expected an array; its entries became no records"
                )
                entries = []
            for entry in entries or []:
                if not isinstance(entry, dict):
                    skipped.add("reviews entries are not JSON objects and became no record")
                    continue
                symbols: List[str] = []
                evidence = entry.get("evidence")
                if isinstance(evidence, list):
                    for item in evidence:
                        if not isinstance(item, dict):
                            skipped.add(
                                "reviews evidence entries are not JSON objects "
                                "and became no locations"
                            )
                            continue
                        symbol = as_str(item.get("function")) or as_str(item.get("pattern"))
                        if symbol:
                            symbols.append(symbol)
                elif evidence is not None:
                    skipped.add(
                        "reviews entries carry an evidence value that is not an array "
                        "and the symbols became no locations"
                    )
                binary = paths.relative(entry.get("filename"))
                if binary is None:
                    locations = []
                elif symbols:
                    locations = [EvidenceLocation(file=binary, method=s) for s in symbols]
                else:
                    locations = [EvidenceLocation(file=binary)]
                try:
                    entry_record(entry, "positive", locations, reviews_source or source)
                except RecursionError:
                    skipped.add(TOO_DEEP_REASON)

    outside = paths.producer_caveat()
    caveats = _dedupe_caveats(base_caveats + skipped.caveats() + ([outside] if outside else []))
    return AdapterResult(status=STATUS_COMPLETED, records=records, caveats=caveats)


__all__ = [
    "KNOWN_MINOR",
    "PRODUCER_NAME",
    "SUPPORTED_MAJOR",
    "extract",
]
