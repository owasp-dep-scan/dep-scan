"""The evidence record: the Python model behind ``evidence.jsonl``.

One record is what a reachability producer said about one package, kept as
the producer gave it; nothing is inferred from advisory text and no record
carries a timestamp. The JSON Schema in this package's ``schemas/`` directory
is the source of truth for the shape, the dataclasses here mirror it, and a
test walks both so a property that exists in one but not the other fails.
``to_dict`` omits the optional fields that were never set, so a record
written back to JSON stays as small as the schema allows, and ``from_dict``
rejects unknown properties and missing required properties the way the
schema does; the fields the schema lists in ``required`` have no defaults
here, so a record that leaves one out does not read back as an empty one.

The id is stable across runs. It is ``ev-`` followed by the first 16 hex
digits of the SHA-256 digest over the canonical JSON (``sort_keys``, compact
separators) of the array

``["1", producer name, kind, [comparable subject purls sorted], [file,
line, method] of the first location, discriminator]``

where an absent line or method is ``null`` and a record with no locations
carries an empty array for the location part. The comparable form of a purl
is the one ``analysis_lib.findings.vdr_convert.comparable_purl`` computes, so
qualifier-, case- and encoding-spelled variants of one purl share an id. The
discriminator is the producer's own stable object id when the report names
one, and otherwise the MD5 content hash of the report object the record was
built from; it keeps distinct objects that agree on everything else apart.

Sixteen hex digits can still collide, so the store gives every remaining
member of a colliding group a ``-2``, ``-3`` suffix in canonical-JSON order.
That rule is deterministic and documented in ``store.py``; the schema's id
pattern accepts the suffix.
"""

import hashlib
import json
from dataclasses import MISSING, dataclass, field, fields, is_dataclass
from typing import (
    Any,
    ClassVar,
    Dict,
    Iterable,
    List,
    Optional,
    Self,
    Union,
    get_args,
    get_origin,
    get_type_hints,
)

#: The record shape this package publishes and every record carries.
EVIDENCE_SCHEMA_VERSION = "1"

#: The id prefix and the digest length behind it.
ID_PREFIX = "ev-"
ID_DIGEST_HEX_LENGTH = 16

#: The most witness nodes a record's path may carry. A producer that gave
#: more has the first ones kept and the truncation recorded as a caveat.
MAX_PATH_NODES = 64

#: The record kinds, in the settled order the schema lists them. The first
#: seven plus ``no-path`` are the reachability producers' kinds; the rest
#: exist so later producers (binary analysis, BOM annotations, observed
#: runtime traces) fit without a schema change.
KINDS = (
    "reached-flow",
    "usage",
    "callsite",
    "occurrence",
    "callstack",
    "entry-point",
    "exploit-chain",
    "sanitizer",
    "dead-code",
    "dependency",
    "no-path",
    "annotation",
    "presence",
    "introspection",
    "runtime-trace",
)

#: Whether a record says something was observed or says it was not.
POLARITIES = ("positive", "negative")

#: The caveats a record or an analyzer entry may carry. ``schema-minor``
#: marks a newer minor report version, ``schema-unknown`` a report that
#: names no version, ``record-skipped`` a producer object that could not
#: become a record, ``minimal-api`` an entry point whose attribution the
#: producer itself may have misplaced, ``path-truncated`` a witness path
#: cut at :data:`MAX_PATH_NODES`, and ``location-outside-root`` a file the
#: producer named outside the scanned source root, which the record leaves
#: out rather than carry as an absolute path.
CAVEAT_KINDS = (
    "budget",
    "timeout",
    "collapsed-edges",
    "unresolved-call-sites",
    "coverage-gap",
    "path-truncated",
    "schema-minor",
    "schema-unknown",
    "minimal-api",
    "record-skipped",
    "location-outside-root",
)


def comparable_purl(purl: str) -> str:
    """The comparable form of a purl, as the findings module defines it.

    The findings module is imported here rather than at module level so the
    two modules can import each other's names in either order as the
    consumers grow; the comparable form is one definition the whole code
    shares.
    """
    from analysis_lib.findings.vdr_convert import comparable_purl as comparable

    return comparable(purl)


def _encode(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return value.to_dict()
    if isinstance(value, list):
        return [_encode(item) for item in value]
    return value


def _unwrap_optional(hint: Any) -> Any:
    if get_origin(hint) is Union:
        args = [arg for arg in get_args(hint) if arg is not type(None)]
        if len(args) == 1:
            return args[0]
    return hint


def _decode(value: Any, hint: Any, where: str) -> Any:
    inner = _unwrap_optional(hint)
    if get_origin(inner) is list:
        if not isinstance(value, list):
            raise ValueError(f"{where} expects an array, got {type(value).__name__}")
        item_hint = get_args(inner)[0]
        return [_decode(item, item_hint, where) for item in value]
    if isinstance(inner, type) and issubclass(inner, _RecordObject):
        return inner.from_dict(value)
    return value


@dataclass
class _RecordObject:
    """Shared to_dict and from_dict behaviour for the evidence objects.

    ``_KEYS`` maps a dataclass field name to its JSON property name where
    the two differ; a field absent from the map keeps its name. to_dict
    writes every field whose value is not None, which is how unset optional
    fields stay out of the JSON. from_dict resolves each field's type hint,
    so nested objects decode themselves and a malformed array or object is
    named precisely.
    """

    _KEYS: ClassVar[Dict[str, str]] = {}

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for field_ in fields(self):
            value = getattr(self, field_.name)
            if value is None:
                continue
            out[self._KEYS.get(field_.name, field_.name)] = _encode(value)
        return out

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Self:
        if not isinstance(data, dict):
            raise ValueError(f"{cls.__name__} expects a JSON object, got {type(data).__name__}")
        keys = {cls._KEYS.get(field_.name, field_.name) for field_ in fields(cls)}
        unknown = sorted(set(data) - keys)
        if unknown:
            raise ValueError(f"unknown properties for {cls.__name__}: {', '.join(unknown)}")
        required = sorted(
            cls._KEYS.get(field_.name, field_.name)
            for field_ in fields(cls)
            if field_.default is MISSING and field_.default_factory is MISSING
        )
        missing = sorted(name for name in required if name not in data)
        if missing:
            raise ValueError(
                f"missing required properties for {cls.__name__}: {', '.join(missing)}"
            )
        kwargs: Dict[str, Any] = {}
        hints = get_type_hints(cls)
        for field_ in fields(cls):
            json_key = cls._KEYS.get(field_.name, field_.name)
            if json_key in data:
                kwargs[field_.name] = _decode(
                    data[json_key], hints[field_.name], f"{cls.__name__}.{field_.name}"
                )
        return cls(**kwargs)


@dataclass
class EvidenceProducer(_RecordObject):
    """The tool that produced the record, named as it names itself.

    ``report_schema_version`` is the report's own version field, the
    shape-implied version when the report carries none but has one, and the
    literal string ``unknown`` when nothing implies one.
    """

    name: str
    version: str
    report_schema_version: str

    _KEYS: ClassVar[Dict[str, str]] = {"report_schema_version": "reportSchemaVersion"}


@dataclass
class EvidenceSubject(_RecordObject):
    """What the record is about: the package purls and, when the adapter
    resolved one, the BOM component ``bom-ref``."""

    purls: List[str] = field(default_factory=list)
    component_ref: Optional[str] = None

    _KEYS: ClassVar[Dict[str, str]] = {"component_ref": "componentRef"}


@dataclass
class EvidenceLocation(_RecordObject):
    """One place the evidence lives, relative to the scanned source root
    with forward slashes."""

    file: str
    line: Optional[int] = None
    method: Optional[str] = None


@dataclass
class EvidencePathNode(_RecordObject):
    """One witness node on a path: the frames the producer walked, kept in
    its order."""

    file: Optional[str] = None
    line: Optional[int] = None
    method: Optional[str] = None
    symbol: Optional[str] = None


@dataclass
class EvidenceCaveat(_RecordObject):
    """One thing a reader of the record should discount or know: a budget
    the producer hit, a schema that drifted, a path that was cut."""

    kind: str
    detail: str


@dataclass
class Evidence(_RecordObject):
    """One record of ``evidence.jsonl``. Everything a producer stated about
    the object is kept as given: the confidence string it used, the
    attributes it attached, the witness path it walked."""

    schema_version: str
    id: str
    producer: EvidenceProducer
    kind: str
    polarity: str
    subject: EvidenceSubject
    source: str
    locations: List[EvidenceLocation]
    caveats: List[EvidenceCaveat]
    path: Optional[List[EvidencePathNode]] = None
    confidence: Optional[str] = None
    attributes: Optional[Dict[str, Any]] = None

    _KEYS: ClassVar[Dict[str, str]] = {"schema_version": "schemaVersion"}


def record_id(
    producer_name: str,
    kind: str,
    purls: Iterable[str],
    first_location: Optional[EvidenceLocation],
    discriminator: str,
) -> str:
    """The record id, reproducible from the identity parts alone.

    ``purls`` are compared and sorted before hashing, so spelling variants
    of one purl do not split ids. ``first_location`` is the record's first
    location when it has one and ``None`` when it does not.
    """
    subject = sorted(comparable_purl(purl) for purl in purls)
    if first_location is None:
        location: List[Any] = []
    else:
        location: List[Any] = [first_location.file, first_location.line, first_location.method]
    payload = json.dumps(
        [EVIDENCE_SCHEMA_VERSION, producer_name, kind, subject, location, discriminator],
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return ID_PREFIX + digest[:ID_DIGEST_HEX_LENGTH]


def content_discriminator(obj: Any) -> str:
    """The MD5 content hash of a report object, over its canonical JSON.

    This is the discriminator a record uses when the report names no stable
    object id of its own; the rule matches the flow identity hash the
    reachability engine has always applied to dedupe flows.
    """
    return hashlib.md5(
        json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


__all__ = [
    "CAVEAT_KINDS",
    "EVIDENCE_SCHEMA_VERSION",
    "Evidence",
    "EvidenceCaveat",
    "EvidenceLocation",
    "EvidencePathNode",
    "EvidenceProducer",
    "EvidenceSubject",
    "ID_DIGEST_HEX_LENGTH",
    "ID_PREFIX",
    "KINDS",
    "MAX_PATH_NODES",
    "POLARITIES",
    "comparable_purl",
    "content_discriminator",
    "record_id",
]
