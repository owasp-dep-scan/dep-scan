"""Python model for the dep-scan finding schema.

The JSON Schema in analysis_lib/findings/schemas is the source of truth for
the shape; the dataclasses here mirror it, and a test walks both so a property
that exists in one but not the other fails. Everything uses the standard
library. to_dict omits optional fields that were never set, so a finding
written back to JSON stays as small as the schema allows, and from_dict
rejects unknown and missing properties the way the schema does.
"""

from dataclasses import MISSING, dataclass, fields, is_dataclass
from typing import (
    Any,
    Dict,
    List,
    Optional,
    Self,
    Union,
    get_args,
    get_origin,
    get_type_hints,
)


def _encode(value: Any) -> Any:
    if is_dataclass(value):
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
    if isinstance(inner, type) and issubclass(inner, _SchemaObject):
        return inner.from_dict(value)
    return value


@dataclass
class _SchemaObject:
    """Common to_dict and from_dict behaviour for the finding objects.

    to_dict writes every field whose value is not None, which is how the unset
    optional fields stay out of the JSON. from_dict resolves each field's type
    hint, so nested objects decode themselves and a malformed array or object
    is named precisely.
    """

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for field in fields(self):
            value = getattr(self, field.name)
            if value is None:
                continue
            out[field.name] = _encode(value)
        return out

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Self:
        if not isinstance(data, dict):
            raise ValueError(f"{cls.__name__} expects a JSON object, got {type(data).__name__}")
        names = {field.name for field in fields(cls)}
        unknown = sorted(set(data) - names)
        if unknown:
            raise ValueError(f"unknown properties for {cls.__name__}: {', '.join(unknown)}")
        required = sorted(
            field.name
            for field in fields(cls)
            if field.default is MISSING and field.default_factory is MISSING
        )
        missing = sorted(name for name in required if name not in data)
        if missing:
            raise ValueError(f"missing required properties for {cls.__name__}: {', '.join(missing)}")
        kwargs: Dict[str, Any] = {}
        for name, hint in get_type_hints(cls).items():
            if name in data:
                kwargs[name] = _decode(data[name], hint, f"{cls.__name__}.{name}")
        return cls(**kwargs)


@dataclass
class Location(_SchemaObject):
    """One place a finding applies to: a source position, a function, or a
    binary file and offset. Every field is optional because binary and
    manifest findings carry a different subset than source findings do."""

    file: Optional[str] = None
    line: Optional[int] = None
    column: Optional[int] = None
    end_line: Optional[int] = None
    end_column: Optional[int] = None
    function: Optional[str] = None
    binary: Optional[str] = None
    offset: Optional[int] = None


@dataclass
class CoverageReason(_SchemaObject):
    """One concrete reason a capability did not assess what it was asked to."""

    capability: str
    reason: str
    detail: Optional[str] = None


@dataclass
class Coverage(_SchemaObject):
    """Whether the relevant analysis ran. A state of not_assessed means the
    analyzer did not run, failed, hit a budget or lacked data, which is never
    the same as assessed and nothing found."""

    state: str
    reasons: Optional[List[CoverageReason]] = None


@dataclass
class ExploitabilityAxes(_SchemaObject):
    """The five exploitability axes, each graded on the same scale."""

    presence: str
    reach: str
    exposure: str
    barrier: str
    pressure: str


@dataclass
class Exploitability(_SchemaObject):
    """The exploitability assessment. The axes say how confident the analysis
    is about each property of the finding, and the grade summarises them."""

    axes: ExploitabilityAxes
    grade: Optional[str] = None
    rule: Optional[str] = None
    unassessed: Optional[List[str]] = None
    witness: Optional[str] = None


@dataclass
class Triage(_SchemaObject):
    """The human decision about the finding, using the CycloneDX 1.7 impact
    analysis vocabulary for the state, justification and response values."""

    state: Optional[str] = None
    justification: Optional[str] = None
    responses: Optional[List[str]] = None
    detail: Optional[str] = None
    author: Optional[str] = None
    expires: Optional[str] = None


@dataclass
class Fix(_SchemaObject):
    """How to move past the finding."""

    fixed_versions: Optional[List[str]] = None
    upgrade_path: Optional[List[str]] = None
    recommendation: Optional[str] = None


@dataclass
class Producer(_SchemaObject):
    """The analyzer that produced the finding."""

    name: str
    version: str


@dataclass
class Reference(_SchemaObject):
    """One link a reader of the finding may follow."""

    url: str
    type: str


@dataclass
class FindingProperty(_SchemaObject):
    """One extension property, carried as a name and value pair."""

    name: str
    value: str


@dataclass
class Finding(_SchemaObject):
    """One result dep-scan reports, of any category. The id carries the
    line-free fingerprint that baselines and suppressions key on."""

    id: str
    category: str
    rule: str
    title: str
    severity: str
    coverage: Coverage
    producer: Producer
    confidence: Optional[str] = None
    cwes: Optional[List[int]] = None
    components: Optional[List[str]] = None
    locations: Optional[List[Location]] = None
    evidence: Optional[List[str]] = None
    exploitability: Optional[Exploitability] = None
    triage: Optional[Triage] = None
    fix: Optional[Fix] = None
    references: Optional[List[Reference]] = None
    properties: Optional[List[FindingProperty]] = None
